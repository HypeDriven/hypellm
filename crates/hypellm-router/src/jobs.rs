//! Long-running generative work: `POST /v1/jobs` and its lifecycle
//! (specification-extension 11).
//!
//! # Why this endpoint exists
//!
//! Music, video and audio-to-video generation take minutes. The router serves
//! each connection from one bounded worker thread, so holding a socket open for
//! six minutes spends a connection slot on waiting, and a cold-start swap in
//! front of it spends more. A job decouples the two: the request is accepted,
//! the connection is released, and the caller polls or streams progress.
//!
//! It is announced as **first-party**, not dressed up as OpenAI compatibility,
//! because no OpenAI-compatible shape fits. Where a standard shape does exist —
//! `/v1/audio/speech`, `/v1/images/generations` — it is used unchanged.
//!
//! # What bounds it
//!
//! Specification 3.2 admits no unbounded thread, queue, buffer or retention
//! that a request can create, and a job endpoint is four of those at once. So:
//!
//! | Quantity | Bound |
//! |---|---|
//! | Worker threads | `settings job_workers`, fixed at startup, never per request |
//! | Queued jobs | `settings max_queued_jobs`, fleet-wide, a job being tried included; a full queue is a `429` |
//! | Queued batch jobs | `settings max_queued_batch_jobs`, so batch work never fills the queue against the other classes |
//! | Live jobs per tenant | `settings max_jobs_per_tenant`; the cap counts terminal jobs too, until they expire |
//! | Result bytes | `settings max_job_result_bytes` per job, held in memory |
//! | Retention | `settings job_retention_ms` after reaching a terminal state |
//! | Patience | the larger of `settings job_retention_ms` and `default_deadline_ms`, the job's deadline |
//! | Backoffs | [`MAX_JOB_ATTEMPTS`] passes refused by fleet governance, backing off, within the job's deadline |
//!
//! # Waiting for capacity
//!
//! A job waits in this queue and nowhere else (orchestration §11.9). A worker
//! tries it with no wait in the admission queue and no parking. A pass that
//! fails only because a slot is taken or a model has still to be started puts
//! the job back *in its place*: it counts no attempt and starts no backoff, and
//! the job is tried again when something that could unblock it happens — a job
//! leaving the queue — or at the quarter-second tick. Its patience is the only
//! bound on that wait, and a job that outlives it fails `deadline_exceeded`.
//! Holding no worker while it waits, a job for a busy slave no longer keeps a
//! job for an idle one waiting behind it.
//!
//! A pass refused by the fleet's own governance — the activation budget, a host
//! without room — still backs off (specification 26.10): at most
//! [`MAX_JOB_ATTEMPTS`] passes, doubling from a second to a minute. Trying those
//! every tick would ask the agent for an activation four times a second.
//!
//! A queued job is counted as parked demand for its model from submission until
//! it leaves the queue, so the batching trigger, the scheduler, eviction value
//! and idle stop see it while no worker holds it.
//!
//! # Who goes next
//!
//! Class first — the admission classes, resolved as admission resolves them —
//! then model locality within the class (specification 26.11), then share:
//! every principal's first waiting job before anyone's second. The rule is
//! [`hypellm_fleet::schedule::pick_job`]; this module stamps its inputs.
//!
//! The result spool is **memory, bounded and expiring**. The router is not
//! becoming a blob store: specification 2.2's non-goals are not widened by this
//! endpoint, and a result that outlived its window is gone rather than paged to
//! disk.
//!
//! # What a restart does
//!
//! Jobs live in this process. A router that restarts has no worker running the
//! work and no result to serve, so its job table starts empty and a job
//! identifier from before the restart is `not_found`. That is the honest
//! answer: the alternative — a durable record that says `running` with nothing
//! running — is worse, because a client would wait on it.

use crate::dispatch::{AccumulatingSink, EventSink, SinkClosed};
use crate::pipeline;
use crate::state::RouterState;
use hypellm_core::admission::PriorityClass;
use hypellm_core::canonical::{CanonicalRequest, ClientProtocol};
use hypellm_core::decision::{AttemptOutcome, ExclusionReason};
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::{AliasId, GroupId, KeyId, PrincipalId, TenantId};
use hypellm_core::rbac::PermissionSet;
use hypellm_core::target::Capability;
use hypellm_core::time::Clock;
use hypellm_crypto::{hex, random};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use wire_json::{Object, Value};

/// How a job is progressing.
///
/// A closed vocabulary, like every other state in this router: a client that
/// receives an unrecognised state cannot decide whether to keep waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Accepted, waiting for a worker.
    Queued,
    /// A worker is executing it.
    Running,
    /// Finished, with a result to collect.
    Succeeded,
    /// Finished without a result.
    Failed,
    /// Cancelled by the caller.
    Cancelled,
}

impl JobState {
    /// Stable name for the wire and for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// A job identifier.
///
/// Opaque, 128 bits of randomness, prefixed so it is recognisable in a log. It
/// is also the *capability* to read the job's result within its tenant, so it
/// is generated from the OS source and never derived from anything a caller
/// supplied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JobId(String);

impl JobId {
    /// Mint a fresh identifier.
    ///
    /// # Errors
    ///
    /// Fails closed if the OS entropy source is unavailable: a predictable job
    /// identifier in a shared tenant is another caller's result.
    pub fn generate() -> Result<Self, random::RandomError> {
        let bytes = random::bytes::<16>()?;
        Ok(Self(format!("job_{}", hex::encode(&bytes))))
    }

    /// Parse a caller-supplied identifier.
    ///
    /// Shape only. A well-formed identifier that names no job is `not_found`
    /// exactly like a well-formed one belonging to another tenant, so this
    /// cannot be used to tell the two apart.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.strip_prefix("job_")?;
        if rest.len() != 32 || !rest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One job's observable state.
#[derive(Debug, Clone)]
pub struct JobView {
    /// The identifier.
    pub id: JobId,
    /// Current state.
    pub state: JobState,
    /// Progress in permille, or `0` while queued.
    ///
    /// Coarse on purpose. A provider that reports nothing incrementally gives
    /// the router nothing to refine it with, and a figure derived from elapsed
    /// time would read as work completed and be wrong exactly when a caller was
    /// relying on it.
    pub progress_permille: u32,
    /// Milliseconds the router still expects to need, best effort.
    pub eta_ms: u64,
    /// The error code, once failed.
    pub error_code: Option<String>,
    /// The error message, once failed.
    pub error_message: Option<String>,
    /// When the job was created, in wall milliseconds.
    pub created_ms: u64,
    /// When the job last changed, in wall milliseconds.
    pub updated_ms: u64,
    /// Bytes of result held, if any.
    pub result_bytes: usize,
    /// Its priority class, stamped at submission (orchestration §11.9).
    pub class: PriorityClass,
    /// While queued, why: `turn` before its first pass, `slot` when every
    /// slot it could use was taken, `activation` when its model has still to
    /// be started, `backoff` after a refusal by fleet governance. `None` once
    /// it is running or finished.
    ///
    /// It names no other principal and counts nobody, so it says why a caller
    /// waits without saying who else does.
    pub waiting_for: Option<&'static str>,
    /// An artifact job's parts, once it succeeded.
    pub parts: Vec<PartView>,
}

/// One part of a succeeded artifact job, as a caller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartView {
    /// Its name: `GET /v1/jobs/{id}/result/{name}` serves it.
    pub name: String,
    /// Its media type.
    pub media_type: &'static str,
    /// Its length.
    pub bytes: u64,
    /// Its SHA-256, lowercase hex, computed as it was spooled.
    pub sha256: String,
}

/// A job's full record, including what only the router sees.
#[derive(Debug)]
struct Job {
    view: JobView,
    tenant: TenantId,
    principal: PrincipalId,
    /// The rendered response body, once a chat job succeeded.
    result: Option<Vec<u8>>,
    /// An artifact job's spooled parts, once it succeeded.
    parts: Vec<crate::spool::SpooledPart>,
    /// Spool bytes those parts hold, given back when the job leaves the table.
    spooled_bytes: u64,
    /// When a terminal job stops being readable, in monotonic milliseconds.
    expires_ms: Option<u64>,
    /// Set by `DELETE`; read by the worker between steps.
    cancelled: Arc<AtomicBool>,
    /// Monotonically increasing, so an events stream can resume.
    revision: u64,
}

/// Passes refused by fleet governance one job may make before it fails.
pub const MAX_JOB_ATTEMPTS: u32 = 16;

/// The first governance backoff, doubling per pass.
const FIRST_REQUEUE_BACKOFF_MS: u64 = 1_000;

/// The longest governance backoff.
const MAX_REQUEUE_BACKOFF_MS: u64 = 60_000;

/// How long between an artifact job's status polls, unless configured.
pub const DEFAULT_POLL_MS: u64 = 2_000;

/// How long blocked work goes untried when nothing wakes the queue.
///
/// A job leaving the queue wakes it. A slot freed by an interactive request,
/// or a model finishing its load, does not; this bounds how long either goes
/// unnoticed, as `PARK_SLICE` does for a parked request.
const TICK: Duration = Duration::from_millis(250);

/// What a worker needs to run a job, fixed at submission.
#[derive(Debug)]
struct Work {
    id: JobId,
    request: CanonicalRequest,
    groups: Vec<GroupId>,
    permissions: PermissionSet,
    key_id: Option<KeyId>,
    cancelled: Arc<AtomicBool>,
    /// Submission order (specification 26.11).
    seq: u64,
    /// When it was submitted, on the router's monotonic clock: the age the
    /// reordering bound is measured from.
    submitted_ms: u64,
    /// Its class, stamped at submission: a policy published while it waits
    /// applies to later submissions, as an in-flight request keeps the
    /// snapshot it was admitted under.
    priority: PriorityClass,
    /// How many of its principal's jobs of the same class were already
    /// waiting when it was submitted (orchestration §11.9).
    principal_round: u32,
    /// The same count over its tenant.
    tenant_round: u32,
    /// What a shim is asked to make, for an artifact job (orchestration
    /// §11.5); `None` for a chat job.
    artifact: Option<crate::protocol::job::ArtifactSpec>,
}

/// One queued job, and what changes while it waits.
#[derive(Debug)]
struct Entry {
    work: Arc<Work>,
    /// Passes refused by fleet governance so far.
    attempts: u32,
    /// Not to be tried before this, on the router's monotonic clock.
    not_before_ms: u64,
    /// A worker is trying it now. It keeps its place until the pass ends.
    trying: bool,
    /// The pass holds its reservations: it is running, not waiting, and no
    /// longer counts toward a newcomer's round.
    started: bool,
    /// Found blocked under this wake generation, and not tried again until
    /// the generation moves on.
    blocked_in: Option<u64>,
    /// The capability it is counted as parked demand for: from submission,
    /// or from the first pass that found its model still to be started if
    /// the capability's queue was full then. Released exactly once, when it
    /// leaves the queue.
    parked: Option<Capability>,
}

impl Entry {
    fn is_due(&self, now_ms: u64, generation: u64) -> bool {
        !self.trying
            && self.not_before_ms <= now_ms
            && self.blocked_in.is_none_or(|g| g < generation)
    }
}

/// How the job queue is ordered when a worker takes from it
/// (specification 26.11).
///
/// Implemented by the router over its fleet. Absent, or with a bound of zero,
/// jobs are taken by class and share alone.
pub trait JobOrder {
    /// The reordering bound, in milliseconds. Zero switches locality off.
    fn bound_ms(&self) -> u64;
    /// How the request's model stands right now.
    fn class(&self, request: &CanonicalRequest) -> hypellm_fleet::schedule::JobClass;
    /// Note that a job was taken out of submission order: `job_reordered`,
    /// `job_by_class`, `job_by_share`, or `job_starving` when the bound
    /// promoted it.
    fn taken_out_of_order(&self, _outcome: &'static str) {}
}

/// What a job is submitted under, besides the request itself.
#[derive(Debug, Clone, Default)]
pub struct SubmitTerms {
    /// Its priority class, resolved as admission resolves it.
    pub class: PriorityClass,
    /// The capability the caller counted it as parked demand for ([`park`]).
    /// The queue holds it from submission and releases it when the job
    /// leaves; on a refusal nothing is held, and the caller releases it.
    pub parked: Option<Capability>,
    /// The jobs its tenant may hold, overriding the store's
    /// `max_per_tenant` (a `tenant:` quota's `jobs`).
    pub tenant_cap: Option<u32>,
    /// The jobs its principal may hold (a `principal:` quota's `jobs`).
    pub principal_cap: Option<u32>,
    /// What a shim is asked to make, for an artifact job; `None` for a chat
    /// job.
    pub artifact: Option<crate::protocol::job::ArtifactSpec>,
}

/// Why a job could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitRefusal {
    /// The tenant already holds as many jobs as it may.
    TenantAtCapacity,
    /// The principal already holds as many jobs as its quota allows.
    PrincipalAtCapacity,
    /// The queue is full fleet-wide, or full for the job's class.
    QueueFull,
    /// No entropy, so no identifier could be minted.
    NoEntropy,
    /// The router is shutting down and is not accepting new work.
    ShuttingDown,
}

impl SubmitRefusal {
    /// A stable token for the error body.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TenantAtCapacity => "job_tenant_at_capacity",
            Self::PrincipalAtCapacity => "job_principal_at_capacity",
            Self::QueueFull => "job_queue_full",
            Self::NoEntropy => "internal_fault",
            Self::ShuttingDown => "shutting_down",
        }
    }
}

/// The bounds this store enforces.
#[derive(Debug, Clone, Copy)]
pub struct JobLimits {
    /// Live plus retained jobs one tenant may hold.
    pub max_per_tenant: u32,
    /// Jobs waiting, fleet-wide.
    pub max_queued: u32,
    /// Batch-class jobs waiting, fleet-wide: past it a batch submission is
    /// refused, so batch work never fills the queue against the other classes.
    pub max_queued_batch: u32,
    /// Bytes of result held per job.
    pub max_result_bytes: usize,
    /// How long a terminal job stays readable, in milliseconds.
    pub retention_ms: u64,
}

impl JobLimits {
    /// Conservative defaults, all overridable through `settings`.
    pub const DEFAULT: Self = Self {
        max_per_tenant: 32,
        max_queued: 64,
        max_queued_batch: 32,
        max_result_bytes: 8 * 1024 * 1024,
        retention_ms: 900_000,
    };
}

/// Why a pass ended without the job finishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// Every slot it could use was taken. Kept in place, no attempt.
    Slot,
    /// Its model has still to be started. Kept in place, no attempt, and
    /// counted as parked demand.
    Activation,
    /// Refused by fleet governance. An attempt, and a backoff.
    Backoff,
}

impl Wait {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Slot => "slot",
            Self::Activation => "activation",
            Self::Backoff => "backoff",
        }
    }
}

/// What a worker takes from the queue.
#[derive(Debug)]
enum Taken {
    /// Try this job.
    Try {
        work: Arc<Work>,
        /// The wake generation it was taken under.
        generation: u64,
        /// Whether it is already counted as parked demand.
        parked: bool,
    },
    /// It left the queue without running.
    Discard {
        work: Arc<Work>,
        /// The parked demand to release.
        parked: Option<Capability>,
        /// `true` when its patience ran out; `false` when it was cancelled.
        expired: bool,
    },
}

/// The job table, its queue, and its workers.
///
/// One per router. Everything a request can grow is bounded here, in one place,
/// so a reviewer can check the whole of specification 3.2 for this endpoint
/// without reading the workers.
#[derive(Debug)]
pub struct JobStore {
    jobs: Mutex<BTreeMap<JobId, Job>>,
    /// Waiting jobs, in submission order.
    queue: Mutex<VecDeque<Entry>>,
    /// Signalled on submission, when a job leaves the queue, and on shutdown.
    work: Condvar,
    limits: JobLimits,
    stopping: AtomicBool,
    /// Monotonic revision source, so an events stream can resume from a cursor
    /// rather than replaying a job's whole history.
    revisions: AtomicU64,
    /// Submission order source.
    sequence: AtomicU64,
    /// Moves on whenever blocked work might have become unblocked: a job
    /// leaving the queue, or a tick passing.
    generation: AtomicU64,
    /// Where artifact jobs' parts go. `None` refuses artifact jobs.
    spool: Option<crate::spool::Spool>,
    /// How long between an artifact job's status polls, in milliseconds.
    poll_ms: u64,
}

impl JobStore {
    /// An empty store with the given bounds.
    #[must_use]
    pub fn new(limits: JobLimits) -> Self {
        Self {
            jobs: Mutex::new(BTreeMap::new()),
            queue: Mutex::new(VecDeque::new()),
            work: Condvar::new(),
            limits,
            stopping: AtomicBool::new(false),
            revisions: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            generation: AtomicU64::new(1),
            spool: None,
            poll_ms: DEFAULT_POLL_MS,
        }
    }

    /// This store, spooling artifact jobs' parts to `spool` and polling their
    /// shims every `poll_ms`.
    #[must_use]
    pub fn with_spool(mut self, spool: crate::spool::Spool, poll_ms: u64) -> Self {
        self.spool = Some(spool);
        self.poll_ms = poll_ms;
        self
    }

    /// Whether this store can run artifact jobs.
    #[must_use]
    pub const fn runs_artifacts(&self) -> bool {
        self.spool.is_some()
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> JobLimits {
        self.limits
    }

    /// Accept a job, or say why not.
    ///
    /// The per-tenant cap is checked under the same lock that inserts, so two
    /// simultaneous submissions cannot both see room for the last slot. The
    /// job's rounds are stamped under the queue's lock, from the jobs waiting
    /// at that moment.
    ///
    /// # Errors
    ///
    /// [`SubmitRefusal`] when a bound is reached or entropy is unavailable.
    #[allow(
        clippy::too_many_arguments,
        reason = "the request, what came with it, its terms and the two clocks; \
                  bundling them would only rename them"
    )]
    pub fn submit(
        &self,
        request: CanonicalRequest,
        groups: Vec<GroupId>,
        permissions: PermissionSet,
        key_id: Option<KeyId>,
        terms: SubmitTerms,
        now_wall_ms: u64,
        now_ms: u64,
    ) -> Result<JobView, SubmitRefusal> {
        let priority = terms.class;
        if self.stopping.load(Ordering::SeqCst) {
            return Err(SubmitRefusal::ShuttingDown);
        }
        let id = JobId::generate().map_err(|_| SubmitRefusal::NoEntropy)?;
        let cancelled = Arc::new(AtomicBool::new(false));

        let view = {
            let mut jobs = self.lock_jobs();
            // Expiry first, so a tenant is not refused because of jobs that
            // should already have been swept. Sweeping only on a timer would
            // make the cap depend on when the timer last ran.
            self.sweep_locked(&mut jobs, now_ms);

            let held = jobs
                .values()
                .filter(|job| job.tenant == request.tenant)
                .count();
            let tenant_cap = terms.tenant_cap.unwrap_or(self.limits.max_per_tenant);
            if u32::try_from(held).unwrap_or(u32::MAX) >= tenant_cap {
                return Err(SubmitRefusal::TenantAtCapacity);
            }
            if let Some(cap) = terms.principal_cap {
                let held = jobs
                    .values()
                    .filter(|job| job.tenant == request.tenant && job.principal == request.principal)
                    .count();
                if u32::try_from(held).unwrap_or(u32::MAX) >= cap {
                    return Err(SubmitRefusal::PrincipalAtCapacity);
                }
            }

            let view = JobView {
                id: id.clone(),
                state: JobState::Queued,
                progress_permille: 0,
                eta_ms: 0,
                error_code: None,
                error_message: None,
                created_ms: now_wall_ms,
                updated_ms: now_wall_ms,
                result_bytes: 0,
                class: priority,
                waiting_for: Some("turn"),
                parts: Vec::new(),
            };
            jobs.insert(
                id.clone(),
                Job {
                    view: view.clone(),
                    tenant: request.tenant.clone(),
                    principal: request.principal.clone(),
                    result: None,
                    parts: Vec::new(),
                    spooled_bytes: 0,
                    expires_ms: None,
                    cancelled: Arc::clone(&cancelled),
                    revision: self.revisions.fetch_add(1, Ordering::SeqCst),
                },
            );
            view
        };

        // Queued after the table insert, so a worker that picks it up
        // immediately always finds a record to transition.
        {
            let mut queue = self.lock_queue();
            let full = u32::try_from(queue.len()).unwrap_or(u32::MAX) >= self.limits.max_queued;
            let batch_full = priority == PriorityClass::Batch
                && u32::try_from(
                    queue
                        .iter()
                        .filter(|e| e.work.priority == PriorityClass::Batch)
                        .count(),
                )
                .unwrap_or(u32::MAX)
                    >= self.limits.max_queued_batch;
            if full || batch_full {
                // Roll back the table entry. A job that is not queued will
                // never run, and leaving it visible as `queued` would be a lie
                // that also consumed the tenant's cap until it expired.
                self.lock_jobs().remove(&id);
                return Err(SubmitRefusal::QueueFull);
            }
            let (principal_round, tenant_round) =
                Self::rounds(&queue, priority, &request.tenant, &request.principal);
            queue.push_back(Entry {
                work: Arc::new(Work {
                    id,
                    request,
                    groups,
                    permissions,
                    key_id,
                    cancelled,
                    seq: self.sequence.fetch_add(1, Ordering::SeqCst),
                    submitted_ms: now_ms,
                    priority,
                    principal_round,
                    tenant_round,
                    artifact: terms.artifact,
                }),
                attempts: 0,
                not_before_ms: 0,
                trying: false,
                started: false,
                blocked_in: None,
                parked: terms.parked,
            });
        }
        self.work.notify_one();
        Ok(view)
    }

    /// The rounds to stamp on a new job: how many of its principal's, and of
    /// its tenant's, jobs of the same class are waiting now. A job already
    /// running is not waiting, and does not count.
    ///
    /// Stamped rather than recomputed, for the reason the admission queue
    /// gives (`QueueState` in `hypellm_core::admission`): recomputed, a
    /// backlog's second job would fall back to round zero the moment its first
    /// left, and the order would collapse into submission order. Bounded by
    /// `max_queued`, because it counts jobs present, not jobs ever served.
    fn rounds(
        queue: &VecDeque<Entry>,
        priority: PriorityClass,
        tenant: &TenantId,
        principal: &PrincipalId,
    ) -> (u32, u32) {
        let same_class = || {
            queue.iter().filter(move |e| {
                !e.started && e.work.priority == priority && e.work.request.tenant == *tenant
            })
        };
        let principal_round = same_class()
            .filter(|e| e.work.request.principal == *principal)
            .count();
        let tenant_round = same_class().count();
        (
            u32::try_from(principal_round).unwrap_or(u32::MAX),
            u32::try_from(tenant_round).unwrap_or(u32::MAX),
        )
    }

    /// One job, if it belongs to `tenant`.
    ///
    /// Another tenant's job is reported as absent rather than forbidden.
    /// Appendix B bounds management visibility to the caller's tenant, and a
    /// `403` here would confirm that an identifier the caller guessed exists.
    #[must_use]
    pub fn get(&self, id: &JobId, tenant: &TenantId, now_ms: u64) -> Option<JobView> {
        let mut jobs = self.lock_jobs();
        self.sweep_locked(&mut jobs, now_ms);
        jobs.get(id)
            .filter(|job| job.tenant == *tenant)
            .map(|job| job.view.clone())
    }

    /// A job's result body, if it belongs to `tenant` and succeeded.
    #[must_use]
    pub fn result(&self, id: &JobId, tenant: &TenantId, now_ms: u64) -> Option<Vec<u8>> {
        let mut jobs = self.lock_jobs();
        self.sweep_locked(&mut jobs, now_ms);
        jobs.get(id)
            .filter(|job| job.tenant == *tenant)
            .and_then(|job| job.result.clone())
    }

    /// A job's revision, for an events stream's cursor.
    #[must_use]
    pub fn revision(&self, id: &JobId, tenant: &TenantId) -> Option<u64> {
        self.lock_jobs()
            .get(id)
            .filter(|job| job.tenant == *tenant)
            .map(|job| job.revision)
    }

    /// Ask a job to stop.
    ///
    /// Returns the state it is in afterwards. A queued job becomes `cancelled`
    /// at once, and a worker removes it from the queue — releasing any parked
    /// demand it held — the next time it looks. A running one is flagged: its
    /// sink refuses the next event, which ends the exchange on the path a
    /// disconnected client takes, releasing its reservation and any activation
    /// lease there.
    #[must_use]
    pub fn cancel(&self, id: &JobId, tenant: &TenantId, now_wall_ms: u64, now_ms: u64) -> Option<JobView> {
        let mut jobs = self.lock_jobs();
        let job = jobs.get_mut(id).filter(|job| job.tenant == *tenant)?;
        if job.view.state.is_terminal() {
            return Some(job.view.clone());
        }
        job.cancelled.store(true, Ordering::SeqCst);
        if job.view.state == JobState::Queued {
            job.view.state = JobState::Cancelled;
            job.view.waiting_for = None;
            job.view.updated_ms = now_wall_ms;
            job.expires_ms = Some(now_ms.saturating_add(self.limits.retention_ms));
            job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
        }
        let view = job.view.clone();
        drop(jobs);
        self.work.notify_all();
        Some(view)
    }

    /// Jobs belonging to a tenant, newest first, bounded.
    #[must_use]
    pub fn list(&self, tenant: &TenantId, limit: usize, now_ms: u64) -> Vec<JobView> {
        let mut jobs = self.lock_jobs();
        self.sweep_locked(&mut jobs, now_ms);
        let mut out: Vec<JobView> = jobs
            .values()
            .filter(|job| job.tenant == *tenant)
            .map(|job| job.view.clone())
            .collect();
        out.sort_by_key(|job| std::cmp::Reverse(job.created_ms));
        out.truncate(limit.min(usize::try_from(self.limits.max_per_tenant).unwrap_or(usize::MAX)));
        out
    }

    /// Stop accepting work and wake every worker.
    ///
    /// Every job that has not started is flagged cancelled: the router is
    /// going away, and a worker must not start minutes of generation during a
    /// drain. The jobs stay in the queue for the workers to discard, because
    /// discarding is what releases the parked demand each one holds. A job
    /// already running — its pass holding its reservations — is left to
    /// finish, so the drain is bounded by the work already running rather than
    /// by the queue.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        for entry in self.lock_queue().iter().filter(|e| !e.started) {
            entry.work.cancelled.store(true, Ordering::SeqCst);
        }
        self.work.notify_all();
    }

    /// Whether the store is winding down.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// The next thing a worker should do, blocking until there is one or the
    /// store stops.
    ///
    /// A queued job that was cancelled, or ran out of patience, is handed back
    /// to be discarded. Otherwise the job [`pick`](Self::pick) chooses among
    /// those due — not backing off, not found blocked since anything changed —
    /// which stays in the queue, marked as being tried, until its pass ends.
    fn take(&self, clock: &dyn Clock, order: Option<&dyn JobOrder>) -> Option<Taken> {
        let mut queue = self.lock_queue();
        loop {
            let now = clock.now_millis();
            if let Some(position) = queue.iter().position(|e| {
                !e.trying
                    && (e.work.cancelled.load(Ordering::SeqCst)
                        || e.work.request.limits.deadline.is_expired(clock))
            }) {
                if let Some(entry) = queue.remove(position) {
                    drop(queue);
                    self.left_queue();
                    return Some(Taken::Discard {
                        expired: !entry.work.cancelled.load(Ordering::SeqCst),
                        parked: entry.parked,
                        work: entry.work,
                    });
                }
            }
            let generation = self.generation.load(Ordering::SeqCst);
            if let Some(position) = Self::pick(&queue, now, generation, order) {
                if let Some(entry) = queue.get_mut(position) {
                    entry.trying = true;
                    return Some(Taken::Try {
                        work: Arc::clone(&entry.work),
                        generation,
                        parked: entry.parked.is_some(),
                    });
                }
            }
            if self.stopping.load(Ordering::SeqCst) {
                return None;
            }
            let waiting = queue.iter().any(|e| !e.trying);
            let backing_off = queue
                .iter()
                .filter(|e| !e.trying && e.blocked_in.is_none())
                .map(|e| e.not_before_ms)
                .filter(|due| *due > now)
                .min();
            if let Some(due) = backing_off.filter(|_| !queue.iter().any(|e| !e.trying && e.blocked_in.is_some())) {
                // Only backing-off work is queued. Sleep on the router's clock
                // until the first of it is due, a tick at most, so a new
                // submission is not kept waiting long behind the sleep.
                drop(queue);
                clock.sleep(Duration::from_millis(due.saturating_sub(now)).clamp(
                    Duration::from_millis(1),
                    TICK,
                ));
                queue = self.lock_queue();
                continue;
            }
            // A timeout as well as the signal, so a worker cannot sleep through
            // a `shutdown` that raced with it going to sleep, and so blocked
            // work is tried again at least once a tick.
            let (next, _) = self
                .work
                .wait_timeout(queue, TICK)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue = next;
            if waiting {
                self.generation.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// The queue position a worker should take, if any job is due.
    fn pick(
        queue: &VecDeque<Entry>,
        now_ms: u64,
        generation: u64,
        order: Option<&dyn JobOrder>,
    ) -> Option<usize> {
        let bound = order.map_or(0, JobOrder::bound_ms);
        // One try at a time per alias, until it starts. Two idle workers woken
        // by the same freed slot would otherwise take the interactive job and
        // the next batch job together, and whichever reserved first would get
        // the slot: class would be a coin toss exactly when it matters. A try
        // that finds the slot taken is over in a moment, and one that starts
        // stops holding the alias as soon as it holds its reservations.
        let mut contested: Vec<&AliasId> = queue
            .iter()
            .filter(|e| e.trying && !e.started)
            .map(|e| &e.work.request.requested_model)
            .collect();
        contested.sort_unstable();
        let entries: Vec<hypellm_fleet::schedule::JobEntry> = queue
            .iter()
            .map(|e| {
                let due = e.is_due(now_ms, generation)
                    && contested
                        .binary_search(&&e.work.request.requested_model)
                        .is_err();
                hypellm_fleet::schedule::JobEntry {
                    seq: e.work.seq,
                    submitted_ms: e.work.submitted_ms,
                    due,
                    // Only a due job can be taken, so only a due job needs the
                    // fleet consulted about it; and with locality switched off
                    // it is not consulted at all.
                    class: match order {
                        Some(order) if due && bound != 0 => order.class(&e.work.request),
                        _ => hypellm_fleet::schedule::JobClass::Warm,
                    },
                    priority: e.work.priority,
                    principal_round: e.work.principal_round,
                    tenant_round: e.work.tenant_round,
                }
            })
            .collect();
        let picked = hypellm_fleet::schedule::pick_job(&entries, now_ms, bound)?;
        if let Some(outcome) =
            hypellm_fleet::schedule::pick_reason(&entries, picked, now_ms, bound).outcome()
        {
            if let Some(order) = order {
                order.taken_out_of_order(outcome);
            }
        }
        Some(picked)
    }

    /// End a pass that found the job waiting: back in its place, not tried
    /// again until something changes (or, after a governance refusal, until
    /// its backoff has run).
    ///
    /// `parked` is the capability the pass just counted it as parked demand
    /// for, if it was not already. Hands the work back if the job was
    /// cancelled or the store is stopping; the caller then finishes it and
    /// releases what [`Self::leave`] returns.
    #[allow(
        clippy::too_many_arguments,
        reason = "the pass's result and the two clocks; grouping them would only \
                  move the list into a struct used once"
    )]
    fn put_back(
        &self,
        work: &Arc<Work>,
        wait: Wait,
        generation: u64,
        parked: Option<Capability>,
        backoff_ms: u64,
        now_wall_ms: u64,
        now_ms: u64,
    ) -> Result<(), Option<Capability>> {
        let mut queue = self.lock_queue();
        let Some(entry) = queue.iter_mut().find(|e| e.work.id == work.id) else {
            // Not queued any more: nothing else removes a job being tried, so
            // this is a defect, and the job is finished rather than lost.
            return Err(parked);
        };
        if parked.is_some() && entry.parked.is_none() {
            entry.parked = parked;
        }
        if self.stopping.load(Ordering::SeqCst) || work.cancelled.load(Ordering::SeqCst) {
            entry.trying = false;
            drop(queue);
            return Err(self.leave(&work.id));
        }
        entry.trying = false;
        entry.started = false;
        match wait {
            Wait::Slot | Wait::Activation => entry.blocked_in = Some(generation),
            Wait::Backoff => {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.blocked_in = None;
                entry.not_before_ms = now_ms.saturating_add(backoff_ms);
            }
        }
        drop(queue);

        let mut jobs = self.lock_jobs();
        if let Some(job) = jobs.get_mut(&work.id) {
            if job.view.state.is_terminal() {
                return Ok(());
            }
            let eta = if wait == Wait::Backoff { backoff_ms } else { 0 };
            let changed = job.view.state != JobState::Queued
                || job.view.waiting_for != Some(wait.as_str())
                || job.view.eta_ms != eta;
            if changed {
                job.view.state = JobState::Queued;
                job.view.waiting_for = Some(wait.as_str());
                job.view.eta_ms = eta;
                job.view.updated_ms = now_wall_ms;
                job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    /// Governance refusals this job has had, for its next backoff.
    fn attempts(&self, id: &JobId) -> u32 {
        self.lock_queue()
            .iter()
            .find(|e| e.work.id == *id)
            .map_or(0, |e| e.attempts)
    }

    /// Remove a job from the queue for good, returning the parked demand it
    /// held so the caller releases it exactly once.
    fn leave(&self, id: &JobId) -> Option<Capability> {
        let removed = {
            let mut queue = self.lock_queue();
            let position = queue.iter().position(|e| e.work.id == *id);
            position.and_then(|p| queue.remove(p))
        };
        self.left_queue();
        removed.and_then(|e| e.parked)
    }

    /// A job left the queue, which may have freed a slot another is blocked
    /// on: move the generation on and wake every worker.
    fn left_queue(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.work.notify_all();
    }

    /// Move a job to `Running`: its pass holds every reservation it needs.
    ///
    /// Called from the job's sink, and idempotent, because a pass that fails
    /// over is admitted once per candidate. A cancelled job stays cancelled.
    fn started(&self, id: &JobId, now_wall_ms: u64) {
        if let Some(entry) = self.lock_queue().iter_mut().find(|e| e.work.id == *id) {
            entry.started = true;
        }
        let mut jobs = self.lock_jobs();
        let Some(job) = jobs.get_mut(id) else {
            return;
        };
        if job.view.state != JobState::Queued || job.cancelled.load(Ordering::SeqCst) {
            return;
        }
        job.view.state = JobState::Running;
        job.view.waiting_for = None;
        job.view.eta_ms = 0;
        job.view.updated_ms = now_wall_ms;
        job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
    }

    /// Record a running artifact job's progress, as its shim reports it.
    fn progress(&self, id: &JobId, permille: u32, eta_ms: u64, now_wall_ms: u64) {
        let mut jobs = self.lock_jobs();
        let Some(job) = jobs.get_mut(id) else {
            return;
        };
        let permille = permille.min(1_000);
        if job.view.state != JobState::Running
            || (job.view.progress_permille == permille && job.view.eta_ms == eta_ms)
        {
            return;
        }
        job.view.progress_permille = permille;
        job.view.eta_ms = eta_ms;
        job.view.updated_ms = now_wall_ms;
        job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
    }

    /// Record a succeeded artifact job's spooled parts.
    fn finish_parts(
        &self,
        id: &JobId,
        parts: Vec<crate::spool::SpooledPart>,
        spooled_bytes: u64,
        now_wall_ms: u64,
        now_ms: u64,
    ) {
        let mut jobs = self.lock_jobs();
        let Some(job) = jobs.get_mut(id) else {
            drop(jobs);
            // Swept while it ran: nothing will ever serve these parts.
            if let Some(spool) = &self.spool {
                spool.remove(id, spooled_bytes);
            }
            return;
        };
        job.view.state = JobState::Succeeded;
        job.view.progress_permille = 1_000;
        job.view.eta_ms = 0;
        job.view.waiting_for = None;
        job.view.updated_ms = now_wall_ms;
        job.view.result_bytes =
            usize::try_from(spooled_bytes).unwrap_or(usize::MAX);
        job.view.parts = parts
            .iter()
            .map(|p| PartView {
                name: p.name.as_str().to_owned(),
                media_type: p.media_type.as_str(),
                bytes: p.bytes,
                sha256: hex::encode(&p.sha256),
            })
            .collect();
        job.parts = parts;
        job.spooled_bytes = spooled_bytes;
        job.expires_ms = Some(now_ms.saturating_add(self.limits.retention_ms));
        job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
    }

    /// One of a succeeded artifact job's parts, opened for reading: the named
    /// one, or the first.
    #[must_use]
    pub fn part(
        &self,
        id: &JobId,
        tenant: &TenantId,
        name: Option<&str>,
        now_ms: u64,
    ) -> Option<(crate::spool::SpooledPart, std::fs::File)> {
        let part = {
            let mut jobs = self.lock_jobs();
            self.sweep_locked(&mut jobs, now_ms);
            let job = jobs.get(id).filter(|job| job.tenant == *tenant)?;
            match name {
                None => job.parts.first().cloned(),
                Some(name) => job.parts.iter().find(|p| p.name.as_str() == name).cloned(),
            }?
        };
        let file = self.spool.as_ref()?.open_part(id, &part.name).ok()?;
        Some((part, file))
    }

    /// Record a terminal state, with the result or the error.
    fn finish(
        &self,
        id: &JobId,
        state: JobState,
        result: Option<Vec<u8>>,
        error: Option<(String, String)>,
        now_wall_ms: u64,
        now_ms: u64,
    ) {
        let mut jobs = self.lock_jobs();
        let Some(job) = jobs.get_mut(id) else {
            return;
        };
        // A result larger than the spool allows is not truncated: half a
        // response body is not a response, and a caller that received one would
        // have no way to tell. The job fails, naming the bound.
        let (state, result, error) = match result {
            Some(bytes) if bytes.len() > self.limits.max_result_bytes => (
                JobState::Failed,
                None,
                Some((
                    "job_result_too_large".to_owned(),
                    format!(
                        "the result is {} bytes, beyond this router's {}-byte job spool",
                        bytes.len(),
                        self.limits.max_result_bytes
                    ),
                )),
            ),
            other => (state, other, error),
        };

        job.view.state = state;
        job.view.progress_permille = if state == JobState::Succeeded { 1_000 } else { 0 };
        job.view.eta_ms = 0;
        job.view.waiting_for = None;
        job.view.updated_ms = now_wall_ms;
        job.view.result_bytes = result.as_ref().map_or(0, Vec::len);
        if let Some((code, message)) = error {
            job.view.error_code = Some(code);
            job.view.error_message = Some(message);
        }
        job.result = result;
        job.expires_ms = Some(now_ms.saturating_add(self.limits.retention_ms));
        job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
    }

    /// Drop terminal jobs whose retention window has closed.
    ///
    /// Called from every path that reads the table, rather than from a timer,
    /// so retention does not depend on a sweeper having run recently — and so
    /// the per-tenant cap counts what is actually readable.
    ///
    /// An expired job's spooled parts go with it. That is file removal under
    /// the table's lock — at most four files a job, and only at expiry.
    fn sweep_locked(&self, jobs: &mut BTreeMap<JobId, Job>, now_ms: u64) {
        jobs.retain(|id, job| {
            let keep = job.expires_ms.is_none_or(|expiry| now_ms < expiry);
            if !keep && job.spooled_bytes > 0 {
                if let Some(spool) = &self.spool {
                    spool.remove(id, job.spooled_bytes);
                }
            }
            keep
        });
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, BTreeMap<JobId, Job>> {
        self.jobs.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Entry>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl hypellm_admin_api::JobQueue for JobStore {
    fn queue(&self, tenant: &TenantId) -> Vec<hypellm_admin_api::QueuedJob> {
        // The queue first and the table after, never both held: the order the
        // rest of the store takes them in when it takes both is queue, then
        // table, and a reader is not the place to invent the other order.
        let mut waiting: Vec<(bool, Arc<Work>)> = self
            .lock_queue()
            .iter()
            .filter(|e| e.work.request.tenant == *tenant)
            .map(|e| (e.started, Arc::clone(&e.work)))
            .collect();
        waiting.sort_by_key(|(started, work)| {
            (
                !*started,
                work.priority,
                work.principal_round,
                work.tenant_round,
                work.seq,
            )
        });
        let jobs = self.lock_jobs();
        waiting
            .iter()
            .filter_map(|(_, work)| {
                let job = jobs.get(&work.id)?;
                if job.view.state.is_terminal() {
                    return None;
                }
                Some(hypellm_admin_api::QueuedJob {
                    id: work.id.as_str().to_owned(),
                    principal: work.request.principal.clone(),
                    alias: work.request.requested_model.clone(),
                    class: work.priority,
                    round: work.principal_round,
                    state: job.view.state.as_str(),
                    waiting_for: job.view.waiting_for,
                    created_ms: job.view.created_ms,
                })
            })
            .collect()
    }
}

/// The sink a job's pass writes to.
///
/// Accumulates like any buffered request. Two differences: admission moves the
/// job to `running`, so `queued` means waiting and nothing else; and a
/// cancelled job refuses the next event, which ends the exchange on the path a
/// client that disconnected takes — reservations and leases released there.
struct JobSink<'a> {
    inner: AccumulatingSink,
    jobs: &'a JobStore,
    id: &'a JobId,
    cancelled: &'a AtomicBool,
    clock: &'a dyn Clock,
}

impl EventSink for JobSink<'_> {
    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(SinkClosed);
        }
        self.inner.deliver(event)
    }

    fn keepalive(&mut self) -> Result<(), SinkClosed> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(SinkClosed);
        }
        Ok(())
    }

    fn admitted(&mut self) {
        self.jobs.started(self.id, self.clock.wall_millis());
    }
}

/// Run one worker until the store stops.
///
/// One fixed thread, started at boot. A request never creates one
/// (specification 3.2), and the pool size is what bounds how much long-running
/// work the router will do at once.
pub fn worker_loop(state: &Arc<RouterState>) {
    let Some(jobs) = state.jobs() else {
        return;
    };
    let order = FleetJobOrder { state };
    while let Some(taken) = jobs.take(state.clock.as_ref(), Some(&order)) {
        match taken {
            Taken::Discard {
                work,
                parked,
                expired,
            } => {
                release_parked(state, &work.request.requested_model, work.priority, parked);
                if expired {
                    count_expired(state, work.priority);
                    jobs.finish(
                        &work.id,
                        JobState::Failed,
                        None,
                        Some((
                            ErrorCode::DeadlineExceeded.as_str().to_owned(),
                            "the job's patience ran out while it waited".to_owned(),
                        )),
                        state.clock.wall_millis(),
                        state.clock.now_millis(),
                    );
                }
            }
            Taken::Try {
                work,
                generation,
                parked,
            } => run_pass(state, jobs, &work, generation, parked),
        }
    }
}

/// One pass of one job, and what follows from it.
fn run_pass(state: &RouterState, jobs: &JobStore, work: &Arc<Work>, generation: u64, parked: bool) {
    let clock = state.clock.as_ref();
    let mut sink = JobSink {
        inner: AccumulatingSink::default(),
        jobs,
        id: &work.id,
        cancelled: &work.cancelled,
        clock,
    };
    let progress = |permille: u32, eta_ms: u64| {
        jobs.progress(&work.id, permille, eta_ms, clock.wall_millis());
    };
    let artifact = match (&work.artifact, &jobs.spool) {
        (Some(spec), Some(spool)) => Some(crate::job_exchange::ArtifactRun {
            job: &work.id,
            spec,
            spool,
            cancelled: &work.cancelled,
            progress: &progress,
            poll_ms: jobs.poll_ms,
            output: std::sync::Mutex::new(crate::job_exchange::RunOutput::default()),
        }),
        _ => None,
    };
    if work.artifact.is_some() && artifact.is_none() {
        // Submission refuses an artifact job on a store with no spool, so this
        // is not reachable from a request; it is answered rather than assumed.
        release_parked(
            state,
            &work.request.requested_model,
            work.priority,
            jobs.leave(&work.id),
        );
        jobs.finish(
            &work.id,
            JobState::Failed,
            None,
            Some((
                ErrorCode::InternalFault.as_str().to_owned(),
                "this router has no job spool".to_owned(),
            )),
            clock.wall_millis(),
            clock.now_millis(),
        );
        return;
    }
    let outcome = pipeline::execute_job_pass(
        state,
        &work.request,
        &work.groups,
        work.permissions.clone(),
        work.key_id.as_ref(),
        &mut sink,
        parked,
        artifact.as_ref(),
    );
    let now_wall = clock.wall_millis();
    let now = clock.now_millis();
    let run_output = artifact
        .map(|run| run.output.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner));

    // A shim that ran out of memory, has not loaded its model, or a spool with
    // no room: the job waits and tries again, as for a governance refusal.
    let raw_wait = if run_output.as_ref().is_some_and(|o| o.waits_for_capacity) && !outcome.is_success() {
        Some(Wait::Backoff)
    } else {
        wait_of(&outcome)
    };
    let cancelled = work.cancelled.load(Ordering::SeqCst);
    // A job that was still only waiting when its patience ran out failed for
    // that reason, whatever the last pass happened to be refused for.
    let expired_waiting =
        raw_wait.is_some() && !cancelled && work.request.limits.deadline.is_expired(clock);
    let wait = raw_wait.filter(|_| !cancelled && !expired_waiting);
    if let Some(wait) = wait {
        let attempts = match wait {
            Wait::Backoff => jobs.attempts(&work.id).saturating_add(1),
            Wait::Slot | Wait::Activation => 0,
        };
        if attempts < MAX_JOB_ATTEMPTS {
            let newly_parked = if wait == Wait::Activation && !parked {
                park(state, &work.request.requested_model, work.priority)
            } else {
                None
            };
            let backoff = requeue_backoff_ms(attempts).min(
                u64::try_from(work.request.limits.deadline.remaining(clock).as_millis())
                    .unwrap_or(u64::MAX),
            );
            match jobs.put_back(work, wait, generation, newly_parked, backoff, now_wall, now) {
                Ok(()) => return,
                // Cancelled or shutting down meanwhile: it has left the queue,
                // and is finished below as any other ended pass is.
                Err(released) => {
                    release_parked(state, &work.request.requested_model, work.priority, released);
                }
            }
        } else {
            release_parked(
                state,
                &work.request.requested_model,
                work.priority,
                jobs.leave(&work.id),
            );
        }
    } else {
        release_parked(
                state,
                &work.request.requested_model,
                work.priority,
                jobs.leave(&work.id),
            );
    }

    // Recorded once per job, for the pass that ended it, the same way an
    // interactive request is, so usage, quota and the decision trace do not
    // depend on which endpoint was used. A pass that only found the job
    // waiting is not a completed request.
    pipeline::record_completion(state, &work.request, &outcome, 0, work.key_id.as_ref());

    if work.cancelled.load(Ordering::SeqCst) {
        jobs.finish(
            &work.id,
            JobState::Cancelled,
            None,
            Some((
                "cancelled".to_owned(),
                "the job was cancelled by its caller".to_owned(),
            )),
            now_wall,
            now,
        );
        return;
    }
    if expired_waiting {
        count_expired(state, work.priority);
        jobs.finish(
            &work.id,
            JobState::Failed,
            None,
            Some((
                ErrorCode::DeadlineExceeded.as_str().to_owned(),
                "the job's patience ran out while it waited".to_owned(),
            )),
            now_wall,
            now,
        );
        return;
    }
    if let (None, Some(output)) = (&outcome.error, run_output) {
        jobs.finish_parts(&work.id, output.parts, output.spooled_bytes, now_wall, now);
        return;
    }
    match &outcome.error {
        Some(error) => {
            if error.code == ErrorCode::DeadlineExceeded {
                count_expired(state, work.priority);
            }
            jobs.finish(
                &work.id,
                JobState::Failed,
                None,
                Some((
                    error.code.as_str().to_owned(),
                    error.detail.as_str().to_owned(),
                )),
                now_wall,
                now,
            );
        }
        None => match render_result(state, &work.request, &sink.inner) {
            Ok(payload) => jobs.finish(
                &work.id,
                JobState::Succeeded,
                Some(payload),
                None,
                now_wall,
                now,
            ),
            // The upstream's output could not be represented faithfully
            // (for example tool arguments that are not a JSON object): the
            // job failed, rather than succeeding with a substituted body.
            Err(error) => jobs.finish(
                &work.id,
                JobState::Failed,
                None,
                Some((
                    error.code.as_str().to_owned(),
                    error.detail.as_str().to_owned(),
                )),
                now_wall,
                now,
            ),
        },
    }
}

/// Count a queued job as parked demand for its model (specification 26.10),
/// as a parked request is counted: in the batching queue for its capability,
/// which bounds it, and against its alias, by class, for the scheduler.
///
/// From submission, so the demand and its age are there while the job waits
/// for a worker as well as while it waits for a slot: forty songs queued
/// behind two busy workers are forty songs' demand to the batching trigger,
/// to eviction value and to idle stop, not two. `None` when there is no fleet,
/// the alias declares no capability, or jobs already hold their half of the
/// capability's queue — the other half is kept for requests that hold a
/// connection and can wait nowhere else.
pub(crate) fn park(state: &RouterState, alias: &AliasId, class: PriorityClass) -> Option<Capability> {
    let fleet = state.fleet()?;
    let capability = state
        .config()
        .snapshot
        .aliases
        .get(alias)
        .and_then(|record| record.capability)?;
    if !fleet.park_job(capability) {
        return None;
    }
    fleet.park_alias(alias, class);
    Some(capability)
}

/// Undo [`park`], once.
pub(crate) fn release_parked(
    state: &RouterState,
    alias: &AliasId,
    class: PriorityClass,
    parked: Option<Capability>,
) {
    let (Some(capability), Some(fleet)) = (parked, state.fleet()) else {
        return;
    };
    fleet.unpark_alias(alias, class);
    fleet.unpark(capability);
}

/// Count a job whose patience ran out before it finished, by class: the
/// evidence an operator needs to tell whether batch work is being held for
/// good by the classes above it.
fn count_expired(state: &RouterState, class: PriorityClass) {
    state.telemetry.count(
        hypellm_telemetry::names::JOBS_EXPIRED_WAITING,
        "Jobs whose patience ran out before they finished, by priority class.",
        &hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Class, class.as_str()),
    );
}

/// The router's job order: the fleet's view of each job's model
/// (specification 26.11).
struct FleetJobOrder<'a> {
    state: &'a RouterState,
}

impl JobOrder for FleetJobOrder<'_> {
    fn bound_ms(&self) -> u64 {
        self.state
            .fleet()
            .map_or(0, |fleet| fleet.max_reorder_wait_ms())
    }

    fn class(&self, request: &CanonicalRequest) -> hypellm_fleet::schedule::JobClass {
        let Some(fleet) = self.state.fleet() else {
            return hypellm_fleet::schedule::JobClass::Warm;
        };
        let config = self.state.config();
        config
            .snapshot
            .aliases
            .get(&request.requested_model)
            .map_or(hypellm_fleet::schedule::JobClass::Warm, |alias| {
                fleet.job_class(&alias.permitted_targets)
            })
    }

    fn taken_out_of_order(&self, outcome: &'static str) {
        self.state.telemetry.count(
            hypellm_telemetry::names::FLEET_SCHEDULE_DECISIONS,
            "Churn-aware scheduling decisions, by host and outcome.",
            &hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Outcome, outcome),
        );
    }
}

/// Whether a failed pass failed only for want of capacity, and how the job
/// should wait for it.
///
/// Nothing may have been sent: every attempt failed before acceptance, or none
/// was made. A key-budget refusal is not capacity (specification 12.2 ends the
/// request), and neither is anything else the trace records.
fn wait_of(outcome: &pipeline::Outcome) -> Option<Wait> {
    if outcome.is_success() || outcome.saw_output {
        return None;
    }
    let before_acceptance = outcome
        .trace
        .attempts
        .iter()
        .all(|a| matches!(a.outcome, AttemptOutcome::FailedBeforeAcceptance(_)));
    let exclusions = &outcome.trace.exclusions;
    if !before_acceptance
        || exclusions
            .iter()
            .any(|e| e.reason == ExclusionReason::BudgetExceeded)
    {
        return None;
    }
    let any = |reasons: &[ExclusionReason]| exclusions.iter().any(|e| reasons.contains(&e.reason));
    if any(&[
        ExclusionReason::ActivationQueued,
        ExclusionReason::DeploymentInDwell,
        ExclusionReason::EvictionValueInsufficient,
    ]) {
        Some(Wait::Activation)
    } else if any(&[ExclusionReason::CapacityExhausted]) {
        Some(Wait::Slot)
    } else if any(&[
        ExclusionReason::ActivationBudgetExhausted,
        ExclusionReason::HostCapacityInsufficient,
    ]) {
        Some(Wait::Backoff)
    } else {
        None
    }
}

/// The backoff before the pass after governance refusal `attempts`: doubling
/// from one second, capped.
fn requeue_backoff_ms(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(16);
    FIRST_REQUEUE_BACKOFF_MS
        .saturating_mul(1_u64 << shift)
        .min(MAX_REQUEUE_BACKOFF_MS)
}

/// Render a completed job's response in the dialect it was submitted in.
fn render_result(
    state: &RouterState,
    request: &CanonicalRequest,
    sink: &AccumulatingSink,
) -> Result<Vec<u8>, RouterError> {
    let seconds = crate::routes::wall_seconds(state.clock.as_ref());
    let rendered = match request.protocol {
        ClientProtocol::AnthropicMessages => {
            crate::protocol::anthropic::try_render_message_response(request, &sink.accumulator)?
        }
        ClientProtocol::OpenAiEmbeddings => {
            crate::protocol::openai::render_embeddings_response(request, &sink.accumulator)
        }
        ClientProtocol::OpenAiResponses => crate::protocol::openai::render_responses_response(
            request,
            &sink.accumulator,
            seconds,
        ),
        _ => crate::protocol::openai::render_chat_response(request, &sink.accumulator, seconds),
    };
    Ok(rendered.into_bytes())
}

/// The JSON body describing a job.
#[must_use]
pub fn job_body(view: &JobView) -> Value {
    let mut root = Object::new();
    root.push("job_id", Value::from(view.id.as_str()));
    root.push("state", Value::from(view.state.as_str()));
    root.push("progress_permille", Value::from(u64::from(view.progress_permille)));
    root.push("eta_ms", Value::from(view.eta_ms));
    root.push("created_ms", Value::from(view.created_ms));
    root.push("updated_ms", Value::from(view.updated_ms));
    root.push("result_bytes", Value::from(u64::try_from(view.result_bytes).unwrap_or(u64::MAX)));
    root.push("class", Value::from(view.class.as_str()));
    if let Some(waiting_for) = view.waiting_for {
        root.push("waiting_for", Value::from(waiting_for));
    }
    if !view.parts.is_empty() {
        let parts = view
            .parts
            .iter()
            .map(|part| {
                let mut object = Object::new();
                object.push("name", Value::from(part.name.as_str()));
                object.push("media_type", Value::from(part.media_type));
                object.push("bytes", Value::from(part.bytes));
                object.push("sha256", Value::from(part.sha256.as_str()));
                Value::Object(object)
            })
            .collect();
        root.push("parts", Value::Array(parts));
    }
    if let (Some(code), Some(message)) = (&view.error_code, &view.error_message) {
        let mut error = Object::new();
        error.push("code", Value::from(code.as_str()));
        error.push("message", Value::from(message.as_str()));
        root.push("error", Value::Object(error));
    }
    Value::Object(root)
}
