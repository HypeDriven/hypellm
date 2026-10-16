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
//! | Queued jobs | `settings max_queued_jobs`, fleet-wide; a full queue is a `429` |
//! | Live jobs per tenant | `settings max_jobs_per_tenant`; the cap counts terminal jobs too, until they expire |
//! | Result bytes | `settings max_job_result_bytes` per job, held in memory |
//! | Retention | `settings job_retention_ms` after reaching a terminal state |
//! | Patience | `settings max_job_patience_ms`, the ceiling on what a caller may ask to wait |
//! | Re-queues | [`MAX_JOB_ATTEMPTS`] passes per job, backing off, within the job's deadline |
//!
//! # Waiting for capacity
//!
//! A job that fails only because no slave could take it yet — the model it
//! needs is queued to start, a host is busy activating something else, every
//! warm target is at its concurrency limit — goes back to the end of the queue
//! rather than failing (specification 26.10). Bounded three ways: at most
//! [`MAX_JOB_ATTEMPTS`] passes, an exponential backoff between them, and the
//! job's own deadline. A re-queued job is one the store already admitted, so it
//! is not refused by `max_queued`; the queue therefore holds at most
//! `max_queued` plus one per worker.
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

use crate::dispatch::AccumulatingSink;
use crate::pipeline;
use crate::state::RouterState;
use hypellm_core::canonical::{CanonicalRequest, ClientProtocol};
use hypellm_core::decision::{AttemptOutcome, ExclusionReason};
use hypellm_core::time::Clock;
use hypellm_core::error::RouterError;
use hypellm_core::ids::{GroupId, KeyId, TenantId};
use hypellm_core::rbac::PermissionSet;
use hypellm_crypto::{hex, random};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
}

/// A job's full record, including what only the router sees.
#[derive(Debug)]
struct Job {
    view: JobView,
    tenant: TenantId,
    /// The rendered response body, once succeeded.
    result: Option<Vec<u8>>,
    /// When a terminal job stops being readable, in monotonic milliseconds.
    expires_ms: Option<u64>,
    /// Set by `DELETE`; read by the worker between steps.
    cancelled: Arc<AtomicBool>,
    /// Monotonically increasing, so an events stream can resume.
    revision: u64,
}

/// Passes one job may make through the pipeline, the first included.
pub const MAX_JOB_ATTEMPTS: u32 = 16;

/// The first re-queue backoff, doubling per pass.
const FIRST_REQUEUE_BACKOFF_MS: u64 = 1_000;

/// The longest re-queue backoff.
const MAX_REQUEUE_BACKOFF_MS: u64 = 60_000;

/// Work handed to a worker thread.
#[derive(Debug)]
struct Pending {
    id: JobId,
    request: CanonicalRequest,
    groups: Vec<GroupId>,
    permissions: PermissionSet,
    key_id: Option<KeyId>,
    cancelled: Arc<AtomicBool>,
    /// Passes already made.
    attempts: u32,
    /// Not to be taken before this, on the router's monotonic clock.
    not_before_ms: u64,
    /// Submission order, kept across re-queues (specification 26.11).
    seq: u64,
    /// When it was submitted, on the router's monotonic clock: the age the
    /// reordering bound is measured from, so a job that waited for capacity
    /// keeps the time it has already waited.
    submitted_ms: u64,
}

/// How the job queue is ordered when a worker takes from it
/// (specification 26.11).
///
/// Implemented by the router over its fleet. Absent, or with a bound of zero,
/// jobs are taken in queue order as they always were.
pub trait JobOrder {
    /// The reordering bound, in milliseconds. Zero is queue order.
    fn bound_ms(&self) -> u64;
    /// How the request's model stands right now.
    fn class(&self, request: &CanonicalRequest) -> hypellm_fleet::schedule::JobClass;
    /// Note that a job was taken out of queue order: `job_reordered`, or
    /// `job_starving` when the bound promoted it.
    fn taken_out_of_order(&self, _outcome: &'static str) {}
}

/// Why a job could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitRefusal {
    /// The tenant already holds `max_jobs_per_tenant`.
    TenantAtCapacity,
    /// The queue is full fleet-wide.
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
    /// Jobs waiting for a worker, fleet-wide.
    pub max_queued: u32,
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
        max_result_bytes: 8 * 1024 * 1024,
        retention_ms: 900_000,
    };
}

/// The job table, its queue, and its workers.
///
/// One per router. Everything a request can grow is bounded here, in one place,
/// so a reviewer can check the whole of specification 3.2 for this endpoint
/// without reading the workers.
#[derive(Debug)]
pub struct JobStore {
    jobs: Mutex<BTreeMap<JobId, Job>>,
    queue: Mutex<VecDeque<Pending>>,
    /// Signalled on submission and on shutdown.
    work: Condvar,
    limits: JobLimits,
    stopping: AtomicBool,
    /// Monotonic revision source, so an events stream can resume from a cursor
    /// rather than replaying a job's whole history.
    revisions: AtomicU64,
    /// Submission order source.
    sequence: AtomicU64,
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
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> JobLimits {
        self.limits
    }

    /// Accept a job, or say why not.
    ///
    /// The per-tenant cap is checked under the same lock that inserts, so two
    /// simultaneous submissions cannot both see room for the last slot.
    ///
    /// # Errors
    ///
    /// [`SubmitRefusal`] when a bound is reached or entropy is unavailable.
    pub fn submit(
        &self,
        request: CanonicalRequest,
        groups: Vec<GroupId>,
        permissions: PermissionSet,
        key_id: Option<KeyId>,
        now_wall_ms: u64,
        now_ms: u64,
    ) -> Result<JobView, SubmitRefusal> {
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
            Self::sweep_locked(&mut jobs, now_ms);

            let held = jobs
                .values()
                .filter(|job| job.tenant == request.tenant)
                .count();
            if u32::try_from(held).unwrap_or(u32::MAX) >= self.limits.max_per_tenant {
                return Err(SubmitRefusal::TenantAtCapacity);
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
            };
            jobs.insert(
                id.clone(),
                Job {
                    view: view.clone(),
                    tenant: request.tenant.clone(),
                    result: None,
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
            if u32::try_from(queue.len()).unwrap_or(u32::MAX) >= self.limits.max_queued {
                // Roll back the table entry. A job that is not queued will
                // never run, and leaving it visible as `queued` would be a lie
                // that also consumed the tenant's cap until it expired.
                self.lock_jobs().remove(&id);
                return Err(SubmitRefusal::QueueFull);
            }
            queue.push_back(Pending {
                id,
                request,
                groups,
                permissions,
                key_id,
                cancelled,
                attempts: 0,
                not_before_ms: 0,
                seq: self.sequence.fetch_add(1, Ordering::SeqCst),
                submitted_ms: now_ms,
            });
        }
        self.work.notify_one();
        Ok(view)
    }

    /// One job, if it belongs to `tenant`.
    ///
    /// Another tenant's job is reported as absent rather than forbidden.
    /// Appendix B bounds management visibility to the caller's tenant, and a
    /// `403` here would confirm that an identifier the caller guessed exists.
    #[must_use]
    pub fn get(&self, id: &JobId, tenant: &TenantId, now_ms: u64) -> Option<JobView> {
        let mut jobs = self.lock_jobs();
        Self::sweep_locked(&mut jobs, now_ms);
        jobs.get(id)
            .filter(|job| job.tenant == *tenant)
            .map(|job| job.view.clone())
    }

    /// A job's result body, if it belongs to `tenant` and succeeded.
    #[must_use]
    pub fn result(&self, id: &JobId, tenant: &TenantId, now_ms: u64) -> Option<Vec<u8>> {
        let mut jobs = self.lock_jobs();
        Self::sweep_locked(&mut jobs, now_ms);
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
    /// at once; a running one is flagged and stops at its next cancellation
    /// point, which is where its reservation and any activation lease are
    /// released — by the pipeline, on the path it already takes for a client
    /// that disconnected.
    #[must_use]
    pub fn cancel(&self, id: &JobId, tenant: &TenantId, now_wall_ms: u64, now_ms: u64) -> Option<JobView> {
        let mut jobs = self.lock_jobs();
        let job = jobs.get_mut(id).filter(|job| job.tenant == *tenant)?;
        if job.view.state.is_terminal() {
            return Some(job.view.clone());
        }
        job.cancelled.store(true, Ordering::SeqCst);
        if job.view.state == JobState::Queued {
            // Nothing is running it, so nothing will observe the flag. Marked
            // terminal here; the worker skips it when it reaches the queue
            // entry.
            job.view.state = JobState::Cancelled;
            job.view.updated_ms = now_wall_ms;
            job.expires_ms = Some(now_ms.saturating_add(self.limits.retention_ms));
            job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
        }
        Some(job.view.clone())
    }

    /// Jobs belonging to a tenant, newest first, bounded.
    #[must_use]
    pub fn list(&self, tenant: &TenantId, limit: usize, now_ms: u64) -> Vec<JobView> {
        let mut jobs = self.lock_jobs();
        Self::sweep_locked(&mut jobs, now_ms);
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
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Every queued job is cancelled: the router is going away, and a client
        // polling one after the restart would otherwise be told `queued` by a
        // process that will never run it.
        for pending in self.lock_queue().drain(..) {
            pending.cancelled.store(true, Ordering::SeqCst);
        }
        self.work.notify_all();
    }

    /// Whether the store is winding down.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Take the next job that is due, blocking until one is or the store
    /// stops.
    ///
    /// In queue order unless `order` reorders it (specification 26.11): jobs
    /// whose model is loaded first, then jobs for a model being loaded, then
    /// cold jobs grouped by model, all bounded by the reordering bound. A
    /// re-queued job backing off is skipped, not waited for, so it holds no
    /// worker and delays nothing behind it.
    fn take(&self, clock: &dyn Clock, order: Option<&dyn JobOrder>) -> Option<Pending> {
        let mut queue = self.lock_queue();
        loop {
            let now = clock.now_millis();
            if let Some(position) = Self::pick(&queue, now, order) {
                if let Some(pending) = queue.remove(position) {
                    return Some(pending);
                }
            }
            if self.stopping.load(Ordering::SeqCst) {
                return None;
            }
            if let Some(due) = queue.iter().map(|p| p.not_before_ms).min() {
                // Only backing-off work is queued. Sleep on the router's clock
                // until the first of it is due, a quarter second at most, so a
                // new submission is not kept waiting long behind the sleep.
                drop(queue);
                clock.sleep(std::time::Duration::from_millis(
                    due.saturating_sub(now).clamp(1, 250),
                ));
                queue = self.lock_queue();
                continue;
            }
            // A timeout as well as the signal, so a worker cannot sleep through
            // a `shutdown` that raced with it going to sleep.
            let (next, _) = self
                .work
                .wait_timeout(queue, std::time::Duration::from_millis(250))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue = next;
        }
    }

    /// The queue position a worker should take, if any job is due.
    fn pick(queue: &VecDeque<Pending>, now_ms: u64, order: Option<&dyn JobOrder>) -> Option<usize> {
        let first_due = queue.iter().position(|p| p.not_before_ms <= now_ms);
        let Some(order) = order else {
            return first_due;
        };
        let bound = order.bound_ms();
        if bound == 0 || first_due.is_none() {
            return first_due;
        }
        let entries: Vec<hypellm_fleet::schedule::JobEntry> = queue
            .iter()
            .map(|p| {
                let due = p.not_before_ms <= now_ms;
                hypellm_fleet::schedule::JobEntry {
                    seq: p.seq,
                    submitted_ms: p.submitted_ms,
                    due,
                    // Only a due job can be taken, so only a due job needs
                    // the fleet consulted about it.
                    class: if due {
                        order.class(&p.request)
                    } else {
                        hypellm_fleet::schedule::JobClass::Warm
                    },
                }
            })
            .collect();
        let picked = hypellm_fleet::schedule::pick_job(&entries, now_ms, bound)?;
        // "Out of order" against submission order among due jobs, which is
        // what a caller would have expected.
        let earliest = entries
            .iter()
            .filter(|e| e.due)
            .map(|e| e.seq)
            .min()
            .unwrap_or(0);
        let chosen = entries.get(picked)?;
        if chosen.seq != earliest {
            order.taken_out_of_order("job_reordered");
        } else if now_ms.saturating_sub(chosen.submitted_ms) >= bound {
            order.taken_out_of_order("job_starving");
        }
        Some(picked)
    }

    /// Put a job back at the end of the queue to try again after `backoff_ms`.
    ///
    /// Hands the job back, untouched, if it was cancelled or the store is
    /// stopping; the caller then finishes it.
    fn requeue(
        &self,
        mut pending: Pending,
        backoff_ms: u64,
        now_wall_ms: u64,
        now_ms: u64,
    ) -> Result<(), Box<Pending>> {
        if self.stopping.load(Ordering::SeqCst) || pending.cancelled.load(Ordering::SeqCst) {
            return Err(Box::new(pending));
        }
        {
            let mut jobs = self.lock_jobs();
            let Some(job) = jobs.get_mut(&pending.id) else {
                return Err(Box::new(pending));
            };
            if job.view.state.is_terminal() {
                return Err(Box::new(pending));
            }
            job.view.state = JobState::Queued;
            job.view.eta_ms = backoff_ms;
            job.view.updated_ms = now_wall_ms;
            job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
        }
        pending.not_before_ms = now_ms.saturating_add(backoff_ms);
        self.lock_queue().push_back(pending);
        self.work.notify_one();
        Ok(())
    }

    /// Move a job to `Running`, unless it was cancelled first.
    fn begin(&self, id: &JobId, now_wall_ms: u64) -> bool {
        let mut jobs = self.lock_jobs();
        let Some(job) = jobs.get_mut(id) else {
            return false;
        };
        if job.view.state.is_terminal() || job.cancelled.load(Ordering::SeqCst) {
            return false;
        }
        job.view.state = JobState::Running;
        job.view.updated_ms = now_wall_ms;
        job.revision = self.revisions.fetch_add(1, Ordering::SeqCst);
        true
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
    fn sweep_locked(jobs: &mut BTreeMap<JobId, Job>, now_ms: u64) {
        jobs.retain(|_, job| job.expires_ms.is_none_or(|expiry| now_ms < expiry));
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, BTreeMap<JobId, Job>> {
        self.jobs.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Pending>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
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
    let fleet_order = FleetJobOrder { state };
    let order: Option<&dyn JobOrder> = if state.fleet().is_some() {
        Some(&fleet_order)
    } else {
        None
    };
    while let Some(mut pending) = jobs.take(state.clock.as_ref(), order) {
        let now_wall = state.clock.wall_millis();
        if !jobs.begin(&pending.id, now_wall) {
            // Cancelled between submission and pickup. Nothing was reserved and
            // nothing needs releasing.
            continue;
        }

        let mut sink = AccumulatingSink::default();
        let outcome = pipeline::execute_for_key(
            state,
            &pending.request,
            &pending.groups,
            pending.permissions.clone(),
            pending.key_id.as_ref(),
            &mut sink,
        );
        let now_wall = state.clock.wall_millis();
        let now = state.clock.now_millis();

        // Recorded the same way an interactive request is, so usage, quota and
        // the decision trace do not depend on which endpoint was used.
        pipeline::record_completion(
            state,
            &pending.request,
            &outcome,
            0,
            pending.key_id.as_ref(),
        );

        if pending.cancelled.load(Ordering::SeqCst) {
            jobs.finish(
                &pending.id,
                JobState::Cancelled,
                None,
                Some((
                    "cancelled".to_owned(),
                    "the job was cancelled by its caller".to_owned(),
                )),
                now_wall,
                now,
            );
            continue;
        }

        pending.attempts = pending.attempts.saturating_add(1);
        if waits_for_capacity(&outcome)
            && pending.attempts < MAX_JOB_ATTEMPTS
            && !pending.request.limits.deadline.is_expired(state.clock.as_ref())
        {
            let backoff = requeue_backoff_ms(pending.attempts)
                .min(u64::try_from(
                    pending
                        .request
                        .limits
                        .deadline
                        .remaining(state.clock.as_ref())
                        .as_millis(),
                ).unwrap_or(u64::MAX));
            match jobs.requeue(pending, backoff, now_wall, now) {
                Ok(()) => continue,
                // Cancelled or shutting down meanwhile: finished below, as
                // any other failed pass is.
                Err(back) => pending = *back,
            }
        }

        match &outcome.error {
            Some(error) => jobs.finish(
                &pending.id,
                JobState::Failed,
                None,
                Some((
                    error.code.as_str().to_owned(),
                    error.detail.as_str().to_owned(),
                )),
                now_wall,
                now,
            ),
            None => match render_result(state, &pending.request, &sink) {
                Ok(payload) => jobs.finish(
                    &pending.id,
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
                    &pending.id,
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
        if let Some(fleet) = self.state.fleet() {
            fleet.count_job_schedule(outcome);
        }
    }
}

/// Whether a failed pass failed only for want of capacity, so the job may wait
/// for a slave to become available and try again.
///
/// Nothing may have been sent: every attempt failed before acceptance, or none
/// was made. A key-budget refusal is not capacity (specification 12.2 ends the
/// request), and neither is anything else the trace records.
fn waits_for_capacity(outcome: &pipeline::Outcome) -> bool {
    if outcome.is_success() || outcome.saw_output {
        return false;
    }
    let before_acceptance = outcome
        .trace
        .attempts
        .iter()
        .all(|a| matches!(a.outcome, AttemptOutcome::FailedBeforeAcceptance(_)));
    let exclusions = &outcome.trace.exclusions;
    before_acceptance
        && !exclusions
            .iter()
            .any(|e| e.reason == ExclusionReason::BudgetExceeded)
        && exclusions.iter().any(|e| {
            matches!(
                e.reason,
                ExclusionReason::ActivationQueued
                    | ExclusionReason::CapacityExhausted
                    | ExclusionReason::ActivationBudgetExhausted
                    | ExclusionReason::HostCapacityInsufficient
                    | ExclusionReason::DeploymentInDwell
                    | ExclusionReason::EvictionValueInsufficient
            )
        })
}

/// The backoff before pass `attempts + 1`: doubling from one second, capped.
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
    if let (Some(code), Some(message)) = (&view.error_code, &view.error_message) {
        let mut error = Object::new();
        error.push("code", Value::from(code.as_str()));
        error.push("message", Value::from(message.as_str()));
        root.push("error", Value::Object(error));
    }
    Value::Object(root)
}
