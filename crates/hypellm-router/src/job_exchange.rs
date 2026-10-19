//! One artifact job's exchanges with its shim (orchestration §11.3–§11.5).
//!
//! An artifact job is not one exchange. It is a submit, a poll every
//! `poll_ms` until the shim reports a terminal state, and then a fetch of each
//! part into the [`Spool`]. [`run`] is the whole of it, called by the pipeline
//! in place of a single-exchange attempt once every reservation the job needs
//! is held — so the target's concurrency slot, the key's admission and the
//! deployment's in-flight count are held for the whole generation, released
//! when the shim reports a terminal state and not before.
//!
//! # What the shim cannot do to the router
//!
//! Every reply is parsed by `hypellm_adapters::job::JobAdapter` under tight
//! bounds, and every identifier it returns is validated before it reaches a
//! path. Control replies are read to at most [`MAX_REPLY_BYTES`]. A part is
//! fetched only after its head matches the type and length the status
//! declared, read to exactly that length, hashed as it is written, and
//! deleted if anything goes wrong — so a part longer than declared, a type
//! that changed, or a connection that dropped leaves no file behind.
//!
//! # Holding a worker, not a socket
//!
//! Between polls no connection is held: each poll is its own bounded request
//! with its own deadline. **[as built]** The worker thread that runs the job
//! is held for the whole generation, sleeping between polls; §11.5's design
//! has one worker advance many jobs. `job_workers` therefore bounds artifact
//! jobs in flight, exactly as it bounds chat jobs.

use crate::dispatch::{AttemptFailure, AttemptPhase, AttemptSummary};
use crate::jobs::JobId;
use crate::protocol::job::ArtifactSpec;
use crate::spool::{Spool, SpooledPart};
use crate::state::RouterState;
use hypellm_adapters::job::{
    JobAdapter, JobInput, JobSubmission, PartInfo, ProviderJobId, SUBMIT_PATH, ShimState,
    ShimStatus,
};
use hypellm_adapters::{CredentialHandle, ErrorClassification, SensitiveHeaders};
use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::{CanonicalUsage, UpstreamErrorClass};
use hypellm_core::target::{Endpoint, Provider, Target};
use hypellm_core::time::Deadline;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use wire_http1::{BodyDecoder, BodyFraming, Limits as HttpLimits, Method, RequestBuilder};

/// The most bytes a control reply may have: status, accepted, cancelled.
pub const MAX_REPLY_BYTES: u64 = 64 * 1024;

/// Polls in a row that may fail to reach the shim before the job does.
///
/// A shim restarting under a long generation is ordinary; one unreachable for
/// this many polls is not coming back for this job.
pub const MAX_POLL_FAILURES: u32 = 5;

/// The shortest poll interval, whatever a target declares: a status poll is a
/// request, and a shim polled continuously is a shim under load.
pub const MIN_POLL_MS: u64 = 250;

/// What a job run needs beyond the request, and what it produces.
pub struct ArtifactRun<'a> {
    /// The router's job.
    pub job: &'a JobId,
    /// What the shim is asked to do.
    pub spec: &'a ArtifactSpec,
    /// Where parts go.
    pub spool: &'a Spool,
    /// Set by `DELETE /v1/jobs/{id}`.
    pub cancelled: &'a AtomicBool,
    /// Told the shim's progress in permille, and its estimate in
    /// milliseconds, after every poll.
    pub progress: &'a (dyn Fn(u32, u64) + Sync),
    /// How long between polls.
    pub poll_ms: u64,
    /// What the run produced.
    pub output: Mutex<RunOutput>,
}

impl std::fmt::Debug for ArtifactRun<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactRun")
            .field("job", &self.job)
            .field("verb", &self.spec.verb)
            .finish_non_exhaustive()
    }
}

/// What a run leaves for the job worker.
#[derive(Debug, Default)]
pub struct RunOutput {
    /// The parts it spooled, in the order the shim listed them.
    pub parts: Vec<SpooledPart>,
    /// Spool bytes reserved for them, which the job owns from here.
    pub spooled_bytes: u64,
    /// Accelerator time the shim reported, in milliseconds.
    pub elapsed_ms: u64,
    /// The shim refused or failed for want of capacity — out of memory, model
    /// not loaded, or the spool full — so the job may wait and try again.
    pub waits_for_capacity: bool,
}

fn failure(phase: AttemptPhase, class: UpstreamErrorClass, code: ErrorCode, detail: &str) -> AttemptFailure {
    AttemptFailure {
        phase,
        class,
        error: RouterError::new(code, detail),
        provider_code: None,
        client_cancelled: false,
    }
}

/// Run one artifact job against one shim, from submit to spooled parts.
///
/// # Errors
///
/// An [`AttemptFailure`], before acceptance when the submit did not get a job
/// id and after it otherwise. When the failure was only capacity, the run's
/// output says so.
pub fn run(
    state: &RouterState,
    request: &CanonicalRequest,
    target: &Target,
    provider: &Provider,
    run: &ArtifactRun<'_>,
    deadline: Deadline,
) -> Result<AttemptSummary, AttemptFailure> {
    let clock = state.clock.as_ref();
    let started = clock.now_millis();
    let started_micros = clock.now_micros();
    let Some(endpoint) = provider.endpoints.get(target.endpoint_index) else {
        return Err(failure(
            AttemptPhase::BeforeAcceptance,
            UpstreamErrorClass::Connection,
            ErrorCode::InternalFault,
            "the job service has no endpoint",
        ));
    };
    let shim = Shim {
        state,
        provider,
        endpoint,
        request,
    };

    // -- Submit ------------------------------------------------------------
    let inputs: Vec<JobInput<'_>> = run
        .spec
        .inputs
        .iter()
        .map(|input| JobInput {
            name: &input.name,
            media_type: input.media_type,
            data_base64: &input.data_base64,
        })
        .collect();
    let request_id = request.request_id.to_string();
    let body = JobAdapter::encode_submit(&JobSubmission {
        verb: run.spec.verb,
        prompt: &run.spec.prompt,
        params: run.spec.params,
        inputs: &inputs,
        options: run.spec.options.as_ref(),
        request_id: &request_id,
    })
    .map_err(|f| AttemptFailure {
        phase: AttemptPhase::BeforeAcceptance,
        class: UpstreamErrorClass::InvalidRequest,
        error: f.to_router_error(),
        provider_code: None,
        client_cancelled: false,
    })?;
    let (status, reply) = shim.exchange(Method::Post, SUBMIT_PATH, &body, deadline, false)?;
    let id = JobAdapter::decode_accepted(status, &reply).map_err(|c| {
        note_capacity(run, &c);
        AttemptFailure::from_classification(AttemptPhase::BeforeAcceptance, &c)
    })?;
    let first_byte_millis = clock.now_millis().saturating_sub(started);
    let first_byte_micros = clock.now_micros().saturating_sub(started_micros);

    // -- Poll --------------------------------------------------------------
    let final_status = poll(&shim, run, &id, deadline)?;
    lock(&run.output).elapsed_ms = final_status.elapsed_ms;
    match final_status.state {
        ShimState::Succeeded => {}
        ShimState::Cancelled => {
            return Err(AttemptFailure {
                client_cancelled: run.cancelled.load(Ordering::SeqCst),
                ..failure(
                    AttemptPhase::AfterAcceptance,
                    UpstreamErrorClass::Connection,
                    ErrorCode::UpstreamInvalidResponse,
                    "the job service cancelled the job",
                )
            });
        }
        ShimState::Failed => {
            let shim_error = final_status.error;
            if shim_error.is_some_and(hypellm_adapters::job::ShimError::waits_for_capacity) {
                lock(&run.output).waits_for_capacity = true;
            }
            let classification = JobAdapter::classify(
                500,
                format!(
                    r#"{{"error":"{}"}}"#,
                    shim_error.map_or("internal", hypellm_adapters::job::ShimError::as_str)
                )
                .as_bytes(),
            );
            return Err(AttemptFailure::from_classification(
                AttemptPhase::AfterAcceptance,
                &classification,
            ));
        }
        ShimState::Queued | ShimState::Running => {
            return Err(failure(
                AttemptPhase::AfterAcceptance,
                UpstreamErrorClass::Timeout,
                ErrorCode::DeadlineExceeded,
                "the job did not finish before its deadline",
            ));
        }
    }
    if run.cancelled.load(Ordering::SeqCst) {
        // Finished as the cancel arrived. Its parts are not fetched: nobody is
        // waiting for them.
        return Err(AttemptFailure {
            client_cancelled: true,
            ..failure(
                AttemptPhase::AfterAcceptance,
                UpstreamErrorClass::Connection,
                ErrorCode::UpstreamInvalidResponse,
                "the job was cancelled",
            )
        });
    }

    // -- Fetch -------------------------------------------------------------
    fetch_parts(&shim, run, &id, &final_status.parts, deadline)?;

    let total_millis = clock.now_millis().saturating_sub(started);
    Ok(AttemptSummary {
        // Nothing token-denominated describes an artifact; accelerator time is
        // in the run's output for whoever accounts for it.
        usage: CanonicalUsage::estimated(0, 0),
        first_byte_millis: Some(first_byte_millis),
        total_millis,
        first_byte_micros: Some(first_byte_micros),
        total_micros: clock.now_micros().saturating_sub(started_micros),
        saw_output: false,
        native_model: None,
    })
}

fn lock(output: &Mutex<RunOutput>) -> std::sync::MutexGuard<'_, RunOutput> {
    output.lock().unwrap_or_else(|p| p.into_inner())
}

fn note_capacity(run: &ArtifactRun<'_>, classification: &ErrorClassification) {
    if JobAdapter::shim_error(classification)
        .is_some_and(hypellm_adapters::job::ShimError::waits_for_capacity)
    {
        lock(&run.output).waits_for_capacity = true;
    }
}

/// Poll until the shim reports a terminal state or the deadline passes,
/// sending the cancel once if one is asked for.
fn poll(
    shim: &Shim<'_>,
    run: &ArtifactRun<'_>,
    id: &ProviderJobId,
    deadline: Deadline,
) -> Result<ShimStatus, AttemptFailure> {
    let clock = shim.state.clock.as_ref();
    let interval = Duration::from_millis(run.poll_ms.max(MIN_POLL_MS));
    let mut cancel_sent = false;
    let mut failures = 0_u32;
    let mut last: Option<ShimStatus> = None;
    loop {
        if run.cancelled.load(Ordering::SeqCst) && !cancel_sent {
            cancel_sent = true;
            // Best effort: a shim that cannot stop mid-generation says so,
            // and the slot stays held until it reports a terminal state.
            let _ = shim.exchange(Method::Delete, &JobAdapter::cancel_path(id), b"", deadline, true);
        }
        if deadline.is_expired(clock) {
            if !cancel_sent {
                let _ = shim.exchange(
                    Method::Delete,
                    &JobAdapter::cancel_path(id),
                    b"",
                    Deadline::after(clock, interval),
                    true,
                );
            }
            return Ok(last.unwrap_or(ShimStatus {
                state: ShimState::Running,
                progress_permille: 0,
                eta_ms: 0,
                elapsed_ms: 0,
                error: None,
                parts: Vec::new(),
            }));
        }
        clock.sleep(interval.min(deadline.remaining(clock)));
        match shim.exchange(Method::Get, &JobAdapter::status_path(id), b"", deadline, true) {
            Ok((status, body)) => {
                failures = 0;
                // A reply outside the protocol is not retried: a shim that
                // says something malformed once is not trusted to have meant
                // something else.
                let reply = JobAdapter::decode_status(status, &body).map_err(|c| {
                    AttemptFailure::from_classification(AttemptPhase::AfterAcceptance, &c)
                })?;
                (run.progress)(reply.progress_permille, reply.eta_ms);
                if reply.state.is_terminal() {
                    return Ok(reply);
                }
                last = Some(reply);
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                if failures >= MAX_POLL_FAILURES {
                    return Err(AttemptFailure {
                        phase: AttemptPhase::AfterAcceptance,
                        ..error
                    });
                }
            }
        }
    }
}

/// Fetch every part into the spool, all or nothing.
fn fetch_parts(
    shim: &Shim<'_>,
    run: &ArtifactRun<'_>,
    id: &ProviderJobId,
    parts: &[PartInfo],
    deadline: Deadline,
) -> Result<(), AttemptFailure> {
    let spool = run.spool;
    if let Some(part) = parts.iter().find(|p| p.bytes > spool.max_part_bytes()) {
        return Err(failure(
            AttemptPhase::AfterAcceptance,
            UpstreamErrorClass::ProtocolViolation,
            ErrorCode::UpstreamInvalidResponse,
            &format!(
                "part '{}' is larger than this router's max_job_part_bytes",
                part.name.as_str()
            ),
        ));
    }
    let total = parts.iter().fold(0_u64, |sum, p| sum.saturating_add(p.bytes));
    if !spool.reserve(total) {
        lock(&run.output).waits_for_capacity = true;
        return Err(failure(
            AttemptPhase::AfterAcceptance,
            UpstreamErrorClass::ServerError,
            ErrorCode::CapacityExhausted,
            "the job spool is full",
        ));
    }
    let mut spooled = Vec::with_capacity(parts.len());
    for part in parts {
        match fetch_part(shim, run, id, part, deadline) {
            Ok(done) => spooled.push(done),
            Err(error) => {
                spool.remove(run.job, total);
                return Err(error);
            }
        }
    }
    let mut output = lock(&run.output);
    output.parts = spooled;
    output.spooled_bytes = total;
    Ok(())
}

fn fetch_part(
    shim: &Shim<'_>,
    run: &ArtifactRun<'_>,
    id: &ProviderJobId,
    part: &PartInfo,
    deadline: Deadline,
) -> Result<SpooledPart, AttemptFailure> {
    let state = shim.state;
    let clock = state.clock.as_ref();
    let path = JobAdapter::part_path(id, &part.name);
    let (mut connection, head) = shim.open(Method::Get, &path, b"", deadline, true)?;
    let content_length = match head.body {
        BodyFraming::Fixed(n) => Some(n),
        _ => None,
    };
    if let Err(c) = JobAdapter::check_part_head(
        part,
        head.status,
        head.headers.get("content-type"),
        content_length,
    ) {
        connection.poison();
        state.egress.release(connection);
        return Err(AttemptFailure::from_classification(AttemptPhase::AfterAcceptance, &c));
    }
    let violation = |detail: &str| {
        failure(
            AttemptPhase::AfterAcceptance,
            UpstreamErrorClass::ProtocolViolation,
            ErrorCode::UpstreamInvalidResponse,
            detail,
        )
    };
    let mut file = run.spool.create(run.job, &part.name).map_err(|_| {
        failure(
            AttemptPhase::AfterAcceptance,
            UpstreamErrorClass::ServerError,
            ErrorCode::InternalFault,
            "the job spool could not be written",
        )
    })?;
    // Held to the declared length by the decoder itself: a body past it is a
    // framing error, not more bytes.
    let limits = HttpLimits {
        max_body_bytes: part.bytes,
        ..HttpLimits::UPSTREAM
    };
    let mut decoder = BodyDecoder::new(head.body, limits);
    let mut hasher = hypellm_crypto::sha256::Sha256::new();
    let mut written = 0_u64;
    let mut chunk = Vec::with_capacity(64 * 1024);
    let outcome = loop {
        chunk.clear();
        match connection.read_body(&mut decoder, &mut chunk, clock, deadline) {
            Ok(0) if decoder.is_complete() => break Ok(()),
            Ok(0) => break Err(violation("a part ended before its declared length")),
            Ok(_) => {
                written = written.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                if written > part.bytes {
                    break Err(violation("a part is longer than its declared length"));
                }
                hasher.update(&chunk);
                if file.write_all(&chunk).is_err() {
                    break Err(failure(
                        AttemptPhase::AfterAcceptance,
                        UpstreamErrorClass::ServerError,
                        ErrorCode::InternalFault,
                        "the job spool could not be written",
                    ));
                }
                if decoder.is_complete() {
                    break Ok(());
                }
            }
            Err(e) => break Err(AttemptFailure::from_upstream(AttemptPhase::AfterAcceptance, &e)),
        }
    };
    if outcome.is_ok() && written == part.bytes && file.sync_all().is_ok() {
        state.egress.release(connection);
        return Ok(SpooledPart {
            name: part.name.clone(),
            media_type: part.media_type,
            bytes: written,
            sha256: hasher.finalize(),
        });
    }
    connection.poison();
    state.egress.release(connection);
    Err(outcome
        .err()
        .unwrap_or_else(|| violation("a part ended before its declared length")))
}

/// One shim, for the length of one run.
struct Shim<'a> {
    state: &'a RouterState,
    provider: &'a Provider,
    endpoint: &'a Endpoint,
    request: &'a CanonicalRequest,
}

impl Shim<'_> {
    fn headers(&self) -> Result<SensitiveHeaders, AttemptFailure> {
        let missing = || {
            failure(
                AttemptPhase::BeforeAcceptance,
                UpstreamErrorClass::Authentication,
                ErrorCode::InternalFault,
                "the job service's credential is not available",
            )
        };
        // Configuration refuses a `job` provider without a credential, so
        // this is a credential file missing at runtime, not a shim that needs
        // none. Either way nothing is sent.
        let reference = self.provider.credential_ref.as_ref().ok_or_else(missing)?;
        self.state
            .credentials
            .with_secret(reference, |secret| {
                JobAdapter::encode_headers(&CredentialHandle::new(reference, secret))
            })
            .ok_or_else(missing)
    }

    /// Send one request and read its head, retrying once on a fresh socket
    /// when a pooled one turns out dead before any byte came back.
    fn open(
        &self,
        method: Method,
        path: &str,
        body: &[u8],
        deadline: Deadline,
        idempotent: bool,
    ) -> Result<(hypellm_net::UpstreamConnection, wire_http1::ResponseHead), AttemptFailure> {
        let state = self.state;
        let clock = state.clock.as_ref();
        let headers = self.headers()?;
        let internal = || {
            failure(
                AttemptPhase::BeforeAcceptance,
                UpstreamErrorClass::Connection,
                ErrorCode::InternalFault,
                "the job request could not be built",
            )
        };
        let mut builder = RequestBuilder::new(method.clone(), &self.endpoint.path(path), &self.endpoint.authority())
            .map_err(|_| internal())?;
        for (name, value) in headers.iter() {
            builder = builder.header(name, value).map_err(|_| internal())?;
        }
        let wire = builder.finish_with_body(body).map_err(|_| internal())?;
        let credential_class = state.credential_class(
            &self.request.tenant,
            self.provider.credential_ref.as_ref(),
        );
        let profile = state.egress_profile(&self.provider.id);
        let mut retried = false;
        loop {
            let mut connection = if retried {
                state.egress.dial_fresh(self.endpoint, profile, &credential_class)
            } else {
                state.egress.acquire(self.endpoint, profile, &credential_class)
            }
            .map_err(|e| AttemptFailure::from_upstream(AttemptPhase::BeforeAcceptance, &e))?;
            let pooled = connection.is_pooled() && !retried;
            let outcome = match connection.send(&wire, b"", clock, deadline) {
                Err(e) => Err((AttemptPhase::BeforeAcceptance, e)),
                Ok(()) => connection
                    .read_head(&method, &HttpLimits::UPSTREAM, clock, deadline)
                    .map_err(|e| (AttemptPhase::AfterAcceptance, e)),
            };
            match outcome {
                Ok(head) => return Ok((connection, head)),
                Err((phase, e)) => {
                    // The same rule the single-exchange path keeps: replay
                    // only what cannot have run, unless it is safe to run
                    // twice.
                    let replayable = pooled
                        && (phase == AttemptPhase::BeforeAcceptance
                            || idempotent
                            || (matches!(e, hypellm_net::UpstreamError::Truncated)
                                && !connection.has_received_any()));
                    connection.poison();
                    state.egress.release(connection);
                    if replayable {
                        retried = true;
                        continue;
                    }
                    return Err(AttemptFailure::from_upstream(phase, &e));
                }
            }
        }
    }

    /// One control exchange: the status and a body of at most
    /// [`MAX_REPLY_BYTES`].
    fn exchange(
        &self,
        method: Method,
        path: &str,
        body: &[u8],
        deadline: Deadline,
        idempotent: bool,
    ) -> Result<(u16, Vec<u8>), AttemptFailure> {
        let state = self.state;
        let clock = state.clock.as_ref();
        let (mut connection, head) = self.open(method, path, body, deadline, idempotent)?;
        let limits = HttpLimits {
            max_body_bytes: MAX_REPLY_BYTES,
            ..HttpLimits::UPSTREAM
        };
        let mut decoder = BodyDecoder::new(head.body, limits);
        match connection.read_body_to_end(&mut decoder, clock, deadline) {
            Ok(reply) => {
                if !head.is_success() {
                    connection.poison();
                }
                state.egress.release(connection);
                Ok((head.status, reply))
            }
            Err(e) => {
                connection.poison();
                state.egress.release(connection);
                Err(AttemptFailure::from_upstream(AttemptPhase::AfterAcceptance, &e))
            }
        }
    }
}
