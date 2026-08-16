//! One attempt against one target.
//!
//! Specification 3.1, steps 6 and 7:
//!
//! > Serialize through the selected adapter, send to a predeclared upstream,
//! > and stream with bounded buffers and cancellation propagation.
//! >
//! > Normalize usage, errors, finish reasons, tool calls, and stream events
//! > back to the client protocol.
//!
//! # The phase is the point
//!
//! Specification 6.5 makes failover legality depend entirely on *how far the
//! exchange got*:
//!
//! | Phase | Failover |
//! |---|---|
//! | Before the upstream accepted | permitted within the deadline and attempt budget |
//! | Accepted, no response bytes yet | only for an idempotent request or one with an idempotency key |
//! | Any semantic output reached the client | **never** |
//!
//! [`AttemptPhase`] is therefore tracked explicitly and returned with every
//! failure, so the retry loop has the one fact it needs and cannot infer it
//! wrongly from an error kind.

use hypellm_adapters::{Adapter, CredentialHandle, ErrorClassification, RequestMeta};
use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::{CanonicalEvent, CanonicalUsage, UpstreamErrorClass};
use hypellm_core::target::{Provider, Target};
use hypellm_core::time::{Clock, Deadline};
use std::time::Duration;
use hypellm_net::{UpstreamConnection, UpstreamError};
use core::fmt;
use wire_http1::{BodyDecoder, Limits as HttpLimits, Method, RequestBuilder};
use wire_sse::SseParser;

use crate::state::{CredentialStore, RouterState};

/// How far an attempt got before it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptPhase {
    /// The upstream had not accepted the request.
    BeforeAcceptance,
    /// The upstream accepted but sent no response bytes.
    AfterAcceptance,
    /// Semantic output had already reached the client.
    AfterOutput,
}

impl AttemptPhase {
    /// Whether failover is permitted from this phase.
    ///
    /// `idempotent` covers both an idempotent method and a client-supplied
    /// idempotency key, which specification 6.5 treats alike.
    #[must_use]
    pub const fn permits_failover(self, idempotent: bool) -> bool {
        match self {
            Self::BeforeAcceptance => true,
            Self::AfterAcceptance => idempotent,
            Self::AfterOutput => false,
        }
    }

    /// Stable name for traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeAcceptance => "before_acceptance",
            Self::AfterAcceptance => "after_acceptance",
            Self::AfterOutput => "after_output",
        }
    }
}

/// Why an attempt failed.
#[derive(Debug)]
pub struct AttemptFailure {
    /// How far it got.
    pub phase: AttemptPhase,
    /// How the failure is classified.
    pub class: UpstreamErrorClass,
    /// The client-facing error.
    pub error: RouterError,
    /// The provider's own code, when it supplied one.
    pub provider_code: Option<String>,
}

impl AttemptFailure {
    /// Whether the router may try another target.
    #[must_use]
    pub fn may_failover(&self, idempotent: bool) -> bool {
        self.phase.permits_failover(idempotent) && self.class.is_retriable()
    }

    fn from_classification(
        phase: AttemptPhase,
        classification: &ErrorClassification,
    ) -> Self {
        let code = classification.class.to_client_code();
        let mut error = RouterError::new(code, classification.safe_detail.as_str());
        if let Some(secs) = classification.retry_after_secs {
            error = error.with_retry_after(secs);
        }
        Self {
            phase,
            class: classification.class,
            error,
            provider_code: classification
                .provider_code
                .as_ref()
                .map(|c| c.as_str().to_owned()),
        }
    }

    fn from_upstream(phase: AttemptPhase, error: &UpstreamError) -> Self {
        let class = error.class();
        Self {
            phase,
            class,
            error: RouterError::new(
                class.to_client_code(),
                match class {
                    UpstreamErrorClass::Timeout => "the upstream did not respond in time",
                    UpstreamErrorClass::ProtocolViolation => {
                        "the upstream violated the protocol contract"
                    }
                    _ => "the upstream connection failed",
                },
            ),
            provider_code: None,
        }
    }
}

impl fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.error.code, self.phase.as_str())
    }
}

/// Where decoded events go.
///
/// The streaming and non-streaming paths differ only in the sink, so both run
/// the same code — which is what stops the two from drifting apart
/// (specification 14).
pub trait EventSink {
    /// Deliver one event.
    ///
    /// Returning `Err` cancels the exchange, which is how client disconnection
    /// and the slow-client timeout propagate upstream.
    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed>;

    /// Write a protocol-level keepalive, if this sink has one.
    ///
    /// Specification 14 requires periodic keepalives on an open stream. They
    /// exist because a provider can be silent for a long time before its first
    /// token — a cold model, a queue, a long prompt — and an intermediary with
    /// an idle timeout will drop a connection that has sent nothing, turning a
    /// slow answer into a failed one.
    ///
    /// A no-op by default: a buffered sink has no stream to keep alive, and
    /// making this required would push an empty implementation onto every
    /// caller that does not stream.
    fn keepalive(&mut self) -> Result<(), SinkClosed> {
        Ok(())
    }
}

/// The sink refused further events: the client is gone or too slow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkClosed;

/// A sink that accumulates, for non-streaming responses.
#[derive(Debug, Default)]
pub struct AccumulatingSink {
    /// The accumulated response.
    pub accumulator: hypellm_core::event::ResponseAccumulator,
}

impl EventSink for AccumulatingSink {
    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed> {
        self.accumulator.push(event);
        Ok(())
    }
}

/// What one successful attempt produced.
#[derive(Debug, Clone)]
pub struct AttemptSummary {
    /// Usage, with its provenance.
    pub usage: CanonicalUsage,
    /// Milliseconds until the first response byte.
    pub first_byte_millis: Option<u64>,
    /// Milliseconds for the whole attempt.
    pub total_millis: u64,
    /// Whether semantic output reached the sink.
    pub saw_output: bool,
    /// The provider's native model, when reported.
    pub native_model: Option<String>,
}

/// Run one attempt against one target.
///
/// Every step has a deadline derived from the request's, and none of them can
/// extend it (specification 18.2).
#[allow(clippy::too_many_arguments, reason = "an attempt genuinely needs this context")]
pub fn attempt(
    state: &RouterState,
    request: &CanonicalRequest,
    target: &Target,
    provider: &Provider,
    adapter: &dyn Adapter,
    deadline: Deadline,
    sink: &mut dyn EventSink,
) -> Result<AttemptSummary, AttemptFailure> {
    attempt_with(
        state,
        request,
        target,
        provider,
        adapter,
        deadline,
        sink,
        CredentialChoice::Current,
    )
}

/// One attempt, presenting `credential`.
#[allow(
    clippy::too_many_arguments,
    reason = "one upstream exchange, fully specified; a struct here would only \
              move the arguments rather than reduce them"
)]
pub fn attempt_with(
    state: &RouterState,
    request: &CanonicalRequest,
    target: &Target,
    provider: &Provider,
    adapter: &dyn Adapter,
    deadline: Deadline,
    sink: &mut dyn EventSink,
    credential: CredentialChoice,
) -> Result<AttemptSummary, AttemptFailure> {
    let clock = state.clock.as_ref();
    let started = clock.now_millis();
    let mut saw_output = false;

    let Some(endpoint) = provider.endpoints.get(target.endpoint_index) else {
        return Err(AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        });
    };

    let meta = RequestMeta {
        target,
        endpoint,
        request_id: request.request_id.to_string(),
        streaming: request.stream.enabled,
        idempotency_key: request.hints.idempotency_key.clone(),
    };

    // -- Encode, before any I/O -------------------------------------------

    adapter
        .validate(request, &target.capabilities)
        .map_err(|failure| AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::UnsupportedFeature,
            error: failure.to_router_error(),
            provider_code: None,
        })?;

    let path_suffix = adapter.path_for(request).map_err(|failure| AttemptFailure {
        phase: AttemptPhase::BeforeAcceptance,
        class: UpstreamErrorClass::UnsupportedFeature,
        error: failure.to_router_error(),
        provider_code: None,
    })?;

    let body = adapter
        .encode_request(request, &meta)
        .map_err(|failure| AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::InvalidRequest,
            error: failure.to_router_error(),
            provider_code: None,
        })?;

    let headers = build_headers(state, provider, adapter, &meta, credential)?;

    let path = endpoint.path(path_suffix);
    let mut builder = RequestBuilder::new(Method::Post, &path, &endpoint.authority()).map_err(
        |_| AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        },
    )?;
    for (name, value) in headers.iter() {
        builder = builder.header(name, value).map_err(|_| AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        })?;
    }
    let wire = builder
        .finish_with_body(&body)
        .map_err(|_| AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        })?;

    // -- Connect and send --------------------------------------------------

    let credential_class =
        state.credential_class(&request.tenant, provider.credential_ref.as_ref());
    let profile = state.egress_profile(&provider.id);

    // -- Connect, send, and read the response head -------------------------
    //
    // A connection taken from the pool may have been closed by the peer at any
    // moment while it sat idle, and nothing observes that until the exchange is
    // attempted. Such a failure says nothing about the upstream — the request
    // was never delivered and no response was ever produced — so it is retried
    // once on a socket that is known to be new. Without the retry a healthy
    // provider answers the first request after every idle period with
    // `upstream_invalid_response`, reporting an upstream that was never
    // reached; the shorter the provider's own keep-alive timeout is relative to
    // the pool's, the more often it happens.
    //
    // `dial_fresh` rather than `acquire`, because `acquire` would hand back
    // another connection from the same stale bucket.
    //
    // This does not weaken specification 6.5. The retry is bounded to exactly
    // one, happens only before the upstream produced any byte, and replays to
    // the *same* target — it is not a failover, and no client-visible semantic
    // byte can have been emitted.
    let mut retried = false;
    let (mut connection, head) = loop {
        let mut candidate = if retried {
            state.egress.dial_fresh(endpoint, profile, &credential_class)
        } else {
            state.egress.acquire(endpoint, profile, &credential_class)
        }
        .map_err(|e| AttemptFailure::from_upstream(AttemptPhase::BeforeAcceptance, &e))?;

        // Only a reused socket can fail for this reason, and only the first
        // pass may retry.
        let reusable_socket = candidate.is_pooled() && !retried;

        let outcome = match candidate.send(&wire, b"", clock, deadline) {
            // Nothing was delivered.
            Err(e) => Err((AttemptPhase::BeforeAcceptance, e)),
            // A failure reading the head means the upstream accepted the
            // request but produced nothing usable.
            Ok(()) => candidate
                .read_head(&Method::Post, &HttpLimits::UPSTREAM, clock, deadline)
                .map_err(|e| (AttemptPhase::AfterAcceptance, e)),
        };

        match outcome {
            Ok(head) => break (candidate, head),
            Err((phase, e)) => {
                // Whether replaying is safe depends on how far the exchange
                // got, not just on whether the socket came from the pool.
                //
                // A send failure never delivered a complete request — HTTP
                // needs the whole head and body before a server can act — so
                // nothing upstream can have happened.
                //
                // A head-read failure is only safe to replay in one shape: the
                // peer closed without sending a single byte. That is the idle
                // pooled socket this retry exists for, and by this module's own
                // definition acceptance means the provider began producing a
                // response. Any other head-read failure — a timeout, a partial
                // head, an oversize one — leaves it entirely possible that the
                // provider read the request and started work, and replaying a
                // non-idempotent POST there would run the exchange twice and
                // bill it twice. Specification 6.5 permits a retry after
                // acceptance only for idempotent requests; the safe move is to
                // report it.
                let replayable = reusable_socket
                    && match phase {
                        AttemptPhase::BeforeAcceptance => true,
                        AttemptPhase::AfterAcceptance | AttemptPhase::AfterOutput => {
                            matches!(e, hypellm_net::UpstreamError::Truncated)
                                && !candidate.has_received_any()
                        }
                    };

                // The framing of a half-used connection is in doubt; poisoning
                // makes `release` close it instead of pooling it again.
                candidate.poison();
                state.egress.release(candidate);
                if replayable {
                    retried = true;
                    continue;
                }
                return Err(AttemptFailure::from_upstream(phase, &e));
            }
        }
    };

    let first_byte_millis = clock.now_millis().saturating_sub(started);
    let mut decoder = BodyDecoder::new(head.body, HttpLimits::UPSTREAM);

    // -- Error responses ---------------------------------------------------

    if !head.is_success() {
        let body = connection
            .read_body_to_end(&mut decoder, clock, deadline)
            .unwrap_or_default();
        connection.poison();
        state.egress.release(connection);
        let mut classification = adapter.classify_error(head.status, &body);
        // Specification 6.5: "`Retry-After` is capped by the remaining
        // deadline." Read here rather than in the adapter, because
        // `Retry-After` is standard HTTP with standard semantics rather than
        // anything provider-specific: one implementation instead of eight, and
        // the deadline it must be capped against is already in scope.
        //
        // An adapter that parsed a back-off out of the *body* still wins — it
        // knows its provider's shape and this does not — so the header only
        // fills a gap.
        if classification.retry_after_secs.is_none() {
            classification.retry_after_secs =
                retry_after_secs(head.headers.get("retry-after"), deadline, clock);
        }

        // An error status is an explicit *refusal*: the provider read the
        // request and declined it, so no inference happened and nothing was
        // billed. That is "before acceptance" for failover purposes, even
        // though bytes crossed the wire.
        //
        // The alternative reading — that any response means the upstream
        // accepted — would make specification 6.5's "429 … may fail over"
        // clause dead for every inference request, since inference requests
        // are POSTs and a 429 always arrives after the request was sent.
        // Acceptance means the provider began producing a response, which is
        // a 2xx.
        return Err(AttemptFailure::from_classification(
            AttemptPhase::BeforeAcceptance,
            &classification,
        ));
    }

    // -- Success -----------------------------------------------------------

    let mut usage = CanonicalUsage::estimated(request.estimated_input_tokens(), 0);
    let mut native_model = None;
    let mut collected: Vec<CanonicalEvent> = Vec::new();

    let result = if head.is_event_stream() {
        stream_events(
            state,
            adapter,
            &mut connection,
            &mut decoder,
            deadline,
            sink,
            &mut saw_output,
            &mut collected,
        )
    } else {
        let body = connection
            .read_body_to_end(&mut decoder, clock, deadline)
            .map_err(|e| {
                AttemptFailure::from_upstream(
                    if saw_output {
                        AttemptPhase::AfterOutput
                    } else {
                        AttemptPhase::AfterAcceptance
                    },
                    &e,
                )
            })?;
        match adapter.decode_response(head.status, &body) {
            Ok(events) => {
                for event in &events {
                    if event.is_semantic_output() {
                        saw_output = true;
                    }
                    sink.deliver(event).map_err(|_| cancelled(saw_output))?;
                }
                // The same filter the streaming path uses. A non-streaming body
                // is already bounded by `Limits::UPSTREAM.max_body_bytes`, so
                // this is not a memory bound so much as a consistency one: the
                // two paths must agree about what a later stage can read, or a
                // change to one silently changes behaviour on the other.
                collected = events
                    .into_iter()
                    .filter(retain_after_stream)
                    .take(MAX_RETAINED_EVENTS)
                    .collect();
                Ok(())
            }
            Err(classification) => Err(AttemptFailure::from_classification(
                if saw_output {
                    AttemptPhase::AfterOutput
                } else {
                    AttemptPhase::AfterAcceptance
                },
                &classification,
            )),
        }
    };

    // Release before propagating, so a failure does not leak the connection.
    if head.connection_close {
        connection.poison();
    }
    state.egress.release(connection);
    result?;

    for event in &collected {
        if let CanonicalEvent::Start {
            native_model: model,
            ..
        } = event
        {
            if native_model.is_none() {
                native_model.clone_from(model);
            }
        }
    }
    let reported = adapter.usage_from_events(&collected);
    if reported.is_reported() {
        usage = reported;
    } else {
        // No provider report: keep the router's estimate and say so.
        usage.output_tokens = reported.output_tokens;
    }

    Ok(AttemptSummary {
        usage,
        first_byte_millis: Some(first_byte_millis),
        total_millis: clock.now_millis().saturating_sub(started),
        saw_output,
        native_model,
    })
}

/// Whether an event is still needed once the stream has finished.
///
/// The two consumers after `stream_events` returns are the `Start` event, which
/// carries the provider's native model name for response metadata, and the
/// `Usage` event, which reconciles the admission estimate. Everything else has
/// already been written to the client and is dead weight.
/// How many post-stream events one attempt may retain.
///
/// `retain_after_stream` already discards the deltas, which is where the volume
/// is — but `Usage` and `Start` are chosen by the *provider*, and nothing stops
/// one sending a million of them. Specification 3.2 bounds every buffer that
/// originates from a request, and this one does.
///
/// Well above any real response: a provider sends one `Start` and one or two
/// `Usage` events. Anthropic sends two, which is why the merge exists at all.
const MAX_RETAINED_EVENTS: usize = 256;

const fn retain_after_stream(event: &CanonicalEvent) -> bool {
    matches!(
        event,
        CanonicalEvent::Start { .. } | CanonicalEvent::Usage(_)
    )
}

/// The provider's back-off hint, capped by what remains of the deadline.
///
/// Only the delta-seconds form is honoured. The HTTP-date form is legal and
/// would need a date parser, and a wrong answer here is worse than none: too
/// large and the request sits out its deadline for nothing, too small and the
/// router hammers a provider that asked for room. An unparsed value simply
/// means the router falls back to its own retry budget, which is the behaviour
/// it had before this existed.
///
/// Capping is not politeness. An uncapped hint lets a provider hold a request
/// past its deadline, which is a client-visible stall the router promised would
/// not happen — and a compromised or misconfigured upstream could set it to a
/// year.
fn retry_after_secs(header: Option<&str>, deadline: Deadline, clock: &dyn Clock) -> Option<u32> {
    let requested: u32 = header?.trim().parse().ok()?;
    let remaining = u32::try_from(deadline.remaining(clock).as_secs()).unwrap_or(u32::MAX);
    Some(requested.min(remaining))
}

fn cancelled(saw_output: bool) -> AttemptFailure {
    AttemptFailure {
        phase: if saw_output {
            AttemptPhase::AfterOutput
        } else {
            AttemptPhase::AfterAcceptance
        },
        class: UpstreamErrorClass::Connection,
        error: RouterError::new(ErrorCode::InvalidRequest, "the client closed the connection"),
        provider_code: None,
    }
}

/// Build request headers, borrowing the credential for exactly as long as it
/// takes.
fn build_headers(
    state: &RouterState,
    provider: &Provider,
    adapter: &dyn Adapter,
    meta: &RequestMeta<'_>,
    credential: CredentialChoice,
) -> Result<hypellm_adapters::SensitiveHeaders, AttemptFailure> {
    match &provider.credential_ref {
        None => Ok(adapter.encode_headers(None, meta)),
        Some(reference) => credential_headers(
            &state.credentials,
            reference,
            adapter,
            meta,
            credential,
            state.clock.wall_millis(),
        ),
    }
}

/// Which secret an attempt presents.
///
/// Specification 22.2 step 16's bounded overlap, expressed as an explicit
/// argument rather than as a fallback buried in the credential store. The store
/// cannot decide this: only the caller knows that the *current* secret has
/// already been refused, and a store that silently tried both would make a
/// rotation to a wrong secret indistinguishable from a correct one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChoice {
    /// The live secret. Every ordinary request.
    Current,
    /// The superseded secret, inside its overlap window.
    ///
    /// Only after the current one has been refused, and only once.
    Superseded,
}

fn credential_headers(
    credentials: &CredentialStore,
    reference: &hypellm_core::ids::CredentialRef,
    adapter: &dyn Adapter,
    meta: &RequestMeta<'_>,
    credential: CredentialChoice,
    now_millis: u64,
) -> Result<hypellm_adapters::SensitiveHeaders, AttemptFailure> {
    let encode = |secret: &[u8]| {
        let handle = CredentialHandle::new(reference, secret);
        adapter.encode_headers(Some(&handle), meta)
    };
    match credential {
        CredentialChoice::Current => credentials.with_secret(reference, encode),
        CredentialChoice::Superseded => {
            credentials.with_superseded_secret(reference, now_millis, encode)
        }
    }
        .ok_or_else(|| {
            // Previously this fell back to unauthenticated headers and sent the
            // request anyway. That is the wrong direction on every count: the
            // provider rejects it, so the caller waits for a round trip that
            // could not succeed; the prompt is transmitted to a third party on
            // a request that was never going to be served; and the resulting
            // 401 is indistinguishable from a genuine credential problem, so a
            // configuration fault reads as a provider outage.
            //
            // Failing here means nothing leaves the process. The phase is
            // `BeforeAcceptance`, so routing may still fail over to another
            // target whose credential does resolve (specification 6.5).
            AttemptFailure {
                phase: AttemptPhase::BeforeAcceptance,
                class: UpstreamErrorClass::Authentication,
                error: RouterError::new(
                    ErrorCode::InternalFault,
                    "the target's provider credential is not available",
                ),
                provider_code: None,
            }
        })
}

/// Read a streaming response, delivering events as they arrive.
#[allow(clippy::too_many_arguments, reason = "the streaming loop needs this context")]
fn stream_events(
    state: &RouterState,
    adapter: &dyn Adapter,
    connection: &mut UpstreamConnection,
    decoder: &mut BodyDecoder,
    deadline: Deadline,
    sink: &mut dyn EventSink,
    saw_output: &mut bool,
    collected: &mut Vec<CanonicalEvent>,
) -> Result<(), AttemptFailure> {
    let clock = state.clock.as_ref();
    let mut parser = SseParser::with_default_limits();
    let mut chunk = Vec::new();
    // Specification 14's keepalive cadence. Zero disables it, in which case the
    // read simply waits out the whole deadline as it did before.
    let keepalive = state.config().settings.keepalive_interval_ms;

    loop {
        if decoder.is_complete() {
            return Ok(());
        }
        chunk.clear();
        // Read against the nearer of the request deadline and the next
        // keepalive, so a silent upstream produces a comment rather than
        // nothing. A timed-out read leaves the connection's buffer and the
        // decoder untouched (`fill` truncates back on error), which is what
        // makes polling safe here rather than a way to lose a partial frame.
        let poll = if keepalive > 0 {
            deadline.min(Deadline::after(clock, Duration::from_millis(keepalive)))
        } else {
            deadline
        };
        let produced = match connection.read_body(decoder, &mut chunk, clock, poll) {
            Ok(produced) => produced,
            // The keepalive interval elapsed with nothing to read, and the
            // request still has time. Say so on the wire and wait again.
            Err(hypellm_net::UpstreamError::Timeout) if !deadline.is_expired(clock) => {
                sink.keepalive().map_err(|_| cancelled(*saw_output))?;
                continue;
            }
            Err(e) => {
                return Err(AttemptFailure::from_upstream(
                    if *saw_output {
                        AttemptPhase::AfterOutput
                    } else {
                        AttemptPhase::AfterAcceptance
                    },
                    &e,
                ));
            }
        };

        if produced > 0 {
            parser.push(&chunk).map_err(|_| AttemptFailure {
                phase: if *saw_output {
                    AttemptPhase::AfterOutput
                } else {
                    AttemptPhase::AfterAcceptance
                },
                class: UpstreamErrorClass::ProtocolViolation,
                error: RouterError::new(
                    ErrorCode::UpstreamInvalidResponse,
                    "the upstream sent a malformed event stream",
                ),
                provider_code: None,
            })?;

            let events = parser.drain().map_err(|_| AttemptFailure {
                phase: AttemptPhase::AfterOutput,
                class: UpstreamErrorClass::ProtocolViolation,
                error: RouterError::new(
                    ErrorCode::UpstreamInvalidResponse,
                    "the upstream sent a malformed event stream",
                ),
                provider_code: None,
            })?;

            for sse in events {
                if adapter.is_stream_terminator(&sse.data) {
                    return Ok(());
                }
                let decoded = adapter
                    .decode_stream_event(sse.event.as_deref(), &sse.data)
                    .map_err(|classification| {
                        AttemptFailure::from_classification(
                            if *saw_output {
                                AttemptPhase::AfterOutput
                            } else {
                                AttemptPhase::AfterAcceptance
                            },
                            &classification,
                        )
                    })?;

                for event in decoded {
                    if event.is_semantic_output() {
                        *saw_output = true;
                    }
                    // Delivery is where backpressure lives: a blocked write to
                    // a slow client stops this loop, which stops reading from
                    // the upstream (specification 14).
                    sink.deliver(&event).map_err(|_| cancelled(*saw_output))?;

                    // Retain only what the caller reads after the stream ends:
                    // `Start` for the native model, `Usage` for reconciliation.
                    //
                    // Accumulating every event grew this vector in proportion
                    // to the length of the completion — a hundred thousand
                    // `TextDelta` strings for a long generation — against
                    // specification 3.2's "per-stream buffered data: 256 KiB
                    // default total across inbound and outbound". The deltas
                    // have already been delivered; holding a second copy of the
                    // whole response bought nothing.
                    if retain_after_stream(&event) && collected.len() < MAX_RETAINED_EVENTS {
                        collected.push(event);
                    }
                }
            }
        }

        if produced == 0 && decoder.is_complete() {
            return Ok(());
        }
    }
}

#[cfg(test)]
// The crate-root `deny` in `lib.rs` guards production code. A test module
// indexes its own fixtures and reports failure by panicking; holding it to the
// data-plane rules would only push the panics behind `unwrap_or_else`.
#[allow(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::panic,
    clippy::expect_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    #[test]
    fn only_the_scalars_are_retained_after_a_stream() {
        // Specification 3.2 bounds per-stream buffered data. Accumulating every
        // decoded event grew a vector in proportion to the length of the
        // completion — a hundred thousand `TextDelta` strings for a long
        // generation — while the deltas had already been delivered to the
        // client. A second copy of the whole response bought nothing.
        //
        // What the later stages actually read is the native model, from
        // `Start`, and the usage, which Anthropic merges across *all* `Usage`
        // events — so those two are kept and nothing else.
        for event in [
            CanonicalEvent::TextDelta("a".to_owned()),
            CanonicalEvent::ReasoningDelta("a".to_owned()),
            CanonicalEvent::Embedding {
                index: 0,
                values: vec![0.0],
            },
            CanonicalEvent::Finish {
                reason: hypellm_core::event::FinishReason::Stop,
            },
        ] {
            assert!(
                !super::retain_after_stream(&event),
                "{event:?} must not be retained after the stream"
            );
        }

        assert!(super::retain_after_stream(&CanonicalEvent::Start {
            upstream_id: None,
            native_model: None,
        }));
        assert!(super::retain_after_stream(&CanonicalEvent::Usage(
            hypellm_core::event::CanonicalUsage::estimated(1, 1)
        )));
    }


    #[test]
    fn a_provider_back_off_is_honoured_and_capped_by_the_deadline() {
        // Specification 6.5: "`Retry-After` is capped by the remaining
        // deadline." Before this the header was never read at all: every
        // adapter set `retry_after_secs: None` and a provider's hint was
        // discarded, so a client never saw a `Retry-After` on a 429 that
        // originated upstream.
        let clock = hypellm_core::time::TestClock::new();
        let deadline = Deadline::after(&clock, std::time::Duration::from_secs(30));

        assert_eq!(
            super::retry_after_secs(Some("5"), deadline, &clock),
            Some(5),
            "a hint inside the deadline is passed through"
        );
        assert_eq!(
            super::retry_after_secs(Some("  7 "), deadline, &clock),
            Some(7),
            "surrounding whitespace is not a parse failure"
        );

        // The cap. An uncapped hint lets a provider hold a request past its
        // deadline — a client-visible stall the router promised would not
        // happen — and a misconfigured upstream can ask for a year.
        assert_eq!(
            super::retry_after_secs(Some("86400"), deadline, &clock),
            Some(30)
        );
        assert_eq!(
            super::retry_after_secs(Some("4294967295"), deadline, &clock),
            Some(30)
        );

        // Absent, malformed, and the HTTP-date form all fall back to the
        // router's own budget rather than to a guess.
        assert_eq!(super::retry_after_secs(None, deadline, &clock), None);
        assert_eq!(super::retry_after_secs(Some(""), deadline, &clock), None);
        assert_eq!(super::retry_after_secs(Some("soon"), deadline, &clock), None);
        assert_eq!(super::retry_after_secs(Some("-1"), deadline, &clock), None);
        assert_eq!(
            super::retry_after_secs(Some("Wed, 21 Oct 2015 07:28:00 GMT"), deadline, &clock),
            None
        );
    }

    use super::*;

    #[test]
    fn failover_legality_follows_specification_6_5() {
        // Before acceptance: always permitted.
        assert!(AttemptPhase::BeforeAcceptance.permits_failover(false));
        assert!(AttemptPhase::BeforeAcceptance.permits_failover(true));

        // After acceptance, before bytes: only when idempotent.
        assert!(!AttemptPhase::AfterAcceptance.permits_failover(false));
        assert!(AttemptPhase::AfterAcceptance.permits_failover(true));

        // After output: never, whatever the request.
        assert!(!AttemptPhase::AfterOutput.permits_failover(false));
        assert!(
            !AttemptPhase::AfterOutput.permits_failover(true),
            "an idempotency key must not license splicing a second model's output"
        );
    }

    #[test]
    fn a_failure_needs_both_a_permissive_phase_and_a_retriable_class() {
        let connection_failure = AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        };
        assert!(connection_failure.may_failover(false));

        // A retriable class after output is still not retriable.
        let after_output = AttemptFailure {
            phase: AttemptPhase::AfterOutput,
            class: UpstreamErrorClass::Connection,
            error: RouterError::internal(),
            provider_code: None,
        };
        assert!(!after_output.may_failover(true));

        // A permissive phase with a non-retriable class is not retried:
        // another target would reject it the same way.
        let invalid = AttemptFailure {
            phase: AttemptPhase::BeforeAcceptance,
            class: UpstreamErrorClass::InvalidRequest,
            error: RouterError::invalid_request("bad"),
            provider_code: None,
        };
        assert!(!invalid.may_failover(true));
    }

    #[test]
    fn an_accumulating_sink_collects_events() {
        let mut sink = AccumulatingSink::default();
        sink.deliver(&CanonicalEvent::TextDelta("Hel".to_owned()))
            .unwrap();
        sink.deliver(&CanonicalEvent::TextDelta("lo".to_owned()))
            .unwrap();
        assert_eq!(sink.accumulator.text, "Hello");
        assert!(sink.accumulator.saw_semantic_output());
    }

    #[test]
    fn a_classification_becomes_a_client_error_without_the_provider_message() {
        let classification = ErrorClassification {
            class: UpstreamErrorClass::RateLimited,
            provider_code: Some(hypellm_core::sensitive::Capped::new("rate_limit", 64)),
            safe_detail: hypellm_core::sensitive::Capped::new(
                "the provider rate limited the request",
                200,
            ),
            retry_after_secs: Some(30),
        };
        let failure =
            AttemptFailure::from_classification(AttemptPhase::AfterAcceptance, &classification);
        assert_eq!(failure.error.code, ErrorCode::RateLimited);
        assert_eq!(failure.error.retry_after_secs, Some(30));
        assert_eq!(failure.provider_code.as_deref(), Some("rate_limit"));
        assert!(failure.may_failover(true));
    }

    #[test]
    fn a_provider_credential_failure_does_not_surface_as_a_client_auth_error() {
        let classification = ErrorClassification {
            class: UpstreamErrorClass::Authentication,
            provider_code: None,
            safe_detail: hypellm_core::sensitive::Capped::new("credential rejected", 200),
            retry_after_secs: None,
        };
        let failure =
            AttemptFailure::from_classification(AttemptPhase::AfterAcceptance, &classification);
        assert_eq!(
            failure.error.code,
            ErrorCode::InternalFault,
            "the caller's own key was not the problem"
        );
    }

    #[test]
    fn an_explicit_refusal_is_retriable_for_a_non_idempotent_request() {
        // A 429 or 503 *response* means the provider declined the work. No
        // inference ran, nothing was billed, and no output exists — so trying
        // another target is safe even for a POST with no idempotency key.
        //
        // The opposite classification would make specification 6.5's
        // "429 … may fail over" clause unreachable for inference, which is the
        // only kind of request the router carries.
        for class in [
            UpstreamErrorClass::RateLimited,
            UpstreamErrorClass::ServerError,
        ] {
            let refusal = AttemptFailure {
                phase: AttemptPhase::BeforeAcceptance,
                class,
                error: RouterError::internal(),
                provider_code: None,
            };
            assert!(
                refusal.may_failover(false),
                "{class:?} refusal should fail over without an idempotency key"
            );
        }
    }

    #[test]
    fn an_ambiguous_failure_after_sending_needs_an_idempotency_key() {
        // A timeout or dropped connection after the request was sent is
        // different: the provider may have started work, so retrying could
        // duplicate it. That is the case the idempotency key exists for.
        for class in [UpstreamErrorClass::Timeout, UpstreamErrorClass::Connection] {
            let ambiguous = AttemptFailure {
                phase: AttemptPhase::AfterAcceptance,
                class,
                error: RouterError::internal(),
                provider_code: None,
            };
            assert!(
                !ambiguous.may_failover(false),
                "{class:?} after sending must not be retried blind"
            );
            assert!(
                ambiguous.may_failover(true),
                "{class:?} may be retried with an idempotency key"
            );
        }
    }

    #[test]
    fn phase_names_are_distinct() {
        let names = [
            AttemptPhase::BeforeAcceptance.as_str(),
            AttemptPhase::AfterAcceptance.as_str(),
            AttemptPhase::AfterOutput.as_str(),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 3);
    }
}
