//! The inference listener's request routing.
//!
//! Specification 8 fixes the endpoint set:
//!
//! | Endpoint | Requirement |
//! |---|---|
//! | `POST /v1/chat/completions` | MUST |
//! | `POST /v1/responses` | MUST for new integrations |
//! | `POST /v1/embeddings` | SHOULD |
//! | `GET /v1/models` | MUST, authorized aliases only |
//! | `POST /v1/messages` | SHOULD, Anthropic profile |
//! | `GET /health/live`, `/health/ready` | MUST, no sensitive provider detail |
//! | `POST /v1/tokenize` | MAY |
//!
//! Paths are matched **exactly**, against the undecoded path. There is no
//! prefix matching and no normalisation step, because a router that decodes
//! `%2f` before matching can be walked into an endpoint the caller did not
//! name.

use hypellm_auth::{Principal, Scope, apikey};
use hypellm_core::canonical::{CanonicalRequest, ClientProtocol, Operation};
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::{CanonicalEvent, FinishReason};
use hypellm_core::ids::{GroupId, RequestId};
use hypellm_core::policy::RoutingContext;
use hypellm_core::time::{Clock, Deadline};
use hypellm_crypto::random;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use wire_http1::{Method, RequestHead, ResponseBuilder};
use wire_json::Limits as JsonLimits;

use crate::dispatch::{AccumulatingSink, EventSink, SinkClosed};
use crate::pipeline;
use crate::protocol::{ParseContext, anthropic, openai};
use crate::server::{ClientWriter, Disposition, Handler};
use crate::state::RouterState;

/// Wall-clock time as whole seconds since the Unix epoch.
///
/// The OpenAI-shaped `created` field is expressed in seconds while the clock
/// reports milliseconds; discarding the sub-second part is the conversion, not
/// a loss of precision that matters to the wire format.
#[allow(
    clippy::integer_division,
    reason = "milliseconds to whole seconds is the intended truncation"
)]
fn wall_seconds(clock: &dyn Clock) -> u64 {
    clock.wall_millis() / 1000
}

/// The inference listener.
#[derive(Debug)]
pub struct InferenceHandler {
    state: Arc<RouterState>,
}

impl InferenceHandler {
    /// Create a handler over shared state.
    #[must_use]
    pub const fn new(state: Arc<RouterState>) -> Self {
        Self { state }
    }
}

impl Handler for InferenceHandler {
    fn handle(
        &self,
        head: &RequestHead,
        body: &[u8],
        writer: &mut ClientWriter,
    ) -> io::Result<Disposition> {
        let started = self.state.clock.now_millis();

        // Health comes first: it must answer even when the configuration is
        // broken or every provider is down.
        //
        // Metrics are deliberately *not* here. Specification 17's exposition
        // lists target identifiers, queue depths, breaker states, auth failure
        // counts, and the active configuration version — an operational map of
        // the deployment, and specification 3 separates the data path from the
        // management path precisely so that an inference caller cannot read it.
        // The exposition lives on the management listener, and on the
        // dedicated `metrics_listen` address when one is configured.
        match (&head.method, head.path.as_str()) {
            (Method::Get, "/health/live") => return liveness(writer),
            (Method::Get, "/health/ready") => return readiness(&self.state, writer),
            _ => {}
        }

        // Specification 17 requires request ids for correlation: the decision
        // trace, the audit record, and `X-Request-Id` all key on this. Falling
        // back to zero — which is what this did — assigns every request the
        // same id, so correlation collapses and nothing says so.
        //
        // Fails closed instead. Every other consumer of entropy already does:
        // session tokens, API key secrets, and OIDC state all refuse rather
        // than weaken, so a router that cannot read entropy is already unable
        // to authenticate anyone. Serving inference with unusable identity
        // would be the one path that pretended otherwise.
        let Ok(value) = random::u128_value() else {
            self.state.telemetry.log(
                &hypellm_telemetry::Event::critical("router.entropy_unavailable").str_field(
                    hypellm_telemetry::Field::Detail,
                    "no request identifier could be generated; refusing rather than \
                     serving requests that cannot be correlated",
                ),
            );
            self.state.telemetry.count(
                hypellm_telemetry::names::ENTROPY_FAILURES,
                "Requests refused because no entropy was available.",
                &hypellm_telemetry::Labels::one(
                    hypellm_telemetry::LabelName::Listener,
                    "inference",
                ),
            );
            return respond_error(
                writer,
                &RouterError::new(
                    ErrorCode::InternalFault,
                    "the router cannot generate a request identifier",
                ),
                None,
                protocol_for(&head.path),
            );
        };
        let request_id = RequestId::from_u128(value);

        // `Peer::ip()` is `None` for a Unix socket, so a key carrying a source
        // restriction fails closed over one: the restriction cannot be
        // evaluated, so it is not satisfied. A key pinned to a network must not
        // become unrestricted by arriving through a different transport.
        let principal = match authenticate(&self.state, head, writer.peer().ip()) {
            Ok(principal) => principal,
            Err(error) => {
                return respond_error(writer, &error, Some(request_id), protocol_for(&head.path));
            }
        };

        match (&head.method, head.path.as_str()) {
            (Method::Get, "/v1/models") => list_models(&self.state, &principal, writer),
            (Method::Post, "/v1/chat/completions") => self.inference(
                head,
                body,
                writer,
                &principal,
                request_id,
                Operation::Chat,
                started,
            ),
            (Method::Post, "/v1/responses") => self.inference(
                head,
                body,
                writer,
                &principal,
                request_id,
                Operation::Responses,
                started,
            ),
            (Method::Post, "/v1/embeddings") => self.inference(
                head,
                body,
                writer,
                &principal,
                request_id,
                Operation::Embeddings,
                started,
            ),
            (Method::Post, "/v1/messages") => self.inference(
                head,
                body,
                writer,
                &principal,
                request_id,
                Operation::Chat,
                started,
            ),
            (Method::Post, "/v1/tokenize") => self.inference(
                head,
                body,
                writer,
                &principal,
                request_id,
                Operation::Tokenize,
                started,
            ),
            (Method::Options, _) => no_content(writer),
            (_, path) if is_known_path(path) => {
                let error = RouterError::new(
                    ErrorCode::InvalidRequest,
                    "the method is not allowed for this endpoint",
                );
                respond_error(writer, &error, Some(request_id), protocol_for(path))
            }
            (_, path) => {
                let error = RouterError::new(ErrorCode::InvalidRequest, "no such endpoint");
                respond_error(writer, &error, Some(request_id), protocol_for(path))
            }
        }
    }
}

impl InferenceHandler {
    #[allow(clippy::too_many_arguments, reason = "one handler entry point")]
    fn inference(
        &self,
        head: &RequestHead,
        body: &[u8],
        writer: &mut ClientWriter,
        principal: &Principal,
        request_id: RequestId,
        operation: Operation,
        started: u64,
    ) -> io::Result<Disposition> {
        let state = &self.state;
        let config = state.config();
        let protocol = protocol_for(&head.path);

        // The scope check happens before parsing, so an unauthorized caller
        // never has their body examined.
        let scope = Scope::for_operation(operation);
        if !principal.has_scope(scope) {
            let error = RouterError::new(
                ErrorCode::Forbidden,
                "the credential is not permitted to perform this operation",
            );
            return respond_error(writer, &error, Some(request_id), protocol);
        }

        let deadline = Deadline::after(
            state.clock.as_ref(),
            Duration::from_millis(config.settings.default_deadline_ms),
        );
        // Residency and the cost ceiling are compliance constraints, so they
        // come from the tenant record rather than from the request body. Before
        // this, both were hardcoded to `None` in every parser, which left the
        // residency and cost-ceiling filters of specification 6.2 unable to
        // exclude anything at all — a target in the wrong region was eligible
        // for an EU tenant.
        let tenant_config = config.tenants.get(&principal.tenant);

        let context = ParseContext {
            request_id,
            tenant: principal.tenant.clone(),
            principal: principal.id.clone(),
            deadline,
            // Hints are an operator-granted capability; a plain inference key
            // does not carry it (specification 5.1).
            hints_permitted: principal
                .permissions()
                .has(hypellm_core::rbac::Permission::OperateTargets),
            residency: tenant_config.and_then(|t| t.residency.clone()),
            max_cost_class: tenant_config.and_then(|t| t.max_cost_class),
            min_quality_class: tenant_config.and_then(|t| t.min_quality_class),
            document_limits: crate::protocol::DocumentLimits {
                max_documents: config.settings.max_documents_per_request,
                max_document_bytes: config.settings.max_document_bytes,
                max_inline_bytes: config.settings.max_inline_document_bytes,
            },
        };

        let limits = JsonLimits::DEFAULT
            .with_max_input_bytes(usize::try_from(config.settings.max_body_bytes).unwrap_or(usize::MAX));

        let parsed = match protocol {
            ClientProtocol::AnthropicMessages => {
                anthropic::parse_messages_request(body, &context, &limits)
            }
            ClientProtocol::OpenAiEmbeddings => {
                openai::parse_embeddings_request(body, &context, &limits)
            }
            ClientProtocol::OpenAiResponses => {
                openai::parse_responses_request(body, &context, &limits)
            }
            _ => openai::parse_chat_request(body, &context, &limits),
        };

        let request = match parsed {
            Ok(mut request) => {
                request.operation = operation;
                request
            }
            Err(error) => return respond_error(writer, &error, Some(request_id), protocol),
        };

        // After parsing, before routing: the count and size bounds are a
        // property of the request rather than of the dialect it arrived in, so
        // they are checked once here instead of in each parser.
        if let Err(error) =
            crate::protocol::enforce_document_limits(&request, &context.document_limits)
        {
            return respond_error(writer, &error, Some(request_id), protocol);
        }

        if request.stream.enabled {
            self.stream(&request, principal, writer, started)
        } else {
            self.buffered(&request, principal, writer, started)
        }
    }

    fn buffered(
        &self,
        request: &CanonicalRequest,
        principal: &Principal,
        writer: &mut ClientWriter,
        started: u64,
    ) -> io::Result<Disposition> {
        let state = &self.state;
        let mut sink = AccumulatingSink::default();
        let outcome = pipeline::execute(state, request, &principal.groups, principal.permissions(), &mut sink);
        let total = state.clock.now_millis().saturating_sub(started);
        // The key, not just the principal: specification 22.3 step 20 searches
        // usage by *key*, and one principal can hold several.
        pipeline::record_completion(
            state,
            request,
            &outcome,
            total,
            principal.key_id.as_ref(),
        );

        if let Some(error) = &outcome.error {
            return respond_error(writer, error, Some(request.request_id), request.protocol);
        }

        let payload = match request.protocol {
            ClientProtocol::AnthropicMessages => {
                anthropic::render_message_response(request, &sink.accumulator)
            }
            ClientProtocol::OpenAiEmbeddings => {
                openai::render_embeddings_response(request, &sink.accumulator)
            }
            // The Responses dialect reports typed `output` items and a
            // `status`, not `choices` and a `finish_reason`; rendering a chat
            // body here would hand the caller a shape their SDK cannot read.
            ClientProtocol::OpenAiResponses => openai::render_responses_response(
                request,
                &sink.accumulator,
                wall_seconds(state.clock.as_ref()),
            ),
            _ => openai::render_chat_response(
                request,
                &sink.accumulator,
                wall_seconds(state.clock.as_ref()),
            ),
        };

        let bytes_before = writer.bytes_written();
        write_json(writer, 200, &payload, request.request_id)?;
        state.admission.record_output_bytes(
            writer.bytes_written().saturating_sub(bytes_before),
            state.clock.now_millis(),
        );
        Ok(Disposition::KeepAlive)
    }

    fn stream(
        &self,
        request: &CanonicalRequest,
        principal: &Principal,
        writer: &mut ClientWriter,
        started: u64,
    ) -> io::Result<Disposition> {
        let state = &self.state;

        // The head goes out before the first upstream byte, so a client that
        // is waiting on headers sees the stream open promptly.
        let bytes_before = writer.bytes_written();
        let head = ResponseBuilder::new(200)
            .header("Content-Type", "text/event-stream")
            .and_then(|b| b.header("Cache-Control", "no-store"))
            .and_then(|b| b.header("X-Accel-Buffering", "no"))
            .and_then(|b| b.header("X-Request-Id", &request.request_id.to_string()))
            .and_then(ResponseBuilder::finish_streaming)
            .map_err(|_| io::Error::other("response head"))?;
        writer.write(&head)?;
        writer.flush()?;

        let mut sink = StreamSink::new(
            request.clone(),
            writer,
            wall_seconds(state.clock.as_ref()),
            state.clock.as_ref(),
        );
        let outcome = pipeline::execute(state, request, &principal.groups, principal.permissions(), &mut sink);
        let total = state.clock.now_millis().saturating_sub(started);
        // The key, not just the principal: specification 22.3 step 20 searches
        // usage by *key*, and one principal can hold several.
        pipeline::record_completion(
            state,
            request,
            &outcome,
            total,
            principal.key_id.as_ref(),
        );

        if let Some(error) = &outcome.error {
            // Specification 14: "Emit protocol-supported error event if
            // possible, then close. Never append failover output."
            sink.emit_error(error);
        } else {
            sink.finish();
        }
        sink.flush();

        // Observed once at the end rather than per write: a stream is many
        // small writes, and a metric call on each would cost more than the
        // thing it measures. Labelled by operation only — specification 7.1
        // forbids a per-request or per-principal series here.
        state.telemetry.metrics.histogram_observe(
            hypellm_telemetry::names::STREAM_BACKPRESSURE_MS,
            "Time a stream spent blocked writing to the client.",
            &hypellm_telemetry::Labels::one(
                hypellm_telemetry::LabelName::Operation,
                request.operation.as_str(),
            ),
            sink.blocked_millis,
        );

        // The output half of specification 12's Global byte rates (`DI-053`).
        // Counted at the writer, which knows exactly how many bytes reached the
        // client, and charged *after* the fact: the size of a completion is not
        // known until it exists, so this throttles subsequent requests. Cutting
        // the current response to satisfy a rate limit would corrupt it.
        state.admission.record_output_bytes(
            sink.writer.bytes_written().saturating_sub(bytes_before),
            state.clock.now_millis(),
        );

        // A stream always closes the connection: the response had no length,
        // so there is no framing that lets another request follow.
        Ok(Disposition::Close)
    }
}

/// Writes canonical events to the client as SSE frames.
struct StreamSink<'a> {
    request: CanonicalRequest,
    writer: &'a mut ClientWriter,
    created: u64,
    /// Clock used to measure how long writes to the client block.
    clock: &'a dyn Clock,
    /// Cumulative milliseconds spent inside a blocking write to the client.
    ///
    /// Specification 14 asks for explicit high/low watermarks that pause
    /// upstream reads. The blocking model produces that behaviour without a
    /// tunable — the connection thread stops reading upstream precisely because
    /// it is stuck here — so there is no watermark to set. There is, though,
    /// something to measure: this is the quantity a watermark would have
    /// controlled, and without it "the client is slow" and "the provider is
    /// slow" look identical from outside (`DI-037`).
    blocked_millis: u64,
    buffer: String,
    anthropic: anthropic::StreamRenderer,
    responses: openai::ResponsesStreamState,
    saw_output: bool,
    closed: bool,
}

impl<'a> StreamSink<'a> {
    fn new(
        request: CanonicalRequest,
        writer: &'a mut ClientWriter,
        created: u64,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            request,
            writer,
            created,
            clock,
            blocked_millis: 0,
            buffer: String::with_capacity(4096),
            anthropic: anthropic::StreamRenderer::new(),
            responses: openai::ResponsesStreamState::new(),
            saw_output: false,
            closed: false,
        }
    }

    fn is_anthropic(&self) -> bool {
        self.request.protocol == ClientProtocol::AnthropicMessages
    }

    /// Whether the caller speaks the Responses dialect, whose stream is named
    /// events terminated by `response.completed` — and which has no `[DONE]`
    /// sentinel, so emitting one would leave a client's reader waiting.
    fn is_responses(&self) -> bool {
        self.request.protocol == ClientProtocol::OpenAiResponses
    }

    fn push(&mut self, bytes: &str) -> Result<(), SinkClosed> {
        if self.closed {
            return Err(SinkClosed);
        }
        // Written straight through rather than accumulated: a stream that is
        // buffered until the end is not a stream, and specification 14 forbids
        // buffering a completion.
        //
        // Timed around the write because this is where backpressure lives: the
        // socket buffer fills, `write` blocks, and this thread stops reading
        // upstream. That is the pause specification 14's high watermark would
        // trigger, arrived at structurally instead of by configuration.
        let before = self.clock.now_millis();
        let result = self.writer.write(bytes.as_bytes()).and_then(|()| self.writer.flush());
        self.blocked_millis = self
            .blocked_millis
            .saturating_add(self.clock.now_millis().saturating_sub(before));
        match result {
            Ok(()) => Ok(()),
            Err(_) => {
                self.closed = true;
                Err(SinkClosed)
            }
        }
    }

    fn emit_error(&mut self, error: &RouterError) {
        if self.closed {
            return;
        }
        self.buffer.clear();
        if self.is_anthropic() {
            let frames = self
                .anthropic
                .render(&self.request, &CanonicalEvent::Error(error.clone()));
            for frame in frames {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else if self.is_responses() {
            // This dialect has a named `error` event, so the error is delivered
            // as one rather than as an untyped `data:` payload.
            for frame in self.responses.error(error) {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else {
            // The OpenAI streaming profile has no error frame, so the error is
            // delivered as a `data:` payload the SDKs surface, followed by the
            // terminator so the client's loop ends cleanly.
            let payload = openai::render_error(error, Some(self.request.request_id));
            wire_sse::encode_data(&mut self.buffer, &payload);
            wire_sse::encode_done(&mut self.buffer);
        }
        let text = core::mem::take(&mut self.buffer);
        let _ = self.push(&text);
    }

    fn finish(&mut self) {
        if self.closed {
            return;
        }
        self.buffer.clear();
        if self.is_anthropic() {
            for frame in self.anthropic.finish(FinishReason::Stop) {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else if self.is_responses() {
            // The terminal frame is `response.completed`, not `[DONE]`.
            let frames = self
                .responses
                .finish(&self.request, FinishReason::Stop, self.created);
            for frame in frames {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else {
            wire_sse::encode_done(&mut self.buffer);
        }
        let text = core::mem::take(&mut self.buffer);
        let _ = self.push(&text);
    }

    fn flush(&mut self) {
        let _ = self.writer.flush();
    }
}

impl EventSink for StreamSink<'_> {
    /// Specification 14's keepalive: an SSE comment, which every conforming
    /// client ignores and every idle-timeout intermediary counts as traffic.
    ///
    /// Sent only while the stream is genuinely idle, so it cannot interleave
    /// with a partially written event. It carries no semantic content, so it is
    /// also safe before the first token — which is exactly when it is needed,
    /// since that is the longest silence a stream has.
    fn keepalive(&mut self) -> Result<(), SinkClosed> {
        if self.closed {
            return Err(SinkClosed);
        }
        let mut comment = String::new();
        wire_sse::encode_keepalive(&mut comment);
        self.push(&comment)
    }

    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed> {
        if event.is_semantic_output() {
            self.saw_output = true;
        }
        self.buffer.clear();

        if self.is_anthropic() {
            let frames = self.anthropic.render(&self.request, event);
            for frame in frames {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else if self.is_responses() {
            let frames = openai::render_responses_chunk(
                &mut self.responses,
                &self.request,
                event,
                self.created,
            );
            for frame in frames {
                wire_sse::encode_event(&mut self.buffer, &frame.event, &frame.data);
            }
        } else if let Some(chunk) =
            openai::render_chat_chunk(&self.request, event, self.created)
        {
            wire_sse::encode_data(&mut self.buffer, &chunk);
        }

        if self.buffer.is_empty() {
            return Ok(());
        }
        let text = core::mem::take(&mut self.buffer);
        self.push(&text)
    }
}

/// Which client dialect a path speaks.
fn protocol_for(path: &str) -> ClientProtocol {
    match path {
        "/v1/messages" => ClientProtocol::AnthropicMessages,
        "/v1/embeddings" => ClientProtocol::OpenAiEmbeddings,
        "/v1/responses" => ClientProtocol::OpenAiResponses,
        "/v1/chat/completions" => ClientProtocol::OpenAiChat,
        _ => ClientProtocol::Native,
    }
}

/// Whether the path is one the router serves, for 405 versus 404.
fn is_known_path(path: &str) -> bool {
    matches!(
        path,
        "/v1/chat/completions"
            | "/v1/responses"
            | "/v1/embeddings"
            | "/v1/messages"
            | "/v1/models"
            | "/v1/tokenize"
            | "/health/live"
            | "/health/ready"
    )
}

/// The anonymous principal to serve an uncredentialed request as, if any.
///
/// Two independent conditions, and they come from two different places on
/// purpose:
///
/// - **Whether** anonymous access is on is runtime state, not configuration —
///   the `AtomicBool` that `POST /admin/v1/settings/anonymous` sets and a
///   `RecordKind::AnonymousAccess` frame restores at startup. A configuration
///   file cannot switch it on; `anonymous_enabled` is not a settings key.
/// - **Who** it is comes from the document, which validated at load that a
///   declared subject names a resolvable principal and tenant and holds no
///   management scope. Nothing here re-decides any of that.
///
/// `None` — the default, and the state of any router that has never been told
/// otherwise — means an uncredentialed request is refused, which is
/// specification 9.2's behaviour.
///
/// Groups come from `group` records exactly as they do for a key-authenticated
/// caller. An anonymous principal named by a `group` gets that group's routing
/// policy, which is the point of naming it.
fn anonymous_principal(state: &RouterState) -> Option<Principal> {
    if !state
        .anonymous_access
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return None;
    }
    let config = state.config();
    let settings = &config.settings;
    let id = hypellm_core::ids::PrincipalId::new(settings.anonymous_principal.as_deref()?).ok()?;
    let tenant = hypellm_core::ids::TenantId::new(settings.anonymous_tenant.as_deref()?).ok()?;
    let scopes = settings
        .anonymous_scopes
        .iter()
        .filter_map(|s| Scope::parse(s))
        .collect();
    let groups = groups_for(state, &tenant, &id);
    Some(Principal::anonymous(id, tenant, scopes, groups))
}

/// Authenticate a request.
///
/// Accepts `Authorization: Bearer` and, for the Anthropic profile, `x-api-key`.
/// Both resolve to the same key store: the header a harness happens to use is a
/// transport detail, not a separate credential type.
fn authenticate(
    state: &RouterState,
    head: &RequestHead,
    peer: Option<std::net::IpAddr>,
) -> Result<Principal, RouterError> {
    // Header *presence* and credential *usability* are two different questions,
    // and anonymous access turns on the difference. `bearer_token` returns
    // `None` for `Bearer ` and for any scheme it does not recognise, so folding
    // the two together would make a caller who presented a malformed
    // credential indistinguishable from one who presented none — and serve it
    // anonymously instead of telling it the credential is broken.
    let authorization = head.headers.get("authorization");
    let api_key_header = head.headers.get("x-api-key");
    let presented = authorization
        .and_then(apikey::bearer_token)
        .or(api_key_header);

    let Some(presented) = presented else {
        // Nothing usable was presented. Anonymous access is reachable only
        // when nothing was presented *at all*: a revoked or expired key is
        // well-formed and fails verification below, and a malformed one is
        // caught by the header check here. Either way the caller is refused
        // rather than quietly downgraded, which is the whole safety property
        // of the setting — `a_rejected_key_is_not_downgraded_to_anonymous` in
        // `tests/anonymous.rs` covers both shapes and fails if this is
        // loosened to "no usable credential".
        if authorization.is_none() && api_key_header.is_none() {
            if let Some(principal) = anonymous_principal(state) {
                return Ok(principal);
            }
        }
        state.telemetry.count(
            hypellm_telemetry::names::AUTH_FAILURES,
            "Authentication failures.",
            &hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Listener, "inference"),
        );
        return Err(hypellm_auth::AuthFailure::NoCredential.to_router_error());
    };

    let record = state
        .keys
        .verify(presented, peer, state.clock.wall_millis())
        .map_err(|rejection| {
            state.telemetry.count(
                hypellm_telemetry::names::AUTH_FAILURES,
                "Authentication failures.",
                &hypellm_telemetry::Labels::new()
                    .with(hypellm_telemetry::LabelName::Listener, "inference")
                    .with(hypellm_telemetry::LabelName::Reason, rejection.code()),
            );
            hypellm_auth::AuthFailure::Key(rejection).to_router_error()
        })?;

    // Groups come from configuration, never from a token claim
    // (specification 25).
    let groups = groups_for(state, &record.tenant, &record.principal);
    Ok(Principal::from_key(&record, groups))
}

/// The groups `principal` actually belongs to, within its own tenant.
///
/// Specification 25 settles the source: "Local role bindings or separately
/// provisioned directory sync; do not infer Google group membership from email
/// domain." Membership comes from `group` records and nowhere else — never from
/// a token claim, and never from the shape of an identifier.
///
/// The tenant filter matters because specification 6.1 places group bindings at
/// precedence 3 and 4, above tenant defaults. Returning a group the principal
/// does not belong to hands it another subject's routing policy; returning one
/// from another tenant breaks isolation outright.
fn groups_for(
    state: &RouterState,
    tenant: &hypellm_core::ids::TenantId,
    principal: &hypellm_core::ids::PrincipalId,
) -> Vec<GroupId> {
    let config = state.config();
    config
        .groups
        .iter()
        .filter(|group| group.tenant == *tenant && group.members.contains(principal))
        .map(|group| group.id.clone())
        .collect()
}

fn list_models(
    state: &RouterState,
    principal: &Principal,
    writer: &mut ClientWriter,
) -> io::Result<Disposition> {
    if !principal.has_scope(Scope::Models) && !principal.has_scope(Scope::Inference) {
        let error = RouterError::new(
            ErrorCode::Forbidden,
            "the credential is not permitted to list models",
        );
        return respond_error(writer, &error, None, ClientProtocol::OpenAiChat);
    }

    let config = state.config();
    let attempted = Vec::new();
    let context = RoutingContext {
        principal: &principal.id,
        groups: &principal.groups,
        tenant: &principal.tenant,
        attempted: &attempted,
        now_millis: 0,
    };

    // Appendix B: "The models endpoint reveals only authorized aliases."
    let visible = config.snapshot.visible_aliases(&context, Operation::Chat);
    let entries: Vec<(&str, Option<&str>)> = visible
        .iter()
        .map(|alias| (alias.id.as_str(), alias.description.as_deref()))
        .collect();

    let payload = openai::render_models(&entries, wall_seconds(state.clock.as_ref()));
    write_json_plain(writer, 200, &payload)?;
    Ok(Disposition::KeepAlive)
}

/// Liveness: is the process running and its event loop responsive.
///
/// Specification 17: "Liveness is process/event-loop". It deliberately does not
/// consult configuration or providers — a liveness probe that fails on a
/// provider outage causes the orchestrator to restart a healthy router.
pub(crate) fn liveness(writer: &mut ClientWriter) -> io::Result<Disposition> {
    write_json_plain(writer, 200, r#"{"status":"ok"}"#)?;
    Ok(Disposition::KeepAlive)
}

/// Readiness: is the router able to serve.
///
/// Specification 17: "readiness requires loaded valid config and required local
/// services, **not every provider healthy**."
/// Readiness on the *data* listener: the status and nothing else.
///
/// Specification 8 requires health endpoints to expose "no sensitive provider
/// detail", and specification 17 defines readiness as "loaded valid config and
/// required local services". A load balancer needs the verdict; it does not
/// need to know which configuration produced it.
///
/// This used to return `config_version` and `config_digest` to any
/// unauthenticated caller who could reach the inference port, which is enough to
/// fingerprint the active configuration and to watch for the moment it changes.
/// No target, provider, or credential was disclosed — the metrics exposition,
/// which does carry those, was correctly moved off this listener — but a
/// deployment's change cadence is not a thing to publish either.
///
/// The detailed form is still available to an authenticated caller on the
/// management listener, which is where an operator asks the question.
fn readiness(state: &RouterState, writer: &mut ClientWriter) -> io::Result<Disposition> {
    let config = state.config();
    let ready = config.snapshot.version > 0 && !config.snapshot.targets.is_empty();
    let payload = format!(
        r#"{{"status":"{}"}}"#,
        if ready { "ready" } else { "not_ready" }
    );
    write_json_plain(writer, if ready { 200 } else { 503 }, &payload)?;
    Ok(Disposition::KeepAlive)
}

/// Write the specification 17 text exposition.
///
/// Public within the crate so the management listener and the dedicated
/// metrics listener share one implementation; the data plane does not serve it.
pub(crate) fn metrics(
    state: &RouterState,
    writer: &mut ClientWriter,
) -> io::Result<Disposition> {
    let body = state.telemetry.exposition();
    let head = ResponseBuilder::new(200)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .and_then(|b| b.finish_with_length(body.len()))
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.write(body.as_bytes())?;
    writer.flush()?;
    Ok(Disposition::KeepAlive)
}

fn no_content(writer: &mut ClientWriter) -> io::Result<Disposition> {
    let head = ResponseBuilder::new(204)
        .finish_no_body()
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.flush()?;
    Ok(Disposition::KeepAlive)
}

fn respond_error(
    writer: &mut ClientWriter,
    error: &RouterError,
    request_id: Option<RequestId>,
    protocol: ClientProtocol,
) -> io::Result<Disposition> {
    let payload = match protocol {
        ClientProtocol::AnthropicMessages => anthropic::render_error(error, request_id),
        _ => openai::render_error(error, request_id),
    };

    let mut builder = ResponseBuilder::new(error.status())
        .header("Content-Type", "application/json")
        .map_err(|_| io::Error::other("response head"))?;
    if let Some(secs) = error.retry_after_secs {
        builder = builder
            .header("Retry-After", &secs.to_string())
            .map_err(|_| io::Error::other("response head"))?;
    }
    if let Some(id) = request_id {
        builder = builder
            .header("X-Request-Id", &id.to_string())
            .map_err(|_| io::Error::other("response head"))?;
    }
    // An authentication failure tells the client which scheme to use, and
    // nothing else.
    if error.code == ErrorCode::Unauthenticated {
        builder = builder
            .header("WWW-Authenticate", "Bearer")
            .map_err(|_| io::Error::other("response head"))?;
    }

    let head = builder
        .finish_with_length(payload.len())
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.write(payload.as_bytes())?;
    writer.flush()?;
    Ok(Disposition::KeepAlive)
}

fn write_json(
    writer: &mut ClientWriter,
    status: u16,
    payload: &str,
    request_id: RequestId,
) -> io::Result<()> {
    let head = ResponseBuilder::new(status)
        .header("Content-Type", "application/json")
        .and_then(|b| b.header("X-Request-Id", &request_id.to_string()))
        .and_then(|b| b.finish_with_length(payload.len()))
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.write(payload.as_bytes())?;
    writer.flush()
}

fn write_json_plain(writer: &mut ClientWriter, status: u16, payload: &str) -> io::Result<()> {
    let head = ResponseBuilder::new(status)
        .header("Content-Type", "application/json")
        .and_then(|b| b.finish_with_length(payload.len()))
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.write(payload.as_bytes())?;
    writer.flush()
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
    use super::*;

    /// A configuration with two groups in one tenant and a third in another,
    /// so that both the membership filter and the tenant filter are exercised.
    const GROUPS: &str = "\
tenant id=acme
tenant id=other
provider id=p family=openai scheme=https host=api.example egress=remote
credential id=c scope=p
target id=p:m provider=p model=m operations=chat context=1000 max_output=100
alias id=a targets=p:m
group id=engineering tenant=acme members=svc:test,user:9
group id=finance tenant=acme members=user:9
group id=engineering-other tenant=other members=svc:test
";

    fn groups_of(principal: &str, tenant: &str) -> Vec<String> {
        // The upstream is never called; `router_with_config` only needs one to
        // exist, and `FakeUpstream` requires at least one canned response.
        let upstream = crate::testing::FakeUpstream::start_sequence(vec![
            crate::testing::CannedResponse::json(200, "{}"),
        ]);
        let router = crate::testing::router_with_config(&upstream, GROUPS);
        let tenant = hypellm_core::ids::TenantId::new(tenant).expect("tenant");
        let principal = hypellm_core::ids::PrincipalId::new(principal).expect("principal");
        groups_for(&router.state, &tenant, &principal)
            .iter()
            .map(|g| g.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_principal_belongs_only_to_the_groups_that_list_it() {
        // Before this was fixed, `groups_for` returned every group named in any
        // role binding, so every authenticated principal was a member of every
        // group — and specification 6.1 places group bindings above tenant
        // defaults, so one subject's policy applied to all of them.
        assert_eq!(groups_of("svc:test", "acme"), vec!["engineering"]);
    }

    #[test]
    fn a_principal_does_not_belong_to_a_group_that_omits_it() {
        // `finance` lists user:9 only.
        assert!(!groups_of("svc:test", "acme").contains(&"finance".to_owned()));
        assert_eq!(groups_of("user:9", "acme"), vec!["engineering", "finance"]);
    }

    #[test]
    fn group_membership_does_not_cross_tenants() {
        // `engineering-other` lists svc:test, but belongs to tenant `other`.
        // Reading it while acting for `acme` would hand one tenant another's
        // routing policy.
        assert_eq!(groups_of("svc:test", "acme"), vec!["engineering"]);
        assert_eq!(groups_of("svc:test", "other"), vec!["engineering-other"]);
    }

    #[test]
    fn an_unknown_principal_belongs_to_no_group() {
        assert!(groups_of("user:nobody", "acme").is_empty());
    }

    #[test]
    fn paths_map_to_their_dialect() {
        assert_eq!(
            protocol_for("/v1/messages"),
            ClientProtocol::AnthropicMessages
        );
        assert_eq!(
            protocol_for("/v1/chat/completions"),
            ClientProtocol::OpenAiChat
        );
        assert_eq!(
            protocol_for("/v1/embeddings"),
            ClientProtocol::OpenAiEmbeddings
        );
        assert_eq!(
            protocol_for("/v1/responses"),
            ClientProtocol::OpenAiResponses
        );
        assert_eq!(protocol_for("/anything"), ClientProtocol::Native);
    }

    #[test]
    fn the_specification_8_endpoints_are_all_known() {
        for path in [
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/embeddings",
            "/v1/models",
            "/v1/messages",
            "/health/live",
            "/health/ready",
            "/v1/tokenize",
        ] {
            assert!(is_known_path(path), "{path} must be a known endpoint");
        }
    }

    #[test]
    fn path_matching_is_exact_and_undecoded() {
        // A router that normalises before matching can be walked somewhere the
        // caller did not name.
        assert!(!is_known_path("/v1/chat/completions/"));
        assert!(!is_known_path("/v1/chat/completions/../models"));
        assert!(!is_known_path("/V1/CHAT/COMPLETIONS"));
        assert!(!is_known_path("//v1/chat/completions"));
        assert!(!is_known_path("/v1/%63hat/completions"));
        assert!(!is_known_path("/v1/chat/completions?x=1"));
        assert!(!is_known_path(""));
    }

    #[test]
    fn operations_map_to_the_scope_they_need() {
        assert_eq!(Scope::for_operation(Operation::Chat), Scope::Inference);
        assert_eq!(
            Scope::for_operation(Operation::Embeddings),
            Scope::Embeddings
        );
        assert_eq!(Scope::for_operation(Operation::Tokenize), Scope::Tokenize);
    }
}
