//! The OpenAI-compatible adapter.
//!
//! Serves five families (specification 7): OpenAI itself, llama.cpp's
//! OpenAI-compatible server, DeepSeek, Moonshot/Kimi, and the opt-in generic
//! adapter. They share a wire format; what differs is which *capabilities* the
//! target declares, and specification 23 is explicit that those are declared
//! rather than inferred — so one encoder plus per-target capability checks is
//! the faithful implementation, not a shortcut.
//!
//! # What the encoder will not do
//!
//! - It never sends a sampling parameter the client did not set. Specification
//!   5.1 distinguishes unset from zero, and a provider's default for an omitted
//!   field is not always the value the router would pick.
//! - It never rewrites a tool schema. Specification 7 lets an adapter *reject*
//!   an unsupported schema; none of them silently repairs one, because the
//!   client's schema is what the model was prompted against.
//! - It never invents a `max_tokens`. An absent limit means the provider's
//!   default, which is the client's expectation.
//!
//! # Two request dialects
//!
//! Specification 7 puts the Responses API first for this family and
//! specification 8 marks `POST /v1/responses` as a MUST for new integrations,
//! so this adapter encodes and decodes two shapes rather than one. They are not
//! variations on each other — every field a router cares about is spelled
//! differently:
//!
//! | Chat Completions | Responses |
//! |---|---|
//! | `messages` | `input` items, or a bare string |
//! | a `system` message | top-level `instructions` |
//! | `text` / `image_url` parts | `input_text` / `input_image` / `output_text` |
//! | `max_tokens` | `max_output_tokens` |
//! | `{type, function: {…}}` tools | flat `{type, name, parameters}` tools |
//! | `response_format` | `text.format` |
//! | `choices[].message` | `output[]` of typed items |
//! | `finish_reason` | `status` plus `incomplete_details.reason` |
//! | `prompt_tokens` / `completion_tokens` | `input_tokens` / `output_tokens` |
//! | unnamed SSE frames ending in `[DONE]` | named SSE events, no sentinel |
//!
//! Which shape is *encoded* follows the operation. What the *caller* speaks is
//! independent of it: specification 5.1 keeps the client protocol and the
//! operation as separate fields precisely because a client may POST
//! `/v1/chat/completions` and be routed to a target served through the
//! Responses API, or POST `/v1/responses` and be routed to Anthropic. Decoding
//! therefore dispatches on the shape of the body the provider actually sent,
//! never on the shape the router asked for.

use crate::contract::{
    Adapter, CredentialHandle, ErrorClassification, RequestMeta, SensitiveHeaders,
    ValidationFailure, ValidationResult, class_for_status, sanitize_provider_code,
};
use hypellm_core::canonical::{
    CanonicalRequest, ContentPart, ImageSource, Operation, ResponseFormat, Role, ToolChoice,
};
use hypellm_core::event::{
    CanonicalEvent, CanonicalUsage, FinishReason, ToolCallDelta, UpstreamErrorClass,
};
use hypellm_core::sensitive::Capped;
use hypellm_core::target::{Capabilities, ProviderFamily};
use wire_json::{Limits, Object, Value, parse, parse_str, to_vec};

/// The OpenAI-compatible adapter.
#[derive(Debug, Clone, Copy)]
pub struct OpenAiAdapter {
    family: ProviderFamily,
}

impl OpenAiAdapter {
    /// Create an adapter for one of the OpenAI-compatible families.
    #[must_use]
    pub const fn new(family: ProviderFamily) -> Self {
        Self { family }
    }

    /// Whether this family sends the `OpenAI-Beta` and organisation headers.
    const fn is_openai_proper(self) -> bool {
        matches!(self.family, ProviderFamily::OpenAi)
    }
}

impl Adapter for OpenAiAdapter {
    fn family(&self) -> ProviderFamily {
        self.family
    }

    fn path_for(&self, request: &CanonicalRequest) -> Result<&'static str, ValidationFailure> {
        Ok(match request.operation {
            Operation::Chat => "/chat/completions",
            Operation::Responses => "/responses",
            Operation::Embeddings => "/embeddings",
            Operation::Tokenize => "/tokenize",
            Operation::Rerank => {
                return Err(ValidationFailure::new(
                    "operation_unsupported",
                    "this provider family does not serve rerank",
                ));
            }
        })
    }

    fn validate(
        &self,
        request: &CanonicalRequest,
        capabilities: &Capabilities,
    ) -> ValidationResult {
        if !capabilities.supports_operation(request.operation) {
            return Err(ValidationFailure::new(
                "operation_unsupported",
                "the selected model does not serve this operation",
            ));
        }
        if request.stream.enabled && !capabilities.streaming {
            return Err(ValidationFailure::new(
                "streaming_unsupported",
                "the selected model does not support streaming",
            )
            .with_param("stream"));
        }
        if request.requires_tools() && !capabilities.tools {
            return Err(ValidationFailure::new(
                "tools_unsupported",
                "the selected model does not support tool calling",
            )
            .with_param("tools"));
        }
        match &request.response_format {
            Some(ResponseFormat::JsonObject) if !capabilities.json_mode => {
                return Err(ValidationFailure::new(
                    "json_mode_unsupported",
                    "the selected model does not support JSON response format",
                )
                .with_param("response_format"));
            }
            Some(ResponseFormat::JsonSchema { .. }) if !capabilities.structured_output => {
                return Err(ValidationFailure::new(
                    "structured_output_unsupported",
                    "the selected model does not support schema-constrained output",
                )
                .with_param("response_format"));
            }
            _ => {}
        }
        if !capabilities.supports_modalities(&request.required_modalities()) {
            return Err(ValidationFailure::new(
                "modality_unsupported",
                "the selected model does not accept one of the supplied content types",
            )
            .with_param("messages"));
        }
        if let Some(want) = request.limits.max_output_tokens {
            if u64::from(want) > u64::from(capabilities.max_output_tokens) {
                return Err(ValidationFailure::new(
                    "max_tokens_too_large",
                    "the requested output length exceeds this model's limit",
                )
                .with_param("max_tokens"));
            }
        }
        if let Err(param) = request.sampling.validate() {
            return Err(ValidationFailure::new(
                "sampling_out_of_range",
                "a sampling parameter is outside the permitted range",
            )
            .with_param(match param {
                "temperature" => "temperature",
                "top_p" => "top_p",
                "frequency_penalty" => "frequency_penalty",
                "presence_penalty" => "presence_penalty",
                _ => "stop",
            }));
        }
        if request.operation == Operation::Embeddings && request.inputs.is_empty() {
            return Err(ValidationFailure::new(
                "empty_input",
                "an embeddings request must supply at least one input",
            )
            .with_param("input"));
        }
        if request.operation == Operation::Chat && request.messages.is_empty() {
            return Err(ValidationFailure::new(
                "empty_messages",
                "a chat request must supply at least one message",
            )
            .with_param("messages"));
        }
        Ok(())
    }

    fn encode_headers(
        &self,
        credential: Option<&CredentialHandle<'_>>,
        meta: &RequestMeta<'_>,
    ) -> SensitiveHeaders {
        let mut headers = SensitiveHeaders::new();
        headers.push("content-type", "application/json");
        headers.push(
            "accept",
            if meta.streaming {
                "text/event-stream"
            } else {
                "application/json"
            },
        );
        // A router-generated identifier, so a provider-side trace can be
        // correlated with a router decision without exposing anything else.
        headers.push("x-request-id", meta.request_id.clone());

        if let Some(credential) = credential {
            if let Some(secret) = credential.expose_str() {
                headers.push_secret("authorization", format!("Bearer {secret}"));
            }
        }
        if self.is_openai_proper() {
            if let Some(key) = &meta.idempotency_key {
                headers.push("idempotency-key", key.clone());
            }
        }
        headers
    }

    fn encode_request(
        &self,
        request: &CanonicalRequest,
        meta: &RequestMeta<'_>,
    ) -> Result<Vec<u8>, ValidationFailure> {
        let mut body = Object::new();
        body.push("model", Value::from(meta.target.native_model.as_str()));

        match request.operation {
            Operation::Embeddings => {
                let inputs: Vec<Value> = request.inputs.iter().map(|s| Value::from(s.as_str())).collect();
                body.push("input", Value::Array(inputs));
                if let Some(dims) = meta.target.capabilities.embedding_dimensions {
                    body.push("dimensions", Value::from(dims));
                }
                push_chat_sampling(&mut body, request);
            }
            // A separate shape, not a Chat Completions body sent to another
            // path: see the dialect table in the module documentation. A real
            // deployment rejects the Chat shape here, so "close enough" is a
            // 400 for every request the router sends.
            Operation::Responses => encode_responses_body(&mut body, request)?,
            _ => {
                body.push("messages", encode_messages(request)?);
                if request.stream.enabled {
                    body.push("stream", Value::from(true));
                    if request.stream.include_usage {
                        let mut options = Object::new();
                        options.push("include_usage", Value::from(true));
                        body.push("stream_options", Value::Object(options));
                    }
                }
                if !request.tools.is_empty() {
                    body.push("tools", encode_tools(request)?);
                }
                if let Some(choice) = &request.tool_choice {
                    body.push("tool_choice", encode_tool_choice(choice));
                }
                if let Some(format) = &request.response_format {
                    body.push_opt("response_format", encode_response_format(format)?);
                }
                push_chat_sampling(&mut body, request);
            }
        }

        let bytes = to_vec(&Value::Object(body));
        if bytes.len() > crate::contract::MAX_REQUEST_BYTES {
            return Err(ValidationFailure::new(
                "request_too_large",
                "the encoded request exceeds the permitted size",
            ));
        }
        Ok(bytes)
    }

    fn decode_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        if !(200..300).contains(&status) {
            return Err(self.classify_error(status, body));
        }
        let value = parse(body, &Limits::DEFAULT).map_err(|_| ErrorClassification {
            class: UpstreamErrorClass::ProtocolViolation,
            provider_code: None,
            safe_detail: Capped::new("the provider returned a malformed response body", 200),
            retry_after_secs: None,
        })?;

        let mut events = Vec::new();
        events.push(CanonicalEvent::Start {
            upstream_id: value.get("id").and_then(|v| v.as_str()).map(str::to_owned),
            native_model: value.get("model").and_then(|v| v.as_str()).map(str::to_owned),
        });

        // The Responses shape is recognised from the body, not from the
        // operation the router asked for. A target configured for one dialect
        // that answers in the other is still understood, and the caller's own
        // dialect never enters into it.
        if is_responses_body(&value) {
            decode_responses_output(&value, &mut events)?;
            return Ok(events);
        }

        // Embeddings.
        if let Some(data) = value.get("data").and_then(|v| v.as_array()) {
            for item in data {
                let index = item.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let values: Vec<f32> = item
                    .get("embedding")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_f64())
                            .map(narrow_embedding_component)
                            .collect()
                    })
                    .unwrap_or_default();
                events.push(CanonicalEvent::Embedding {
                    index: u32::try_from(index).unwrap_or(0),
                    values,
                });
            }
        }

        // Chat completion.
        if let Some(choices) = value.get("choices").and_then(|v| v.as_array()) {
            if let Some(choice) = choices.first() {
                if let Some(message) = choice.get("message") {
                    if let Some(text) = message.get("content").and_then(|v| v.as_str()) {
                        if !text.is_empty() {
                            events.push(CanonicalEvent::TextDelta(text.to_owned()));
                        }
                    }
                    if let Some(reasoning) =
                        message.get("reasoning_content").and_then(|v| v.as_str())
                    {
                        if !reasoning.is_empty() {
                            events.push(CanonicalEvent::ReasoningDelta(reasoning.to_owned()));
                        }
                    }
                    if let Some(calls) = message.get("tool_calls").and_then(|v| v.as_array()) {
                        for (index, call) in calls.iter().enumerate() {
                            events.push(CanonicalEvent::ToolCallDelta(decode_tool_call(
                                call,
                                u32::try_from(index).unwrap_or(0),
                            )));
                        }
                    }
                }
                if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                    events.push(CanonicalEvent::Finish {
                        reason: FinishReason::parse_openai(reason).unwrap_or(FinishReason::Unrecognized),
                    });
                }
            }
        }

        if let Some(usage) = decode_usage(&value) {
            events.push(CanonicalEvent::Usage(usage));
        }
        if !events.iter().any(CanonicalEvent::is_terminal) {
            events.push(CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            });
        }
        Ok(events)
    }

    fn decode_stream_event(
        &self,
        event_name: Option<&str>,
        data: &str,
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        if self.is_stream_terminator(data) {
            return Ok(Vec::new());
        }
        let value = parse_str(data, &Limits::STREAM_EVENT).map_err(|_| ErrorClassification {
            class: UpstreamErrorClass::ProtocolViolation,
            provider_code: None,
            safe_detail: Capped::new("the provider sent a malformed stream event", 200),
            retry_after_secs: None,
        })?;

        // The Responses dialect names every event and repeats the name in the
        // payload's `type`. The name is authoritative when present; the `type`
        // is the fallback for an intermediary that drops it. A Chat Completions
        // chunk carries neither, so this is a shape test, not a mode flag.
        let kind = event_name
            .or_else(|| value.get("type").and_then(|v| v.as_str()))
            .unwrap_or("");
        if kind == "error" || kind.starts_with("response.") {
            return decode_responses_stream_event(kind, &value);
        }

        // Some providers deliver an error mid-stream as a JSON object.
        if let Some(error) = value.get("error") {
            return Err(classify_error_object(error, 500));
        }

        let mut events = Vec::new();
        if let Some(choices) = value.get("choices").and_then(|v| v.as_array()) {
            for choice in choices {
                if let Some(delta) = choice.get("delta") {
                    if let Some(text) = delta.get("content").and_then(|v| v.as_str()) {
                        if !text.is_empty() {
                            events.push(CanonicalEvent::TextDelta(text.to_owned()));
                        }
                    }
                    if let Some(reasoning) = delta.get("reasoning_content").and_then(|v| v.as_str())
                    {
                        if !reasoning.is_empty() {
                            events.push(CanonicalEvent::ReasoningDelta(reasoning.to_owned()));
                        }
                    }
                    if let Some(calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                        for (position, call) in calls.iter().enumerate() {
                            // The provider's own index wins; the position in
                            // the array is only a fallback. Specification 14
                            // requires preserving call identity, and two calls
                            // can arrive in one delta out of order.
                            let index = call
                                .get("index")
                                .and_then(|v| v.as_u64())
                                .and_then(|v| u32::try_from(v).ok())
                                .unwrap_or_else(|| u32::try_from(position).unwrap_or(0));
                            events.push(CanonicalEvent::ToolCallDelta(decode_tool_call(
                                call, index,
                            )));
                        }
                    }
                }
                if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                    events.push(CanonicalEvent::Finish {
                        reason: FinishReason::parse_openai(reason).unwrap_or(FinishReason::Unrecognized),
                    });
                }
            }
        }
        if let Some(usage) = decode_usage(&value) {
            events.push(CanonicalEvent::Usage(usage));
        }
        Ok(events)
    }

    /// Whether a payload is the Chat Completions sentinel.
    ///
    /// Only that dialect has one. **A Responses stream never sends `[DONE]`**:
    /// it ends with `response.completed`, `response.incomplete`,
    /// `response.failed`, or an `error` event, each of which decodes to a
    /// terminal canonical event. A reader that waits for the sentinel before
    /// finishing a Responses stream hangs until the deadline fires, which is
    /// why termination is expressed as [`CanonicalEvent::is_terminal`] rather
    /// than as "the marker arrived".
    ///
    /// The check stays unconditional because it cannot misfire: `[DONE]` is not
    /// valid JSON, so no Responses frame can be mistaken for it.
    fn is_stream_terminator(&self, data: &str) -> bool {
        data.trim() == wire_sse::DONE_MARKER
    }

    fn classify_error(&self, status: u16, body: &[u8]) -> ErrorClassification {
        let parsed = parse(body, &Limits::SMALL).ok();
        if let Some(value) = &parsed {
            if let Some(error) = value.get("error") {
                return classify_error_object(error, status);
            }
        }
        ErrorClassification {
            class: class_for_status(status),
            provider_code: None,
            safe_detail: Capped::new(safe_detail_for(status), 200),
            retry_after_secs: None,
        }
    }
}

fn classify_error_object(error: &Value, status: u16) -> ErrorClassification {
    let error_type = error.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let code = error.get("code").and_then(|v| v.as_str()).unwrap_or("");

    // The provider's own type refines the status. A 400 that says
    // `context_length_exceeded` is a context overflow, which routes differently
    // from an ordinary invalid request.
    let class = if error_type.contains("rate_limit") || code.contains("rate_limit") {
        UpstreamErrorClass::RateLimited
    } else if code.contains("context_length") || error_type.contains("context_length") {
        UpstreamErrorClass::ContextOverflow
    } else if error_type.contains("authentication") || error_type.contains("permission") {
        UpstreamErrorClass::Authentication
    } else if code.contains("content_filter") || error_type.contains("content_filter") {
        UpstreamErrorClass::ContentFilter
    } else {
        class_for_status(status)
    };

    ErrorClassification {
        class,
        // The provider's *type* is recorded, narrowed. Its *message* is not:
        // specification 10 keeps a provider body out of the client's error, and
        // those messages routinely echo the prompt.
        provider_code: Some(sanitize_provider_code(if code.is_empty() {
            error_type
        } else {
            code
        })),
        safe_detail: Capped::new(safe_detail_for(status), 200),
        retry_after_secs: None,
    }
}

const fn safe_detail_for(status: u16) -> &'static str {
    match status {
        400 | 422 => "the provider rejected the request as invalid",
        401 | 403 => "the router's provider credential was not accepted",
        404 => "the provider does not recognise the requested model",
        413 => "the request exceeded the provider's context limit",
        429 => "the provider rate limited the request",
        500..=599 => "the provider returned a server error",
        _ => "the provider returned an unexpected response",
    }
}

/// Narrow one embedding component from the JSON parser's `f64` to the `f32`
/// element type [`CanonicalEvent::Embedding`] is defined with.
///
/// Allowed rather than rewritten: the standard library offers no checked or
/// lossless `f64 -> f32` conversion, so there is nothing to convert *to*. The
/// cast is nevertheless total and panic-free — float-to-float `as` rounds to
/// nearest-even and saturates to `f32::INFINITY` rather than trapping or
/// producing an unspecified value — and the precision loss is the declared
/// intent of the canonical type, not an accident of this call site.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "no checked f64 -> f32 exists; the cast is total and the narrowing is the canonical type's declared precision"
)]
fn narrow_embedding_component(component: f64) -> f32 {
    component as f32
}

fn decode_usage(value: &Value) -> Option<CanonicalUsage> {
    let usage = value.get("usage")?;
    let input = usage.get("prompt_tokens").and_then(|v| v.as_u64())?;
    let output = usage
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cached = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let reasoning = usage
        .get("completion_tokens_details")
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(CanonicalUsage {
        input_tokens: input,
        output_tokens: output,
        cached_input_tokens: cached,
        reasoning_tokens: reasoning,
        // Provider-reported, and marked as such: specification 14 requires the
        // provenance to travel with the number.
        source: hypellm_core::event::UsageSource::ProviderReported,
    })
}

fn decode_tool_call(call: &Value, index: u32) -> ToolCallDelta {
    let function = call.get("function");
    ToolCallDelta {
        index,
        id: call.get("id").and_then(|v| v.as_str()).map(str::to_owned),
        name: function
            .and_then(|f| f.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        arguments_delta: function
            .and_then(|f| f.get("arguments"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
    }
}

/// The sampling tail Chat Completions and embeddings share.
///
/// Only what the client actually set. Specification 5.1's "explicit unset
/// distinct from zero" is the whole reason these are `push_opt` rather than
/// defaulted. The Responses dialect spells the same knobs differently and
/// accepts fewer of them, so it emits its own tail rather than reusing this.
fn push_chat_sampling(body: &mut Object, request: &CanonicalRequest) {
    let sampling = &request.sampling;
    body.push_opt("temperature", sampling.temperature.map(Value::from));
    body.push_opt("top_p", sampling.top_p.map(Value::from));
    body.push_opt("seed", sampling.seed.map(Value::from));
    body.push_opt(
        "frequency_penalty",
        sampling.frequency_penalty.map(Value::from),
    );
    body.push_opt(
        "presence_penalty",
        sampling.presence_penalty.map(Value::from),
    );
    if !sampling.stop.is_empty() {
        body.push(
            "stop",
            Value::Array(sampling.stop.iter().map(|s| Value::from(s.as_str())).collect()),
        );
    }
    body.push_opt(
        "max_tokens",
        request.limits.max_output_tokens.map(Value::from),
    );
}

// -- The Responses dialect -------------------------------------------------
//
// Specification 7, "Responses API first". Everything below encodes or decodes
// `POST /v1/responses`; nothing in it is reachable from the Chat Completions
// path, and neither path may assume the other, because the caller's dialect and
// the target's are independent (see the module documentation).

/// Fill in a Responses request body.
///
/// The caller has already pushed `model`; this adds everything that differs
/// from the Chat Completions shape.
fn encode_responses_body(
    body: &mut Object,
    request: &CanonicalRequest,
) -> Result<(), ValidationFailure> {
    // Canonical system messages are a top-level field in this dialect rather
    // than a turn in the conversation, exactly as in the Anthropic protocol.
    let instructions: Vec<&str> = request
        .messages
        .iter()
        .filter(|m| m.role == Role::System)
        .filter_map(|m| {
            m.content.iter().find_map(|p| match p {
                ContentPart::Text(t) => Some(t.as_str()),
                _ => None,
            })
        })
        .collect();
    if !instructions.is_empty() {
        body.push("instructions", Value::from(instructions.join("\n\n")));
    }

    body.push("input", encode_responses_input(request)?);

    if request.stream.enabled {
        body.push("stream", Value::from(true));
        // No `stream_options`: this dialect reports usage in its terminal
        // `response.completed` event unconditionally, so there is nothing to
        // opt into and the Chat Completions field is rejected.
    }
    if !request.tools.is_empty() {
        body.push("tools", encode_responses_tools(request)?);
    }
    if let Some(choice) = &request.tool_choice {
        body.push("tool_choice", encode_responses_tool_choice(choice));
    }
    if let Some(format) = &request.response_format {
        body.push_opt("text", encode_responses_text_format(format)?);
    }

    body.push_opt("temperature", request.sampling.temperature.map(Value::from));
    body.push_opt("top_p", request.sampling.top_p.map(Value::from));
    // `max_output_tokens`, not `max_tokens`. The canonical field is already
    // named for the thing it limits, which is why nothing here has to guess.
    body.push_opt(
        "max_output_tokens",
        request.limits.max_output_tokens.map(Value::from),
    );
    // `seed`, the two penalties, and `stop` have no counterpart in this
    // dialect. They are dropped rather than translated: there is nothing to
    // translate them into, and inventing an approximation would change the
    // model's behaviour in a way the caller could not see. The encoder does not
    // reject the request over it, because a request is routed to a Responses
    // target by policy and the caller did not choose the dialect.
    Ok(())
}

/// Encode the canonical messages as Responses `input` items.
///
/// Three item types come out of one canonical message list: a `message`
/// carrying content parts, a `function_call` for each tool call the assistant
/// made, and a `function_call_output` for each tool result. The last two are
/// top-level items here rather than fields on a message, and a tool result is
/// tied to the call it answers by `call_id` — losing that tie is how a
/// multi-turn tool conversation stops replaying correctly.
fn encode_responses_input(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut items = Vec::with_capacity(request.messages.len());

    for message in &request.messages {
        // Hoisted into `instructions` above.
        if message.role == Role::System {
            continue;
        }

        let mut parts = Vec::with_capacity(message.content.len());
        for part in &message.content {
            if let ContentPart::ToolResult {
                tool_call_id,
                content,
                ..
            } = part
            {
                let mut item = Object::new();
                item.push("type", Value::from("function_call_output"));
                item.push("call_id", Value::from(tool_call_id.as_str()));
                item.push("output", Value::from(content.as_str()));
                items.push(Value::Object(item));
                continue;
            }
            parts.push(encode_responses_content_part(message.role, part)?);
        }

        if !parts.is_empty() {
            let mut item = Object::new();
            item.push("type", Value::from("message"));
            item.push(
                "role",
                // This dialect has no tool role: a tool message's own text, if
                // it carries any beyond the results hoisted above, is delivered
                // as a user turn.
                Value::from(match message.role {
                    Role::Assistant => "assistant",
                    _ => "user",
                }),
            );
            item.push("content", Value::Array(parts));
            items.push(Value::Object(item));
        }

        for call in &message.tool_calls {
            let mut item = Object::new();
            item.push("type", Value::from("function_call"));
            item.push("call_id", Value::from(call.id.as_str()));
            item.push("name", Value::from(call.name.as_str()));
            // Still the text the model produced, never a re-encoded value tree
            // (specification 14).
            item.push("arguments", Value::from(call.arguments.as_str()));
            items.push(Value::Object(item));
        }
    }

    Ok(Value::Array(items))
}

/// One content part, in the input or output spelling.
///
/// The direction is part of the type name here — `input_text` on the way in,
/// `output_text` on the way out — where Chat Completions uses `text` for both.
fn encode_responses_content_part(
    role: Role,
    part: &ContentPart,
) -> Result<Value, ValidationFailure> {
    let mut object = Object::new();
    match part {
        ContentPart::Text(text) => {
            object.push(
                "type",
                Value::from(if role == Role::Assistant {
                    "output_text"
                } else {
                    "input_text"
                }),
            );
            object.push("text", Value::from(text.as_str()));
        }
        ContentPart::Image(source) => {
            object.push("type", Value::from("input_image"));
            // A plain string, not the nested `{"url": …}` Chat Completions
            // wraps it in. The router still never fetches it (specification 10).
            object.push(
                "image_url",
                match source {
                    ImageSource::Url(u) => Value::from(u.as_str()),
                    ImageSource::Inline {
                        media_type,
                        base64_data,
                    } => Value::from(format!("data:{media_type};base64,{base64_data}")),
                },
            );
        }
        ContentPart::Audio {
            format,
            base64_data,
        } => {
            object.push("type", Value::from("input_audio"));
            let mut audio = Object::new();
            audio.push("data", Value::from(base64_data.as_str()));
            audio.push("format", Value::from(format.as_str()));
            object.push("input_audio", Value::Object(audio));
        }
        // Handled by the caller as its own top-level item; reaching here would
        // mean a tool result had been flattened into a message, which loses the
        // `call_id` tie.
        ContentPart::ToolResult { content, .. } => {
            object.push("type", Value::from("input_text"));
            object.push("text", Value::from(content.as_str()));
        }
    }
    Ok(Value::Object(object))
}

/// Tool definitions, flat rather than nested under a `function` key.
fn encode_responses_tools(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut tools = Vec::with_capacity(request.tools.len());
    for tool in &request.tools {
        // Parsed to confirm it is JSON, then re-serialized — never rewritten.
        // Same rule as the Chat Completions encoder, same reason.
        let parameters = parse_str(&tool.parameters_json, &Limits::SMALL).map_err(|_| {
            ValidationFailure::new(
                "invalid_tool_schema",
                "a tool's parameter schema is not valid JSON",
            )
            .with_param("tools")
        })?;

        let mut object = Object::new();
        object.push("type", Value::from("function"));
        object.push("name", Value::from(tool.name.as_str()));
        object.push_opt("description", tool.description.as_deref().map(Value::from));
        object.push("parameters", parameters);
        if tool.strict {
            object.push("strict", Value::from(true));
        }
        tools.push(Value::Object(object));
    }
    Ok(Value::Array(tools))
}

/// Tool choice; the named form is flat here too.
fn encode_responses_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => Value::from("auto"),
        ToolChoice::None => Value::from("none"),
        ToolChoice::Required => Value::from("required"),
        ToolChoice::Function(name) => {
            let mut object = Object::new();
            object.push("type", Value::from("function"));
            object.push("name", Value::from(name.as_str()));
            Value::Object(object)
        }
    }
}

/// The response format, which lives under `text.format` in this dialect.
///
/// A JSON schema is flat here — `{type, name, schema, strict}` — where Chat
/// Completions nests it under a `json_schema` key.
fn encode_responses_text_format(
    format: &ResponseFormat,
) -> Result<Option<Value>, ValidationFailure> {
    let inner = match format {
        // As in the Chat Completions encoder: free text is the provider's
        // default, so the field is omitted rather than asserted.
        ResponseFormat::Text => return Ok(None),
        ResponseFormat::JsonObject => {
            let mut object = Object::new();
            object.push("type", Value::from("json_object"));
            object
        }
        ResponseFormat::JsonSchema {
            name,
            schema_json,
            strict,
        } => {
            let schema = parse_str(schema_json, &Limits::SMALL).map_err(|_| {
                ValidationFailure::new(
                    "invalid_response_schema",
                    "the response schema is not valid JSON",
                )
                .with_param("response_format")
            })?;
            let mut object = Object::new();
            object.push("type", Value::from("json_schema"));
            object.push("name", Value::from(name.as_str()));
            object.push("schema", schema);
            object.push("strict", Value::from(*strict));
            object
        }
    };
    let mut text = Object::new();
    text.push("format", Value::Object(inner));
    Ok(Some(Value::Object(text)))
}

/// Whether a success body is a Responses payload.
///
/// `object: "response"` is the declaration; the structural test is the fallback
/// for a compatible server that omits it. `choices` being absent is part of the
/// test so that a body carrying both — which no real provider sends — is read
/// as the Chat Completion it claims to be rather than silently changing
/// meaning.
fn is_responses_body(value: &Value) -> bool {
    value.get("object").and_then(|v| v.as_str()) == Some("response")
        || (value.get("output").and_then(|v| v.as_array()).is_some()
            && value.get("choices").is_none())
}

/// Decode a non-streaming Responses body into canonical events.
///
/// Appends output, usage, and exactly one terminal event. The `Start` event has
/// already been pushed by the caller from the shared `id`/`model` fields.
fn decode_responses_output(
    value: &Value,
    events: &mut Vec<CanonicalEvent>,
) -> Result<(), ErrorClassification> {
    let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("");

    // A failed generation is not a completion with an unhappy reason: nothing
    // usable was produced, and nothing has reached the client yet, so this is
    // classified as an upstream failure — which is what lets specification 6.5
    // consider another target. 500 is assumed because the transport status was
    // a success; the provider's own code refines the class.
    if status == "failed" {
        let error = value.get("error").unwrap_or(value);
        return Err(classify_error_object(error, 500));
    }

    let mut saw_tool_call = false;
    if let Some(output) = value.get("output").and_then(|v| v.as_array()) {
        for (position, item) in output.iter().enumerate() {
            // The item's position in `output` is its canonical index, the same
            // rule the Anthropic decoder applies to content blocks. Specification
            // 14 requires call identity to survive, and a counter over tool
            // calls only would collide with the block indices a mixed output
            // produces.
            let index = u32::try_from(position).unwrap_or(0);
            match item.get("type").and_then(|v| v.as_str()) {
                Some("message") => {
                    if let Some(parts) = item.get("content").and_then(|v| v.as_array()) {
                        for part in parts {
                            if part.get("type").and_then(|v| v.as_str()) != Some("output_text") {
                                continue;
                            }
                            if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                if !text.is_empty() {
                                    events.push(CanonicalEvent::TextDelta(text.to_owned()));
                                }
                            }
                        }
                    }
                }
                Some("function_call") => {
                    saw_tool_call = true;
                    events.push(CanonicalEvent::ToolCallDelta(decode_responses_tool_call(
                        item, index,
                    )));
                }
                Some("reasoning") => {
                    if let Some(parts) = item.get("summary").and_then(|v| v.as_array()) {
                        for part in parts {
                            if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                if !text.is_empty() {
                                    events.push(CanonicalEvent::ReasoningDelta(text.to_owned()));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(usage) = decode_responses_usage(value) {
        events.push(CanonicalEvent::Usage(usage));
    }
    events.push(CanonicalEvent::Finish {
        reason: responses_finish_reason(value, saw_tool_call),
    });
    Ok(())
}

/// One `function_call` output item as a canonical tool call delta.
///
/// `call_id` is preferred over `id`: it is the identifier a later
/// `function_call_output` must quote, so it is the one the client needs back.
fn decode_responses_tool_call(item: &Value, index: u32) -> ToolCallDelta {
    ToolCallDelta {
        index,
        id: item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        name: item.get("name").and_then(|v| v.as_str()).map(str::to_owned),
        arguments_delta: item
            .get("arguments")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
    }
}

/// Usage in the Responses spelling.
fn decode_responses_usage(value: &Value) -> Option<CanonicalUsage> {
    let usage = value.get("usage")?;
    // `input_tokens`/`output_tokens`, not `prompt_tokens`/`completion_tokens`.
    let input = usage.get("input_tokens").and_then(|v| v.as_u64());
    let output = usage.get("output_tokens").and_then(|v| v.as_u64());
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(CanonicalUsage {
        input_tokens: input.unwrap_or(0),
        output_tokens: output.unwrap_or(0),
        cached_input_tokens: usage
            .get("input_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        reasoning_tokens: usage
            .get("output_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        source: hypellm_core::event::UsageSource::ProviderReported,
    })
}

/// Map a response object's `status` onto a canonical finish reason.
///
/// There is no `finish_reason` in this dialect: completion is a `status`, and a
/// truncation reason appears in `incomplete_details.reason`. Anything this
/// router does not recognise — a status or a reason — is
/// [`FinishReason::Unrecognized`] and never [`FinishReason::Stop`]: telling a
/// caller the model finished naturally when the router has no idea whether it
/// did is the failure that variant exists to prevent.
fn responses_finish_reason(response: &Value, saw_tool_call: bool) -> FinishReason {
    match response.get("status").and_then(|v| v.as_str()) {
        Some("completed") => {
            // `completed` is reported even when the model stopped to wait for
            // tool results. Reporting a plain stop there would tell a
            // Chat-speaking caller the turn was finished when a tool call is
            // outstanding.
            if saw_tool_call {
                FinishReason::ToolCalls
            } else {
                FinishReason::Stop
            }
        }
        Some("incomplete") => match response
            .get("incomplete_details")
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str())
        {
            Some("max_output_tokens") => FinishReason::Length,
            Some("content_filter") => FinishReason::ContentFilter,
            _ => FinishReason::Unrecognized,
        },
        Some("failed") => FinishReason::Error,
        _ => FinishReason::Unrecognized,
    }
}

/// Decode one named Responses stream event.
///
/// Only the incremental events carry content. The `.done` events repeat what
/// the deltas already delivered — `response.output_text.done` carries the whole
/// text, `response.function_call_arguments.done` the whole argument string, and
/// the terminal `response.completed` the entire `output` array — so emitting
/// anything from them would duplicate the completion the client already has.
fn decode_responses_stream_event(
    kind: &str,
    value: &Value,
) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
    // A dedicated `error` event, flat rather than nested; the fallback handles
    // a server that wraps it anyway.
    if kind == "error" {
        return Err(classify_error_object(value.get("error").unwrap_or(value), 500));
    }

    let mut events = Vec::new();
    match kind {
        "response.created" => {
            let response = value.get("response");
            events.push(CanonicalEvent::Start {
                upstream_id: response
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                native_model: response
                    .and_then(|r| r.get("model"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
            });
        }
        "response.output_item.added" => {
            // A tool call's identity arrives here and its arguments in later
            // fragments tied to the same `output_index`. Losing the tie yields a
            // named call with no arguments and an anonymous fragment.
            if let Some(item) = value.get("item") {
                if item.get("type").and_then(|v| v.as_str()) == Some("function_call") {
                    events.push(CanonicalEvent::ToolCallDelta(decode_responses_tool_call(
                        item,
                        responses_output_index(value),
                    )));
                }
            }
        }
        "response.output_text.delta" => {
            if let Some(text) = value.get("delta").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    events.push(CanonicalEvent::TextDelta(text.to_owned()));
                }
            }
        }
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            if let Some(text) = value.get("delta").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    events.push(CanonicalEvent::ReasoningDelta(text.to_owned()));
                }
            }
        }
        "response.function_call_arguments.delta" => {
            if let Some(fragment) = value.get("delta").and_then(|v| v.as_str()) {
                events.push(CanonicalEvent::ToolCallDelta(ToolCallDelta {
                    index: responses_output_index(value),
                    id: None,
                    name: None,
                    arguments_delta: fragment.to_owned(),
                }));
            }
        }
        "response.completed" | "response.incomplete" | "response.failed" => {
            let response = value.get("response").unwrap_or(value);
            if let Some(usage) = decode_responses_usage(response) {
                events.push(CanonicalEvent::Usage(usage));
            }
            // Whether the turn ended on a tool call is read from the terminal
            // event's own `output`, because an adapter decodes one event at a
            // time and holds no state between them.
            let saw_tool_call = response
                .get("output")
                .and_then(|v| v.as_array())
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|i| i.get("type").and_then(|v| v.as_str()) == Some("function_call"))
                });
            events.push(CanonicalEvent::Finish {
                reason: responses_finish_reason(response, saw_tool_call),
            });
        }
        // Everything else — the `.added`/`.done` bookkeeping around content
        // parts and items, and any event added after this mapping was written —
        // carries no canonical meaning. Ignoring an unknown event is correct;
        // failing on one would end a healthy stream.
        _ => {}
    }
    Ok(events)
}

/// The output-item index an event belongs to.
fn responses_output_index(value: &Value) -> u32 {
    value
        .get("output_index")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

fn encode_messages(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut messages = Vec::with_capacity(request.messages.len());

    for message in &request.messages {
        let mut object = Object::new();
        object.push("role", Value::from(message.role.as_str()));
        object.push_opt("name", message.name.as_deref().map(Value::from));

        // A tool result is its own message shape in this protocol.
        if let Some(ContentPart::ToolResult {
            tool_call_id,
            content,
            ..
        }) = message.content.first()
        {
            if message.role == Role::Tool {
                object.push("tool_call_id", Value::from(tool_call_id.as_str()));
                object.push("content", Value::from(content.as_str()));
                messages.push(Value::Object(object));
                continue;
            }
        }

        // A text-only message uses the string form, which every
        // OpenAI-compatible server accepts. The array form is used only when
        // the message actually carries a non-text part — some servers,
        // llama.cpp among them, do not accept the array form for plain text.
        if let Some(text) = message.as_text() {
            object.push("content", Value::from(text));
        } else {
            let mut parts = Vec::with_capacity(message.content.len());
            for part in &message.content {
                parts.push(encode_content_part(part)?);
            }
            object.push("content", Value::Array(parts));
        }

        if !message.tool_calls.is_empty() {
            let calls: Vec<Value> = message
                .tool_calls
                .iter()
                .map(|call| {
                    let mut function = Object::new();
                    function.push("name", Value::from(call.name.as_str()));
                    function.push("arguments", Value::from(call.arguments.as_str()));
                    let mut wrapper = Object::new();
                    wrapper.push("id", Value::from(call.id.as_str()));
                    wrapper.push("type", Value::from("function"));
                    wrapper.push("function", Value::Object(function));
                    Value::Object(wrapper)
                })
                .collect();
            object.push("tool_calls", Value::Array(calls));
        }

        messages.push(Value::Object(object));
    }

    Ok(Value::Array(messages))
}

fn encode_content_part(part: &ContentPart) -> Result<Value, ValidationFailure> {
    let mut object = Object::new();
    match part {
        ContentPart::Text(text) => {
            object.push("type", Value::from("text"));
            object.push("text", Value::from(text.as_str()));
        }
        ContentPart::Image(source) => {
            object.push("type", Value::from("image_url"));
            let mut url = Object::new();
            match source {
                ImageSource::Url(u) => url.push("url", Value::from(u.as_str())),
                ImageSource::Inline {
                    media_type,
                    base64_data,
                } => url.push(
                    "url",
                    Value::from(format!("data:{media_type};base64,{base64_data}")),
                ),
            }
            object.push("image_url", Value::Object(url));
        }
        ContentPart::Audio {
            format,
            base64_data,
        } => {
            object.push("type", Value::from("input_audio"));
            let mut audio = Object::new();
            audio.push("data", Value::from(base64_data.as_str()));
            audio.push("format", Value::from(format.as_str()));
            object.push("input_audio", Value::Object(audio));
        }
        ContentPart::ToolResult { content, .. } => {
            object.push("type", Value::from("text"));
            object.push("text", Value::from(content.as_str()));
        }
    }
    Ok(Value::Object(object))
}

fn encode_tools(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut tools = Vec::with_capacity(request.tools.len());
    for tool in &request.tools {
        // The client's schema text is parsed to confirm it is JSON, then
        // re-serialized. It is never rewritten: specification 7 permits
        // rejecting an unsupported schema, not repairing one.
        let parameters = parse_str(&tool.parameters_json, &Limits::SMALL).map_err(|_| {
            ValidationFailure::new(
                "invalid_tool_schema",
                "a tool's parameter schema is not valid JSON",
            )
            .with_param("tools")
        })?;

        let mut function = Object::new();
        function.push("name", Value::from(tool.name.as_str()));
        function.push_opt("description", tool.description.as_deref().map(Value::from));
        function.push("parameters", parameters);
        if tool.strict {
            function.push("strict", Value::from(true));
        }

        let mut wrapper = Object::new();
        wrapper.push("type", Value::from("function"));
        wrapper.push("function", Value::Object(function));
        tools.push(Value::Object(wrapper));
    }
    Ok(Value::Array(tools))
}

fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => Value::from("auto"),
        ToolChoice::None => Value::from("none"),
        ToolChoice::Required => Value::from("required"),
        ToolChoice::Function(name) => {
            let mut function = Object::new();
            function.push("name", Value::from(name.as_str()));
            let mut wrapper = Object::new();
            wrapper.push("type", Value::from("function"));
            wrapper.push("function", Value::Object(function));
            Value::Object(wrapper)
        }
    }
}

fn encode_response_format(format: &ResponseFormat) -> Result<Option<Value>, ValidationFailure> {
    Ok(match format {
        ResponseFormat::Text => None,
        ResponseFormat::JsonObject => {
            let mut object = Object::new();
            object.push("type", Value::from("json_object"));
            Some(Value::Object(object))
        }
        ResponseFormat::JsonSchema {
            name,
            schema_json,
            strict,
        } => {
            let schema = parse_str(schema_json, &Limits::SMALL).map_err(|_| {
                ValidationFailure::new(
                    "invalid_response_schema",
                    "the response schema is not valid JSON",
                )
                .with_param("response_format")
            })?;
            let mut inner = Object::new();
            inner.push("name", Value::from(name.as_str()));
            inner.push("schema", schema);
            inner.push("strict", Value::from(*strict));
            let mut object = Object::new();
            object.push("type", Value::from("json_schema"));
            object.push("json_schema", Value::Object(inner));
            Some(Value::Object(object))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{request_fixture, target_fixture, meta_fixture};
    use hypellm_core::canonical::{Message, Sampling, ToolDef};
    use hypellm_core::ids::CredentialRef;

    fn adapter() -> OpenAiAdapter {
        OpenAiAdapter::new(ProviderFamily::OpenAi)
    }

    fn encoded(request: &CanonicalRequest) -> Value {
        let target = target_fixture();
        let endpoint = target_fixture_endpoint();
        let meta = meta_fixture(&target, &endpoint, request.stream.enabled);
        let bytes = adapter().encode_request(request, &meta).expect("encodes");
        parse(&bytes, &Limits::DEFAULT).expect("valid JSON")
    }

    fn target_fixture_endpoint() -> hypellm_core::target::Endpoint {
        hypellm_core::target::Endpoint {
            scheme: hypellm_core::target::EndpointScheme::Https,
            host: "api.openai.com".to_owned(),
            port: 443,
            base_path: "/v1".to_owned(),
        }
    }

    // -- Encoding -----------------------------------------------------------

    #[test]
    fn a_chat_request_encodes_to_the_expected_shape() {
        let request = request_fixture();
        let body = encoded(&request);

        assert_eq!(body.field_str("model").unwrap(), "gpt-4.1");
        let messages = body.field_array("messages").unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].field_str("role").unwrap(), "system");
        assert_eq!(messages[1].field_str("role").unwrap(), "user");
        assert_eq!(messages[1].field_str("content").unwrap(), "Explain backpressure.");
    }

    #[test]
    fn unset_sampling_parameters_are_omitted_entirely() {
        // Specification 5.1: unset is distinct from zero. Sending a default the
        // client did not ask for changes the model's behaviour.
        let mut request = request_fixture();
        request.sampling = Sampling::default();
        let body = encoded(&request);

        for field in [
            "temperature",
            "top_p",
            "seed",
            "frequency_penalty",
            "presence_penalty",
            "stop",
        ] {
            assert!(
                body.get(field).is_none(),
                "unset {field} must not be sent, found {:?}",
                body.get(field)
            );
        }
    }

    #[test]
    fn a_zero_sampling_value_is_sent() {
        let mut request = request_fixture();
        request.sampling = Sampling {
            temperature: Some(0.0),
            top_p: Some(0.0),
            ..Sampling::default()
        };
        let body = encoded(&request);
        assert_eq!(body.opt_field_f64("temperature").unwrap(), Some(0.0));
        assert_eq!(body.opt_field_f64("top_p").unwrap(), Some(0.0));
    }

    #[test]
    fn streaming_adds_the_stream_flag_and_options() {
        let mut request = request_fixture();
        request.stream.enabled = true;
        request.stream.include_usage = true;
        let body = encoded(&request);
        assert_eq!(body.opt_field_bool("stream").unwrap(), Some(true));
        assert_eq!(
            body.get("stream_options")
                .unwrap()
                .opt_field_bool("include_usage")
                .unwrap(),
            Some(true)
        );

        let mut request = request_fixture();
        request.stream.enabled = false;
        let body = encoded(&request);
        assert!(body.get("stream").is_none());
    }

    #[test]
    fn a_tool_schema_is_forwarded_unchanged() {
        // Specification 7: an adapter may reject an unsupported schema; it does
        // not rewrite one. The model was prompted against the client's schema.
        let mut request = request_fixture();
        request.tools.push(ToolDef {
            name: "lookup".to_owned(),
            description: Some("Look something up".to_owned()),
            parameters_json: r#"{"type":"object","properties":{"q":{"type":"string","description":"the query"}},"required":["q"],"additionalProperties":false}"#
                .to_owned(),
            strict: true,
        });
        let body = encoded(&request);

        let tools = body.field_array("tools").unwrap();
        assert_eq!(tools.len(), 1);
        let function = tools[0].get("function").unwrap();
        assert_eq!(function.field_str("name").unwrap(), "lookup");
        assert_eq!(function.opt_field_bool("strict").unwrap(), Some(true));

        let parameters = function.get("parameters").unwrap();
        assert_eq!(parameters.field_str("type").unwrap(), "object");
        assert_eq!(
            parameters.get("required").unwrap().as_array().unwrap().len(),
            1
        );
        assert_eq!(
            parameters.opt_field_bool("additionalProperties").unwrap(),
            Some(false)
        );
        // The nested description survives, which is what "unchanged" means.
        assert_eq!(
            parameters
                .get("properties")
                .unwrap()
                .get("q")
                .unwrap()
                .field_str("description")
                .unwrap(),
            "the query"
        );
    }

    #[test]
    fn a_malformed_tool_schema_is_rejected_not_repaired() {
        let mut request = request_fixture();
        request.tools.push(ToolDef {
            name: "bad".to_owned(),
            description: None,
            parameters_json: "{not json".to_owned(),
            strict: false,
        });
        let target = target_fixture();
        let endpoint = target_fixture_endpoint();
        let meta = meta_fixture(&target, &endpoint, false);
        let failure = adapter()
            .encode_request(&request, &meta)
            .expect_err("must reject");
        assert_eq!(failure.code, "invalid_tool_schema");
        assert_eq!(failure.param, Some("tools"));
    }

    #[test]
    fn tool_choice_shapes() {
        let mut request = request_fixture();
        request.tools.push(ToolDef {
            name: "t".to_owned(),
            description: None,
            parameters_json: "{}".to_owned(),
            strict: false,
        });

        request.tool_choice = Some(ToolChoice::Auto);
        assert_eq!(encoded(&request).field_str("tool_choice").unwrap(), "auto");

        request.tool_choice = Some(ToolChoice::Required);
        assert_eq!(encoded(&request).field_str("tool_choice").unwrap(), "required");

        request.tool_choice = Some(ToolChoice::Function("lookup".to_owned()));
        let body = encoded(&request);
        let choice = body.get("tool_choice").unwrap();
        assert_eq!(choice.field_str("type").unwrap(), "function");
        assert_eq!(
            choice.get("function").unwrap().field_str("name").unwrap(),
            "lookup"
        );
    }

    #[test]
    fn text_only_messages_use_the_string_form() {
        // llama.cpp and several compatible servers reject the array form for
        // plain text, so the encoder uses the string form when it can.
        let request = request_fixture();
        let body = encoded(&request);
        let messages = body.field_array("messages").unwrap();
        assert!(messages[0].get("content").unwrap().as_str().is_some());
    }

    #[test]
    fn multimodal_messages_use_the_array_form() {
        let mut request = request_fixture();
        request.messages.push(Message {
            role: Role::User,
            content: vec![
                ContentPart::Text("what is this".to_owned()),
                ContentPart::Image(ImageSource::Url("https://example.com/x.png".to_owned())),
            ],
            name: None,
            tool_calls: Vec::new(),
        });
        let body = encoded(&request);
        let messages = body.field_array("messages").unwrap();
        let parts = messages[2].get("content").unwrap().as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].field_str("type").unwrap(), "text");
        assert_eq!(parts[1].field_str("type").unwrap(), "image_url");
        assert_eq!(
            parts[1]
                .get("image_url")
                .unwrap()
                .field_str("url")
                .unwrap(),
            "https://example.com/x.png"
        );
    }

    #[test]
    fn inline_images_become_data_uris() {
        let mut request = request_fixture();
        request.messages.push(Message {
            role: Role::User,
            content: vec![ContentPart::Image(ImageSource::Inline {
                media_type: "image/png".to_owned(),
                base64_data: "AAAA".to_owned(),
            })],
            name: None,
            tool_calls: Vec::new(),
        });
        let body = encoded(&request);
        let messages = body.field_array("messages").unwrap();
        let parts = messages[2].get("content").unwrap().as_array().unwrap();
        assert_eq!(
            parts[0].get("image_url").unwrap().field_str("url").unwrap(),
            "data:image/png;base64,AAAA"
        );
    }

    #[test]
    fn an_embeddings_request_uses_the_input_field() {
        let mut request = request_fixture();
        request.operation = Operation::Embeddings;
        request.messages.clear();
        request.inputs = vec!["one".to_owned(), "two".to_owned()];
        let body = encoded(&request);
        assert_eq!(body.field_array("input").unwrap().len(), 2);
        assert!(body.get("messages").is_none());
    }

    // -- Headers ------------------------------------------------------------

    #[test]
    fn headers_carry_the_credential_as_a_bearer_token() {
        let reference = CredentialRef::new("cred_openai").unwrap();
        let credential = CredentialHandle::new(&reference, b"sk-live-secret");
        let target = target_fixture();
        let endpoint = target_fixture_endpoint();
        let meta = meta_fixture(&target, &endpoint, true);

        let headers = adapter().encode_headers(Some(&credential), &meta);
        let pairs: Vec<(&str, &str)> = headers.iter().collect();
        assert!(pairs.contains(&("authorization", "Bearer sk-live-secret")));
        assert!(pairs.contains(&("content-type", "application/json")));
        assert!(pairs.contains(&("accept", "text/event-stream")));

        // And the debug rendering does not disclose it.
        assert!(!format!("{headers:?}").contains("sk-live-secret"));
    }

    #[test]
    fn a_request_without_a_credential_sends_no_authorization() {
        // A local llama.cpp server needs no credential.
        let target = target_fixture();
        let endpoint = target_fixture_endpoint();
        let meta = meta_fixture(&target, &endpoint, false);
        let headers = OpenAiAdapter::new(ProviderFamily::LlamaCpp).encode_headers(None, &meta);
        assert!(headers.names().all(|n| n != "authorization"));
        assert!(headers.iter().any(|(n, _)| n == "content-type"));
    }

    // -- Decoding -----------------------------------------------------------

    #[test]
    fn a_complete_response_decodes_to_events() {
        let body = br#"{
            "id": "chatcmpl-1",
            "model": "gpt-4.1",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello, world"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}
        }"#;
        let events = adapter().decode_response(200, body).expect("decodes");

        assert!(matches!(events[0], CanonicalEvent::Start { .. }));
        assert!(events.iter().any(|e| matches!(
            e,
            CanonicalEvent::TextDelta(t) if t == "Hello, world"
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            CanonicalEvent::Finish { reason: FinishReason::Stop }
        )));

        let usage = adapter().usage_from_events(&events);
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 3);
        assert!(usage.is_reported(), "provider-reported usage must be marked");
    }

    #[test]
    fn a_response_without_usage_yields_an_estimated_zero() {
        let body = br#"{"id":"x","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}"#;
        let events = adapter().decode_response(200, body).expect("decodes");
        let usage = adapter().usage_from_events(&events);
        assert!(!usage.is_reported(), "an absent usage must not look reported");
    }

    #[test]
    fn stream_events_decode_incrementally() {
        let a = adapter();
        let frames = [
            r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Hel"}}]}"#,
            r#"{"id":"1","choices":[{"delta":{"content":"lo"}}]}"#,
            r#"{"id":"1","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"id":"1","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
        ];
        let mut all = Vec::new();
        for frame in frames {
            all.extend(a.decode_stream_event(None, frame).expect("decodes"));
        }

        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for event in &all {
            accumulator.push(event);
        }
        assert_eq!(accumulator.text, "Hello");
        assert_eq!(accumulator.finish, Some(FinishReason::Stop));
        assert_eq!(accumulator.usage.expect("usage").input_tokens, 5);
    }

    #[test]
    fn the_terminator_is_recognised_and_yields_nothing() {
        let a = adapter();
        assert!(a.is_stream_terminator("[DONE]"));
        assert!(a.is_stream_terminator(" [DONE] "));
        assert!(!a.is_stream_terminator(r#"{"choices":[]}"#));
        assert!(a.decode_stream_event(None, "[DONE]").unwrap().is_empty());
    }

    #[test]
    fn tool_call_deltas_preserve_the_provider_index() {
        // Specification 14: call identity and ordering must survive. A provider
        // that interleaves two calls must not have their arguments merged.
        let a = adapter();
        let frames = [
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"f","arguments":"{\"x\":"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"g","arguments":"{\"y\":"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}}]}}]}"#,
        ];
        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for frame in frames {
            for event in a.decode_stream_event(None, frame).expect("decodes") {
                accumulator.push(&event);
            }
        }
        let calls = accumulator.sorted_tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].id, "call_a");
        assert_eq!(calls[0].arguments, r#"{"x":1}"#);
        assert_eq!(calls[1].id, "call_b");
        assert_eq!(calls[1].arguments, r#"{"y":2}"#);
    }

    #[test]
    fn a_malformed_stream_event_is_a_protocol_violation() {
        let err = adapter()
            .decode_stream_event(None, "{not json")
            .expect_err("must fail");
        assert_eq!(err.class, UpstreamErrorClass::ProtocolViolation);
    }

    #[test]
    fn embeddings_decode_to_vectors() {
        let body = br#"{"model":"text-embedding-3","data":[{"index":0,"embedding":[0.1,0.2,0.3]},{"index":1,"embedding":[0.4]}]}"#;
        let events = adapter().decode_response(200, body).expect("decodes");
        let vectors: Vec<&CanonicalEvent> = events
            .iter()
            .filter(|e| matches!(e, CanonicalEvent::Embedding { .. }))
            .collect();
        assert_eq!(vectors.len(), 2);
        match vectors[0] {
            CanonicalEvent::Embedding { index, values } => {
                assert_eq!(*index, 0);
                assert_eq!(values.len(), 3);
            }
            other => panic!("expected an embedding, got {other:?}"),
        }
    }

    // -- Error classification -----------------------------------------------

    #[test]
    fn provider_errors_classify_by_type_not_only_status() {
        let a = adapter();

        let rate = a.classify_error(
            429,
            br#"{"error":{"message":"Rate limit reached","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
        );
        assert_eq!(rate.class, UpstreamErrorClass::RateLimited);
        assert!(rate.is_retriable());

        let context = a.classify_error(
            400,
            br#"{"error":{"message":"maximum context length is 8192 tokens","type":"invalid_request_error","code":"context_length_exceeded"}}"#,
        );
        assert_eq!(context.class, UpstreamErrorClass::ContextOverflow);
        assert!(!context.is_retriable(), "another target has the same limit shape");

        let auth = a.classify_error(
            401,
            br#"{"error":{"message":"Incorrect API key","type":"authentication_error"}}"#,
        );
        assert_eq!(auth.class, UpstreamErrorClass::Authentication);
        assert!(!auth.is_retriable());

        let server = a.classify_error(503, b"upstream unavailable");
        assert_eq!(server.class, UpstreamErrorClass::ServerError);
        assert!(server.is_retriable());
    }

    #[test]
    fn a_provider_message_never_reaches_the_client_detail() {
        // Provider messages routinely echo the prompt or an internal hostname.
        let classification = adapter().classify_error(
            400,
            br#"{"error":{"message":"Invalid prompt: 'my secret internal data' at host db-7.internal","type":"invalid_request_error"}}"#,
        );
        let detail = classification.safe_detail.as_str();
        assert!(!detail.contains("secret internal data"));
        assert!(!detail.contains("db-7.internal"));
        assert_eq!(detail, "the provider rejected the request as invalid");
        // The type is recorded for diagnosis, narrowed.
        assert_eq!(
            classification.provider_code.expect("code").as_str(),
            "invalid_request_error"
        );
    }

    #[test]
    fn a_hostile_provider_code_is_narrowed() {
        let classification = adapter().classify_error(
            400,
            br#"{"error":{"type":"bad\ntype\"with'quotes","code":""}}"#,
        );
        let code = classification.provider_code.expect("code");
        assert!(!code.as_str().contains('\n'));
        assert!(!code.as_str().contains('"'));
    }

    #[test]
    fn an_error_status_makes_decode_response_fail() {
        let err = adapter()
            .decode_response(500, b"{}")
            .expect_err("an error status must not decode as success");
        assert_eq!(err.class, UpstreamErrorClass::ServerError);
    }

    #[test]
    fn a_mid_stream_error_object_is_classified() {
        let err = adapter()
            .decode_stream_event(None, r#"{"error":{"type":"rate_limit_error"}}"#)
            .expect_err("must fail");
        assert_eq!(err.class, UpstreamErrorClass::RateLimited);
    }

    // -- Validation ---------------------------------------------------------

    #[test]
    fn validation_refuses_capabilities_the_target_lacks() {
        let a = adapter();
        let mut capabilities = target_fixture().capabilities;
        capabilities.tools = false;
        capabilities.streaming = false;
        capabilities.json_mode = false;

        let mut request = request_fixture();
        request.stream.enabled = true;
        assert_eq!(
            a.validate(&request, &capabilities).unwrap_err().code,
            "streaming_unsupported"
        );

        let mut request = request_fixture();
        request.tools.push(ToolDef {
            name: "t".to_owned(),
            description: None,
            parameters_json: "{}".to_owned(),
            strict: false,
        });
        assert_eq!(
            a.validate(&request, &capabilities).unwrap_err().code,
            "tools_unsupported"
        );

        let mut request = request_fixture();
        request.response_format = Some(ResponseFormat::JsonObject);
        assert_eq!(
            a.validate(&request, &capabilities).unwrap_err().code,
            "json_mode_unsupported"
        );
    }

    #[test]
    fn validation_accepts_a_capable_target() {
        let target = target_fixture();
        let mut request = request_fixture();
        request.stream.enabled = true;
        assert!(adapter().validate(&request, &target.capabilities).is_ok());
    }

    #[test]
    fn validation_rejects_an_over_long_output_request() {
        let target = target_fixture();
        let mut request = request_fixture();
        request.limits.max_output_tokens = Some(u32::MAX);
        let failure = adapter()
            .validate(&request, &target.capabilities)
            .unwrap_err();
        assert_eq!(failure.code, "max_tokens_too_large");
        assert_eq!(failure.param, Some("max_tokens"));
    }

    #[test]
    fn validation_rejects_empty_inputs() {
        let target = target_fixture();
        let a = adapter();

        let mut request = request_fixture();
        request.messages.clear();
        assert_eq!(
            a.validate(&request, &target.capabilities).unwrap_err().code,
            "empty_messages"
        );

        let mut request = request_fixture();
        request.operation = Operation::Embeddings;
        request.inputs.clear();
        assert_eq!(
            a.validate(&request, &target.capabilities).unwrap_err().code,
            "empty_input"
        );
    }

    #[test]
    fn paths_match_the_operation() {
        let a = adapter();
        let mut request = request_fixture();

        request.operation = Operation::Chat;
        assert_eq!(a.path_for(&request).unwrap(), "/chat/completions");
        request.operation = Operation::Responses;
        assert_eq!(a.path_for(&request).unwrap(), "/responses");
        request.operation = Operation::Embeddings;
        assert_eq!(a.path_for(&request).unwrap(), "/embeddings");
        request.operation = Operation::Rerank;
        assert!(a.path_for(&request).is_err());
    }

    // -- The Responses dialect ----------------------------------------------

    fn responses_request() -> CanonicalRequest {
        let mut request = request_fixture();
        request.operation = Operation::Responses;
        // The caller's protocol is deliberately left as Chat: a client speaking
        // one dialect may be routed to a target served through the other, and
        // the encoder must not consult it.
        request
    }

    #[test]
    fn a_responses_request_is_not_a_chat_body_sent_to_another_path() {
        let body = encoded(&responses_request());

        // The fields that exist only in this dialect.
        assert_eq!(body.field_str("instructions").unwrap(), "You are terse.");
        assert_eq!(body.field_i64("max_output_tokens").unwrap(), 512);

        let input = body.field_array("input").unwrap();
        // The system message was hoisted, so only the user turn remains.
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].field_str("type").unwrap(), "message");
        assert_eq!(input[0].field_str("role").unwrap(), "user");
        let parts = input[0].field_array("content").unwrap();
        assert_eq!(parts[0].field_str("type").unwrap(), "input_text");
        assert_eq!(parts[0].field_str("text").unwrap(), "Explain backpressure.");

        // And the fields that must not survive the translation.
        for field in ["messages", "max_tokens", "response_format"] {
            assert!(
                body.get(field).is_none(),
                "{field} is the Chat Completions spelling and must not be sent to /responses"
            );
        }
    }

    #[test]
    fn responses_content_parts_carry_their_direction() {
        // `input_text` on the way in and `output_text` on the way out, where
        // Chat Completions spells both `text`. A replayed assistant turn sent
        // as `input_text` is rejected.
        let mut request = responses_request();
        request.messages.push(Message::text(Role::Assistant, "Flow control."));
        let body = encoded(&request);
        let input = body.field_array("input").unwrap();
        assert_eq!(input.len(), 2);
        assert_eq!(input[1].field_str("role").unwrap(), "assistant");
        assert_eq!(
            input[1].field_array("content").unwrap()[0]
                .field_str("type")
                .unwrap(),
            "output_text"
        );
    }

    #[test]
    fn responses_images_use_a_plain_image_url_string() {
        let mut request = responses_request();
        request.messages.push(Message {
            role: Role::User,
            content: vec![
                ContentPart::Text("what is this".to_owned()),
                ContentPart::Image(ImageSource::Inline {
                    media_type: "image/png".to_owned(),
                    base64_data: "AAAA".to_owned(),
                }),
            ],
            name: None,
            tool_calls: Vec::new(),
        });
        let body = encoded(&request);
        let parts = body.field_array("input").unwrap()[1]
            .field_array("content")
            .unwrap();
        assert_eq!(parts[1].field_str("type").unwrap(), "input_image");
        // A string, not the `{"url": …}` object Chat Completions nests it in.
        assert_eq!(
            parts[1].field_str("image_url").unwrap(),
            "data:image/png;base64,AAAA"
        );
    }

    #[test]
    fn responses_tool_calls_and_results_become_their_own_items() {
        // Both are top-level items here rather than fields on a message, and the
        // result is tied to the call by `call_id`. Losing the tie is how a
        // replayed tool conversation stops making sense to the model.
        let mut request = responses_request();
        request.messages.push(Message {
            role: Role::Assistant,
            content: Vec::new(),
            name: None,
            tool_calls: vec![hypellm_core::canonical::ToolCall {
                id: "call_1".to_owned(),
                name: "list_files".to_owned(),
                arguments: r#"{"path":"/srv"}"#.to_owned(),
            }],
        });
        request.messages.push(Message {
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                tool_call_id: "call_1".to_owned(),
                content: "a.txt".to_owned(),
                is_error: false,
            }],
            name: None,
            tool_calls: Vec::new(),
        });

        let body = encoded(&request);
        let input = body.field_array("input").unwrap();
        assert_eq!(input.len(), 3, "user turn, function_call, function_call_output");

        assert_eq!(input[1].field_str("type").unwrap(), "function_call");
        assert_eq!(input[1].field_str("call_id").unwrap(), "call_1");
        assert_eq!(input[1].field_str("name").unwrap(), "list_files");
        // The argument text the model produced, byte for byte.
        assert_eq!(input[1].field_str("arguments").unwrap(), r#"{"path":"/srv"}"#);

        assert_eq!(input[2].field_str("type").unwrap(), "function_call_output");
        assert_eq!(input[2].field_str("call_id").unwrap(), "call_1");
        assert_eq!(input[2].field_str("output").unwrap(), "a.txt");
    }

    #[test]
    fn responses_tools_are_flat_and_the_schema_is_unchanged() {
        let mut request = responses_request();
        request.tools.push(ToolDef {
            name: "lookup".to_owned(),
            description: Some("Look something up".to_owned()),
            parameters_json: r#"{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}"#.to_owned(),
            strict: true,
        });
        request.tool_choice = Some(ToolChoice::Function("lookup".to_owned()));
        let body = encoded(&request);

        let tools = body.field_array("tools").unwrap();
        assert_eq!(tools.len(), 1);
        // Flat: no `function` wrapper, which is the whole difference.
        assert!(tools[0].get("function").is_none());
        assert_eq!(tools[0].field_str("type").unwrap(), "function");
        assert_eq!(tools[0].field_str("name").unwrap(), "lookup");
        assert_eq!(tools[0].opt_field_bool("strict").unwrap(), Some(true));
        assert_eq!(
            tools[0]
                .get("parameters")
                .unwrap()
                .get("properties")
                .unwrap()
                .get("q")
                .unwrap()
                .field_str("type")
                .unwrap(),
            "string"
        );

        let choice = body.get("tool_choice").unwrap();
        assert_eq!(choice.field_str("type").unwrap(), "function");
        assert_eq!(choice.field_str("name").unwrap(), "lookup");
        assert!(choice.get("function").is_none());
    }

    #[test]
    fn a_malformed_tool_schema_is_rejected_on_the_responses_path_too() {
        let mut request = responses_request();
        request.tools.push(ToolDef {
            name: "bad".to_owned(),
            description: None,
            parameters_json: "{not json".to_owned(),
            strict: false,
        });
        let target = target_fixture();
        let endpoint = target_fixture_endpoint();
        let meta = meta_fixture(&target, &endpoint, false);
        let failure = adapter()
            .encode_request(&request, &meta)
            .expect_err("must reject");
        assert_eq!(failure.code, "invalid_tool_schema");
    }

    #[test]
    fn responses_response_format_lives_under_text_format() {
        let mut request = responses_request();
        request.response_format = Some(ResponseFormat::JsonSchema {
            name: "answer".to_owned(),
            schema_json: r#"{"type":"object"}"#.to_owned(),
            strict: true,
        });
        let body = encoded(&request);
        assert!(body.get("response_format").is_none());
        let format = body.get("text").unwrap().get("format").unwrap();
        assert_eq!(format.field_str("type").unwrap(), "json_schema");
        // Flat here; Chat Completions nests the same fields under `json_schema`.
        assert_eq!(format.field_str("name").unwrap(), "answer");
        assert_eq!(format.get("schema").unwrap().field_str("type").unwrap(), "object");
        assert_eq!(format.opt_field_bool("strict").unwrap(), Some(true));

        request.response_format = Some(ResponseFormat::JsonObject);
        let body = encoded(&request);
        assert_eq!(
            body.get("text")
                .unwrap()
                .get("format")
                .unwrap()
                .field_str("type")
                .unwrap(),
            "json_object"
        );

        // Free text is the provider's default, so nothing is asserted.
        request.response_format = Some(ResponseFormat::Text);
        assert!(encoded(&request).get("text").is_none());
    }

    #[test]
    fn responses_sends_only_the_sampling_fields_the_dialect_has() {
        let mut request = responses_request();
        request.sampling = Sampling {
            temperature: Some(0.0),
            top_p: Some(0.5),
            seed: Some(7),
            frequency_penalty: Some(1.0),
            presence_penalty: Some(1.0),
            stop: vec!["END".to_owned()],
            top_k: None,
        };
        let body = encoded(&request);

        // Zero is still sent: specification 5.1's unset-is-not-zero rule.
        assert_eq!(body.opt_field_f64("temperature").unwrap(), Some(0.0));
        assert_eq!(body.opt_field_f64("top_p").unwrap(), Some(0.5));
        // These have no counterpart in this dialect. Sending them is a 400, and
        // there is nothing to translate them into.
        for field in ["seed", "frequency_penalty", "presence_penalty", "stop"] {
            assert!(body.get(field).is_none(), "{field} has no Responses spelling");
        }
    }

    #[test]
    fn a_streaming_responses_request_asks_for_no_stream_options() {
        let mut request = responses_request();
        request.stream.enabled = true;
        request.stream.include_usage = true;
        let body = encoded(&request);
        assert_eq!(body.opt_field_bool("stream").unwrap(), Some(true));
        // Usage arrives in the terminal event unconditionally; the Chat
        // Completions opt-in field is rejected here.
        assert!(body.get("stream_options").is_none());
    }

    #[test]
    fn a_responses_body_decodes_to_events() {
        let body = br#"{
            "id": "resp_1",
            "object": "response",
            "created_at": 1750000000,
            "status": "completed",
            "model": "gpt-4.1",
            "output": [{"type":"message","id":"msg_1","status":"completed","role":"assistant",
                        "content":[{"type":"output_text","text":"Hello, world","annotations":[]}]}],
            "usage": {"input_tokens":12,"output_tokens":3,"total_tokens":15,
                      "input_tokens_details":{"cached_tokens":8},
                      "output_tokens_details":{"reasoning_tokens":1}}
        }"#;
        let events = adapter().decode_response(200, body).expect("decodes");

        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for event in &events {
            accumulator.push(event);
        }
        assert_eq!(accumulator.text, "Hello, world");
        assert_eq!(accumulator.upstream_id.as_deref(), Some("resp_1"));
        assert_eq!(accumulator.native_model.as_deref(), Some("gpt-4.1"));
        assert_eq!(accumulator.finish, Some(FinishReason::Stop));

        let usage = adapter().usage_from_events(&events);
        // `input_tokens`/`output_tokens`, not the Chat Completions spelling: a
        // decoder that looks for `prompt_tokens` here reports zero and meters
        // the request as free.
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 3);
        assert_eq!(usage.cached_input_tokens, 8);
        assert_eq!(usage.reasoning_tokens, 1);
        assert!(usage.is_reported());
    }

    #[test]
    fn a_responses_function_call_item_decodes_to_a_tool_call() {
        let body = br#"{"id":"resp_2","object":"response","status":"completed","model":"gpt-4.1",
            "output":[
                {"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"Listing."}]},
                {"type":"function_call","id":"fc_1","call_id":"call_1","name":"list_files","arguments":"{\"path\":\"/srv\"}"}
            ]}"#;
        let events = adapter().decode_response(200, body).expect("decodes");

        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for event in &events {
            accumulator.push(event);
        }
        let calls = accumulator.sorted_tool_calls();
        assert_eq!(calls.len(), 1);
        // The item's position in `output`, so a mixed output cannot collide.
        assert_eq!(calls[0].index, 1);
        // `call_id`, not `id`: that is what a later `function_call_output` quotes.
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "list_files");
        assert_eq!(calls[0].arguments, r#"{"path":"/srv"}"#);
        // `status` is `completed` even though the model is waiting for a tool
        // result. Reporting a plain stop would tell the caller the turn is over.
        assert_eq!(accumulator.finish, Some(FinishReason::ToolCalls));
    }

    #[test]
    fn a_truncated_responses_body_is_reported_as_truncated() {
        let body = br#"{"id":"resp_3","object":"response","status":"incomplete","model":"gpt-4.1",
            "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Back"}]}],
            "incomplete_details":{"reason":"max_output_tokens"}}"#;
        let events = adapter().decode_response(200, body).expect("decodes");
        assert!(events.iter().any(|e| matches!(
            e,
            CanonicalEvent::Finish {
                reason: FinishReason::Length
            }
        )));
    }

    #[test]
    fn an_unrecognised_responses_status_or_reason_is_never_a_natural_stop() {
        // The distinction [`FinishReason::Unrecognized`] exists for: providers
        // add statuses over time, and folding one into `Stop` tells the caller
        // the model finished when the router has no idea whether it did.
        for body in [
            br#"{"object":"response","status":"incomplete","incomplete_details":{"reason":"policy_review"},"output":[]}"#.as_slice(),
            br#"{"object":"response","status":"queued","output":[]}"#.as_slice(),
            br#"{"object":"response","output":[]}"#.as_slice(),
        ] {
            let events = adapter().decode_response(200, body).expect("decodes");
            let finish = events.iter().find_map(|e| match e {
                CanonicalEvent::Finish { reason } => Some(*reason),
                _ => None,
            });
            assert_eq!(finish, Some(FinishReason::Unrecognized), "body: {body:?}");
        }
    }

    #[test]
    fn a_failed_responses_body_is_an_upstream_failure_not_an_empty_completion() {
        // The transport status is 200, but nothing usable was generated. Decoding
        // it as a completion would report success for a response that failed —
        // and nothing has reached the client, so failover is still available.
        let body = br#"{"id":"resp_4","object":"response","status":"failed","model":"gpt-4.1","output":[],
            "error":{"code":"server_error","message":"the model failed while generating"}}"#;
        let error = adapter()
            .decode_response(200, body)
            .expect_err("a failed response must not decode as a success");
        assert_eq!(error.class, UpstreamErrorClass::ServerError);
        assert!(error.is_retriable());
        assert!(!error.safe_detail.as_str().contains("failed while generating"));
    }

    #[test]
    fn the_two_dialects_are_told_apart_by_the_body_not_by_a_flag() {
        let a = adapter();
        // A Chat Completion still decodes, whatever the router asked for.
        let chat = a
            .decode_response(
                200,
                br#"{"id":"c1","object":"chat.completion","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}"#,
            )
            .expect("decodes");
        assert!(chat.iter().any(|e| matches!(e, CanonicalEvent::TextDelta(t) if t == "hi")));

        // And a compatible server that omits `object` is still recognised from
        // the presence of `output` and the absence of `choices`.
        let responses = a
            .decode_response(
                200,
                br#"{"id":"r1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]}]}"#,
            )
            .expect("decodes");
        assert!(responses.iter().any(|e| matches!(e, CanonicalEvent::TextDelta(t) if t == "hi")));
    }

    /// The documented event sequence for one streamed text message.
    const RESPONSES_STREAM: &[(&str, &str)] = &[
        (
            "response.created",
            r#"{"type":"response.created","response":{"id":"resp_5","object":"response","status":"in_progress","model":"gpt-4.1","output":[]}}"#,
        ),
        (
            "response.output_item.added",
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[]}}"#,
        ),
        (
            "response.content_part.added",
            r#"{"type":"response.content_part.added","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"hel"}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"lo"}"#,
        ),
        (
            "response.output_text.done",
            r#"{"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"hello"}"#,
        ),
        (
            "response.content_part.done",
            r#"{"type":"response.content_part.done","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"hello","annotations":[]}}"#,
        ),
        (
            "response.output_item.done",
            r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}}"#,
        ),
        (
            "response.completed",
            r#"{"type":"response.completed","response":{"id":"resp_5","object":"response","status":"completed","model":"gpt-4.1","output":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}"#,
        ),
    ];

    #[test]
    fn a_responses_stream_decodes_without_duplicating_its_own_output() {
        let a = adapter();
        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for (name, data) in RESPONSES_STREAM {
            for event in a.decode_stream_event(Some(name), data).expect("decodes") {
                accumulator.push(&event);
            }
        }
        // "hello", once. Every `.done` event and the terminal `response.completed`
        // repeat the whole text; emitting from them would deliver it three times.
        assert_eq!(accumulator.text, "hello");
        assert_eq!(accumulator.upstream_id.as_deref(), Some("resp_5"));
        assert_eq!(accumulator.native_model.as_deref(), Some("gpt-4.1"));
        assert_eq!(accumulator.finish, Some(FinishReason::Stop));
        let usage = accumulator.usage.expect("usage");
        assert_eq!((usage.input_tokens, usage.output_tokens), (10, 5));
        assert!(usage.is_reported());
    }

    #[test]
    fn a_responses_stream_terminates_without_a_done_sentinel() {
        // There is no `[DONE]` in this dialect. A reader that waits for one
        // hangs until the deadline fires; termination is the terminal event.
        let a = adapter();
        for (_, data) in RESPONSES_STREAM {
            assert!(!a.is_stream_terminator(data));
        }
        let terminal = RESPONSES_STREAM.last().expect("non-empty");
        let events = a
            .decode_stream_event(Some(terminal.0), terminal.1)
            .expect("decodes");
        assert!(events.iter().any(CanonicalEvent::is_terminal));
    }

    #[test]
    fn a_responses_stream_event_is_recognised_from_its_payload_when_unnamed() {
        // Some intermediaries drop the SSE `event:` line. The payload's own
        // `type` repeats it, and that is the fallback.
        let a = adapter();
        let (_, data) = RESPONSES_STREAM.get(3).expect("a text delta");
        let events = a.decode_stream_event(None, data).expect("decodes");
        assert_eq!(events, vec![CanonicalEvent::TextDelta("hel".to_owned())]);
    }

    #[test]
    fn responses_stream_tool_calls_bind_identity_to_their_arguments() {
        // Identity arrives in `output_item.added`, arguments in later fragments
        // tied to the same `output_index`; the `.done` event repeats the whole
        // argument string and must not be appended to it.
        let a = adapter();
        let frames = [
            ("response.output_item.added", r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"list_files","arguments":""}}"#),
            ("response.function_call_arguments.delta", r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":"{\"path\":"}"#),
            ("response.function_call_arguments.delta", r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":"\"/srv\"}"}"#),
            ("response.function_call_arguments.done", r#"{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":"{\"path\":\"/srv\"}"}"#),
            ("response.completed", r#"{"type":"response.completed","response":{"id":"resp_6","object":"response","status":"completed","model":"gpt-4.1","output":[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"list_files","arguments":"{\"path\":\"/srv\"}"}],"usage":{"input_tokens":9,"output_tokens":6}}}"#),
        ];
        let mut accumulator = hypellm_core::event::ResponseAccumulator::new();
        for (name, data) in frames {
            for event in a.decode_stream_event(Some(name), data).expect("decodes") {
                accumulator.push(&event);
            }
        }
        let calls = accumulator.sorted_tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "list_files");
        assert_eq!(calls[0].arguments, r#"{"path":"/srv"}"#);
        assert_eq!(accumulator.finish, Some(FinishReason::ToolCalls));
    }

    #[test]
    fn a_streamed_responses_failure_is_terminal_rather_than_silent() {
        let a = adapter();

        // A dedicated `error` event, flat rather than nested.
        let error = a
            .decode_stream_event(
                Some("error"),
                r#"{"type":"error","code":"rate_limit_exceeded","message":"slow down","param":null}"#,
            )
            .expect_err("must fail");
        assert_eq!(error.class, UpstreamErrorClass::RateLimited);
        assert!(!error.safe_detail.as_str().contains("slow down"));

        // `response.failed` ends the stream in place: content may already have
        // reached the client, and specification 6.5 forbids splicing another
        // model's output after it.
        let events = a
            .decode_stream_event(
                Some("response.failed"),
                r#"{"type":"response.failed","response":{"id":"resp_7","object":"response","status":"failed","output":[],"error":{"code":"server_error","message":"x"}}}"#,
            )
            .expect("decodes");
        assert!(events.contains(&CanonicalEvent::Finish {
            reason: FinishReason::Error
        }));
    }

    #[test]
    fn a_streamed_incomplete_response_reports_the_truncation() {
        let events = adapter()
            .decode_stream_event(
                Some("response.incomplete"),
                r#"{"type":"response.incomplete","response":{"id":"resp_8","object":"response","status":"incomplete","output":[],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":4,"output_tokens":16}}}"#,
            )
            .expect("decodes");
        assert!(events.contains(&CanonicalEvent::Finish {
            reason: FinishReason::Length
        }));
        assert!(events.iter().any(|e| matches!(
            e,
            CanonicalEvent::Usage(u) if u.output_tokens == 16
        )));
    }

    #[test]
    fn an_unknown_responses_event_is_ignored_rather_than_fatal() {
        // Providers add events over time. Failing on one would end a healthy
        // stream that the router could have served.
        let events = adapter()
            .decode_stream_event(
                Some("response.web_search_call.in_progress"),
                r#"{"type":"response.web_search_call.in_progress","output_index":0,"item_id":"ws_1"}"#,
            )
            .expect("decodes");
        assert!(events.is_empty());
    }

    #[test]
    fn chat_completions_streaming_is_untouched_by_the_responses_branch() {
        // The dispatch is on the payload's shape, and a Chat chunk has neither
        // an event name nor a `type`, so it must still take the old path.
        let a = adapter();
        let events = a
            .decode_stream_event(None, r#"{"id":"1","choices":[{"delta":{"content":"Hel"}}]}"#)
            .expect("decodes");
        assert_eq!(events, vec![CanonicalEvent::TextDelta("Hel".to_owned())]);
        assert!(a.is_stream_terminator("[DONE]"));
    }
}
