//! The Anthropic adapter.
//!
//! Specification 7: "`/v1/messages`, system/message conversion, content block
//! streaming, tool use/result mapping, **prompt caching headers only when
//! explicitly allowed**."
//!
//! # Three shape differences from the OpenAI protocol
//!
//! 1. **The system prompt is a top-level field**, not a message with a role.
//!    Canonical system messages are collected and hoisted.
//! 2. **`max_tokens` is required.** A request that omits it is rejected by the
//!    provider, so the adapter supplies the target's declared limit rather than
//!    letting the call fail at the upstream.
//! 3. **Streaming is content-block oriented.** Events are named
//!    (`content_block_delta`, `message_delta`, …) and a tool call's arguments
//!    arrive as `input_json_delta` fragments tied to a block index.
//!
//! # Prompt caching
//!
//! `cache_control` markers are added only when the target declares
//! `prompt_caching`. Caching changes where prompt data rests and for how long,
//! which is a data-protection decision (specification 10), not an optimisation
//! the router may make on an administrator's behalf.

use crate::contract::{
    Adapter, CredentialHandle, ErrorClassification, RequestMeta, SensitiveHeaders,
    ValidationFailure, ValidationResult, class_for_status, sanitize_provider_code,
};
use hypellm_core::canonical::{
    CanonicalRequest, ContentPart, ImageSource, Operation, ResponseFormat, Role, ToolChoice,
};
use hypellm_core::event::{
    CanonicalEvent, CanonicalUsage, FinishReason, ToolCallDelta, UpstreamErrorClass, UsageSource,
};
use hypellm_core::sensitive::Capped;
use hypellm_core::target::{Capabilities, ProviderFamily};
use wire_json::{Limits, Object, Value, parse, parse_str, to_vec};

/// The API version header Anthropic requires.
pub const API_VERSION: &str = "2023-06-01";

/// The Anthropic adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnthropicAdapter;

impl Adapter for AnthropicAdapter {
    fn family(&self) -> ProviderFamily {
        ProviderFamily::Anthropic
    }

    fn path_for(&self, request: &CanonicalRequest) -> Result<&'static str, ValidationFailure> {
        match request.operation {
            Operation::Chat | Operation::Responses => Ok("/messages"),
            Operation::Tokenize => Ok("/messages/count_tokens"),
            Operation::Embeddings | Operation::Rerank => Err(ValidationFailure::new(
                "operation_unsupported",
                "this provider does not serve this operation",
            )),
        }
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
        if !capabilities.supports_modalities(&request.required_modalities()) {
            return Err(ValidationFailure::new(
                "modality_unsupported",
                "the selected model does not accept one of the supplied content types",
            )
            .with_param("messages"));
        }
        // This protocol has no JSON-mode switch; structured output is expressed
        // through a tool. Accepting the request and silently dropping the
        // constraint would give the caller unconstrained text they will try to
        // parse as JSON.
        if matches!(
            request.response_format,
            Some(ResponseFormat::JsonObject | ResponseFormat::JsonSchema { .. })
        ) {
            return Err(ValidationFailure::new(
                "response_format_unsupported",
                "this provider expresses structured output through tools rather than a response format",
            )
            .with_param("response_format"));
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
        if capabilities.max_output_tokens == 0 {
            return Err(ValidationFailure::new(
                "max_tokens_undeclared",
                "this provider requires an output limit and the target declares none",
            ));
        }
        if request.messages.is_empty() {
            return Err(ValidationFailure::new(
                "empty_messages",
                "a request must supply at least one message",
            )
            .with_param("messages"));
        }
        if let Err(param) = request.sampling.validate() {
            return Err(
                ValidationFailure::new("sampling_out_of_range", "a sampling parameter is out of range")
                    .with_param(match param {
                        "temperature" => "temperature",
                        "top_p" => "top_p",
                        _ => "stop",
                    }),
            );
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
        headers.push("anthropic-version", API_VERSION);
        headers.push("x-request-id", meta.request_id.clone());

        if let Some(credential) = credential {
            if let Some(secret) = credential.expose_str() {
                headers.push_secret("x-api-key", secret.to_owned());
            }
        }
        if let Some(key) = &meta.idempotency_key {
            headers.push("idempotency-key", key.clone());
        }
        headers
    }

    fn encode_request(
        &self,
        request: &CanonicalRequest,
        meta: &RequestMeta<'_>,
    ) -> Result<Vec<u8>, ValidationFailure> {
        let capabilities = &meta.target.capabilities;
        let mut body = Object::new();
        body.push("model", Value::from(meta.target.native_model.as_str()));

        // `max_tokens` is mandatory here. Falling back to the target's declared
        // limit is better than sending nothing and having the provider reject
        // a request the router has already admitted and metered.
        let max_tokens = request
            .limits
            .max_output_tokens
            .unwrap_or(capabilities.max_output_tokens);
        body.push("max_tokens", Value::from(max_tokens));

        // The system prompt is hoisted out of the message list.
        let system: Vec<&str> = request
            .messages
            .iter()
            .filter(|m| m.role == Role::System)
            .filter_map(|m| m.content.iter().find_map(|p| match p {
                ContentPart::Text(t) => Some(t.as_str()),
                _ => None,
            }))
            .collect();
        if !system.is_empty() {
            let joined = system.join("\n\n");
            if capabilities.prompt_caching {
                // Only when declared. See the module documentation.
                let mut block = Object::new();
                block.push("type", Value::from("text"));
                block.push("text", Value::from(joined.as_str()));
                let mut cache = Object::new();
                cache.push("type", Value::from("ephemeral"));
                block.push("cache_control", Value::Object(cache));
                body.push("system", Value::Array(vec![Value::Object(block)]));
            } else {
                body.push("system", Value::from(joined.as_str()));
            }
        }

        body.push("messages", encode_messages(request)?);

        if request.stream.enabled {
            body.push("stream", Value::from(true));
        }
        if !request.tools.is_empty() {
            body.push("tools", encode_tools(request)?);
        }
        if let Some(choice) = &request.tool_choice {
            body.push_opt("tool_choice", encode_tool_choice(choice));
        }

        let sampling = &request.sampling;
        body.push_opt("temperature", sampling.temperature.map(Value::from));
        body.push_opt("top_p", sampling.top_p.map(Value::from));
        body.push_opt("top_k", sampling.top_k.map(Value::from));
        if !sampling.stop.is_empty() {
            body.push(
                "stop_sequences",
                Value::Array(sampling.stop.iter().map(|s| Value::from(s.as_str())).collect()),
            );
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

        let mut events = vec![CanonicalEvent::Start {
            upstream_id: value.get("id").and_then(|v| v.as_str()).map(str::to_owned),
            native_model: value.get("model").and_then(|v| v.as_str()).map(str::to_owned),
        }];

        if let Some(blocks) = value.get("content").and_then(|v| v.as_array()) {
            for (index, block) in blocks.iter().enumerate() {
                let index = u32::try_from(index).unwrap_or(0);
                match block.get("type").and_then(|v| v.as_str()) {
                    Some("text") => {
                        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                            events.push(CanonicalEvent::TextDelta(text.to_owned()));
                        }
                    }
                    Some("thinking") => {
                        if let Some(text) = block.get("thinking").and_then(|v| v.as_str()) {
                            events.push(CanonicalEvent::ReasoningDelta(text.to_owned()));
                        }
                    }
                    Some("tool_use") => {
                        let arguments = block
                            .get("input")
                            .map(wire_json::to_string)
                            .unwrap_or_else(|| "{}".to_owned());
                        events.push(CanonicalEvent::ToolCallDelta(ToolCallDelta {
                            index,
                            id: block.get("id").and_then(|v| v.as_str()).map(str::to_owned),
                            name: block.get("name").and_then(|v| v.as_str()).map(str::to_owned),
                            arguments_delta: arguments,
                        }));
                    }
                    _ => {}
                }
            }
        }

        if let Some(usage) = decode_usage(value.get("usage")) {
            events.push(CanonicalEvent::Usage(usage));
        }
        // A missing `stop_reason`, or one this router does not know, is not a
        // natural stop — it is a reason the router cannot vouch for. Anthropic
        // has added stop reasons since this mapping was written, and reporting
        // an unknown one as `end_turn` would tell the caller the model finished
        // when it may have refused or paused.
        let reason = value
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map_or(FinishReason::Unrecognized, |raw| {
                FinishReason::parse_anthropic(raw).unwrap_or(FinishReason::Unrecognized)
            });
        events.push(CanonicalEvent::Finish { reason });
        Ok(events)
    }

    fn decode_stream_event(
        &self,
        event_name: Option<&str>,
        data: &str,
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        let value = parse_str(data, &Limits::STREAM_EVENT).map_err(|_| ErrorClassification {
            class: UpstreamErrorClass::ProtocolViolation,
            provider_code: None,
            safe_detail: Capped::new("the provider sent a malformed stream event", 200),
            retry_after_secs: None,
        })?;

        // The event name is authoritative when present; the payload's own
        // `type` is the fallback, since some intermediaries drop the name.
        let kind = event_name
            .or_else(|| value.get("type").and_then(|v| v.as_str()))
            .unwrap_or("");

        let mut events = Vec::new();
        match kind {
            "message_start" => {
                let message = value.get("message");
                events.push(CanonicalEvent::Start {
                    upstream_id: message
                        .and_then(|m| m.get("id"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    native_model: message
                        .and_then(|m| m.get("model"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                });
                if let Some(usage) = decode_usage(message.and_then(|m| m.get("usage"))) {
                    events.push(CanonicalEvent::Usage(usage));
                }
            }
            "content_block_start" => {
                let index = block_index(&value);
                if let Some(block) = value.get("content_block") {
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        events.push(CanonicalEvent::ToolCallDelta(ToolCallDelta {
                            index,
                            id: block.get("id").and_then(|v| v.as_str()).map(str::to_owned),
                            name: block.get("name").and_then(|v| v.as_str()).map(str::to_owned),
                            arguments_delta: String::new(),
                        }));
                    }
                }
            }
            "content_block_delta" => {
                let index = block_index(&value);
                if let Some(delta) = value.get("delta") {
                    match delta.get("type").and_then(|v| v.as_str()) {
                        Some("text_delta") => {
                            if let Some(text) = delta.get("text").and_then(|v| v.as_str()) {
                                events.push(CanonicalEvent::TextDelta(text.to_owned()));
                            }
                        }
                        Some("thinking_delta") => {
                            if let Some(text) = delta.get("thinking").and_then(|v| v.as_str()) {
                                events.push(CanonicalEvent::ReasoningDelta(text.to_owned()));
                            }
                        }
                        Some("input_json_delta") => {
                            if let Some(fragment) =
                                delta.get("partial_json").and_then(|v| v.as_str())
                            {
                                events.push(CanonicalEvent::ToolCallDelta(ToolCallDelta {
                                    index,
                                    id: None,
                                    name: None,
                                    arguments_delta: fragment.to_owned(),
                                }));
                            }
                        }
                        _ => {}
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = decode_usage(value.get("usage")) {
                    events.push(CanonicalEvent::Usage(usage));
                }
                if let Some(reason) = value
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(|v| v.as_str())
                {
                    events.push(CanonicalEvent::Finish {
                        reason: FinishReason::parse_anthropic(reason).unwrap_or(FinishReason::Unrecognized),
                    });
                }
            }
            "error" => {
                let error = value.get("error").unwrap_or(&value);
                return Err(classify_error_object(error, 500));
            }
            // `ping`, `content_block_stop`, and `message_stop` carry no
            // canonical meaning; ignoring them is correct, not a gap.
            _ => {}
        }
        Ok(events)
    }

    fn is_stream_terminator(&self, _data: &str) -> bool {
        // This protocol has no sentinel payload: the stream ends with a
        // `message_stop` event and the connection closing.
        false
    }

    fn classify_error(&self, status: u16, body: &[u8]) -> ErrorClassification {
        if let Ok(value) = parse(body, &Limits::SMALL) {
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

    fn usage_from_events(&self, events: &[CanonicalEvent]) -> CanonicalUsage {
        // Usage arrives in two parts: input tokens in `message_start`, output
        // tokens in `message_delta`. Taking only the last event would report
        // zero input, so the two are merged.
        let mut merged: Option<CanonicalUsage> = None;
        for event in events {
            if let CanonicalEvent::Usage(usage) = event {
                merged = Some(match merged {
                    None => *usage,
                    Some(previous) => CanonicalUsage {
                        input_tokens: usage.input_tokens.max(previous.input_tokens),
                        output_tokens: usage.output_tokens.max(previous.output_tokens),
                        cached_input_tokens: usage
                            .cached_input_tokens
                            .max(previous.cached_input_tokens),
                        reasoning_tokens: usage.reasoning_tokens.max(previous.reasoning_tokens),
                        source: UsageSource::ProviderReported,
                    },
                });
            }
        }
        merged.unwrap_or_else(|| CanonicalUsage::estimated(0, 0))
    }
}

fn block_index(value: &Value) -> u32 {
    value
        .get("index")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

fn decode_usage(usage: Option<&Value>) -> Option<CanonicalUsage> {
    let usage = usage?;
    let input = usage.get("input_tokens").and_then(|v| v.as_u64());
    let output = usage.get("output_tokens").and_then(|v| v.as_u64());
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(CanonicalUsage {
        input_tokens: input.unwrap_or(0),
        output_tokens: output.unwrap_or(0),
        cached_input_tokens: usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        reasoning_tokens: 0,
        source: UsageSource::ProviderReported,
    })
}

fn classify_error_object(error: &Value, status: u16) -> ErrorClassification {
    let error_type = error.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let class = match error_type {
        "rate_limit_error" | "overloaded_error" => UpstreamErrorClass::RateLimited,
        "authentication_error" | "permission_error" => UpstreamErrorClass::Authentication,
        "not_found_error" => UpstreamErrorClass::InvalidRequest,
        "api_error" => UpstreamErrorClass::ServerError,
        "invalid_request_error" => {
            // The distinguishing detail is in the message, which the router
            // does not forward. Matching on the substring is enough to route
            // the failure correctly without echoing it.
            let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("");
            if message.contains("max_tokens") || message.contains("context") {
                UpstreamErrorClass::ContextOverflow
            } else {
                UpstreamErrorClass::InvalidRequest
            }
        }
        _ => class_for_status(status),
    };

    ErrorClassification {
        class,
        provider_code: Some(sanitize_provider_code(error_type)),
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
        529 => "the provider is overloaded",
        500..=599 => "the provider returned a server error",
        _ => "the provider returned an unexpected response",
    }
}

fn encode_messages(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut messages = Vec::new();

    for message in &request.messages {
        // System messages were hoisted into the top-level field.
        if message.role == Role::System {
            continue;
        }

        let mut object = Object::new();
        object.push(
            "role",
            Value::from(match message.role {
                // A tool result is delivered as a user turn carrying a
                // `tool_result` block, which is this protocol's shape.
                Role::Assistant => "assistant",
                _ => "user",
            }),
        );

        let mut blocks = Vec::with_capacity(message.content.len() + message.tool_calls.len());
        for part in &message.content {
            blocks.push(encode_content_part(part)?);
        }
        for call in &message.tool_calls {
            let input = parse_str(&call.arguments, &Limits::SMALL).unwrap_or_else(|_| {
                // A model's own tool arguments should be valid JSON; if they
                // are not, forwarding an empty object is better than failing a
                // conversation replay on a historical turn.
                Value::Object(Object::new())
            });
            let mut block = Object::new();
            block.push("type", Value::from("tool_use"));
            block.push("id", Value::from(call.id.as_str()));
            block.push("name", Value::from(call.name.as_str()));
            block.push("input", input);
            blocks.push(Value::Object(block));
        }

        if blocks.is_empty() {
            continue;
        }
        object.push("content", Value::Array(blocks));
        messages.push(Value::Object(object));
    }

    if messages.is_empty() {
        return Err(ValidationFailure::new(
            "empty_messages",
            "the request contains no non-system messages",
        )
        .with_param("messages"));
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
        ContentPart::Image(ImageSource::Inline {
            media_type,
            base64_data,
        }) => {
            object.push("type", Value::from("image"));
            let mut source = Object::new();
            source.push("type", Value::from("base64"));
            source.push("media_type", Value::from(media_type.as_str()));
            source.push("data", Value::from(base64_data.as_str()));
            object.push("source", Value::Object(source));
        }
        ContentPart::Image(ImageSource::Url(url)) => {
            object.push("type", Value::from("image"));
            let mut source = Object::new();
            source.push("type", Value::from("url"));
            source.push("url", Value::from(url.as_str()));
            object.push("source", Value::Object(source));
        }
        ContentPart::Audio { .. } => {
            return Err(ValidationFailure::new(
                "modality_unsupported",
                "this provider does not accept audio content",
            )
            .with_param("messages"));
        }
        ContentPart::ToolResult {
            tool_call_id,
            content,
            is_error,
        } => {
            object.push("type", Value::from("tool_result"));
            object.push("tool_use_id", Value::from(tool_call_id.as_str()));
            object.push("content", Value::from(content.as_str()));
            if *is_error {
                object.push("is_error", Value::from(true));
            }
        }
    }
    Ok(Value::Object(object))
}

fn encode_tools(request: &CanonicalRequest) -> Result<Value, ValidationFailure> {
    let mut tools = Vec::with_capacity(request.tools.len());
    for tool in &request.tools {
        let schema = parse_str(&tool.parameters_json, &Limits::SMALL).map_err(|_| {
            ValidationFailure::new(
                "invalid_tool_schema",
                "a tool's parameter schema is not valid JSON",
            )
            .with_param("tools")
        })?;
        let mut object = Object::new();
        object.push("name", Value::from(tool.name.as_str()));
        object.push_opt("description", tool.description.as_deref().map(Value::from));
        object.push("input_schema", schema);
        tools.push(Value::Object(object));
    }
    Ok(Value::Array(tools))
}

fn encode_tool_choice(choice: &ToolChoice) -> Option<Value> {
    let mut object = Object::new();
    match choice {
        ToolChoice::Auto => object.push("type", Value::from("auto")),
        ToolChoice::Required => object.push("type", Value::from("any")),
        ToolChoice::Function(name) => {
            object.push("type", Value::from("tool"));
            object.push("name", Value::from(name.as_str()));
        }
        // There is no "none" in this protocol; omitting the field with no tools
        // present is the equivalent, and the caller has already been validated.
        ToolChoice::None => return None,
    }
    Some(Value::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{anthropic_target_fixture, endpoint_fixture, meta_fixture, request_fixture};
    use hypellm_core::canonical::{Message, Sampling, ToolDef};
    use hypellm_core::event::ResponseAccumulator;
    use hypellm_core::ids::CredentialRef;

    fn encoded(request: &CanonicalRequest) -> Value {
        let target = anthropic_target_fixture();
        let endpoint = endpoint_fixture("api.anthropic.com");
        let meta = meta_fixture(&target, &endpoint, request.stream.enabled);
        let bytes = AnthropicAdapter
            .encode_request(request, &meta)
            .expect("encodes");
        parse(&bytes, &Limits::DEFAULT).expect("valid JSON")
    }

    /// The system text, whichever shape the encoder used.
    ///
    /// With prompt caching declared the field is an array of blocks; without
    /// it, a plain string. Both are valid and the tests care about the text.
    fn system_text(body: &Value) -> String {
        match body.get("system") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|v| v.as_str()))
                .collect::<Vec<_>>()
                .join("\n\n"),
            other => panic!("unexpected system field: {other:?}"),
        }
    }

    #[test]
    fn the_system_prompt_is_hoisted_out_of_the_messages() {
        let request = request_fixture();
        let body = encoded(&request);

        assert_eq!(system_text(&body), "You are terse.");
        let messages = body.field_array("messages").unwrap();
        assert_eq!(messages.len(), 1, "the system message must not be repeated");
        assert_eq!(messages[0].field_str("role").unwrap(), "user");
    }

    #[test]
    fn several_system_messages_are_joined() {
        let mut request = request_fixture();
        request
            .messages
            .insert(1, Message::text(Role::System, "Answer in British English."));
        let body = encoded(&request);
        let system = system_text(&body);
        assert!(system.contains("You are terse."));
        assert!(system.contains("British English"));
    }

    #[test]
    fn max_tokens_is_always_sent() {
        // The provider requires it; omitting it would fail a request the router
        // has already admitted and metered.
        let mut request = request_fixture();
        request.limits.max_output_tokens = None;
        let body = encoded(&request);
        assert_eq!(
            body.field_i64("max_tokens").unwrap(),
            i64::from(anthropic_target_fixture().capabilities.max_output_tokens),
            "an absent limit falls back to the target's declared maximum"
        );

        let mut request = request_fixture();
        request.limits.max_output_tokens = Some(256);
        assert_eq!(encoded(&request).field_i64("max_tokens").unwrap(), 256);
    }

    #[test]
    fn prompt_caching_markers_appear_only_when_declared() {
        // Specification 7: caching headers "only when explicitly allowed".
        let request = request_fixture();

        let mut target = anthropic_target_fixture();
        target.capabilities.prompt_caching = false;
        let endpoint = endpoint_fixture("api.anthropic.com");
        let meta = meta_fixture(&target, &endpoint, false);
        let bytes = AnthropicAdapter.encode_request(&request, &meta).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("cache_control"),
            "caching must not be requested for a target that does not declare it"
        );

        // Declared: the marker appears.
        let body = encoded(&request);
        let system = body.get("system").unwrap().as_array().expect("array form");
        assert!(system[0].get("cache_control").is_some());
    }

    #[test]
    fn headers_use_the_api_key_scheme_and_version() {
        let reference = CredentialRef::new("cred_anthropic").unwrap();
        let credential = CredentialHandle::new(&reference, b"sk-ant-secret");
        let target = anthropic_target_fixture();
        let endpoint = endpoint_fixture("api.anthropic.com");
        let meta = meta_fixture(&target, &endpoint, true);

        let headers = AnthropicAdapter.encode_headers(Some(&credential), &meta);
        let pairs: Vec<(&str, &str)> = headers.iter().collect();
        assert!(pairs.contains(&("x-api-key", "sk-ant-secret")));
        assert!(pairs.contains(&("anthropic-version", API_VERSION)));
        assert!(pairs.iter().all(|(n, _)| *n != "authorization"));
        assert!(!format!("{headers:?}").contains("sk-ant-secret"));
    }

    #[test]
    fn tool_results_become_tool_result_blocks() {
        let mut request = request_fixture();
        request.messages.push(Message {
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                tool_call_id: "toolu_1".to_owned(),
                content: r#"{"answer":42}"#.to_owned(),
                is_error: false,
            }],
            name: None,
            tool_calls: Vec::new(),
        });
        let body = encoded(&request);
        let messages = body.field_array("messages").unwrap();
        let last = messages.last().unwrap();
        assert_eq!(last.field_str("role").unwrap(), "user");
        let block = &last.get("content").unwrap().as_array().unwrap()[0];
        assert_eq!(block.field_str("type").unwrap(), "tool_result");
        assert_eq!(block.field_str("tool_use_id").unwrap(), "toolu_1");
    }

    #[test]
    fn assistant_tool_calls_become_tool_use_blocks() {
        let mut request = request_fixture();
        request.messages.push(Message {
            role: Role::Assistant,
            content: Vec::new(),
            name: None,
            tool_calls: vec![hypellm_core::canonical::ToolCall {
                id: "toolu_1".to_owned(),
                name: "lookup".to_owned(),
                arguments: r#"{"q":"x"}"#.to_owned(),
            }],
        });
        let body = encoded(&request);
        let messages = body.field_array("messages").unwrap();
        let last = messages.last().unwrap();
        assert_eq!(last.field_str("role").unwrap(), "assistant");
        let block = &last.get("content").unwrap().as_array().unwrap()[0];
        assert_eq!(block.field_str("type").unwrap(), "tool_use");
        assert_eq!(block.field_str("name").unwrap(), "lookup");
        // The arguments become a JSON object, not a string.
        assert_eq!(block.get("input").unwrap().field_str("q").unwrap(), "x");
    }

    #[test]
    fn tools_use_the_input_schema_field() {
        let mut request = request_fixture();
        request.tools.push(ToolDef {
            name: "lookup".to_owned(),
            description: Some("Look up".to_owned()),
            parameters_json: r#"{"type":"object","properties":{"q":{"type":"string"}}}"#.to_owned(),
            strict: false,
        });
        let body = encoded(&request);
        let tools = body.field_array("tools").unwrap();
        assert_eq!(tools[0].field_str("name").unwrap(), "lookup");
        assert_eq!(
            tools[0].get("input_schema").unwrap().field_str("type").unwrap(),
            "object"
        );
    }

    #[test]
    fn a_complete_response_decodes() {
        let body = br#"{
            "id": "msg_1",
            "model": "claude-sonnet-5",
            "content": [{"type":"text","text":"Hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 4}
        }"#;
        let events = AnthropicAdapter.decode_response(200, body).expect("decodes");

        let mut accumulator = ResponseAccumulator::new();
        for event in &events {
            accumulator.push(event);
        }
        assert_eq!(accumulator.text, "Hello");
        assert_eq!(accumulator.finish, Some(FinishReason::Stop));
        assert_eq!(accumulator.upstream_id.as_deref(), Some("msg_1"));

        let usage = AnthropicAdapter.usage_from_events(&events);
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 4);
        assert!(usage.is_reported());
    }

    #[test]
    fn the_streaming_sequence_decodes() {
        let a = AnthropicAdapter;
        let frames: Vec<(&str, &str)> = vec![
            (
                "message_start",
                r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-5","usage":{"input_tokens":10,"output_tokens":0}}}"#,
            ),
            (
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            (
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}"#,
            ),
            (
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}"#,
            ),
            ("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
            (
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}"#,
            ),
            ("message_stop", r#"{"type":"message_stop"}"#),
        ];

        let mut all = Vec::new();
        for (name, data) in frames {
            all.extend(a.decode_stream_event(Some(name), data).expect("decodes"));
        }

        let mut accumulator = ResponseAccumulator::new();
        for event in &all {
            accumulator.push(event);
        }
        assert_eq!(accumulator.text, "Hello");
        assert_eq!(accumulator.finish, Some(FinishReason::Stop));

        // Usage from both halves is merged, not overwritten.
        let usage = a.usage_from_events(&all);
        assert_eq!(usage.input_tokens, 10, "input tokens come from message_start");
        assert_eq!(usage.output_tokens, 4, "output tokens come from message_delta");
    }

    #[test]
    fn streaming_tool_calls_assemble_from_json_fragments() {
        let a = AnthropicAdapter;
        let frames: Vec<(&str, &str)> = vec![
            (
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"lookup"}}"#,
            ),
            (
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"q\":"}}"#,
            ),
            (
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"\"x\"}"}}"#,
            ),
        ];
        let mut accumulator = ResponseAccumulator::new();
        for (name, data) in frames {
            for event in a.decode_stream_event(Some(name), data).expect("decodes") {
                accumulator.push(&event);
            }
        }
        let calls = accumulator.sorted_tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "toolu_1");
        assert_eq!(calls[0].name, "lookup");
        assert_eq!(calls[0].arguments, r#"{"q":"x"}"#);
    }

    #[test]
    fn two_tool_blocks_do_not_merge() {
        let a = AnthropicAdapter;
        let frames: Vec<(&str, &str)> = vec![
            (
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"tool_use","id":"a","name":"f"}}"#,
            ),
            (
                "content_block_start",
                r#"{"index":1,"content_block":{"type":"tool_use","id":"b","name":"g"}}"#,
            ),
            (
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}"#,
            ),
            (
                "content_block_delta",
                r#"{"index":1,"delta":{"type":"input_json_delta","partial_json":"{\"b\":2}"}}"#,
            ),
        ];
        let mut accumulator = ResponseAccumulator::new();
        for (name, data) in frames {
            for event in a.decode_stream_event(Some(name), data).expect("decodes") {
                accumulator.push(&event);
            }
        }
        let calls = accumulator.sorted_tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].arguments, r#"{"a":1}"#);
        assert_eq!(calls[1].arguments, r#"{"b":2}"#);
    }

    #[test]
    fn there_is_no_terminator_payload() {
        // The stream ends with message_stop and a close, not a sentinel.
        assert!(!AnthropicAdapter.is_stream_terminator("[DONE]"));
        assert!(!AnthropicAdapter.is_stream_terminator(""));
    }

    #[test]
    fn ignorable_events_produce_nothing() {
        let a = AnthropicAdapter;
        for (name, data) in [
            ("ping", r#"{"type":"ping"}"#),
            ("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
            ("message_stop", r#"{"type":"message_stop"}"#),
        ] {
            assert!(
                a.decode_stream_event(Some(name), data).unwrap().is_empty(),
                "{name} should produce no canonical events"
            );
        }
    }

    #[test]
    fn errors_classify_by_provider_type() {
        let a = AnthropicAdapter;

        let rate = a.classify_error(429, br#"{"error":{"type":"rate_limit_error"}}"#);
        assert_eq!(rate.class, UpstreamErrorClass::RateLimited);
        assert!(rate.is_retriable());

        let overloaded = a.classify_error(529, br#"{"error":{"type":"overloaded_error"}}"#);
        assert_eq!(overloaded.class, UpstreamErrorClass::RateLimited);

        let auth = a.classify_error(401, br#"{"error":{"type":"authentication_error"}}"#);
        assert_eq!(auth.class, UpstreamErrorClass::Authentication);
        assert!(!auth.is_retriable());

        let context = a.classify_error(
            400,
            br#"{"error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum context"}}"#,
        );
        assert_eq!(context.class, UpstreamErrorClass::ContextOverflow);
    }

    #[test]
    fn a_provider_message_is_not_forwarded() {
        let classification = AnthropicAdapter.classify_error(
            400,
            br#"{"error":{"type":"invalid_request_error","message":"messages.0: 'my private prompt text' is invalid"}}"#,
        );
        assert!(!classification.safe_detail.as_str().contains("private prompt"));
    }

    #[test]
    fn a_mid_stream_error_event_is_classified() {
        let err = AnthropicAdapter
            .decode_stream_event(
                Some("error"),
                r#"{"type":"error","error":{"type":"overloaded_error"}}"#,
            )
            .expect_err("must fail");
        assert_eq!(err.class, UpstreamErrorClass::RateLimited);
    }

    #[test]
    fn response_format_is_refused_rather_than_dropped() {
        // Accepting and silently ignoring the constraint would hand the caller
        // unconstrained text they will try to parse as JSON.
        let target = anthropic_target_fixture();
        let mut request = request_fixture();
        request.response_format = Some(ResponseFormat::JsonObject);
        let failure = AnthropicAdapter
            .validate(&request, &target.capabilities)
            .unwrap_err();
        assert_eq!(failure.code, "response_format_unsupported");
        assert_eq!(failure.param, Some("response_format"));
    }

    #[test]
    fn audio_content_is_refused() {
        let mut request = request_fixture();
        request.messages.push(Message {
            role: Role::User,
            content: vec![ContentPart::Audio {
                format: "wav".to_owned(),
                base64_data: "AAAA".to_owned(),
            }],
            name: None,
            tool_calls: Vec::new(),
        });
        let target = anthropic_target_fixture();
        let endpoint = endpoint_fixture("api.anthropic.com");
        let meta = meta_fixture(&target, &endpoint, false);
        let failure = AnthropicAdapter
            .encode_request(&request, &meta)
            .expect_err("must refuse");
        assert_eq!(failure.code, "modality_unsupported");
    }

    #[test]
    fn embeddings_are_not_served() {
        let mut request = request_fixture();
        request.operation = Operation::Embeddings;
        assert!(AnthropicAdapter.path_for(&request).is_err());
    }

    #[test]
    fn unset_sampling_is_omitted() {
        let mut request = request_fixture();
        request.sampling = Sampling::default();
        let body = encoded(&request);
        for field in ["temperature", "top_p", "top_k", "stop_sequences"] {
            assert!(body.get(field).is_none(), "{field} must not be sent");
        }
    }
}
