//! The Anthropic-compatible client protocol.
//!
//! Specification 8: `POST /v1/messages` — "SHOULD; Anthropic-compatible client
//! profile", and 8.1: "Implement exact Messages streaming/error profile."
//!
//! The streaming profile is the part that has to be exact. An Anthropic client
//! SDK drives a state machine over *named* events and will fail on a stream
//! that carries the right content in the wrong frame sequence:
//!
//! ```text
//! message_start          → the message shell and input token count
//! content_block_start    → one per content block, with its index
//! content_block_delta    → text_delta or input_json_delta fragments
//! content_block_stop     → closes a block
//! message_delta          → the stop reason and output token count
//! message_stop           → ends the stream
//! ```
//!
//! [`StreamRenderer`] owns that sequence, so the listener emits canonical
//! events and the frame discipline is enforced in one place.

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, ContentPart, ImageSource, Message, Operation, RequestLimits,
    Role, RoutingHints, Sampling, StreamOptions, ToolCall, ToolChoice, ToolDef,
};
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::{CanonicalEvent, FinishReason, ResponseAccumulator};
use hypellm_core::ids::{AliasId, RequestId};
use wire_json::{Limits, Object, Value, parse, to_string};

use super::openai::ParseContext;

/// Parse an Anthropic-style messages request.
pub fn parse_messages_request(
    body: &[u8],
    context: &ParseContext,
    limits: &Limits,
) -> Result<CanonicalRequest, RouterError> {
    let value = parse(body, limits).map_err(|e| {
        RouterError::invalid_request(&format!("request body is not valid JSON ({})", e.kind.code()))
    })?;

    let raw_model = value.field_str("model").map_err(|_| {
        RouterError::invalid_request("the 'model' field is required").with_param("model")
    })?;
    let model = AliasId::new(raw_model).map_err(|_| {
        RouterError::new(ErrorCode::ModelNotFound, "the requested model is not available")
            .with_param("model")
    })?;

    let mut messages = Vec::new();

    // The system prompt arrives as a top-level field and becomes a system
    // message, which is the canonical shape.
    match value.get_present("system") {
        None => {}
        Some(Value::String(text)) => {
            messages.push(Message::text(Role::System, text.as_str()));
        }
        Some(Value::Array(blocks)) => {
            let joined: Vec<&str> = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|v| v.as_str()))
                .collect();
            if !joined.is_empty() {
                messages.push(Message::text(Role::System, joined.join("\n\n")));
            }
        }
        Some(_) => {
            return Err(
                RouterError::invalid_request("'system' must be a string or an array of blocks")
                    .with_param("system"),
            );
        }
    }

    let raw_messages = value.field_array("messages").map_err(|_| {
        RouterError::invalid_request("the 'messages' field is required").with_param("messages")
    })?;
    for (index, raw) in raw_messages.iter().enumerate() {
        messages.push(parse_message(raw, index)?);
    }

    let mut tools = Vec::new();
    if let Some(raw_tools) = value.opt_field_array("tools").map_err(type_error)? {
        for (index, raw) in raw_tools.iter().enumerate() {
            let name = raw.field_str("name").map_err(|_| {
                RouterError::invalid_request("each tool requires a name")
                    .with_param(&format!("tools[{index}]"))
            })?;
            tools.push(ToolDef {
                name: name.to_owned(),
                description: raw
                    .opt_field_str("description")
                    .map_err(type_error)?
                    .map(str::to_owned),
                parameters_json: raw
                    .get("input_schema")
                    .map_or_else(|| "{}".to_owned(), to_string),
                strict: false,
            });
        }
    }

    let sampling = Sampling {
        temperature: value.opt_field_f64("temperature").map_err(type_error)?,
        top_p: value.opt_field_f64("top_p").map_err(type_error)?,
        top_k: value
            .opt_field_i64("top_k")
            .map_err(type_error)?
            .and_then(|v| u32::try_from(v).ok()),
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        stop: value
            .opt_field_array("stop_sequences")
            .map_err(type_error)?
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    };
    if let Err(param) = sampling.validate() {
        return Err(
            RouterError::invalid_request("a sampling parameter is out of range").with_param(param),
        );
    }

    // `max_tokens` is required by this protocol, so a missing one is a client
    // error rather than something the router fills in.
    let max_tokens = value.field_i64("max_tokens").map_err(|_| {
        RouterError::invalid_request("the 'max_tokens' field is required")
            .with_param("max_tokens")
    })?;
    let max_output_tokens = u32::try_from(max_tokens).map_err(|_| {
        RouterError::invalid_request("'max_tokens' is out of range").with_param("max_tokens")
    })?;

    Ok(CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol: ClientProtocol::AnthropicMessages,
        operation: Operation::Chat,
        requested_model: model,
        messages,
        inputs: Vec::new(),
        tools,
        tool_choice: parse_tool_choice(&value)?,
        response_format: None,
        sampling,
        limits: RequestLimits {
            max_output_tokens: Some(max_output_tokens),
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            residency: context.residency.clone(),
        },
        stream: StreamOptions {
            enabled: value.opt_field_bool("stream").map_err(type_error)?.unwrap_or(false),
            include_usage: true,
        },
        hints: RoutingHints::default(),
    })
}

fn type_error(e: wire_json::TypeError) -> RouterError {
    RouterError::invalid_request(&e.to_string()).with_param(&e.path)
}

fn parse_message(raw: &Value, index: usize) -> Result<Message, RouterError> {
    let param = format!("messages[{index}]");
    let role_text = raw.field_str("role").map_err(|_| {
        RouterError::invalid_request("each message requires a 'role'").with_param(&param)
    })?;
    let role = match role_text {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        other => {
            return Err(RouterError::invalid_request(&format!(
                "unrecognised message role '{other}'"
            ))
            .with_param(&param));
        }
    };

    let mut content = Vec::new();
    let mut tool_calls = Vec::new();

    match raw.get_present("content") {
        None => {}
        Some(Value::String(text)) => content.push(ContentPart::Text(text.clone())),
        Some(Value::Array(blocks)) => {
            for block in blocks {
                match block.opt_field_str("type").map_err(type_error)?.unwrap_or("text") {
                    "text" => content.push(ContentPart::Text(
                        block.opt_field_str("text").map_err(type_error)?.unwrap_or("").to_owned(),
                    )),
                    "image" => {
                        let source = block.get("source").ok_or_else(|| {
                            RouterError::invalid_request("an image block requires 'source'")
                                .with_param(&param)
                        })?;
                        match source.opt_field_str("type").map_err(type_error)? {
                            Some("url") => content.push(ContentPart::Image(ImageSource::Url(
                                source
                                    .opt_field_str("url")
                                    .map_err(type_error)?
                                    .unwrap_or("")
                                    .to_owned(),
                            ))),
                            _ => content.push(ContentPart::Image(ImageSource::Inline {
                                media_type: source
                                    .opt_field_str("media_type")
                                    .map_err(type_error)?
                                    .unwrap_or("application/octet-stream")
                                    .to_owned(),
                                base64_data: source
                                    .opt_field_str("data")
                                    .map_err(type_error)?
                                    .unwrap_or("")
                                    .to_owned(),
                            })),
                        }
                    }
                    "tool_use" => tool_calls.push(ToolCall {
                        id: block.opt_field_str("id").map_err(type_error)?.unwrap_or("").to_owned(),
                        name: block
                            .opt_field_str("name")
                            .map_err(type_error)?
                            .unwrap_or("")
                            .to_owned(),
                        arguments: block
                            .get("input")
                            .map_or_else(|| "{}".to_owned(), to_string),
                    }),
                    "tool_result" => content.push(ContentPart::ToolResult {
                        tool_call_id: block
                            .opt_field_str("tool_use_id")
                            .map_err(type_error)?
                            .unwrap_or("")
                            .to_owned(),
                        content: match block.get("content") {
                            Some(Value::String(s)) => s.clone(),
                            Some(other) => to_string(other),
                            None => String::new(),
                        },
                        is_error: block
                            .opt_field_bool("is_error")
                            .map_err(type_error)?
                            .unwrap_or(false),
                    }),
                    other => {
                        return Err(RouterError::invalid_request(&format!(
                            "unsupported content block type '{other}'"
                        ))
                        .with_param(&param));
                    }
                }
            }
        }
        Some(_) => {
            return Err(RouterError::invalid_request(
                "message content must be a string or an array of blocks",
            )
            .with_param(&param));
        }
    }

    Ok(Message {
        role,
        content,
        name: None,
        tool_calls,
    })
}

fn parse_tool_choice(value: &Value) -> Result<Option<ToolChoice>, RouterError> {
    let Some(choice) = value.get_present("tool_choice") else {
        return Ok(None);
    };
    let kind = choice.field_str("type").map_err(|_| {
        RouterError::invalid_request("tool_choice requires a 'type'").with_param("tool_choice")
    })?;
    Ok(Some(match kind {
        "auto" => ToolChoice::Auto,
        "any" => ToolChoice::Required,
        "none" => ToolChoice::None,
        "tool" => ToolChoice::Function(
            choice
                .opt_field_str("name")
                .map_err(type_error)?
                .unwrap_or("")
                .to_owned(),
        ),
        other => {
            return Err(RouterError::invalid_request(&format!(
                "unrecognised tool_choice type '{other}'"
            ))
            .with_param("tool_choice"));
        }
    }))
}

// -- Rendering --------------------------------------------------------------

/// Render a complete, non-streaming message response.
#[must_use]
pub fn render_message_response(
    request: &CanonicalRequest,
    accumulator: &ResponseAccumulator,
) -> String {
    let mut blocks = Vec::new();
    if !accumulator.text.is_empty() {
        let mut block = Object::new();
        block.push("type", Value::from("text"));
        block.push("text", Value::from(accumulator.text.as_str()));
        blocks.push(Value::Object(block));
    }
    for call in accumulator.sorted_tool_calls() {
        let mut block = Object::new();
        block.push("type", Value::from("tool_use"));
        block.push("id", Value::from(call.id.as_str()));
        block.push("name", Value::from(call.name.as_str()));
        block.push(
            "input",
            wire_json::parse_str(&call.arguments, &Limits::SMALL)
                .unwrap_or_else(|_| Value::Object(Object::new())),
        );
        blocks.push(Value::Object(block));
    }

    let usage = accumulator.usage.unwrap_or_default();
    let mut usage_object = Object::new();
    usage_object.push("input_tokens", Value::from(usage.input_tokens));
    usage_object.push("output_tokens", Value::from(usage.output_tokens));

    let mut root = Object::new();
    root.push("id", Value::from(format!("msg_{}", request.request_id)));
    root.push("type", Value::from("message"));
    root.push("role", Value::from("assistant"));
    root.push("model", Value::from(request.requested_model.as_str()));
    root.push("content", Value::Array(blocks));
    root.push(
        "stop_reason",
        Value::from(
            accumulator
                .finish
                .unwrap_or(FinishReason::Stop)
                .anthropic_str(),
        ),
    );
    root.push("stop_sequence", Value::Null);
    root.push("usage", Value::Object(usage_object));
    to_string(&Value::Object(root))
}

/// Render the error envelope.
#[must_use]
pub fn render_error(error: &RouterError, request_id: Option<RequestId>) -> String {
    let mut inner = Object::new();
    inner.push("type", Value::from(error.code.anthropic_type()));
    inner.push("message", Value::from(error.detail.as_str()));

    let mut root = Object::new();
    root.push("type", Value::from("error"));
    root.push("error", Value::Object(inner));
    root.push_opt(
        "request_id",
        request_id.map(|id| Value::from(id.to_string())),
    );
    to_string(&Value::Object(root))
}

/// A rendered stream frame: an event name and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The SSE event name.
    pub event: String,
    /// The JSON payload.
    pub data: String,
}

/// Renders the Anthropic streaming frame sequence.
///
/// The sequence is a state machine, not a per-event mapping: a text delta must
/// be preceded by a `content_block_start` for its block, and every opened block
/// must be closed before `message_stop`. Encoding that here means the listener
/// cannot emit a frame order a client SDK will reject.
#[derive(Debug)]
pub struct StreamRenderer {
    message_started: bool,
    /// The index of the currently open block, if any.
    open_block: Option<u32>,
    /// The next block index to allocate for text.
    next_text_block: u32,
    /// Whether a text block has been opened.
    text_block: Option<u32>,
    stopped: bool,
}

impl StreamRenderer {
    /// A renderer at the start of a stream.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            message_started: false,
            open_block: None,
            next_text_block: 0,
            text_block: None,
            stopped: false,
        }
    }

    /// Whether `message_start` has been emitted.
    #[must_use]
    pub const fn has_started(&self) -> bool {
        self.message_started
    }

    /// Render the frames for one canonical event.
    pub fn render(&mut self, request: &CanonicalRequest, event: &CanonicalEvent) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.stopped {
            return frames;
        }

        match event {
            CanonicalEvent::Start { upstream_id, .. } => {
                if !self.message_started {
                    self.message_started = true;
                    frames.push(self.message_start(request, upstream_id.as_deref()));
                }
            }
            CanonicalEvent::TextDelta(text) => {
                self.ensure_started(request, &mut frames);
                let index = match self.text_block {
                    Some(index) => index,
                    None => {
                        let index = self.allocate_block();
                        self.text_block = Some(index);
                        frames.push(content_block_start_text(index));
                        self.open_block = Some(index);
                        index
                    }
                };
                frames.push(text_delta(index, text));
            }
            CanonicalEvent::ReasoningDelta(text) => {
                self.ensure_started(request, &mut frames);
                let index = match self.text_block {
                    Some(index) => index,
                    None => {
                        let index = self.allocate_block();
                        self.text_block = Some(index);
                        frames.push(content_block_start_text(index));
                        self.open_block = Some(index);
                        index
                    }
                };
                frames.push(thinking_delta(index, text));
            }
            CanonicalEvent::ToolCallDelta(call) => {
                self.ensure_started(request, &mut frames);
                // A tool block interrupts the text block, which must close.
                if let Some(open) = self.text_block.take() {
                    frames.push(content_block_stop(open));
                }
                let index = call.index;
                if call.id.is_some() || call.name.is_some() {
                    frames.push(content_block_start_tool(
                        index,
                        call.id.as_deref().unwrap_or(""),
                        call.name.as_deref().unwrap_or(""),
                    ));
                    self.open_block = Some(index);
                    self.next_text_block = self.next_text_block.max(index + 1);
                }
                if !call.arguments_delta.is_empty() {
                    frames.push(input_json_delta(index, &call.arguments_delta));
                }
            }
            CanonicalEvent::Usage(usage) => {
                self.ensure_started(request, &mut frames);
                frames.push(message_delta(None, Some(usage.output_tokens)));
            }
            CanonicalEvent::Finish { reason } => {
                self.ensure_started(request, &mut frames);
                if let Some(open) = self.open_block.take() {
                    frames.push(content_block_stop(open));
                    self.text_block = None;
                }
                frames.push(message_delta(Some(*reason), None));
                frames.push(message_stop());
                self.stopped = true;
            }
            CanonicalEvent::Error(error) => {
                frames.push(error_frame(error));
                self.stopped = true;
            }
            CanonicalEvent::Embedding { .. } => {}
        }

        frames
    }

    /// Close any open block and end the stream, for a cancellation or a
    /// deadline.
    pub fn finish(&mut self, reason: FinishReason) -> Vec<Frame> {
        if self.stopped {
            return Vec::new();
        }
        let mut frames = Vec::new();
        if let Some(open) = self.open_block.take() {
            frames.push(content_block_stop(open));
        }
        frames.push(message_delta(Some(reason), None));
        frames.push(message_stop());
        self.stopped = true;
        frames
    }

    fn allocate_block(&mut self) -> u32 {
        let index = self.next_text_block;
        self.next_text_block += 1;
        index
    }

    fn ensure_started(&mut self, request: &CanonicalRequest, frames: &mut Vec<Frame>) {
        if !self.message_started {
            self.message_started = true;
            frames.push(self.message_start(request, None));
        }
    }

    fn message_start(&self, request: &CanonicalRequest, upstream_id: Option<&str>) -> Frame {
        let mut usage = Object::new();
        usage.push("input_tokens", Value::from(0i64));
        usage.push("output_tokens", Value::from(0i64));

        let mut message = Object::new();
        message.push(
            "id",
            Value::from(
                upstream_id
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("msg_{}", request.request_id)),
            ),
        );
        message.push("type", Value::from("message"));
        message.push("role", Value::from("assistant"));
        message.push("model", Value::from(request.requested_model.as_str()));
        message.push("content", Value::Array(Vec::new()));
        message.push("stop_reason", Value::Null);
        message.push("stop_sequence", Value::Null);
        message.push("usage", Value::Object(usage));

        let mut root = Object::new();
        root.push("type", Value::from("message_start"));
        root.push("message", Value::Object(message));
        Frame {
            event: "message_start".to_owned(),
            data: to_string(&Value::Object(root)),
        }
    }
}

impl Default for StreamRenderer {
    fn default() -> Self {
        Self::new()
    }
}

fn content_block_start_text(index: u32) -> Frame {
    let mut block = Object::new();
    block.push("type", Value::from("text"));
    block.push("text", Value::from(""));
    let mut root = Object::new();
    root.push("type", Value::from("content_block_start"));
    root.push("index", Value::from(u64::from(index)));
    root.push("content_block", Value::Object(block));
    Frame {
        event: "content_block_start".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn content_block_start_tool(index: u32, id: &str, name: &str) -> Frame {
    let mut block = Object::new();
    block.push("type", Value::from("tool_use"));
    block.push("id", Value::from(id));
    block.push("name", Value::from(name));
    block.push("input", Value::Object(Object::new()));
    let mut root = Object::new();
    root.push("type", Value::from("content_block_start"));
    root.push("index", Value::from(u64::from(index)));
    root.push("content_block", Value::Object(block));
    Frame {
        event: "content_block_start".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn text_delta(index: u32, text: &str) -> Frame {
    let mut delta = Object::new();
    delta.push("type", Value::from("text_delta"));
    delta.push("text", Value::from(text));
    delta_frame(index, delta)
}

fn thinking_delta(index: u32, text: &str) -> Frame {
    let mut delta = Object::new();
    delta.push("type", Value::from("thinking_delta"));
    delta.push("thinking", Value::from(text));
    delta_frame(index, delta)
}

fn input_json_delta(index: u32, fragment: &str) -> Frame {
    let mut delta = Object::new();
    delta.push("type", Value::from("input_json_delta"));
    delta.push("partial_json", Value::from(fragment));
    delta_frame(index, delta)
}

fn delta_frame(index: u32, delta: Object) -> Frame {
    let mut root = Object::new();
    root.push("type", Value::from("content_block_delta"));
    root.push("index", Value::from(u64::from(index)));
    root.push("delta", Value::Object(delta));
    Frame {
        event: "content_block_delta".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn content_block_stop(index: u32) -> Frame {
    let mut root = Object::new();
    root.push("type", Value::from("content_block_stop"));
    root.push("index", Value::from(u64::from(index)));
    Frame {
        event: "content_block_stop".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn message_delta(reason: Option<FinishReason>, output_tokens: Option<u64>) -> Frame {
    let mut delta = Object::new();
    delta.push(
        "stop_reason",
        reason.map_or(Value::Null, |r| Value::from(r.anthropic_str())),
    );
    delta.push("stop_sequence", Value::Null);

    let mut usage = Object::new();
    usage.push("output_tokens", Value::from(output_tokens.unwrap_or(0)));

    let mut root = Object::new();
    root.push("type", Value::from("message_delta"));
    root.push("delta", Value::Object(delta));
    root.push("usage", Value::Object(usage));
    Frame {
        event: "message_delta".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn message_stop() -> Frame {
    let mut root = Object::new();
    root.push("type", Value::from("message_stop"));
    Frame {
        event: "message_stop".to_owned(),
        data: to_string(&Value::Object(root)),
    }
}

fn error_frame(error: &RouterError) -> Frame {
    let mut inner = Object::new();
    inner.push("type", Value::from(error.code.anthropic_type()));
    inner.push("message", Value::from(error.detail.as_str()));
    let mut root = Object::new();
    root.push("type", Value::from("error"));
    root.push("error", Value::Object(inner));
    Frame {
        event: "error".to_owned(),
        data: to_string(&Value::Object(root)),
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
    use super::*;
    use hypellm_core::ids::{PrincipalId, TenantId};
    use hypellm_core::time::{Deadline, TestClock};
    use std::time::Duration;
    use wire_json::parse_str;

    fn context() -> ParseContext {
        let clock = TestClock::new();
        ParseContext {
            request_id: RequestId::from_u128(0x1234),
            tenant: TenantId::new("acme").unwrap(),
            principal: PrincipalId::new("user:42").unwrap(),
            deadline: Deadline::after(&clock, Duration::from_secs(60)),
            hints_permitted: false,
            residency: None,
            max_cost_class: None,
        }
    }

    fn parse_messages(body: &str) -> Result<CanonicalRequest, RouterError> {
        parse_messages_request(body.as_bytes(), &context(), &Limits::DEFAULT)
    }

    const MINIMAL: &str =
        r#"{"model":"code-premium","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}"#;

    #[test]
    fn a_minimal_request_parses() {
        let request = parse_messages(MINIMAL).expect("parses");
        assert_eq!(request.requested_model.as_str(), "code-premium");
        assert_eq!(request.protocol, ClientProtocol::AnthropicMessages);
        assert_eq!(request.limits.max_output_tokens, Some(1024));
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].as_text().as_deref(), Some("hi"));
    }

    #[test]
    fn max_tokens_is_required() {
        let error = parse_messages(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#)
            .expect_err("must fail");
        assert_eq!(error.param.expect("param").as_str(), "max_tokens");
    }

    #[test]
    fn the_system_field_becomes_a_system_message() {
        let request = parse_messages(
            r#"{"model":"m","max_tokens":10,"system":"Be terse.","messages":[{"role":"user","content":"x"}]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].role, Role::System);
        assert_eq!(request.messages[0].as_text().as_deref(), Some("Be terse."));
        assert_eq!(request.messages[1].role, Role::User);
    }

    #[test]
    fn a_block_form_system_field_is_joined() {
        let request = parse_messages(
            r#"{"model":"m","max_tokens":10,"system":[{"type":"text","text":"One."},{"type":"text","text":"Two."}],"messages":[{"role":"user","content":"x"}]}"#,
        )
        .unwrap();
        let system = request.messages[0].as_text().expect("text");
        assert!(system.contains("One."));
        assert!(system.contains("Two."));
    }

    #[test]
    fn content_blocks_parse() {
        let request = parse_messages(
            r#"{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[
                {"type":"text","text":"look"},
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}
            ]}]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].content.len(), 2);
        match &request.messages[0].content[1] {
            ContentPart::Image(ImageSource::Inline { media_type, .. }) => {
                assert_eq!(media_type, "image/png");
            }
            other => panic!("expected an inline image, got {other:?}"),
        }
    }

    #[test]
    fn tool_use_and_tool_result_blocks_parse() {
        let request = parse_messages(
            r#"{"model":"m","max_tokens":10,"messages":[
                {"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"f","input":{"q":"x"}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"42"}]}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].tool_calls.len(), 1);
        assert_eq!(request.messages[0].tool_calls[0].id, "toolu_1");
        match &request.messages[1].content[0] {
            ContentPart::ToolResult { tool_call_id, content, .. } => {
                assert_eq!(tool_call_id, "toolu_1");
                assert_eq!(content, "42");
            }
            other => panic!("expected a tool result, got {other:?}"),
        }
    }

    #[test]
    fn tools_parse_with_their_input_schema() {
        let request = parse_messages(
            r#"{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"x"}],
                "tools":[{"name":"lookup","description":"d","input_schema":{"type":"object"}}]}"#,
        )
        .unwrap();
        assert_eq!(request.tools[0].name, "lookup");
        let schema = parse_str(&request.tools[0].parameters_json, &Limits::SMALL).unwrap();
        assert_eq!(schema.field_str("type").unwrap(), "object");
    }

    #[test]
    fn tool_choice_shapes_parse() {
        for (raw, expected) in [
            (r#"{"type":"auto"}"#, ToolChoice::Auto),
            (r#"{"type":"any"}"#, ToolChoice::Required),
            (r#"{"type":"none"}"#, ToolChoice::None),
            (
                r#"{"type":"tool","name":"f"}"#,
                ToolChoice::Function("f".to_owned()),
            ),
        ] {
            let body = format!(
                r#"{{"model":"m","max_tokens":10,"messages":[{{"role":"user","content":"x"}}],"tool_choice":{raw}}}"#
            );
            assert_eq!(parse_messages(&body).unwrap().tool_choice, Some(expected));
        }
    }

    // -- Streaming ----------------------------------------------------------

    fn render_all(events: &[CanonicalEvent]) -> Vec<Frame> {
        let request = parse_messages(MINIMAL).unwrap();
        let mut renderer = StreamRenderer::new();
        let mut frames = Vec::new();
        for event in events {
            frames.extend(renderer.render(&request, event));
        }
        frames
    }

    fn names(frames: &[Frame]) -> Vec<&str> {
        frames.iter().map(|f| f.event.as_str()).collect()
    }

    #[test]
    fn the_frame_sequence_matches_the_profile() {
        let frames = render_all(&[
            CanonicalEvent::Start {
                upstream_id: Some("msg_up".to_owned()),
                native_model: None,
            },
            CanonicalEvent::TextDelta("Hel".to_owned()),
            CanonicalEvent::TextDelta("lo".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);

        assert_eq!(
            names(&frames),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
    }

    #[test]
    fn a_stream_that_starts_with_content_still_emits_message_start() {
        // A provider that omits an explicit start must not produce a stream
        // missing its opening frame — a client SDK rejects that outright.
        let frames = render_all(&[CanonicalEvent::TextDelta("x".to_owned())]);
        assert_eq!(names(&frames)[0], "message_start");
    }

    #[test]
    fn every_opened_block_is_closed() {
        let frames = render_all(&[
            CanonicalEvent::TextDelta("a".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);
        let starts = frames.iter().filter(|f| f.event == "content_block_start").count();
        let stops = frames.iter().filter(|f| f.event == "content_block_stop").count();
        assert_eq!(starts, stops, "unbalanced content blocks: {:?}", names(&frames));
    }

    #[test]
    fn a_tool_call_closes_the_text_block_first() {
        let frames = render_all(&[
            CanonicalEvent::TextDelta("thinking".to_owned()),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 1,
                id: Some("toolu_1".to_owned()),
                name: Some("f".to_owned()),
                arguments_delta: String::new(),
            }),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 1,
                id: None,
                name: None,
                arguments_delta: r#"{"q":1}"#.to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        let sequence = names(&frames);
        assert_eq!(sequence[0], "message_start");
        assert_eq!(sequence[1], "content_block_start");
        assert_eq!(sequence[2], "content_block_delta");
        assert_eq!(sequence[3], "content_block_stop", "the text block closes");
        assert_eq!(sequence[4], "content_block_start", "the tool block opens");
        assert_eq!(sequence[5], "content_block_delta");
        assert_eq!(sequence[6], "content_block_stop");
        assert_eq!(sequence[7], "message_delta");
        assert_eq!(sequence[8], "message_stop");
    }

    #[test]
    fn tool_argument_fragments_use_input_json_delta() {
        let frames = render_all(&[CanonicalEvent::ToolCallDelta(
            hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("t".to_owned()),
                name: Some("f".to_owned()),
                arguments_delta: r#"{"a":"#.to_owned(),
            },
        )]);
        let delta = frames.iter().find(|f| f.event == "content_block_delta").unwrap();
        let value = parse_str(&delta.data, &Limits::SMALL).unwrap();
        assert_eq!(
            value.get("delta").unwrap().field_str("type").unwrap(),
            "input_json_delta"
        );
        assert_eq!(
            value.get("delta").unwrap().field_str("partial_json").unwrap(),
            r#"{"a":"#
        );
    }

    #[test]
    fn every_frame_is_valid_json_with_a_matching_type() {
        let frames = render_all(&[
            CanonicalEvent::Start {
                upstream_id: None,
                native_model: None,
            },
            CanonicalEvent::TextDelta("x".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(5, 2)),
            CanonicalEvent::Finish {
                reason: FinishReason::Length,
            },
        ]);
        for frame in &frames {
            let value = parse_str(&frame.data, &Limits::SMALL)
                .unwrap_or_else(|e| panic!("frame {} is not valid JSON: {e}", frame.event));
            assert_eq!(
                value.field_str("type").unwrap(),
                frame.event,
                "the payload type must match the event name"
            );
        }
    }

    #[test]
    fn the_stop_reason_is_translated() {
        let frames = render_all(&[CanonicalEvent::Finish {
            reason: FinishReason::Length,
        }]);
        let delta = frames.iter().find(|f| f.event == "message_delta").unwrap();
        let value = parse_str(&delta.data, &Limits::SMALL).unwrap();
        assert_eq!(
            value.get("delta").unwrap().field_str("stop_reason").unwrap(),
            "max_tokens"
        );
    }

    #[test]
    fn nothing_is_emitted_after_the_stream_stops() {
        let request = parse_messages(MINIMAL).unwrap();
        let mut renderer = StreamRenderer::new();
        renderer.render(
            &request,
            &CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        );
        let after = renderer.render(&request, &CanonicalEvent::TextDelta("late".to_owned()));
        assert!(after.is_empty(), "no frame may follow message_stop");
        assert!(renderer.finish(FinishReason::Stop).is_empty());
    }

    #[test]
    fn finishing_early_closes_the_stream_cleanly() {
        // A cancellation or deadline must still leave a well-formed stream.
        let request = parse_messages(MINIMAL).unwrap();
        let mut renderer = StreamRenderer::new();
        renderer.render(&request, &CanonicalEvent::TextDelta("partial".to_owned()));
        let closing = renderer.finish(FinishReason::Cancelled);
        assert_eq!(
            names(&closing),
            vec!["content_block_stop", "message_delta", "message_stop"]
        );
    }

    #[test]
    fn an_error_event_renders_an_error_frame_and_stops() {
        let frames = render_all(&[
            CanonicalEvent::TextDelta("x".to_owned()),
            CanonicalEvent::Error(RouterError::new(
                ErrorCode::UpstreamInvalidResponse,
                "the provider violated its contract",
            )),
        ]);
        let last = frames.last().unwrap();
        assert_eq!(last.event, "error");
        let value = parse_str(&last.data, &Limits::SMALL).unwrap();
        assert_eq!(
            value.get("error").unwrap().field_str("type").unwrap(),
            "api_error"
        );
    }

    // -- Non-streaming rendering --------------------------------------------

    #[test]
    fn a_complete_response_renders() {
        let request = parse_messages(MINIMAL).unwrap();
        let mut accumulator = ResponseAccumulator::new();
        for event in [
            CanonicalEvent::TextDelta("Hello".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(10, 2)),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ] {
            accumulator.push(&event);
        }

        let value = parse_str(
            &render_message_response(&request, &accumulator),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(value.field_str("type").unwrap(), "message");
        assert_eq!(value.field_str("role").unwrap(), "assistant");
        assert_eq!(value.field_str("stop_reason").unwrap(), "end_turn");
        let content = value.field_array("content").unwrap();
        assert_eq!(content[0].field_str("type").unwrap(), "text");
        assert_eq!(content[0].field_str("text").unwrap(), "Hello");
        assert_eq!(
            value.get("usage").unwrap().field_i64("input_tokens").unwrap(),
            10
        );
    }

    #[test]
    fn tool_calls_render_as_tool_use_blocks() {
        let request = parse_messages(MINIMAL).unwrap();
        let mut accumulator = ResponseAccumulator::new();
        accumulator.push(&CanonicalEvent::ToolCallDelta(
            hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("toolu_1".to_owned()),
                name: Some("lookup".to_owned()),
                arguments_delta: r#"{"q":"x"}"#.to_owned(),
            },
        ));
        let value = parse_str(
            &render_message_response(&request, &accumulator),
            &Limits::DEFAULT,
        )
        .unwrap();
        let block = &value.field_array("content").unwrap()[0];
        assert_eq!(block.field_str("type").unwrap(), "tool_use");
        assert_eq!(block.field_str("id").unwrap(), "toolu_1");
        assert_eq!(block.get("input").unwrap().field_str("q").unwrap(), "x");
    }

    #[test]
    fn the_error_envelope_matches_the_profile() {
        let rendered = render_error(
            &RouterError::new(ErrorCode::RateLimited, "quota exceeded"),
            Some(RequestId::from_u128(7)),
        );
        let value = parse_str(&rendered, &Limits::SMALL).unwrap();
        assert_eq!(value.field_str("type").unwrap(), "error");
        assert_eq!(
            value.get("error").unwrap().field_str("type").unwrap(),
            "rate_limit_error"
        );
    }
}
