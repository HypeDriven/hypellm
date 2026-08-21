//! The OpenAI-compatible client protocol.
//!
//! Specification 8: "The primary compatibility contract is OpenAI-style HTTP
//! because most coding harnesses can be pointed at a custom base URL.
//! Compatibility is **behavioral**, not merely path-level: streaming frames,
//! error objects, tool calls, usage reporting, cancellation, and model
//! discovery must match documented profiles."
//!
//! This module is the client-facing half: it parses a caller's request into a
//! [`CanonicalRequest`] and renders [`CanonicalEvent`]s back into the dialect
//! the caller speaks. It is deliberately separate from the *provider*-facing
//! adapter of the same name — the router does not proxy bytes through, and
//! keeping the two apart is what stops a provider quirk from becoming part of
//! the client contract.

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, ContentPart, CostClass, DocumentSource, DocumentType,
    ImageSource, Message, Operation, QualityClass, ReasoningEffort, RequestLimits, Residency,
    ResponseFormat, Role, RoutingHints, Sampling, StreamOptions, ToolCall, ToolChoice, ToolDef,
};
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::{CanonicalEvent, FinishReason, ResponseAccumulator};
use hypellm_core::ids::{AliasId, PrincipalId, RequestId, TenantId};
use hypellm_core::time::Deadline;
use wire_json::{Limits, Object, Value, parse, to_string};

/// What the caller supplied, before authentication resolves the principal.
#[derive(Debug, Clone)]
pub struct ParseContext {
    /// The request identifier the router assigned.
    pub request_id: RequestId,
    /// The authenticated tenant.
    pub tenant: TenantId,
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// The deadline for the whole exchange.
    pub deadline: Deadline,
    /// Whether the principal may supply routing hints (specification 5.1).
    pub hints_permitted: bool,
    /// The tenant's required data region, from configuration.
    ///
    /// Specification 6.2 lists residency among the eligibility filters, and
    /// specification 5.1 keeps it out of the caller's hands: a residency
    /// constraint a client could set would be one it could also unset. It comes
    /// from the `tenant` record and is applied to every request that tenant
    /// makes.
    pub residency: Option<Residency>,
    /// The most expensive class this tenant's requests may select.
    ///
    /// Specification 6.2: "Estimated cost class and actual policy ceiling
    /// permit selection." The ceiling is policy, so it comes from
    /// configuration, not from the request body.
    pub max_cost_class: Option<CostClass>,
    /// The lowest quality class this tenant's requests may select.
    ///
    /// The policy floor. Unlike the cost ceiling, a caller may *raise* it in
    /// the request body — see [`effective_quality_floor`]. Raising a floor can
    /// only narrow the candidate set, so it needs no permission gate; lowering
    /// one would let a caller opt out of a compliance decision, which is why
    /// the combination takes the maximum rather than the request's value.
    pub min_quality_class: Option<QualityClass>,
    /// Bounds on the document parts a request may carry.
    pub document_limits: DocumentLimits,
}

/// The bounds a request's document parts must satisfy.
///
/// Specification-extension 3.3. Carried into the parser rather than checked
/// afterwards for the count and per-part rules, because a request that has
/// already been parsed has already allocated whatever it declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentLimits {
    /// Maximum document parts in one request.
    pub max_documents: u32,
    /// Maximum decoded bytes in any one inline document.
    pub max_document_bytes: u64,
    /// Maximum decoded bytes across every inline document.
    pub max_inline_bytes: u64,
}

impl DocumentLimits {
    /// The compiled-in defaults, matching `Settings::default`.
    pub const DEFAULT: Self = Self {
        max_documents: 4,
        max_document_bytes: 4 * 1024 * 1024,
        max_inline_bytes: 8 * 1024 * 1024,
    };
}

impl Default for DocumentLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The floor that applies to a request: the tenant's, or the caller's if higher.
fn effective_quality_floor(value: &Value, context: &ParseContext) -> Option<QualityClass> {
    let requested = value
        .opt_field_i64("min_quality")
        .ok()
        .flatten()
        .and_then(|v| u8::try_from(v).ok())
        .map(QualityClass::new);
    match (context.min_quality_class, requested) {
        (None, other) | (other, None) => other,
        (Some(policy), Some(caller)) => Some(policy.max(caller)),
    }
}

/// The reasoning tier the caller asked for, in either OpenAI spelling.
///
/// Chat Completions carries a flat `reasoning_effort`; the Responses dialect
/// nests it under `reasoning.effort`. Both are read here so that a request is
/// not silently downgraded because it used the other one.
///
/// An unrecognised value is an error rather than a silent `Unset`. A caller who
/// writes `"reasoning_effort": "maximum"` and receives a minimal answer has no
/// way to discover why.
fn parse_reasoning_effort(value: &Value) -> Result<ReasoningEffort, RouterError> {
    let raw = match value.opt_field_str("reasoning_effort").map_err(type_error)? {
        Some(v) => Some(v),
        None => value
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(Value::as_str),
    };
    let Some(raw) = raw else {
        return Ok(ReasoningEffort::Unset);
    };
    ReasoningEffort::parse(raw).ok_or_else(|| {
        RouterError::invalid_request(
            "'reasoning_effort' must be one of minimal, low, medium, or high",
        )
        .with_param("reasoning_effort")
    })
}

/// Parse an OpenAI-style chat completion request.
pub fn parse_chat_request(
    body: &[u8],
    context: &ParseContext,
    limits: &Limits,
) -> Result<CanonicalRequest, RouterError> {
    let value = parse(body, limits).map_err(|e| {
        RouterError::invalid_request(&format!("request body is not valid JSON ({})", e.kind.code()))
    })?;
    build_request(&value, context, Operation::Chat, ClientProtocol::OpenAiChat)
}

/// Parse an OpenAI-style Responses request.
///
/// Specification 8 marks `POST /v1/responses` MUST for new integrations, and it
/// is a different dialect from Chat Completions rather than a second path onto
/// the same body: `input` instead of `messages` (and it may be a bare string),
/// `input_text`/`input_image` content parts, `instructions` as a top-level
/// field instead of a system message, `max_output_tokens` instead of
/// `max_tokens`, flat tool definitions, and the response format under
/// `text.format`. Parsing it as a chat body would silently drop every one of
/// those.
pub fn parse_responses_request(
    body: &[u8],
    context: &ParseContext,
    limits: &Limits,
) -> Result<CanonicalRequest, RouterError> {
    let value = parse(body, limits).map_err(|e| {
        RouterError::invalid_request(&format!("request body is not valid JSON ({})", e.kind.code()))
    })?;

    let model = require_model(&value)?;

    let mut messages = Vec::new();
    // `instructions` is system-level guidance carried outside the turn list.
    // The canonical model has one place for that — a system message — so it is
    // hoisted to the front, ahead of every input item.
    if let Some(instructions) = value.opt_field_str("instructions").map_err(type_error)? {
        if !instructions.is_empty() {
            messages.push(Message::text(Role::System, instructions));
        }
    }

    match value.get_present("input") {
        // The bare-string form is the shorthand for a single user turn.
        Some(Value::String(text)) => messages.push(Message::text(Role::User, text.as_str())),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                messages.push(parse_input_item(item, index)?);
            }
        }
        Some(_) => {
            return Err(RouterError::invalid_request(
                "'input' must be a string or an array of input items",
            )
            .with_param("input"));
        }
        None => {
            return Err(
                RouterError::invalid_request("the 'input' field is required").with_param("input")
            );
        }
    }

    let mut tools = Vec::new();
    if let Some(raw_tools) = value.opt_field_array("tools").map_err(type_error)? {
        for (index, raw) in raw_tools.iter().enumerate() {
            tools.push(parse_responses_tool(raw, index)?);
        }
    }

    let sampling = parse_sampling(&value)?;

    let max_output_tokens = value
        .opt_field_i64("max_output_tokens")
        .map_err(type_error)?
        .map(|v| {
            u32::try_from(v).map_err(|_| {
                RouterError::invalid_request("'max_output_tokens' is out of range")
                    .with_param("max_output_tokens")
            })
        })
        .transpose()?;

    Ok(CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol: ClientProtocol::OpenAiResponses,
        operation: Operation::Responses,
        requested_model: model,
        messages,
        inputs: Vec::new(),
        tools,
        tool_choice: parse_responses_tool_choice(&value)?,
        response_format: parse_text_format(&value)?,
        sampling,
        reasoning_effort: parse_reasoning_effort(&value)?,
        limits: RequestLimits {
            max_output_tokens,
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            min_quality_class: effective_quality_floor(&value, context),
            residency: context.residency.clone(),
        },
        stream: StreamOptions {
            enabled: value.opt_field_bool("stream").map_err(type_error)?.unwrap_or(false),
            // The terminal `response.completed` event carries usage in this
            // dialect, so the router always needs the numbers — there is no
            // opt-in flag for the client to forget.
            include_usage: true,
        },
        hints: parse_hints(&value, context)?,
    })
}

/// Parse an OpenAI-style embeddings request.
pub fn parse_embeddings_request(
    body: &[u8],
    context: &ParseContext,
    limits: &Limits,
) -> Result<CanonicalRequest, RouterError> {
    let value = parse(body, limits).map_err(|e| {
        RouterError::invalid_request(&format!("request body is not valid JSON ({})", e.kind.code()))
    })?;

    let model = require_model(&value)?;
    let inputs = match value.get("input") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(text) = item.as_str() else {
                    return Err(RouterError::invalid_request(
                        "each embeddings input must be a string",
                    )
                    .with_param("input"));
                };
                out.push(text.to_owned());
            }
            out
        }
        _ => {
            return Err(
                RouterError::invalid_request("an embeddings request requires 'input'")
                    .with_param("input"),
            );
        }
    };

    Ok(CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol: ClientProtocol::OpenAiEmbeddings,
        operation: Operation::Embeddings,
        requested_model: model,
        messages: Vec::new(),
        inputs,
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        // Embeddings have no reasoning tier to request. Left `Unset` rather
        // than parsed, so an embeddings target is never excluded for a field
        // that could not have applied to it.
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: None,
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            min_quality_class: effective_quality_floor(&value, context),
            residency: context.residency.clone(),
        },
        stream: StreamOptions::default(),
        // Embeddings honour hints too. They used to be dropped here
        // unconditionally, which meant a caller who set `require_local` on an
        // embeddings request silently got a remote target — a narrowing the
        // caller asked for and did not receive, with nothing to tell them.
        hints: parse_hints(&value, context)?,
    })
}

fn require_model(value: &Value) -> Result<AliasId, RouterError> {
    let raw = value.field_str("model").map_err(|_| {
        RouterError::invalid_request("the 'model' field is required").with_param("model")
    })?;
    AliasId::new(raw).map_err(|_| {
        // The name is not echoed: a 404 that repeats an arbitrary caller string
        // is a reflection surface, and specification 8.2 gives `model_not_found`
        // no detail beyond the code.
        RouterError::new(ErrorCode::ModelNotFound, "the requested model is not available")
            .with_param("model")
    })
}

fn build_request(
    value: &Value,
    context: &ParseContext,
    operation: Operation,
    protocol: ClientProtocol,
) -> Result<CanonicalRequest, RouterError> {
    let model = require_model(value)?;

    let raw_messages = value
        .field_array("messages")
        .or_else(|_| value.field_array("input"))
        .map_err(|_| {
            RouterError::invalid_request("the 'messages' field is required").with_param("messages")
        })?;

    let mut messages = Vec::with_capacity(raw_messages.len());
    for (index, raw) in raw_messages.iter().enumerate() {
        messages.push(parse_message(raw, index)?);
    }

    let mut tools = Vec::new();
    if let Some(raw_tools) = value.opt_field_array("tools").map_err(type_error)? {
        for (index, raw) in raw_tools.iter().enumerate() {
            tools.push(parse_tool(raw, index)?);
        }
    }

    let sampling = parse_sampling(value)?;

    // Both spellings are accepted: `max_tokens` is the older field and
    // `max_completion_tokens` the newer one. Harnesses in the field send both.
    let max_output_tokens = value
        .opt_field_i64("max_completion_tokens")
        .map_err(type_error)?
        .or(value.opt_field_i64("max_tokens").map_err(type_error)?)
        .map(|v| {
            u32::try_from(v).map_err(|_| {
                RouterError::invalid_request("'max_tokens' is out of range")
                    .with_param("max_tokens")
            })
        })
        .transpose()?;

    let stream_enabled = value.opt_field_bool("stream").map_err(type_error)?.unwrap_or(false);
    let include_usage = value
        .get_present("stream_options")
        .and_then(|o| o.opt_field_bool("include_usage").ok().flatten())
        .unwrap_or(false);

    Ok(CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol,
        operation,
        requested_model: model,
        messages,
        inputs: Vec::new(),
        tools,
        tool_choice: parse_tool_choice(value)?,
        response_format: parse_response_format(value)?,
        sampling,
        reasoning_effort: parse_reasoning_effort(value)?,
        limits: RequestLimits {
            max_output_tokens,
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            min_quality_class: effective_quality_floor(value, context),
            residency: context.residency.clone(),
        },
        stream: StreamOptions {
            enabled: stream_enabled,
            include_usage,
        },
        hints: parse_hints(value, context)?,
    })
}

fn type_error(e: wire_json::TypeError) -> RouterError {
    RouterError::invalid_request(&e.to_string()).with_param(&e.path)
}

/// Read the sampling parameters, which both OpenAI dialects spell alike.
fn parse_sampling(value: &Value) -> Result<Sampling, RouterError> {
    let sampling = Sampling {
        temperature: value.opt_field_f64("temperature").map_err(type_error)?,
        top_p: value.opt_field_f64("top_p").map_err(type_error)?,
        top_k: value
            .opt_field_i64("top_k")
            .map_err(type_error)?
            .and_then(|v| u32::try_from(v).ok()),
        seed: value.opt_field_i64("seed").map_err(type_error)?,
        frequency_penalty: value.opt_field_f64("frequency_penalty").map_err(type_error)?,
        presence_penalty: value.opt_field_f64("presence_penalty").map_err(type_error)?,
        stop: parse_stop(value)?,
    };
    if let Err(param) = sampling.validate() {
        return Err(
            RouterError::invalid_request("a sampling parameter is out of range").with_param(param),
        );
    }
    Ok(sampling)
}

fn parse_stop(value: &Value) -> Result<Vec<String>, RouterError> {
    Ok(match value.get_present("stop") {
        None => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Some(_) => {
            return Err(
                RouterError::invalid_request("'stop' must be a string or an array of strings")
                    .with_param("stop"),
            );
        }
    })
}

fn parse_message(raw: &Value, index: usize) -> Result<Message, RouterError> {
    let role_text = raw.field_str("role").map_err(|_| {
        RouterError::invalid_request("each message requires a 'role'")
            .with_param(&format!("messages[{index}].role"))
    })?;
    let role = Role::parse(role_text).ok_or_else(|| {
        RouterError::invalid_request("unrecognised message role")
            .with_param(&format!("messages[{index}].role"))
    })?;

    let mut content = Vec::new();
    match raw.get_present("content") {
        None => {}
        Some(Value::String(text)) => content.push(ContentPart::Text(text.clone())),
        Some(Value::Array(parts)) => {
            for part in parts {
                content.push(parse_content_part(part, index)?);
            }
        }
        Some(_) => {
            return Err(RouterError::invalid_request(
                "message content must be a string or an array of parts",
            )
            .with_param(&format!("messages[{index}].content")));
        }
    }

    // A tool result message carries its call identifier alongside the content.
    if role == Role::Tool {
        let call_id = raw
            .opt_field_str("tool_call_id")
            .map_err(type_error)?
            .unwrap_or("");
        let text = content
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        content = vec![ContentPart::ToolResult {
            tool_call_id: call_id.to_owned(),
            content: text,
            is_error: false,
        }];
    }

    let mut tool_calls = Vec::new();
    if let Some(raw_calls) = raw.opt_field_array("tool_calls").map_err(type_error)? {
        for call in raw_calls {
            let function = call.get("function");
            tool_calls.push(ToolCall {
                id: call.opt_field_str("id").map_err(type_error)?.unwrap_or("").to_owned(),
                name: function
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                arguments: function
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
            });
        }
    }

    Ok(Message {
        role,
        content,
        name: raw.opt_field_str("name").map_err(type_error)?.map(str::to_owned),
        tool_calls,
    })
}

fn parse_content_part(part: &Value, message_index: usize) -> Result<ContentPart, RouterError> {
    let param = format!("messages[{message_index}].content");
    let kind = part
        .opt_field_str("type")
        .map_err(type_error)?
        .unwrap_or("text");

    Ok(match kind {
        "text" | "input_text" => ContentPart::Text(
            part.opt_field_str("text")
                .map_err(type_error)?
                .unwrap_or("")
                .to_owned(),
        ),
        "image_url" | "input_image" => {
            let url = part
                .get("image_url")
                .and_then(|o| o.get("url"))
                .and_then(|v| v.as_str())
                .or_else(|| part.get("image_url").and_then(|v| v.as_str()))
                .ok_or_else(|| {
                    RouterError::invalid_request("an image part requires a URL").with_param(&param)
                })?;
            // A `data:` URI is decomposed so the adapter can re-encode it in
            // whichever shape the provider expects. It is never fetched by the
            // router: specification 10 forbids user input selecting a
            // destination, and fetching a caller-supplied URL is exactly that.
            match parse_data_uri(url) {
                Some((media_type, base64_data)) => ContentPart::Image(ImageSource::Inline {
                    media_type,
                    base64_data,
                }),
                None => ContentPart::Image(ImageSource::Url(url.to_owned())),
            }
        }
        // A document. The router never decodes, parses, renders, or fetches
        // one; it records the declared media type — matched against a closed
        // allowlist — and forwards the bytes or the URL to a target that
        // declared the modality.
        "file" | "input_file" => parse_document_part(part, &param)?,
        "input_audio" => {
            let audio = part.get("input_audio").ok_or_else(|| {
                RouterError::invalid_request("an audio part requires 'input_audio'")
                    .with_param(&param)
            })?;
            ContentPart::Audio {
                format: audio
                    .opt_field_str("format")
                    .map_err(type_error)?
                    .unwrap_or("wav")
                    .to_owned(),
                base64_data: audio
                    .opt_field_str("data")
                    .map_err(type_error)?
                    .unwrap_or("")
                    .to_owned(),
            }
        }
        other => {
            return Err(
                RouterError::invalid_request(&format!("unsupported content part type '{other}'"))
                    .with_param(&param),
            );
        }
    })
}

/// Parse a `file` / `input_file` content part into a document.
///
/// Two shapes are accepted, matching the two OpenAI dialects: Chat Completions
/// nests the payload under `file`, and the Responses dialect carries it flat.
/// Both spell inline bytes as a `data:` URI and a remote document as a URL.
///
/// The media type comes from the `data:` URI, or from an explicit `media_type`
/// / `filename` extension for the URL form. An unrecognised type is refused:
/// the allowlist is what keeps "forward opaque bytes" from meaning "forward
/// anything".
fn parse_document_part(part: &Value, param: &str) -> Result<ContentPart, RouterError> {
    let file = part.get("file").unwrap_or(part);

    let declared = file
        .opt_field_str("media_type")
        .map_err(type_error)?
        .or(file.opt_field_str("mime_type").map_err(type_error)?);

    if let Some(data) = file
        .opt_field_str("file_data")
        .map_err(type_error)?
        .or(file.opt_field_str("data").map_err(type_error)?)
    {
        // Inline. The `data:` URI carries its own media type; a bare base64
        // payload needs `media_type` beside it.
        let (media_type, base64_data) = match parse_data_uri(data) {
            Some((declared_in_uri, payload)) => (declared_in_uri, payload),
            None => (
                declared
                    .ok_or_else(|| {
                        RouterError::invalid_request(
                            "an inline document requires a data: URI or an explicit media_type",
                        )
                        .with_param(param)
                    })?
                    .to_owned(),
                data.to_owned(),
            ),
        };
        let media_type = document_type(&media_type, param)?;
        return Ok(ContentPart::Document {
            media_type,
            source: DocumentSource::Inline { base64_data },
        });
    }

    if let Some(url) = file
        .opt_field_str("file_url")
        .map_err(type_error)?
        .or(file.opt_field_str("url").map_err(type_error)?)
    {
        let media_type = document_type(
            declared.ok_or_else(|| {
                // Without a declared type the router would have to look at the
                // document to know what it is, and looking is the one thing it
                // must not do. Guessing from a file extension would be a guess
                // the caller controls.
                RouterError::invalid_request(
                    "a document URL requires an explicit media_type; the router does not \
                     fetch or inspect the document to determine it",
                )
                .with_param(param)
            })?,
            param,
        )?;
        return Ok(ContentPart::Document {
            media_type,
            source: DocumentSource::Url(url.to_owned()),
        });
    }

    Err(
        RouterError::invalid_request("a document part requires file_data or file_url")
            .with_param(param),
    )
}

/// Match a declared media type against the closed allowlist.
fn document_type(raw: &str, param: &str) -> Result<DocumentType, RouterError> {
    DocumentType::parse(raw).ok_or_else(|| {
        // The caller's string is not echoed. It is attacker-controlled text
        // that would otherwise reach an error body and a log line.
        RouterError::invalid_request("that document media type is not supported")
            .with_param(param)
    })
}

/// Split a `data:` URI into its media type and base64 payload.
fn parse_data_uri(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    let media_type = meta.strip_suffix(";base64")?;
    if media_type.is_empty() {
        return None;
    }
    Some((media_type.to_owned(), payload.to_owned()))
}

fn parse_tool(raw: &Value, index: usize) -> Result<ToolDef, RouterError> {
    let param = format!("tools[{index}]");
    let function = raw.get("function").unwrap_or(raw);
    let name = function.field_str("name").map_err(|_| {
        RouterError::invalid_request("each tool requires a name").with_param(&param)
    })?;

    // The schema is carried as text so that the client's exact bytes reach the
    // provider. Re-serializing from a parsed value would reorder keys.
    let parameters_json = function
        .get("parameters")
        .map_or_else(|| "{}".to_owned(), to_string);

    Ok(ToolDef {
        name: name.to_owned(),
        description: function
            .opt_field_str("description")
            .map_err(type_error)?
            .map(str::to_owned),
        parameters_json,
        strict: function
            .opt_field_bool("strict")
            .map_err(type_error)?
            .unwrap_or(false),
    })
}

fn parse_tool_choice(value: &Value) -> Result<Option<ToolChoice>, RouterError> {
    Ok(match value.get_present("tool_choice") {
        None => None,
        Some(Value::String(s)) => Some(match s.as_str() {
            "auto" => ToolChoice::Auto,
            "none" => ToolChoice::None,
            "required" | "any" => ToolChoice::Required,
            other => {
                return Err(RouterError::invalid_request(&format!(
                    "unrecognised tool_choice '{other}'"
                ))
                .with_param("tool_choice"));
            }
        }),
        Some(object) => {
            let name = object
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RouterError::invalid_request("a tool_choice object requires a function name")
                        .with_param("tool_choice")
                })?;
            Some(ToolChoice::Function(name.to_owned()))
        }
    })
}

fn parse_response_format(value: &Value) -> Result<Option<ResponseFormat>, RouterError> {
    let Some(format) = value.get_present("response_format") else {
        return Ok(None);
    };
    let kind = format.field_str("type").map_err(|_| {
        RouterError::invalid_request("response_format requires a 'type'")
            .with_param("response_format")
    })?;

    Ok(Some(match kind {
        "text" => ResponseFormat::Text,
        "json_object" => ResponseFormat::JsonObject,
        "json_schema" => {
            let schema = format.get("json_schema").ok_or_else(|| {
                RouterError::invalid_request("a json_schema format requires 'json_schema'")
                    .with_param("response_format")
            })?;
            ResponseFormat::JsonSchema {
                name: schema
                    .opt_field_str("name")
                    .map_err(type_error)?
                    .unwrap_or("response")
                    .to_owned(),
                schema_json: schema.get("schema").map_or_else(|| "{}".to_owned(), to_string),
                strict: schema
                    .opt_field_bool("strict")
                    .map_err(type_error)?
                    .unwrap_or(false),
            }
        }
        other => {
            return Err(RouterError::invalid_request(&format!(
                "unsupported response_format type '{other}'"
            ))
            .with_param("response_format"));
        }
    }))
}

// -- Responses request parsing ----------------------------------------------

/// Parse one entry of a Responses `input` array into a canonical message.
///
/// The array is not a message list: alongside `message` items it carries the
/// `function_call` and `function_call_output` items that make a tool round trip
/// replayable. All three become canonical messages, because that is the one
/// shape the router routes on.
fn parse_input_item(raw: &Value, index: usize) -> Result<Message, RouterError> {
    let param = format!("input[{index}]");

    // A bare string in the array is the same shorthand as a bare string body.
    if let Value::String(text) = raw {
        return Ok(Message::text(Role::User, text.as_str()));
    }

    // An item without an explicit type but with a role is a message; that is
    // the form every harness sends for plain conversation.
    let kind = match raw.opt_field_str("type").map_err(type_error)? {
        Some(kind) => kind,
        None if raw.get("role").is_some() => "message",
        None => {
            return Err(
                RouterError::invalid_request("each input item requires a 'type' or a 'role'")
                    .with_param(&param),
            );
        }
    };

    match kind {
        "message" => parse_input_message(raw, &param),
        "function_call" => {
            // The model's own call, replayed by the client on the next turn.
            let mut message = Message {
                role: Role::Assistant,
                content: Vec::new(),
                name: None,
                tool_calls: Vec::new(),
            };
            message.tool_calls.push(ToolCall {
                // `call_id` is the identifier the matching output refers to;
                // `id` names the output item and is not the correlation key.
                id: raw
                    .opt_field_str("call_id")
                    .map_err(type_error)?
                    .or(raw.opt_field_str("id").map_err(type_error)?)
                    .unwrap_or("")
                    .to_owned(),
                name: raw.opt_field_str("name").map_err(type_error)?.unwrap_or("").to_owned(),
                arguments: raw
                    .opt_field_str("arguments")
                    .map_err(type_error)?
                    .unwrap_or("")
                    .to_owned(),
            });
            Ok(message)
        }
        "function_call_output" => Ok(Message {
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                tool_call_id: raw
                    .opt_field_str("call_id")
                    .map_err(type_error)?
                    .unwrap_or("")
                    .to_owned(),
                content: match raw.get_present("output") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => to_string(other),
                    None => String::new(),
                },
                is_error: false,
            }],
            name: None,
            tool_calls: Vec::new(),
        }),
        other => Err(RouterError::invalid_request(&format!(
            "unsupported input item type '{other}'"
        ))
        .with_param(&param)),
    }
}

fn parse_input_message(raw: &Value, param: &str) -> Result<Message, RouterError> {
    let role_text = raw.field_str("role").map_err(|_| {
        RouterError::invalid_request("each input message requires a 'role'")
            .with_param(&format!("{param}.role"))
    })?;
    let role = Role::parse(role_text).ok_or_else(|| {
        RouterError::invalid_request("unrecognised message role")
            .with_param(&format!("{param}.role"))
    })?;

    let content_param = format!("{param}.content");
    let mut content = Vec::new();
    match raw.get_present("content") {
        None => {}
        Some(Value::String(text)) => content.push(ContentPart::Text(text.clone())),
        Some(Value::Array(parts)) => {
            for part in parts {
                content.push(parse_responses_content_part(part, &content_param)?);
            }
        }
        Some(_) => {
            return Err(RouterError::invalid_request(
                "input message content must be a string or an array of parts",
            )
            .with_param(&content_param));
        }
    }

    Ok(Message {
        role,
        content,
        name: raw.opt_field_str("name").map_err(type_error)?.map(str::to_owned),
        tool_calls: Vec::new(),
    })
}

/// Parse one Responses content part.
///
/// The Responses dialect spells its parts `input_text`/`input_image` on the way
/// in and `output_text` on the way back — a replayed assistant turn therefore
/// carries `output_text`. An unrecognised part is rejected rather than skipped:
/// a dropped image is a request the caller believes they sent.
fn parse_responses_content_part(part: &Value, param: &str) -> Result<ContentPart, RouterError> {
    let kind = part.opt_field_str("type").map_err(type_error)?.unwrap_or("input_text");

    Ok(match kind {
        "input_text" | "output_text" | "text" => ContentPart::Text(
            part.opt_field_str("text")
                .map_err(type_error)?
                .unwrap_or("")
                .to_owned(),
        ),
        "input_image" => {
            // `image_url` is a plain string here, not the nested object the
            // Chat dialect uses; the nested form is accepted too because
            // harnesses that share one encoder emit it.
            let url = part
                .opt_field_str("image_url")
                .map_err(type_error)?
                .or_else(|| {
                    part.get("image_url")
                        .and_then(|o| o.get("url"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| {
                    RouterError::invalid_request("an input_image part requires 'image_url'")
                        .with_param(param)
                })?;
            // Never fetched by the router: specification 10 forbids a caller
            // value selecting a destination, and dereferencing this would be
            // exactly that. A `data:` URI is decomposed so the adapter can
            // re-encode it for whichever provider was selected.
            match parse_data_uri(url) {
                Some((media_type, base64_data)) => ContentPart::Image(ImageSource::Inline {
                    media_type,
                    base64_data,
                }),
                None => ContentPart::Image(ImageSource::Url(url.to_owned())),
            }
        }
        // A document. The router never decodes, parses, renders, or fetches
        // one; it records the declared media type — matched against a closed
        // allowlist — and forwards the bytes or the URL to a target that
        // declared the modality.
        "file" | "input_file" => parse_document_part(part, &param)?,
        "input_audio" => {
            let audio = part.get("input_audio").unwrap_or(part);
            ContentPart::Audio {
                format: audio
                    .opt_field_str("format")
                    .map_err(type_error)?
                    .unwrap_or("wav")
                    .to_owned(),
                base64_data: audio
                    .opt_field_str("data")
                    .map_err(type_error)?
                    .unwrap_or("")
                    .to_owned(),
            }
        }
        other => {
            return Err(RouterError::invalid_request(&format!(
                "unsupported content part type '{other}'"
            ))
            .with_param(param));
        }
    })
}

/// Parse a Responses tool definition.
///
/// A tool is flat here — `{type, name, description, parameters}` — rather than
/// nested under a `function` key. The built-in provider-hosted tools (web
/// search, file search, computer use) are rejected: the router cannot honour a
/// capability it does not implement, and accepting one silently would return a
/// model that never calls it.
fn parse_responses_tool(raw: &Value, index: usize) -> Result<ToolDef, RouterError> {
    let param = format!("tools[{index}]");
    let kind = raw.opt_field_str("type").map_err(type_error)?.unwrap_or("function");
    if kind != "function" {
        return Err(RouterError::invalid_request(&format!(
            "unsupported tool type '{kind}': only function tools are supported"
        ))
        .with_param(&param));
    }

    let name = raw.field_str("name").map_err(|_| {
        RouterError::invalid_request("each tool requires a name").with_param(&param)
    })?;

    Ok(ToolDef {
        name: name.to_owned(),
        description: raw
            .opt_field_str("description")
            .map_err(type_error)?
            .map(str::to_owned),
        // Carried as text so the caller's exact schema bytes reach the
        // provider; re-serializing a parsed value would reorder its keys.
        parameters_json: raw.get("parameters").map_or_else(|| "{}".to_owned(), to_string),
        strict: raw.opt_field_bool("strict").map_err(type_error)?.unwrap_or(false),
    })
}

/// Parse a Responses `tool_choice`, whose object form is flat.
fn parse_responses_tool_choice(value: &Value) -> Result<Option<ToolChoice>, RouterError> {
    Ok(match value.get_present("tool_choice") {
        None => None,
        Some(Value::String(s)) => Some(match s.as_str() {
            "auto" => ToolChoice::Auto,
            "none" => ToolChoice::None,
            "required" => ToolChoice::Required,
            other => {
                return Err(RouterError::invalid_request(&format!(
                    "unrecognised tool_choice '{other}'"
                ))
                .with_param("tool_choice"));
            }
        }),
        Some(object) => {
            let kind = object.opt_field_str("type").map_err(type_error)?.unwrap_or("function");
            if kind != "function" {
                return Err(RouterError::invalid_request(&format!(
                    "unsupported tool_choice type '{kind}'"
                ))
                .with_param("tool_choice"));
            }
            let name = object
                .opt_field_str("name")
                .map_err(type_error)?
                .or_else(|| {
                    object
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| {
                    RouterError::invalid_request("a tool_choice object requires a function name")
                        .with_param("tool_choice")
                })?;
            Some(ToolChoice::Function(name.to_owned()))
        }
    })
}

/// Parse `text.format`, the Responses spelling of `response_format`.
///
/// The schema form is flat here: `{type, name, schema, strict}` rather than the
/// Chat dialect's extra `json_schema` wrapper.
fn parse_text_format(value: &Value) -> Result<Option<ResponseFormat>, RouterError> {
    let Some(format) = value
        .get_present("text")
        .and_then(|text| text.get_present("format"))
    else {
        return Ok(None);
    };
    let kind = format.field_str("type").map_err(|_| {
        RouterError::invalid_request("text.format requires a 'type'").with_param("text.format")
    })?;

    Ok(Some(match kind {
        "text" => ResponseFormat::Text,
        "json_object" => ResponseFormat::JsonObject,
        "json_schema" => ResponseFormat::JsonSchema {
            name: format
                .opt_field_str("name")
                .map_err(type_error)?
                .unwrap_or("response")
                .to_owned(),
            schema_json: format.get("schema").map_or_else(|| "{}".to_owned(), to_string),
            strict: format.opt_field_bool("strict").map_err(type_error)?.unwrap_or(false),
        },
        other => {
            return Err(RouterError::invalid_request(&format!(
                "unsupported text.format type '{other}'"
            ))
            .with_param("text.format"));
        }
    }))
}

/// Parse the allowlisted routing hints.
///
/// Specification 5.1: "Optional allowlisted hints; **ignored or rejected unless
/// principal has permission**." A principal without the permission gets its
/// hints dropped silently rather than rejected, so a harness that always sends
/// them still works — but they have no effect.
/// The object routing hints are carried in.
///
/// One constant rather than a literal at each site, because a test that plants
/// hints under a *different* key than the parser reads asserts nothing while
/// appearing to assert everything — which is exactly what the fuzz target
/// `a_hint_is_ignored_unless_the_principal_may_supply_one` did before this
/// existed. Its three cases all returned early on the key lookup and never
/// reached the permission gate, so the target would have passed with the gate
/// deleted.
pub const HINTS_KEY: &str = "hypellm_routing";

pub(crate) fn parse_hints(
    value: &Value,
    context: &ParseContext,
) -> Result<RoutingHints, RouterError> {
    // The permission gate comes first, so that "the principal may not supply
    // hints" is decided before anything about the payload can change the
    // outcome. Ordering it second made the gate unreachable for any body that
    // omitted the key, which is every body a test wrote under the wrong one.
    if !context.hints_permitted {
        return Ok(RoutingHints::default());
    }
    let Some(raw) = value.get_present(HINTS_KEY) else {
        return Ok(RoutingHints::default());
    };

    let prefer_target = raw
        .opt_field_str("prefer_target")
        .map_err(type_error)?
        .map(|t| {
            hypellm_core::ids::TargetId::new(t).map_err(|_| {
                RouterError::invalid_request("prefer_target is not a valid target identifier")
                    .with_param("hypellm_routing.prefer_target")
            })
        })
        .transpose()?;

    Ok(RoutingHints {
        prefer_target,
        require_local: raw
            .opt_field_bool("require_local")
            .map_err(type_error)?
            .unwrap_or(false),
        idempotency_key: raw
            .opt_field_str("idempotency_key")
            .map_err(type_error)?
            .map(str::to_owned),
    })
}

// -- Rendering --------------------------------------------------------------

/// Render a complete, non-streaming chat completion response.
#[must_use]
pub fn render_chat_response(
    request: &CanonicalRequest,
    accumulator: &ResponseAccumulator,
    created_secs: u64,
) -> String {
    let mut message = Object::new();
    message.push("role", Value::from("assistant"));
    // `content` is always present, as null when the turn was tool calls only.
    // Omitting it breaks clients that index the field unconditionally.
    if accumulator.text.is_empty() && !accumulator.tool_calls.is_empty() {
        message.push("content", Value::Null);
    } else {
        message.push("content", Value::from(accumulator.text.as_str()));
    }

    let calls = accumulator.sorted_tool_calls();
    if !calls.is_empty() {
        let rendered: Vec<Value> = calls
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
        message.push("tool_calls", Value::Array(rendered));
    }

    let mut choice = Object::new();
    choice.push("index", Value::from(0i64));
    choice.push("message", Value::Object(message));
    choice.push(
        "finish_reason",
        Value::from(
            accumulator
                .finish
                .unwrap_or(FinishReason::Stop)
                .openai_str(),
        ),
    );

    let mut root = Object::new();
    root.push(
        "id",
        Value::from(format!("chatcmpl-{}", request.request_id)),
    );
    root.push("object", Value::from("chat.completion"));
    root.push("created", Value::from(created_secs));
    root.push(
        "model",
        Value::from(request.requested_model.as_str()),
    );
    root.push("choices", Value::Array(vec![Value::Object(choice)]));
    root.push("usage", render_usage(accumulator));
    root.push(
        "hypellm",
        render_metadata(
            accumulator.native_model.as_deref(),
            accumulator.upstream_id.as_deref(),
        ),
    );
    to_string(&Value::Object(root))
}

/// Render an embeddings response.
#[must_use]
pub fn render_embeddings_response(
    request: &CanonicalRequest,
    accumulator: &ResponseAccumulator,
) -> String {
    let data: Vec<Value> = accumulator
        .embeddings
        .iter()
        .map(|(index, values)| {
            let mut item = Object::new();
            item.push("object", Value::from("embedding"));
            item.push("index", Value::from(u64::from(*index)));
            item.push(
                "embedding",
                Value::Array(values.iter().map(|v| Value::from(f64::from(*v))).collect()),
            );
            Value::Object(item)
        })
        .collect();

    let mut root = Object::new();
    root.push("object", Value::from("list"));
    root.push("data", Value::Array(data));
    root.push("model", Value::from(request.requested_model.as_str()));
    root.push("usage", render_usage(accumulator));
    to_string(&Value::Object(root))
}

fn render_usage(accumulator: &ResponseAccumulator) -> Value {
    let usage = accumulator.usage.unwrap_or_default();
    let mut object = Object::new();
    object.push("prompt_tokens", Value::from(usage.input_tokens));
    object.push("completion_tokens", Value::from(usage.output_tokens));
    object.push("total_tokens", Value::from(usage.total()));
    // Specification 14: usage is marked provider-reported or router-estimated.
    // The flag lives under the router's own namespace so it cannot collide with
    // a future upstream field.
    let mut hypellm = Object::new();
    hypellm.push("usage_source", Value::from(usage.source.as_str()));
    object.push("hypellm", Value::Object(hypellm));
    Value::Object(object)
}

/// Router metadata attached to a response.
///
/// Specification 6.5: a model-family change "must be … visible in response
/// metadata when the protocol permits". The native model the request actually
/// reached is reported here, alongside the alias the caller asked for.
fn render_metadata(native_model: Option<&str>, upstream_id: Option<&str>) -> Value {
    let mut object = Object::new();
    object.push_opt("native_model", native_model.map(Value::from));
    object.push_opt("upstream_id", upstream_id.map(Value::from));
    Value::Object(object)
}

/// Render one streaming chunk for a canonical event.
///
/// Returns `None` for an event with no representation in this protocol.
#[must_use]
pub fn render_chat_chunk(
    request: &CanonicalRequest,
    event: &CanonicalEvent,
    created_secs: u64,
) -> Option<String> {
    let mut delta = Object::new();
    let mut finish: Option<FinishReason> = None;
    let mut usage: Option<Value> = None;

    match event {
        CanonicalEvent::Start { .. } => {
            // The first chunk announces the assistant role, which several
            // client SDKs require before any content.
            delta.push("role", Value::from("assistant"));
        }
        CanonicalEvent::TextDelta(text) => delta.push("content", Value::from(text.as_str())),
        CanonicalEvent::ReasoningDelta(text) => {
            delta.push("reasoning_content", Value::from(text.as_str()));
        }
        CanonicalEvent::ToolCallDelta(call) => {
            let mut function = Object::new();
            function.push_opt("name", call.name.as_deref().map(Value::from));
            if !call.arguments_delta.is_empty() {
                function.push("arguments", Value::from(call.arguments_delta.as_str()));
            }
            let mut wrapper = Object::new();
            wrapper.push("index", Value::from(u64::from(call.index)));
            wrapper.push_opt("id", call.id.as_deref().map(Value::from));
            if call.id.is_some() {
                wrapper.push("type", Value::from("function"));
            }
            wrapper.push("function", Value::Object(function));
            delta.push("tool_calls", Value::Array(vec![Value::Object(wrapper)]));
        }
        CanonicalEvent::Finish { reason } => finish = Some(*reason),
        CanonicalEvent::Usage(u) => {
            let mut object = Object::new();
            object.push("prompt_tokens", Value::from(u.input_tokens));
            object.push("completion_tokens", Value::from(u.output_tokens));
            object.push("total_tokens", Value::from(u.total()));
            let mut hypellm = Object::new();
            hypellm.push("usage_source", Value::from(u.source.as_str()));
            object.push("hypellm", Value::Object(hypellm));
            usage = Some(Value::Object(object));
        }
        // Embeddings do not stream, and an error is rendered by the caller as
        // a terminal error event.
        CanonicalEvent::Embedding { .. } | CanonicalEvent::Error(_) => return None,
    }

    let mut choice = Object::new();
    choice.push("index", Value::from(0i64));
    choice.push("delta", Value::Object(delta));
    choice.push(
        "finish_reason",
        finish.map_or(Value::Null, |r| Value::from(r.openai_str())),
    );

    let mut root = Object::new();
    root.push("id", Value::from(format!("chatcmpl-{}", request.request_id)));
    root.push("object", Value::from("chat.completion.chunk"));
    root.push("created", Value::from(created_secs));
    root.push("model", Value::from(request.requested_model.as_str()));
    root.push("choices", Value::Array(vec![Value::Object(choice)]));
    root.push_opt("usage", usage);
    Some(to_string(&Value::Object(root)))
}

// -- Responses rendering ----------------------------------------------------
//
// The Responses dialect is not Chat Completions with different field names. Its
// body reports an **array of typed output items** rather than `choices`, a
// `status` rather than a `finish_reason`, and `input_tokens`/`output_tokens`
// rather than `prompt_tokens`/`completion_tokens`. Its stream is a sequence of
// *named* events whose order is a state machine — a text delta is only legal
// after the item and the content part that hold it have been opened — and it
// has **no `[DONE]` sentinel**: the terminal frame is `response.completed`,
// `response.incomplete`, or `response.failed`.
//
// [`ResponsesStreamState`] owns that sequence for the same reason the Anthropic
// renderer owns its own: the listener emits canonical events, and the frame
// discipline lives in one place where it cannot be got wrong per call site.

/// A rendered Responses stream frame: an SSE event name and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The SSE event name.
    pub event: String,
    /// The JSON payload.
    pub data: String,
}

/// Build one frame, whose payload always repeats the event name in `type`.
fn frame(event: &'static str, fields: Vec<(&'static str, Value)>) -> Frame {
    let mut object = Object::with_capacity(fields.len().saturating_add(1));
    object.push("type", Value::from(event));
    for (key, value) in fields {
        object.push(key, value);
    }
    Frame {
        event: event.to_owned(),
        data: to_string(&Value::Object(object)),
    }
}

/// The lifecycle status of a response.
///
/// This dialect has no `finish_reason`: completion is the status, and a
/// truncation reason appears separately in `incomplete_details`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseStatus {
    /// The response shell, before any output.
    InProgress,
    /// The model finished.
    Completed,
    /// Generation stopped early, with a reason where there is one to give.
    Incomplete(Option<&'static str>),
    /// The response failed.
    Failed,
}

impl ResponseStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Incomplete(_) => "incomplete",
            Self::Failed => "failed",
        }
    }

    /// The named event that carries a response in this status.
    const fn terminal_event(self) -> &'static str {
        match self {
            // A stream that reaches its end without a finish reason is
            // reported as complete, which is what the client observed.
            Self::InProgress | Self::Completed => "response.completed",
            Self::Incomplete(_) => "response.incomplete",
            Self::Failed => "response.failed",
        }
    }
}

/// Map a canonical outcome onto a response status.
///
/// Matched exhaustively and deliberately without a catch-all arm: the failure
/// this guards against is a new [`FinishReason`] variant silently acquiring the
/// most flattering status. A future reason must be classified here by whoever
/// adds it, and the compiler is what makes that happen.
fn status_for(error: Option<&RouterError>, finish: Option<FinishReason>) -> ResponseStatus {
    if error.is_some() {
        return ResponseStatus::Failed;
    }
    let Some(finish) = finish else {
        // No reason was ever reported; the stream simply ended, which is what
        // the client observed.
        return ResponseStatus::Completed;
    };
    match finish {
        FinishReason::Length => ResponseStatus::Incomplete(Some("max_output_tokens")),
        FinishReason::ContentFilter => ResponseStatus::Incomplete(Some("content_filter")),
        FinishReason::Error => ResponseStatus::Failed,
        // A cancelled turn did not finish. Reporting `completed` would tell the
        // caller the model was done when the router knows it was not, and this
        // dialect — unlike Chat Completions, whose only honest spelling is
        // `stop` — has a status that says so.
        FinishReason::Cancelled => ResponseStatus::Incomplete(None),
        // Neither did a turn whose stop reason the router could not read. The
        // adapter reports [`FinishReason::Unrecognized`] precisely so that an
        // unknown provider status is not laundered into a natural finish; a
        // catch-all arm here undid that one layer later, which is the whole
        // reason the variant exists. Chat Completions has to spell this `stop`
        // because its schema offers nothing better, but this dialect does not,
        // and no reason is claimed because the router has none to give.
        FinishReason::Unrecognized => ResponseStatus::Incomplete(None),
        // The Responses API reports `completed` for a turn that stopped to wait
        // for tool results: the response itself is complete, and the outstanding
        // work is visible as a `function_call` item in `output`.
        FinishReason::Stop | FinishReason::ToolCalls => ResponseStatus::Completed,
    }
}

/// The kind of item in a Responses `output` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    /// Reasoning, reported as a summary.
    Reasoning,
    /// An assistant message.
    Message,
    /// A tool call.
    FunctionCall,
}

impl ItemKind {
    const fn id_prefix(self) -> &'static str {
        match self {
            Self::Reasoning => "rs",
            Self::Message => "msg",
            Self::FunctionCall => "fc",
        }
    }
}

/// One entry of the `output` array, in the router's own terms.
#[derive(Debug, Clone)]
struct OutputItem {
    kind: ItemKind,
    /// The item identifier the stream frames refer to.
    id: String,
    /// Message or reasoning text, or the JSON arguments of a function call.
    text: String,
    /// The tool name, for a function call.
    name: String,
    /// The call identifier a tool result will refer back to.
    call_id: String,
}

impl OutputItem {
    fn new(request: &CanonicalRequest, kind: ItemKind, output_index: u32) -> Self {
        Self {
            kind,
            // Derived from the request identifier so that the identifiers in a
            // response are deterministic and correlate with its trace.
            id: format!("{}_{}_{}", kind.id_prefix(), request.request_id, output_index),
            text: String::new(),
            name: String::new(),
            call_id: String::new(),
        }
    }
}

/// The response-level facts reported outside `output`.
struct ResponseFacts<'a> {
    status: ResponseStatus,
    usage: Option<hypellm_core::event::CanonicalUsage>,
    native_model: Option<&'a str>,
    upstream_id: Option<&'a str>,
    error: Option<&'a RouterError>,
}

impl<'a> ResponseFacts<'a> {
    fn from_accumulator(accumulator: &'a ResponseAccumulator) -> Self {
        Self {
            status: status_for(accumulator.error.as_ref(), accumulator.finish),
            usage: accumulator.usage,
            native_model: accumulator.native_model.as_deref(),
            upstream_id: accumulator.upstream_id.as_deref(),
            error: accumulator.error.as_ref(),
        }
    }
}

fn output_text_part(text: &str) -> Value {
    let mut part = Object::new();
    part.push("type", Value::from("output_text"));
    part.push("text", Value::from(text));
    // Always present, as an empty array: clients iterate it unconditionally.
    part.push("annotations", Value::Array(Vec::new()));
    Value::Object(part)
}

fn summary_text_part(text: &str) -> Value {
    let mut part = Object::new();
    part.push("type", Value::from("summary_text"));
    part.push("text", Value::from(text));
    Value::Object(part)
}

/// Render one output item.
///
/// `with_content` distinguishes the shell announced by
/// `response.output_item.added` — which carries no content yet — from the
/// complete item reported by `response.output_item.done` and by the body.
fn render_output_item(item: &OutputItem, status: &'static str, with_content: bool) -> Value {
    let mut object = Object::new();
    match item.kind {
        ItemKind::Message => {
            object.push("type", Value::from("message"));
            object.push("id", Value::from(item.id.as_str()));
            object.push("status", Value::from(status));
            object.push("role", Value::from("assistant"));
            object.push(
                "content",
                Value::Array(if with_content {
                    vec![output_text_part(&item.text)]
                } else {
                    Vec::new()
                }),
            );
        }
        ItemKind::Reasoning => {
            object.push("type", Value::from("reasoning"));
            object.push("id", Value::from(item.id.as_str()));
            object.push("status", Value::from(status));
            object.push(
                "summary",
                Value::Array(if with_content {
                    vec![summary_text_part(&item.text)]
                } else {
                    Vec::new()
                }),
            );
        }
        ItemKind::FunctionCall => {
            object.push("type", Value::from("function_call"));
            object.push("id", Value::from(item.id.as_str()));
            object.push("status", Value::from(status));
            object.push("call_id", Value::from(item.call_id.as_str()));
            object.push("name", Value::from(item.name.as_str()));
            object.push(
                "arguments",
                Value::from(if with_content { item.text.as_str() } else { "" }),
            );
        }
    }
    Value::Object(object)
}

/// The output items of a completed response, in emission order.
fn output_items(request: &CanonicalRequest, accumulator: &ResponseAccumulator) -> Vec<OutputItem> {
    let mut items = Vec::new();
    let mut index: u32 = 0;

    let mut push = |kind: ItemKind, text: &str, name: &str, call_id: &str| {
        let mut item = OutputItem::new(request, kind, index);
        item.text = text.to_owned();
        item.name = name.to_owned();
        item.call_id = call_id.to_owned();
        items.push(item);
        index = index.saturating_add(1);
    };

    if !accumulator.reasoning.is_empty() {
        push(ItemKind::Reasoning, &accumulator.reasoning, "", "");
    }
    let calls = accumulator.sorted_tool_calls();
    // A turn that produced only tool calls has no message item at all — this
    // dialect omits the item rather than carrying an empty one, which is the
    // counterpart of the Chat renderer's null `content`.
    if !accumulator.text.is_empty() || calls.is_empty() {
        push(ItemKind::Message, &accumulator.text, "", "");
    }
    for call in &calls {
        push(
            ItemKind::FunctionCall,
            &call.arguments,
            &call.name,
            &call.id,
        );
    }
    items
}

fn render_responses_usage(usage: Option<hypellm_core::event::CanonicalUsage>) -> Value {
    let usage = usage.unwrap_or_default();
    let mut object = Object::new();
    object.push("input_tokens", Value::from(usage.input_tokens));
    object.push("output_tokens", Value::from(usage.output_tokens));
    object.push("total_tokens", Value::from(usage.total()));
    // Specification 14: usage carries its provenance, under the router's own
    // namespace so it cannot collide with a future upstream field.
    let mut hypellm = Object::new();
    hypellm.push("usage_source", Value::from(usage.source.as_str()));
    object.push("hypellm", Value::Object(hypellm));
    Value::Object(object)
}

/// Build the `response` object shared by the body and every lifecycle frame.
fn response_object(
    request: &CanonicalRequest,
    facts: &ResponseFacts<'_>,
    items: &[OutputItem],
    created_secs: u64,
) -> Value {
    let mut root = Object::new();
    root.push("id", Value::from(format!("resp_{}", request.request_id)));
    root.push("object", Value::from("response"));
    root.push("created_at", Value::from(created_secs));
    root.push("status", Value::from(facts.status.as_str()));
    // The client-visible alias, never the provider's native model name: the
    // caller asked for the alias, and specification 6.5 puts the model actually
    // reached in the router's own metadata instead.
    root.push("model", Value::from(request.requested_model.as_str()));
    root.push(
        "output",
        Value::Array(
            items
                .iter()
                .map(|item| render_output_item(item, "completed", true))
                .collect(),
        ),
    );
    root.push(
        "incomplete_details",
        match facts.status {
            ResponseStatus::Incomplete(Some(reason)) => {
                let mut details = Object::new();
                details.push("reason", Value::from(reason));
                Value::Object(details)
            }
            _ => Value::Null,
        },
    );
    root.push(
        "error",
        facts.error.map_or(Value::Null, |error| {
            let mut object = Object::new();
            object.push("code", Value::from(error.code.as_str()));
            object.push("message", Value::from(error.detail.as_str()));
            Value::Object(object)
        }),
    );
    root.push(
        "usage",
        // The shell announced by `response.created` has no numbers yet, and
        // reporting zeros there would be a measurement the router never made.
        if facts.status == ResponseStatus::InProgress {
            Value::Null
        } else {
            render_responses_usage(facts.usage)
        },
    );
    root.push(
        "hypellm",
        render_metadata(facts.native_model, facts.upstream_id),
    );
    Value::Object(root)
}

/// Render a complete, non-streaming Responses body.
#[must_use]
pub fn render_responses_response(
    request: &CanonicalRequest,
    accumulator: &ResponseAccumulator,
    created_secs: u64,
) -> String {
    let items = output_items(request, accumulator);
    let facts = ResponseFacts::from_accumulator(accumulator);
    to_string(&response_object(request, &facts, &items, created_secs))
}

/// The item currently open in a Responses stream.
#[derive(Debug)]
struct OpenItem {
    item: OutputItem,
    output_index: u32,
    /// The canonical tool-call index this function-call item carries, so that
    /// two interleaved calls cannot be folded into one item.
    tool_index: u32,
    /// Whether a content part (or reasoning summary part) has been opened.
    part_open: bool,
}

/// The state a Responses stream carries between events.
///
/// `response.output_text.delta` is only legal after `response.output_item.added`
/// and `response.content_part.added` for the item it belongs to, and every
/// opened item must be closed before the terminal frame. Holding that here
/// means a canonical event sequence cannot produce a frame order a client
/// state machine rejects.
///
/// The completed text is retained because the dialect requires it: the `.done`
/// frames and the terminal `response.completed` restate the whole output. The
/// retention is bounded by the output-token ceiling admission already enforced,
/// and frames are still written as they are produced — nothing is delayed.
#[derive(Debug, Default)]
pub struct ResponsesStreamState {
    created: bool,
    /// Whether a finish reason has been seen, after which no further output
    /// item may be opened.
    content_closed: bool,
    /// Whether the terminal frame has been emitted, after which nothing at all
    /// may follow.
    stopped: bool,
    next_index: u32,
    open: Option<OpenItem>,
    items: Vec<OutputItem>,
    usage: Option<hypellm_core::event::CanonicalUsage>,
    finish: Option<FinishReason>,
    upstream_id: Option<String>,
    native_model: Option<String>,
}

impl ResponsesStreamState {
    /// A state at the start of a stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `response.created` has been emitted.
    #[must_use]
    pub const fn has_started(&self) -> bool {
        self.created
    }

    fn facts(&self, status: ResponseStatus) -> ResponseFacts<'_> {
        ResponseFacts {
            status,
            usage: self.usage,
            native_model: self.native_model.as_deref(),
            upstream_id: self.upstream_id.as_deref(),
            error: None,
        }
    }

    fn ensure_created(
        &mut self,
        request: &CanonicalRequest,
        created_secs: u64,
        frames: &mut Vec<Frame>,
    ) {
        if self.created {
            return;
        }
        self.created = true;
        let facts = self.facts(ResponseStatus::InProgress);
        frames.push(frame(
            "response.created",
            vec![("response", response_object(request, &facts, &[], created_secs))],
        ));
    }

    /// Open the item this event belongs to, reusing the open one when it is
    /// already the right item. Returns its identifier and output index.
    fn ensure_item(
        &mut self,
        request: &CanonicalRequest,
        kind: ItemKind,
        tool_index: u32,
        name: Option<&str>,
        call_id: Option<&str>,
        frames: &mut Vec<Frame>,
    ) -> (String, u32) {
        if let Some(open) = &self.open {
            let same_call = kind != ItemKind::FunctionCall || open.tool_index == tool_index;
            if open.item.kind == kind && same_call {
                return (open.item.id.clone(), open.output_index);
            }
        }
        self.close_open(frames);

        let output_index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        let mut item = OutputItem::new(request, kind, output_index);
        if let Some(name) = name {
            item.name = name.to_owned();
        }
        if let Some(call_id) = call_id {
            item.call_id = call_id.to_owned();
        }

        frames.push(frame(
            "response.output_item.added",
            vec![
                ("output_index", Value::from(u64::from(output_index))),
                ("item", render_output_item(&item, "in_progress", false)),
            ],
        ));

        let item_id = Value::from(item.id.as_str());
        let index_value = Value::from(u64::from(output_index));
        let part_open = match kind {
            ItemKind::Message => {
                frames.push(frame(
                    "response.content_part.added",
                    vec![
                        ("item_id", item_id),
                        ("output_index", index_value),
                        ("content_index", Value::from(0i64)),
                        ("part", output_text_part("")),
                    ],
                ));
                true
            }
            ItemKind::Reasoning => {
                frames.push(frame(
                    "response.reasoning_summary_part.added",
                    vec![
                        ("item_id", item_id),
                        ("output_index", index_value),
                        ("summary_index", Value::from(0i64)),
                        ("part", summary_text_part("")),
                    ],
                ));
                true
            }
            // A function call streams its arguments directly against the item;
            // it has no content part to open.
            ItemKind::FunctionCall => false,
        };

        let id = item.id.clone();
        self.open = Some(OpenItem {
            item,
            output_index,
            tool_index,
            part_open,
        });
        (id, output_index)
    }

    fn close_open(&mut self, frames: &mut Vec<Frame>) {
        let Some(open) = self.open.take() else {
            return;
        };
        let item_id = Value::from(open.item.id.as_str());
        let index_value = Value::from(u64::from(open.output_index));

        match open.item.kind {
            ItemKind::Message => {
                if open.part_open {
                    frames.push(frame(
                        "response.output_text.done",
                        vec![
                            ("item_id", item_id.clone()),
                            ("output_index", index_value.clone()),
                            ("content_index", Value::from(0i64)),
                            ("text", Value::from(open.item.text.as_str())),
                        ],
                    ));
                    frames.push(frame(
                        "response.content_part.done",
                        vec![
                            ("item_id", item_id),
                            ("output_index", index_value.clone()),
                            ("content_index", Value::from(0i64)),
                            ("part", output_text_part(&open.item.text)),
                        ],
                    ));
                }
            }
            ItemKind::Reasoning => {
                if open.part_open {
                    frames.push(frame(
                        "response.reasoning_summary_text.done",
                        vec![
                            ("item_id", item_id.clone()),
                            ("output_index", index_value.clone()),
                            ("summary_index", Value::from(0i64)),
                            ("text", Value::from(open.item.text.as_str())),
                        ],
                    ));
                    frames.push(frame(
                        "response.reasoning_summary_part.done",
                        vec![
                            ("item_id", item_id),
                            ("output_index", index_value.clone()),
                            ("summary_index", Value::from(0i64)),
                            ("part", summary_text_part(&open.item.text)),
                        ],
                    ));
                }
            }
            ItemKind::FunctionCall => {
                frames.push(frame(
                    "response.function_call_arguments.done",
                    vec![
                        ("item_id", item_id),
                        ("output_index", index_value.clone()),
                        ("arguments", Value::from(open.item.text.as_str())),
                    ],
                ));
            }
        }

        frames.push(frame(
            "response.output_item.done",
            vec![
                ("output_index", index_value),
                ("item", render_output_item(&open.item, "completed", true)),
            ],
        ));
        self.items.push(open.item);
    }

    fn terminal(&self, request: &CanonicalRequest, created_secs: u64) -> Frame {
        let status = status_for(None, self.finish);
        let facts = self.facts(status);
        frame(
            status.terminal_event(),
            vec![(
                "response",
                response_object(request, &facts, &self.items, created_secs),
            )],
        )
    }

    /// Render the frames for one canonical event.
    fn render(
        &mut self,
        request: &CanonicalRequest,
        event: &CanonicalEvent,
        created_secs: u64,
    ) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.stopped {
            return frames;
        }

        match event {
            CanonicalEvent::Start {
                upstream_id,
                native_model,
            } => {
                if self.upstream_id.is_none() {
                    self.upstream_id.clone_from(upstream_id);
                }
                if self.native_model.is_none() {
                    self.native_model.clone_from(native_model);
                }
                self.ensure_created(request, created_secs, &mut frames);
            }
            CanonicalEvent::TextDelta(text) => {
                if self.content_closed {
                    return frames;
                }
                self.ensure_created(request, created_secs, &mut frames);
                let (item_id, output_index) =
                    self.ensure_item(request, ItemKind::Message, 0, None, None, &mut frames);
                if let Some(open) = self.open.as_mut() {
                    open.item.text.push_str(text);
                }
                frames.push(frame(
                    "response.output_text.delta",
                    vec![
                        ("item_id", Value::from(item_id.as_str())),
                        ("output_index", Value::from(u64::from(output_index))),
                        ("content_index", Value::from(0i64)),
                        ("delta", Value::from(text.as_str())),
                    ],
                ));
            }
            CanonicalEvent::ReasoningDelta(text) => {
                if self.content_closed {
                    return frames;
                }
                self.ensure_created(request, created_secs, &mut frames);
                let (item_id, output_index) =
                    self.ensure_item(request, ItemKind::Reasoning, 0, None, None, &mut frames);
                if let Some(open) = self.open.as_mut() {
                    open.item.text.push_str(text);
                }
                frames.push(frame(
                    "response.reasoning_summary_text.delta",
                    vec![
                        ("item_id", Value::from(item_id.as_str())),
                        ("output_index", Value::from(u64::from(output_index))),
                        ("summary_index", Value::from(0i64)),
                        ("delta", Value::from(text.as_str())),
                    ],
                ));
            }
            CanonicalEvent::ToolCallDelta(call) => {
                if self.content_closed {
                    return frames;
                }
                self.ensure_created(request, created_secs, &mut frames);
                let (item_id, output_index) = self.ensure_item(
                    request,
                    ItemKind::FunctionCall,
                    call.index,
                    call.name.as_deref(),
                    call.id.as_deref(),
                    &mut frames,
                );
                if !call.arguments_delta.is_empty() {
                    if let Some(open) = self.open.as_mut() {
                        open.item.text.push_str(&call.arguments_delta);
                    }
                    frames.push(frame(
                        "response.function_call_arguments.delta",
                        vec![
                            ("item_id", Value::from(item_id.as_str())),
                            ("output_index", Value::from(u64::from(output_index))),
                            ("delta", Value::from(call.arguments_delta.as_str())),
                        ],
                    ));
                }
            }
            // Usage has no frame of its own in this dialect: it is reported by
            // the terminal response object.
            CanonicalEvent::Usage(usage) => self.usage = Some(*usage),
            CanonicalEvent::Finish { reason } => {
                self.finish = Some(*reason);
                self.ensure_created(request, created_secs, &mut frames);
                self.close_open(&mut frames);
                // The terminal frame is deliberately *not* emitted here. It
                // restates the whole response, usage included, and a provider
                // reports usage *after* the finish reason — the Chat
                // Completions decoder yields `Finish` then `Usage` out of a
                // single upstream chunk. Publishing the terminal frame on
                // `Finish` would report a completed response whose usage was
                // zero. [`Self::finish`] emits it when the stream actually
                // ends, by which time everything has arrived.
                self.content_closed = true;
            }
            CanonicalEvent::Error(error) => {
                frames.push(error_frame(error));
                self.stopped = true;
            }
            // Embeddings never reach a Responses caller.
            CanonicalEvent::Embedding { .. } => {}
        }

        frames
    }

    /// Close the stream, emitting the terminal frame.
    ///
    /// `reason` is used only when the upstream never reported one — a
    /// cancellation or a deadline — so that such a stream still closes as a
    /// well-formed response rather than simply stopping.
    pub fn finish(
        &mut self,
        request: &CanonicalRequest,
        reason: FinishReason,
        created_secs: u64,
    ) -> Vec<Frame> {
        if self.stopped {
            return Vec::new();
        }
        if self.finish.is_none() {
            self.finish = Some(reason);
        }
        let mut frames = Vec::new();
        self.ensure_created(request, created_secs, &mut frames);
        self.close_open(&mut frames);
        frames.push(self.terminal(request, created_secs));
        self.stopped = true;
        frames
    }

    /// End the stream with an error event.
    ///
    /// Specification 14: "Emit protocol-supported error event if possible, then
    /// close. Never append failover output."
    pub fn error(&mut self, error: &RouterError) -> Vec<Frame> {
        if self.stopped {
            return Vec::new();
        }
        self.stopped = true;
        vec![error_frame(error)]
    }
}

fn error_frame(error: &RouterError) -> Frame {
    frame(
        "error",
        vec![
            ("code", Value::from(error.code.as_str())),
            ("message", Value::from(error.detail.as_str())),
            (
                "param",
                error
                    .param
                    .as_ref()
                    .map_or(Value::Null, |p| Value::from(p.as_str())),
            ),
        ],
    )
}

/// Render the Responses stream frames for one canonical event.
///
/// Returns every frame the event implies, which may be none (usage) or several
/// (a text delta that has to open its item and content part first).
#[must_use]
pub fn render_responses_chunk(
    state: &mut ResponsesStreamState,
    request: &CanonicalRequest,
    event: &CanonicalEvent,
    created_secs: u64,
) -> Vec<Frame> {
    state.render(request, event, created_secs)
}

/// Render the error envelope.
///
/// Specification 8.2 fixes the code; this is the shape OpenAI clients parse.
#[must_use]
pub fn render_error(error: &RouterError, request_id: Option<RequestId>) -> String {
    let mut inner = Object::new();
    inner.push("message", Value::from(error.detail.as_str()));
    inner.push("type", Value::from(error.code.openai_type()));
    inner.push("code", Value::from(error.code.as_str()));
    inner.push_opt(
        "param",
        error.param.as_ref().map(|p| Value::from(p.as_str())),
    );

    let mut root = Object::new();
    root.push("error", Value::Object(inner));
    // The request identifier is the only correlation handle a caller gets for
    // an internal fault, so it is always present.
    root.push_opt(
        "request_id",
        request_id.map(|id| Value::from(id.to_string())),
    );
    to_string(&Value::Object(root))
}

/// Render the model list.
///
/// Specification 8: "returns only aliases/models authorized for the principal".
/// The caller passes the already-filtered list; this function does no
/// authorization of its own, so there is no second place for the filter to be
/// forgotten.
#[must_use]
pub fn render_models(aliases: &[(&str, Option<&str>)], created_secs: u64) -> String {
    let data: Vec<Value> = aliases
        .iter()
        .map(|(id, description)| {
            let mut item = Object::new();
            item.push("id", Value::from(*id));
            item.push("object", Value::from("model"));
            item.push("created", Value::from(created_secs));
            item.push("owned_by", Value::from("hypellm"));
            item.push_opt("description", description.map(Value::from));
            Value::Object(item)
        })
        .collect();

    let mut root = Object::new();
    root.push("object", Value::from("list"));
    root.push("data", Value::Array(data));
    to_string(&Value::Object(root))
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
    use hypellm_core::time::TestClock;
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
            min_quality_class: None,
            document_limits: DocumentLimits::DEFAULT,
            residency: None,
            max_cost_class: None,
        }
    }

    fn parse_chat(body: &str) -> Result<CanonicalRequest, RouterError> {
        parse_chat_request(body.as_bytes(), &context(), &Limits::DEFAULT)
    }

    // -- Parsing ------------------------------------------------------------

    #[test]
    fn a_minimal_chat_request_parses() {
        let request = parse_chat(r#"{"model":"code-premium","messages":[{"role":"user","content":"hi"}]}"#)
            .expect("parses");
        assert_eq!(request.requested_model.as_str(), "code-premium");
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, Role::User);
        assert_eq!(request.messages[0].as_text().as_deref(), Some("hi"));
        assert!(!request.stream.enabled);
        assert_eq!(request.operation, Operation::Chat);
        // The principal comes from the context, never from the body.
        assert_eq!(request.principal.as_str(), "user:42");
    }

    #[test]
    fn a_client_cannot_set_its_own_principal_or_tenant() {
        // Specification 5.1: "Resolved server-side; client cannot override."
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"principal":"user:admin","tenant":"other","user":"root"}"#,
        )
        .expect("parses");
        assert_eq!(request.principal.as_str(), "user:42");
        assert_eq!(request.tenant.as_str(), "acme");
    }

    #[test]
    fn a_missing_model_is_an_invalid_request() {
        let error = parse_chat(r#"{"messages":[]}"#).expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.param.expect("param").as_str(), "model");
    }

    #[test]
    fn an_unusable_model_name_is_not_echoed_back() {
        // A 404 that repeats an arbitrary caller string is a reflection surface.
        let hostile = r#"{"model":"<script>alert(1)</script>","messages":[{"role":"user","content":"x"}]}"#;
        let error = parse_chat(hostile).expect_err("must fail");
        assert_eq!(error.code, ErrorCode::ModelNotFound);
        assert!(!error.detail.as_str().contains("script"));
    }

    #[test]
    fn malformed_json_is_rejected_without_echoing_the_body() {
        let error = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"my secret"#)
            .expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(!error.detail.as_str().contains("secret"));
    }

    #[test]
    fn unset_sampling_stays_unset_through_parsing() {
        let request = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#)
            .expect("parses");
        assert!(request.sampling.is_unset());
        assert_eq!(request.limits.max_output_tokens, None);
    }

    #[test]
    fn zero_valued_sampling_is_preserved() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"temperature":0,"top_p":0,"seed":0}"#,
        )
        .expect("parses");
        assert_eq!(request.sampling.temperature, Some(0.0));
        assert_eq!(request.sampling.top_p, Some(0.0));
        assert_eq!(request.sampling.seed, Some(0));
        assert!(!request.sampling.is_unset());
    }

    #[test]
    fn an_explicit_null_reads_as_unset() {
        // Harnesses routinely send null for "not set".
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"temperature":null,"stop":null,"max_tokens":null}"#,
        )
        .expect("parses");
        assert_eq!(request.sampling.temperature, None);
        assert!(request.sampling.stop.is_empty());
        assert_eq!(request.limits.max_output_tokens, None);
    }

    #[test]
    fn out_of_range_sampling_is_rejected() {
        let error = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"temperature":5}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.param.expect("param").as_str(), "temperature");
    }

    #[test]
    fn both_max_token_spellings_are_accepted() {
        let a = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":100}"#)
            .unwrap();
        assert_eq!(a.limits.max_output_tokens, Some(100));

        let b = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"max_completion_tokens":200}"#,
        )
        .unwrap();
        assert_eq!(b.limits.max_output_tokens, Some(200));

        // The newer spelling wins when both are present.
        let c = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":100,"max_completion_tokens":200}"#,
        )
        .unwrap();
        assert_eq!(c.limits.max_output_tokens, Some(200));
    }

    #[test]
    fn stop_accepts_a_string_or_an_array() {
        let a = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}],"stop":"END"}"#)
            .unwrap();
        assert_eq!(a.sampling.stop, vec!["END"]);

        let b = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"stop":["A","B"]}"#,
        )
        .unwrap();
        assert_eq!(b.sampling.stop, vec!["A", "B"]);
    }

    #[test]
    fn streaming_options_parse() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true,"stream_options":{"include_usage":true}}"#,
        )
        .unwrap();
        assert!(request.stream.enabled);
        assert!(request.stream.include_usage);
    }

    #[test]
    fn multimodal_content_parses() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":[
                {"type":"text","text":"what is this"},
                {"type":"image_url","image_url":{"url":"https://example.com/x.png"}}
            ]}]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].content.len(), 2);
        assert_eq!(
            request.required_modalities(),
            vec![
                hypellm_core::canonical::Modality::Text,
                hypellm_core::canonical::Modality::Image
            ]
        );
    }

    #[test]
    fn a_data_uri_image_is_decomposed_not_fetched() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":[
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}
            ]}]}"#,
        )
        .unwrap();
        match &request.messages[0].content[0] {
            ContentPart::Image(ImageSource::Inline {
                media_type,
                base64_data,
            }) => {
                assert_eq!(media_type, "image/png");
                assert_eq!(base64_data, "AAAA");
            }
            other => panic!("expected an inline image, got {other:?}"),
        }
    }

    #[test]
    fn a_remote_image_url_is_carried_not_dereferenced() {
        // Specification 10: the router must not fetch a caller-supplied URL.
        // Carrying it through is the only safe handling.
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":[
                {"type":"image_url","image_url":{"url":"http://169.254.169.254/latest/meta-data/"}}
            ]}]}"#,
        )
        .unwrap();
        match &request.messages[0].content[0] {
            ContentPart::Image(ImageSource::Url(url)) => {
                assert!(url.contains("169.254.169.254"));
            }
            other => panic!("expected a URL image, got {other:?}"),
        }
    }

    #[test]
    fn tools_parse_with_their_schema_intact() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[
                {"type":"function","function":{"name":"lookup","description":"d","strict":true,
                 "parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.tools.len(), 1);
        assert_eq!(request.tools[0].name, "lookup");
        assert!(request.tools[0].strict);
        let schema = parse_str(&request.tools[0].parameters_json, &Limits::SMALL).unwrap();
        assert_eq!(schema.field_str("type").unwrap(), "object");
        assert_eq!(schema.field_array("required").unwrap().len(), 1);
    }

    #[test]
    fn tool_choice_shapes_parse() {
        let cases = [
            (r#""auto""#, ToolChoice::Auto),
            (r#""none""#, ToolChoice::None),
            (r#""required""#, ToolChoice::Required),
            (
                r#"{"type":"function","function":{"name":"f"}}"#,
                ToolChoice::Function("f".to_owned()),
            ),
        ];
        for (raw, expected) in cases {
            let body = format!(
                r#"{{"model":"m","messages":[{{"role":"user","content":"x"}}],"tool_choice":{raw}}}"#
            );
            assert_eq!(parse_chat(&body).unwrap().tool_choice, Some(expected));
        }
    }

    #[test]
    fn tool_result_messages_parse() {
        let request = parse_chat(
            r#"{"model":"m","messages":[
                {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},
                {"role":"tool","tool_call_id":"c1","content":"42"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].tool_calls.len(), 1);
        assert_eq!(request.messages[0].tool_calls[0].id, "c1");
        match &request.messages[1].content[0] {
            ContentPart::ToolResult {
                tool_call_id,
                content,
                ..
            } => {
                assert_eq!(tool_call_id, "c1");
                assert_eq!(content, "42");
            }
            other => panic!("expected a tool result, got {other:?}"),
        }
    }

    #[test]
    fn response_format_shapes_parse() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_object"}}"#,
        )
        .unwrap();
        assert_eq!(request.response_format, Some(ResponseFormat::JsonObject));

        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_schema","json_schema":{"name":"r","strict":true,"schema":{"type":"object"}}}}"#,
        )
        .unwrap();
        match request.response_format {
            Some(ResponseFormat::JsonSchema { name, strict, .. }) => {
                assert_eq!(name, "r");
                assert!(strict);
            }
            other => panic!("expected a schema format, got {other:?}"),
        }
    }

    #[test]
    fn routing_hints_are_dropped_without_permission() {
        // Specification 5.1: "ignored or rejected unless principal has
        // permission". Dropping keeps a harness that always sends them working.
        let body = r#"{"model":"m","messages":[{"role":"user","content":"x"}],"hypellm_routing":{"require_local":true,"prefer_target":"local:qwen"}}"#;
        let request = parse_chat(body).unwrap();
        assert!(request.hints.is_empty());
        assert!(!request.hints.require_local);

        let mut permitted = context();
        permitted.hints_permitted = true;
        let request =
            parse_chat_request(body.as_bytes(), &permitted, &Limits::DEFAULT).unwrap();
        assert!(request.hints.require_local);
        assert_eq!(
            request.hints.prefer_target.as_ref().map(|t| t.as_str()),
            Some("local:qwen")
        );
    }

    #[test]
    fn an_embeddings_request_parses_both_input_shapes() {
        let single = parse_embeddings_request(
            br#"{"model":"embed","input":"one"}"#,
            &context(),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(single.inputs, vec!["one"]);
        assert_eq!(single.operation, Operation::Embeddings);

        let many = parse_embeddings_request(
            br#"{"model":"embed","input":["a","b"]}"#,
            &context(),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(many.inputs.len(), 2);

        let error = parse_embeddings_request(
            br#"{"model":"embed"}"#,
            &context(),
            &Limits::DEFAULT,
        )
        .expect_err("must fail");
        assert_eq!(error.param.expect("param").as_str(), "input");
    }

    // -- Rendering ----------------------------------------------------------

    fn accumulate(events: &[CanonicalEvent]) -> ResponseAccumulator {
        let mut accumulator = ResponseAccumulator::new();
        for event in events {
            accumulator.push(event);
        }
        accumulator
    }

    #[test]
    fn a_complete_response_renders_in_the_expected_shape() {
        let request = parse_chat(r#"{"model":"code-premium","messages":[{"role":"user","content":"x"}]}"#)
            .unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::Start {
                upstream_id: Some("resp_1".to_owned()),
                native_model: Some("qwen2.5-coder".to_owned()),
            },
            CanonicalEvent::TextDelta("Hello".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(10, 2)),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);

        let rendered = render_chat_response(&request, &accumulator, 1_767_225_600);
        let value = parse_str(&rendered, &Limits::DEFAULT).expect("valid JSON");

        assert_eq!(value.field_str("object").unwrap(), "chat.completion");
        assert_eq!(value.field_str("model").unwrap(), "code-premium");
        let choice = &value.field_array("choices").unwrap()[0];
        assert_eq!(
            choice.get("message").unwrap().field_str("content").unwrap(),
            "Hello"
        );
        assert_eq!(choice.field_str("finish_reason").unwrap(), "stop");
        assert_eq!(
            value.get("usage").unwrap().field_i64("total_tokens").unwrap(),
            12
        );
        // Specification 6.5: the model actually used is visible in metadata.
        assert_eq!(
            value.get("hypellm").unwrap().field_str("native_model").unwrap(),
            "qwen2.5-coder"
        );
    }

    #[test]
    fn usage_provenance_reaches_the_client() {
        let request = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#).unwrap();

        let reported = accumulate(&[CanonicalEvent::Usage(
            hypellm_core::event::CanonicalUsage::reported(1, 1),
        )]);
        let value = parse_str(
            &render_chat_response(&request, &reported, 0),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            value
                .get("usage")
                .unwrap()
                .get("hypellm")
                .unwrap()
                .field_str("usage_source")
                .unwrap(),
            "provider_reported"
        );

        let estimated = accumulate(&[CanonicalEvent::Usage(
            hypellm_core::event::CanonicalUsage::estimated(1, 1),
        )]);
        let value = parse_str(
            &render_chat_response(&request, &estimated, 0),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            value
                .get("usage")
                .unwrap()
                .get("hypellm")
                .unwrap()
                .field_str("usage_source")
                .unwrap(),
            "router_estimated"
        );
    }

    #[test]
    fn a_tool_call_response_uses_null_content() {
        // Clients index `content` unconditionally; omitting it breaks them.
        let request = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#).unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_owned()),
                name: Some("lookup".to_owned()),
                arguments_delta: r#"{"q":"x"}"#.to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        let value = parse_str(
            &render_chat_response(&request, &accumulator, 0),
            &Limits::DEFAULT,
        )
        .unwrap();
        let message = value.field_array("choices").unwrap()[0].get("message").unwrap();
        assert!(message.get("content").unwrap().is_null());
        let calls = message.field_array("tool_calls").unwrap();
        assert_eq!(calls[0].field_str("id").unwrap(), "call_1");
        assert_eq!(
            calls[0].get("function").unwrap().field_str("arguments").unwrap(),
            r#"{"q":"x"}"#
        );
    }

    #[test]
    fn streaming_chunks_render_and_reparse() {
        let request = parse_chat(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true}"#,
        )
        .unwrap();
        let events = [
            CanonicalEvent::Start {
                upstream_id: None,
                native_model: None,
            },
            CanonicalEvent::TextDelta("Hel".to_owned()),
            CanonicalEvent::TextDelta("lo".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ];

        let mut chunks = Vec::new();
        for event in &events {
            if let Some(chunk) = render_chat_chunk(&request, event, 0) {
                chunks.push(chunk);
            }
        }
        assert_eq!(chunks.len(), 4);

        // The first chunk announces the role.
        let first = parse_str(&chunks[0], &Limits::DEFAULT).unwrap();
        assert_eq!(
            first.field_array("choices").unwrap()[0]
                .get("delta")
                .unwrap()
                .field_str("role")
                .unwrap(),
            "assistant"
        );
        assert_eq!(first.field_str("object").unwrap(), "chat.completion.chunk");

        // Content chunks carry only the delta.
        let second = parse_str(&chunks[1], &Limits::DEFAULT).unwrap();
        assert_eq!(
            second.field_array("choices").unwrap()[0]
                .get("delta")
                .unwrap()
                .field_str("content")
                .unwrap(),
            "Hel"
        );
        assert!(
            second.field_array("choices").unwrap()[0]
                .get("finish_reason")
                .unwrap()
                .is_null()
        );

        // The last carries the finish reason.
        let last = parse_str(&chunks[3], &Limits::DEFAULT).unwrap();
        assert_eq!(
            last.field_array("choices").unwrap()[0]
                .field_str("finish_reason")
                .unwrap(),
            "stop"
        );
    }

    #[test]
    fn streaming_tool_call_chunks_carry_the_index() {
        let request = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#).unwrap();
        let chunk = render_chat_chunk(
            &request,
            &CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 2,
                id: Some("c".to_owned()),
                name: Some("f".to_owned()),
                arguments_delta: "{".to_owned(),
            }),
            0,
        )
        .expect("renders");
        let value = parse_str(&chunk, &Limits::DEFAULT).unwrap();
        let call = &value.field_array("choices").unwrap()[0]
            .get("delta")
            .unwrap()
            .field_array("tool_calls")
            .unwrap()[0];
        assert_eq!(call.field_i64("index").unwrap(), 2);
        assert_eq!(call.field_str("type").unwrap(), "function");
    }

    #[test]
    fn embedding_and_error_events_do_not_render_as_chunks() {
        let request = parse_chat(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#).unwrap();
        assert!(
            render_chat_chunk(
                &request,
                &CanonicalEvent::Embedding {
                    index: 0,
                    values: vec![0.1],
                },
                0
            )
            .is_none()
        );
        assert!(
            render_chat_chunk(&request, &CanonicalEvent::Error(RouterError::internal()), 0)
                .is_none()
        );
    }

    #[test]
    fn the_error_envelope_matches_the_contract() {
        let error = RouterError::new(ErrorCode::RateLimited, "quota exceeded");
        let rendered = render_error(&error, Some(RequestId::from_u128(7)));
        let value = parse_str(&rendered, &Limits::SMALL).unwrap();

        let inner = value.get("error").unwrap();
        assert_eq!(inner.field_str("code").unwrap(), "rate_limited");
        assert_eq!(inner.field_str("type").unwrap(), "rate_limit_error");
        assert_eq!(inner.field_str("message").unwrap(), "quota exceeded");
        assert_eq!(value.field_str("request_id").unwrap().len(), 32);
    }

    #[test]
    fn an_internal_fault_discloses_only_the_request_id() {
        let rendered = render_error(&RouterError::internal(), Some(RequestId::from_u128(9)));
        let value = parse_str(&rendered, &Limits::SMALL).unwrap();
        let inner = value.get("error").unwrap();
        assert_eq!(inner.field_str("message").unwrap(), "internal error");
        assert_eq!(inner.field_str("code").unwrap(), "internal_fault");
        assert!(value.get("request_id").is_some());
    }

    #[test]
    fn the_model_list_renders() {
        let rendered = render_models(
            &[
                ("code-premium", Some("premium coding models")),
                ("code-fast", None),
            ],
            1_767_225_600,
        );
        let value = parse_str(&rendered, &Limits::DEFAULT).unwrap();
        assert_eq!(value.field_str("object").unwrap(), "list");
        let data = value.field_array("data").unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].field_str("id").unwrap(), "code-premium");
        assert_eq!(data[0].field_str("object").unwrap(), "model");
        assert!(data[1].get("description").is_none());
    }

    #[test]
    fn an_embeddings_response_renders() {
        let request = parse_embeddings_request(
            br#"{"model":"embed","input":["a","b"]}"#,
            &context(),
            &Limits::DEFAULT,
        )
        .unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::Embedding {
                index: 0,
                values: vec![0.1, 0.2],
            },
            CanonicalEvent::Embedding {
                index: 1,
                values: vec![0.3],
            },
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(4, 0)),
        ]);
        let value = parse_str(
            &render_embeddings_response(&request, &accumulator),
            &Limits::DEFAULT,
        )
        .unwrap();
        let data = value.field_array("data").unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].field_i64("index").unwrap(), 0);
        assert_eq!(data[0].field_array("embedding").unwrap().len(), 2);
    }

    // -- Responses: parsing -------------------------------------------------

    fn parse_responses(body: &str) -> Result<CanonicalRequest, RouterError> {
        parse_responses_request(body.as_bytes(), &context(), &Limits::DEFAULT)
    }

    #[test]
    fn a_bare_string_input_is_a_single_user_turn() {
        let request = parse_responses(r#"{"model":"code-premium","input":"hi"}"#).expect("parses");
        assert_eq!(request.protocol, ClientProtocol::OpenAiResponses);
        assert_eq!(request.operation, Operation::Responses);
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, Role::User);
        assert_eq!(request.messages[0].as_text().as_deref(), Some("hi"));
    }

    #[test]
    fn a_chat_shaped_body_is_not_a_responses_body() {
        // The regression this whole dialect exists to prevent: a body with
        // `messages` and `max_tokens` carries none of the fields the Responses
        // API defines, and accepting it silently would route an empty request.
        let error = parse_responses(
            r#"{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":10}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.param.expect("param").as_str(), "input");
    }

    #[test]
    fn instructions_are_hoisted_into_a_system_message() {
        let request = parse_responses(
            r#"{"model":"m","instructions":"Be terse.","input":[{"role":"user","content":"x"}]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].role, Role::System);
        assert_eq!(request.messages[0].as_text().as_deref(), Some("Be terse."));
        assert_eq!(request.messages[1].role, Role::User);
    }

    #[test]
    fn responses_content_parts_use_their_own_spelling() {
        let request = parse_responses(
            r#"{"model":"m","input":[
                {"role":"user","content":[
                    {"type":"input_text","text":"what is this"},
                    {"type":"input_image","image_url":"https://example.com/x.png"}
                ]},
                {"role":"assistant","content":[{"type":"output_text","text":"a picture"}]}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[0].content.len(), 2);
        match &request.messages[0].content[1] {
            ContentPart::Image(ImageSource::Url(url)) => assert!(url.contains("example.com")),
            other => panic!("expected a URL image, got {other:?}"),
        }
        // An assistant turn replayed by the client uses the output spelling.
        assert_eq!(request.messages[1].role, Role::Assistant);
        assert_eq!(request.messages[1].as_text().as_deref(), Some("a picture"));
        assert_eq!(
            request.required_modalities(),
            vec![
                hypellm_core::canonical::Modality::Text,
                hypellm_core::canonical::Modality::Image
            ]
        );
    }

    #[test]
    fn an_inline_image_is_decomposed_not_fetched() {
        let request = parse_responses(
            r#"{"model":"m","input":[{"role":"user","content":[
                {"type":"input_image","image_url":"data:image/png;base64,AAAA"}
            ]}]}"#,
        )
        .unwrap();
        match &request.messages[0].content[0] {
            ContentPart::Image(ImageSource::Inline { media_type, base64_data }) => {
                assert_eq!(media_type, "image/png");
                assert_eq!(base64_data, "AAAA");
            }
            other => panic!("expected an inline image, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_content_part_is_rejected_not_dropped() {
        // A dropped part is a request the caller believes they sent.
        let error = parse_responses(
            r#"{"model":"m","input":[{"role":"user","content":[
                {"type":"computer_screenshot","image_url":"x"}
            ]}]}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(error.detail.as_str().contains("computer_screenshot"));
        assert_eq!(error.param.expect("param").as_str(), "input[0].content");
    }

    #[test]
    fn a_provider_side_file_reference_is_refused_rather_than_forwarded() {
        // `file_id` names a file uploaded to the *provider*. The router
        // manages no uploads and holds no such handle, so forwarding one would
        // be passing through an opaque identifier whose meaning depends on
        // which target routing happened to pick — the caller would get a
        // different document, or none, depending on where the request landed.
        let error = parse_responses(
            r#"{"model":"m","input":[{"role":"user","content":[
                {"type":"input_file","file_id":"file_1"}
            ]}]}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.param.expect("param").as_str(), "input[0].content");
    }

    #[test]
    fn an_unknown_input_item_is_rejected() {
        let error = parse_responses(r#"{"model":"m","input":[{"type":"computer_call"}]}"#)
            .expect_err("must fail");
        assert!(error.detail.as_str().contains("computer_call"));
    }

    #[test]
    fn max_output_tokens_is_the_responses_spelling() {
        let request = parse_responses(r#"{"model":"m","input":"x","max_output_tokens":100}"#).unwrap();
        assert_eq!(request.limits.max_output_tokens, Some(100));

        // The chat spelling is not this dialect's field, so it sets nothing.
        let chat_spelling = parse_responses(r#"{"model":"m","input":"x","max_tokens":100}"#).unwrap();
        assert_eq!(chat_spelling.limits.max_output_tokens, None);

        let error = parse_responses(
            r#"{"model":"m","input":"x","max_output_tokens":99999999999}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.param.expect("param").as_str(), "max_output_tokens");
    }

    #[test]
    fn a_function_call_round_trip_parses() {
        let request = parse_responses(
            r#"{"model":"m","input":[
                {"role":"user","content":"go"},
                {"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"x\"}"},
                {"type":"function_call_output","call_id":"call_1","output":"42"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.messages[1].role, Role::Assistant);
        assert_eq!(request.messages[1].tool_calls.len(), 1);
        // `call_id` is the correlation key, not the item id.
        assert_eq!(request.messages[1].tool_calls[0].id, "call_1");
        assert_eq!(request.messages[1].tool_calls[0].arguments, r#"{"q":"x"}"#);
        assert_eq!(request.messages[2].role, Role::Tool);
        match &request.messages[2].content[0] {
            ContentPart::ToolResult { tool_call_id, content, .. } => {
                assert_eq!(tool_call_id, "call_1");
                assert_eq!(content, "42");
            }
            other => panic!("expected a tool result, got {other:?}"),
        }
    }

    #[test]
    fn responses_tools_are_flat() {
        let request = parse_responses(
            r#"{"model":"m","input":"x","tools":[
                {"type":"function","name":"lookup","description":"d","strict":true,
                 "parameters":{"type":"object","properties":{"q":{"type":"string"}}}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(request.tools.len(), 1);
        assert_eq!(request.tools[0].name, "lookup");
        assert!(request.tools[0].strict);
        let schema = parse_str(&request.tools[0].parameters_json, &Limits::SMALL).unwrap();
        assert_eq!(schema.field_str("type").unwrap(), "object");

        // The chat dialect's nested shape has no name where this one looks.
        let error = parse_responses(
            r#"{"model":"m","input":"x","tools":[{"type":"function","function":{"name":"lookup"}}]}"#,
        )
        .expect_err("must fail");
        assert_eq!(error.param.expect("param").as_str(), "tools[0]");

        // A provider-hosted tool the router cannot honour is refused rather
        // than accepted and never called.
        let error = parse_responses(r#"{"model":"m","input":"x","tools":[{"type":"web_search"}]}"#)
            .expect_err("must fail");
        assert!(error.detail.as_str().contains("web_search"));
    }

    #[test]
    fn responses_tool_choice_shapes_parse() {
        for (raw, expected) in [
            (r#""auto""#, ToolChoice::Auto),
            (r#""none""#, ToolChoice::None),
            (r#""required""#, ToolChoice::Required),
            (
                r#"{"type":"function","name":"f"}"#,
                ToolChoice::Function("f".to_owned()),
            ),
        ] {
            let body = format!(r#"{{"model":"m","input":"x","tool_choice":{raw}}}"#);
            assert_eq!(parse_responses(&body).unwrap().tool_choice, Some(expected));
        }
    }

    #[test]
    fn the_response_format_lives_under_text_format() {
        let request = parse_responses(
            r#"{"model":"m","input":"x","text":{"format":{"type":"json_object"}}}"#,
        )
        .unwrap();
        assert_eq!(request.response_format, Some(ResponseFormat::JsonObject));

        let request = parse_responses(
            r#"{"model":"m","input":"x","text":{"format":{"type":"json_schema","name":"r","strict":true,"schema":{"type":"object"}}}}"#,
        )
        .unwrap();
        match request.response_format {
            Some(ResponseFormat::JsonSchema { name, strict, schema_json }) => {
                assert_eq!(name, "r");
                assert!(strict);
                assert!(schema_json.contains("object"));
            }
            other => panic!("expected a schema format, got {other:?}"),
        }

        // `response_format` is the chat spelling and has no effect here.
        let request = parse_responses(
            r#"{"model":"m","input":"x","response_format":{"type":"json_object"}}"#,
        )
        .unwrap();
        assert_eq!(request.response_format, None);
    }

    #[test]
    fn responses_streaming_always_requests_usage() {
        // The terminal event reports usage unconditionally, so the router must
        // always have the numbers.
        let request = parse_responses(r#"{"model":"m","input":"x","stream":true}"#).unwrap();
        assert!(request.stream.enabled);
        assert!(request.stream.include_usage);
    }

    // -- Responses: non-streaming rendering ---------------------------------

    const RESPONSES_MINIMAL: &str = r#"{"model":"code-premium","input":"x"}"#;

    #[test]
    fn a_responses_body_reports_typed_output_items() {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::Start {
                upstream_id: Some("resp_up".to_owned()),
                native_model: Some("gpt-4.1".to_owned()),
            },
            CanonicalEvent::TextDelta("Hello".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(10, 5)),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);
        let value = parse_str(
            &render_responses_response(&request, &accumulator, 1_767_225_600),
            &Limits::DEFAULT,
        )
        .unwrap();

        assert_eq!(value.field_str("object").unwrap(), "response");
        assert_eq!(value.field_i64("created_at").unwrap(), 1_767_225_600);
        assert_eq!(value.field_str("status").unwrap(), "completed");
        // The client-visible alias, not the provider's native name.
        assert_eq!(value.field_str("model").unwrap(), "code-premium");
        assert!(value.get("choices").is_none(), "this dialect has no choices");

        let output = value.field_array("output").unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].field_str("type").unwrap(), "message");
        assert_eq!(output[0].field_str("role").unwrap(), "assistant");
        let content = output[0].field_array("content").unwrap();
        assert_eq!(content[0].field_str("type").unwrap(), "output_text");
        assert_eq!(content[0].field_str("text").unwrap(), "Hello");

        let usage = value.get("usage").unwrap();
        assert_eq!(usage.field_i64("input_tokens").unwrap(), 10);
        assert_eq!(usage.field_i64("output_tokens").unwrap(), 5);
        assert_eq!(usage.field_i64("total_tokens").unwrap(), 15);
        assert!(usage.get("prompt_tokens").is_none());
        assert_eq!(
            usage.get("hypellm").unwrap().field_str("usage_source").unwrap(),
            "provider_reported"
        );

        assert!(value.get("incomplete_details").unwrap().is_null());
        // Specification 6.5: the model actually used stays visible.
        assert_eq!(
            value.get("hypellm").unwrap().field_str("native_model").unwrap(),
            "gpt-4.1"
        );
    }

    #[test]
    fn a_truncated_response_is_incomplete_with_a_reason() {
        // There is no finish_reason here: truncation is the status plus
        // `incomplete_details`.
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::TextDelta("partial".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Length,
            },
        ]);
        let value = parse_str(
            &render_responses_response(&request, &accumulator, 0),
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(value.field_str("status").unwrap(), "incomplete");
        assert_eq!(
            value.get("incomplete_details").unwrap().field_str("reason").unwrap(),
            "max_output_tokens"
        );
        assert!(value.get("output").unwrap().as_array().unwrap()[0]
            .field_array("content")
            .unwrap()
            .first()
            .is_some());
    }

    #[test]
    fn a_tool_only_turn_renders_a_function_call_item() {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let accumulator = accumulate(&[
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_owned()),
                name: Some("lookup".to_owned()),
                arguments_delta: r#"{"q":"x"}"#.to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        let value = parse_str(
            &render_responses_response(&request, &accumulator, 0),
            &Limits::DEFAULT,
        )
        .unwrap();
        let output = value.field_array("output").unwrap();
        assert_eq!(output.len(), 1, "no empty message item is emitted");
        assert_eq!(output[0].field_str("type").unwrap(), "function_call");
        assert_eq!(output[0].field_str("call_id").unwrap(), "call_1");
        assert_eq!(output[0].field_str("name").unwrap(), "lookup");
        assert_eq!(output[0].field_str("arguments").unwrap(), r#"{"q":"x"}"#);
        // A tool turn still completed normally.
        assert_eq!(value.field_str("status").unwrap(), "completed");
    }

    // -- Responses: streaming -----------------------------------------------

    /// Drive a stream exactly as the listener does: every event through the
    /// renderer, then the stream's close.
    fn render_responses_all(events: &[CanonicalEvent]) -> Vec<Frame> {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        let mut frames = Vec::new();
        for event in events {
            frames.extend(render_responses_chunk(&mut state, &request, event, 0));
        }
        frames.extend(state.finish(&request, FinishReason::Stop, 0));
        frames
    }

    fn frame_names(frames: &[Frame]) -> Vec<&str> {
        frames.iter().map(|f| f.event.as_str()).collect()
    }

    #[test]
    fn the_responses_frame_sequence_matches_the_profile() {
        let frames = render_responses_all(&[
            CanonicalEvent::Start {
                upstream_id: Some("resp_up".to_owned()),
                native_model: None,
            },
            CanonicalEvent::TextDelta("hel".to_owned()),
            CanonicalEvent::TextDelta("lo".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(10, 5)),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);

        assert_eq!(
            frame_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );

        // There is no `[DONE]` sentinel in this dialect; assuming one is how a
        // stream reader is left hanging.
        assert!(frames.iter().all(|f| !f.data.contains("[DONE]")));
    }

    #[test]
    fn every_responses_frame_repeats_its_event_name() {
        let frames = render_responses_all(&[
            CanonicalEvent::Start {
                upstream_id: None,
                native_model: None,
            },
            CanonicalEvent::TextDelta("x".to_owned()),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_owned()),
                name: Some("f".to_owned()),
                arguments_delta: "{}".to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        for frame in &frames {
            let value = parse_str(&frame.data, &Limits::DEFAULT)
                .unwrap_or_else(|e| panic!("frame {} is not valid JSON: {e}", frame.event));
            assert_eq!(
                value.field_str("type").unwrap(),
                frame.event,
                "the payload type must match the event name"
            );
        }
    }

    #[test]
    fn a_text_delta_opens_its_item_and_content_part_first() {
        // A provider that starts with content must not produce a delta with no
        // item to attach it to.
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        let frames = render_responses_chunk(
            &mut state,
            &request,
            &CanonicalEvent::TextDelta("x".to_owned()),
            0,
        );
        assert_eq!(
            frame_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
            ]
        );
        let added = parse_str(&frames[1].data, &Limits::SMALL).unwrap();
        let item = added.get("item").unwrap();
        assert_eq!(item.field_str("type").unwrap(), "message");
        assert_eq!(item.field_str("status").unwrap(), "in_progress");
        assert!(item.field_array("content").unwrap().is_empty());
        // The delta names the item it belongs to.
        let delta = parse_str(&frames[3].data, &Limits::SMALL).unwrap();
        assert_eq!(
            delta.field_str("item_id").unwrap(),
            item.field_str("id").unwrap()
        );
        assert_eq!(delta.field_str("delta").unwrap(), "x");
    }

    #[test]
    fn a_tool_call_closes_the_message_item_first() {
        let frames = render_responses_all(&[
            CanonicalEvent::TextDelta("thinking".to_owned()),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_owned()),
                name: Some("lookup".to_owned()),
                arguments_delta: r#"{"q":"#.to_owned(),
            }),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: None,
                name: None,
                arguments_delta: r#""x"}"#.to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        assert_eq!(
            frame_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                // The message item closes before the function call opens.
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.output_item.added",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.done",
                "response.output_item.done",
                "response.completed",
            ]
        );

        // The function call item carries no content part, and its arguments
        // are reassembled in order.
        let done = parse_str(&frames[10].data, &Limits::SMALL).unwrap();
        assert_eq!(done.field_str("arguments").unwrap(), r#"{"q":"x"}"#);
        let item = parse_str(&frames[11].data, &Limits::SMALL)
            .unwrap()
            .get("item")
            .cloned()
            .unwrap();
        assert_eq!(item.field_str("type").unwrap(), "function_call");
        assert_eq!(item.field_str("call_id").unwrap(), "call_1");
        assert_eq!(item.field_str("name").unwrap(), "lookup");
    }

    #[test]
    fn interleaved_tool_calls_get_separate_items() {
        // Two calls must never be folded into one item, whatever order their
        // fragments arrive in.
        let frames = render_responses_all(&[
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 0,
                id: Some("call_a".to_owned()),
                name: Some("a".to_owned()),
                arguments_delta: r#"{"a":1}"#.to_owned(),
            }),
            CanonicalEvent::ToolCallDelta(hypellm_core::event::ToolCallDelta {
                index: 1,
                id: Some("call_b".to_owned()),
                name: Some("b".to_owned()),
                arguments_delta: r#"{"b":2}"#.to_owned(),
            }),
            CanonicalEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]);
        let added: Vec<&Frame> = frames
            .iter()
            .filter(|f| f.event == "response.output_item.added")
            .collect();
        assert_eq!(added.len(), 2);
        let ids: Vec<String> = added
            .iter()
            .map(|f| {
                parse_str(&f.data, &Limits::SMALL)
                    .unwrap()
                    .get("item")
                    .unwrap()
                    .field_str("id")
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_ne!(ids[0], ids[1], "each call gets its own item");

        let terminal = frames.last().unwrap();
        let output = parse_str(&terminal.data, &Limits::DEFAULT)
            .unwrap()
            .get("response")
            .unwrap()
            .field_array("output")
            .unwrap()
            .to_vec();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].field_str("arguments").unwrap(), r#"{"a":1}"#);
        assert_eq!(output[1].field_str("arguments").unwrap(), r#"{"b":2}"#);
    }

    #[test]
    fn the_terminal_frame_carries_the_whole_response() {
        let frames = render_responses_all(&[
            CanonicalEvent::Start {
                upstream_id: Some("resp_up".to_owned()),
                native_model: Some("gpt-4.1".to_owned()),
            },
            CanonicalEvent::TextDelta("hello".to_owned()),
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(10, 5)),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);
        let terminal = frames.last().unwrap();
        assert_eq!(terminal.event, "response.completed");
        let response = parse_str(&terminal.data, &Limits::DEFAULT)
            .unwrap()
            .get("response")
            .cloned()
            .unwrap();
        assert_eq!(response.field_str("status").unwrap(), "completed");
        assert_eq!(
            response.field_array("output").unwrap()[0]
                .field_array("content")
                .unwrap()[0]
                .field_str("text")
                .unwrap(),
            "hello"
        );
        assert_eq!(
            response.get("usage").unwrap().field_i64("total_tokens").unwrap(),
            15
        );
        assert_eq!(
            response.get("hypellm").unwrap().field_str("native_model").unwrap(),
            "gpt-4.1"
        );

        // The opening shell reports no usage it has not measured.
        let created = parse_str(&frames[0].data, &Limits::DEFAULT).unwrap();
        let shell = created.get("response").unwrap();
        assert_eq!(shell.field_str("status").unwrap(), "in_progress");
        assert!(shell.field_array("output").unwrap().is_empty());
        assert!(shell.get("usage").unwrap().is_null());
    }

    #[test]
    fn a_truncated_stream_terminates_with_response_incomplete() {
        let frames = render_responses_all(&[
            CanonicalEvent::TextDelta("partial".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Length,
            },
        ]);
        let terminal = frames.last().unwrap();
        assert_eq!(terminal.event, "response.incomplete");
        let response = parse_str(&terminal.data, &Limits::DEFAULT)
            .unwrap()
            .get("response")
            .cloned()
            .unwrap();
        assert_eq!(
            response.get("incomplete_details").unwrap().field_str("reason").unwrap(),
            "max_output_tokens"
        );
    }

    #[test]
    fn reasoning_streams_as_its_own_item() {
        let frames = render_responses_all(&[
            CanonicalEvent::ReasoningDelta("because".to_owned()),
            CanonicalEvent::TextDelta("so".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]);
        assert_eq!(
            frame_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.reasoning_summary_part.added",
                "response.reasoning_summary_text.delta",
                "response.reasoning_summary_text.done",
                "response.reasoning_summary_part.done",
                "response.output_item.done",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
    }

    #[test]
    fn no_output_follows_the_finish_reason() {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        render_responses_chunk(
            &mut state,
            &request,
            &CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
            0,
        );
        let after = render_responses_chunk(
            &mut state,
            &request,
            &CanonicalEvent::TextDelta("late".to_owned()),
            0,
        );
        assert!(after.is_empty(), "no output may follow the finish reason");

        // The terminal frame is emitted once, by the stream's close.
        let closing = state.finish(&request, FinishReason::Stop, 0);
        assert_eq!(frame_names(&closing), vec!["response.completed"]);
        assert!(state.finish(&request, FinishReason::Stop, 0).is_empty());
    }

    #[test]
    fn usage_reported_after_the_finish_reason_still_reaches_the_client() {
        // The Chat Completions decoder yields `Finish` before `Usage` out of
        // one upstream chunk. This dialect has no usage frame of its own, so a
        // terminal frame emitted on `Finish` would report zero tokens for a
        // response the provider metered.
        let frames = render_responses_all(&[
            CanonicalEvent::TextDelta("hello".to_owned()),
            CanonicalEvent::Finish {
                reason: FinishReason::Stop,
            },
            CanonicalEvent::Usage(hypellm_core::event::CanonicalUsage::reported(12, 5)),
        ]);
        let terminal = frames.last().unwrap();
        assert_eq!(terminal.event, "response.completed");
        let usage = parse_str(&terminal.data, &Limits::DEFAULT)
            .unwrap()
            .get("response")
            .unwrap()
            .get("usage")
            .cloned()
            .unwrap();
        assert_eq!(usage.field_i64("input_tokens").unwrap(), 12);
        assert_eq!(usage.field_i64("output_tokens").unwrap(), 5);
        assert_eq!(
            usage.get("hypellm").unwrap().field_str("usage_source").unwrap(),
            "provider_reported"
        );
    }

    #[test]
    fn finishing_early_closes_the_stream_cleanly() {
        // A cancellation or deadline must still leave a well-formed stream:
        // every open item closed and a terminal frame emitted.
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        render_responses_chunk(
            &mut state,
            &request,
            &CanonicalEvent::TextDelta("partial".to_owned()),
            0,
        );
        let closing = state.finish(&request, FinishReason::Cancelled, 0);
        assert_eq!(
            frame_names(&closing),
            vec![
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.incomplete",
            ]
        );
    }

    #[test]
    fn a_stream_that_produced_nothing_still_terminates() {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        let frames = state.finish(&request, FinishReason::Stop, 0);
        assert_eq!(
            frame_names(&frames),
            vec!["response.created", "response.completed"]
        );
        assert!(state.has_started());
    }

    #[test]
    fn an_error_ends_the_stream_with_an_error_event() {
        let request = parse_responses(RESPONSES_MINIMAL).unwrap();
        let mut state = ResponsesStreamState::new();
        render_responses_chunk(
            &mut state,
            &request,
            &CanonicalEvent::TextDelta("x".to_owned()),
            0,
        );
        let frames = state.error(&RouterError::new(ErrorCode::RateLimited, "quota exceeded"));
        assert_eq!(frame_names(&frames), vec!["error"]);
        let value = parse_str(&frames[0].data, &Limits::SMALL).unwrap();
        assert_eq!(value.field_str("code").unwrap(), "rate_limited");
        assert_eq!(value.field_str("message").unwrap(), "quota exceeded");
        // Specification 14: nothing follows, and no failover output is spliced.
        assert!(state.finish(&request, FinishReason::Stop, 0).is_empty());
    }

    #[test]
    fn an_error_event_in_the_stream_renders_an_error_frame() {
        let frames = render_responses_all(&[
            CanonicalEvent::TextDelta("x".to_owned()),
            CanonicalEvent::Error(RouterError::new(
                ErrorCode::UpstreamInvalidResponse,
                "the provider violated its contract",
            )),
        ]);
        let last = frames.last().unwrap();
        assert_eq!(last.event, "error");
    }

    #[test]
    fn a_request_body_over_the_limit_is_rejected() {
        let tight = Limits::DEFAULT.with_max_input_bytes(64);
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
            "x".repeat(1000)
        );
        let error = parse_chat_request(body.as_bytes(), &context(), &tight).expect_err("must fail");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}
