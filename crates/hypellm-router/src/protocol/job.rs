//! The artifact-job body of `POST /v1/jobs` (orchestration §11.5).
//!
//! ```text
//! POST /v1/jobs
//! { "model": "mesh",
//!   "verb": "image-to-3d",
//!   "prompt": "…",
//!   "params": { "duration_ms": 45000, "seed": 7, "steps": 32 },
//!   "inputs": [ { "name": "image", "media_type": "image/png", "data": "…base64…" } ],
//!   "options": { "texture_size": 1024 },
//!   "patience_ms": 1800000 }
//! ```
//!
//! A body without `verb` is a chat job and goes through the chat parser, as it
//! always did; a body with one is parsed here. It is first-party, so it is
//! strict where the OpenAI-compatible dialects are lenient: a field this parser
//! does not know is refused rather than ignored, because a job silently
//! generated without a parameter its caller set is a job generated wrong.
//!
//! Every value is inert data. `prompt` and `options` reach the shim and are
//! never read by the router; `params` are the only numbers the router reads,
//! and each is bounded here. Inputs travel inline: there is no field a caller
//! can put a URL or a path in, so nothing here can name a file or a host on
//! the service's side (§11.3).

use hypellm_adapters::job::{JobParams, MAX_INPUTS, PartMediaType, PartName};
use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, Message, Operation, ReasoningEffort, RequestLimits, Role,
    Sampling, StreamOptions,
};
use hypellm_core::error::RouterError;
use hypellm_core::target::Capability;
use wire_json::Value;

use super::openai::{ParseContext, effective_quality_floor, parse_hints, require_model};

/// The top-level fields an artifact job may carry.
const FIELDS: &[&str] = &[
    "model",
    "verb",
    "prompt",
    "params",
    "inputs",
    "options",
    "patience_ms",
    "hypellm_routing",
];

/// The deepest `options` may nest.
///
/// Options are a service's own settings — a texture size, a style — and a
/// shallow object carries all of them. A deep one is not a setting.
pub const MAX_OPTIONS_DEPTH: usize = 4;

/// The most entries `options` may have, at any one level.
pub const MAX_OPTIONS_ENTRIES: usize = 64;

/// What an artifact job asks a shim to do, beside the canonical request it is
/// routed by.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactSpec {
    /// What it produces. The alias must serve exactly this verb.
    pub verb: Capability,
    /// The caller's prompt, inert.
    pub prompt: String,
    /// The bounded integers.
    pub params: JobParams,
    /// Inline inputs.
    pub inputs: Vec<ArtifactInput>,
    /// Service-specific options, passed through uninterpreted.
    pub options: Option<Value>,
}

/// One inline input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInput {
    /// Its name.
    pub name: PartName,
    /// Its media type.
    pub media_type: PartMediaType,
    /// Its bytes, standard base64.
    pub data_base64: String,
}

/// Whether a parsed `/v1/jobs` body is an artifact job.
#[must_use]
pub fn is_artifact_body(value: &Value) -> bool {
    value.get("verb").is_some()
}

/// The verbs an artifact job may name: work that produces an artifact. The
/// rest have their own endpoints and their own dialects.
const fn is_artifact_verb(verb: Capability) -> bool {
    match verb {
        Capability::TextToSpeech
        | Capability::TextToMusic
        | Capability::TextToSfx
        | Capability::TextToImage
        | Capability::TextToVideo
        | Capability::ImageToVideo
        | Capability::AudioToVideo
        | Capability::Lipsync
        | Capability::ImageTo3d
        | Capability::TextToMotion => true,
        Capability::Chat
        | Capability::Vision
        | Capability::Document
        | Capability::Embeddings
        | Capability::Rerank => false,
    }
}

fn bad(detail: &str, param: &'static str) -> RouterError {
    RouterError::invalid_request(detail).with_param(param)
}

/// Parse an artifact job.
///
/// Returns the request it is routed by — `Operation::Job`, the prompt as its
/// one message, nothing else a router reads — the spec the shim is sent, and
/// the patience the caller asked for, if any.
///
/// # Errors
///
/// An `invalid_request` naming the field at fault.
pub fn parse_artifact_request(
    value: &Value,
    context: &ParseContext,
) -> Result<(CanonicalRequest, ArtifactSpec, Option<u64>), RouterError> {
    let Some(object) = value.as_object() else {
        return Err(RouterError::invalid_request("a job body must be a JSON object"));
    };
    for (key, _) in object.iter() {
        if !FIELDS.contains(&key) {
            return Err(RouterError::invalid_request(&format!(
                "an artifact job does not take '{}'",
                key.chars().take(64).collect::<String>()
            )));
        }
    }

    let model = require_model(value)?;
    let verb = value
        .get("verb")
        .and_then(Value::as_str)
        .and_then(Capability::parse)
        .filter(|verb| is_artifact_verb(*verb))
        .ok_or_else(|| bad("'verb' must name an artifact verb, such as text-to-music", "verb"))?;
    let prompt = match value.get("prompt") {
        None | Some(Value::Null) => String::new(),
        Some(v) => v
            .as_str()
            .ok_or_else(|| bad("'prompt' must be a string", "prompt"))?
            .to_owned(),
    };
    let params = parse_params(value.get("params"))?;
    let inputs = parse_inputs(value.get("inputs"))?;
    let options = match value.get("options") {
        None | Some(Value::Null) => None,
        Some(options @ Value::Object(_)) => {
            if !shallow(options, 0) {
                return Err(bad(
                    "'options' may nest at most four levels, with at most 64 entries at each",
                    "options",
                ));
            }
            Some(options.clone())
        }
        Some(_) => return Err(bad("'options' must be an object", "options")),
    };
    let patience = match value.get("patience_ms") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|ms| *ms > 0)
                .ok_or_else(|| bad("'patience_ms' must be a positive integer", "patience_ms"))?,
        ),
    };
    if prompt.is_empty() && inputs.is_empty() {
        return Err(RouterError::invalid_request(
            "an artifact job needs a prompt, an input, or both",
        ));
    }

    let request = CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol: ClientProtocol::Native,
        operation: Operation::Job,
        requested_model: model,
        // The prompt rides as the request's one message so the routing
        // filters that read text — none of which can change a job's target —
        // see what the caller sent. Inputs do not: they are the shim's
        // business, and routing on their bytes would be reading them.
        messages: vec![Message::text(Role::User, prompt.clone())],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: None,
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            min_quality_class: effective_quality_floor(value, context),
            residency: context.residency.clone(),
        },
        stream: StreamOptions::default(),
        hints: parse_hints(value, context)?,
    };
    let spec = ArtifactSpec {
        verb,
        prompt,
        params,
        inputs,
        options,
    };
    Ok((request, spec, patience))
}

/// The most a duration may ask for: a day.
const MAX_DURATION_MS: u64 = 86_400_000;
/// The most steps, pixels per side, and outputs a job may ask for.
const MAX_STEPS: u64 = 10_000;
const MAX_PIXELS: u64 = 16_384;
const MAX_COUNT: u64 = 64;

fn parse_params(raw: Option<&Value>) -> Result<JobParams, RouterError> {
    let object = match raw {
        None | Some(Value::Null) => return Ok(JobParams::default()),
        Some(Value::Object(object)) => object,
        Some(_) => return Err(bad("'params' must be an object", "params")),
    };
    let mut params = JobParams::default();
    for (key, value) in object.iter() {
        let number = value
            .as_u64()
            .ok_or_else(|| bad("each param must be a non-negative integer", "params"))?;
        let within = |max: u64| -> Result<u64, RouterError> {
            if number <= max {
                Ok(number)
            } else {
                Err(bad("a param is beyond what one job may ask for", "params"))
            }
        };
        let small = |max: u64| -> Result<Option<u32>, RouterError> {
            within(max).map(|n| u32::try_from(n).ok())
        };
        match key {
            "duration_ms" => params.duration_ms = Some(within(MAX_DURATION_MS)?),
            "seed" => params.seed = Some(number),
            "steps" => params.steps = small(MAX_STEPS)?,
            "width" => params.width = small(MAX_PIXELS)?,
            "height" => params.height = small(MAX_PIXELS)?,
            "count" => params.count = small(MAX_COUNT)?,
            _ => {
                return Err(bad(
                    "params are duration_ms, seed, steps, width, height and count; anything else \
                     goes in 'options'",
                    "params",
                ));
            }
        }
    }
    Ok(params)
}

fn parse_inputs(raw: Option<&Value>) -> Result<Vec<ArtifactInput>, RouterError> {
    let list = match raw {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err(bad("'inputs' must be a list", "inputs")),
    };
    if list.len() > MAX_INPUTS {
        return Err(bad("a job carries at most four inputs", "inputs"));
    }
    let mut inputs: Vec<ArtifactInput> = Vec::with_capacity(list.len());
    for item in list {
        let Some(object) = item.as_object() else {
            return Err(bad("each input must be an object", "inputs"));
        };
        if object
            .iter()
            .any(|(key, _)| !matches!(key, "name" | "media_type" | "data"))
        {
            return Err(bad(
                "an input carries name, media_type and data only; a URL or a path is not taken",
                "inputs",
            ));
        }
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .and_then(PartName::parse)
            .ok_or_else(|| bad("an input's name is 1-64 characters of [A-Za-z0-9_-]", "inputs"))?;
        if inputs.iter().any(|earlier| earlier.name == name) {
            return Err(bad("two inputs share a name", "inputs"));
        }
        let media_type = item
            .get("media_type")
            .and_then(Value::as_str)
            .and_then(PartMediaType::parse)
            .ok_or_else(|| bad("an input's media_type is not one a job takes", "inputs"))?;
        let data = item
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| is_base64(data))
            .ok_or_else(|| bad("an input's data must be standard, padded base64", "inputs"))?;
        inputs.push(ArtifactInput {
            name,
            media_type,
            data_base64: data.to_owned(),
        });
    }
    Ok(inputs)
}

/// Whether `text` is non-empty, standard, padded base64.
fn is_base64(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    !text.is_empty()
        && text.len() % 4 == 0
        && text.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Whether `value` nests no deeper than [`MAX_OPTIONS_DEPTH`] below `depth`
/// with at most [`MAX_OPTIONS_ENTRIES`] at each level. Recursion is bounded by
/// the depth checked first.
fn shallow(value: &Value, depth: usize) -> bool {
    match value {
        Value::Object(object) => {
            depth < MAX_OPTIONS_DEPTH
                && object.len() <= MAX_OPTIONS_ENTRIES
                && object.iter().all(|(_, v)| shallow(v, depth + 1))
        }
        Value::Array(list) => {
            depth < MAX_OPTIONS_DEPTH
                && list.len() <= MAX_OPTIONS_ENTRIES
                && list.iter().all(|v| shallow(v, depth + 1))
        }
        _ => true,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    use super::*;
    use hypellm_core::ids::{PrincipalId, RequestId, TenantId};
    use hypellm_core::time::{Deadline, TestClock};
    use wire_json::{Limits, parse};

    fn context() -> ParseContext {
        ParseContext {
            request_id: RequestId::from_u128(1),
            tenant: TenantId::new("acme").unwrap(),
            principal: PrincipalId::new("svc:caller").unwrap(),
            deadline: Deadline::after(&TestClock::new(), std::time::Duration::from_secs(60)),
            hints_permitted: false,
            residency: None,
            max_cost_class: None,
            min_quality_class: None,
            document_limits: crate::protocol::DocumentLimits {
                max_documents: 4,
                max_document_bytes: 1024,
                max_inline_bytes: 1024,
            },
        }
    }

    fn parsed(body: &str) -> Result<(CanonicalRequest, ArtifactSpec, Option<u64>), RouterError> {
        let value = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
        parse_artifact_request(&value, &context())
    }

    #[test]
    fn an_artifact_job_routes_as_a_job_and_carries_its_spec() {
        let (request, spec, patience) = parsed(
            r#"{"model":"mesh","verb":"image-to-3d","prompt":"a chair",
                "params":{"seed":7,"steps":32},
                "inputs":[{"name":"image","media_type":"image/png","data":"iVBORw0KGgo="}],
                "options":{"texture_size":1024},"patience_ms":600000}"#,
        )
        .unwrap();
        assert_eq!(request.operation, Operation::Job);
        assert_eq!(request.requested_model.as_str(), "mesh");
        assert_eq!(request.estimated_total_tokens(), 0, "a job is not metered in tokens");
        assert!(request.inputs.is_empty(), "inputs are the shim's, not routing's");
        assert_eq!(spec.verb, Capability::ImageTo3d);
        assert_eq!(spec.params.seed, Some(7));
        assert_eq!(spec.inputs[0].name.as_str(), "image");
        assert_eq!(patience, Some(600_000));
    }

    #[test]
    fn a_job_body_names_no_url_no_path_and_no_field_it_does_not_know() {
        for body in [
            r#"{"model":"m","verb":"text-to-image","prompt":"x","callback_url":"http://evil"}"#,
            r#"{"model":"m","verb":"image-to-3d","inputs":[{"name":"image","media_type":"image/png","url":"http://x/y.png"}]}"#,
            r#"{"model":"m","verb":"image-to-3d","inputs":[{"name":"image","media_type":"image/png","data":"iVBORw0KGgo=","path":"/etc/passwd"}]}"#,
            r#"{"model":"m","verb":"image-to-3d","inputs":[{"name":"../x","media_type":"image/png","data":"iVBORw0KGgo="}]}"#,
            r#"{"model":"m","verb":"image-to-3d","inputs":[{"name":"image","media_type":"text/html","data":"iVBORw0KGgo="}]}"#,
            r#"{"model":"m","verb":"image-to-3d","inputs":[{"name":"image","media_type":"image/png","data":"/etc/passwd"}]}"#,
            r#"{"model":"m","verb":"text-to-image","prompt":"x","params":{"cfg":7}}"#,
            r#"{"model":"m","verb":"text-to-image","prompt":"x","params":{"width":100000}}"#,
            r#"{"model":"m","verb":"chat","prompt":"x"}"#,
            r#"{"model":"m","verb":"teleport","prompt":"x"}"#,
            r#"{"model":"m","verb":"text-to-image"}"#,
            r#"{"model":"m","verb":"text-to-image","prompt":"x","options":{"a":{"b":{"c":{"d":{"e":1}}}}}}"#,
        ] {
            assert!(parsed(body).is_err(), "{body}");
        }
    }

    #[test]
    fn a_chat_job_is_not_an_artifact_job() {
        let chat = parse(br#"{"model":"m","messages":[]}"#, &Limits::DEFAULT).unwrap();
        assert!(!is_artifact_body(&chat));
        let artifact = parse(br#"{"model":"m","verb":"text-to-music"}"#, &Limits::DEFAULT).unwrap();
        assert!(is_artifact_body(&artifact));
    }
}
