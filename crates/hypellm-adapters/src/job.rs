//! The `job` family: the first-party shim protocol (orchestration §11.3).
//!
//! The fleet runs generative services the router could not reach directly —
//! one behind a node graph, one behind a Gradio queue, one a command-line
//! tool. Each gets a *shim* beside it, a small HTTP server that speaks this one
//! protocol, and to the router a shim is a provider like any other: an
//! administrator-configured destination, untrusted, read with bounded parsers.
//!
//! ```text
//! GET    /job/v1/health                 → 200 { verbs[] } once loaded; 503 before
//! POST   /job/v1/jobs                   → 202 { id }
//! GET    /job/v1/jobs/{id}              → { state, progress_permille, eta_ms, elapsed_ms, error, parts[] }
//! GET    /job/v1/jobs/{id}/parts/{name} → bytes, with Content-Type and Content-Length
//! DELETE /job/v1/jobs/{id}              → 202 { stopped }
//! ```
//!
//! # What keeps it narrow
//!
//! - **Identifiers are validated before they become paths.** A job id and a
//!   part name are 1–64 characters of `[A-Za-z0-9_-]`, checked when a reply is
//!   parsed and nowhere later, so a hostile shim cannot put `/`, `..`, `%` or
//!   `?` into the next request's path. [`ProviderJobId`] and [`PartName`]
//!   cannot be constructed any other way, and every path builder takes them.
//! - **Vocabularies are closed.** A state, an error, or a media type outside
//!   its set is a protocol violation, not a value to pass along.
//! - **Inputs travel inline.** An input is base64 in the submit body. The
//!   router sends no URL and no path, so no client value can name a file or a
//!   host on the service's side.
//! - **A shim authenticates the router.** Unlike SemIf, every request carries a
//!   bearer credential; [`JobAdapter::encode_headers`] takes one by value, not
//!   by `Option`, so there is no path that sends without it.
//!
//! Like every adapter this is pure: it builds paths, headers and bodies and
//! parses replies, and performs no I/O.

use crate::contract::{
    Adapter, CredentialHandle, ErrorClassification, MAX_REQUEST_BYTES, RequestMeta,
    SensitiveHeaders, ValidationFailure, ValidationResult, class_for_status,
};
use hypellm_core::canonical::{CanonicalRequest, Operation};
use hypellm_core::event::{CanonicalEvent, UpstreamErrorClass};
use hypellm_core::sensitive::Capped;
use hypellm_core::target::{Capabilities, Capability, ProviderFamily};
use wire_json::{Limits, Object, Value, parse, to_vec};

/// The longest job identifier or part name a shim may use.
pub const MAX_IDENTIFIER_BYTES: usize = 64;

/// The most parts one job may produce.
pub const MAX_PARTS: usize = 4;

/// The most inline inputs one job may carry.
pub const MAX_INPUTS: usize = 4;

/// The health path.
pub const HEALTH_PATH: &str = "/job/v1/health";

/// The submit path.
pub const SUBMIT_PATH: &str = "/job/v1/jobs";

/// Bounds on a shim's control replies — status, accepted, health, cancelled.
///
/// Small on purpose: none of them carries content, and a shim that answered a
/// status poll with megabytes is broken or hostile either way.
const REPLY_LIMITS: Limits = Limits {
    max_depth: 4,
    max_string_bytes: 1024,
    max_input_bytes: 16 * 1024,
    max_array_items: 64,
    max_object_entries: 32,
    reject_duplicate_keys: true,
};

/// Whether `raw` is a well-formed shim identifier.
fn is_identifier(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_IDENTIFIER_BYTES
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A shim's job identifier, validated before it can reach a request path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderJobId(String);

impl ProviderJobId {
    /// Parse a shim-supplied identifier.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        is_identifier(raw).then(|| Self(raw.to_owned()))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A part's name, validated before it can reach a request path or a file name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartName(String);

impl PartName {
    /// Parse a shim- or caller-supplied name.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        is_identifier(raw).then(|| Self(raw.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A job's state, as a shim reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimState {
    /// Accepted, not started.
    Queued,
    /// Generating.
    Running,
    /// Finished, with parts to fetch.
    Succeeded,
    /// Finished without parts, with an error.
    Failed,
    /// Stopped by a cancel.
    Cancelled,
}

impl ShimState {
    /// Parse the wire token.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    /// The wire token.
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

/// Why a shim's job failed, or why it refused one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimError {
    /// The request was wrong; trying again will not help.
    InvalidInput,
    /// The service ran out of accelerator memory.
    OutOfMemory,
    /// The service has not loaded its model.
    NotReady,
    /// Anything else.
    Internal,
}

impl ShimError {
    /// Parse the wire token.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "invalid_input" => Self::InvalidInput,
            "out_of_memory" => Self::OutOfMemory,
            "not_ready" => Self::NotReady,
            "internal" => Self::Internal,
            _ => return None,
        })
    }

    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::OutOfMemory => "out_of_memory",
            Self::NotReady => "not_ready",
            Self::Internal => "internal",
        }
    }

    /// Whether the job may wait for capacity and try again, as it would for
    /// any other shortage (specification 26.10). Nothing client-visible exists
    /// before a job succeeds, so a retry can never splice output.
    #[must_use]
    pub const fn waits_for_capacity(self) -> bool {
        matches!(self, Self::OutOfMemory | Self::NotReady)
    }

    /// The router's class for it.
    #[must_use]
    pub const fn class(self) -> UpstreamErrorClass {
        match self {
            Self::InvalidInput => UpstreamErrorClass::InvalidRequest,
            Self::OutOfMemory | Self::NotReady | Self::Internal => UpstreamErrorClass::ServerError,
        }
    }
}

/// The media types a part may have.
///
/// Nothing scriptable: no `text/html`, no `image/svg+xml`. A result is served
/// back to a browser, and a type that could execute there is not in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartMediaType {
    /// FLAC audio.
    AudioFlac,
    /// WAV audio.
    AudioWav,
    /// MP4 video.
    VideoMp4,
    /// PNG image.
    ImagePng,
    /// WebP image.
    ImageWebp,
    /// Binary glTF.
    ModelGltfBinary,
    /// A format with no registered type: PLY, NPZ, BVH.
    OctetStream,
}

impl PartMediaType {
    /// Parse a media type, exactly: no parameters, no other case.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "audio/flac" => Self::AudioFlac,
            "audio/wav" => Self::AudioWav,
            "video/mp4" => Self::VideoMp4,
            "image/png" => Self::ImagePng,
            "image/webp" => Self::ImageWebp,
            "model/gltf-binary" => Self::ModelGltfBinary,
            "application/octet-stream" => Self::OctetStream,
            _ => return None,
        })
    }

    /// The media type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AudioFlac => "audio/flac",
            Self::AudioWav => "audio/wav",
            Self::VideoMp4 => "video/mp4",
            Self::ImagePng => "image/png",
            Self::ImageWebp => "image/webp",
            Self::ModelGltfBinary => "model/gltf-binary",
            Self::OctetStream => "application/octet-stream",
        }
    }
}

/// One part a succeeded job produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartInfo {
    /// Its name.
    pub name: PartName,
    /// Its media type.
    pub media_type: PartMediaType,
    /// Its declared length, which the fetch is held to exactly.
    pub bytes: u64,
}

/// A job's status, as a shim reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimStatus {
    /// Where the job is.
    pub state: ShimState,
    /// Progress in permille, at most 1000.
    pub progress_permille: u32,
    /// What the shim expects still to need, in milliseconds.
    pub eta_ms: u64,
    /// Accelerator time spent so far, in milliseconds.
    pub elapsed_ms: u64,
    /// Why it failed: present exactly when `state` is `failed`.
    pub error: Option<ShimError>,
    /// What it produced: present, one to [`MAX_PARTS`] with distinct names,
    /// exactly when `state` is `succeeded`.
    pub parts: Vec<PartInfo>,
}

/// The bounded integers a job carries, which the router reads for cost and
/// validation. Everything else the service takes goes in `options`,
/// uninterpreted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobParams {
    /// Length of the output, for audio, video and motion.
    pub duration_ms: Option<u64>,
    /// The generator's seed.
    pub seed: Option<u64>,
    /// Sampler steps.
    pub steps: Option<u32>,
    /// Output width, in pixels.
    pub width: Option<u32>,
    /// Output height, in pixels.
    pub height: Option<u32>,
    /// How many outputs: images, meshes.
    pub count: Option<u32>,
}

/// One inline input.
#[derive(Debug, Clone, Copy)]
pub struct JobInput<'a> {
    /// Its name, which the service's own interface gives meaning to.
    pub name: &'a PartName,
    /// Its media type.
    pub media_type: PartMediaType,
    /// Its bytes, standard base64, already validated by the client parser.
    pub data_base64: &'a str,
}

/// Everything a submit carries.
#[derive(Debug, Clone, Copy)]
pub struct JobSubmission<'a> {
    /// What the job produces.
    pub verb: Capability,
    /// The caller's prompt: inert data, passed through.
    pub prompt: &'a str,
    /// The bounded integers.
    pub params: JobParams,
    /// Inline inputs.
    pub inputs: &'a [JobInput<'a>],
    /// Service-specific options, an object the client parser already bounded.
    pub options: Option<&'a Value>,
    /// The router's request identifier, for correlation in the shim's log.
    pub request_id: &'a str,
}

/// The shim protocol's codec.
#[derive(Debug, Clone, Copy)]
pub struct JobAdapter;

impl JobAdapter {
    /// The status path for a job.
    #[must_use]
    pub fn status_path(id: &ProviderJobId) -> String {
        format!("{SUBMIT_PATH}/{}", id.as_str())
    }

    /// The cancel path for a job: the status path, with `DELETE`.
    #[must_use]
    pub fn cancel_path(id: &ProviderJobId) -> String {
        Self::status_path(id)
    }

    /// The path of one part.
    #[must_use]
    pub fn part_path(id: &ProviderJobId, part: &PartName) -> String {
        format!("{SUBMIT_PATH}/{}/parts/{}", id.as_str(), part.as_str())
    }

    /// The headers for every shim request: the router's bearer credential,
    /// always.
    #[must_use]
    pub fn encode_headers(credential: &CredentialHandle<'_>) -> SensitiveHeaders {
        let mut headers = SensitiveHeaders::new();
        headers.push("content-type", "application/json");
        headers.push("accept", "application/json");
        // `is_usable_credential` refused anything that is not header-safe
        // text where the credential was loaded, so this cannot be `None` for
        // a credential that reached an adapter.
        let secret = credential.expose_str().unwrap_or_default();
        headers.push_secret("authorization", format!("Bearer {secret}"));
        headers
    }

    /// Serialize a submit.
    ///
    /// # Errors
    ///
    /// A [`ValidationFailure`] for more inputs than [`MAX_INPUTS`], two inputs
    /// with one name, input data that is not base64, or a body beyond
    /// [`MAX_REQUEST_BYTES`].
    pub fn encode_submit(submission: &JobSubmission<'_>) -> Result<Vec<u8>, ValidationFailure> {
        if submission.inputs.len() > MAX_INPUTS {
            return Err(ValidationFailure::new(
                "too_many_inputs",
                "a job carries at most four inputs",
            )
            .with_param("inputs"));
        }
        let mut inputs = Vec::with_capacity(submission.inputs.len());
        for (i, input) in submission.inputs.iter().enumerate() {
            if submission
                .inputs
                .iter()
                .take(i)
                .any(|earlier| earlier.name == input.name)
            {
                return Err(ValidationFailure::new(
                    "duplicate_input",
                    "two inputs share a name",
                )
                .with_param("inputs"));
            }
            if !is_base64(input.data_base64) {
                return Err(ValidationFailure::new(
                    "invalid_input_data",
                    "input data must be standard base64",
                )
                .with_param("inputs"));
            }
            let mut object = Object::new();
            object.push("name", Value::from(input.name.as_str()));
            object.push("media_type", Value::from(input.media_type.as_str()));
            object.push("data", Value::from(input.data_base64));
            inputs.push(Value::Object(object));
        }

        let p = submission.params;
        let mut params = Object::new();
        for (name, value) in [
            ("duration_ms", p.duration_ms),
            ("seed", p.seed),
            ("steps", p.steps.map(u64::from)),
            ("width", p.width.map(u64::from)),
            ("height", p.height.map(u64::from)),
            ("count", p.count.map(u64::from)),
        ] {
            if let Some(value) = value {
                params.push(name, Value::from(value));
            }
        }

        let mut root = Object::new();
        root.push("verb", Value::from(submission.verb.as_str()));
        root.push("prompt", Value::from(submission.prompt));
        root.push("params", Value::Object(params));
        root.push("inputs", Value::Array(inputs));
        if let Some(options) = submission.options {
            root.push("options", options.clone());
        }
        root.push("request_id", Value::from(submission.request_id));
        let body = to_vec(&Value::Object(root));
        if body.len() > MAX_REQUEST_BYTES {
            return Err(ValidationFailure::new(
                "request_too_large",
                "the job is larger than this router will send",
            ));
        }
        Ok(body)
    }

    /// Decode a health reply: the verbs the shim serves, once its model is
    /// loaded.
    ///
    /// A verb this router does not know is left out rather than refused — it
    /// can be served by nothing here, and a shim newer than the router is not
    /// broken.
    ///
    /// # Errors
    ///
    /// The shim is not ready (`503`), or the reply is not the shape above.
    pub fn decode_health(status: u16, body: &[u8]) -> Result<Vec<Capability>, ErrorClassification> {
        if status != 200 {
            return Err(Self::classify(status, body));
        }
        let value = parse(body, &REPLY_LIMITS).map_err(|_| violation("health reply is not JSON"))?;
        let verbs = value
            .get("verbs")
            .and_then(Value::as_array)
            .ok_or_else(|| violation("health reply lacks verbs"))?;
        let mut out = Vec::new();
        for verb in verbs {
            let token = verb.as_str().ok_or_else(|| violation("a verb is not a string"))?;
            if let Some(capability) = Capability::parse(token) {
                if !out.contains(&capability) {
                    out.push(capability);
                }
            }
        }
        Ok(out)
    }

    /// Decode a submit reply: the shim's identifier for the job.
    ///
    /// # Errors
    ///
    /// A refusal, classified; or a reply whose identifier is not well formed.
    pub fn decode_accepted(status: u16, body: &[u8]) -> Result<ProviderJobId, ErrorClassification> {
        if status != 202 {
            return Err(Self::classify(status, body));
        }
        let value =
            parse(body, &REPLY_LIMITS).map_err(|_| violation("submit reply is not JSON"))?;
        value
            .get("id")
            .and_then(Value::as_str)
            .and_then(ProviderJobId::parse)
            .ok_or_else(|| violation("submit reply carries no well-formed job id"))
    }

    /// Decode a status reply.
    ///
    /// # Errors
    ///
    /// A refusal, classified; or a reply outside the protocol — an unknown
    /// state, error or media type, progress past 1000, an error on a job that
    /// did not fail, parts on a job that did not succeed, more than
    /// [`MAX_PARTS`] parts, or two with one name.
    pub fn decode_status(status: u16, body: &[u8]) -> Result<ShimStatus, ErrorClassification> {
        if status != 200 {
            return Err(Self::classify(status, body));
        }
        let value =
            parse(body, &REPLY_LIMITS).map_err(|_| violation("status reply is not JSON"))?;
        let state = value
            .get("state")
            .and_then(Value::as_str)
            .and_then(ShimState::parse)
            .ok_or_else(|| violation("status reply carries no known state"))?;
        let number = |key: &str| -> Result<u64, ErrorClassification> {
            match value.get(key) {
                None | Some(Value::Null) => Ok(0),
                Some(v) => v
                    .as_u64()
                    .ok_or_else(|| violation("a status number is not a non-negative integer")),
            }
        };
        let progress_permille = u32::try_from(number("progress_permille")?)
            .ok()
            .filter(|p| *p <= 1_000)
            .ok_or_else(|| violation("progress is past 1000 permille"))?;
        let eta_ms = number("eta_ms")?;
        let elapsed_ms = number("elapsed_ms")?;
        let error = match value.get("error") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_str()
                    .and_then(ShimError::parse)
                    .ok_or_else(|| violation("status reply carries an unknown error"))?,
            ),
        };
        if error.is_some() != (state == ShimState::Failed) {
            return Err(violation("an error is reported exactly when a job failed"));
        }
        let parts = match value.get("parts") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => {
                let list = v
                    .as_array()
                    .ok_or_else(|| violation("parts is not a list"))?;
                if list.len() > MAX_PARTS {
                    return Err(violation("a job reports more than four parts"));
                }
                let mut parts: Vec<PartInfo> = Vec::with_capacity(list.len());
                for item in list {
                    let part = decode_part(item)?;
                    if parts.iter().any(|p| p.name == part.name) {
                        return Err(violation("two parts share a name"));
                    }
                    parts.push(part);
                }
                parts
            }
        };
        if (state == ShimState::Succeeded) == parts.is_empty() {
            return Err(violation("parts are reported exactly when a job succeeded"));
        }
        Ok(ShimStatus {
            state,
            progress_permille,
            eta_ms,
            elapsed_ms,
            error,
            parts,
        })
    }

    /// Decode a cancel reply: whether the service stopped the work, or will
    /// only stop when the generation ends.
    ///
    /// # Errors
    ///
    /// A refusal, classified; or a reply without `stopped`.
    pub fn decode_cancelled(status: u16, body: &[u8]) -> Result<bool, ErrorClassification> {
        if status != 202 {
            return Err(Self::classify(status, body));
        }
        let value =
            parse(body, &REPLY_LIMITS).map_err(|_| violation("cancel reply is not JSON"))?;
        match value.get("stopped") {
            Some(Value::Bool(stopped)) => Ok(*stopped),
            _ => Err(violation("cancel reply carries no stopped flag")),
        }
    }

    /// Check a part's response head against what the status declared.
    ///
    /// The fetch is held to the declared type and length exactly: a part whose
    /// head says otherwise fails the job before a byte of it is kept.
    ///
    /// # Errors
    ///
    /// A non-`200`, a missing or different `Content-Type`, or a missing or
    /// different `Content-Length`.
    pub fn check_part_head(
        declared: &PartInfo,
        status: u16,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<(), ErrorClassification> {
        if status != 200 {
            return Err(Self::classify(status, b""));
        }
        if content_type.and_then(PartMediaType::parse) != Some(declared.media_type) {
            return Err(violation("a part's type is not the type its status declared"));
        }
        if content_length != Some(declared.bytes) {
            return Err(violation("a part's length is not the length its status declared"));
        }
        Ok(())
    }

    /// Classify a refusal from its status and, when it carries one, the
    /// shim's error token.
    #[must_use]
    pub fn classify(status: u16, body: &[u8]) -> ErrorClassification {
        let shim = parse(body, &REPLY_LIMITS)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).and_then(ShimError::parse));
        let class = shim.map_or_else(|| class_for_status(status), ShimError::class);
        ErrorClassification {
            class,
            provider_code: shim.map(|e| Capped::new(e.as_str(), 64)),
            safe_detail: Capped::new(
                shim.map_or("the job service refused the request", |e| match e {
                    ShimError::InvalidInput => "the job service refused the input",
                    ShimError::OutOfMemory => "the job service ran out of memory",
                    ShimError::NotReady => "the job service has not loaded its model",
                    ShimError::Internal => "the job service failed",
                }),
                200,
            ),
            retry_after_secs: None,
        }
    }

    /// The shim's error token in a classification, if it carried one.
    #[must_use]
    pub fn shim_error(classification: &ErrorClassification) -> Option<ShimError> {
        classification
            .provider_code
            .as_ref()
            .and_then(|code| ShimError::parse(code.as_str()))
    }
}

fn decode_part(item: &Value) -> Result<PartInfo, ErrorClassification> {
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .and_then(PartName::parse)
        .ok_or_else(|| violation("a part's name is not well formed"))?;
    let media_type = item
        .get("media_type")
        .and_then(Value::as_str)
        .and_then(PartMediaType::parse)
        .ok_or_else(|| violation("a part's media type is not in the protocol's set"))?;
    let bytes = item
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| violation("a part declares no length"))?;
    Ok(PartInfo {
        name,
        media_type,
        bytes,
    })
}

/// Whether `text` is standard, padded base64.
fn is_base64(text: &str) -> bool {
    text.len() % 4 == 0
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        && text.trim_end_matches('=').bytes().all(|b| b != b'=')
        && text.len() - text.trim_end_matches('=').len() <= 2
}

fn violation(detail: &str) -> ErrorClassification {
    ErrorClassification {
        class: UpstreamErrorClass::ProtocolViolation,
        provider_code: None,
        safe_detail: Capped::new(detail, 200),
        retry_after_secs: None,
    }
}

/// The family's single-exchange adapter, which serves nothing.
///
/// [`crate::adapter_for`] is total over [`ProviderFamily`], and a chat request
/// can be routed to a `job` provider by a misconfigured alias. It is refused
/// here, before a byte is sent: a shim speaks [`JobAdapter`]'s protocol only.
#[derive(Debug, Clone, Copy)]
pub struct JobFamilyAdapter;

impl JobFamilyAdapter {
    fn refusal() -> ValidationFailure {
        ValidationFailure::new(
            "operation_unsupported",
            "a job service serves /v1/jobs only",
        )
    }
}

impl Adapter for JobFamilyAdapter {
    fn family(&self) -> ProviderFamily {
        ProviderFamily::Job
    }

    fn path_for(&self, request: &CanonicalRequest) -> Result<&'static str, ValidationFailure> {
        // Named individually, so a new operation is a compile error here and
        // somebody decides whether a job shim can serve it.
        match request.operation {
            // A job is served through `JobAdapter`, never as one exchange.
            Operation::Chat
            | Operation::Responses
            | Operation::Embeddings
            | Operation::Rerank
            | Operation::Tokenize
            | Operation::Job => Err(Self::refusal()),
        }
    }

    fn validate(&self, _request: &CanonicalRequest, _capabilities: &Capabilities) -> ValidationResult {
        Err(Self::refusal())
    }

    fn encode_headers(
        &self,
        _credential: Option<&CredentialHandle<'_>>,
        _meta: &RequestMeta<'_>,
    ) -> SensitiveHeaders {
        SensitiveHeaders::new()
    }

    fn encode_request(
        &self,
        _request: &CanonicalRequest,
        _meta: &RequestMeta<'_>,
    ) -> Result<Vec<u8>, ValidationFailure> {
        Err(Self::refusal())
    }

    fn decode_response(&self, status: u16, body: &[u8]) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        Err(JobAdapter::classify(status, body))
    }

    fn decode_stream_event(
        &self,
        _event_name: Option<&str>,
        _data: &str,
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        Err(violation("a job service does not stream"))
    }

    fn is_stream_terminator(&self, _data: &str) -> bool {
        true
    }

    fn classify_error(&self, status: u16, body: &[u8]) -> ErrorClassification {
        JobAdapter::classify(status, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::ids::CredentialRef;

    fn status(body: &str) -> Result<ShimStatus, ErrorClassification> {
        JobAdapter::decode_status(200, body.as_bytes())
    }

    #[test]
    fn an_identifier_that_could_change_a_path_is_never_accepted() {
        for hostile in [
            "", "../x", "a/b", "a%2fb", "a?b", "a#b", "a b", ".", "..", "a\\b", "a\0b", "é",
            &"x".repeat(65),
        ] {
            assert!(ProviderJobId::parse(hostile).is_none(), "{hostile:?}");
            assert!(PartName::parse(hostile).is_none(), "{hostile:?}");
        }
        let id = ProviderJobId::parse("job_01-AB").expect("well formed");
        let part = PartName::parse("mesh").expect("well formed");
        assert_eq!(JobAdapter::status_path(&id), "/job/v1/jobs/job_01-AB");
        assert_eq!(JobAdapter::part_path(&id, &part), "/job/v1/jobs/job_01-AB/parts/mesh");
    }

    #[test]
    fn a_submit_reply_with_a_path_in_its_id_is_a_protocol_violation() {
        let refused = JobAdapter::decode_accepted(202, br#"{"id":"../../admin"}"#).unwrap_err();
        assert_eq!(refused.class, UpstreamErrorClass::ProtocolViolation);
        let accepted = JobAdapter::decode_accepted(202, br#"{"id":"abc123"}"#).unwrap();
        assert_eq!(accepted.as_str(), "abc123");
    }

    #[test]
    fn a_succeeded_job_reports_its_parts_and_nothing_else_does() {
        let done = status(
            r#"{"state":"succeeded","progress_permille":1000,"elapsed_ms":42000,
                "parts":[{"name":"mesh","media_type":"model/gltf-binary","bytes":1024},
                         {"name":"points","media_type":"application/octet-stream","bytes":2048}]}"#,
        )
        .unwrap();
        assert_eq!(done.parts.len(), 2);
        assert_eq!(done.elapsed_ms, 42_000);
        assert_eq!(done.parts[0].media_type, PartMediaType::ModelGltfBinary);

        let running = status(r#"{"state":"running","progress_permille":250,"eta_ms":9000}"#).unwrap();
        assert!(running.parts.is_empty());
        assert_eq!(running.error, None);

        for broken in [
            // Succeeded with nothing to fetch.
            r#"{"state":"succeeded"}"#,
            // Parts before success.
            r#"{"state":"running","parts":[{"name":"a","media_type":"image/png","bytes":1}]}"#,
            // Failed without saying why, and an error on a job that did not fail.
            r#"{"state":"failed"}"#,
            r#"{"state":"running","error":"internal"}"#,
        ] {
            assert_eq!(
                status(broken).unwrap_err().class,
                UpstreamErrorClass::ProtocolViolation,
                "{broken}"
            );
        }
    }

    #[test]
    fn closed_vocabularies_refuse_what_they_do_not_name() {
        for broken in [
            r#"{"state":"paused"}"#,
            r#"{"state":"failed","error":"disk_full"}"#,
            r#"{"state":"running","progress_permille":1001}"#,
            r#"{"state":"succeeded","parts":[{"name":"page","media_type":"text/html","bytes":1}]}"#,
            r#"{"state":"succeeded","parts":[{"name":"logo","media_type":"image/svg+xml","bytes":1}]}"#,
            r#"{"state":"succeeded","parts":[{"name":"a","media_type":"IMAGE/PNG","bytes":1}]}"#,
            r#"{"state":"succeeded","parts":[{"name":"a","media_type":"image/png; x=1","bytes":1}]}"#,
        ] {
            assert_eq!(
                status(broken).unwrap_err().class,
                UpstreamErrorClass::ProtocolViolation,
                "{broken}"
            );
        }
    }

    #[test]
    fn a_job_has_at_most_four_parts_with_distinct_names() {
        let part = |n: &str| format!(r#"{{"name":"{n}","media_type":"image/png","bytes":1}}"#);
        let five = format!(
            r#"{{"state":"succeeded","parts":[{}]}}"#,
            ["a", "b", "c", "d", "e"].map(part).join(",")
        );
        assert!(status(&five).is_err());
        let twice = format!(r#"{{"state":"succeeded","parts":[{},{}]}}"#, part("a"), part("a"));
        assert!(status(&twice).is_err());
    }

    #[test]
    fn a_part_is_held_to_the_type_and_length_its_status_declared() {
        let declared = PartInfo {
            name: PartName::parse("song").unwrap(),
            media_type: PartMediaType::AudioFlac,
            bytes: 4096,
        };
        assert!(JobAdapter::check_part_head(&declared, 200, Some("audio/flac"), Some(4096)).is_ok());
        assert!(JobAdapter::check_part_head(&declared, 200, Some("audio/wav"), Some(4096)).is_err());
        assert!(JobAdapter::check_part_head(&declared, 200, Some("audio/flac"), Some(4097)).is_err());
        assert!(JobAdapter::check_part_head(&declared, 200, Some("audio/flac"), None).is_err());
        assert!(JobAdapter::check_part_head(&declared, 200, Some("text/html"), Some(4096)).is_err());
    }

    #[test]
    fn capacity_errors_wait_and_input_errors_end_the_job() {
        let oom = JobAdapter::classify(507, br#"{"error":"out_of_memory"}"#);
        assert_eq!(JobAdapter::shim_error(&oom), Some(ShimError::OutOfMemory));
        assert!(ShimError::OutOfMemory.waits_for_capacity());
        assert!(ShimError::NotReady.waits_for_capacity());
        let bad = JobAdapter::classify(400, br#"{"error":"invalid_input"}"#);
        assert_eq!(bad.class, UpstreamErrorClass::InvalidRequest);
        assert!(!ShimError::InvalidInput.waits_for_capacity());
        assert!(!ShimError::Internal.waits_for_capacity());
        // An unknown token is not trusted as one of ours.
        let odd = JobAdapter::classify(500, br#"{"error":"try_again_later"}"#);
        assert_eq!(JobAdapter::shim_error(&odd), None);
    }

    #[test]
    fn every_shim_request_carries_the_bearer_and_redacts_it() {
        let reference = CredentialRef::new("cred_shim").unwrap();
        let handle = CredentialHandle::new(&reference, b"shim-secret");
        let headers = JobAdapter::encode_headers(&handle);
        assert!(headers.iter().any(|(n, v)| n == "authorization" && v == "Bearer shim-secret"));
        assert!(!format!("{headers:?}").contains("shim-secret"));
    }

    #[test]
    fn a_submit_carries_inputs_inline_and_refuses_what_it_cannot_send() {
        let image = PartName::parse("keyframe").unwrap();
        let input = JobInput {
            name: &image,
            media_type: PartMediaType::ImagePng,
            data_base64: "iVBORw0KGgo=",
        };
        let submission = JobSubmission {
            verb: Capability::ImageTo3d,
            prompt: "a chair",
            params: JobParams {
                seed: Some(7),
                ..JobParams::default()
            },
            inputs: &[input],
            options: None,
            request_id: "r1",
        };
        let body = JobAdapter::encode_submit(&submission).unwrap();
        let value = parse(&body, &Limits::DEFAULT).unwrap();
        assert_eq!(value.get("verb").and_then(Value::as_str), Some("image-to-3d"));
        let inputs = value.get("inputs").and_then(Value::as_array).unwrap();
        assert_eq!(inputs[0].get("data").and_then(Value::as_str), Some("iVBORw0KGgo="));
        assert_eq!(
            value.get("params").and_then(|p| p.get("seed")).and_then(Value::as_u64),
            Some(7)
        );

        let not_base64 = JobInput {
            data_base64: "/etc/passwd",
            ..input
        };
        assert!(JobAdapter::encode_submit(&JobSubmission {
            inputs: &[not_base64],
            ..submission
        })
        .is_err());
        assert!(JobAdapter::encode_submit(&JobSubmission {
            inputs: &[input, input],
            ..submission
        })
        .is_err());
        assert!(JobAdapter::encode_submit(&JobSubmission {
            inputs: &[input; 5],
            ..submission
        })
        .is_err());
    }

    #[test]
    fn health_lists_known_verbs_and_a_shim_still_loading_is_not_ready() {
        let verbs =
            JobAdapter::decode_health(200, br#"{"verbs":["image-to-3d","teleport","image-to-3d"]}"#)
                .unwrap();
        assert_eq!(verbs, vec![Capability::ImageTo3d]);
        let loading = JobAdapter::decode_health(503, br#"{"error":"not_ready"}"#).unwrap_err();
        assert_eq!(JobAdapter::shim_error(&loading), Some(ShimError::NotReady));
    }

    #[test]
    fn the_single_exchange_adapter_refuses_every_operation() {
        use hypellm_core::canonical::Operation;
        let adapter = JobFamilyAdapter;
        for operation in [
            Operation::Chat,
            Operation::Responses,
            Operation::Embeddings,
            Operation::Rerank,
            Operation::Tokenize,
        ] {
            let mut request = crate::testing::request_fixture();
            request.operation = operation;
            assert!(adapter.path_for(&request).is_err(), "{operation:?}");
        }
    }
}
