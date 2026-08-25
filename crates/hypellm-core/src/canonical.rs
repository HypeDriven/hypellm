//! The canonical request (specification 5.1).
//!
//! Every client protocol is parsed into this shape before routing, and every
//! provider protocol is generated from it. The router never re-parses a client
//! payload downstream, which is what keeps a provider-specific quirk from
//! becoming a routing input.
//!
//! Two rules shape the types:
//!
//! - **"Unset" is distinct from zero.** Specification 5.1 says so explicitly
//!   for sampling. `temperature: 0.0` means deterministic sampling;
//!   `temperature: None` means "do not send the field". Collapsing them changes
//!   the model's behaviour.
//! - **Prompt content is sensitive.** `Debug` for content, messages, and the
//!   request itself reports shape and size, never text. Specification 10 makes
//!   prompts sensitive by default, and a struct that prints its own prompt will
//!   eventually print it into a panic message.

use crate::ids::{AliasId, PrincipalId, RequestId, TargetId, TenantId};
use crate::time::Deadline;
use core::fmt;

/// The operation being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
    /// Chat completion.
    Chat,
    /// The Responses API shape.
    Responses,
    /// Embedding generation.
    Embeddings,
    /// Tokenisation only.
    Tokenize,
    /// Reranking.
    Rerank,
}

impl Operation {
    /// Stable name used in metrics, policy, and capability declarations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Embeddings => "embeddings",
            Self::Tokenize => "tokenize",
            Self::Rerank => "rerank",
        }
    }

    /// Parse from a policy or configuration token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "chat" => Self::Chat,
            "responses" => Self::Responses,
            "embeddings" => Self::Embeddings,
            "tokenize" => Self::Tokenize,
            "rerank" => Self::Rerank,
            _ => return None,
        })
    }

    /// Whether this operation can stream.
    #[must_use]
    pub const fn can_stream(self) -> bool {
        matches!(self, Self::Chat | Self::Responses)
    }

    /// Every operation, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Chat,
            Self::Responses,
            Self::Embeddings,
            Self::Tokenize,
            Self::Rerank,
        ]
    }
}

/// A message role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// System or developer instruction.
    System,
    /// End-user turn.
    User,
    /// Model turn.
    Assistant,
    /// A tool result being returned to the model.
    Tool,
}

impl Role {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }

    /// Parse from a client payload.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            // "developer" is the newer spelling of the system role.
            "system" | "developer" => Self::System,
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "tool" | "function" => Self::Tool,
            _ => return None,
        })
    }
}

/// A reference to image data.
#[derive(Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// A `data:` URI carrying base64 image bytes.
    Inline {
        /// The declared media type, for example `image/png`.
        media_type: String,
        /// Base64 payload, exactly as received.
        base64_data: String,
    },
    /// An absolute URL.
    ///
    /// The router never fetches this: doing so would make it an SSRF proxy for
    /// whatever the caller names (specification 10). It is forwarded to the
    /// provider, which fetches it under its own egress policy, and only when
    /// the target declares the capability.
    Url(String),
}

impl fmt::Debug for ImageSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline {
                media_type,
                base64_data,
            } => write!(
                f,
                "Inline {{ media_type: {media_type:?}, base64_data: {} bytes }}",
                base64_data.len()
            ),
            // The URL is caller-supplied and may itself be sensitive.
            Self::Url(_) => f.write_str("Url([redacted])"),
        }
    }
}

/// A declared document media type, from a closed allowlist.
///
/// Closed because the router forwards documents to providers that declared the
/// modality and must never be talked into forwarding something else — and
/// because the value reaches a metric label, which specification 17 requires to
/// have a bounded vocabulary.
///
/// The router does **not** verify that the bytes match the declaration. It
/// cannot: doing so would mean parsing the document, which is exactly what the
/// data plane must not do. The declaration selects which targets are eligible;
/// the provider is what interprets the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DocumentType {
    /// `application/pdf`
    Pdf,
    /// `text/plain`
    PlainText,
    /// `text/markdown`
    Markdown,
    /// `text/csv`
    Csv,
}

impl DocumentType {
    /// The media type string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "application/pdf",
            Self::PlainText => "text/plain",
            Self::Markdown => "text/markdown",
            Self::Csv => "text/csv",
        }
    }

    /// Parse a client-supplied media type.
    ///
    /// Parameters after a `;` — `text/plain; charset=utf-8` — are ignored, and
    /// the type is matched case-insensitively, because both are ordinary in
    /// real clients. Anything not on the list is rejected rather than passed
    /// through.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let base = s.split(';').next().unwrap_or(s).trim().to_ascii_lowercase();
        Some(match base.as_str() {
            "application/pdf" => Self::Pdf,
            "text/plain" => Self::PlainText,
            "text/markdown" | "text/x-markdown" => Self::Markdown,
            "text/csv" => Self::Csv,
            _ => return None,
        })
    }

    /// Every type, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Pdf, Self::PlainText, Self::Markdown, Self::Csv]
    }
}

impl fmt::Display for DocumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reference to document data.
///
/// Mirrors [`ImageSource`] exactly, including the rule its comment already
/// states: a URL is **forwarded to the provider and never fetched by the
/// router**. Fetching a caller-named URL would make the router an SSRF proxy
/// (specification 10). Reusing the shape rather than inventing an upload
/// endpoint means documents inherit a boundary that is already reasoned about
/// and tested.
#[derive(Clone, PartialEq, Eq)]
pub enum DocumentSource {
    /// Inline base64 document bytes.
    Inline {
        /// Base64 payload, exactly as received. Never decoded by the router.
        base64_data: String,
    },
    /// An absolute URL, forwarded and never dereferenced here.
    Url(String),
}

impl fmt::Debug for DocumentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { base64_data } => {
                write!(f, "Inline {{ base64_data: {} bytes }}", base64_data.len())
            }
            // The URL is caller-supplied and may itself be sensitive.
            Self::Url(_) => f.write_str("Url([redacted])"),
        }
    }
}

/// One part of a message's content.
#[derive(Clone, PartialEq)]
pub enum ContentPart {
    /// Text.
    Text(String),
    /// An image.
    Image(ImageSource),
    /// A document.
    ///
    /// Opaque bounded bytes. The router performs no page counting, no text
    /// extraction, no rendering, and no format validation beyond matching the
    /// declared media type against [`DocumentType`]'s allowlist. Adding a PDF
    /// parser to the data plane would put a notoriously hostile format in front
    /// of untrusted input, in a codebase whose entire parser strategy is small,
    /// strict, in-repository, and fuzzed.
    Document {
        /// The declared media type.
        media_type: DocumentType,
        /// Where the bytes are.
        source: DocumentSource,
    },
    /// Audio, as base64 with a declared format.
    Audio {
        /// Format token such as `wav` or `mp3`.
        format: String,
        /// Base64 payload.
        base64_data: String,
    },
    /// A tool result being returned to the model.
    ToolResult {
        /// The identifier of the call this answers.
        tool_call_id: String,
        /// The result payload, serialized by the client.
        content: String,
        /// Whether the tool reported an error.
        is_error: bool,
    },
}

impl ContentPart {
    /// Approximate byte length, used for conservative token estimation.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Text(t) => t.len(),
            Self::Image(ImageSource::Inline { base64_data, .. }) => base64_data.len(),
            Self::Image(ImageSource::Url(u)) => u.len(),
            Self::Audio { base64_data, .. } => base64_data.len(),
            Self::ToolResult { content, .. } => content.len(),
            Self::Document { source, .. } => match source {
                DocumentSource::Inline { base64_data } => base64_data.len(),
                DocumentSource::Url(u) => u.len(),
            },
        }
    }

    /// The modality this part requires of a target.
    #[must_use]
    pub const fn modality(&self) -> Modality {
        match self {
            Self::Text(_) | Self::ToolResult { .. } => Modality::Text,
            Self::Image(_) => Modality::Image,
            Self::Audio { .. } => Modality::Audio,
            Self::Document { .. } => Modality::Document,
        }
    }

    /// Whether this part is a document.
    ///
    /// Documents are counted and budgeted separately from every other part
    /// because their byte length says nothing about their token cost: a scanned
    /// PDF is megabytes and few tokens, a dense text PDF is the reverse, and a
    /// URL-form document has no length the router can see at all.
    #[must_use]
    pub const fn is_document(&self) -> bool {
        matches!(self, Self::Document { .. })
    }

    /// The decoded byte length of an inline document part.
    ///
    /// Base64 carries three bytes in every four characters, minus padding.
    /// Computed from the encoded length rather than by decoding: the router
    /// never decodes a document, and a length check that had to allocate the
    /// decoded form first would be a denial-of-service vector of its own.
    /// Returns `None` for a URL-form document, whose size the router cannot
    /// know and must not try to learn.
    #[must_use]
    pub fn inline_document_bytes(&self) -> Option<usize> {
        let Self::Document {
            source: DocumentSource::Inline { base64_data },
            ..
        } = self
        else {
            return None;
        };
        let padding = base64_data
            .as_bytes()
            .iter()
            .rev()
            .take_while(|b| **b == b'=')
            .count();
        // `div_euclid` rather than `/`: this crate denies `integer_division`
        // so that an accidental truncating divide in a score or a quota is a
        // build failure, and the exemptions are named rather than assumed.
        let decoded = base64_data.len().div_euclid(4).saturating_mul(3);
        Some(decoded.saturating_sub(padding.min(2)))
    }
}

impl fmt::Debug for ContentPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text({} bytes)", t.len()),
            Self::Image(src) => write!(f, "Image({src:?})"),
            Self::Audio { format, base64_data } => {
                write!(f, "Audio {{ format: {format:?}, {} bytes }}", base64_data.len())
            }
            Self::ToolResult {
                tool_call_id,
                content,
                is_error,
            } => write!(
                f,
                "ToolResult {{ tool_call_id: {tool_call_id:?}, {} bytes, is_error: {is_error} }}",
                content.len()
            ),
            Self::Document { media_type, source } => {
                write!(f, "Document {{ media_type: {media_type}, {source:?} }}")
            }
        }
    }
}

/// An input modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Modality {
    /// Text.
    Text,
    /// Images.
    Image,
    /// Audio.
    Audio,
    /// Documents, forwarded opaquely.
    ///
    /// A distinct modality rather than a flavour of `Image` because it decides
    /// eligibility on its own: a target may accept images and refuse
    /// documents, which is exactly the fleet's Qwen3.8 deployments — the
    /// vision projector reads an image, and a document is forwarded opaquely
    /// to a server that has no path for one.
    Document,
}

impl Modality {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Document => "document",
        }
    }

    /// Parse from a capability declaration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "text" => Self::Text,
            "image" => Self::Image,
            "audio" => Self::Audio,
            "document" => Self::Document,
            _ => return None,
        })
    }

    /// Every modality, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Text, Self::Image, Self::Audio, Self::Document]
    }
}

/// A tool call requested by the model.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Provider-assigned call identifier.
    pub id: String,
    /// The tool name.
    pub name: String,
    /// Arguments, as the JSON text the model produced.
    ///
    /// Kept as text: specification 14 requires preserving "ordered argument
    /// deltas" and validating "size and syntax but do not execute". Re-encoding
    /// through a value tree would reorder keys and change the bytes the client
    /// sees.
    pub arguments: String,
}

impl fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Arguments are model output derived from the prompt: sensitive.
        write!(
            f,
            "ToolCall {{ id: {:?}, name: {:?}, arguments: {} bytes }}",
            self.id,
            self.name,
            self.arguments.len()
        )
    }
}

/// A message in the conversation.
#[derive(Clone, PartialEq)]
pub struct Message {
    /// The role.
    pub role: Role,
    /// Ordered content parts.
    pub content: Vec<ContentPart>,
    /// Optional participant name.
    pub name: Option<String>,
    /// Tool calls the assistant made in this turn.
    pub tool_calls: Vec<ToolCall>,
}

impl Message {
    /// A plain text message.
    #[must_use]
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: vec![ContentPart::Text(text.into())],
            name: None,
            tool_calls: Vec::new(),
        }
    }

    /// Total content bytes.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.content.iter().map(ContentPart::byte_len).sum::<usize>()
            + self
                .tool_calls
                .iter()
                .map(|c| c.arguments.len() + c.name.len())
                .sum::<usize>()
    }

    /// Concatenated text parts, when the message is text-only.
    #[must_use]
    pub fn as_text(&self) -> Option<String> {
        if self
            .content
            .iter()
            .any(|p| !matches!(p, ContentPart::Text(_)))
        {
            return None;
        }
        Some(
            self.content
                .iter()
                .filter_map(|p| match p {
                    ContentPart::Text(t) => Some(t.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
        )
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("role", &self.role)
            .field("parts", &self.content.len())
            .field("bytes", &self.byte_len())
            .field("tool_calls", &self.tool_calls.len())
            .finish()
    }
}

/// A tool the model may call.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDef {
    /// The tool name.
    pub name: String,
    /// A human-readable description.
    pub description: Option<String>,
    /// The parameter schema, as canonical JSON text.
    ///
    /// Held as text so that the exact schema the client sent reaches the
    /// provider. Specification 7 lets an adapter *reject* an unsupported
    /// schema; none of them rewrite one.
    pub parameters_json: String,
    /// Whether the client asked for strict schema adherence.
    pub strict: bool,
}

/// How the model should choose tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChoice {
    /// The model decides.
    Auto,
    /// The model must not call a tool.
    None,
    /// The model must call some tool.
    Required,
    /// The model must call this specific tool.
    Function(String),
}

/// The requested response format.
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseFormat {
    /// Free text.
    Text,
    /// Any valid JSON object.
    JsonObject,
    /// JSON matching a named schema.
    JsonSchema {
        /// Schema name.
        name: String,
        /// The schema, as canonical JSON text.
        schema_json: String,
        /// Whether adherence is strict.
        strict: bool,
    },
}

/// Sampling parameters.
///
/// Every field is optional, and `None` means "the client did not set this".
/// Specification 5.1 requires an explicit "unset" distinct from zero.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sampling {
    /// Temperature.
    pub temperature: Option<f64>,
    /// Nucleus sampling threshold.
    pub top_p: Option<f64>,
    /// Top-k sampling.
    pub top_k: Option<u32>,
    /// Deterministic seed.
    pub seed: Option<i64>,
    /// Frequency penalty.
    pub frequency_penalty: Option<f64>,
    /// Presence penalty.
    pub presence_penalty: Option<f64>,
    /// Stop sequences.
    pub stop: Vec<String>,
}

impl Sampling {
    /// True when the client set nothing at all.
    #[must_use]
    pub fn is_unset(&self) -> bool {
        self.temperature.is_none()
            && self.top_p.is_none()
            && self.top_k.is_none()
            && self.seed.is_none()
            && self.frequency_penalty.is_none()
            && self.presence_penalty.is_none()
            && self.stop.is_empty()
    }

    /// Validate ranges, returning the name of the first out-of-range field.
    ///
    /// Ranges are the intersection of what the supported providers accept, so
    /// that a request the router forwards is not rejected downstream for a
    /// reason the caller could have been told about immediately.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(t) = self.temperature {
            if !(0.0..=2.0).contains(&t) || !t.is_finite() {
                return Err("temperature");
            }
        }
        if let Some(p) = self.top_p {
            if !(0.0..=1.0).contains(&p) || !p.is_finite() {
                return Err("top_p");
            }
        }
        if let Some(p) = self.frequency_penalty {
            if !(-2.0..=2.0).contains(&p) || !p.is_finite() {
                return Err("frequency_penalty");
            }
        }
        if let Some(p) = self.presence_penalty {
            if !(-2.0..=2.0).contains(&p) || !p.is_finite() {
                return Err("presence_penalty");
            }
        }
        if self.stop.len() > 8 {
            return Err("stop");
        }
        Ok(())
    }
}

/// A relative cost class.
///
/// Specification 6.3: "Configured relative cost; never derived from untrusted
/// provider response." The class is an administrator-assigned ordinal, not a
/// price read from a provider's API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CostClass(pub u8);

impl CostClass {
    /// The cheapest class.
    pub const CHEAPEST: Self = Self(0);
    /// The most expensive class the scale allows.
    pub const MOST_EXPENSIVE: Self = Self(9);

    /// Construct, clamping into range.
    #[must_use]
    pub const fn new(v: u8) -> Self {
        Self(if v > 9 { 9 } else { v })
    }
}

impl fmt::Display for CostClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An administrator-assigned quality class, ordered, higher is better.
///
/// Exactly symmetric with [`CostClass`], and deliberately independent of it.
/// Cost and quality are not one axis: a local Q5 model may be cheaper *and*
/// better than a remote Q4 one, and expressing "better" through `cost_class`
/// makes that target either unreachable or mispriced.
///
/// Quantization itself stays unmodelled. What routing needs is memory,
/// context, quality, and cost — all of which are declared. "Q5" is the
/// operator's label in a target identifier, not a concept the router reasons
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QualityClass(pub u8);

impl QualityClass {
    /// The lowest class.
    pub const LOWEST: Self = Self(0);
    /// The highest class the scale allows.
    pub const HIGHEST: Self = Self(9);

    /// Construct, clamping into range.
    #[must_use]
    pub const fn new(v: u8) -> Self {
        Self(if v > 9 { 9 } else { v })
    }
}

impl Default for QualityClass {
    /// The default is the *lowest* class, not the middle one.
    ///
    /// A target whose configuration omits `quality` must not satisfy a floor
    /// its operator never claimed it met. The same argument as
    /// [`crate::target::Capabilities::default`]: an under-specified target does
    /// not acquire a property by omission.
    fn default() -> Self {
        Self::LOWEST
    }
}

impl fmt::Display for QualityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How much reasoning the caller is asking for.
///
/// [`ReasoningEffort::Unset`] is distinct from [`ReasoningEffort::Minimal`],
/// per specification 5.1's existing rule that an explicit unset is distinct
/// from zero. `Capabilities::reasoning` is a different question — it means
/// "exposes reasoning content" — and is unchanged by this.
///
/// Effort is a routing input, not a provider passthrough. It multiplies
/// expected output tokens, so it changes the admission reservation; it raises
/// expected time to completion, so it changes the cold-start feasibility check;
/// and each adapter family maps the tier to its own parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum ReasoningEffort {
    /// The client said nothing. The provider's own default applies.
    #[default]
    Unset,
    /// As little as the model supports.
    Minimal,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

impl ReasoningEffort {
    /// Stable token for configuration, traces, and the closed metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Parse from a client request or a capability declaration.
    ///
    /// Provider-specific spellings are not accepted here. A family that calls
    /// this something else maps it inside its adapter, which is where
    /// specification 7.1 puts typed conversion.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "unset" | "none" => Self::Unset,
            "minimal" => Self::Minimal,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            _ => return None,
        })
    }

    /// Every tier a target may declare support for.
    ///
    /// Excludes [`ReasoningEffort::Unset`], which is the absence of a request
    /// rather than a tier: a target cannot "not support" a caller saying
    /// nothing.
    #[must_use]
    pub const fn declarable() -> &'static [Self] {
        &[Self::Minimal, Self::Low, Self::Medium, Self::High]
    }

    /// Every value, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Unset,
            Self::Minimal,
            Self::Low,
            Self::Medium,
            Self::High,
        ]
    }

    /// The default output multiplier for this tier.
    ///
    /// 1 / 2 / 4 / 8 for minimal / low / medium / high, and 1 for `Unset`. A
    /// target may override the four declarable tiers; nothing may override
    /// `Unset`, because there is no request to scale.
    #[must_use]
    pub const fn default_output_multiplier(self) -> u32 {
        match self {
            Self::Unset | Self::Minimal => 1,
            Self::Low => 2,
            Self::Medium => 4,
            Self::High => 8,
        }
    }
}

impl fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A data residency requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residency(String);

impl Residency {
    /// Construct from a region token such as `eu` or `us`.
    #[must_use]
    pub fn new(region: impl Into<String>) -> Self {
        Self(region.into().to_ascii_lowercase())
    }

    /// The region token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Residency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-request limits (specification 5.1).
#[derive(Debug, Clone)]
pub struct RequestLimits {
    /// Maximum tokens the model may generate.
    pub max_output_tokens: Option<u32>,
    /// End-to-end deadline.
    pub deadline: Deadline,
    /// The most expensive class the request may select.
    pub max_cost_class: Option<CostClass>,
    /// The lowest quality class the request will accept.
    ///
    /// A floor, exactly symmetric with `max_cost_class`'s ceiling and
    /// independent of it. Neither is derived from the other.
    pub min_quality_class: Option<QualityClass>,
    /// Required data residency.
    pub residency: Option<Residency>,
}

/// Streaming options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamOptions {
    /// Whether the client asked for a stream.
    pub enabled: bool,
    /// Whether to emit a final usage event.
    pub include_usage: bool,
}

/// Allowlisted routing hints.
///
/// Specification 5.1: "Optional allowlisted hints; ignored or rejected unless
/// principal has permission." A hint can only *narrow* selection to something
/// policy already permits; it can never widen it, name an endpoint, or select a
/// credential.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingHints {
    /// Prefer this target if it is already eligible.
    pub prefer_target: Option<TargetId>,
    /// Require local inference.
    pub require_local: bool,
    /// An idempotency key supplied by the client.
    pub idempotency_key: Option<String>,
}

impl RoutingHints {
    /// True when the client supplied any hint at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefer_target.is_none() && !self.require_local && self.idempotency_key.is_none()
    }
}

/// The client protocol a request arrived on.
///
/// Recorded so that responses, errors, and stream events are rendered in the
/// dialect the caller speaks (specification 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocol {
    /// `POST /v1/chat/completions`
    OpenAiChat,
    /// `POST /v1/responses`
    OpenAiResponses,
    /// `POST /v1/embeddings`
    OpenAiEmbeddings,
    /// `POST /v1/messages`
    AnthropicMessages,
    /// A router-native extension endpoint.
    Native,
}

impl ClientProtocol {
    /// Stable name for metrics and traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai_chat",
            Self::OpenAiResponses => "openai_responses",
            Self::OpenAiEmbeddings => "openai_embeddings",
            Self::AnthropicMessages => "anthropic_messages",
            Self::Native => "native",
        }
    }
}

/// The canonical request.
#[derive(Clone)]
pub struct CanonicalRequest {
    /// Correlation identifier. Never an authorization input.
    pub request_id: RequestId,
    /// The tenant the principal belongs to.
    pub tenant: TenantId,
    /// The authenticated principal. Resolved server-side; a client cannot
    /// override it.
    pub principal: PrincipalId,
    /// The protocol the request arrived on.
    pub protocol: ClientProtocol,
    /// The operation.
    pub operation: Operation,
    /// The client-visible model name as requested.
    pub requested_model: AliasId,
    /// Conversation messages, for chat-shaped operations.
    pub messages: Vec<Message>,
    /// Raw inputs, for embedding-shaped operations.
    pub inputs: Vec<String>,
    /// Tools available to the model.
    pub tools: Vec<ToolDef>,
    /// How the model should choose tools.
    pub tool_choice: Option<ToolChoice>,
    /// The requested response format.
    pub response_format: Option<ResponseFormat>,
    /// Sampling parameters.
    pub sampling: Sampling,
    /// How much reasoning the caller asked for.
    ///
    /// Part of the capability contract, not a sampling parameter: it filters
    /// targets that do not declare the tier and multiplies the admission
    /// reservation before any outbound I/O.
    pub reasoning_effort: ReasoningEffort,
    /// Request limits.
    pub limits: RequestLimits,
    /// Streaming options.
    pub stream: StreamOptions,
    /// Allowlisted routing hints.
    pub hints: RoutingHints,
}

impl CanonicalRequest {
    /// Total input bytes across messages and inputs.
    ///
    /// The basis for the conservative token estimate used at admission when no
    /// tokenizer is available (specification 12).
    #[must_use]
    pub fn input_byte_len(&self) -> usize {
        self.messages.iter().map(Message::byte_len).sum::<usize>()
            + self.inputs.iter().map(String::len).sum::<usize>()
            + self
                .tools
                .iter()
                .map(|t| t.parameters_json.len() + t.name.len())
                .sum::<usize>()
    }

    /// The set of modalities the request requires of a target.
    #[must_use]
    pub fn required_modalities(&self) -> Vec<Modality> {
        let mut set: Vec<Modality> = self
            .messages
            .iter()
            .flat_map(|m| m.content.iter().map(ContentPart::modality))
            .collect();
        if set.is_empty() {
            set.push(Modality::Text);
        }
        set.sort_unstable();
        set.dedup();
        set
    }

    /// True when the request needs tool support.
    #[must_use]
    pub fn requires_tools(&self) -> bool {
        !self.tools.is_empty()
            || self
                .messages
                .iter()
                .any(|m| !m.tool_calls.is_empty())
    }

    /// True when the request needs structured output support.
    #[must_use]
    pub fn requires_structured_output(&self) -> bool {
        matches!(
            self.response_format,
            Some(ResponseFormat::JsonObject | ResponseFormat::JsonSchema { .. })
        )
    }

    /// Input bytes excluding document parts.
    ///
    /// The basis for the byte-derived half of the estimate. Documents are
    /// excluded because their byte length says nothing about their token cost
    /// in either direction, and a URL-form document has no length at all.
    #[must_use]
    pub fn non_document_input_byte_len(&self) -> usize {
        let document_bytes: usize = self
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter(|p| p.is_document())
            .map(ContentPart::byte_len)
            .sum();
        self.input_byte_len().saturating_sub(document_bytes)
    }

    /// How many document parts the request carries.
    #[must_use]
    pub fn document_parts(&self) -> usize {
        self.messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter(|p| p.is_document())
            .count()
    }

    /// Total decoded bytes across inline document parts.
    ///
    /// URL-form documents contribute nothing: the router never fetches them and
    /// cannot know their size.
    #[must_use]
    pub fn inline_document_bytes(&self) -> u64 {
        self.messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(ContentPart::inline_document_bytes)
            .map(|b| u64::try_from(b).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add)
    }

    /// Conservative upper bound on input tokens.
    ///
    /// Specification 12: "Estimated input tokens use the selected target
    /// tokenizer when available; otherwise a conservative byte-based upper
    /// bound." Two bytes per token is deliberately pessimistic — under-counting
    /// would let a request slip past a quota it should have been held by.
    ///
    /// Uses the compiled-in default document constant. Prefer
    /// [`CanonicalRequest::estimated_input_tokens_with`] on the routing path,
    /// where the selected target's declaration is available.
    #[must_use]
    pub fn estimated_input_tokens(&self) -> u64 {
        self.estimated_input_tokens_with(DEFAULT_DOCUMENT_TOKEN_ESTIMATE)
    }

    /// Conservative upper bound on input tokens, given a document constant.
    ///
    /// A document contributes `document_token_estimate` tokens regardless of
    /// its size, because the router cannot count pages without parsing it and
    /// parsing it is exactly what the data plane must not do. An operator
    /// tuning this constant is choosing between rejecting large documents and
    /// admitting them past a quota, and the number should err high.
    #[must_use]
    pub fn estimated_input_tokens_with(&self, document_token_estimate: u32) -> u64 {
        // Saturating rather than truncating: this is an upper bound feeding a
        // quota check, so a value too large holds the request, while a
        // wrapped-around small value would let it slip past.
        let bytes = u64::try_from(self.non_document_input_byte_len()).unwrap_or(u64::MAX);
        // Per-message framing overhead that every provider adds.
        let framing = u64::try_from(self.messages.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        let documents = u64::try_from(self.document_parts())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(document_token_estimate));
        bytes
            .div_ceil(2)
            .saturating_add(framing)
            .saturating_add(documents)
    }

    /// Reserved output tokens, after the reasoning tier's multiplier.
    ///
    /// Applied **at reservation**, not after completion. Reserving unmultiplied
    /// would let a high-effort request consume several times what it was held
    /// to — a quota bypass that needs no malformed input at all, just a JSON
    /// field. The figure is reconciled against provider-reported usage on
    /// completion through the existing `Reservation::commit` path.
    #[must_use]
    pub fn estimated_output_tokens_with(&self, output_multiplier: u32) -> u64 {
        u64::from(self.limits.max_output_tokens.unwrap_or(0))
            .saturating_mul(u64::from(output_multiplier.max(1)))
    }

    /// Total token budget the request could consume.
    ///
    /// The compiled-in defaults: no target declaration, so the default
    /// document constant and the tier's default multiplier apply.
    #[must_use]
    pub fn estimated_total_tokens(&self) -> u64 {
        self.estimated_total_tokens_with(&TokenEstimate::for_effort(self.reasoning_effort))
    }

    /// Total token budget under a specific target's declarations.
    #[must_use]
    pub fn estimated_total_tokens_with(&self, estimate: &TokenEstimate) -> u64 {
        self.estimated_input_tokens_with(estimate.document_token_estimate)
            .saturating_add(self.estimated_output_tokens_with(estimate.output_multiplier))
    }
}

/// The compiled-in per-document token constant.
///
/// Deliberately larger than a page of dense text and larger than the fixed cost
/// of a rendered page image, because over-estimation is the correct failure
/// direction here: it holds a request that might have fitted, where
/// under-estimation admits one that should have been held. Operators raise or
/// lower it per target, or router-wide through `default_document_token_estimate`.
pub const DEFAULT_DOCUMENT_TOKEN_ESTIMATE: u32 = 4_096;

/// The two target-declared inputs to a token estimate.
///
/// Bundled rather than passed as two integers because they are read together
/// at exactly one place — the reservation — and a transposed pair would be a
/// silently wrong quota rather than a type error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenEstimate {
    /// Tokens charged per document part.
    pub document_token_estimate: u32,
    /// Multiplier applied to the requested output length.
    pub output_multiplier: u32,
}

impl TokenEstimate {
    /// The estimate for a request with no target declaration available.
    #[must_use]
    pub const fn for_effort(effort: ReasoningEffort) -> Self {
        Self {
            document_token_estimate: DEFAULT_DOCUMENT_TOKEN_ESTIMATE,
            output_multiplier: effort.default_output_multiplier(),
        }
    }
}

impl Default for TokenEstimate {
    fn default() -> Self {
        Self::for_effort(ReasoningEffort::Unset)
    }
}

impl fmt::Debug for CanonicalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately shape-only: this struct holds the prompt.
        f.debug_struct("CanonicalRequest")
            .field("request_id", &self.request_id)
            .field("tenant", &self.tenant)
            .field("principal", &self.principal)
            .field("protocol", &self.protocol)
            .field("operation", &self.operation)
            .field("requested_model", &self.requested_model)
            .field("messages", &self.messages.len())
            .field("inputs", &self.inputs.len())
            .field("tools", &self.tools.len())
            .field("input_bytes", &self.input_byte_len())
            .field("stream", &self.stream.enabled)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TestClock;
    use std::time::Duration;

    fn request() -> CanonicalRequest {
        let clock = TestClock::new();
        CanonicalRequest {
            request_id: RequestId::from_u128(1),
            tenant: TenantId::new("acme").unwrap(),
            principal: PrincipalId::new("user:42").unwrap(),
            protocol: ClientProtocol::OpenAiChat,
            operation: Operation::Chat,
            requested_model: AliasId::new("code-premium").unwrap(),
            messages: vec![
                Message::text(Role::System, "You are terse."),
                Message::text(Role::User, "Explain backpressure."),
            ],
            inputs: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            response_format: None,
            sampling: Sampling::default(),
            reasoning_effort: Default::default(),
            limits: RequestLimits {
                max_output_tokens: Some(512),
                deadline: Deadline::after(&clock, Duration::from_secs(60)),
                max_cost_class: None,
                min_quality_class: None,
                residency: None,
            },
            stream: StreamOptions {
                enabled: true,
                include_usage: false,
            },
            hints: RoutingHints::default(),
        }
    }

    #[test]
    fn debug_never_prints_prompt_text() {
        let r = request();
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("backpressure"));
        assert!(!rendered.contains("You are terse"));
        assert!(rendered.contains("messages: 2"));
        assert!(rendered.contains("code-premium"));
    }

    #[test]
    fn debug_of_a_message_is_shape_only() {
        let m = Message::text(Role::User, "a secret prompt");
        let rendered = format!("{m:?}");
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("bytes: 15"));
    }

    #[test]
    fn debug_of_content_parts_is_shape_only() {
        let parts = vec![
            ContentPart::Text("secret text".to_owned()),
            ContentPart::Image(ImageSource::Url("https://secret.example/x.png".to_owned())),
            ContentPart::Image(ImageSource::Inline {
                media_type: "image/png".to_owned(),
                base64_data: "AAAA".to_owned(),
            }),
            ContentPart::Audio {
                format: "wav".to_owned(),
                base64_data: "BBBB".to_owned(),
            },
            ContentPart::ToolResult {
                tool_call_id: "call_1".to_owned(),
                content: "confidential result".to_owned(),
                is_error: false,
            },
        ];
        let rendered = format!("{parts:?}");
        assert!(!rendered.contains("secret text"));
        assert!(!rendered.contains("secret.example"));
        assert!(!rendered.contains("confidential"));
        // Non-sensitive structural facts are still visible.
        assert!(rendered.contains("image/png"));
        assert!(rendered.contains("call_1"));
    }

    #[test]
    fn debug_of_tool_call_hides_arguments() {
        let c = ToolCall {
            id: "call_1".to_owned(),
            name: "lookup".to_owned(),
            arguments: r#"{"q":"private query"}"#.to_owned(),
        };
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("private query"));
        assert!(rendered.contains("lookup"));
    }

    #[test]
    fn unset_sampling_is_distinct_from_zero() {
        let unset = Sampling::default();
        assert!(unset.is_unset());
        assert_eq!(unset.temperature, None);

        let zero = Sampling {
            temperature: Some(0.0),
            ..Sampling::default()
        };
        assert!(!zero.is_unset());
        assert_ne!(unset.temperature, zero.temperature);
    }

    #[test]
    fn sampling_validation_bounds() {
        assert!(Sampling::default().validate().is_ok());
        assert!(
            Sampling {
                temperature: Some(0.0),
                ..Sampling::default()
            }
            .validate()
            .is_ok()
        );
        assert_eq!(
            Sampling {
                temperature: Some(2.5),
                ..Sampling::default()
            }
            .validate(),
            Err("temperature")
        );
        assert_eq!(
            Sampling {
                temperature: Some(-0.1),
                ..Sampling::default()
            }
            .validate(),
            Err("temperature")
        );
        assert_eq!(
            Sampling {
                temperature: Some(f64::NAN),
                ..Sampling::default()
            }
            .validate(),
            Err("temperature")
        );
        assert_eq!(
            Sampling {
                top_p: Some(1.5),
                ..Sampling::default()
            }
            .validate(),
            Err("top_p")
        );
        assert_eq!(
            Sampling {
                frequency_penalty: Some(3.0),
                ..Sampling::default()
            }
            .validate(),
            Err("frequency_penalty")
        );
        assert_eq!(
            Sampling {
                stop: vec![String::new(); 9],
                ..Sampling::default()
            }
            .validate(),
            Err("stop")
        );
    }

    #[test]
    fn modality_detection() {
        let mut r = request();
        assert_eq!(r.required_modalities(), vec![Modality::Text]);

        r.messages.push(Message {
            role: Role::User,
            content: vec![
                ContentPart::Text("look".to_owned()),
                ContentPart::Image(ImageSource::Url("https://x/y.png".to_owned())),
            ],
            name: None,
            tool_calls: Vec::new(),
        });
        assert_eq!(
            r.required_modalities(),
            vec![Modality::Text, Modality::Image]
        );
    }

    #[test]
    fn empty_request_still_requires_text() {
        let mut r = request();
        r.messages.clear();
        assert_eq!(r.required_modalities(), vec![Modality::Text]);
    }

    #[test]
    fn capability_requirements_are_derived() {
        let mut r = request();
        assert!(!r.requires_tools());
        assert!(!r.requires_structured_output());

        r.tools.push(ToolDef {
            name: "lookup".to_owned(),
            description: None,
            parameters_json: "{}".to_owned(),
            strict: true,
        });
        assert!(r.requires_tools());

        r.response_format = Some(ResponseFormat::JsonObject);
        assert!(r.requires_structured_output());

        r.response_format = Some(ResponseFormat::Text);
        assert!(!r.requires_structured_output());
    }

    #[test]
    fn token_estimate_is_conservative() {
        let r = request();
        let bytes = r.input_byte_len() as u64;
        let estimate = r.estimated_input_tokens();
        // Never under-count: a real tokenizer averages 3-4 bytes per token, so
        // 2 bytes per token plus framing is a genuine upper bound.
        assert!(estimate >= bytes / 4, "{estimate} vs {bytes} bytes");
        assert!(estimate >= bytes / 2);
        assert_eq!(
            r.estimated_total_tokens(),
            estimate + 512,
            "output budget must be included"
        );
    }

    #[test]
    fn token_estimate_never_overflows() {
        let mut r = request();
        r.limits.max_output_tokens = Some(u32::MAX);
        // Saturating arithmetic: a huge output budget must not wrap the total.
        assert!(r.estimated_total_tokens() >= u64::from(u32::MAX));
    }

    #[test]
    fn message_text_extraction() {
        let m = Message::text(Role::User, "hello");
        assert_eq!(m.as_text().as_deref(), Some("hello"));

        let m = Message {
            role: Role::User,
            content: vec![
                ContentPart::Text("a".to_owned()),
                ContentPart::Text("b".to_owned()),
            ],
            name: None,
            tool_calls: Vec::new(),
        };
        assert_eq!(m.as_text().as_deref(), Some("ab"));

        let m = Message {
            role: Role::User,
            content: vec![ContentPart::Image(ImageSource::Url("u".to_owned()))],
            name: None,
            tool_calls: Vec::new(),
        };
        assert_eq!(m.as_text(), None, "a non-text part must not be dropped");
    }

    #[test]
    fn role_and_operation_parsing() {
        assert_eq!(Role::parse("system"), Some(Role::System));
        assert_eq!(Role::parse("developer"), Some(Role::System));
        assert_eq!(Role::parse("function"), Some(Role::Tool));
        assert_eq!(Role::parse("nope"), None);

        for op in Operation::all() {
            assert_eq!(Operation::parse(op.as_str()), Some(*op));
        }
        assert_eq!(Operation::parse("nope"), None);
        assert!(Operation::Chat.can_stream());
        assert!(!Operation::Embeddings.can_stream());
    }

    #[test]
    fn cost_class_is_clamped_and_ordered() {
        assert_eq!(CostClass::new(200), CostClass::MOST_EXPENSIVE);
        assert!(CostClass::CHEAPEST < CostClass::MOST_EXPENSIVE);
        assert_eq!(CostClass::new(3).to_string(), "3");
    }

    #[test]
    fn residency_is_case_insensitive() {
        assert_eq!(Residency::new("EU"), Residency::new("eu"));
        assert_eq!(Residency::new("Eu").as_str(), "eu");
    }

    #[test]
    fn hints_default_to_empty() {
        assert!(RoutingHints::default().is_empty());
        assert!(
            !RoutingHints {
                require_local: true,
                ..RoutingHints::default()
            }
            .is_empty()
        );
    }
}
