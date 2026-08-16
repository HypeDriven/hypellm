//! The canonical event stream (specification 7.1, 14).
//!
//! An adapter decodes a provider's wire format into this sequence; a client
//! protocol encoder turns it back into whatever dialect the caller speaks. The
//! router core never sees provider bytes and never sees client bytes.
//!
//! Two invariants from specification 14 are encoded in the types:
//!
//! - Usage is marked as **provider-reported or router-estimated**. A number
//!   that feeds metering must carry its provenance, because reconciling an
//!   estimate against a bill is a different operation from trusting a report.
//! - Tool call deltas preserve **call identity and ordering**. The index is
//!   part of the event, not implied by arrival order, so a reordered or
//!   interleaved provider stream cannot merge two calls' arguments.

use crate::sensitive::Capped;
use std::collections::BTreeMap;
use core::fmt;

/// Why generation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    /// The model finished naturally.
    Stop,
    /// The output token limit was reached.
    Length,
    /// The model emitted tool calls and is waiting for results.
    ToolCalls,
    /// The provider's content filter stopped generation.
    ContentFilter,
    /// The request was cancelled by the client or the router.
    Cancelled,
    /// An error ended the stream.
    Error,
    /// The provider reported a finish reason this router does not recognise.
    ///
    /// Providers add stop reasons over time — Anthropic's `refusal` and
    /// `pause_turn` both postdate the original mapping here. Folding an unknown
    /// value into [`FinishReason::Stop`] would tell the caller the model
    /// finished naturally when the router has no idea whether it did, and would
    /// make the difference invisible in traces and metrics. Keeping a distinct
    /// variant costs nothing on the wire — it renders as the same conservative
    /// spelling — while letting the router report the truth in its own metadata.
    Unrecognized,
}

impl FinishReason {
    /// The OpenAI wire spelling.
    #[must_use]
    pub const fn openai_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolCalls => "tool_calls",
            Self::ContentFilter => "content_filter",
            // OpenAI has no cancellation or error finish reason; the closest
            // faithful mapping is `stop`, and the router additionally reports
            // the truth in its own metadata rather than inventing a value the
            // client's SDK would fail to parse. The same applies to a reason
            // the router does not recognise.
            Self::Cancelled | Self::Error | Self::Unrecognized => "stop",
        }
    }

    /// The Anthropic wire spelling.
    #[must_use]
    pub const fn anthropic_str(self) -> &'static str {
        match self {
            Self::Stop => "end_turn",
            Self::Length => "max_tokens",
            Self::ToolCalls => "tool_use",
            Self::ContentFilter | Self::Cancelled | Self::Error | Self::Unrecognized => {
                "stop_sequence"
            }
        }
    }

    /// Parse an OpenAI finish reason.
    #[must_use]
    pub fn parse_openai(s: &str) -> Option<Self> {
        Some(match s {
            "stop" => Self::Stop,
            "length" => Self::Length,
            "tool_calls" | "function_call" => Self::ToolCalls,
            "content_filter" => Self::ContentFilter,
            _ => return None,
        })
    }

    /// Parse an Anthropic stop reason.
    #[must_use]
    pub fn parse_anthropic(s: &str) -> Option<Self> {
        Some(match s {
            "end_turn" | "stop_sequence" => Self::Stop,
            "max_tokens" => Self::Length,
            "tool_use" => Self::ToolCalls,
            _ => return None,
        })
    }
}

/// Where a usage number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageSource {
    /// The provider reported it.
    ProviderReported,
    /// The router estimated it.
    RouterEstimated,
}

impl UsageSource {
    /// Stable name for traces and metering records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderReported => "provider_reported",
            Self::RouterEstimated => "router_estimated",
        }
    }
}

/// Token accounting for one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalUsage {
    /// Input tokens.
    pub input_tokens: u64,
    /// Generated tokens.
    pub output_tokens: u64,
    /// Tokens served from a provider prompt cache, when reported.
    pub cached_input_tokens: u64,
    /// Reasoning tokens, when reported separately.
    pub reasoning_tokens: u64,
    /// Provenance of these numbers.
    pub source: UsageSource,
}

impl CanonicalUsage {
    /// An all-zero, router-estimated usage record.
    #[must_use]
    pub const fn estimated(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            source: UsageSource::RouterEstimated,
        }
    }

    /// A provider-reported usage record.
    #[must_use]
    pub const fn reported(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            source: UsageSource::ProviderReported,
        }
    }

    /// Total billable tokens.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    /// True when the numbers came from the provider.
    #[must_use]
    pub const fn is_reported(&self) -> bool {
        matches!(self.source, UsageSource::ProviderReported)
    }
}

impl Default for CanonicalUsage {
    fn default() -> Self {
        Self::estimated(0, 0)
    }
}

/// A tool call being streamed in fragments.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolCallDelta {
    /// Position of this call in the assistant turn.
    ///
    /// Carried explicitly rather than inferred from arrival order: an out-of-
    /// order provider stream must not concatenate two calls' arguments.
    pub index: u32,
    /// The call identifier, sent once at the start of the call.
    pub id: Option<String>,
    /// The tool name, sent once at the start of the call.
    pub name: Option<String>,
    /// A fragment of the JSON arguments.
    pub arguments_delta: String,
}

impl fmt::Debug for ToolCallDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ToolCallDelta {{ index: {}, id: {:?}, name: {:?}, args: {} bytes }}",
            self.index,
            self.id,
            self.name,
            self.arguments_delta.len()
        )
    }
}

/// A canonical stream event.
#[derive(Clone, PartialEq)]
pub enum CanonicalEvent {
    /// The response has started. Carries the provider-assigned identifier and
    /// the model actually used, which may differ from the requested alias.
    Start {
        /// Provider-assigned response identifier, when it supplies one.
        upstream_id: Option<String>,
        /// The native model name the provider reports.
        native_model: Option<String>,
    },
    /// A fragment of assistant text.
    TextDelta(String),
    /// A fragment of reasoning text, where the provider exposes it separately.
    ReasoningDelta(String),
    /// A fragment of a tool call.
    ToolCallDelta(ToolCallDelta),
    /// An embedding vector, for embedding operations.
    Embedding {
        /// Position in the input batch.
        index: u32,
        /// The vector.
        values: Vec<f32>,
    },
    /// Usage accounting.
    Usage(CanonicalUsage),
    /// Generation finished.
    Finish {
        /// Why it finished.
        reason: FinishReason,
    },
    /// The stream ended in an error.
    ///
    /// Specification 14: "Emit protocol-supported error event if possible, then
    /// close. Never append failover output."
    Error(crate::error::RouterError),
}

impl CanonicalEvent {
    /// Whether this event carries semantic output the client can observe.
    ///
    /// This is the predicate behind the most important failover rule
    /// (specification 6.5): once one of these has reached the client, the
    /// router may never splice a second model's output into the stream.
    #[must_use]
    pub const fn is_semantic_output(&self) -> bool {
        matches!(
            self,
            Self::TextDelta(_)
                | Self::ReasoningDelta(_)
                | Self::ToolCallDelta(_)
                | Self::Embedding { .. }
        )
    }

    /// Whether this event ends the stream.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Finish { .. } | Self::Error(_))
    }

    /// Approximate payload size, for bounding buffered data.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Start {
                upstream_id,
                native_model,
            } => {
                upstream_id.as_ref().map_or(0, String::len)
                    + native_model.as_ref().map_or(0, String::len)
            }
            Self::TextDelta(t) | Self::ReasoningDelta(t) => t.len(),
            Self::ToolCallDelta(d) => d.arguments_delta.len(),
            Self::Embedding { values, .. } => values.len() * 4,
            Self::Usage(_) | Self::Finish { .. } => 0,
            Self::Error(e) => e.detail.as_str().len(),
        }
    }
}

impl fmt::Debug for CanonicalEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start {
                upstream_id,
                native_model,
            } => f
                .debug_struct("Start")
                .field("upstream_id", upstream_id)
                .field("native_model", native_model)
                .finish(),
            // Model output is derived from the prompt and is equally sensitive.
            Self::TextDelta(t) => write!(f, "TextDelta({} bytes)", t.len()),
            Self::ReasoningDelta(t) => write!(f, "ReasoningDelta({} bytes)", t.len()),
            Self::ToolCallDelta(d) => write!(f, "{d:?}"),
            Self::Embedding { index, values } => {
                write!(f, "Embedding {{ index: {index}, dims: {} }}", values.len())
            }
            Self::Usage(u) => write!(f, "{u:?}"),
            Self::Finish { reason } => write!(f, "Finish {{ reason: {reason:?} }}"),
            Self::Error(e) => write!(f, "Error({})", e.code),
        }
    }
}

/// Bounds on what one response may accumulate.
///
/// Specification 3.2: no buffer originating from a request may be unbounded,
/// and every one of these is written by a *provider* — a party the router does
/// not control and whose output length is not the caller's to cap. Without
/// them, one upstream that never stops streaming is one router that runs out of
/// memory, and the request that triggered it looks ordinary.
///
/// The values are far above any real completion: a model producing 8 MiB of
/// text has already exceeded every `max_output_tokens` a target declares, so
/// reaching a limit here means something is wrong rather than something is
/// large. When one is reached the excess is discarded and
/// [`ResponseAccumulator::truncated`] reports it, so the response is short and
/// says so rather than being silently wrong.
pub mod limits {
    /// Assembled assistant text.
    pub const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;
    /// Assembled reasoning text.
    pub const MAX_REASONING_BYTES: usize = 8 * 1024 * 1024;
    /// Distinct tool calls in one response.
    pub const MAX_TOOL_CALLS: usize = 1_024;
    /// Assembled arguments for one tool call.
    pub const MAX_TOOL_ARGUMENTS_BYTES: usize = 1024 * 1024;
    /// Embedding vectors in one response.
    pub const MAX_EMBEDDINGS: usize = 100_000;
}

/// Accumulates a stream into a complete response.
///
/// Non-streaming clients still route through the streaming path — specification
/// 14 forbids buffering an entire completion for a *streaming* client, and
/// running one code path for both means the two cannot drift apart.
#[derive(Debug, Default)]
pub struct ResponseAccumulator {
    /// Assembled assistant text.
    pub text: String,
    /// Assembled reasoning text.
    pub reasoning: String,
    /// Assembled tool calls, indexed by their stream position.
    pub tool_calls: Vec<AccumulatedToolCall>,
    /// Embedding vectors.
    pub embeddings: Vec<(u32, Vec<f32>)>,
    /// Usage, once seen.
    pub usage: Option<CanonicalUsage>,
    /// Finish reason, once seen.
    pub finish: Option<FinishReason>,
    /// The provider's response identifier.
    pub upstream_id: Option<String>,
    /// The native model the provider used.
    pub native_model: Option<String>,
    /// A terminal error, if the stream failed.
    pub error: Option<crate::error::RouterError>,
    /// Whether any semantic output was observed.
    saw_output: bool,
    /// Whether any bound in [`limits`] was reached and content discarded.
    truncated: bool,
    /// Tool-call index to position in `tool_calls`.
    ///
    /// Without this, every `ToolCallDelta` scanned the whole vector to find its
    /// slot, so a response with N tool calls cost O(N²) in deltas — and a
    /// provider chooses both N and the number of deltas.
    tool_slots: BTreeMap<u32, usize>,
}

/// A tool call assembled from deltas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccumulatedToolCall {
    /// Stream position.
    pub index: u32,
    /// Call identifier.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// Complete JSON arguments.
    pub arguments: String,
}

impl ResponseAccumulator {
    /// Create an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb one event.
    pub fn push(&mut self, event: &CanonicalEvent) {
        if event.is_semantic_output() {
            self.saw_output = true;
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
            }
            CanonicalEvent::TextDelta(t) => {
                self.truncated |= append_bounded(&mut self.text, t, limits::MAX_TEXT_BYTES);
            }
            CanonicalEvent::ReasoningDelta(t) => {
                self.truncated |=
                    append_bounded(&mut self.reasoning, t, limits::MAX_REASONING_BYTES);
            }
            CanonicalEvent::ToolCallDelta(d) => {
                // O(log n) rather than a linear scan per delta. The provider
                // chooses how many tool calls and how many deltas, so the
                // quadratic version was work it could ask for.
                let position = match self.tool_slots.get(&d.index) {
                    Some(position) => *position,
                    None => {
                        if self.tool_calls.len() >= limits::MAX_TOOL_CALLS {
                            self.truncated = true;
                            return;
                        }
                        let position = self.tool_calls.len();
                        self.tool_calls.push(AccumulatedToolCall {
                            index: d.index,
                            ..AccumulatedToolCall::default()
                        });
                        self.tool_slots.insert(d.index, position);
                        position
                    }
                };
                let Some(slot) = self.tool_calls.get_mut(position) else {
                    // Unreachable: positions are only ever recorded for slots
                    // that were just pushed and are never removed.
                    return;
                };
                if let Some(id) = &d.id {
                    slot.id.clone_from(id);
                }
                if let Some(name) = &d.name {
                    slot.name.clone_from(name);
                }
                if append_bounded(
                    &mut slot.arguments,
                    &d.arguments_delta,
                    limits::MAX_TOOL_ARGUMENTS_BYTES,
                ) {
                    self.truncated = true;
                }
            }
            CanonicalEvent::Embedding { index, values } => {
                if self.embeddings.len() >= limits::MAX_EMBEDDINGS {
                    self.truncated = true;
                    return;
                }
                self.embeddings.push((*index, values.clone()));
            }
            CanonicalEvent::Usage(u) => self.usage = Some(*u),
            CanonicalEvent::Finish { reason } => self.finish = Some(*reason),
            CanonicalEvent::Error(e) => self.error = Some(e.clone()),
        }
    }

    /// Whether any bound in [`limits`] was reached and content discarded.
    ///
    /// A caller that renders this accumulator should say so rather than present
    /// a silently short completion as a complete one.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether any semantic output has been observed.
    ///
    /// Once true, failover is forbidden (specification 6.5).
    #[must_use]
    pub const fn saw_semantic_output(&self) -> bool {
        self.saw_output
    }

    /// Tool calls sorted by stream index.
    #[must_use]
    pub fn sorted_tool_calls(&self) -> Vec<AccumulatedToolCall> {
        let mut calls = self.tool_calls.clone();
        calls.sort_by_key(|c| c.index);
        calls
    }
}

/// Append `addition` to `target`, stopping at `max`.
///
/// Returns whether anything was discarded. Truncation lands on a character
/// boundary, so the result is still valid UTF-8 and still renderable — a
/// completion cut mid-character would fail to serialise and turn a large
/// response into an error.
fn append_bounded(target: &mut String, addition: &str, max: usize) -> bool {
    if target.len() >= max {
        return !addition.is_empty();
    }
    let room = max.saturating_sub(target.len());
    if addition.len() <= room {
        target.push_str(addition);
        return false;
    }
    let mut end = room;
    while end > 0 && !addition.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(addition.get(..end).unwrap_or(""));
    true
}

/// A bounded description of an upstream failure, for classification.
///
/// Specification 7.1 requires `classify_error` to yield "retryability and safe
/// client detail". The provider's own message is never forwarded verbatim: it
/// can contain an internal hostname, a quota identifier, or an echo of the
/// prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamError {
    /// The provider's HTTP status, when there was one.
    pub status: Option<u16>,
    /// The provider's error type token, when it supplied one.
    pub provider_code: Option<Capped>,
    /// Whether the router may retry this on another target.
    pub retriable: bool,
    /// Retry delay the provider asked for.
    pub retry_after_secs: Option<u32>,
    /// The router's own classification.
    pub class: UpstreamErrorClass,
}

/// How an upstream failure is classified for failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamErrorClass {
    /// Could not connect or the connection dropped before acceptance.
    Connection,
    /// Timed out.
    Timeout,
    /// The provider rejected the credential.
    Authentication,
    /// The provider rate limited the request.
    RateLimited,
    /// The provider rejected the request as invalid.
    InvalidRequest,
    /// The requested context exceeded the model's window.
    ContextOverflow,
    /// The provider asked for a capability the model lacks.
    UnsupportedFeature,
    /// The provider returned a server error.
    ServerError,
    /// The provider's response violated the adapter contract.
    ProtocolViolation,
    /// The provider's content filter refused.
    ContentFilter,
}

impl UpstreamErrorClass {
    /// Whether this class may be failed over to another target.
    ///
    /// Specification 6.5: "429, connection refusal, timeout, selected 5xx, or
    /// circuit-open may fail over according to policy" while "context overflow,
    /// unsupported feature, policy denial, invalid request, and authentication
    /// errors are not retriable".
    #[must_use]
    pub const fn is_retriable(self) -> bool {
        matches!(
            self,
            Self::Connection
                | Self::Timeout
                | Self::RateLimited
                | Self::ServerError
                | Self::ProtocolViolation
        )
    }

    /// Whether this class should count against target health.
    ///
    /// A caller sending an invalid request says nothing about whether the
    /// target is healthy; counting it would let one bad client open a circuit
    /// for everyone.
    #[must_use]
    pub const fn affects_health(self) -> bool {
        matches!(
            self,
            Self::Connection | Self::Timeout | Self::ServerError | Self::ProtocolViolation
        )
    }

    /// Stable name for traces and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Timeout => "timeout",
            Self::Authentication => "authentication",
            Self::RateLimited => "rate_limited",
            Self::InvalidRequest => "invalid_request",
            Self::ContextOverflow => "context_overflow",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::ServerError => "server_error",
            Self::ProtocolViolation => "protocol_violation",
            Self::ContentFilter => "content_filter",
        }
    }

    /// Every class, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Connection,
            Self::Timeout,
            Self::Authentication,
            Self::RateLimited,
            Self::InvalidRequest,
            Self::ContextOverflow,
            Self::UnsupportedFeature,
            Self::ServerError,
            Self::ProtocolViolation,
            Self::ContentFilter,
        ]
    }

    /// The client-facing error this maps to.
    #[must_use]
    pub const fn to_client_code(self) -> crate::error::ErrorCode {
        use crate::error::ErrorCode as E;
        match self {
            Self::Connection | Self::ServerError | Self::ProtocolViolation => {
                E::UpstreamInvalidResponse
            }
            Self::Timeout => E::DeadlineExceeded,
            // A provider rejecting the router's credential is an operational
            // fault of the deployment, not something the caller did. It must
            // never surface as a 401 to the caller, which would tell them their
            // own key was wrong.
            Self::Authentication => E::InternalFault,
            Self::RateLimited => E::RateLimited,
            Self::InvalidRequest
            | Self::ContextOverflow
            | Self::UnsupportedFeature
            | Self::ContentFilter => E::InvalidRequest,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn accumulated_text_is_bounded_and_reports_truncation() {
        // Specification 3.2: no buffer originating from a request may be
        // unbounded. This one is written by the *provider* — a party whose
        // output length the router does not control and the caller cannot cap.
        // One upstream that never stops streaming was one router that ran out
        // of memory, from a request that looked ordinary.
        let mut acc = ResponseAccumulator::new();
        assert!(!acc.truncated());

        let chunk = "x".repeat(64 * 1024);
        for _ in 0..200 {
            acc.push(&CanonicalEvent::TextDelta(chunk.clone()));
        }
        assert!(acc.text.len() <= limits::MAX_TEXT_BYTES);
        assert!(
            acc.truncated(),
            "a truncated completion must say so rather than read as complete"
        );
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // A completion cut mid-character would fail to serialise, turning a
        // large response into an error rather than a short one.
        let mut acc = ResponseAccumulator::new();
        acc.push(&CanonicalEvent::TextDelta(
            "a".repeat(limits::MAX_TEXT_BYTES - 1),
        ));
        // A three-byte character that cannot fit in the one remaining byte.
        acc.push(&CanonicalEvent::TextDelta("\u{20ac}".to_owned()));

        assert!(acc.truncated());
        assert_eq!(acc.text.len(), limits::MAX_TEXT_BYTES - 1);
        // Still valid UTF-8 by construction; this asserts it is also unchanged.
        assert!(acc.text.chars().all(|c| c == 'a'));
    }

    #[test]
    fn tool_calls_are_bounded_in_count_and_in_argument_size() {
        let mut acc = ResponseAccumulator::new();
        for index in 0..(limits::MAX_TOOL_CALLS as u32 + 50) {
            acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
                index,
                id: None,
                name: None,
                arguments_delta: String::new(),
            }));
        }
        assert_eq!(acc.tool_calls.len(), limits::MAX_TOOL_CALLS);
        assert!(acc.truncated());

        let mut acc = ResponseAccumulator::new();
        let chunk = "y".repeat(64 * 1024);
        for _ in 0..40 {
            acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
                index: 0,
                id: None,
                name: None,
                arguments_delta: chunk.clone(),
            }));
        }
        assert!(acc.tool_calls[0].arguments.len() <= limits::MAX_TOOL_ARGUMENTS_BYTES);
        assert!(acc.truncated());
    }

    #[test]
    fn interleaved_tool_call_deltas_land_in_the_right_slots() {
        // Every `ToolCallDelta` used to scan the whole vector for its slot, so
        // N tool calls cost O(N²) in deltas — and a provider chooses both N and
        // the number of deltas. The fix is an index map.
        //
        // What this asserts is *correctness* of that map under interleaving,
        // not the complexity. A wall-clock test was written first and deleted:
        // at any size that runs quickly the linear version passes it too, so it
        // would have been decoration. The complexity claim rests on reading
        // `push`, and this test is what stops the map and the vector drifting
        // apart — which is the failure the optimisation could actually cause.
        let mut acc = ResponseAccumulator::new();
        let calls = 200u32;

        // Round-robin, so no call's deltas are contiguous.
        for round in 0..5u32 {
            for index in 0..calls {
                acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
                    index,
                    id: (round == 0).then(|| format!("call-{index}")),
                    name: (round == 0).then(|| format!("tool-{index}")),
                    arguments_delta: format!("{round}"),
                }));
            }
        }

        assert_eq!(acc.tool_calls.len(), calls as usize);
        let sorted = acc.sorted_tool_calls();
        for (index, call) in sorted.iter().enumerate() {
            let index = u32::try_from(index).expect("small");
            assert_eq!(call.index, index);
            assert_eq!(call.id, format!("call-{index}"));
            assert_eq!(call.name, format!("tool-{index}"));
            // Each call collected its own five deltas, in order, and nobody
            // else's.
            assert_eq!(call.arguments, "01234");
        }
    }

    #[test]
    fn embeddings_are_bounded() {
        let mut acc = ResponseAccumulator::new();
        for index in 0..(limits::MAX_EMBEDDINGS as u32 + 10) {
            acc.push(&CanonicalEvent::Embedding {
                index,
                values: vec![0.0],
            });
        }
        assert_eq!(acc.embeddings.len(), limits::MAX_EMBEDDINGS);
        assert!(acc.truncated());
    }


    use super::*;
    use crate::error::{ErrorCode, RouterError};

    #[test]
    fn an_unknown_provider_finish_reason_is_not_reported_as_a_natural_stop() {
        // Providers add stop reasons over time. Folding them into `Stop` tells
        // the caller the model finished when the router does not know that.
        assert_eq!(FinishReason::parse_anthropic("refusal"), None);
        assert_eq!(FinishReason::parse_anthropic("pause_turn"), None);
        assert_eq!(FinishReason::parse_openai("something_new"), None);

        // The distinct variant still renders as a spelling every client SDK
        // parses, so nothing downstream breaks.
        assert_eq!(FinishReason::Unrecognized.openai_str(), "stop");
        assert_eq!(FinishReason::Unrecognized.anthropic_str(), "stop_sequence");

        // But it is distinguishable from a genuine stop internally.
        assert_ne!(FinishReason::Unrecognized, FinishReason::Stop);
    }

    #[test]
    fn known_finish_reasons_still_round_trip() {
        for (wire, expected) in [
            ("stop", FinishReason::Stop),
            ("length", FinishReason::Length),
            ("tool_calls", FinishReason::ToolCalls),
            ("content_filter", FinishReason::ContentFilter),
        ] {
            assert_eq!(FinishReason::parse_openai(wire), Some(expected));
        }
        for (wire, expected) in [
            ("end_turn", FinishReason::Stop),
            ("stop_sequence", FinishReason::Stop),
            ("max_tokens", FinishReason::Length),
            ("tool_use", FinishReason::ToolCalls),
        ] {
            assert_eq!(FinishReason::parse_anthropic(wire), Some(expected));
        }
    }

    #[test]
    fn semantic_output_predicate_is_the_failover_gate() {
        assert!(CanonicalEvent::TextDelta("x".to_owned()).is_semantic_output());
        assert!(CanonicalEvent::ReasoningDelta("x".to_owned()).is_semantic_output());
        assert!(
            CanonicalEvent::ToolCallDelta(ToolCallDelta {
                index: 0,
                id: None,
                name: None,
                arguments_delta: "{".to_owned(),
            })
            .is_semantic_output()
        );
        assert!(
            CanonicalEvent::Embedding {
                index: 0,
                values: vec![0.0],
            }
            .is_semantic_output()
        );

        // These do not commit the router to a model: failover is still legal.
        assert!(
            !CanonicalEvent::Start {
                upstream_id: Some("id".to_owned()),
                native_model: Some("m".to_owned()),
            }
            .is_semantic_output()
        );
        assert!(!CanonicalEvent::Usage(CanonicalUsage::default()).is_semantic_output());
        assert!(
            !CanonicalEvent::Finish {
                reason: FinishReason::Stop
            }
            .is_semantic_output()
        );
    }

    #[test]
    fn terminal_events() {
        assert!(
            CanonicalEvent::Finish {
                reason: FinishReason::Stop
            }
            .is_terminal()
        );
        assert!(CanonicalEvent::Error(RouterError::internal()).is_terminal());
        assert!(!CanonicalEvent::TextDelta("x".to_owned()).is_terminal());
    }

    #[test]
    fn debug_never_prints_model_output() {
        let events = vec![
            CanonicalEvent::TextDelta("the secret answer".to_owned()),
            CanonicalEvent::ReasoningDelta("private chain of thought".to_owned()),
            CanonicalEvent::ToolCallDelta(ToolCallDelta {
                index: 0,
                id: Some("call_1".to_owned()),
                name: Some("lookup".to_owned()),
                arguments_delta: r#"{"q":"confidential"}"#.to_owned(),
            }),
        ];
        let rendered = format!("{events:?}");
        assert!(!rendered.contains("secret answer"));
        assert!(!rendered.contains("chain of thought"));
        assert!(!rendered.contains("confidential"));
        assert!(rendered.contains("call_1"), "identifiers stay visible");
    }

    #[test]
    fn usage_carries_provenance() {
        let e = CanonicalUsage::estimated(100, 50);
        assert!(!e.is_reported());
        assert_eq!(e.source, UsageSource::RouterEstimated);
        assert_eq!(e.total(), 150);

        let r = CanonicalUsage::reported(100, 50);
        assert!(r.is_reported());
        assert_ne!(e, r, "provenance is part of the value");
    }

    #[test]
    fn accumulator_assembles_text_and_tool_calls() {
        let mut acc = ResponseAccumulator::new();
        acc.push(&CanonicalEvent::Start {
            upstream_id: Some("resp_1".to_owned()),
            native_model: Some("qwen-coder".to_owned()),
        });
        acc.push(&CanonicalEvent::TextDelta("Hello".to_owned()));
        acc.push(&CanonicalEvent::TextDelta(", world".to_owned()));
        acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
            index: 0,
            id: Some("call_a".to_owned()),
            name: Some("lookup".to_owned()),
            arguments_delta: r#"{"q":"#.to_owned(),
        }));
        acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
            index: 0,
            id: None,
            name: None,
            arguments_delta: r#""x"}"#.to_owned(),
        }));
        acc.push(&CanonicalEvent::Usage(CanonicalUsage::reported(10, 5)));
        acc.push(&CanonicalEvent::Finish {
            reason: FinishReason::ToolCalls,
        });

        assert_eq!(acc.text, "Hello, world");
        assert_eq!(acc.upstream_id.as_deref(), Some("resp_1"));
        assert_eq!(acc.native_model.as_deref(), Some("qwen-coder"));
        assert_eq!(acc.finish, Some(FinishReason::ToolCalls));
        assert_eq!(acc.usage.unwrap().total(), 15);

        let calls = acc.sorted_tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_a");
        assert_eq!(calls[0].name, "lookup");
        assert_eq!(calls[0].arguments, r#"{"q":"x"}"#);
    }

    #[test]
    fn interleaved_tool_calls_do_not_merge() {
        // The reason `index` is on the wire rather than implied: a provider
        // that interleaves two calls must not have their arguments concatenated.
        let mut acc = ResponseAccumulator::new();
        for (index, id, frag) in [
            (0u32, Some("call_a"), r#"{"a":"#),
            (1, Some("call_b"), r#"{"b":"#),
            (0, None, "1}"),
            (1, None, "2}"),
        ] {
            acc.push(&CanonicalEvent::ToolCallDelta(ToolCallDelta {
                index,
                id: id.map(str::to_owned),
                name: id.map(|_| "t".to_owned()),
                arguments_delta: frag.to_owned(),
            }));
        }
        let calls = acc.sorted_tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].arguments, r#"{"a":1}"#);
        assert_eq!(calls[1].arguments, r#"{"b":2}"#);
        assert_eq!(calls[0].id, "call_a");
        assert_eq!(calls[1].id, "call_b");
    }

    #[test]
    fn accumulator_tracks_semantic_output() {
        let mut acc = ResponseAccumulator::new();
        assert!(!acc.saw_semantic_output());
        acc.push(&CanonicalEvent::Start {
            upstream_id: None,
            native_model: None,
        });
        assert!(!acc.saw_semantic_output(), "start is not semantic output");
        acc.push(&CanonicalEvent::TextDelta("x".to_owned()));
        assert!(acc.saw_semantic_output());
    }

    #[test]
    fn finish_reason_mappings_roundtrip() {
        for r in [
            FinishReason::Stop,
            FinishReason::Length,
            FinishReason::ToolCalls,
            FinishReason::ContentFilter,
        ] {
            assert_eq!(FinishReason::parse_openai(r.openai_str()), Some(r));
        }
        assert_eq!(
            FinishReason::parse_anthropic("max_tokens"),
            Some(FinishReason::Length)
        );
        assert_eq!(
            FinishReason::parse_anthropic("tool_use"),
            Some(FinishReason::ToolCalls)
        );
        assert_eq!(FinishReason::parse_openai("nope"), None);
        // Cancellation has no OpenAI spelling; it must map to something the
        // client's SDK can parse rather than a novel token.
        assert_eq!(FinishReason::Cancelled.openai_str(), "stop");
    }

    #[test]
    fn upstream_error_retriability_matches_specification_6_5() {
        for class in [
            UpstreamErrorClass::Connection,
            UpstreamErrorClass::Timeout,
            UpstreamErrorClass::RateLimited,
            UpstreamErrorClass::ServerError,
        ] {
            assert!(class.is_retriable(), "{class:?} should be retriable");
        }
        for class in [
            UpstreamErrorClass::Authentication,
            UpstreamErrorClass::InvalidRequest,
            UpstreamErrorClass::ContextOverflow,
            UpstreamErrorClass::UnsupportedFeature,
            UpstreamErrorClass::ContentFilter,
        ] {
            assert!(!class.is_retriable(), "{class:?} must not be retriable");
        }
    }

    #[test]
    fn client_error_classes_do_not_affect_target_health() {
        // One caller sending malformed requests must not open a circuit that
        // takes a healthy target out of service for everyone else.
        for class in [
            UpstreamErrorClass::InvalidRequest,
            UpstreamErrorClass::ContextOverflow,
            UpstreamErrorClass::UnsupportedFeature,
            UpstreamErrorClass::ContentFilter,
            UpstreamErrorClass::RateLimited,
        ] {
            assert!(!class.affects_health(), "{class:?} must not affect health");
        }
        for class in [
            UpstreamErrorClass::Connection,
            UpstreamErrorClass::Timeout,
            UpstreamErrorClass::ServerError,
            UpstreamErrorClass::ProtocolViolation,
        ] {
            assert!(class.affects_health(), "{class:?} should affect health");
        }
    }

    #[test]
    fn provider_credential_failure_is_not_reported_as_client_auth_failure() {
        // Telling a caller "unauthenticated" when it is the router's own
        // provider key that expired sends them to debug the wrong thing.
        assert_eq!(
            UpstreamErrorClass::Authentication.to_client_code(),
            ErrorCode::InternalFault
        );
        assert_ne!(
            UpstreamErrorClass::Authentication.to_client_code(),
            ErrorCode::Unauthenticated
        );
    }

    #[test]
    fn error_class_names_are_distinct() {
        let mut names: Vec<&str> = UpstreamErrorClass::all().iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }
}
