//! Golden provider responses for replay without network egress.
//!
//! Specification 21 requires integration tests "against recorded golden
//! servers", and specification 7 fixes what each provider family's wire format
//! means. These fixtures are what a golden server replays: the exact bytes an
//! adapter's decoder must turn into canonical events, paired with the events it
//! must produce.
//!
//! # A family is not a dialect
//!
//! The OpenAI-compatible family serves two wire dialects, and both are
//! recorded: Chat Completions, and the Responses API that specification 7 puts
//! first and specification 8 marks a MUST for new integrations. They share a
//! provider and an adapter and almost nothing else — `output` items rather than
//! `choices`, `input_tokens` rather than `prompt_tokens`, `status` rather than
//! `finish_reason`, named SSE events with no `[DONE]` sentinel rather than
//! unnamed frames with one. [`GoldenDialect`] records which a fixture is in, so
//! that a framing assertion applies the rules that actually govern it.
//!
//! # These fixtures are synthetic
//!
//! **Nothing here was recorded from a live provider.** Every body below was
//! written by hand against the shapes `hypellm-adapters` decodes. There are no
//! real API keys, no organisation or account identifiers, no real prompts, and
//! no real completions — the prompts are one sentence about backpressure and
//! the tool call lists a directory. Identifiers are spelled `*_hypellm_golden_*`
//! so that a grep for a leaked credential can rule this crate out at a glance.
//!
//! That is a deliberate constraint, not an apology for the fixtures being small.
//! A golden corpus is a permanent plaintext artifact: it lives in every
//! checkout and in version history forever. Specification 10 keeps credentials
//! behind opaque handles and specification 17 keeps prompt and completion
//! bodies out of logs by default; a fixture captured unredacted from a real
//! exchange defeats both, permanently. If a recording tool is ever built, it
//! must redact at capture time — a reviewer scanning a multi-megabyte SSE
//! transcript is not a control.
//!
//! It also has a cost worth naming: a hand-written fixture cannot surface a
//! shape the author did not know about. These goldens prove the decoder handles
//! the documented shapes; they cannot prove it handles what a provider actually
//! sends today. That gap is recorded in `MODULE.md` and is not closed here.
//!
//! # What the expectations mean
//!
//! Expected values are spelled as plain data rather than as `hypellm_core` types,
//! because this crate takes no dependencies (see `MODULE.md` for why). A
//! consumer maps [`ExpectedFinish`] onto `FinishReason` and the class string
//! onto `UpstreamErrorClass::as_str` in one match arm.

/// The provider family a fixture belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoldenFamily {
    /// The OpenAI-compatible wire format: OpenAI itself, llama.cpp, DeepSeek,
    /// Moonshot, and the opt-in generic adapter all share it.
    OpenAiCompatible,
    /// The Anthropic Messages wire format.
    Anthropic,
}

impl GoldenFamily {
    /// The `hypellm_core::target::ProviderFamily::as_str` token a consumer would
    /// construct the adapter with.
    ///
    /// `OpenAiCompatible` reports `openai` because that is the family whose
    /// adapter behaviour the fixture was written against; the same bytes are
    /// valid for the other OpenAI-compatible families, which differ in declared
    /// capabilities rather than in wire shape.
    #[must_use]
    pub const fn provider_family_token(self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

/// The wire dialect a fixture is written in.
///
/// The family is not enough. The OpenAI-compatible family serves **two**
/// dialects — Chat Completions and the Responses API, which specification 8
/// marks a MUST for new integrations — and they differ in every respect a
/// decoder cares about: `messages` against `input` items, `choices` against a
/// typed `output` array, `finish_reason` against `status` plus
/// `incomplete_details`, and unnamed SSE frames ending in a `[DONE]` sentinel
/// against named events with no sentinel at all.
///
/// Recorded on the fixture so that a framing assertion knows which rules apply
/// to it. Without it, a test can only assert what is true of every fixture in
/// the family, which is nothing.
///
/// Failure fixtures carry no dialect: error classification is shared by both
/// OpenAI-compatible dialects, and [`FailurePath`] already records the event
/// name that distinguishes their stream failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoldenDialect {
    /// `POST /v1/chat/completions` and its `chat.completion.chunk` stream.
    ChatCompletions,
    /// `POST /v1/responses` and its named event stream.
    Responses,
    /// `POST /v1/messages` and its content-block stream.
    Messages,
}

impl GoldenDialect {
    /// The family that serves this dialect.
    #[must_use]
    pub const fn family(self) -> GoldenFamily {
        match self {
            Self::ChatCompletions | Self::Responses => GoldenFamily::OpenAiCompatible,
            Self::Messages => GoldenFamily::Anthropic,
        }
    }

    /// Whether a stream in this dialect ends with a `[DONE]` sentinel.
    ///
    /// Only Chat Completions has one. A reader that waits for it on a Responses
    /// or Messages stream hangs until the deadline fires, which is why this is
    /// recorded rather than assumed.
    #[must_use]
    pub const fn has_done_sentinel(self) -> bool {
        matches!(self, Self::ChatCompletions)
    }

    /// Whether every SSE frame in this dialect carries an `event:` name.
    #[must_use]
    pub const fn names_stream_events(self) -> bool {
        matches!(self, Self::Responses | Self::Messages)
    }

    /// Stable name, for assertion messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Responses => "responses",
            Self::Messages => "messages",
        }
    }

    /// Every dialect, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::ChatCompletions, Self::Responses, Self::Messages]
    }
}

/// The canonical finish reason a decoder must produce.
///
/// Mirrors `hypellm_core::event::FinishReason` without depending on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedFinish {
    /// The model finished naturally.
    Stop,
    /// The output token limit was reached.
    Length,
    /// The model emitted tool calls and is waiting for results.
    ToolCalls,
    /// The provider's content filter stopped generation.
    ContentFilter,
    /// The provider reported a reason this router does not recognise.
    ///
    /// Present because folding an unknown reason into `Stop` would tell a
    /// caller the model finished when it may have refused.
    Unrecognized,
}

impl ExpectedFinish {
    /// The canonical variant name, for assertion messages and for consumers
    /// that prefer to compare strings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolCalls => "tool_calls",
            Self::ContentFilter => "content_filter",
            Self::Unrecognized => "unrecognized",
        }
    }
}

/// A tool call a decoder must assemble from a response or a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedToolCall {
    /// The position the provider assigned, which call identity depends on.
    pub index: u32,
    /// The provider's call identifier.
    pub id: &'static str,
    /// The tool name.
    pub name: &'static str,
    /// The complete JSON arguments, after every fragment has been joined.
    pub arguments: &'static str,
}

/// Everything a decoder must produce from one completion, streamed or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedCompletion {
    /// The provider's response identifier, when the decoder surfaces one.
    ///
    /// `None` for OpenAI-compatible *streams*: that adapter emits no start
    /// event from stream frames, so the identifier is not observable through
    /// the decoder. This is a property of the adapter, not of the fixture.
    pub upstream_id: Option<&'static str>,
    /// The native model the provider reported, when the decoder surfaces one.
    pub native_model: Option<&'static str>,
    /// The assembled assistant text.
    pub text: &'static str,
    /// The assembled reasoning text, empty when the fixture has none.
    pub reasoning: &'static str,
    /// The finish reason.
    pub finish: ExpectedFinish,
    /// Provider-reported input tokens.
    pub input_tokens: u64,
    /// Provider-reported output tokens.
    pub output_tokens: u64,
    /// Provider-reported cached input tokens.
    pub cached_input_tokens: u64,
    /// Whether usage is provider-reported rather than router-estimated.
    pub usage_is_reported: bool,
    /// Tool calls, in index order.
    pub tool_calls: &'static [ExpectedToolCall],
}

/// A recorded non-streaming response body.
#[derive(Debug, Clone, Copy)]
pub struct GoldenResponse {
    /// Stable identifier.
    pub name: &'static str,
    /// Which wire format it is in.
    pub family: GoldenFamily,
    /// Which of that family's dialects it is in.
    pub dialect: GoldenDialect,
    /// The HTTP status it was served with.
    pub status: u16,
    /// The response body.
    pub body: &'static str,
    /// What the decoder must produce.
    pub expect: ExpectedCompletion,
    /// What this fixture is for.
    pub why: &'static str,
}

/// One frame of a recorded stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrame {
    /// The SSE `event:` name, when the provider names its events.
    pub event: Option<&'static str>,
    /// The SSE `data:` payload.
    pub data: &'static str,
}

impl StreamFrame {
    /// An unnamed frame, which is the OpenAI-compatible shape.
    #[must_use]
    pub const fn data(data: &'static str) -> Self {
        Self { event: None, data }
    }

    /// A named frame, which is the Anthropic shape.
    #[must_use]
    pub const fn named(event: &'static str, data: &'static str) -> Self {
        Self {
            event: Some(event),
            data,
        }
    }
}

/// A recorded streaming response.
#[derive(Debug, Clone, Copy)]
pub struct GoldenStream {
    /// Stable identifier.
    pub name: &'static str,
    /// Which wire format it is in.
    pub family: GoldenFamily,
    /// Which of that family's dialects it is in, which decides how the stream
    /// is framed and how it ends.
    pub dialect: GoldenDialect,
    /// The frames in the order they arrived.
    pub frames: &'static [StreamFrame],
    /// What the decoder must produce once every frame has been fed to it.
    pub expect: ExpectedCompletion,
    /// What this fixture is for.
    pub why: &'static str,
}

/// One embedding vector a decoder must produce.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExpectedEmbedding {
    /// The provider-assigned position.
    pub index: u32,
    /// The vector.
    ///
    /// Every component is exactly representable in binary floating point, so a
    /// consumer may compare with `==` and a failure means a decoding fault
    /// rather than a rounding difference.
    pub values: &'static [f32],
}

/// A recorded embeddings response.
#[derive(Debug, Clone, Copy)]
pub struct GoldenEmbeddings {
    /// Stable identifier.
    pub name: &'static str,
    /// Which wire format it is in.
    pub family: GoldenFamily,
    /// The HTTP status it was served with.
    pub status: u16,
    /// The response body.
    pub body: &'static str,
    /// The vectors the decoder must produce, in order.
    pub expect: &'static [ExpectedEmbedding],
    /// Provider-reported input tokens.
    pub input_tokens: u64,
    /// What this fixture is for.
    pub why: &'static str,
}

/// How a failure fixture reaches the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePath {
    /// Feed the body to the adapter's whole-response decoder along with the
    /// status. This covers both an error status and a malformed success body.
    Response,
    /// Feed the payload to the adapter's stream-event decoder, with this event
    /// name.
    StreamEvent {
        /// The SSE event name, when the provider names its events.
        event: Option<&'static str>,
    },
}

/// A recorded provider failure.
#[derive(Debug, Clone, Copy)]
pub struct GoldenFailure {
    /// Stable identifier.
    pub name: &'static str,
    /// Which wire format it is in.
    pub family: GoldenFamily,
    /// How to feed it to the adapter.
    pub path: FailurePath,
    /// The HTTP status, when the failure arrived as a response.
    pub status: u16,
    /// The body or stream payload.
    pub body: &'static str,
    /// The `hypellm_core::event::UpstreamErrorClass::as_str` value the adapter
    /// must classify it as.
    pub expect_class: &'static str,
    /// The narrowed provider code the adapter must record, when it records one.
    pub expect_provider_code: Option<&'static str>,
    /// Whether specification 6.5 permits failing over on this class.
    pub expect_retriable: bool,
    /// Text that must NOT appear in the detail the client is shown.
    ///
    /// Provider messages routinely echo the prompt or an internal hostname;
    /// specification 10 keeps them out of the client's error. Each fixture
    /// names the fragment of its own body that must not survive.
    pub must_not_leak: &'static [&'static str],
    /// What this fixture is for.
    pub why: &'static str,
}

/// Every non-streaming completion fixture.
#[must_use]
pub const fn responses() -> &'static [GoldenResponse] {
    RESPONSES
}

/// Every streaming completion fixture.
#[must_use]
pub const fn streams() -> &'static [GoldenStream] {
    STREAMS
}

/// Every embeddings fixture.
#[must_use]
pub const fn embeddings() -> &'static [GoldenEmbeddings] {
    EMBEDDINGS
}

/// Every failure fixture.
#[must_use]
pub const fn failures() -> &'static [GoldenFailure] {
    FAILURES
}

/// Look one completion fixture up by name.
#[must_use]
pub fn response_by_name(name: &str) -> Option<&'static GoldenResponse> {
    RESPONSES.iter().find(|r| r.name == name)
}

/// Look one stream fixture up by name.
#[must_use]
pub fn stream_by_name(name: &str) -> Option<&'static GoldenStream> {
    STREAMS.iter().find(|s| s.name == name)
}

const NO_TOOL_CALLS: &[ExpectedToolCall] = &[];

const RESPONSES: &[GoldenResponse] = &[
    GoldenResponse {
        name: "golden/openai_chat_completion",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        status: 200,
        body: r#"{"id":"chatcmpl-hypellm-golden-0001","object":"chat.completion","created":1750000000,"model":"gpt-4.1-2025-04-14","choices":[{"index":0,"message":{"role":"assistant","content":"Backpressure is flow control."},"finish_reason":"stop"}],"usage":{"prompt_tokens":24,"completion_tokens":7,"total_tokens":31,"prompt_tokens_details":{"cached_tokens":16}}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("chatcmpl-hypellm-golden-0001"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 24,
            output_tokens: 7,
            cached_input_tokens: 16,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "The ordinary success path, including the nested `prompt_tokens_details` that cached-token accounting depends on.",
    },
    GoldenResponse {
        name: "golden/openai_chat_completion_tool_call",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        status: 200,
        body: r#"{"id":"chatcmpl-hypellm-golden-0002","object":"chat.completion","created":1750000001,"model":"gpt-4.1-2025-04-14","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_hypellm_golden_0001","type":"function","function":{"name":"list_files","arguments":"{\"path\":\"/srv\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":30,"completion_tokens":12,"total_tokens":42}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("chatcmpl-hypellm-golden-0002"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "",
            reasoning: "",
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 30,
            output_tokens: 12,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: &[ExpectedToolCall {
                index: 0,
                id: "call_hypellm_golden_0001",
                name: "list_files",
                arguments: r#"{"path":"/srv"}"#,
            }],
        },
        why: "`content` is JSON null here, not an empty string. A decoder that stringifies null emits a text delta the model never produced — and specification 6.5 forbids failing over once any content delta has reached the client.",
    },
    GoldenResponse {
        name: "golden/openai_chat_completion_length_stop",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        status: 200,
        body: r#"{"id":"chatcmpl-hypellm-golden-0003","object":"chat.completion","created":1750000002,"model":"gpt-4.1-2025-04-14","choices":[{"index":0,"message":{"role":"assistant","content":"Backpressure is"},"finish_reason":"length"}],"usage":{"prompt_tokens":24,"completion_tokens":4,"total_tokens":28}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("chatcmpl-hypellm-golden-0003"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Backpressure is",
            reasoning: "",
            finish: ExpectedFinish::Length,
            input_tokens: 24,
            output_tokens: 4,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "A truncated completion must be reported as truncated; reporting it as a natural stop tells the caller the answer is complete.",
    },
    GoldenResponse {
        name: "golden/openai_chat_completion_without_usage",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        status: 200,
        body: r#"{"id":"chatcmpl-hypellm-golden-0004","object":"chat.completion","model":"local-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("chatcmpl-hypellm-golden-0004"),
            native_model: Some("local-model"),
            text: "ok",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            usage_is_reported: false,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "Some OpenAI-compatible servers, llama.cpp among them, omit usage entirely. Specification 14 requires the provenance to travel with the number, so an absent usage must not be reported as a provider-reported zero.",
    },
    GoldenResponse {
        name: "golden/openai_responses_completion",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        status: 200,
        body: r#"{"id":"resp_hypellm_golden_0001","object":"response","created_at":1750000020,"status":"completed","model":"gpt-4.1-2025-04-14","output":[{"type":"message","id":"msg_hypellm_golden_0011","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Backpressure is flow control.","annotations":[]}]}],"usage":{"input_tokens":24,"output_tokens":7,"total_tokens":31,"input_tokens_details":{"cached_tokens":16}}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("resp_hypellm_golden_0001"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 24,
            output_tokens: 7,
            cached_input_tokens: 16,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "The same completion as `golden/openai_chat_completion` in the other dialect of the same family: `output` items rather than `choices`, `input_tokens`/`output_tokens` rather than `prompt_tokens`/`completion_tokens`, and `status` rather than `finish_reason`. A decoder that reads the Chat spelling here reports empty text and meters the request as free.",
    },
    GoldenResponse {
        name: "golden/openai_responses_completion_tool_call",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        status: 200,
        body: r#"{"id":"resp_hypellm_golden_0002","object":"response","created_at":1750000021,"status":"completed","model":"gpt-4.1-2025-04-14","output":[{"type":"message","id":"msg_hypellm_golden_0012","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Listing.","annotations":[]}]},{"type":"function_call","id":"fc_hypellm_golden_0001","call_id":"call_hypellm_golden_0011","status":"completed","name":"list_files","arguments":"{\"path\":\"/srv\"}"}],"usage":{"input_tokens":30,"output_tokens":12,"total_tokens":42}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("resp_hypellm_golden_0002"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Listing.",
            reasoning: "",
            // `status` is `completed` even though the model is waiting for a
            // tool result: this dialect has no `finish_reason` to say so.
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 30,
            output_tokens: 12,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: &[ExpectedToolCall {
                // The item's position in `output`, not a counter over tool
                // calls: the message item occupies index 0.
                index: 1,
                // `call_id`, not the item's own `id`. A later
                // `function_call_output` quotes the former, so a decoder that
                // surfaces `fc_…` gives the client an identifier it cannot use.
                id: "call_hypellm_golden_0011",
                name: "list_files",
                arguments: r#"{"path":"/srv"}"#,
            }],
        },
        why: "Reporting a plain stop here would tell the caller the turn is finished while a tool call is outstanding, and the caller would never send the result.",
    },
    GoldenResponse {
        name: "golden/openai_responses_completion_incomplete",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        status: 200,
        body: r#"{"id":"resp_hypellm_golden_0003","object":"response","created_at":1750000022,"status":"incomplete","model":"gpt-4.1-2025-04-14","output":[{"type":"message","id":"msg_hypellm_golden_0013","status":"incomplete","role":"assistant","content":[{"type":"output_text","text":"Backpressure is","annotations":[]}]}],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":24,"output_tokens":4,"total_tokens":28}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("resp_hypellm_golden_0003"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Backpressure is",
            reasoning: "",
            finish: ExpectedFinish::Length,
            input_tokens: 24,
            output_tokens: 4,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "Truncation is two fields here rather than one: `status` says the response is incomplete and `incomplete_details.reason` says why. A decoder that reads only the status cannot tell a truncated answer from a filtered one.",
    },
    GoldenResponse {
        name: "golden/openai_responses_completion_unknown_reason",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        status: 200,
        body: r#"{"id":"resp_hypellm_golden_0004","object":"response","created_at":1750000023,"status":"incomplete","model":"gpt-4.1-2025-04-14","output":[{"type":"message","id":"msg_hypellm_golden_0014","status":"incomplete","role":"assistant","content":[{"type":"output_text","text":"I will not.","annotations":[]}]}],"incomplete_details":{"reason":"policy_review"},"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("resp_hypellm_golden_0004"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "I will not.",
            reasoning: "",
            finish: ExpectedFinish::Unrecognized,
            input_tokens: 11,
            output_tokens: 4,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "The Responses twin of `golden/anthropic_message_unknown_stop_reason`. Providers add reasons over time; an unknown one must stay unknown rather than be folded into a natural stop.",
    },
    GoldenResponse {
        name: "golden/anthropic_message",
        family: GoldenFamily::Anthropic,
        dialect: GoldenDialect::Messages,
        status: 200,
        body: r#"{"id":"msg_hypellm_golden_0001","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[{"type":"text","text":"Backpressure is flow control."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":24,"output_tokens":7,"cache_read_input_tokens":16}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("msg_hypellm_golden_0001"),
            native_model: Some("claude-sonnet-4-5-20250929"),
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 24,
            output_tokens: 7,
            cached_input_tokens: 16,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "The Anthropic success path: content blocks rather than a message string, and `end_turn` rather than `stop`.",
    },
    GoldenResponse {
        name: "golden/anthropic_message_tool_use",
        family: GoldenFamily::Anthropic,
        dialect: GoldenDialect::Messages,
        status: 200,
        body: r#"{"id":"msg_hypellm_golden_0002","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[{"type":"text","text":"Listing."},{"type":"tool_use","id":"toolu_hypellm_golden_0001","name":"list_files","input":{"path":"/srv"}}],"stop_reason":"tool_use","usage":{"input_tokens":30,"output_tokens":12}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("msg_hypellm_golden_0002"),
            native_model: Some("claude-sonnet-4-5-20250929"),
            text: "Listing.",
            reasoning: "",
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 30,
            output_tokens: 12,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: &[ExpectedToolCall {
                // The block position, not a counter over tool blocks: the text
                // block occupies index 0.
                index: 1,
                id: "toolu_hypellm_golden_0001",
                name: "list_files",
                arguments: r#"{"path":"/srv"}"#,
            }],
        },
        why: "Tool arguments arrive as a JSON object here and as a JSON string in the OpenAI format. The canonical form is the string, so the decoder must re-serialize rather than pass the value through.",
    },
    GoldenResponse {
        name: "golden/anthropic_message_unknown_stop_reason",
        family: GoldenFamily::Anthropic,
        dialect: GoldenDialect::Messages,
        status: 200,
        body: r#"{"id":"msg_hypellm_golden_0003","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[{"type":"text","text":"I will not."}],"stop_reason":"refusal","usage":{"input_tokens":11,"output_tokens":4}}"#,
        expect: ExpectedCompletion {
            upstream_id: Some("msg_hypellm_golden_0003"),
            native_model: Some("claude-sonnet-4-5-20250929"),
            text: "I will not.",
            reasoning: "",
            finish: ExpectedFinish::Unrecognized,
            input_tokens: 11,
            output_tokens: 4,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "Providers add stop reasons over time. An unknown one must stay unknown: folding `refusal` into a natural stop tells the caller the model answered when it declined.",
    },
];

const STREAMS: &[GoldenStream] = &[
    GoldenStream {
        name: "golden/openai_chat_stream",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        frames: &[
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0101","object":"chat.completion.chunk","created":1750000010,"model":"gpt-4.1-2025-04-14","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0101","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Back"},"finish_reason":null}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0101","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"pressure is flow control."},"finish_reason":null}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0101","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0101","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":24,"completion_tokens":5,"total_tokens":29}}"#,
            ),
            StreamFrame::data("[DONE]"),
        ],
        expect: ExpectedCompletion {
            // The OpenAI-compatible adapter emits no start event from stream
            // frames, so the identifier in the payloads is not observable here.
            upstream_id: None,
            native_model: None,
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 24,
            output_tokens: 5,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "The first frame carries an empty content delta and the last a usage-only chunk. Emitting a text delta for the empty one would make specification 6.5 treat the response as already committed before any content existed.",
    },
    GoldenStream {
        name: "golden/openai_chat_stream_interleaved_tool_calls",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::ChatCompletions,
        frames: &[
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0102","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_hypellm_golden_0101","type":"function","function":{"name":"list_files","arguments":"{\"path\":"}}]}}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0102","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_hypellm_golden_0102","type":"function","function":{"name":"read_file","arguments":"{\"path\":"}}]}}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0102","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"/srv\"}"}}]}}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0102","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"/etc/hosts\"}"}}]}}]}"#,
            ),
            StreamFrame::data(
                r#"{"id":"chatcmpl-hypellm-golden-0102","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            ),
            StreamFrame::data("[DONE]"),
        ],
        expect: ExpectedCompletion {
            upstream_id: None,
            native_model: None,
            text: "",
            reasoning: "",
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            usage_is_reported: false,
            tool_calls: &[
                ExpectedToolCall {
                    index: 0,
                    id: "call_hypellm_golden_0101",
                    name: "list_files",
                    arguments: r#"{"path":"/srv"}"#,
                },
                ExpectedToolCall {
                    index: 1,
                    id: "call_hypellm_golden_0102",
                    name: "read_file",
                    arguments: r#"{"path":"/etc/hosts"}"#,
                },
            ],
        },
        why: "Two calls interleave, and their fragments arrive out of order relative to each other. The provider's own index is what keeps them apart; using array position would merge `/srv` and `/etc/hosts` into one call's arguments.",
    },
    GoldenStream {
        name: "golden/openai_responses_stream",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        frames: &[
            StreamFrame::named(
                "response.created",
                r#"{"type":"response.created","response":{"id":"resp_hypellm_golden_0101","object":"response","created_at":1750000030,"status":"in_progress","model":"gpt-4.1-2025-04-14","output":[]}}"#,
            ),
            StreamFrame::named(
                "response.in_progress",
                r#"{"type":"response.in_progress","response":{"id":"resp_hypellm_golden_0101","object":"response","status":"in_progress","model":"gpt-4.1-2025-04-14","output":[]}}"#,
            ),
            StreamFrame::named(
                "response.output_item.added",
                r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_hypellm_golden_0101","status":"in_progress","role":"assistant","content":[]}}"#,
            ),
            StreamFrame::named(
                "response.content_part.added",
                r#"{"type":"response.content_part.added","item_id":"msg_hypellm_golden_0101","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}"#,
            ),
            StreamFrame::named(
                "response.output_text.delta",
                r#"{"type":"response.output_text.delta","item_id":"msg_hypellm_golden_0101","output_index":0,"content_index":0,"delta":"Back"}"#,
            ),
            StreamFrame::named(
                "response.output_text.delta",
                r#"{"type":"response.output_text.delta","item_id":"msg_hypellm_golden_0101","output_index":0,"content_index":0,"delta":"pressure is flow control."}"#,
            ),
            StreamFrame::named(
                "response.output_text.done",
                r#"{"type":"response.output_text.done","item_id":"msg_hypellm_golden_0101","output_index":0,"content_index":0,"text":"Backpressure is flow control."}"#,
            ),
            StreamFrame::named(
                "response.content_part.done",
                r#"{"type":"response.content_part.done","item_id":"msg_hypellm_golden_0101","output_index":0,"content_index":0,"part":{"type":"output_text","text":"Backpressure is flow control.","annotations":[]}}"#,
            ),
            StreamFrame::named(
                "response.output_item.done",
                r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_hypellm_golden_0101","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Backpressure is flow control.","annotations":[]}]}}"#,
            ),
            StreamFrame::named(
                "response.completed",
                r#"{"type":"response.completed","response":{"id":"resp_hypellm_golden_0101","object":"response","status":"completed","model":"gpt-4.1-2025-04-14","output":[{"type":"message","id":"msg_hypellm_golden_0101","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Backpressure is flow control.","annotations":[]}]}],"usage":{"input_tokens":24,"output_tokens":5,"total_tokens":29}}}"#,
            ),
        ],
        expect: ExpectedCompletion {
            // Unlike the Chat Completions stream, this dialect announces the
            // response in a `response.created` event, so the identifier and the
            // native model are observable from the stream alone.
            upstream_id: Some("resp_hypellm_golden_0101"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            input_tokens: 24,
            output_tokens: 5,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "Four of these frames repeat text the deltas already delivered — the two `.done` events, the item `.done`, and the terminal `response.completed` all carry the whole string. A decoder that emits from any of them delivers the completion two or three times. Note also what is absent: there is no `[DONE]` sentinel, so the stream ends at `response.completed` and a reader waiting for the Chat Completions marker hangs until the deadline fires.",
    },
    GoldenStream {
        name: "golden/openai_responses_stream_tool_call",
        family: GoldenFamily::OpenAiCompatible,
        dialect: GoldenDialect::Responses,
        frames: &[
            StreamFrame::named(
                "response.created",
                r#"{"type":"response.created","response":{"id":"resp_hypellm_golden_0102","object":"response","created_at":1750000031,"status":"in_progress","model":"gpt-4.1-2025-04-14","output":[]}}"#,
            ),
            StreamFrame::named(
                "response.output_item.added",
                r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_hypellm_golden_0101","call_id":"call_hypellm_golden_0111","name":"list_files","arguments":"","status":"in_progress"}}"#,
            ),
            StreamFrame::named(
                "response.function_call_arguments.delta",
                r#"{"type":"response.function_call_arguments.delta","item_id":"fc_hypellm_golden_0101","output_index":0,"delta":"{\"path\":"}"#,
            ),
            StreamFrame::named(
                "response.function_call_arguments.delta",
                r#"{"type":"response.function_call_arguments.delta","item_id":"fc_hypellm_golden_0101","output_index":0,"delta":"\"/srv\"}"}"#,
            ),
            StreamFrame::named(
                "response.function_call_arguments.done",
                r#"{"type":"response.function_call_arguments.done","item_id":"fc_hypellm_golden_0101","output_index":0,"arguments":"{\"path\":\"/srv\"}"}"#,
            ),
            StreamFrame::named(
                "response.output_item.done",
                r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_hypellm_golden_0101","call_id":"call_hypellm_golden_0111","name":"list_files","arguments":"{\"path\":\"/srv\"}","status":"completed"}}"#,
            ),
            StreamFrame::named(
                "response.completed",
                r#"{"type":"response.completed","response":{"id":"resp_hypellm_golden_0102","object":"response","status":"completed","model":"gpt-4.1-2025-04-14","output":[{"type":"function_call","id":"fc_hypellm_golden_0101","call_id":"call_hypellm_golden_0111","name":"list_files","arguments":"{\"path\":\"/srv\"}","status":"completed"}],"usage":{"input_tokens":30,"output_tokens":15,"total_tokens":45}}}"#,
            ),
        ],
        expect: ExpectedCompletion {
            upstream_id: Some("resp_hypellm_golden_0102"),
            native_model: Some("gpt-4.1-2025-04-14"),
            text: "",
            reasoning: "",
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 30,
            output_tokens: 15,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: &[ExpectedToolCall {
                index: 0,
                id: "call_hypellm_golden_0111",
                name: "list_files",
                arguments: r#"{"path":"/srv"}"#,
            }],
        },
        why: "The call's identity arrives in `response.output_item.added` and its arguments in later fragments tied to the same `output_index`; the `.done` frames then repeat the complete argument string. Appending those would produce `{\"path\":\"/srv\"}{\"path\":\"/srv\"}`, which no tool can parse. The terminal event is also the only place a stateless decoder can see that the turn ended on a tool call, since `status` is merely `completed`.",
    },
    GoldenStream {
        name: "golden/anthropic_message_stream",
        family: GoldenFamily::Anthropic,
        dialect: GoldenDialect::Messages,
        frames: &[
            StreamFrame::named(
                "message_start",
                r#"{"type":"message_start","message":{"id":"msg_hypellm_golden_0101","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[],"stop_reason":null,"usage":{"input_tokens":24,"output_tokens":1}}}"#,
            ),
            StreamFrame::named(
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            StreamFrame::named("ping", r#"{"type":"ping"}"#),
            StreamFrame::named(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Back"}}"#,
            ),
            StreamFrame::named(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pressure is flow control."}}"#,
            ),
            StreamFrame::named(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":0}"#,
            ),
            StreamFrame::named(
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":7}}"#,
            ),
            StreamFrame::named("message_stop", r#"{"type":"message_stop"}"#),
        ],
        expect: ExpectedCompletion {
            upstream_id: Some("msg_hypellm_golden_0101"),
            native_model: Some("claude-sonnet-4-5-20250929"),
            text: "Backpressure is flow control.",
            reasoning: "",
            finish: ExpectedFinish::Stop,
            // Input tokens arrive in `message_start` and output tokens in
            // `message_delta`. Taking only the last usage event would report
            // zero input for every streamed Anthropic response.
            input_tokens: 24,
            output_tokens: 7,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: NO_TOOL_CALLS,
        },
        why: "Usage is split across two events here, and `ping`, `content_block_stop`, and `message_stop` carry no canonical meaning. Ignoring them is correct; failing on them would end a healthy stream.",
    },
    GoldenStream {
        name: "golden/anthropic_message_stream_tool_use",
        family: GoldenFamily::Anthropic,
        dialect: GoldenDialect::Messages,
        frames: &[
            StreamFrame::named(
                "message_start",
                r#"{"type":"message_start","message":{"id":"msg_hypellm_golden_0102","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[],"usage":{"input_tokens":30,"output_tokens":1}}}"#,
            ),
            StreamFrame::named(
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            StreamFrame::named(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Listing."}}"#,
            ),
            StreamFrame::named(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":0}"#,
            ),
            StreamFrame::named(
                "content_block_start",
                r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_hypellm_golden_0101","name":"list_files","input":{}}}"#,
            ),
            StreamFrame::named(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#,
            ),
            StreamFrame::named(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"/srv\"}"}}"#,
            ),
            StreamFrame::named(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":1}"#,
            ),
            StreamFrame::named(
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":15}}"#,
            ),
            StreamFrame::named("message_stop", r#"{"type":"message_stop"}"#),
        ],
        expect: ExpectedCompletion {
            upstream_id: Some("msg_hypellm_golden_0102"),
            native_model: Some("claude-sonnet-4-5-20250929"),
            text: "Listing.",
            reasoning: "",
            finish: ExpectedFinish::ToolCalls,
            input_tokens: 30,
            output_tokens: 15,
            cached_input_tokens: 0,
            usage_is_reported: true,
            tool_calls: &[ExpectedToolCall {
                index: 1,
                id: "toolu_hypellm_golden_0101",
                name: "list_files",
                arguments: r#"{"path":"/srv"}"#,
            }],
        },
        why: "The tool call's identity arrives in `content_block_start` and its arguments in later `input_json_delta` fragments tied to the same block index. Losing the tie produces a named call with no arguments and an anonymous fragment.",
    },
];

const EMBEDDINGS: &[GoldenEmbeddings] = &[GoldenEmbeddings {
    name: "golden/openai_embeddings",
    family: GoldenFamily::OpenAiCompatible,
    status: 200,
    body: r#"{"object":"list","model":"text-embedding-3-small","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.25,0.125]},{"object":"embedding","index":1,"embedding":[-1.0,0.0,0.75]}],"usage":{"prompt_tokens":8,"total_tokens":8}}"#,
    expect: &[
        ExpectedEmbedding {
            index: 0,
            values: &[0.5, -0.25, 0.125],
        },
        ExpectedEmbedding {
            index: 1,
            values: &[-1.0, 0.0, 0.75],
        },
    ],
    input_tokens: 8,
    why: "Two vectors, so a decoder that returns only the first fails. Every component is exactly representable, so a mismatch is a decoding fault and never a rounding artefact.",
}];

const FAILURES: &[GoldenFailure] = &[
    GoldenFailure {
        name: "golden/openai_error_rate_limited",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 429,
        body: r#"{"error":{"message":"Rate limit reached for gpt-4.1 in organization org-hypellm-golden on requests per min (RPM): Limit 500, Used 500.","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
        expect_class: "rate_limited",
        expect_provider_code: Some("rate_limit_exceeded"),
        expect_retriable: true,
        must_not_leak: &["org-hypellm-golden", "Limit 500"],
        why: "Specification 6.5 lists 429 as failover-eligible, so the class drives a routing decision. The organisation identifier in the message must not reach the client.",
    },
    GoldenFailure {
        name: "golden/openai_error_context_length",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 400,
        body: r#"{"error":{"message":"This model's maximum context length is 128000 tokens, however you requested 190000 tokens.","type":"invalid_request_error","code":"context_length_exceeded"}}"#,
        expect_class: "context_overflow",
        expect_provider_code: Some("context_length_exceeded"),
        expect_retriable: false,
        must_not_leak: &["190000"],
        why: "A 400 that is really a context overflow. Classifying it by status alone would make it an invalid request; classifying it as retriable would send the same oversized prompt to a target with the same limit.",
    },
    GoldenFailure {
        name: "golden/openai_error_authentication",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 401,
        body: r#"{"error":{"message":"Incorrect API key provided: sk-hypellm-golden-not-a-real-key. You can find your API key at https://example.invalid/keys.","type":"authentication_error","code":"invalid_api_key"}}"#,
        expect_class: "authentication",
        expect_provider_code: Some("invalid_api_key"),
        expect_retriable: false,
        must_not_leak: &["sk-hypellm-golden-not-a-real-key"],
        why: "Providers echo the rejected key back in the message. That is the router's own credential, and specification 10 keeps it behind an opaque handle — it must not appear in a client error or a log line. The key in this fixture is a placeholder that authenticates nothing.",
    },
    GoldenFailure {
        name: "golden/openai_error_server_non_json",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 503,
        body: "<html><head><title>503 Service Unavailable</title></head></html>",
        expect_class: "server_error",
        expect_provider_code: None,
        expect_retriable: true,
        must_not_leak: &["<html>"],
        why: "An error body from an intermediary rather than from the provider. It must classify by status without the JSON path, and the HTML must not be forwarded.",
    },
    GoldenFailure {
        name: "golden/openai_malformed_success_body",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 200,
        body: r#"{"id":"chatcmpl-hypellm-golden-0201","choices":[{"message":{"content":"tru"#,
        expect_class: "protocol_violation",
        expect_provider_code: None,
        expect_retriable: true,
        must_not_leak: &["chatcmpl-hypellm-golden-0201"],
        why: "A 200 whose body is truncated. Specification 8.2 has a dedicated `upstream_invalid_response` for a provider that violates its contract; treating this as an empty completion would report success for a response that never arrived.",
    },
    GoldenFailure {
        name: "golden/openai_stream_error_frame",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::StreamEvent { event: None },
        status: 500,
        body: r#"{"error":{"message":"The server had an error while processing your request.","type":"server_error","code":null}}"#,
        expect_class: "server_error",
        expect_provider_code: Some("server_error"),
        expect_retriable: true,
        must_not_leak: &["had an error while processing"],
        why: "Some providers deliver a failure mid-stream as an ordinary data frame. Decoding it as a completion chunk would end the stream as if it had succeeded.",
    },
    GoldenFailure {
        name: "golden/openai_stream_malformed_frame",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::StreamEvent { event: None },
        status: 200,
        body: r#"{"choices":[{"delta":{"content":"Back"#,
        expect_class: "protocol_violation",
        expect_provider_code: None,
        expect_retriable: true,
        must_not_leak: &[],
        why: "A truncated frame must fail rather than yield a partial delta. Note the interaction with specification 6.5: retriable here means the class permits failover, but once a content delta has reached the client the pipeline must still refuse to splice.",
    },
    GoldenFailure {
        name: "golden/openai_responses_stream_error_event",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::StreamEvent {
            event: Some("error"),
        },
        status: 500,
        body: r#"{"type":"error","code":"rate_limit_exceeded","message":"Rate limit reached for gpt-4.1 in organization org-hypellm-golden.","param":null,"sequence_number":4}"#,
        expect_class: "rate_limited",
        expect_provider_code: Some("rate_limit_exceeded"),
        expect_retriable: true,
        must_not_leak: &["org-hypellm-golden"],
        why: "This dialect signals a mid-stream failure with a named `error` event whose payload is flat — `code` and `message` at the top level, not nested under an `error` key as the Chat Completions frame is. A decoder that only looks for the nested shape reads this as an ordinary event and ends the stream as if it had succeeded.",
    },
    GoldenFailure {
        name: "golden/openai_responses_failed_status",
        family: GoldenFamily::OpenAiCompatible,
        path: FailurePath::Response,
        status: 200,
        body: r#"{"id":"resp_hypellm_golden_0201","object":"response","created_at":1750000040,"status":"failed","model":"gpt-4.1-2025-04-14","output":[],"error":{"code":"server_error","message":"The model failed while generating for org-hypellm-golden."}}"#,
        expect_class: "server_error",
        expect_provider_code: Some("server_error"),
        expect_retriable: true,
        must_not_leak: &["org-hypellm-golden", "failed while generating"],
        why: "A transport success carrying a failed generation. There is no `finish_reason` to carry the failure, so a decoder that only reads `output` sees an empty completion and reports success — losing both the error and, because nothing reached the client, the chance to fail over that specification 6.5 still permits here.",
    },
    GoldenFailure {
        name: "golden/anthropic_error_rate_limited",
        family: GoldenFamily::Anthropic,
        path: FailurePath::Response,
        status: 429,
        body: r#"{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your per-minute rate limit."}}"#,
        expect_class: "rate_limited",
        expect_provider_code: Some("rate_limit_error"),
        expect_retriable: true,
        must_not_leak: &["per-minute rate limit"],
        why: "This family carries no separate `code` field, so the type is what the router records.",
    },
    GoldenFailure {
        name: "golden/anthropic_error_overloaded",
        family: GoldenFamily::Anthropic,
        path: FailurePath::Response,
        status: 529,
        body: r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        expect_class: "rate_limited",
        expect_provider_code: Some("overloaded_error"),
        expect_retriable: true,
        must_not_leak: &[],
        why: "529 is not a status the HTTP registry defines, and overload is a capacity signal rather than a fault. Classifying it as a server error would count it against target health differently than a 429 that means the same thing.",
    },
    GoldenFailure {
        name: "golden/anthropic_error_max_tokens",
        family: GoldenFamily::Anthropic,
        path: FailurePath::Response,
        status: 400,
        body: r#"{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: 200000 > 64000, which is the maximum allowed number of output tokens for this model"}}"#,
        expect_class: "context_overflow",
        expect_provider_code: Some("invalid_request_error"),
        expect_retriable: false,
        must_not_leak: &["200000 > 64000"],
        why: "The distinguishing detail lives in the message, which the router does not forward. Matching a substring routes the failure correctly without echoing it — and the result must not be retriable, since another target has the same shape of limit.",
    },
    GoldenFailure {
        name: "golden/anthropic_error_authentication",
        family: GoldenFamily::Anthropic,
        path: FailurePath::Response,
        status: 401,
        body: r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        expect_class: "authentication",
        expect_provider_code: Some("authentication_error"),
        expect_retriable: false,
        must_not_leak: &["x-api-key"],
        why: "A credential fault is the router's own misconfiguration and must never be retried against another target with the same credential.",
    },
    GoldenFailure {
        name: "golden/anthropic_stream_error_frame",
        family: GoldenFamily::Anthropic,
        path: FailurePath::StreamEvent {
            event: Some("error"),
        },
        status: 500,
        body: r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        expect_class: "rate_limited",
        expect_provider_code: Some("overloaded_error"),
        expect_retriable: true,
        must_not_leak: &[],
        why: "This family signals a mid-stream failure with a named `error` event rather than a sentinel payload.",
    },
    GoldenFailure {
        name: "golden/anthropic_error_hostile_type",
        family: GoldenFamily::Anthropic,
        path: FailurePath::Response,
        status: 400,
        body: "{\"type\":\"error\",\"error\":{\"type\":\"bad\\ntype \\\"with quotes\\\"\",\"message\":\"x\"}}",
        expect_class: "invalid_request",
        // Every byte outside the identifier alphabet is replaced, not dropped,
        // so the length is preserved and the substitution is visible.
        expect_provider_code: Some("bad_type__with_quotes_"),
        expect_retriable: false,
        // The guard here is the expected code itself: it contains neither the
        // newline nor the quotes the provider sent.
        must_not_leak: &[],
        why: "The provider's type reaches a log line and a metric label. Narrowing it to an identifier alphabet is what stops a newline in it from forging a second log record (specification 17).",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn every_name() -> Vec<&'static str> {
        let mut names: Vec<&'static str> = RESPONSES.iter().map(|r| r.name).collect();
        names.extend(STREAMS.iter().map(|s| s.name));
        names.extend(EMBEDDINGS.iter().map(|e| e.name));
        names.extend(FAILURES.iter().map(|f| f.name));
        names
    }

    #[test]
    fn names_are_unique_and_namespaced() {
        let mut names = every_name();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "golden fixture names must be unique");
        assert!(names.iter().all(|n| n.starts_with("golden/")));
    }

    #[test]
    fn both_provider_families_are_covered_in_every_shape() {
        for family in [GoldenFamily::OpenAiCompatible, GoldenFamily::Anthropic] {
            assert!(
                RESPONSES.iter().any(|r| r.family == family),
                "{family:?} has no non-streaming fixture"
            );
            assert!(
                STREAMS.iter().any(|s| s.family == family),
                "{family:?} has no streaming fixture"
            );
            assert!(
                FAILURES.iter().any(|f| f.family == family),
                "{family:?} has no failure fixture"
            );
        }
    }

    #[test]
    fn tool_calling_is_covered_streamed_and_not() {
        assert!(
            RESPONSES
                .iter()
                .filter(|r| !r.expect.tool_calls.is_empty())
                .count()
                >= 2
        );
        assert!(
            STREAMS
                .iter()
                .filter(|s| !s.expect.tool_calls.is_empty())
                .count()
                >= 2
        );
    }

    #[test]
    fn tool_call_expectations_are_ordered_by_index() {
        for calls in RESPONSES
            .iter()
            .map(|r| r.expect.tool_calls)
            .chain(STREAMS.iter().map(|s| s.expect.tool_calls))
        {
            let indices: Vec<u32> = calls.iter().map(|c| c.index).collect();
            let mut sorted = indices.clone();
            sorted.sort_unstable();
            assert_eq!(indices, sorted, "tool calls must be listed in index order");
            sorted.dedup();
            assert_eq!(sorted.len(), indices.len(), "indices must be distinct");
        }
    }

    #[test]
    fn no_fixture_contains_a_plausible_live_credential() {
        // Not a substitute for review, but it catches the paste. Every secret
        // shaped string in this crate must be a placeholder that names itself.
        let streamed = STREAMS
            .iter()
            .flat_map(|s| s.frames.iter().map(move |f| (s.name, f.data)));
        for (name, body) in RESPONSES
            .iter()
            .map(|r| (r.name, r.body))
            .chain(FAILURES.iter().map(|f| (f.name, f.body)))
            .chain(EMBEDDINGS.iter().map(|e| (e.name, e.body)))
            .chain(streamed)
        {
            for marker in ["sk-live", "sk-ant-api", "sk-proj-", "Bearer "] {
                assert!(
                    !body.contains(marker),
                    "{name} contains {marker:?}, which looks like a real credential"
                );
            }
            if let Some(at) = body.find("sk-") {
                let tail = body.get(at..).unwrap_or_default();
                assert!(
                    tail.starts_with("sk-hypellm-golden-"),
                    "{name} contains a key-shaped string that does not name itself a fixture"
                );
            }
        }
    }

    #[test]
    fn a_fixtures_dialect_belongs_to_its_family() {
        for (name, family, dialect) in RESPONSES
            .iter()
            .map(|r| (r.name, r.family, r.dialect))
            .chain(STREAMS.iter().map(|s| (s.name, s.family, s.dialect)))
        {
            assert_eq!(
                dialect.family(),
                family,
                "{name} is family {family:?} but dialect {}",
                dialect.as_str()
            );
        }
    }

    #[test]
    fn stream_frames_are_named_as_their_dialect_requires() {
        // Per dialect, not per family: the OpenAI-compatible family serves one
        // dialect that names every event and one that names none.
        for stream in STREAMS {
            if stream.dialect.names_stream_events() {
                assert!(
                    stream.frames.iter().all(|f| f.event.is_some()),
                    "{} has an unnamed frame; the {} dialect names every event",
                    stream.name,
                    stream.dialect.as_str()
                );
            } else {
                assert!(
                    stream.frames.iter().all(|f| f.event.is_none()),
                    "{} names its frames; the {} dialect does not",
                    stream.name,
                    stream.dialect.as_str()
                );
            }
        }
    }

    #[test]
    fn only_the_dialect_with_a_sentinel_ends_with_one() {
        // The `[DONE]` marker is a Chat Completions convention. Assuming it
        // elsewhere is a common way to hang a stream reader, so the corpus
        // records a stream that genuinely does not have one.
        for stream in STREAMS {
            let last = stream.frames.last().map(|f| f.data);
            if stream.dialect.has_done_sentinel() {
                assert_eq!(
                    last,
                    Some("[DONE]"),
                    "{} does not end with the terminal marker",
                    stream.name
                );
            } else {
                assert!(
                    !stream.frames.iter().any(|f| f.data.trim() == "[DONE]"),
                    "{} carries a sentinel the {} dialect never sends",
                    stream.name,
                    stream.dialect.as_str()
                );
            }
        }
    }

    #[test]
    fn every_dialect_is_covered_in_every_shape() {
        // Specification 8 makes `POST /v1/responses` a MUST for new
        // integrations, so leaving that dialect to the Chat Completions
        // fixtures would leave the router's primary OpenAI surface untested.
        for dialect in GoldenDialect::all() {
            assert!(
                RESPONSES.iter().any(|r| r.dialect == *dialect),
                "{} has no non-streaming fixture",
                dialect.as_str()
            );
            assert!(
                STREAMS.iter().any(|s| s.dialect == *dialect),
                "{} has no streaming fixture",
                dialect.as_str()
            );
            assert!(
                STREAMS
                    .iter()
                    .any(|s| s.dialect == *dialect && !s.expect.tool_calls.is_empty()),
                "{} has no streamed tool call fixture",
                dialect.as_str()
            );
        }
    }

    #[test]
    fn failure_classes_and_retriability_agree_with_specification_6_5() {
        // Specification 6.5: connection refusal, timeout, 429, selected 5xx and
        // protocol violations may fail over; context overflow, unsupported
        // feature, invalid request and authentication may not.
        for failure in FAILURES {
            let expected = matches!(
                failure.expect_class,
                "connection" | "timeout" | "rate_limited" | "server_error" | "protocol_violation"
            );
            assert_eq!(
                failure.expect_retriable, expected,
                "{} claims retriable={} for class {}",
                failure.name, failure.expect_retriable, failure.expect_class
            );
        }
    }

    #[test]
    fn every_leak_guard_names_text_that_is_actually_in_the_body() {
        // A guard listing text the fixture does not contain asserts nothing.
        for failure in FAILURES {
            for fragment in failure.must_not_leak {
                assert!(
                    failure.body.contains(fragment),
                    "{} guards against {fragment:?}, which is not in its body",
                    failure.name
                );
            }
        }
    }

    #[test]
    fn usage_provenance_is_recorded_for_every_completion() {
        // A fixture with no usage must not claim provider-reported zeros:
        // specification 14 requires the provenance to travel with the number.
        for expect in RESPONSES
            .iter()
            .map(|r| r.expect)
            .chain(STREAMS.iter().map(|s| s.expect))
        {
            if !expect.usage_is_reported {
                assert_eq!(expect.input_tokens, 0);
                assert_eq!(expect.output_tokens, 0);
            }
        }
    }

    #[test]
    fn embedding_components_are_exactly_representable() {
        for fixture in EMBEDDINGS {
            for vector in fixture.expect {
                for value in vector.values {
                    let doubled = f64::from(*value);
                    #[expect(
                        clippy::as_conversions,
                        clippy::cast_possible_truncation,
                        reason = "the round trip is the property under test"
                    )]
                    let back = doubled as f32;
                    assert_eq!(
                        *value, back,
                        "{} carries a component that does not survive f64 round tripping",
                        fixture.name
                    );
                }
            }
        }
    }

    #[test]
    fn lookup_by_name_finds_fixtures() {
        assert!(response_by_name("golden/anthropic_message").is_some());
        assert!(stream_by_name("golden/openai_chat_stream").is_some());
        assert!(response_by_name("golden/nope").is_none());
    }
}
