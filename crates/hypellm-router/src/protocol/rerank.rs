//! `POST /v1/rerank` — the normalised reranking dialect.
//!
//! Specification 8 lists reranking as an operation and admits normalised
//! extension endpoints "advertised via capabilities", which is what
//! `/v1/tokenize` already is. This is the second: the request and response
//! shapes follow the convention the reranking services in the field settled on
//! — `query`, `documents`, `top_n`, `return_documents` in, `results` with an
//! `index` and a `relevance_score` out — so an existing rerank client can be
//! pointed at the router without a new SDK.
//!
//! # Where the fields go
//!
//! A rerank request is a scoring request: *given this, which of these?* The
//! canonical model already has both halves, so nothing new was added to it:
//!
//! - `query` becomes the **last message**, the criterion the candidates are
//!   scored against.
//! - `context` — this dialect's one addition — becomes the **first message**,
//!   the evidence the criterion is applied to. It exists because a decision
//!   scorer is asked "given this state, which action?", and a dialect with
//!   nowhere to put the state can only ask half the question.
//! - Omit `context` and the query is both: the first and last message are the
//!   same message. No text is invented to fill the gap, here or in an adapter.
//! - `documents` become [`CanonicalRequest::inputs`], the same field the
//!   embeddings dialect fills, so admission's byte-based estimate covers them
//!   without a special case.
//!
//! # What this dialect does not do
//!
//! It does not stream. A rerank response is one array that exists only once
//! every candidate has a score; there is no partial answer to send, and a
//! `"stream": true` is refused rather than quietly ignored — a caller who
//! asked for frames and received a body would read the refusal as success.

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, Message, Operation, ReasoningEffort, RequestLimits, Role,
    Sampling, StreamOptions,
};
use hypellm_core::error::RouterError;
use hypellm_core::event::ResponseAccumulator;
use wire_json::{Limits, Object, Value, parse, to_string};

use super::openai::{ParseContext, effective_quality_floor, parse_hints, require_model, type_error};

/// The most candidates one rerank request may carry.
///
/// A request bound, not a model bound: what a given scorer will accept is a
/// property of that family and is enforced by its adapter — the SemIf scorer
/// takes 2 to 16 and says so. This exists so that the work one request can
/// create is bounded before any target is chosen, in the same spirit as
/// specification 3.3's document limits, and it is far above anything a real
/// reranking call sends.
pub const MAX_DOCUMENTS: usize = 1_024;

/// Parse a rerank request.
pub fn parse_rerank_request(
    body: &[u8],
    context: &ParseContext,
    limits: &Limits,
) -> Result<CanonicalRequest, RouterError> {
    let value = parse(body, limits).map_err(|e| {
        RouterError::invalid_request(&format!("request body is not valid JSON ({})", e.kind.code()))
    })?;

    let model = require_model(&value)?;

    let query = value
        .field_str("query")
        .map_err(|_| {
            RouterError::invalid_request("a rerank request requires 'query'").with_param("query")
        })?
        .to_owned();
    if query.is_empty() {
        return Err(RouterError::invalid_request("'query' must not be empty").with_param("query"));
    }

    let raw_documents = value.field_array("documents").map_err(|_| {
        RouterError::invalid_request("a rerank request requires 'documents'")
            .with_param("documents")
    })?;
    if raw_documents.len() > MAX_DOCUMENTS {
        return Err(RouterError::invalid_request(&format!(
            "a rerank request may carry at most {MAX_DOCUMENTS} documents"
        ))
        .with_param("documents"));
    }
    let mut documents = Vec::with_capacity(raw_documents.len());
    for raw in raw_documents {
        // Both conventions in the field: a bare string, or `{"text": "..."}`.
        let text = match raw {
            Value::String(text) => text.as_str(),
            Value::Object(_) => raw.get("text").and_then(Value::as_str).ok_or_else(|| {
                RouterError::invalid_request("a document object must carry a string 'text'")
                    .with_param("documents")
            })?,
            _ => {
                return Err(RouterError::invalid_request(
                    "each document must be a string or an object with 'text'",
                )
                .with_param("documents"));
            }
        };
        if text.is_empty() {
            return Err(
                RouterError::invalid_request("a document must not be empty")
                    .with_param("documents"),
            );
        }
        documents.push(text.to_owned());
    }
    if documents.is_empty() {
        return Err(
            RouterError::invalid_request("a rerank request requires at least one document")
                .with_param("documents"),
        );
    }

    if value.opt_field_bool("stream").map_err(type_error)?.unwrap_or(false) {
        return Err(
            RouterError::invalid_request("reranking does not stream").with_param("stream")
        );
    }

    // The criterion is always the last message; the evidence is the first. With
    // no context they are one message, which is the honest encoding of "the
    // caller gave us one string".
    let context_text = value
        .opt_field_str("context")
        .map_err(type_error)?
        .map(str::to_owned);
    let mut messages = Vec::with_capacity(2);
    if let Some(evidence) = context_text {
        if evidence.is_empty() {
            return Err(RouterError::invalid_request("'context' must not be empty")
                .with_param("context"));
        }
        messages.push(Message::text(Role::System, evidence));
    }
    messages.push(Message::text(Role::User, query));

    Ok(CanonicalRequest {
        request_id: context.request_id,
        tenant: context.tenant.clone(),
        principal: context.principal.clone(),
        protocol: ClientProtocol::Rerank,
        operation: Operation::Rerank,
        requested_model: model,
        messages,
        inputs: documents,
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        // Nothing here is generated, so no reasoning tier can apply. Left
        // `Unset` rather than parsed, so a scorer is never excluded for a field
        // that could not have described it.
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: None,
            deadline: context.deadline,
            max_cost_class: context.max_cost_class,
            min_quality_class: effective_quality_floor(&value, context),
            residency: context.residency.clone(),
        },
        stream: StreamOptions::default(),
        hints: parse_hints(&value, context)?,
    })
}

/// How many results a rerank response may report, and whether to echo text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RenderOptions {
    /// `top_n` from the request, when the caller set one.
    pub top_n: Option<usize>,
    /// `return_documents` from the request.
    pub return_documents: bool,
}

impl RenderOptions {
    /// Read the render options out of a request body.
    ///
    /// Parsed separately from the canonical request because neither is a
    /// routing input: a `top_n` that narrowed the candidate set would change
    /// what the scorer was asked, and it must not. Every candidate is scored;
    /// `top_n` decides only how much of the answer is printed.
    #[must_use]
    pub fn from_body(body: &[u8], limits: &Limits) -> Self {
        let Ok(value) = parse(body, limits) else {
            return Self::default();
        };
        Self {
            top_n: value
                .get("top_n")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok()),
            return_documents: value
                .get("return_documents")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }
}

/// Render a rerank response.
pub fn render_rerank_response(
    request: &CanonicalRequest,
    accumulator: &ResponseAccumulator,
    options: RenderOptions,
) -> String {
    // Ordered by score, highest first, with the candidate's own position
    // breaking a tie. Equal scores must not reorder between two identical
    // calls: Appendix B's determinism requirement is about routing, but a
    // response that shuffles its own ties is no more defensible.
    let mut ranked: Vec<(u32, f32)> = accumulator
        .scores
        .iter()
        .copied()
        // A score for a candidate the caller did not send cannot be attached
        // to one they did. Dropping it is the only safe reading, and
        // `scored_documents` below reports that it happened.
        .filter(|(index, _)| usize::try_from(*index).is_ok_and(|i| i < request.inputs.len()))
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let scored = ranked.len();
    if let Some(top_n) = options.top_n {
        ranked.truncate(top_n);
    }

    let results: Vec<Value> = ranked
        .iter()
        .map(|(index, score)| {
            let mut item = Object::new();
            item.push("index", Value::from(u64::from(*index)));
            item.push("relevance_score", Value::from(f64::from(*score)));
            if options.return_documents {
                if let Some(text) = usize::try_from(*index)
                    .ok()
                    .and_then(|i| request.inputs.get(i))
                {
                    let mut document = Object::new();
                    document.push("text", Value::from(text.as_str()));
                    item.push("document", Value::Object(document));
                }
            }
            Value::Object(item)
        })
        .collect();

    let mut root = Object::new();
    root.push("object", Value::from("list"));
    root.push("results", Value::Array(results));
    root.push("model", Value::from(request.requested_model.as_str()));

    // A scorer generates nothing, so an absent report still knows the output
    // half: zero. The input half it does not know, and renders as `null` —
    // not as zero, which would read as a free request.
    let usage = super::UsageView::of(Some(accumulator.usage.unwrap_or(
        hypellm_core::event::CanonicalUsage::output_only(0),
    )));
    let usage_source = if accumulator.usage.is_some() { usage.source } else { "unreported" };
    let mut usage_object = Object::new();
    usage_object.push("prompt_tokens", usage.input);
    // Present and zero rather than absent: a scorer reads the prompt and
    // generates nothing, and an SDK that expects the field should see the
    // number rather than infer it.
    usage_object.push("completion_tokens", usage.output);
    usage_object.push("total_tokens", usage.total);
    let mut usage_meta = Object::new();
    usage_meta.push("usage_source", Value::from(usage_source));
    usage_object.push("hypellm", Value::Object(usage_meta));
    root.push("usage", Value::Object(usage_object));

    let mut meta = Object::new();
    meta.push_opt("native_model", accumulator.native_model.as_deref().map(Value::from));
    meta.push("documents", Value::from(u64::try_from(request.inputs.len()).unwrap_or(u64::MAX)));
    // The two counts are separate on purpose. A response that scored fewer
    // documents than it was given is a short answer, and a caller comparing
    // the numbers finds that out rather than assuming the missing ones ranked
    // last.
    meta.push("scored_documents", Value::from(u64::try_from(scored).unwrap_or(u64::MAX)));
    // Scores come from the target that served the request and mean whatever
    // that model's scale means. They are comparable within one response and
    // between no two of them, and nothing here rescales them to imply
    // otherwise.
    meta.push("score_scale", Value::from("provider_reported"));
    if accumulator.truncated() {
        meta.push("truncated", Value::from(true));
    }
    root.push("hypellm", Value::Object(meta));

    to_string(&Value::Object(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::event::{CanonicalEvent, CanonicalUsage};
    use hypellm_core::ids::{PrincipalId, RequestId, TenantId};
    use hypellm_core::time::{Deadline, TestClock};
    use std::time::Duration;
    use wire_json::parse_str;

    fn context() -> ParseContext {
        let clock = TestClock::new();
        ParseContext {
            request_id: RequestId::from_u128(0x1234),
            tenant: TenantId::new("acme").expect("valid identifier"),
            principal: PrincipalId::new("user:42").expect("valid identifier"),
            deadline: Deadline::after(&clock, Duration::from_secs(60)),
            hints_permitted: false,
            min_quality_class: None,
            document_limits: crate::protocol::openai::DocumentLimits::DEFAULT,
            residency: None,
            max_cost_class: None,
        }
    }

    fn parse_body(body: &str) -> Result<CanonicalRequest, RouterError> {
        parse_rerank_request(body.as_bytes(), &context(), &Limits::DEFAULT)
    }

    const WITH_CONTEXT: &str = r#"{"model":"decide","context":"40 days since purchase.","query":"What should the agent do?","documents":["Refund","Deny"]}"#;

    #[test]
    fn the_query_is_the_last_message_and_the_context_is_the_first() {
        let request = parse_body(WITH_CONTEXT).expect("a valid request");
        assert_eq!(request.operation, Operation::Rerank);
        assert_eq!(request.protocol, ClientProtocol::Rerank);
        assert_eq!(request.messages.len(), 2);
        assert_eq!(
            request.messages.first().and_then(Message::as_text).as_deref(),
            Some("40 days since purchase.")
        );
        assert_eq!(
            request.messages.last().and_then(Message::as_text).as_deref(),
            Some("What should the agent do?")
        );
        assert_eq!(request.inputs, vec!["Refund".to_owned(), "Deny".to_owned()]);
    }

    #[test]
    fn a_query_with_no_context_is_one_message_that_is_both() {
        // The adapter reads the first message as evidence and the last as
        // criterion. With one message they are the same message, which is how
        // "the caller gave us one string" is encoded without inventing a
        // second one.
        let request = parse_body(r#"{"model":"decide","query":"Which is cheapest?","documents":["a","b"]}"#)
            .expect("a valid request");
        assert_eq!(request.messages.len(), 1);
        assert_eq!(
            request.messages.first().and_then(Message::as_text),
            request.messages.last().and_then(Message::as_text)
        );
    }

    #[test]
    fn the_documents_are_counted_for_admission() {
        // They live in `inputs`, which `input_byte_len` already sums, so the
        // pre-dispatch reservation covers the candidate list. A dialect that
        // parked them somewhere else would reserve for the query alone and
        // admit a request an order of magnitude larger than it booked.
        let request = parse_body(WITH_CONTEXT).expect("a valid request");
        let documents: usize = ["Refund", "Deny"].iter().map(|d| d.len()).sum();
        assert!(
            request.input_byte_len() >= documents,
            "the candidate list is part of what this request costs"
        );
    }

    #[test]
    fn a_document_object_carries_its_text_and_anything_else_is_refused() {
        let request = parse_body(
            r#"{"model":"decide","query":"q","documents":[{"text":"Refund"},"Deny"]}"#,
        )
        .expect("both document conventions are accepted");
        assert_eq!(request.inputs, vec!["Refund".to_owned(), "Deny".to_owned()]);

        for bad in [
            r#"{"model":"decide","query":"q","documents":[{"body":"Refund"},"Deny"]}"#,
            r#"{"model":"decide","query":"q","documents":[42,"Deny"]}"#,
            r#"{"model":"decide","query":"q","documents":["","Deny"]}"#,
            r#"{"model":"decide","query":"q","documents":[]}"#,
            r#"{"model":"decide","query":"q"}"#,
        ] {
            let error = parse_body(bad).expect_err("a malformed candidate list is refused");
            assert_eq!(error.param.as_ref().map(hypellm_core::sensitive::Capped::as_str), Some("documents"), "{bad}");
        }
    }

    #[test]
    fn an_empty_or_missing_query_is_refused_rather_than_scored_against_nothing() {
        for bad in [
            r#"{"model":"decide","documents":["a","b"]}"#,
            r#"{"model":"decide","query":"","documents":["a","b"]}"#,
        ] {
            let error = parse_body(bad).expect_err("a scoring request needs a criterion");
            assert_eq!(error.param.as_ref().map(hypellm_core::sensitive::Capped::as_str), Some("query"), "{bad}");
        }
        let error = parse_body(r#"{"model":"decide","query":"q","context":"","documents":["a","b"]}"#)
            .expect_err("an empty context is a mistake, not an omission");
        assert_eq!(error.param.as_ref().map(hypellm_core::sensitive::Capped::as_str), Some("context"));
    }

    #[test]
    fn a_streaming_rerank_request_is_refused_rather_than_answered_in_one_piece() {
        let error = parse_body(
            r#"{"model":"decide","query":"q","documents":["a","b"],"stream":true}"#,
        )
        .expect_err("there is no partial ranking to send");
        assert_eq!(error.param.as_ref().map(hypellm_core::sensitive::Capped::as_str), Some("stream"));
    }

    #[test]
    fn more_documents_than_one_request_may_carry_is_refused() {
        let documents: Vec<String> = (0..=MAX_DOCUMENTS).map(|i| format!("\"d{i}\"")).collect();
        let body = format!(
            r#"{{"model":"decide","query":"q","documents":[{}]}}"#,
            documents.join(",")
        );
        let error = parse_body(&body).expect_err("the request bound holds");
        assert_eq!(error.param.as_ref().map(hypellm_core::sensitive::Capped::as_str), Some("documents"));
    }

    fn scored(scores: &[(u32, f32)]) -> ResponseAccumulator {
        let mut accumulator = ResponseAccumulator::new();
        accumulator.push(&CanonicalEvent::Start {
            upstream_id: None,
            native_model: Some("scorer.gguf".to_owned()),
        });
        for (index, score) in scores {
            accumulator.push(&CanonicalEvent::Score {
                index: *index,
                score: *score,
            });
        }
        accumulator.push(&CanonicalEvent::Usage(CanonicalUsage::reported(131, 0)));
        accumulator
    }

    #[test]
    fn a_scorer_that_omits_input_tokens_is_not_shown_as_a_free_request() {
        let request = parse_body(r#"{"model":"decide","query":"q","documents":["a","b"]}"#)
            .expect("a valid request");
        let mut accumulator = ResponseAccumulator::new();
        accumulator.push(&CanonicalEvent::Score { index: 0, score: 0.5 });
        let rendered = render_rerank_response(&request, &accumulator, RenderOptions::default());
        let value = parse_str(&rendered, &Limits::DEFAULT).expect("valid JSON");
        let usage = value.get("usage").expect("usage");
        assert!(usage.get("prompt_tokens").is_some_and(Value::is_null), "unknown, not zero");
        assert!(usage.get("total_tokens").is_some_and(Value::is_null));
        assert_eq!(usage.get("completion_tokens").and_then(Value::as_u64), Some(0));
        assert_eq!(
            usage.get("hypellm").and_then(|m| m.get("usage_source")).and_then(Value::as_str),
            Some("unreported")
        );

        // A reported count still renders as the number it is.
        let reported = scored(&[(0, 0.5)]);
        let rendered = render_rerank_response(&request, &reported, RenderOptions::default());
        let value = parse_str(&rendered, &Limits::DEFAULT).expect("valid JSON");
        let usage = value.get("usage").expect("usage");
        assert_eq!(usage.get("prompt_tokens").and_then(Value::as_u64), Some(131));
        assert_eq!(usage.get("total_tokens").and_then(Value::as_u64), Some(131));
    }

    #[test]
    fn results_are_ranked_by_score_with_the_candidate_position_breaking_ties() {
        let request = parse_body(
            r#"{"model":"decide","query":"q","documents":["a","b","c","d"]}"#,
        )
        .expect("a valid request");
        // Two equal scores, delivered in the wrong order: the tie must break
        // by position, deterministically, or two identical calls disagree.
        let accumulator = scored(&[(2, 0.1), (1, 0.5), (0, 0.5), (3, 0.2)]);
        let rendered = render_rerank_response(&request, &accumulator, RenderOptions::default());
        let value = parse_str(&rendered, &Limits::DEFAULT).expect("valid JSON");
        let results = value.get("results").and_then(Value::as_array).expect("results");
        let order: Vec<u64> = results
            .iter()
            .filter_map(|r| r.get("index").and_then(Value::as_u64))
            .collect();
        assert_eq!(order, vec![0, 1, 3, 2]);
    }

    #[test]
    fn a_score_for_a_candidate_the_caller_never_sent_is_dropped_and_counted() {
        // The provider is not trusted to answer about the right list. A score
        // at index 9 for a three-document request cannot be attached to
        // document 0 just because that index exists.
        let request = parse_body(r#"{"model":"decide","query":"q","documents":["a","b","c"]}"#)
            .expect("a valid request");
        let accumulator = scored(&[(0, 0.2), (9, 0.9), (1, 0.1)]);
        let rendered = render_rerank_response(&request, &accumulator, RenderOptions::default());
        let value = parse_str(&rendered, &Limits::DEFAULT).expect("valid JSON");

        let results = value.get("results").and_then(Value::as_array).expect("results");
        assert_eq!(results.len(), 2, "the stray score is not rendered");
        assert!(
            results
                .iter()
                .all(|r| r.get("index").and_then(Value::as_u64).is_some_and(|i| i < 3)),
            "no result points outside the caller's own list"
        );
        let meta = value.get("hypellm").expect("metadata");
        assert_eq!(meta.get("documents").and_then(Value::as_u64), Some(3));
        assert_eq!(
            meta.get("scored_documents").and_then(Value::as_u64),
            Some(2),
            "a short answer says it is short rather than looking complete"
        );
    }

    #[test]
    fn documents_are_echoed_only_when_the_caller_asked_for_them() {
        let request = parse_body(r#"{"model":"decide","query":"q","documents":["a","b"]}"#)
            .expect("a valid request");
        let accumulator = scored(&[(0, 0.9), (1, 0.1)]);

        let quiet = render_rerank_response(&request, &accumulator, RenderOptions::default());
        assert!(!quiet.contains("\"document\""));

        let echoed = render_rerank_response(
            &request,
            &accumulator,
            RenderOptions {
                top_n: None,
                return_documents: true,
            },
        );
        assert!(echoed.contains("\"document\""));
    }

    #[test]
    fn render_options_come_from_the_body_and_survive_a_malformed_one() {
        let options = RenderOptions::from_body(
            br#"{"top_n":2,"return_documents":true}"#,
            &Limits::DEFAULT,
        );
        assert_eq!(options.top_n, Some(2));
        assert!(options.return_documents);

        // Read a second time from a body the parser already accepted once, so
        // a body that cannot be read here is not a body that reached routing.
        // Defaulting rather than failing keeps that impossible case harmless.
        let fallback = RenderOptions::from_body(b"not json", &Limits::DEFAULT);
        assert_eq!(fallback, RenderOptions::default());
    }
}
