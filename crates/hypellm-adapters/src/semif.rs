//! The SemIf semantic-decision scorer.
//!
//! SemIf ("semantic if") answers one question: given some evidence and a
//! criterion, which of these typed options fits? It does that in a single
//! forward pass, reading the logits of the answer slots and generating no
//! tokens at all. That makes it the only family here that is not
//! OpenAI-shaped: there is one endpoint, `POST /score`, it never streams, it
//! has no notion of a message list, and it returns a probability per option
//! rather than text.
//!
//! # The mapping
//!
//! The router already has an operation for "score these candidates against
//! this request" — [`Operation::Rerank`] — and `POST /v1/rerank`
//! (`hypellm-router::protocol::rerank`) is the dialect clients speak. This
//! adapter is the other half of that translation:
//!
//! | Canonical | SemIf row field | Source |
//! |---|---|---|
//! | last message text | `question` | the caller's `query` |
//! | first message text | `state` | the caller's `context`, or the query again |
//! | `inputs[i]` | `options[i].description` | the caller's `documents[i]` |
//! | — | `options[i].id` | the decimal index `i` |
//! | `request_id` | `id` | the router's own identifier |
//!
//! **The adapter writes no prompt text of its own.** Every string it sends
//! came from the caller; where SemIf needs a field the caller did not supply,
//! it repeats one the caller did. A gateway that quietly injected "which
//! option best answers the question above?" would be choosing the semantics of
//! a scoring call on the caller's behalf, and the score that came back would be
//! partly the router's opinion. Appendix B's "prompts are inert data" cuts both
//! ways: the router neither interprets them nor authors them.
//!
//! # What it refuses
//!
//! SemIf's own `validate_row` takes 2 to 16 options and nothing else, so this
//! adapter refuses a request outside that range rather than letting the scorer
//! answer `400` after the prompt has crossed the network. It refuses streaming,
//! tools, response formats and every operation but rerank, because the scorer
//! implements none of them.
//!
//! # Scores are reported, not renormalised
//!
//! SemIf labels its own numbers: `"probability_status": "conditional option
//! score over quantized weights; uncalibrated as decision confidence"`. They
//! are carried through unchanged and that sentence is carried with them
//! (`hypellm-router::protocol::rerank`). Rescaling them into something that
//! looked like a calibrated confidence would be the router inventing a
//! measurement.

use crate::contract::{
    Adapter, CredentialHandle, ErrorClassification, RequestMeta, SensitiveHeaders,
    ValidationFailure, ValidationResult, class_for_status, sanitize_provider_code,
};
use hypellm_core::canonical::{CanonicalRequest, Operation};
use hypellm_core::event::{CanonicalEvent, CanonicalUsage, FinishReason, UpstreamErrorClass};
use hypellm_core::sensitive::Capped;
use hypellm_core::target::{Capabilities, ProviderFamily};
use wire_json::{Limits, Object, Value, parse, to_vec};

/// The fewest options SemIf will score.
///
/// `semif_phase1.core.validate_row`: "options must contain 2-16 entries". One
/// option is not a decision, and the scorer says so.
pub const MIN_OPTIONS: usize = 2;

/// The most options SemIf will score.
///
/// The answer slots are single letters drawn from a fixed alphabet, so this is
/// a property of the prompt format rather than a tuning parameter.
pub const MAX_OPTIONS: usize = 16;

/// The SemIf adapter.
#[derive(Debug, Clone, Copy)]
pub struct SemIfAdapter;

impl SemIfAdapter {
    /// The evidence and criterion a row carries, drawn from the request.
    ///
    /// The rerank dialect puts the criterion in the last message and the
    /// evidence in the first, which are the same message when the caller sent
    /// no separate context.
    fn evidence_and_criterion(request: &CanonicalRequest) -> Option<(String, String)> {
        let first = request.messages.first()?;
        let last = request.messages.last()?;
        // `as_text` is `None` for a message carrying an image or a document
        // part. A scorer that reads text logits cannot see one, and sending
        // the text around it would silently score a different question than
        // the caller asked.
        let evidence = first.as_text()?;
        let criterion = last.as_text()?;
        if evidence.is_empty() || criterion.is_empty() {
            return None;
        }
        Some((evidence, criterion))
    }
}

impl Adapter for SemIfAdapter {
    fn family(&self) -> ProviderFamily {
        ProviderFamily::SemIf
    }

    fn path_for(&self, request: &CanonicalRequest) -> Result<&'static str, ValidationFailure> {
        match request.operation {
            Operation::Rerank => Ok("/score"),
            // Named individually rather than caught by a wildcard, so that a
            // new operation is a compile error here and somebody decides
            // whether a scorer can serve it.
            Operation::Chat | Operation::Responses | Operation::Embeddings | Operation::Tokenize => {
                Err(ValidationFailure::new(
                    "operation_unsupported",
                    "a SemIf scorer serves rerank only; it generates no tokens",
                ))
            }
        }
    }

    fn validate(
        &self,
        request: &CanonicalRequest,
        capabilities: &Capabilities,
    ) -> ValidationResult {
        if request.operation != Operation::Rerank {
            return Err(ValidationFailure::new(
                "operation_unsupported",
                "a SemIf scorer serves rerank only; it generates no tokens",
            ));
        }
        if !capabilities.supports_operation(Operation::Rerank) {
            return Err(ValidationFailure::new(
                "operation_unsupported",
                "the selected model does not serve this operation",
            ));
        }
        if request.stream.enabled {
            // Not "unsupported by this model" but unsupported by the shape of
            // the work: one forward pass has nothing to stream.
            return Err(ValidationFailure::new(
                "streaming_unsupported",
                "a SemIf scorer answers in one forward pass and cannot stream",
            )
            .with_param("stream"));
        }
        if request.requires_tools() {
            return Err(ValidationFailure::new(
                "tools_unsupported",
                "a SemIf scorer does not call tools",
            )
            .with_param("tools"));
        }
        if request.response_format.is_some() {
            return Err(ValidationFailure::new(
                "response_format_unsupported",
                "a SemIf scorer returns scores, not generated content",
            )
            .with_param("response_format"));
        }
        if Self::evidence_and_criterion(request).is_none() {
            return Err(ValidationFailure::new(
                "invalid_request",
                "a rerank request needs a non-empty query",
            )
            .with_param("query"));
        }
        let options = request.inputs.len();
        if !(MIN_OPTIONS..=MAX_OPTIONS).contains(&options) {
            return Err(ValidationFailure::new(
                "invalid_request",
                "a SemIf scorer takes between 2 and 16 documents",
            )
            .with_param("documents"));
        }
        if request.inputs.iter().any(String::is_empty) {
            return Err(ValidationFailure::new(
                "invalid_request",
                "every document must be a non-empty string",
            )
            .with_param("documents"));
        }
        Ok(())
    }

    fn encode_headers(
        &self,
        _credential: Option<&CredentialHandle<'_>>,
        meta: &RequestMeta<'_>,
    ) -> SensitiveHeaders {
        // No authentication header, and no place to put one: `serve.py` reads
        // none. A credential configured for this provider is therefore not
        // silently sent somewhere it would not be checked — it is not sent at
        // all, and `docs/deferred-issues.md` says so.
        let mut headers = SensitiveHeaders::new();
        headers.push("content-type", "application/json");
        headers.push("accept", "application/json");
        headers.push("x-request-id", meta.request_id.clone());
        headers
    }

    fn encode_request(
        &self,
        request: &CanonicalRequest,
        meta: &RequestMeta<'_>,
    ) -> Result<Vec<u8>, ValidationFailure> {
        let (evidence, criterion) = Self::evidence_and_criterion(request).ok_or_else(|| {
            ValidationFailure::new("invalid_request", "a rerank request needs a non-empty query")
                .with_param("query")
        })?;
        if !(MIN_OPTIONS..=MAX_OPTIONS).contains(&request.inputs.len()) {
            return Err(ValidationFailure::new(
                "invalid_request",
                "a SemIf scorer takes between 2 and 16 documents",
            )
            .with_param("documents"));
        }

        let mut options = Vec::with_capacity(request.inputs.len());
        for (index, document) in request.inputs.iter().enumerate() {
            let mut option = Object::new();
            // The decimal position, which is also what the rerank dialect
            // reports back as `index`. Unique by construction, which is SemIf's
            // other requirement of option ids.
            option.push("id", Value::from(index.to_string()));
            option.push("description", Value::from(document.as_str()));
            options.push(Value::Object(option));
        }

        let mut row = Object::new();
        row.push("id", Value::from(meta.request_id.as_str()));
        row.push("state", Value::from(evidence.as_str()));
        row.push("question", Value::from(criterion.as_str()));
        row.push("options", Value::Array(options));
        Ok(to_vec(&Value::Object(row)))
    }

    fn decode_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        if !(200..300).contains(&status) {
            return Err(self.classify_error(status, body));
        }
        let value = parse(body, &Limits::DEFAULT).map_err(|_| protocol_violation("malformed"))?;

        // A list body is what SemIf answers a list request with. The router
        // never sends one, so a list here means the scorer answered a question
        // the router did not ask.
        let Value::Object(_) = &value else {
            return Err(protocol_violation("shape"));
        };

        let (Some(ids), Some(probabilities)) = (
            value.get("option_ids").and_then(Value::as_array),
            value.get("probabilities").and_then(Value::as_array),
        ) else {
            return Err(protocol_violation("fields"));
        };
        if ids.len() != probabilities.len() || ids.is_empty() || ids.len() > MAX_OPTIONS {
            return Err(protocol_violation("length"));
        }

        let mut events = Vec::with_capacity(ids.len() + 3);
        events.push(CanonicalEvent::Start {
            upstream_id: value.get("id").and_then(Value::as_str).map(str::to_owned),
            native_model: native_model(&value),
        });

        let mut seen = [false; MAX_OPTIONS];
        for (id, probability) in ids.iter().zip(probabilities.iter()) {
            // The id is the decimal index this adapter sent. Anything else is
            // an answer about options the router did not offer, and a score
            // that cannot be attached to one of the caller's documents must
            // not be attached to a different one.
            let index = id
                .as_str()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|index| *index < MAX_OPTIONS)
                .ok_or_else(|| protocol_violation("option id"))?;
            let Some(slot) = seen.get_mut(index) else {
                return Err(protocol_violation("option id"));
            };
            if core::mem::replace(slot, true) {
                return Err(protocol_violation("duplicate option"));
            }
            let score = probability
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| protocol_violation("probability"))?;
            events.push(CanonicalEvent::Score {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                score: narrow_score(score),
            });
        }

        // `input_tokens` is what the scorer actually read, reported by the
        // scorer. There are no output tokens, and saying zero is the truth
        // rather than an omission: the readout generates nothing.
        if let Some(input_tokens) = value.get("input_tokens").and_then(Value::as_u64) {
            events.push(CanonicalEvent::Usage(CanonicalUsage::reported(
                input_tokens,
                0,
            )));
        }
        events.push(CanonicalEvent::Finish {
            reason: FinishReason::Stop,
        });
        Ok(events)
    }

    fn decode_stream_event(
        &self,
        _event_name: Option<&str>,
        _data: &str,
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification> {
        // Unreachable through `validate`, which refuses a streaming request
        // before any of this. Reachable only if a scorer answered a
        // non-streaming request with a stream, which is a protocol violation
        // and is reported as one rather than ignored.
        Err(protocol_violation("stream"))
    }

    fn is_stream_terminator(&self, _data: &str) -> bool {
        false
    }

    fn classify_error(&self, status: u16, body: &[u8]) -> ErrorClassification {
        // `serve.py` answers every failure with
        // `{"error": "<ExceptionType>: <message>"}` and status 400, including
        // failures that are not the caller's fault. The exception *type* is
        // recorded, narrowed to an identifier; the message is not, because it
        // is free text from a Python exception and specification 10 keeps a
        // provider body out of a client's error.
        let provider_code = parse(body, &Limits::SMALL)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(|text| text.split(':').next().unwrap_or(text).trim().to_owned())
            })
            .filter(|token| !token.is_empty())
            .map(|token| sanitize_provider_code(&token));

        ErrorClassification {
            class: class_for_status(status),
            provider_code,
            safe_detail: Capped::new(safe_detail_for(status), 200),
            retry_after_secs: None,
        }
    }
}

fn protocol_violation(what: &str) -> ErrorClassification {
    ErrorClassification {
        class: UpstreamErrorClass::ProtocolViolation,
        provider_code: Some(sanitize_provider_code(what)),
        safe_detail: Capped::new("the scorer returned a response the router cannot read", 200),
        retry_after_secs: None,
    }
}

/// The model a score came from, as the scorer describes it.
fn native_model(value: &Value) -> Option<String> {
    let model = value.get("model")?;
    // The GGUF file is the thing that actually produced the logits; the
    // `source` repository is what it was quantised from. Preferring the file
    // means two instances serving different quantisations of one model are
    // distinguishable in a decision trace, which is the question anyone asks
    // when two scorers disagree.
    model
        .get("gguf")
        .and_then(|gguf| gguf.get("file"))
        .and_then(Value::as_str)
        .or_else(|| model.get("source").and_then(Value::as_str))
        .map(str::to_owned)
}

const fn safe_detail_for(status: u16) -> &'static str {
    match status {
        400 | 422 => "the scorer rejected the request as invalid",
        404 => "the scorer does not serve this endpoint",
        413 => "the request exceeded the scorer's prompt limit",
        429 => "the scorer rate limited the request",
        500..=599 => "the scorer returned a server error",
        _ => "the scorer returned an unexpected response",
    }
}

/// Narrow one score from the JSON parser's `f64` to the `f32` that
/// [`CanonicalEvent::Score`] is defined with.
///
/// The same reasoning as `openai::narrow_embedding_component`: there is no
/// checked `f64 -> f32` to call, the cast is total and panic-free, and the
/// precision is the canonical type's declared precision rather than an
/// accident here. A probability carries nowhere near 24 bits of meaning — the
/// scorer itself calls it uncalibrated.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "no checked f64 -> f32 exists; the cast is total and the narrowing is the canonical type's declared precision"
)]
fn narrow_score(score: f64) -> f32 {
    score as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        endpoint_fixture, meta_fixture, rerank_capabilities, rerank_request_fixture, target_fixture,
    };
    use hypellm_core::canonical::{Message, Role};
    use wire_json::parse;

    fn encoded(request: &CanonicalRequest) -> Value {
        let target = target_fixture();
        let endpoint = endpoint_fixture("scorer.example");
        let meta = meta_fixture(&target, &endpoint, false);
        let body = SemIfAdapter
            .encode_request(request, &meta)
            .expect("the fixture is a valid rerank request");
        parse(&body, &Limits::DEFAULT).expect("the adapter emitted valid JSON")
    }

    #[test]
    fn a_document_becomes_an_option_whose_id_is_its_position() {
        let request = rerank_request_fixture();
        let value = encoded(&request);
        let options = value
            .get("options")
            .and_then(Value::as_array)
            .expect("options");
        assert_eq!(options.len(), 3);
        for (index, option) in options.iter().enumerate() {
            assert_eq!(
                option.get("id").and_then(Value::as_str),
                Some(index.to_string().as_str()),
                "the id is the position, which is what the reply is read back by"
            );
        }
        assert_eq!(
            options[2].get("description").and_then(Value::as_str),
            Some("Escalate to a supervisor")
        );
    }

    #[test]
    fn the_query_is_the_criterion_and_the_context_is_the_evidence() {
        let value = encoded(&rerank_request_fixture());
        assert_eq!(
            value.get("question").and_then(Value::as_str),
            Some("What should the agent do?"),
            "the caller's query is the criterion"
        );
        assert_eq!(
            value.get("state").and_then(Value::as_str),
            Some("The customer asked for a refund after 40 days."),
            "the caller's context is the evidence"
        );
    }

    #[test]
    fn a_query_without_a_context_is_sent_as_both_rather_than_padded() {
        // SemIf refuses an empty state, so the adapter must put something
        // there. The only honest something is a string the caller wrote.
        let request = CanonicalRequest {
            messages: vec![Message::text(Role::User, "Which is cheapest?")],
            ..rerank_request_fixture()
        };
        let value = encoded(&request);
        assert_eq!(
            value.get("state").and_then(Value::as_str),
            Some("Which is cheapest?")
        );
        assert_eq!(
            value.get("question").and_then(Value::as_str),
            Some("Which is cheapest?")
        );
    }

    #[test]
    fn every_word_the_scorer_reads_came_from_the_caller() {
        // The property the mapping rests on. A gateway that added "which
        // option best satisfies the criterion?" would be supplying part of the
        // prompt that decides the answer, and the score coming back would be
        // partly the router's opinion. Appendix B's "prompts are inert data"
        // is not only about interpreting them.
        //
        // Every string in the encoded body is therefore one of: the router's
        // own request id, an option id (a decimal position), or text the
        // caller sent. There is no fourth category, and if one appears this
        // fails.
        let request = rerank_request_fixture();
        let value = encoded(&request);
        let mut caller_text: Vec<String> = request.inputs.clone();
        for message in &request.messages {
            caller_text.extend(message.as_text());
        }
        let request_id = value
            .get("id")
            .and_then(Value::as_str)
            .expect("the row carries the router's request id")
            .to_owned();

        fn strings(value: &Value, into: &mut Vec<String>) {
            match value {
                Value::String(text) => into.push(text.clone()),
                Value::Array(items) => items.iter().for_each(|item| strings(item, into)),
                Value::Object(object) => {
                    object.iter().for_each(|(_, item)| strings(item, into));
                }
                _ => {}
            }
        }
        let mut written = Vec::new();
        strings(&value, &mut written);
        assert!(written.len() >= 6, "the body should carry every field");

        for text in written {
            let is_caller_text = caller_text.contains(&text);
            let is_option_id = text.parse::<usize>().is_ok_and(|id| id < MAX_OPTIONS);
            let is_request_id = text == request_id;
            assert!(
                is_caller_text || is_option_id || is_request_id,
                "the adapter wrote {text:?}, which the caller never sent"
            );
        }
    }

    #[test]
    fn a_candidate_list_outside_the_scorers_range_is_refused_before_the_network() {
        let capabilities = rerank_capabilities();
        for count in [0_usize, 1, 17, 64] {
            let request = CanonicalRequest {
                inputs: (0..count).map(|i| format!("option {i}")).collect(),
                ..rerank_request_fixture()
            };
            let failure = SemIfAdapter
                .validate(&request, &capabilities)
                .expect_err("SemIf scores 2 to 16 options");
            assert_eq!(failure.param, Some("documents"), "{count} documents");
        }
        for count in [2_usize, 3, 16] {
            let request = CanonicalRequest {
                inputs: (0..count).map(|i| format!("option {i}")).collect(),
                ..rerank_request_fixture()
            };
            SemIfAdapter
                .validate(&request, &capabilities)
                .expect("2 to 16 options is what the scorer takes");
        }
    }

    #[test]
    fn a_scorer_serves_rerank_and_refuses_every_other_operation() {
        let capabilities = rerank_capabilities();
        for operation in [
            Operation::Chat,
            Operation::Responses,
            Operation::Embeddings,
            Operation::Tokenize,
        ] {
            let request = CanonicalRequest {
                operation,
                ..rerank_request_fixture()
            };
            assert!(
                SemIfAdapter.path_for(&request).is_err(),
                "{operation:?} has no endpoint on a scorer"
            );
            let failure = SemIfAdapter
                .validate(&request, &capabilities)
                .expect_err("a scorer generates nothing");
            assert_eq!(failure.code, "operation_unsupported");
        }
        let request = rerank_request_fixture();
        assert_eq!(SemIfAdapter.path_for(&request), Ok("/score"));
    }

    #[test]
    fn a_message_carrying_an_image_is_refused_rather_than_silently_flattened() {
        // `as_text` returns `None` for a non-text part. Scoring the text around
        // an image would answer a question the caller did not ask, and the
        // caller would have no way to tell.
        use hypellm_core::canonical::{ContentPart, ImageSource};
        let request = CanonicalRequest {
            messages: vec![Message {
                role: Role::User,
                content: vec![
                    ContentPart::Text("Which of these?".to_owned()),
                    ContentPart::Image(ImageSource::Url("https://example.invalid/a.png".to_owned())),
                ],
                name: None,
                tool_calls: Vec::new(),
            }],
            ..rerank_request_fixture()
        };
        let failure = SemIfAdapter
            .validate(&request, &rerank_capabilities())
            .expect_err("a scorer cannot see an image");
        assert_eq!(failure.param, Some("query"));
    }

    #[test]
    fn no_credential_is_ever_written_into_a_scorer_request() {
        // The scorer reads no authentication header. An adapter that sent one
        // anyway would be handing a secret to a service that cannot check it
        // and will log the request line.
        use hypellm_core::ids::CredentialRef;
        let reference = CredentialRef::new("cred_scorer").expect("valid identifier");
        let handle = CredentialHandle::new(&reference, b"sk-should-never-be-sent");
        let target = target_fixture();
        let endpoint = endpoint_fixture("scorer.example");
        let headers = SemIfAdapter.encode_headers(
            Some(&handle),
            &meta_fixture(&target, &endpoint, false),
        );
        let rendered = format!("{headers:?}");
        assert!(!rendered.contains("sk-should-never"));
        assert!(
            !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("x-api-key")),
            "the scorer takes no credential, so none is sent"
        );
    }

    #[test]
    fn a_scorer_that_answers_a_non_streaming_request_with_a_stream_is_a_violation() {
        let failure = SemIfAdapter
            .decode_stream_event(None, "data: {}")
            .expect_err("a scorer has nothing to stream");
        assert_eq!(failure.class, UpstreamErrorClass::ProtocolViolation);
        assert!(!SemIfAdapter.is_stream_terminator("[DONE]"));
    }
}
