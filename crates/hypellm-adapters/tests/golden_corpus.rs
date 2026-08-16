//! The golden provider corpus, decoded by the real adapters.
//!
//! Specification 21 requires integration tests "against recorded golden
//! servers". `hypellm-test-corpus` holds the response bodies, the stream frames,
//! and the canonical result each must decode to; this file feeds them to the
//! adapters and compares. No socket is opened and no host is resolved: the
//! fixtures are the server.
//!
//! Every fixture in that crate is synthetic and contains no real credential,
//! identifier, prompt, or completion. That has a cost worth restating here: a
//! passing run proves the decoders handle the documented shapes, not that a
//! provider still sends them.
//!
//! The inline decoder tests in `src/openai.rs` and `src/anthropic.rs` are
//! unaffected and stay where they are.

use hypellm_adapters::contract::{Adapter, ErrorClassification};
use hypellm_adapters::{AnthropicAdapter, OpenAiAdapter};
use hypellm_core::event::{CanonicalEvent, FinishReason, ResponseAccumulator};
use hypellm_core::target::ProviderFamily;
use hypellm_test_corpus::golden::{
    self, ExpectedCompletion, ExpectedFinish, FailurePath, GoldenFamily,
};

/// The adapter for a fixture's wire format.
///
/// Returned as a boxed trait object so one comparison routine serves both
/// families: the point of the corpus is that the *expectation* is the same
/// shape whatever produced the bytes.
fn adapter_for(family: GoldenFamily) -> Box<dyn Adapter> {
    match family {
        GoldenFamily::OpenAiCompatible => {
            Box::new(OpenAiAdapter::new(ProviderFamily::OpenAi))
        }
        GoldenFamily::Anthropic => Box::new(AnthropicAdapter),
    }
}

/// The corpus spells finish reasons as plain data, since it takes no
/// dependencies. This is the one place the two vocabularies meet.
fn finish_matches(observed: Option<FinishReason>, expected: ExpectedFinish) -> bool {
    let want = match expected {
        ExpectedFinish::Stop => FinishReason::Stop,
        ExpectedFinish::Length => FinishReason::Length,
        ExpectedFinish::ToolCalls => FinishReason::ToolCalls,
        ExpectedFinish::ContentFilter => FinishReason::ContentFilter,
        ExpectedFinish::Unrecognized => FinishReason::Unrecognized,
    };
    observed == Some(want)
}

/// Compare a decoded event sequence against a corpus expectation.
fn assert_completion(
    name: &str,
    why: &str,
    adapter: &dyn Adapter,
    events: &[CanonicalEvent],
    expect: &ExpectedCompletion,
) {
    let mut accumulator = ResponseAccumulator::new();
    for event in events {
        accumulator.push(event);
    }

    assert_eq!(
        accumulator.text, expect.text,
        "{name}: assembled text differs\n  why: {why}"
    );
    assert_eq!(
        accumulator.reasoning, expect.reasoning,
        "{name}: assembled reasoning differs\n  why: {why}"
    );
    assert_eq!(
        accumulator.upstream_id.as_deref(),
        expect.upstream_id,
        "{name}: upstream identifier differs\n  why: {why}"
    );
    assert_eq!(
        accumulator.native_model.as_deref(),
        expect.native_model,
        "{name}: native model differs\n  why: {why}"
    );
    assert!(
        finish_matches(accumulator.finish, expect.finish),
        "{name}: finish reason is {:?}, the corpus expects {}\n  why: {why}",
        accumulator.finish,
        expect.finish.as_str()
    );

    let calls = accumulator.sorted_tool_calls();
    assert_eq!(
        calls.len(),
        expect.tool_calls.len(),
        "{name}: assembled {} tool calls, the corpus expects {}\n  why: {why}",
        calls.len(),
        expect.tool_calls.len()
    );
    for (observed, want) in calls.iter().zip(expect.tool_calls) {
        assert_eq!(observed.index, want.index, "{name}: tool call index differs");
        assert_eq!(observed.id, want.id, "{name}: tool call id differs");
        assert_eq!(observed.name, want.name, "{name}: tool call name differs");
        assert_eq!(
            observed.arguments, want.arguments,
            "{name}: tool call arguments differ\n  why: {why}"
        );
    }

    // Specification 14 requires the provenance to travel with the number: an
    // absent usage must not be reported as a provider-reported zero, because a
    // metering record cannot then tell "free" from "unknown".
    let usage = adapter.usage_from_events(events);
    assert_eq!(
        usage.is_reported(),
        expect.usage_is_reported,
        "{name}: usage provenance differs\n  why: {why}"
    );
    assert_eq!(usage.input_tokens, expect.input_tokens, "{name}: input tokens");
    assert_eq!(
        usage.output_tokens, expect.output_tokens,
        "{name}: output tokens"
    );
    assert_eq!(
        usage.cached_input_tokens, expect.cached_input_tokens,
        "{name}: cached input tokens"
    );
}

#[test]
fn every_recorded_response_decodes_to_the_expected_events() {
    assert!(!golden::responses().is_empty(), "the corpus is empty");
    for fixture in golden::responses() {
        let adapter = adapter_for(fixture.family);
        let events = adapter
            .decode_response(fixture.status, fixture.body.as_bytes())
            .unwrap_or_else(|error| {
                panic!("{}: decoding failed: {:?}", fixture.name, error.class)
            });
        assert_completion(
            fixture.name,
            fixture.why,
            adapter.as_ref(),
            &events,
            &fixture.expect,
        );
    }
}

#[test]
fn every_recorded_stream_decodes_to_the_expected_events() {
    assert!(!golden::streams().is_empty(), "the corpus is empty");
    for fixture in golden::streams() {
        let adapter = adapter_for(fixture.family);
        let mut events = Vec::new();
        for frame in fixture.frames {
            if adapter.is_stream_terminator(frame.data) {
                // The terminal marker ends the stream; anything after it would
                // be data the router must not attribute to this response.
                continue;
            }
            events.extend(
                adapter
                    .decode_stream_event(frame.event, frame.data)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{}: frame {:?} failed to decode: {:?}",
                            fixture.name, frame.event, error.class
                        )
                    }),
            );
        }
        assert_completion(
            fixture.name,
            fixture.why,
            adapter.as_ref(),
            &events,
            &fixture.expect,
        );
    }
}

#[test]
fn a_stream_and_its_non_streaming_twin_agree_on_the_text() {
    // The router may serve the same alias streamed or not, and specification 8
    // makes compatibility behavioural rather than path-level. If the two paths
    // disassemble the same content differently, a harness that toggles
    // streaming sees two different answers from one model.
    for (stream_name, response_name) in [
        ("golden/openai_chat_stream", "golden/openai_chat_completion"),
        ("golden/anthropic_message_stream", "golden/anthropic_message"),
        (
            "golden/anthropic_message_stream_tool_use",
            "golden/anthropic_message_tool_use",
        ),
    ] {
        let stream = golden::stream_by_name(stream_name).expect("present");
        let response = golden::response_by_name(response_name).expect("present");
        assert_eq!(
            stream.expect.text, response.expect.text,
            "{stream_name} and {response_name} carry the same content in different framings"
        );
        assert_eq!(stream.expect.finish, response.expect.finish);
        assert_eq!(
            stream.expect.tool_calls.len(),
            response.expect.tool_calls.len(),
            "{stream_name} and {response_name} disagree on how many tool calls the content holds"
        );
    }
}

#[test]
fn recorded_embeddings_decode_to_the_expected_vectors() {
    for fixture in golden::embeddings() {
        let adapter = adapter_for(fixture.family);
        let events = adapter
            .decode_response(fixture.status, fixture.body.as_bytes())
            .unwrap_or_else(|error| {
                panic!("{}: decoding failed: {:?}", fixture.name, error.class)
            });

        let mut accumulator = ResponseAccumulator::new();
        for event in &events {
            accumulator.push(event);
        }
        assert_eq!(
            accumulator.embeddings.len(),
            fixture.expect.len(),
            "{}: decoded {} vectors, the corpus expects {}\n  why: {}",
            fixture.name,
            accumulator.embeddings.len(),
            fixture.expect.len(),
            fixture.why
        );
        for ((index, values), want) in accumulator.embeddings.iter().zip(fixture.expect) {
            assert_eq!(*index, want.index, "{}: vector index differs", fixture.name);
            assert_eq!(
                values.as_slice(),
                want.values,
                "{}: vector components differ",
                fixture.name
            );
        }
        assert_eq!(
            adapter.usage_from_events(&events).input_tokens,
            fixture.input_tokens,
            "{}: input tokens",
            fixture.name
        );
    }
}

#[test]
fn every_recorded_failure_classifies_as_the_corpus_requires() {
    assert!(!golden::failures().is_empty(), "the corpus is empty");
    for fixture in golden::failures() {
        let adapter = adapter_for(fixture.family);
        let classification: ErrorClassification = match fixture.path {
            FailurePath::Response => adapter
                .decode_response(fixture.status, fixture.body.as_bytes())
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "{}: decoded as a success, but the corpus records a failure\n  why: {}",
                        fixture.name, fixture.why
                    )
                }),
            FailurePath::StreamEvent { event } => adapter
                .decode_stream_event(event, fixture.body)
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "{}: decoded as an ordinary frame, but the corpus records a failure\n  why: {}",
                        fixture.name, fixture.why
                    )
                }),
        };

        assert_eq!(
            classification.class.as_str(),
            fixture.expect_class,
            "{}: classified as {}, the corpus requires {}\n  why: {}",
            fixture.name,
            classification.class.as_str(),
            fixture.expect_class,
            fixture.why
        );
        assert_eq!(
            classification.is_retriable(),
            fixture.expect_retriable,
            "{}: retriability differs, which is a specification 6.5 failover decision",
            fixture.name
        );
        assert_eq!(
            classification
                .provider_code
                .as_ref()
                .map(hypellm_core::sensitive::Capped::as_str),
            fixture.expect_provider_code,
            "{}: recorded provider code differs",
            fixture.name
        );
    }
}

#[test]
fn no_recorded_failure_leaks_provider_text_to_the_client() {
    // Specification 10 keeps a provider body out of the client's error, and
    // those messages routinely echo the prompt, an internal hostname, a quota
    // identifier, or the router's own rejected credential. Each fixture names
    // the fragment of its own body that must not survive.
    for fixture in golden::failures() {
        let adapter = adapter_for(fixture.family);
        let classification = adapter.classify_error(fixture.status, fixture.body.as_bytes());
        let detail = classification.safe_detail.as_str();
        for fragment in fixture.must_not_leak {
            assert!(
                !detail.contains(fragment),
                "{}: the client-visible detail contains {fragment:?}\n  detail: {detail:?}",
                fixture.name
            );
        }

        // The narrowed provider code reaches log lines and metric labels.
        // Specification 17 forbids high-cardinality and injectable label
        // values, so it must stay inside an identifier alphabet.
        if let Some(code) = &classification.provider_code {
            assert!(
                code.as_str()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')),
                "{}: provider code {:?} is outside the identifier alphabet",
                fixture.name,
                code.as_str()
            );
        }
    }
}
