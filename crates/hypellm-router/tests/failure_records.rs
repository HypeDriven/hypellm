//! What a failed request leaves for an operator to read.
//!
//! A failed attempt has no usage, and before these records existed a stream
//! cut off after twenty minutes of tool-call arguments and a refusal in the
//! first second left the same `request.completed` line: a code, a duration, no
//! target. Each test drives the real pipeline against a fake provider and
//! asserts two things about the record: that it says where and how the attempt
//! failed, and that it says so without carrying any of the output, the
//! provider's message, or the tool arguments (specification 10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::decision::AttemptOutcome;
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::AliasId;
use hypellm_core::rbac::PermissionSet;
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline::{self, Outcome};
use hypellm_router::testing::{
    CannedResponse, FakeUpstream, TestRouter, default_config_text, router_with_config,
};

fn streaming_request() -> CanonicalRequest {
    let mut request = hypellm_adapters::testing::request_fixture();
    request.requested_model = AliasId::new("test-alias").unwrap();
    request.stream.enabled = true;
    request
}

struct Accept;

impl EventSink for Accept {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        Ok(())
    }
}

/// A client that takes `remaining` events and then goes away.
struct LeavesAfter {
    remaining: usize,
}

impl EventSink for LeavesAfter {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        self.remaining = self.remaining.checked_sub(1).ok_or(SinkClosed)?;
        Ok(())
    }
}

/// An event stream that stops without `[DONE]` or a finish reason, as a
/// connection closed mid-generation does.
fn cut_stream(frames: &[&str]) -> CannedResponse {
    let mut response = CannedResponse::event_stream(frames);
    let done = b"data: [DONE]\n\n";
    assert!(response.body.ends_with(done), "the fixture's framing changed");
    response.body.truncate(response.body.len() - done.len());
    response
}

fn run(router: &TestRouter, request: &CanonicalRequest, sink: &mut dyn EventSink) -> Outcome {
    let outcome = pipeline::execute(&router.state, request, &[], PermissionSet::empty(), sink);
    pipeline::record_completion(&router.state, request, &outcome, 1, None);
    outcome
}

fn completed_line(router: &TestRouter) -> String {
    router
        .logs
        .lines()
        .into_iter()
        .find(|line| line.contains("\"request.completed\""))
        .expect("a request.completed line")
}

const TOOL_UNIT: &str = r#""a1b2", "#;

#[test]
fn a_stream_cut_off_inside_a_looping_tool_call_says_where_and_in_what_shape() {
    let opening = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"lookup","arguments":"{\"ids\": ["}}]}}]}"#;
    let unit = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a1b2\", "}}]}}]}"#;
    let mut frames = vec![opening];
    frames.extend(std::iter::repeat_n(unit, 60));
    let upstream = FakeUpstream::start(cut_stream(&frames));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));

    let outcome = run(&router, &streaming_request(), &mut Accept);
    assert!(!outcome.is_success());

    let attempt = outcome.trace.attempts.last().expect("one attempt");
    assert!(
        matches!(attempt.outcome, AttemptOutcome::FailedAfterOutput(_)),
        "{:?}",
        attempt.outcome
    );
    assert_eq!(attempt.upstream_status, Some(200), "it failed inside a 200, not by refusal");
    let output = attempt.output;
    assert_eq!(output.deltas, 61);
    assert_eq!(output.tool_calls, 1, "one call, named once, however long its arguments");
    assert_eq!(output.text_bytes, 0);
    let arguments = "{\"ids\": [".len() + 60 * TOOL_UNIT.len();
    assert_eq!(output.tool_argument_bytes, u64::try_from(arguments).unwrap());
    assert_eq!(output.repeat_period, Some(8), "the loop's unit");
    assert_eq!(output.repeat_bytes, Some(480), "all sixty units, nothing before them");

    let line = completed_line(&router);
    for expected in [
        r#""target":"local:model""#,
        r#""attempt_outcome":"failed_after_output""#,
        r#""upstream_status":200"#,
        r#""output_deltas":61"#,
        r#""tool_calls":1"#,
        r#""repeat_period":8"#,
        r#""repeat_bytes":480"#,
    ] {
        assert!(line.contains(expected), "missing {expected} in {line}");
    }
    assert!(!line.contains("a1b2"), "tool arguments reached the log: {line}");
    assert!(!line.contains("lookup"), "the tool name reached the log: {line}");
}

#[test]
fn an_error_event_inside_a_stream_names_the_provider_code_and_never_its_message() {
    let upstream = FakeUpstream::start(cut_stream(&[
        r#"{"choices":[{"delta":{"content":"PARTIAL-ANSWER"}}]}"#,
        r#"{"error":{"type":"server_error","message":"failed near: SECRET-PROMPT-ECHO"}}"#,
    ]));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));

    let outcome = run(&router, &streaming_request(), &mut Accept);
    let attempt = outcome.trace.attempts.last().expect("one attempt");
    assert_eq!(attempt.provider_code.as_deref(), Some("server_error"));
    assert_eq!(attempt.output.text_bytes, u64::try_from("PARTIAL-ANSWER".len()).unwrap());

    let line = completed_line(&router);
    assert!(line.contains(r#""provider_code":"server_error""#), "{line}");
    assert!(line.contains(r#""error_class":"server_error""#), "{line}");
    assert!(!line.contains("SECRET-PROMPT-ECHO"), "the provider's message reached the log");
    assert!(!line.contains("PARTIAL-ANSWER"), "output reached the log");
}

#[test]
fn a_client_that_leaves_is_recorded_as_cancelled_not_as_a_target_failure() {
    // The caller is told `invalid_request` — there is nobody left to tell —
    // but an operator reading the record needs to know the client left, or a
    // harness-side timeout reads as the provider failing.
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"choices":[{"delta":{"content":"one"}}]}"#,
        r#"{"choices":[{"delta":{"content":"two"}}]}"#,
        r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
    ]));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));

    let outcome = run(&router, &streaming_request(), &mut LeavesAfter { remaining: 1 });
    let attempt = outcome.trace.attempts.last().expect("one attempt");
    assert_eq!(attempt.outcome, AttemptOutcome::Cancelled);
    assert_eq!(attempt.output.deltas, 2, "the delta the client refused was still produced");

    let line = completed_line(&router);
    assert!(line.contains(r#""code":"invalid_request""#), "{line}");
    assert!(line.contains(r#""attempt_outcome":"cancelled""#), "{line}");
    assert!(line.contains(r#""target":"local:model""#), "{line}");
}

#[test]
fn a_successful_request_line_is_unchanged() {
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"choices":[{"delta":{"content":"fine"}}]}"#,
        r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
    ]));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));

    let outcome = run(&router, &streaming_request(), &mut Accept);
    assert!(outcome.is_success(), "{:?}", outcome.error);
    let line = completed_line(&router);
    assert!(!line.contains("attempt_outcome"), "{line}");
    assert!(!line.contains("output_deltas"), "{line}");
}
