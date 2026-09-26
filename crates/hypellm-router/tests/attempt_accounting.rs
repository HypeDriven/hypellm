//! What one attempt leaves behind: breaker probe slots, target health, and
//! admission budget.
//!
//! Each test drives the real pipeline against a fake provider on a real
//! socket and asserts the state the attempt left, not merely the status it
//! returned. The properties are the ones Appendix B and specifications 6.5,
//! 12 and 13 state: every reservation and every probe slot is returned exactly
//! once on every path, a client that disconnects is not evidence against a
//! target, a stream is complete only when the provider says so, and an attempt
//! the provider never accepted costs no token budget.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::canonical::{CanonicalRequest, Operation};
use hypellm_core::event::CanonicalEvent;
use hypellm_core::health::BreakerState;
use hypellm_core::ids::{AliasId, TargetId};
use hypellm_core::rbac::PermissionSet;
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline::{self, Outcome};
use hypellm_router::testing::{
    CannedResponse, FakeUpstream, TestRouter, default_config_text, router_with_config,
};

const OK_BODY: &str = r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"fine"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;

fn request() -> CanonicalRequest {
    let mut request = hypellm_adapters::testing::request_fixture();
    request.requested_model = AliasId::new("test-alias").unwrap();
    request
}

fn target() -> TargetId {
    TargetId::new("local:model").unwrap()
}

/// Collects what reached the client.
#[derive(Default)]
struct Collect {
    events: Vec<CanonicalEvent>,
}

impl EventSink for Collect {
    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed> {
        self.events.push(event.clone());
        Ok(())
    }
}

/// A client that has gone away.
struct Gone;

impl EventSink for Gone {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        Err(SinkClosed)
    }
}

fn run(router: &TestRouter, request: &CanonicalRequest, sink: &mut dyn EventSink) -> Outcome {
    pipeline::execute(&router.state, request, &[], PermissionSet::empty(), sink)
}

fn half_open(router: &TestRouter) {
    let health = router.state.health.entry(&target(), Operation::Chat);
    let now = router.state.clock.now_millis();
    // Open with no cooldown: the next look finds it half-open.
    health.breaker.force_open(now, 0);
    assert_eq!(health.breaker.state(now), BreakerState::HalfOpen);
}

fn probe_slot_is_free(router: &TestRouter) -> bool {
    let health = router.state.health.entry(&target(), Operation::Chat);
    let now = router.state.clock.now_millis();
    health.breaker.admit(now).is_some()
}


#[test]
fn a_half_open_probe_that_ends_in_a_client_error_does_not_lock_the_target_out() {
    // The provider rejects the caller's request. That says nothing about the
    // target, so it is kept out of the breaker — and the probe slot the
    // request took used to be kept out with it, refusing the target forever.
    let upstream = FakeUpstream::start(CannedResponse::json(
        400,
        r#"{"error":{"type":"invalid_request_error","message":"no"}}"#,
    ));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    half_open(&router);

    let first = run(&router, &request(), &mut Collect::default());
    assert!(!first.is_success());
    assert_eq!(upstream.served(), 1);

    let second = run(&router, &request(), &mut Collect::default());
    assert_eq!(
        upstream.served(),
        2,
        "the second request was refused by the breaker: {:?}",
        second.trace.exclusions
    );
    assert!(probe_slot_is_free(&router));
}

#[test]
fn a_half_open_probe_refused_by_admission_returns_its_slot() {
    // Refused before any I/O, by the target's own concurrency limit, after the
    // breaker had already handed out its only probe slot.
    let upstream = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let port = upstream.address.port();
    let config = format!(
        "{}quota scope=target:local:model concurrency=1\n",
        default_config_text(port)
    );
    let router = router_with_config(&upstream, &config);

    let request = request();
    let holder = router
        .state
        .admission
        .reserve(&request.tenant, &request.principal, &target(), 1)
        .expect("the one slot");
    half_open(&router);

    let refused = run(&router, &request, &mut Collect::default());
    assert!(!refused.is_success());
    assert_eq!(upstream.served(), 0);
    drop(holder);

    assert!(probe_slot_is_free(&router), "the refused request kept the probe slot");
    let served = run(&router, &request, &mut Collect::default());
    assert!(served.is_success(), "{:?}", served.error);
}

#[test]
fn a_client_that_disconnects_is_not_counted_against_the_target() {
    let upstream = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    let health = router.state.health.entry(&target(), Operation::Chat);

    // Closed: many disconnects add no failures, so no amount of them opens it.
    for _ in 0..30 {
        let outcome = run(&router, &request(), &mut Gone);
        assert!(!outcome.is_success());
        assert_eq!(outcome.trace.attempts.len(), 1, "no failover once the client is gone");
    }
    let now = router.state.clock.now_millis();
    assert_eq!(health.total_failures(), 0);
    assert_eq!(health.breaker.failure_percent(now), 0);
    assert_eq!(health.breaker.state(now), BreakerState::Closed);

    // Half-open: a disconnect during the probe neither reopens the breaker nor
    // keeps the slot.
    half_open(&router);
    let outcome = run(&router, &request(), &mut Gone);
    assert!(!outcome.is_success());
    let now = router.state.clock.now_millis();
    assert_eq!(health.breaker.state(now), BreakerState::HalfOpen);
    assert!(probe_slot_is_free(&router));
}

#[test]
fn a_stream_cut_off_mid_generation_is_reported_as_a_failure() {
    // Close-delimited framing: the upstream sends a delta and closes, with no
    // finish and no `[DONE]`. The body is complete in the HTTP sense, and was
    // once treated as a successful response.
    let mut body = String::new();
    wire_sse::encode_data(
        &mut body,
        r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Half an ans"}}]}"#,
    );
    let upstream = FakeUpstream::start(CannedResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "text/event-stream".to_owned())],
        body: body.into_bytes(),
        streaming: true,
        body_delay: std::time::Duration::ZERO,
        delay: std::time::Duration::ZERO,
    });
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    let mut request = request();
    request.stream.enabled = true;

    let mut sink = Collect::default();
    let outcome = run(&router, &request, &mut sink);

    assert!(
        sink.events.iter().any(CanonicalEvent::is_semantic_output),
        "the fixture must have delivered output before the cut"
    );
    assert!(!outcome.is_success(), "a truncated stream was reported as success");
    assert!(outcome.saw_output, "the error must be a terminal event, not a new response");
    assert_eq!(upstream.served(), 1, "never fail over after output");
}

#[test]
fn a_complete_stream_still_succeeds() {
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Whole"}}]}"#,
        r#"{"id":"1","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
    ]));
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    let mut request = request();
    request.stream.enabled = true;
    let outcome = run(&router, &request, &mut Collect::default());
    assert!(outcome.is_success(), "{:?}", outcome.error);
}

#[test]
fn a_failover_attempt_the_provider_refused_costs_no_token_budget() {
    // The tenant's token bucket holds exactly one request's estimate and
    // refills at one token a second. The first target refuses with a 503
    // before accepting anything; the failover to the second target needs the
    // same estimate again. When the refused attempt was left to `Drop`, which
    // charges the whole estimate, the failover was refused for budget the
    // tenant never used.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, r#"{"error":{"type":"api_error"}}"#),
        CannedResponse::json(200, OK_BODY),
    ]);
    let request = request();
    let estimate = request.estimated_total_tokens();
    assert!(estimate > 10, "the fixture needs a meaningful estimate");
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:first provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
target id=local:second provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
alias id=test-alias targets=local:first,local:second family_failover=true
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:first,local:second
quota scope=tenant:acme tpm=60 token_burst={estimate}
"
    );
    let router = router_with_config(&upstream, &config);

    let outcome = run(&router, &request, &mut Collect::default());
    assert_eq!(upstream.served(), 2, "the failover never reached the second target");
    assert!(outcome.is_success(), "{:?} {:?}", outcome.error, outcome.trace.exclusions);
}
