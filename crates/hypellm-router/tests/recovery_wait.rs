//! Waiting out an outage instead of failing at once.
//!
//! `provider recovery_wait_ms` lets a request ride out a machine that is
//! briefly down — rebooting, or still loading its model — rather than failing
//! on the first refused connection. The properties: it waits only when the
//! operator asked, only for an outage (never for a refusal time cannot cure),
//! and never past the request's own deadline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::AliasId;
use hypellm_core::rbac::PermissionSet;
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline;
use hypellm_router::testing::{CannedResponse, FakeUpstream, default_config_text, router_with_config};
use hypellm_telemetry::{LabelName, Labels, names};
use std::time::Instant;

const OK_BODY: &str = r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"fine"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
const LOADING: &str = r#"{"error":{"message":"Loading model","type":"unavailable_error"}}"#;

fn request() -> CanonicalRequest {
    let mut request = hypellm_adapters::testing::request_fixture();
    request.requested_model = AliasId::new("test-alias").unwrap();
    request
}

#[derive(Default)]
struct Collect(Vec<CanonicalEvent>);

impl EventSink for Collect {
    fn deliver(&mut self, event: &CanonicalEvent) -> Result<(), SinkClosed> {
        self.0.push(event.clone());
        Ok(())
    }
}

fn config(port: u16, wait_ms: u64) -> String {
    default_config_text(port).replace(
        "egress=local\n",
        &format!("egress=local recovery_wait_ms={wait_ms}\n"),
    )
}

#[test]
fn a_machine_that_is_still_loading_is_waited_for_rather_than_failed() {
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, LOADING),
        CannedResponse::json(503, LOADING),
        CannedResponse::json(200, OK_BODY),
    ]);
    let router = router_with_config(&upstream, &config(upstream.address.port(), 4_000));

    let outcome = pipeline::execute(
        &router.state,
        &request(),
        &[],
        PermissionSet::empty(),
        &mut Collect::default(),
    );
    assert!(outcome.is_success(), "{:?}", outcome.error);
    assert_eq!(upstream.served(), 3, "it must have retried until the model answered");
    assert_eq!(
        router.state.recovery_waiters.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the waiter slot is returned"
    );

    // While it waited it was counted as pending; now it is not.
    let metrics = &router.state.telemetry.metrics;
    let pending = Labels::new()
        .with(LabelName::Reason, "recovery")
        .with(LabelName::Alias, "test-alias");
    assert_eq!(metrics.gauge_value(names::PENDING_REQUESTS, &pending), Some(0));

    // The completion is attributed to the model that served it.
    pipeline::record_completion(&router.state, &request(), &outcome, 10, None);
    let by_model = Labels::new()
        .with(LabelName::Target, "local:model")
        .with(LabelName::Alias, "test-alias");
    assert_eq!(metrics.counter_value(names::MODEL_OUTPUT_TOKENS, &by_model), Some(1));
    assert_eq!(metrics.counter_value(names::MODEL_INPUT_TOKENS, &by_model), Some(1));
    let exposition = metrics.exposition();
    assert!(
        exposition.contains("hypellm_output_tokens_per_second_bucket{target=\"local:model\""),
        "{exposition}"
    );
}

#[test]
fn without_a_recovery_wait_the_outage_fails_at_once() {
    // The control for the test above: the same upstream, no wait configured.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, LOADING),
        CannedResponse::json(200, OK_BODY),
    ]);
    let router = router_with_config(&upstream, &config(upstream.address.port(), 0));
    let outcome = pipeline::execute(
        &router.state,
        &request(),
        &[],
        PermissionSet::empty(),
        &mut Collect::default(),
    );
    assert!(!outcome.is_success());
    assert_eq!(upstream.served(), 1);
}

#[test]
fn a_refusal_time_cannot_cure_is_not_waited_out() {
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(400, r#"{"error":{"message":"bad request"}}"#),
        CannedResponse::json(200, OK_BODY),
    ]);
    let router = router_with_config(&upstream, &config(upstream.address.port(), 4_000));
    let started = Instant::now();
    let outcome = pipeline::execute(
        &router.state,
        &request(),
        &[],
        PermissionSet::empty(),
        &mut Collect::default(),
    );
    assert!(!outcome.is_success());
    assert_eq!(upstream.served(), 1, "a client error must not be retried");
    assert!(started.elapsed().as_millis() < 1_000);
}

#[test]
fn a_machine_that_stays_down_fails_within_its_wait_and_the_deadline() {
    // Nothing listens: bind a port and let it go.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let upstream = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    // The wait is far longer than this request's 3 s deadline: the deadline wins.
    let router = router_with_config(&upstream, &config(port, 60_000));
    let mut request = request();
    request.limits.deadline = hypellm_core::time::Deadline::after(
        router.state.clock.as_ref(),
        std::time::Duration::from_secs(3),
    );
    let started = Instant::now();
    let outcome = pipeline::execute(
        &router.state,
        &request,
        &[],
        PermissionSet::empty(),
        &mut Collect::default(),
    );
    let elapsed = started.elapsed().as_millis();
    assert!(!outcome.is_success());
    assert!(elapsed >= 1_000, "it must have waited, not failed at once ({elapsed} ms)");
    assert!(elapsed < 4_500, "it must not wait past the request deadline ({elapsed} ms)");
    assert_eq!(upstream.served(), 0);
}
