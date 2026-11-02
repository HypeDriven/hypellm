//! Conversation affinity: a turn returns to the target that served the
//! conversation, so its prompt prefix is likely still in that KV cache.
//!
//! The properties, each against two otherwise-equal targets so that only the
//! affinity term can explain where a turn lands:
//!
//! - a conversation returns to the target that last served it, on request
//!   identifiers whose tie-break alone would have spread it;
//! - affinity is a score, not a pin — a target whose breaker is open is not
//!   chosen, and the conversation follows the target that served it instead;
//! - an observation from before the target was started again is discarded;
//! - zero in the settings switches it off and records nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use hypellm_core::canonical::{CanonicalRequest, Operation};
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::{AliasId, RequestId, TargetId};
use hypellm_core::rbac::PermissionSet;
use hypellm_core::{AffinityLimits, ConversationKey};
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline;
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};

const OK: &str = r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"fine"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
const TURNS: u128 = 24;

struct Sink;
impl EventSink for Sink {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        Ok(())
    }
}

struct Fixture {
    router: TestRouter,
    _a: FakeUpstream,
    _b: FakeUpstream,
}

/// Two targets of equal rank, weight and cost behind one alias.
fn fixture(extra_settings: &str) -> Fixture {
    let responses = || {
        (0..400)
            .map(|_| CannedResponse::json(200, OK))
            .collect::<Vec<_>>()
    };
    let a = FakeUpstream::start_sequence(responses());
    let b = FakeUpstream::start_sequence(responses());
    let config = format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3 \
weighted_tie_break=true {extra_settings}
tenant id=acme
provider id=pa family=openai scheme=http host=127.0.0.1 port={} base_path=/v1 egress=local
provider id=pb family=openai scheme=http host=127.0.0.1 port={} base_path=/v1 egress=local
target id=pa:m provider=pa model=test-model local=true operations=chat context=100000 max_output=8192 concurrency=8
target id=pb:m provider=pb model=test-model local=true operations=chat context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=pa:m,pb:m
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
",
        a.address.port(),
        b.address.port()
    );
    Fixture {
        router: router_with_config(&a, &config),
        _a: a,
        _b: b,
    }
}

fn request(rid: u128, conversation: Option<&str>) -> CanonicalRequest {
    let mut request = hypellm_adapters::testing::request_fixture();
    request.requested_model = AliasId::new("test-alias").unwrap();
    request.request_id = RequestId::from_u128(rid);
    request.hints.conversation_id = conversation.map(str::to_owned);
    request
}

fn serve(router: &TestRouter, rid: u128, conversation: Option<&str>) -> TargetId {
    let outcome = pipeline::execute(
        &router.state,
        &request(rid, conversation),
        &[],
        PermissionSet::empty(),
        &mut Sink,
    );
    outcome
        .trace
        .chosen
        .clone()
        .unwrap_or_else(|| panic!("nothing served: {:?}", outcome.trace))
}

fn key(conversation: &str) -> ConversationKey {
    let r = request(0, None);
    ConversationKey::new(r.tenant, r.principal, r.requested_model, conversation).unwrap()
}

fn other(target: &TargetId) -> TargetId {
    TargetId::new(if target.as_str() == "pa:m" {
        "pb:m"
    } else {
        "pa:m"
    })
    .unwrap()
}

/// Request identifiers in `range` whose tie-break, with no conversation,
/// lands on `target`.
fn ids_landing_on(
    router: &TestRouter,
    target: &TargetId,
    range: std::ops::Range<u128>,
) -> Vec<u128> {
    range
        .filter(|rid| serve(router, *rid, None) == *target)
        .collect()
}

#[test]
fn a_conversation_returns_to_the_target_that_served_it() {
    let f = fixture("");
    let first = serve(&f.router, 1, Some("conv-1"));
    // Adversarial: these identifiers alone would send the turn elsewhere.
    let elsewhere = ids_landing_on(&f.router, &other(&first), 100..100 + TURNS * 4);
    assert!(
        elsewhere.len() >= 4,
        "the fixture must spread without affinity"
    );
    for rid in elsewhere {
        assert_eq!(serve(&f.router, rid, Some("conv-1")), first, "turn {rid}");
    }
    // A different conversation is not pulled along with it.
    let spread: BTreeSet<TargetId> = (500..500 + TURNS)
        .map(|rid| serve(&f.router, rid, Some(&format!("c{rid}"))))
        .collect();
    assert_eq!(spread.len(), 2, "distinct conversations still spread");
}

#[test]
fn affinity_never_routes_to_a_target_whose_breaker_is_open_and_follows_the_server() {
    let f = fixture("");
    let first = serve(&f.router, 1, Some("conv-1"));
    let state = &f.router.state;
    let health = state.health.entry(&first, Operation::Chat);
    health.breaker.force_open(state.clock.now_millis(), 600_000);

    let moved = serve(&f.router, 2, Some("conv-1"));
    assert_eq!(
        moved,
        other(&first),
        "an open breaker is a filter; affinity cannot undo it"
    );
    let now = state.clock.now_millis();
    let table = state.conversation_affinity.lock().unwrap();
    assert_eq!(table.preferred(&key("conv-1"), now).unwrap().target, moved);
}

#[test]
fn an_observation_from_before_the_target_was_restarted_is_discarded() {
    let f = fixture("");
    let state = &f.router.state;
    let stale = TargetId::new("pa:m").unwrap();
    // Recorded under activation epoch 1; the target's epoch is now 0, as it
    // is for any target this router has not started since.
    state.conversation_affinity.lock().unwrap().observe(
        key("conv-1"),
        stale.clone(),
        1,
        state.clock.now_millis(),
        AffinityLimits {
            ttl_ms: 600_000,
            max_entries: 100,
        },
    );
    let rid = ids_landing_on(&f.router, &other(&stale), 1..40)[0];
    assert_eq!(serve(&f.router, rid, Some("conv-1")), other(&stale));
    let now = state.clock.now_millis();
    let table = state.conversation_affinity.lock().unwrap();
    let observation = table.preferred(&key("conv-1"), now).unwrap();
    assert_eq!(
        (observation.target.clone(), observation.epoch),
        (other(&stale), 0)
    );
}

#[test]
fn zero_in_the_settings_switches_affinity_off_and_records_nothing() {
    for settings in [
        "conversation_affinity_ttl_ms=0",
        "conversation_affinity_max_entries=0",
    ] {
        let f = fixture(settings);
        let served: BTreeSet<TargetId> = (1..=TURNS)
            .map(|rid| serve(&f.router, rid, Some("conv-1")))
            .collect();
        assert_eq!(
            served.len(),
            2,
            "{settings}: turns spread as if no conversation were named"
        );
        assert!(
            f.router
                .state
                .conversation_affinity
                .lock()
                .unwrap()
                .is_empty(),
            "{settings}"
        );
    }
}
