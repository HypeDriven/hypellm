//! `GET /admin/v1/fleet/access`.
//!
//! The properties: it is not served without `ReadFleet`; it shows one tenant
//! nothing of another tenant's machines or grants; the principal list goes
//! only to a caller who could turn it into a draft; and it answers from
//! configuration with no fleet runtime running.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

mod harness;

use harness::{Harness, default_config};
use wire_json::Value;

fn config() -> String {
    default_config()
        // acme reaches only the shared alias; globex reaches its own too.
        .replace(
            "grant scope=tenant:acme model=* allow=true",
            "grant scope=tenant:acme model=test-alias allow=true",
        )
        + "\
target id=globex:model provider=local model=globex-only local=true \\
       operations=chat context=100000 max_output=8192 concurrency=8
alias id=globex-alias targets=globex:model
fleet_agent id=local socket=\"/run/hypellm/fleet.sock\"
host id=spark agent=local arch=aarch64
host id=gpu9 agent=local arch=x86_64
accelerator id=spark-gpu0 host=spark kind=cuda memory_bytes=100000000000
accelerator id=gpu9-gpu0 host=gpu9 kind=cuda memory_bytes=100000000000
deployment id=d-spark target=local:model accelerator=spark-gpu0 memory_bytes=1000
deployment id=d-gpu9 target=globex:model accelerator=gpu9-gpu0 memory_bytes=1000
fleet_grant id=g-acme scope=tenant:acme host=spark model=* allow=false
fleet_grant id=g-globex scope=tenant:globex host=gpu9 model=* allow=true
fleet_grant id=g-global scope=global host=* model=* allow=true
"
}

fn strings(value: Option<&Value>, field: &str) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get(field).and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_tenant_sees_its_own_machines_and_grants_and_nothing_of_another_tenant() {
    let harness = Harness::with_config(&config());
    harness.issue_api_key("acme", "svc:ci");
    harness.issue_api_key("globex", "svc:theirs");

    let response = harness.get(&harness.policy_editor(), "/admin/v1/fleet/access");
    assert!(response.is_ok(), "{}", response.body);
    let body = response.json();

    assert_eq!(strings(body.get("hosts"), "id"), vec!["spark".to_owned()]);
    let grants = strings(body.get("grants"), "id");
    assert!(grants.contains(&"g-acme".to_owned()), "{grants:?}");
    assert!(grants.contains(&"g-global".to_owned()), "{grants:?}");
    assert!(!grants.contains(&"g-globex".to_owned()), "{grants:?}");
    assert!(!response.body.contains("gpu9"), "{}", response.body);
    assert!(!response.body.contains("globex:model"), "{}", response.body);
    assert_eq!(body.get("default").and_then(Value::as_str), Some("allow"));

    let principals: Vec<String> = body
        .get("subjects")
        .and_then(|s| s.get("principals"))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    assert!(principals.contains(&"svc:ci".to_owned()), "{principals:?}");
    assert!(!principals.contains(&"svc:theirs".to_owned()), "{principals:?}");
}

#[test]
fn the_principal_list_goes_only_to_a_caller_who_could_draft_from_it() {
    let harness = Harness::with_config(&config());
    harness.issue_api_key("acme", "svc:ci");
    // An operator reads the fleet but cannot author policy.
    let response = harness.get(&harness.operator(), "/admin/v1/fleet/access");
    assert!(response.is_ok(), "{}", response.body);
    assert!(matches!(response.json().get("subjects"), Some(Value::Null)));
    assert!(!response.body.contains("svc:ci"));
}

#[test]
fn no_read_fleet_no_view() {
    let harness = Harness::with_config(&config());
    let response = harness.get(&harness.viewer(), "/admin/v1/fleet/access");
    assert_eq!(response.status, 403, "{}", response.body);
}
