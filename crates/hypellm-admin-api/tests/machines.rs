//! `GET /admin/v1/machines`.
//!
//! The properties: what running work holds is the live ledger, not a copy of
//! the configuration; a waiter is shown by class and size, never by the key
//! that identifies its caller's request; and a tenant sees only the machines
//! and targets it can reach.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

mod harness;

use harness::{Harness, default_config};
use hypellm_core::admission::PriorityClass;
use hypellm_core::ids::{PrincipalId, TargetId, TenantId};
use wire_json::Value;

const GIB: u64 = 1 << 30;

fn config() -> String {
    default_config()
        .replace(
            "grant scope=tenant:acme model=* allow=true",
            "grant scope=tenant:acme model=test-alias allow=true",
        )
        .replace(
            "grant scope=tenant:globex model=* allow=true",
            "grant scope=tenant:globex model=globex-alias allow=true",
        )
        .replace(
            "provider id=local family=openai scheme=http host=127.0.0.1 port=8081 \\\n         base_path=/v1 egress=local",
            "provider id=local family=openai scheme=http host=127.0.0.1 port=8081 \\\n         base_path=/v1 egress=local machine=spark",
        )
        .replace(
            "context=100000 max_output=8192 concurrency=8\n",
            "context=100000 max_output=8192 concurrency=8 run_memory_bytes=64424509440 class=batch\n",
        )
        + "\
machine id=spark memory_bytes=85899345920 description=\"DGX Spark .105\"
machine id=other memory_bytes=85899345920
provider id=theirs family=openai scheme=http host=127.0.0.1 port=8082 \\
         base_path=/v1 egress=local machine=other
target id=theirs:model provider=theirs model=theirs local=true \\
       operations=chat context=100000 max_output=8192 run_memory_bytes=1073741824
alias id=globex-alias targets=theirs:model
"
}

fn machine<'a>(body: &'a Value, id: &str) -> Option<&'a Value> {
    body.get("data")?
        .as_array()?
        .iter()
        .find(|m| m.get("id").and_then(Value::as_str) == Some(id))
}

#[test]
fn held_memory_and_the_waiting_line_are_the_live_ledgers() {
    let harness = Harness::with_config(&config());
    let controller = harness.admission.as_ref().expect("the harness has one");
    let target = TargetId::new("local:model").unwrap();
    let tenant = TenantId::new("acme").unwrap();
    let principal = PrincipalId::new("svc:ci").unwrap();

    let before = harness.get(&harness.viewer(), "/admin/v1/machines");
    assert!(before.is_ok(), "{}", before.body);
    let spark = machine(&before.json(), "spark").cloned().expect("spark is listed");
    assert_eq!(spark.get("memory_bytes").and_then(Value::as_u64), Some(80 * GIB));
    assert_eq!(spark.get("held_bytes").and_then(Value::as_u64), Some(0));
    let targets = spark.get("targets").and_then(Value::as_array).unwrap();
    assert_eq!(targets[0].get("class").and_then(Value::as_str), Some("batch"));

    let running = controller.reserve(&tenant, &principal, &target, 0).unwrap();
    let refused = controller.reserve_queued_as(
        &tenant,
        &principal,
        None,
        &target,
        0,
        PriorityClass::Standard,
        std::time::Duration::ZERO,
        Some("job-secret-identifier"),
    );
    assert!(refused.is_err());

    let during = harness.get(&harness.viewer(), "/admin/v1/machines");
    let spark = machine(&during.json(), "spark").cloned().unwrap();
    assert_eq!(spark.get("held_bytes").and_then(Value::as_u64), Some(60 * GIB));
    let waiting = spark.get("waiting").and_then(Value::as_array).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].get("class").and_then(Value::as_str), Some("batch"));
    assert!(!during.body.contains("job-secret-identifier"), "{}", during.body);

    drop(running);
    let after = harness.get(&harness.viewer(), "/admin/v1/machines");
    let spark = machine(&after.json(), "spark").cloned().unwrap();
    assert_eq!(spark.get("held_bytes").and_then(Value::as_u64), Some(0));
}

#[test]
fn a_tenant_sees_only_the_machines_it_can_reach() {
    let harness = Harness::with_config(&config());
    let acme = harness.get(&harness.viewer(), "/admin/v1/machines");
    assert!(machine(&acme.json(), "spark").is_some(), "{}", acme.body);
    assert!(!acme.body.contains("theirs:model"), "{}", acme.body);

    let globex = harness.get(&harness.viewer_in("globex"), "/admin/v1/machines");
    assert!(machine(&globex.json(), "other").is_some(), "{}", globex.body);
    assert!(machine(&globex.json(), "spark").is_none(), "{}", globex.body);
}
