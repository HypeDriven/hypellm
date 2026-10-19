//! `GET /admin/v1/jobs`: the job queue, as an operator sees it
//! (orchestration §11.9).
//!
//! The properties are the management API's own: a permission gates it, it
//! never shows another tenant's work, and a router that runs no jobs says so
//! rather than listing an empty queue.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod harness;

use harness::{Harness, TENANT_A, TENANT_B};
use hypellm_admin_api::{JobQueue, QueuedJob};
use hypellm_core::admission::PriorityClass;
use hypellm_core::ids::{AliasId, PrincipalId, TenantId};
use std::sync::{Arc, Mutex};
use wire_json::Value;

/// A queue holding one job per tenant, recording which tenant it was asked
/// about.
#[derive(Debug, Default)]
struct TwoTenantQueue {
    asked: Mutex<Vec<TenantId>>,
}

impl JobQueue for TwoTenantQueue {
    fn queue(&self, tenant: &TenantId) -> Vec<QueuedJob> {
        self.asked.lock().unwrap().push(tenant.clone());
        let principal = if tenant.as_str() == TENANT_A { "svc:mine" } else { "svc:theirs" };
        vec![QueuedJob {
            id: format!("job_{}", tenant.as_str()),
            principal: PrincipalId::new(principal).unwrap(),
            alias: AliasId::new("song").unwrap(),
            class: PriorityClass::Batch,
            round: 2,
            state: "queued",
            waiting_for: Some("slot"),
            created_ms: 0,
        }]
    }
}

#[test]
fn an_operator_sees_their_own_tenants_queue_and_nothing_of_anothers() {
    let queue = Arc::new(TwoTenantQueue::default());
    let admin = Harness::builder()
        .jobs(Arc::clone(&queue) as Arc<dyn JobQueue>)
        .build();

    let response = admin.get(&admin.operator(), "/admin/v1/jobs");
    assert_eq!(response.status, 200, "{:?}", response.body);
    let body = response.json();
    let items = match body.get("items") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("expected items, got {other:?}"),
    };
    assert_eq!(items.len(), 1);
    let row = &items[0];
    assert_eq!(row.get("principal").and_then(Value::as_str), Some("svc:mine"));
    assert_eq!(row.get("class").and_then(Value::as_str), Some("batch"));
    assert_eq!(row.get("waiting_for").and_then(Value::as_str), Some("slot"));
    assert!(!format!("{body:?}").contains("svc:theirs"));
    assert_eq!(
        *queue.asked.lock().unwrap(),
        vec![TenantId::new(TENANT_A).unwrap()],
        "the queue was asked about a tenant other than the caller's"
    );

    // The other tenant's operator sees theirs, never this one's.
    let theirs = admin.get(&admin.operator_in(TENANT_B), "/admin/v1/jobs").json();
    assert!(!format!("{theirs:?}").contains("svc:mine"));
}

#[test]
fn a_viewer_cannot_read_the_queue() {
    let admin = Harness::builder()
        .jobs(Arc::new(TwoTenantQueue::default()) as Arc<dyn JobQueue>)
        .build();
    let response = admin.get(&admin.viewer(), "/admin/v1/jobs");
    assert_eq!(response.status, 403, "{:?}", response.body);
}

#[test]
fn a_router_that_runs_no_jobs_says_so() {
    let admin = Harness::builder().build();
    let response = admin.get(&admin.operator(), "/admin/v1/jobs");
    assert_eq!(response.status, 404, "{:?}", response.body);
    assert!(
        format!("{:?}", response.body).contains("does not run jobs"),
        "{:?}",
        response.body
    );
}
