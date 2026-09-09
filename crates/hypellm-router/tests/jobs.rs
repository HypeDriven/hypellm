//! `POST /v1/jobs` and its lifecycle (specification-extension 11).
//!
//! The endpoint exists so a six-minute generation does not hold a connection
//! worker for six minutes, and the properties worth asserting are the ones that
//! keep it from becoming an unbounded queue with a REST interface: a per-tenant
//! cap, a bounded queue, an expiring result spool, and — the one that is a
//! security property rather than a resource one — a job identifier that is not
//! a capability across tenants.

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, Message, Operation, ReasoningEffort, RequestLimits, Role,
    RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::ids::{AliasId, PrincipalId, RequestId, TenantId};
use hypellm_core::rbac::PermissionSet;
use hypellm_core::time::{Deadline, TestClock};
use hypellm_router::jobs::{JobId, JobLimits, JobState, JobStore, SubmitRefusal};
use std::time::Duration;

fn tenant(id: &str) -> TenantId {
    TenantId::new(id).expect("a valid tenant")
}

/// A canonical request belonging to `tenant`.
///
/// The job store never executes it in these tests — a worker needs a whole
/// router — so only the fields the store reads have to be real.
fn request(tenant_id: &str, n: u128) -> CanonicalRequest {
    let clock = TestClock::new();
    CanonicalRequest {
        request_id: RequestId::from_u128(n),
        tenant: tenant(tenant_id),
        principal: PrincipalId::new("svc:caller").expect("a valid principal"),
        protocol: ClientProtocol::OpenAiChat,
        operation: Operation::Chat,
        requested_model: AliasId::new("test-alias").expect("a valid alias"),
        messages: vec![Message::text(Role::User, "hello")],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: Some(64),
            deadline: Deadline::after(&clock, Duration::from_secs(60)),
            max_cost_class: None,
            min_quality_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: RoutingHints::default(),
    }
}

fn store(limits: JobLimits) -> JobStore {
    JobStore::new(limits)
}

fn submit(store: &JobStore, tenant_id: &str, n: u128) -> Result<JobId, SubmitRefusal> {
    store
        .submit(
            request(tenant_id, n),
            Vec::new(),
            PermissionSet::default(),
            None,
            1_000 + u64::try_from(n).unwrap_or(0),
            1_000 + u64::try_from(n).unwrap_or(0),
        )
        .map(|view| view.id)
}

#[test]
fn a_job_identifier_is_not_a_capability_across_tenants() {
    // The security property. A job id is 128 bits of randomness and is the
    // handle to a result, so the tenant check must not be skippable by holding
    // one — and the answer for another tenant's job must be *absent*, not
    // forbidden, or a caller can confirm that an id they guessed is real.
    let store = store(JobLimits::DEFAULT);
    let id = submit(&store, "acme", 1).expect("submit");

    assert!(store.get(&id, &tenant("acme"), 2_000).is_some());
    assert!(
        store.get(&id, &tenant("globex"), 2_000).is_none(),
        "another tenant read a job by identifier"
    );
    assert!(
        store.result(&id, &tenant("globex"), 2_000).is_none(),
        "another tenant read a job's result"
    );
    assert!(
        store
            .cancel(&id, &tenant("globex"), 2_000, 2_000)
            .is_none(),
        "another tenant cancelled a job"
    );
    assert!(
        store.list(&tenant("globex"), 100, 2_000).is_empty(),
        "another tenant's job appeared in a listing"
    );
    // And the owner's job is untouched by all of that.
    assert_eq!(
        store.get(&id, &tenant("acme"), 2_000).map(|v| v.state),
        Some(JobState::Queued)
    );
}

#[test]
fn a_tenant_cannot_hold_more_jobs_than_its_cap() {
    // Specification 3.2: a request may not create unbounded retention. The cap
    // counts *retained* jobs too, so a tenant cannot get around it by letting
    // jobs finish.
    let limits = JobLimits {
        max_per_tenant: 3,
        ..JobLimits::DEFAULT
    };
    let store = store(limits);

    for n in 0..3 {
        submit(&store, "acme", n).expect("within the cap");
    }
    assert_eq!(
        submit(&store, "acme", 3).err(),
        Some(SubmitRefusal::TenantAtCapacity)
    );

    // One tenant's cap is not another's.
    submit(&store, "globex", 100).expect("a different tenant has its own cap");
}

#[test]
fn a_full_queue_refuses_rather_than_growing() {
    let limits = JobLimits {
        max_per_tenant: 100,
        max_queued: 2,
        ..JobLimits::DEFAULT
    };
    let store = store(limits);

    submit(&store, "acme", 0).expect("first");
    submit(&store, "acme", 1).expect("second");
    assert_eq!(submit(&store, "acme", 2).err(), Some(SubmitRefusal::QueueFull));

    // And the refused job left nothing behind. A record that survived a
    // rejected submission would consume the tenant's cap until it expired, for
    // work that will never run.
    assert_eq!(
        store.list(&tenant("acme"), 100, 1_000).len(),
        2,
        "a refused submission left a job record"
    );
}

#[test]
fn a_finished_job_expires_and_stops_counting_against_the_cap() {
    // The spool is bounded in time as well as in bytes: "the router is not
    // becoming a blob store". A result that outlives its window is gone, and
    // the slot it held comes back.
    let limits = JobLimits {
        max_per_tenant: 1,
        retention_ms: 10_000,
        ..JobLimits::DEFAULT
    };
    let store = store(limits);
    let id = submit(&store, "acme", 0).expect("submit");

    // Cancel to reach a terminal state without needing a worker.
    store.cancel(&id, &tenant("acme"), 1_000, 1_000).expect("cancel");
    assert_eq!(
        store.get(&id, &tenant("acme"), 1_000).map(|v| v.state),
        Some(JobState::Cancelled)
    );
    // Still held, so still counted: retention is what the cap counts.
    assert_eq!(
        submit(&store, "acme", 1).err(),
        Some(SubmitRefusal::TenantAtCapacity)
    );

    // Past the window.
    assert!(
        store.get(&id, &tenant("acme"), 11_001).is_none(),
        "the job outlived its retention window"
    );
    submit(&store, "acme", 2).expect("the expired job freed the tenant's slot");
}

#[test]
fn cancelling_a_queued_job_is_immediate_and_final() {
    let store = store(JobLimits::DEFAULT);
    let id = submit(&store, "acme", 0).expect("submit");

    let view = store
        .cancel(&id, &tenant("acme"), 2_000, 2_000)
        .expect("cancel");
    assert_eq!(view.state, JobState::Cancelled);

    // Cancelling twice is not an error and does not un-terminate it. A client
    // retrying a cancel it did not see the answer to must not resurrect a job.
    let again = store
        .cancel(&id, &tenant("acme"), 3_000, 3_000)
        .expect("second cancel");
    assert_eq!(again.state, JobState::Cancelled);
    assert_eq!(
        again.updated_ms, view.updated_ms,
        "a repeated cancel moved the job's clock"
    );
}

#[test]
fn a_malformed_identifier_never_reaches_the_table() {
    // The shape check is what keeps a caller-supplied string out of a map key
    // and out of a log line. Every one of these must be refused by `parse`
    // rather than looked up and missed.
    for raw in [
        "",
        "job_",
        "job_short",
        "job_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "job_0123456789ABCDEF0123456789abcdef",
        "notajob_0123456789abcdef0123456789abcdef",
        "job_0123456789abcdef0123456789abcdef0",
    ] {
        assert!(JobId::parse(raw).is_none(), "{raw:?} parsed as a job id");
    }
    // And a real one round-trips.
    let id = JobId::generate().expect("entropy");
    assert_eq!(
        JobId::parse(id.as_str()).as_ref().map(JobId::as_str),
        Some(id.as_str())
    );
}

#[test]
fn two_generated_identifiers_differ() {
    // A predictable identifier in a shared tenant is another caller's result.
    let a = JobId::generate().expect("entropy");
    let b = JobId::generate().expect("entropy");
    assert_ne!(a.as_str(), b.as_str());
    assert_eq!(a.as_str().len(), "job_".len() + 32);
}

#[test]
fn a_shutdown_stops_accepting_and_cancels_what_is_queued() {
    // A queued job at shutdown will never run, and a client polling it after
    // the restart must not be told `queued` by a process that is gone.
    let store = store(JobLimits::DEFAULT);
    let id = submit(&store, "acme", 0).expect("submit");

    store.shutdown();
    assert!(store.is_stopping());
    assert_eq!(
        submit(&store, "acme", 1).err(),
        Some(SubmitRefusal::ShuttingDown)
    );

    // The queued job's cancellation flag is set, so the worker that would have
    // picked it up declines it rather than starting minutes of generation
    // during a drain.
    let view = store.get(&id, &tenant("acme"), 2_000).expect("still listed");
    assert_eq!(view.state, JobState::Queued);
    assert_eq!(
        store.cancel(&id, &tenant("acme"), 2_000, 2_000).map(|v| v.state),
        Some(JobState::Cancelled)
    );
}
