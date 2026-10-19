//! Who goes next in the job queue (orchestration §11.9), end to end: a real
//! router, the real job workers, one slot, and a fake upstream that holds it.
//!
//! Each fixture is adversarial for the property it names. The job that should
//! go first is submitted *last*, so submission order — what the queue did
//! before classes and share existed — gets every one of these wrong.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::admission::PriorityClass;
use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, Message, Operation, ReasoningEffort, RequestLimits, Role,
    RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::ids::{AliasId, PrincipalId, RequestId, TenantId};
use hypellm_core::rbac::PermissionSet;
use hypellm_core::time::Deadline;
use hypellm_router::jobs::{JobId, JobState, JobStore, SubmitTerms};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use std::sync::Arc;
use std::time::{Duration, Instant};

const COMPLETION: &str = r#"{"id":"c1","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#;

/// One target with one slot: every job after the first waits for it.
fn config(port: u16) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=60000 retry_budget_ms=60000 max_attempts=1
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat context=100000 max_output=8192 concurrency=1
alias id=slow targets=local:model
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
"
    )
}

/// The upstream: the first exchange holds the slot for `hold`, the rest are
/// quick.
fn upstream(hold: Duration) -> FakeUpstream {
    FakeUpstream::start_sequence(vec![
        CannedResponse::json(200, COMPLETION).after(hold),
        CannedResponse::json(200, COMPLETION).after(Duration::from_millis(30)),
    ])
}

/// A chat request from `principal`, whose only message is `label`, so the
/// upstream's log says which job reached it when.
fn request(router: &TestRouter, principal: &str, label: &str, n: u128) -> CanonicalRequest {
    CanonicalRequest {
        request_id: RequestId::from_u128(n),
        tenant: TenantId::new("acme").unwrap(),
        principal: PrincipalId::new(principal).unwrap(),
        protocol: ClientProtocol::OpenAiChat,
        operation: Operation::Chat,
        requested_model: AliasId::new("slow").unwrap(),
        messages: vec![Message::text(Role::User, label)],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: Some(64),
            deadline: Deadline::after(router.state.clock.as_ref(), Duration::from_secs(60)),
            max_cost_class: None,
            min_quality_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: RoutingHints::default(),
    }
}

struct Harness {
    router: TestRouter,
    upstream: FakeUpstream,
    workers: Vec<std::thread::JoinHandle<()>>,
    next: u128,
}

impl Harness {
    fn start(hold: Duration, workers: usize) -> Self {
        let upstream = upstream(hold);
        let router = router_with_config(&upstream, &config(upstream.address.port()));
        let workers = (0..workers)
            .map(|_| {
                let state = Arc::clone(&router.state);
                std::thread::spawn(move || hypellm_router::jobs::worker_loop(&state))
            })
            .collect();
        Self {
            router,
            upstream,
            workers,
            next: 1,
        }
    }

    fn jobs(&self) -> &JobStore {
        self.router.state.jobs().expect("the test router runs jobs")
    }

    fn submit(&mut self, principal: &str, label: &str, class: PriorityClass) -> JobId {
        self.next += 1;
        let clock = self.router.state.clock.as_ref();
        self.jobs()
            .submit(
                request(&self.router, principal, label, self.next),
                Vec::new(),
                PermissionSet::default(),
                None,
                SubmitTerms {
                    class,
                    ..SubmitTerms::default()
                },
                clock.wall_millis(),
                clock.now_millis(),
            )
            .expect("submitted")
            .id
    }

    fn state_of(&self, id: &JobId) -> JobState {
        let tenant = TenantId::new("acme").unwrap();
        self.jobs()
            .get(id, &tenant, self.router.state.clock.now_millis())
            .expect("job")
            .state
    }

    fn wait_for(&self, id: &JobId, want: impl Fn(JobState) -> bool) {
        let until = Instant::now() + Duration::from_secs(30);
        while !want(self.state_of(id)) {
            assert!(Instant::now() < until, "job {} stuck in {:?}", id.as_str(), self.state_of(id));
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Which labelled job reached the upstream, in order.
    fn order(&self, labels: &[&str]) -> Vec<String> {
        self.upstream
            .received()
            .iter()
            .map(|raw| {
                let text = String::from_utf8_lossy(raw);
                labels
                    .iter()
                    .find(|label| text.contains(&format!("\"{label}\"")))
                    .map_or_else(|| "?".to_owned(), |label| (*label).to_owned())
            })
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(jobs) = self.router.state.jobs() {
            jobs.shutdown();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[test]
fn an_interactive_job_starts_before_every_batch_job_waiting_for_its_slot() {
    let mut h = Harness::start(Duration::from_millis(600), 3);
    let blocker = h.submit("svc:first", "blocker", PriorityClass::Standard);
    h.wait_for(&blocker, |s| s == JobState::Running);

    let batch: Vec<JobId> = (0..4)
        .map(|i| h.submit("svc:bulk", &format!("batch-{i}"), PriorityClass::Batch))
        .collect();
    let interactive = h.submit("svc:human", "interactive", PriorityClass::Interactive);

    for id in batch.iter().chain([&blocker, &interactive]) {
        h.wait_for(id, JobState::is_terminal);
        assert_eq!(h.state_of(id), JobState::Succeeded, "{}", id.as_str());
    }
    let order = h.order(&["blocker", "interactive", "batch-0", "batch-1", "batch-2", "batch-3"]);
    assert_eq!(order[0], "blocker");
    assert_eq!(
        order[1], "interactive",
        "the slot went to {} though an interactive job was waiting: {order:?}",
        order[1]
    );
}

#[test]
fn a_principals_one_job_waits_for_at_most_one_job_of_another_principals_backlog() {
    let mut h = Harness::start(Duration::from_millis(600), 3);
    let blocker = h.submit("svc:first", "blocker", PriorityClass::Standard);
    h.wait_for(&blocker, |s| s == JobState::Running);

    // The backlog is submitted first and is the same class: submission order
    // would put the single job fifth.
    let backlog: Vec<JobId> = (0..4)
        .map(|i| h.submit("svc:bulk", &format!("bulk-{i}"), PriorityClass::Standard))
        .collect();
    let single = h.submit("svc:single", "single", PriorityClass::Standard);

    for id in backlog.iter().chain([&blocker, &single]) {
        h.wait_for(id, JobState::is_terminal);
    }
    let order = h.order(&["blocker", "single", "bulk-0", "bulk-1", "bulk-2", "bulk-3"]);
    let position = order.iter().position(|l| l == "single").expect("single ran");
    assert!(
        position <= 2,
        "the single job waited behind {} of the backlog: {order:?}",
        position - 1
    );
    // And the backlog kept its own submission order.
    let bulk: Vec<&String> = order.iter().filter(|l| l.starts_with("bulk")).collect();
    assert_eq!(bulk, ["bulk-0", "bulk-1", "bulk-2", "bulk-3"]);
}

#[test]
fn a_job_waiting_for_a_slot_takes_it_when_it_frees_and_never_spends_an_attempt() {
    // The slot is held for 3.5 s — fourteen ticks, and long enough that a job
    // backing off from its first refusal (1 s, 2 s, 4 s) would not try again
    // until seven seconds in. A job that waits in its place is tried as the
    // blocker leaves.
    let mut h = Harness::start(Duration::from_millis(3_500), 2);
    let blocker = h.submit("svc:first", "blocker", PriorityClass::Standard);
    h.wait_for(&blocker, |s| s == JobState::Running);
    let started = Instant::now();
    let next = h.submit("svc:second", "next", PriorityClass::Standard);

    // While the slot is held the job is queued, and says why.
    std::thread::sleep(Duration::from_millis(600));
    let tenant = TenantId::new("acme").unwrap();
    let view = h
        .jobs()
        .get(&next, &tenant, h.router.state.clock.now_millis())
        .unwrap();
    assert_eq!(view.state, JobState::Queued);
    assert_eq!(view.waiting_for, Some("slot"));

    h.wait_for(&next, JobState::is_terminal);
    assert_eq!(h.state_of(&next), JobState::Succeeded);
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_millis(4_600),
        "the job took {waited:?} to finish behind a 3.5 s blocker"
    );
}

#[test]
fn a_job_reports_its_class_and_why_it_waits() {
    let mut h = Harness::start(Duration::from_millis(400), 1);
    let blocker = h.submit("svc:first", "blocker", PriorityClass::Standard);
    h.wait_for(&blocker, |s| s == JobState::Running);
    let job = h.submit("svc:bulk", "batch", PriorityClass::Batch);
    let tenant = TenantId::new("acme").unwrap();
    let view = h
        .jobs()
        .get(&job, &tenant, h.router.state.clock.now_millis())
        .unwrap();
    assert_eq!(view.class, PriorityClass::Batch);
    assert!(matches!(view.waiting_for, Some("turn" | "slot")), "{:?}", view.waiting_for);

    h.wait_for(&job, JobState::is_terminal);
    let done = h
        .jobs()
        .get(&job, &tenant, h.router.state.clock.now_millis())
        .unwrap();
    assert_eq!(done.waiting_for, None);
    let body = wire_json::to_string(&hypellm_router::jobs::job_body(&done));
    assert!(body.contains("\"class\":\"batch\""), "{body}");
    assert!(!body.contains("waiting_for"), "{body}");
}

#[test]
fn the_operators_queue_view_lists_running_work_then_class_and_share_order() {
    use hypellm_admin_api::JobQueue;
    let mut h = Harness::start(Duration::from_millis(800), 1);
    let blocker = h.submit("svc:first", "blocker", PriorityClass::Standard);
    h.wait_for(&blocker, |s| s == JobState::Running);
    h.submit("svc:bulk", "bulk-0", PriorityClass::Batch);
    h.submit("svc:bulk", "bulk-1", PriorityClass::Standard);
    h.submit("svc:bulk", "bulk-2", PriorityClass::Standard);
    h.submit("svc:single", "single", PriorityClass::Standard);
    h.submit("svc:human", "human", PriorityClass::Interactive);

    let rows = h.jobs().queue(&TenantId::new("acme").unwrap());
    let seen: Vec<(String, &str, u32)> = rows
        .iter()
        .map(|r| (r.principal.as_str().to_owned(), r.class.as_str(), r.round))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("svc:first".to_owned(), "standard", 0),
            ("svc:human".to_owned(), "interactive", 0),
            ("svc:bulk".to_owned(), "standard", 0),
            ("svc:single".to_owned(), "standard", 0),
            ("svc:bulk".to_owned(), "standard", 1),
            ("svc:bulk".to_owned(), "batch", 0),
        ]
    );
    assert_eq!(rows[0].state, "running");
    assert!(rows[1..].iter().all(|r| r.state == "queued"));
    // Another tenant's view of the same queue is empty.
    assert!(h.jobs().queue(&TenantId::new("globex").unwrap()).is_empty());
}

#[test]
fn a_shutdown_lets_a_running_job_finish_and_cancels_only_what_had_not_started() {
    let mut h = Harness::start(Duration::from_millis(600), 1);
    let running = h.submit("svc:first", "running", PriorityClass::Standard);
    h.wait_for(&running, |s| s == JobState::Running);
    let queued = h.submit("svc:second", "queued", PriorityClass::Standard);
    h.jobs().shutdown();
    h.wait_for(&running, JobState::is_terminal);
    assert_eq!(h.state_of(&running), JobState::Succeeded, "a running job was cut off by the drain");
    let order = h.order(&["running", "queued"]);
    assert_eq!(order, vec!["running"], "a job that had not started ran during the drain");
    let _ = queued;
}
