//! Churn-aware scheduling (specification 26.11), end to end: real sockets, a
//! real router, the real job worker, and the simulated agent.
//!
//! The fixture is the adversarial one for a one-slot host: two models that
//! cannot be resident together, and work for them submitted strictly
//! alternately. Arrival order loads a model for every job. Each test states
//! the property it would catch the absence of, and runs the same fixture with
//! reordering switched off as the baseline it has to beat.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::time::Clock;
use hypellm_net::fleet_sim::{AgentScript, Behaviour, SimulatedAgent};
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const KEY: &[u8] = b"a-fleet-schedule-test-key-0123456789";

const COMPLETION: &str = r#"{"id":"c1","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#;

fn socket(name: &str) -> String {
    format!("/tmp/hypellm-sched-{name}-{}.sock", std::process::id())
}

/// Two chat models, each 12 GiB, on one 16 GiB accelerator: only one fits.
///
/// Both are cheap to evict (`retention_weight` at its floor, no margin, no
/// dwell, no cooldown), so nothing but the scheduler stands between an
/// alternating stream and a swap per job. Both serve the same capability, so
/// the batching queue alone cannot tell them apart.
fn config(port: u16, socket: &str, reorder_ms: u64) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=60000 retry_budget_ms=60000 \\
         max_attempts=3 fleet_enabled=true
tenant id=acme
provider id=pa family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
provider id=pb family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=pa:m provider=pa model=model-a local=true cost=1 \\
       operations=chat capabilities=chat context=100000 max_output=8192 concurrency=8
target id=pb:m provider=pb model=model-b local=true cost=1 \\
       operations=chat capabilities=chat context=100000 max_output=8192 concurrency=8
alias id=alpha capability=chat targets=pa:m
alias id=beta capability=chat targets=pb:m
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
fleet_agent id=local socket=\"{socket}\" observation_interval_ms=1000 \\
    observation_max_age_ms=600000 request_timeout_ms=5000
host id=h1 agent=local arch=x86_64
accelerator host=h1 id=gpu0 kind=cuda memory_bytes=17179869184
deployment id=d-a target=pa:m accelerator=gpu0 memory_bytes=12884901888 \\
    start_ms=1000 stop_ms=500 drain_ms=500 probe_ms=500 min_resident_ms=0 \\
    autostart=true readiness=http_ok retention_weight=-100000
deployment id=d-b target=pb:m accelerator=gpu0 memory_bytes=12884901888 \\
    start_ms=1000 stop_ms=500 drain_ms=500 probe_ms=500 min_resident_ms=0 \\
    autostart=true readiness=http_ok retention_weight=-100000
fleet_policy scope=fleet activation_min_demand=1 activation_max_wait_ms=0 \\
    reactivation_cooldown_ms=0 max_activations_per_hour=200 eviction_margin_permille=0 \\
    idle_stop_ms=0 max_reorder_wait_ms={reorder_ms}
"
    )
}

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
    upstream: FakeUpstream,
    agent: SimulatedAgent,
}

impl Harness {
    fn start(reorder_ms: u64, name: &str) -> Self {
        let socket = socket(name);
        let upstream = FakeUpstream::start(CannedResponse::json(200, COMPLETION));
        let text = config(upstream.address.port(), &socket, reorder_ms);
        let router = router_with_config(&upstream, &text);
        let digest = router.state.config().fleet.digest();
        let agent = SimulatedAgent::start(
            &socket,
            AgentScript::empty(digest, KEY)
                .with_deployment("d-a", Behaviour::ReadyAfter(1))
                .with_deployment("d-b", Behaviour::ReadyAfter(1))
                .with_state("d-a", "stopped")
                .with_state("d-b", "stopped"),
        );
        hypellm_router::testing::attach_fleet(&router, KEY);
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = server.shutdown_handle();
        let handler = Arc::new(InferenceHandler::new(Arc::clone(&router.state)));
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
            router,
            upstream,
            agent,
        }
    }

    /// Model loads the agent was asked for, in order.
    fn loads(&self) -> Vec<String> {
        self.agent
            .verbs()
            .iter()
            .filter(|v| v.starts_with("ACTIVATE "))
            .map(|v| v.split_whitespace().nth(1).unwrap_or_default().to_owned())
            .collect()
    }

    fn submit(&self, alias: &str) -> String {
        let body = format!(r#"{{"model":"{alias}","messages":[{{"role":"user","content":"hi"}}]}}"#);
        let (status, text) = request(self.address, &self.router.api_key, "POST", "/v1/jobs", &body);
        assert_eq!(status, 202, "{text}");
        text.split("\"job_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a job id")
            .to_owned()
    }

    fn state_of(&self, job: &str) -> String {
        let (_, text) = request(self.address, &self.router.api_key, "GET", &format!("/v1/jobs/{job}"), "");
        text.split("\"state\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_owned()
    }

    /// Run one worker until every job is terminal, and return their states in
    /// submission order and the order the worker finished them in.
    fn run(&self, jobs: &[String]) -> Vec<String> {
        let state = Arc::clone(&self.router.state);
        let store = state.jobs().expect("the harness enables jobs").clone();
        let worker = std::thread::spawn(move || hypellm_router::jobs::worker_loop(&state));
        let deadline = Instant::now() + Duration::from_secs(60);
        let states = loop {
            let states: Vec<String> = jobs.iter().map(|j| self.state_of(j)).collect();
            if states.iter().all(|s| s == "succeeded" || s == "failed" || s == "cancelled") {
                break states;
            }
            assert!(Instant::now() < deadline, "jobs did not finish: {states:?}");
            std::thread::sleep(Duration::from_millis(50));
        };
        store.shutdown();
        let _ = worker.join();
        states
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.agent.stop();
    }
}

fn request(address: SocketAddr, key: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
         Connection: close\r\nAuthorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, text)
}

const ALTERNATING: [&str; 6] = ["alpha", "beta", "alpha", "beta", "alpha", "beta"];

#[test]
fn alternating_jobs_for_two_models_on_one_slot_load_each_model_once() {
    // With reordering, the worker takes the three `alpha` jobs while `alpha` is
    // loaded and only then loads `beta`: two loads for six jobs. Without it,
    // every job swaps — the baseline below proves the fixture really does
    // force that, so the reduction is the scheduler's and not the fixture's.
    let baseline = Harness::start(0, "fifo");
    let jobs: Vec<String> = ALTERNATING.iter().map(|a| baseline.submit(a)).collect();
    let states = baseline.run(&jobs);
    assert!(states.iter().all(|s| s == "succeeded"), "{states:?}");
    let fifo = baseline.loads();
    drop(baseline);

    let scheduled = Harness::start(120_000, "ordered");
    let jobs: Vec<String> = ALTERNATING.iter().map(|a| scheduled.submit(a)).collect();
    let states = scheduled.run(&jobs);
    assert!(states.iter().all(|s| s == "succeeded"), "{states:?}");
    assert_eq!(scheduled.upstream.served(), 6);
    let loads = scheduled.loads();

    assert_eq!(fifo.len(), 6, "the baseline must swap on every job: {fifo:?}");
    assert_eq!(loads, vec!["d-a", "d-b"], "one load per model: {loads:?}");
}

/// Load `alpha` with a chat request, then queue one `beta` job, let it age by `age`, queue three
/// more `alpha` jobs, and run them all. Returns the loads.
fn old_cold_job_behind_warm_work(reorder_ms: u64, name: &str, age: Duration) -> Vec<String> {
    let harness = Harness::start(reorder_ms, name);
    // Warmed by an interactive request, so the job store's one worker run —
    // which ends by stopping the store — is the one under test.
    let body = r#"{"model":"alpha","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, text) = request(
        harness.address,
        &harness.router.api_key,
        "POST",
        "/v1/chat/completions",
        body,
    );
    assert_eq!(status, 200, "{text}");

    let mut jobs = vec![harness.submit("beta")];
    std::thread::sleep(age);
    for _ in 0..3 {
        jobs.push(harness.submit("alpha"));
    }
    let states = harness.run(&jobs);
    assert!(states.iter().all(|s| s == "succeeded"), "{states:?}");
    harness.loads()
}

#[test]
fn a_job_past_the_reordering_bound_is_not_held_behind_warm_work() {
    // The adversarial arrangement for the bound: the old job is the lone cold
    // one, and everything behind it is for the model already loaded — exactly
    // what reordering prefers. Inside the bound the warm work goes first and
    // `beta` is loaded last; past it, `beta` goes first even though that costs
    // a swap back to `alpha` afterwards.
    let inside = old_cold_job_behind_warm_work(120_000, "inside", Duration::ZERO);
    assert_eq!(inside, vec!["d-a", "d-b"], "warm work first inside the bound: {inside:?}");

    let past = old_cold_job_behind_warm_work(5_000, "past", Duration::from_millis(5_200));
    assert_eq!(past, vec!["d-a", "d-b", "d-a"], "the old job first past the bound: {past:?}");
}

fn plan_for(harness: &Harness, target: &str) -> hypellm_fleet::plan::Plan {
    let fleet = harness.router.state.fleet().expect("fleet attached");
    let context = hypellm_fleet::plan::PlanContext {
        now_ms: fleet.now_ms(),
        deadline_remaining_ms: 600_000,
        effort_multiplier: 1,
        effort_headroom_ms: 1_000,
        may_activate: true,
        may_fetch: false,
        capability: Some(hypellm_core::target::Capability::Chat),
        priority_bonus: 0,
    };
    let target = hypellm_core::ids::TargetId::new(target).unwrap();
    match hypellm_fleet::plan::plan(&fleet.snapshot(), &fleet.demand_snapshot(), &target, &context) {
        hypellm_fleet::plan::PlanOutcome::Plan(plan) => *plan,
        other => panic!("expected a plan for {target}, got {other:?}"),
    }
}

#[test]
fn a_parked_swap_waits_while_the_loaded_model_is_working_and_goes_when_it_is_quiet() {
    // The hysteresis against ping-pong. `alpha` is loaded and serving; work
    // parks for `beta`, which can only be loaded by stopping `alpha`. While
    // `alpha` has a request in flight the swap is deferred — stopping work to
    // start work is what thrash is — and the moment it goes quiet the swap is
    // allowed. Before this, the parked request paid for the swap at once.
    use hypellm_core::target::Capability;
    use hypellm_fleet::governance::QueueAdmission;

    let harness = Harness::start(120_000, "warm");
    let body = r#"{"model":"alpha","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, text) = request(harness.address, &harness.router.api_key, "POST", "/v1/chat/completions", body);
    assert_eq!(status, 200, "{text}");
    let fleet = harness.router.state.fleet().expect("fleet attached");

    let alpha = hypellm_core::ids::TargetId::new("pa:m").unwrap();
    let hold = fleet.enter_dispatch(&alpha).unwrap().expect("alpha is a fleet target");
    let beta = hypellm_core::ids::AliasId::new("beta").unwrap();
    assert!(fleet.park(Capability::Chat));
    fleet.park_alias(&beta);

    let swap = plan_for(&harness, "pb:m");
    assert!(swap.evicts(), "the fixture must force a swap");
    assert!(
        matches!(fleet.poll_queue(Capability::Chat, &swap), QueueAdmission::Wait { .. }),
        "the swap went ahead while alpha was serving"
    );

    fleet.leave_dispatch(hold);
    assert_eq!(fleet.poll_queue(Capability::Chat, &swap), QueueAdmission::Activate);

    fleet.unpark_alias(&beta);
    fleet.unpark(Capability::Chat);
}

#[test]
fn the_model_more_requests_wait_for_is_loaded_first_and_the_fleet_view_says_so() {
    // An empty one-slot host, one request parked for `alpha` first and three
    // for `beta` after it. Arrival order would load `alpha`; the scheduler
    // loads `beta` and refuses `alpha` until then.
    use hypellm_core::target::Capability;
    use hypellm_fleet::governance::QueueAdmission;

    let harness = Harness::start(120_000, "ranked");
    let fleet = harness.router.state.fleet().expect("fleet attached");
    let alpha = hypellm_core::ids::AliasId::new("alpha").unwrap();
    let beta = hypellm_core::ids::AliasId::new("beta").unwrap();
    assert!(fleet.park(Capability::Chat));
    fleet.park_alias(&alpha);
    std::thread::sleep(Duration::from_millis(20));
    for _ in 0..3 {
        assert!(fleet.park(Capability::Chat));
        fleet.park_alias(&beta);
    }

    let next = fleet.next_activations();
    assert_eq!(next.len(), 1, "{next:?}");
    assert_eq!(next[0].deployment.as_str(), "d-b");
    assert_eq!(next[0].reason, "ranked");
    assert_eq!(next[0].waiting, 3);

    let load_alpha = plan_for(&harness, "pa:m");
    let load_beta = plan_for(&harness, "pb:m");
    assert!(
        matches!(fleet.poll_queue(Capability::Chat, &load_alpha), QueueAdmission::Wait { .. }),
        "alpha was loaded ahead of three times the demand"
    );
    assert_eq!(fleet.poll_queue(Capability::Chat, &load_beta), QueueAdmission::Activate);

    fleet.unpark_alias(&alpha);
    for _ in 0..3 {
        fleet.unpark_alias(&beta);
        fleet.unpark(Capability::Chat);
    }
    fleet.unpark(Capability::Chat);
}
