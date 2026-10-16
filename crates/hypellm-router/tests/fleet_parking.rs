//! Parking (specification 26.10): a request whose model has to be started for
//! it waits for that, rather than failing because demand batching has not yet
//! reached its trigger.
//!
//! Real sockets, a real router, the simulated agent, and the system clock — so
//! the waits here are real, and kept to a second or two. Each test states the
//! property it would catch the absence of; each was watched failing with
//! parking switched off.

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

const KEY: &[u8] = b"a-fleet-parking-test-key-0123456789";

const COMPLETION: &str = r#"{"id":"c1","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#;

fn socket(name: &str) -> String {
    format!("/tmp/hypellm-park-{name}-{}.sock", std::process::id())
}

/// One cold, router-managed model behind alias `coder`, and optionally a warm
/// unmanaged target ranked ahead of it.
fn config(port: u16, socket: &str, settings: &str, policy: &str, warm: bool) -> String {
    let (warm_records, targets) = if warm {
        (
            format!(
                "provider id=warm family=openai scheme=http host=127.0.0.1 port={port} \
                 base_path=/v1 egress=local\n\
                 target id=warm:m provider=warm model=model-warm local=true cost=0 \
                 operations=chat capabilities=chat context=100000 max_output=8192 concurrency=1\n"
            ),
            "warm:m,cold:m",
        )
    } else {
        (String::new(), "cold:m")
    };
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=20000 retry_budget_ms=20000 \\
         max_attempts=3 fleet_enabled=true {settings}
tenant id=acme
provider id=cold family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=cold:m provider=cold model=model-cold local=true cost=1 \\
       operations=chat capabilities=chat context=100000 max_output=8192 concurrency=8
{warm_records}alias id=coder capability=chat targets={targets}
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
fleet_agent id=local socket=\"{socket}\" observation_interval_ms=1000 \\
    observation_max_age_ms=600000 request_timeout_ms=5000
host id=h1 agent=local arch=x86_64
accelerator host=h1 id=gpu0 kind=cuda memory_bytes=17179869184
deployment id=d-cold target=cold:m accelerator=gpu0 memory_bytes=8589934592 \\
    start_ms=1000 stop_ms=500 drain_ms=500 probe_ms=500 min_resident_ms=0 \\
    autostart=true readiness=http_ok
fleet_policy scope=fleet {policy}
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
    fn start(upstream: FakeUpstream, text: &str, socket: &str) -> Self {
        let router = router_with_config(&upstream, text);
        let digest = router.state.config().fleet.digest();
        let agent = SimulatedAgent::start(
            socket,
            AgentScript::empty(digest, KEY)
                .with_deployment("d-cold", Behaviour::ReadyAfter(1))
                .with_state("d-cold", "stopped"),
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

    fn activations(&self) -> usize {
        self.agent
            .verbs()
            .iter()
            .filter(|v| v.starts_with("ACTIVATE "))
            .count()
    }

    /// Every admission reservation taken has been released, nothing is
    /// parked, and the batching queue is empty.
    fn assert_nothing_held(&self) {
        let state = &self.router.state;
        let (acquired, released) = state.admission.global().conservation();
        assert_eq!(acquired, released, "an admission reservation leaked");
        assert_eq!(
            state
                .parked_requests
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a parked request was never counted out"
        );
        let fleet = state.fleet().expect("fleet attached");
        assert_eq!(fleet.parked_total(), 0, "the batching queue kept a waiter");
        let (granted, finished) = fleet.ledger().accounting();
        assert_eq!(granted, finished, "an activation lease leaked");
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

fn chat(address: SocketAddr, key: &str) -> (u16, String) {
    let body = r#"{"model":"coder","messages":[{"role":"user","content":"hi"}]}"#;
    let raw = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
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

#[test]
fn a_lone_request_parks_until_its_wait_triggers_the_start_and_is_then_served() {
    // Batching wants three requests or a second and a half. One request
    // arrives. Without parking it is refused at once — the queue said "wait"
    // and nothing waited — and the model never starts, because the request
    // that would have aged into the trigger left.
    let socket = socket("lone");
    let upstream = FakeUpstream::start(CannedResponse::json(200, COMPLETION));
    let text = config(
        upstream.address.port(),
        &socket,
        "",
        "activation_min_demand=3 activation_max_wait_ms=1500",
        false,
    );
    let harness = Harness::start(upstream, &text, &socket);
    let key = harness.router.api_key.clone();

    let started = Instant::now();
    let (status, body) = chat(harness.address, &key);
    assert_eq!(status, 200, "{body}");
    assert!(
        started.elapsed() >= Duration::from_millis(1_400),
        "served before the batching wait could have elapsed"
    );
    assert_eq!(harness.activations(), 1);
    assert_eq!(harness.upstream.served(), 1);
    assert_nothing_held_eventually(&harness);
}

#[test]
fn two_requests_for_a_cold_model_cost_one_start_and_both_are_served() {
    // The first parks; the second brings demand to the trigger and pays for
    // the start; the parked one rides it. One swap, two answers.
    let socket = socket("pair");
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(200, COMPLETION),
        CannedResponse::json(200, COMPLETION),
    ]);
    let text = config(
        upstream.address.port(),
        &socket,
        "",
        "activation_min_demand=2 activation_max_wait_ms=60000",
        false,
    );
    let harness = Harness::start(upstream, &text, &socket);
    let key = harness.router.api_key.clone();

    let address = harness.address;
    let first_key = key.clone();
    let first = std::thread::spawn(move || chat(address, &first_key));
    // Long enough for the first to have parked.
    std::thread::sleep(Duration::from_millis(400));
    let (second_status, second_body) = chat(harness.address, &key);
    let (first_status, first_body) = first.join().unwrap();

    assert_eq!(first_status, 200, "{first_body}");
    assert_eq!(second_status, 200, "{second_body}");
    assert_eq!(harness.activations(), 1, "{:?}", harness.agent.verbs());
    assert_eq!(harness.upstream.served(), 2);
    assert_nothing_held_eventually(&harness);
}

#[test]
fn a_parked_request_gives_up_at_its_deadline_and_holds_nothing_afterwards() {
    // Demand never reaches the trigger inside the request's two seconds. The
    // request ends with an error, the model is not started on its behalf after
    // it has gone, and every count it took is returned.
    let socket = socket("deadline");
    let upstream = FakeUpstream::start(CannedResponse::json(200, COMPLETION));
    // A quick model and no headroom, so a start would fit the two seconds
    // and the request has a reason to park at all.
    let text = config(
        upstream.address.port(),
        &socket,
        "activation_effort_headroom_ms=0",
        "activation_min_demand=5 activation_max_wait_ms=600000",
        false,
    )
    .replace("default_deadline_ms=20000", "default_deadline_ms=2000")
    .replace("start_ms=1000", "start_ms=100")
    .replace("probe_ms=500", "probe_ms=100");
    let harness = Harness::start(upstream, &text, &socket);
    let key = harness.router.api_key.clone();

    let started = Instant::now();
    let (status, body) = chat(harness.address, &key);
    assert_ne!(status, 200, "{body}");
    assert!(started.elapsed() >= Duration::from_millis(1_500), "it did not park");
    assert!(started.elapsed() < Duration::from_secs(10), "it outlived its deadline");
    assert!(!body.contains("h1") && !body.contains("d-cold"), "{body}");
    assert_eq!(harness.activations(), 0);
    assert_eq!(harness.upstream.served(), 0);
    assert_nothing_held_eventually(&harness);
}

#[test]
fn with_no_room_to_park_a_request_fails_at_once_as_it_did_before() {
    let socket = socket("cap");
    let upstream = FakeUpstream::start(CannedResponse::json(200, COMPLETION));
    let text = config(
        upstream.address.port(),
        &socket,
        "max_parked_requests=0",
        "activation_min_demand=5 activation_max_wait_ms=600000",
        false,
    );
    let harness = Harness::start(upstream, &text, &socket);
    let key = harness.router.api_key.clone();

    let started = Instant::now();
    let (status, _) = chat(harness.address, &key);
    assert_ne!(status, 200);
    assert!(started.elapsed() < Duration::from_millis(1_000), "it parked past the cap");
    assert_eq!(harness.activations(), 0);
    assert_nothing_held_eventually(&harness);
}

#[test]
fn a_parked_request_is_served_by_a_warm_target_that_frees_up_and_starts_nothing() {
    // A warm target with one slot is busy for a second and a half; the cold
    // model would need five requests or ten minutes to justify a start. The
    // second request parks, and when the warm slot frees it is simply taken —
    // no swap is paid for a request a running model could serve.
    let socket = socket("warm");
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(200, COMPLETION).after(Duration::from_millis(1_500)),
        CannedResponse::json(200, COMPLETION),
    ]);
    let text = config(
        upstream.address.port(),
        &socket,
        "queue_timeout_ms=100",
        "activation_min_demand=5 activation_max_wait_ms=600000",
        true,
    );
    let harness = Harness::start(upstream, &text, &socket);
    let key = harness.router.api_key.clone();

    let address = harness.address;
    let first_key = key.clone();
    let first = std::thread::spawn(move || chat(address, &first_key));
    std::thread::sleep(Duration::from_millis(300));
    let (status, body) = chat(harness.address, &key);
    let (first_status, _) = first.join().unwrap();

    assert_eq!(first_status, 200);
    assert_eq!(status, 200, "{body}");
    assert_eq!(harness.activations(), 0, "{:?}", harness.agent.verbs());
    assert_eq!(harness.upstream.served(), 2);
    let sent = harness.upstream.last_body().unwrap_or_default();
    assert!(sent.contains("model-warm"), "{sent}");
    assert_nothing_held_eventually(&harness);
}

/// Accounting settles a moment after the response is written, on the worker
/// that wrote it.
fn assert_nothing_held_eventually(harness: &Harness) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.assert_nothing_held();
        }));
        match result {
            Ok(()) => return,
            Err(panic) if Instant::now() >= deadline => std::panic::resume_unwind(panic),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}
