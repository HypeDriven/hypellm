//! The target liveness probe (`hypellm_router::probe`).
//!
//! The limitation this closes: a target's health was learned only from the
//! requests routed to it, so a slave that died while idle read as healthy
//! until a caller's request found out. The properties:
//!
//! - a target whose `/health` stops answering is excluded within two probe
//!   rounds, without any request being routed to it;
//! - it is routable again after two good rounds;
//! - the probe dials only what the configuration declares, and only the
//!   families that serve a liveness path;
//! - a probe never moves a breaker, and a probed-down target is a filter, not
//!   a penalty;
//! - the loop ends within one probe timeout of shutdown.
//!
//! Loopback only, against an in-process server whose answer can be switched.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::decision::ExclusionReason;
use hypellm_core::event::CanonicalEvent;
use hypellm_core::health::{BreakerState, ProbeState};
use hypellm_core::ids::{AliasId, TargetId};
use hypellm_core::rbac::PermissionSet;
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline;
use hypellm_router::probe;
use hypellm_router::testing::{CannedResponse, FakeUpstream, router_with_config};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const OK_BODY: &str = r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"fine"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;

const HEALTHY: u8 = 0;
const LOADING: u8 = 1;
const SILENT: u8 = 2;

/// A slave whose `/health` answer can be switched, and which serves a chat
/// completion on anything else.
struct Slave {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    health_hits: Arc<AtomicU64>,
    chat_hits: Arc<AtomicU64>,
    stopping: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Slave {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(HEALTHY));
        let health_hits = Arc::new(AtomicU64::new(0));
        let chat_hits = Arc::new(AtomicU64::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let (m, h, c, s) = (
            Arc::clone(&mode),
            Arc::clone(&health_hits),
            Arc::clone(&chat_hits),
            Arc::clone(&stopping),
        );
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut socket) = stream else { break };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buffer = vec![0u8; 64 * 1024];
                let n = socket.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let response = if request.starts_with("GET /health ") {
                    h.fetch_add(1, Ordering::SeqCst);
                    match m.load(Ordering::SeqCst) {
                        HEALTHY => "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\nconnection: close\r\n\r\n{\"status\":\"ok\"}".to_owned(),
                        LOADING => "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
                        _ => {
                            // Accepted and never answered: what a wedged
                            // server looks like from outside.
                            let until = Instant::now() + Duration::from_secs(20);
                            while Instant::now() < until && !s.load(Ordering::SeqCst) {
                                std::thread::sleep(Duration::from_millis(20));
                            }
                            continue;
                        }
                    }
                } else {
                    c.fetch_add(1, Ordering::SeqCst);
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{OK_BODY}",
                        OK_BODY.len()
                    )
                };
                let _ = socket.write_all(response.as_bytes());
                let _ = socket.flush();
            }
        });
        Self {
            address,
            mode,
            health_hits,
            chat_hits,
            stopping,
            handle: Some(handle),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn chats(&self) -> u64 {
        self.chat_hits.load(Ordering::SeqCst)
    }

    fn healths(&self) -> u64 {
        self.health_hits.load(Ordering::SeqCst)
    }
}

impl Drop for Slave {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect_timeout(&self.address, Duration::from_millis(200));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Two llama.cpp slaves behind one alias, `down` ranked first so that it is
/// the one every request would choose while it is up.
fn config(down: u16, up: u16, extra: &str) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3 \
target_probe_interval_ms=5000 target_probe_timeout_ms=1000
tenant id=acme
provider id=down family=llamacpp scheme=http host=127.0.0.1 port={down} base_path=/v1 egress=local
provider id=up family=llamacpp scheme=http host=127.0.0.1 port={up} base_path=/v1 egress=local
target id=down:model provider=down model=test-model local=true \\
       operations=chat streaming=true tools=true json_mode=true context=100000 max_output=8192 concurrency=8
target id=up:model provider=up model=test-model local=true \\
       operations=chat streaming=true tools=true json_mode=true context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=down:model,up:model description=\"two slaves\"
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=down:model,up:model
{extra}"
    )
}

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

fn never() -> bool {
    false
}

const TIMEOUT: Duration = Duration::from_millis(1_000);

fn tid(s: &str) -> TargetId {
    TargetId::new(s).unwrap()
}

#[test]
fn an_idle_target_whose_health_stops_answering_is_excluded_without_a_routed_request() {
    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&unused, &config(down.port(), up.port(), ""));
    let state = &router.state;

    // Both answer: the preferred one serves.
    assert_eq!(probe::run_round(state, TIMEOUT, &never), 2);
    let served = pipeline::execute(state, &request(), &[], PermissionSet::empty(), &mut Collect::default());
    assert!(served.is_success(), "{:?}", served.error);
    assert_eq!(down.chats(), 1, "the fixture must prefer `down` while it is up");

    // It stops answering. Nothing is routed to it from here on.
    down.set(LOADING);
    probe::run_round(state, TIMEOUT, &never);
    assert!(
        !state.health.probe_status(&tid("down:model")).is_some_and(|p| p.state == ProbeState::Unreachable),
        "one miss must not exclude a working machine"
    );
    probe::run_round(state, TIMEOUT, &never);
    let status = state.health.probe_status(&tid("down:model")).unwrap();
    assert_eq!(status.state, ProbeState::Unreachable);

    // The next request goes to `up` without ever trying `down`.
    let outcome = pipeline::execute(state, &request(), &[], PermissionSet::empty(), &mut Collect::default());
    assert!(outcome.is_success(), "{:?}", outcome.error);
    assert_eq!(down.chats(), 1, "a probed-down target was dialled for a request");
    assert_eq!(up.chats(), 1);
    assert!(
        outcome
            .trace
            .exclusions
            .iter()
            .any(|e| e.target.as_str() == "down:model" && e.reason == ExclusionReason::ProbeUnreachable),
        "the decision must say the probe excluded it: {:?}",
        outcome.trace.exclusions
    );

    // The exclusion came from the probe alone: no routed request failed, so
    // the breaker never moved.
    let breaker = state.health.entry(&tid("down:model"), hypellm_core::canonical::Operation::Chat);
    assert_eq!(breaker.breaker.state(state.clock.now_millis()), BreakerState::Closed);
    assert_eq!(breaker.total_failures(), 0);
}

#[test]
fn a_probed_down_target_returns_after_its_health_answers_again() {
    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&unused, &config(down.port(), up.port(), ""));
    let state = &router.state;

    down.set(LOADING);
    probe::run_round(state, TIMEOUT, &never);
    probe::run_round(state, TIMEOUT, &never);
    assert_eq!(
        state.health.probe_status(&tid("down:model")).unwrap().state,
        ProbeState::Unreachable
    );

    down.set(HEALTHY);
    probe::run_round(state, TIMEOUT, &never);
    assert_eq!(
        state.health.probe_status(&tid("down:model")).unwrap().state,
        ProbeState::Unreachable,
        "one answer while loading is not recovery"
    );
    probe::run_round(state, TIMEOUT, &never);
    assert_eq!(
        state.health.probe_status(&tid("down:model")).unwrap().state,
        ProbeState::Reachable
    );

    let outcome = pipeline::execute(state, &request(), &[], PermissionSet::empty(), &mut Collect::default());
    assert!(outcome.is_success(), "{:?}", outcome.error);
    assert_eq!(down.chats(), 1, "the recovered, preferred target serves again");
    assert_eq!(up.chats(), 0);
}

#[test]
fn a_wedged_health_endpoint_fails_its_probe_within_the_timeout() {
    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&unused, &config(down.port(), up.port(), ""));

    down.set(SILENT);
    let started = Instant::now();
    probe::run_round(&router.state, TIMEOUT, &never);
    let elapsed = started.elapsed();
    assert!(
        elapsed < TIMEOUT + Duration::from_millis(700),
        "a probe outlived its deadline: {elapsed:?}"
    );
    let status = router.state.health.probe_status(&tid("down:model")).unwrap();
    assert!(!status.last_ok);
    assert!(router.state.health.probe_status(&tid("up:model")).unwrap().last_ok);
}

#[test]
fn the_probe_dials_only_configured_endpoints_of_probed_families() {
    // A decoy listening where nothing is configured, and a remote-family
    // provider pointing at a second decoy: neither may ever be dialled.
    let decoy = TcpListener::bind("127.0.0.1:0").unwrap();
    decoy.set_nonblocking(true).unwrap();
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let remote_port = remote.local_addr().unwrap().port();

    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let extra = format!(
        "provider id=cloud family=openai scheme=http host=127.0.0.1 port={remote_port} base_path=/v1 egress=local\n\
         target id=cloud:model provider=cloud model=m local=true operations=chat context=1000 max_output=100\n\
         alias id=cloud-alias targets=cloud:model\n"
    );
    let router = router_with_config(&unused, &config(down.port(), up.port(), &extra));

    let set = probe::probe_set(&router.state.config());
    let dialled: Vec<(String, u16)> = set.iter().map(|p| (p.provider.to_string(), p.endpoint.port)).collect();
    assert_eq!(
        dialled,
        vec![("down".to_owned(), down.port()), ("up".to_owned(), up.port())],
        "the probe set must be exactly the configured llama.cpp and SemIf endpoints"
    );

    for _ in 0..5 {
        probe::run_round(&router.state, TIMEOUT, &never);
    }
    assert!(decoy.accept().is_err(), "an unconfigured address was dialled");
    assert!(remote.accept().is_err(), "a remote-family provider was probed");
    assert_eq!(down.healths(), 5);
    assert_eq!(up.healths(), 5);
    assert!(router.state.health.probe_status(&tid("cloud:model")).is_none());
}

#[test]
fn a_fleet_managed_target_is_never_probed_and_never_left_excluded() {
    // A target with a deployment is the fleet's: a stopped container there is
    // a cold target the planner may start, so excluding it would mean it is
    // never started (only `Infeasible` excludes).
    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&unused, &config(down.port(), up.port(), ""));
    let state = &router.state;

    down.set(LOADING);
    probe::run_round(state, TIMEOUT, &never);
    probe::run_round(state, TIMEOUT, &never);
    assert_eq!(state.health.probe_status(&tid("down:model")).unwrap().state, ProbeState::Unreachable);

    // Leaving the probe set clears the verdict: the record is retained only
    // for targets the probe is still probing.
    let probed: std::collections::BTreeSet<TargetId> = [tid("up:model")].into_iter().collect();
    state.health.retain_probes(&probed);
    assert!(state.health.probe_status(&tid("down:model")).is_none());

    // With the fleet on and a deployment for `down`, it leaves the probe set;
    // `up`, which has none, stays in it.
    let fleet = "\
fleet_agent id=local socket=\"/run/hypellm/fleet.sock\"
host id=spark agent=local arch=aarch64
accelerator id=spark-gpu0 host=spark kind=cuda memory_bytes=100000000000
deployment id=d-down target=down:model accelerator=spark-gpu0 memory_bytes=1000 autostart=false
";
    let text = config(down.port(), up.port(), fleet);
    let enabled = text.replacen("max_attempts=3", "max_attempts=3 fleet_enabled=true", 1);
    let managed = probe::probe_set(&hypellm_router::testing::config_from(&enabled));
    let names: Vec<String> = managed.iter().map(|p| p.provider.to_string()).collect();
    assert_eq!(names, vec!["up".to_owned()], "a fleet-managed target was probed");

    // The same document with the fleet off manages nothing: both are probed.
    let off = probe::probe_set(&hypellm_router::testing::config_from(&text));
    assert_eq!(off.len(), 2);
}

#[test]
fn the_loop_stops_within_one_probe_timeout_of_shutdown() {
    let down = Slave::start();
    let up = Slave::start();
    let unused = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let router = router_with_config(&unused, &config(down.port(), up.port(), ""));
    // A wedged endpoint, so the loop is inside a probe when shutdown arrives.
    down.set(SILENT);

    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let state = Arc::clone(&router.state);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || probe::probe_loop(&state, &|| stop.load(Ordering::SeqCst)))
    };
    // Let it reach the wedged probe.
    let until = Instant::now() + Duration::from_secs(3);
    while down.healths() == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(down.healths() > 0, "the loop never probed");

    let asked = Instant::now();
    stop.store(true, Ordering::SeqCst);
    thread.join().unwrap();
    let took = asked.elapsed();
    assert!(
        took < TIMEOUT + Duration::from_millis(700),
        "shutdown waited {took:?}, more than one probe timeout"
    );
}
