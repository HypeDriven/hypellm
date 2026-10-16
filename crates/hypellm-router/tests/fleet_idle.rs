//! Idle stop (specification 26.10), against the simulated agent on a
//! deterministic clock: a model nothing is using is taken down after
//! `idle_stop_ms`, and never while anything is using it, waiting for it, or
//! anchoring it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "specification 18.2 permits these in tests; the casts are unsizing coercions"
)]

use hypellm_core::ids::{AcceleratorId, AgentId, DeploymentId, HostId, PoolId, TargetId};
use hypellm_core::target::Capability;
use hypellm_core::time::{Clock, TestClock};
use hypellm_fleet::demand::DemandSnapshot;
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, Host, HostState,
    Readiness,
};
use hypellm_fleet::plan::{PlanContext, PlanOutcome};
use hypellm_net::fleet_sim::{AgentScript, Behaviour, SimulatedAgent};
use hypellm_router::fleet::{ActivationResult, FleetRuntime};
use hypellm_store::audit::AuditAction;
use hypellm_store::{Store, TempDir};
use hypellm_telemetry::{Logger, MemorySink, Severity, Telemetry};
use std::sync::Arc;

const KEY: &[u8] = b"a-fleet-key-for-these-tests-0123456789";
const GIB: u64 = 1024 * 1024 * 1024;

fn did(s: &str) -> DeploymentId {
    DeploymentId::new(s).unwrap()
}
fn tid(s: &str) -> TargetId {
    TargetId::new(s).unwrap()
}

fn deployment(id: &str, target: &str, memory: u64) -> Deployment {
    Deployment {
        id: did(id),
        target: tid(target),
        accelerator: AcceleratorId::new("gb10").unwrap(),
        artifact: None,
        memory_bytes: memory,
        start_ms: 180_000,
        stop_ms: 15_000,
        drain_ms: 30_000,
        probe_ms: 10_000,
        readiness: Readiness::HttpOk,
        min_resident_ms: 600_000,
        evictable: true,
        pinned: false,
        autostart: true,
        retention_weight: 0,
        max_drainable_inflight: 0,
        force_stop: false,
    }
}

/// The Spark, at the numbers the design was validated against.
fn spark(socket: &str) -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = true;
    fleet.agents.insert(
        AgentId::new("local").unwrap(),
        FleetAgent {
            id: AgentId::new("local").unwrap(),
            socket: socket.to_owned(),
            observation_interval_ms: 5_000,
            observation_max_age_ms: 30_000,
            request_timeout_ms: 2_000,
            ssh_public_key: None,
        },
    );
    fleet.hosts.insert(
        HostId::new("spark").unwrap(),
        Host {
            id: HostId::new("spark").unwrap(),
            agent: AgentId::new("local").unwrap(),
            arch: Arch::Aarch64,
            state: HostState::Enabled,
            reserved_memory_bytes: 16 * GIB,
            max_concurrent_activations: 1,
        },
    );
    fleet.accelerators.insert(
        AcceleratorId::new("gb10").unwrap(),
        Accelerator {
            id: AcceleratorId::new("gb10").unwrap(),
            host: HostId::new("spark").unwrap(),
            kind: AcceleratorKind::Unified,
            memory_bytes: 130 * GIB,
            pool: PoolId::new("spark-unified").unwrap(),
        },
    );
    fleet
}

struct Harness {
    runtime: Arc<FleetRuntime>,
    clock: Arc<TestClock>,
    agent: SimulatedAgent,
    store: Arc<Store>,
    _dir: TempDir,
}

fn harness(fleet: FleetConfig, script: impl FnOnce(AgentScript) -> AgentScript) -> Harness {
    let dir = TempDir::new("fleet-integration");
    let socket = fleet
        .agents
        .values()
        .next()
        .map(|a| a.socket.clone())
        .unwrap_or_default();
    let digest = fleet.digest();
    let agent = SimulatedAgent::start(&socket, script(AgentScript::empty(digest, KEY)));

    let clock: Arc<TestClock> = Arc::new(TestClock::new());
    let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0).unwrap();
    let telemetry = Arc::new(Telemetry::new(logger(&clock), b"pseudonym-key"));
    let dynamic: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let store = Arc::new(store);
    let runtime = FleetRuntime::new(
        Arc::new(fleet),
        KEY.to_vec(),
        dynamic,
        telemetry,
        Arc::clone(&store),
    )
    .expect("an enabled fleet with deployments yields a runtime");

    Harness {
        runtime: Arc::new(runtime),
        clock,
        agent,
        store,
        _dir: dir,
    }
}

/// A logger that collects rather than writing to standard error.
///
/// The fleet path is deliberately talkative — divergence, drift, mismatch — and
/// a test suite that printed all of it would bury the failures that matter.
fn logger(clock: &Arc<TestClock>) -> Logger {
    Logger::new(
        Box::new(MemorySink::new()),
        Severity::Info,
        Arc::clone(clock) as Arc<dyn Clock>,
    )
}

fn socket_in(name: &str) -> String {
    // Short paths: a Unix socket path is limited to about 108 bytes, and a
    // temporary directory under a deep target directory can exceed it.
    format!("/tmp/hypellm-fleet-{name}-{}.sock", std::process::id())
}

/// Bring a deployment up through the runtime, as production would.
///
/// A deployment the *router* started is one it owns and may later stop; one it
/// merely found running is adopted for routing and never evicted. Tests about
/// eviction have to establish ownership the same way production does, or they
/// are testing adoption by accident.
fn start_through_router(h: &Harness, target: &TargetId) {
    h.runtime.observe();
    let snapshot = h.runtime.snapshot();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &DemandSnapshot::default(),
        target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("the setup activation must be plannable");
    };
    assert_eq!(
        h.runtime.ensure_ready(target, &plan, "setup", 900_000),
        ActivationResult::Ready
    );
}

fn context(now_ms: u64, patience_ms: u64) -> PlanContext {
    PlanContext {
        now_ms,
        deadline_remaining_ms: patience_ms,
        effort_multiplier: 1,
        effort_headroom_ms: 5_000,
        may_activate: true,
        may_fetch: false,
        capability: Some(Capability::TextToMusic),
        priority_bonus: 0,
    }
}


/// The default idle window.
const IDLE: u64 = 900_000;

fn one_model(name: &str, pinned: bool) -> (Harness, Deployment) {
    let socket = socket_in(name);
    let mut fleet = spark(&socket);
    let mut music = deployment("spark-music3", "spark:music3", 64 * GIB);
    music.pinned = pinned;
    fleet.deployments.insert(music.id.clone(), music.clone());
    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "stopped")
    });
    h.runtime
        .set_capability_for_test(&music.id, Capability::TextToMusic);
    start_through_router(&h, &music.target);
    (h, music)
}

fn deactivations(h: &Harness) -> usize {
    h.agent
        .verbs()
        .iter()
        .filter(|v| v.starts_with("DEACTIVATE "))
        .count()
}

/// Let `ms` pass and refresh belief, as the housekeeping loop would.
fn pass(h: &Harness, ms: u64) {
    h.clock.advance(ms);
    h.runtime.observe();
}

#[test]
fn a_model_nothing_uses_is_stopped_once_its_window_has_passed_and_not_before() {
    let (h, music) = one_model("idle-window", false);

    pass(&h, IDLE - 1_000);
    assert!(h.runtime.idle_stop().is_empty(), "stopped inside its window");
    assert_eq!(deactivations(&h), 0);

    pass(&h, 1_000);
    assert_eq!(h.runtime.idle_stop(), vec![music.id.clone()]);
    assert_eq!(deactivations(&h), 1);

    // Audited as a stop, with the reason an operator would look for.
    let audited = h
        .store
        .audit_records(None, 500)
        .unwrap()
        .into_iter()
        .any(|(_, r)| {
            r.event.action == AuditAction::FleetDeactivate
                && r.event
                    .reason
                    .as_ref()
                    .is_some_and(|reason| reason.as_str().starts_with("idle"))
        });
    assert!(audited, "the idle stop was not audited with its reason");
}

#[test]
fn a_request_in_flight_keeps_its_model_up_and_the_window_restarts_when_it_ends() {
    let (h, music) = one_model("idle-inflight", false);

    let hold = h
        .runtime
        .enter_dispatch(&music.target)
        .unwrap()
        .expect("a deployment target is counted");
    pass(&h, IDLE * 3);
    assert!(h.runtime.idle_stop().is_empty(), "stopped under a request");
    h.runtime.leave_dispatch(hold);

    // The request just ended, so the model has been idle for no time at all.
    pass(&h, IDLE - 1_000);
    assert!(h.runtime.idle_stop().is_empty(), "the window did not restart");
    pass(&h, 1_000);
    assert_eq!(h.runtime.idle_stop(), vec![music.id]);
}

#[test]
fn a_request_parked_for_the_model_keeps_it_up() {
    let (h, _music) = one_model("idle-parked", false);
    assert!(h.runtime.park(Capability::TextToMusic));
    pass(&h, IDLE * 2);
    assert!(h.runtime.idle_stop().is_empty(), "stopped with a request waiting for it");
    h.runtime.unpark(Capability::TextToMusic);
    assert_eq!(h.runtime.idle_stop().len(), 1);
}

#[test]
fn a_pinned_model_is_never_idle_stopped() {
    let (h, _music) = one_model("idle-pinned", true);
    pass(&h, IDLE * 10);
    assert!(h.runtime.idle_stop().is_empty());
    assert_eq!(deactivations(&h), 0);
}

#[test]
fn stale_belief_stops_nothing() {
    let (h, _music) = one_model("idle-stale", false);
    // Time passes, but nobody looks: the last observation is far older than
    // `observation_max_age_ms`.
    h.clock.advance(IDLE * 2);
    assert!(h.runtime.idle_stop().is_empty());
    assert_eq!(deactivations(&h), 0);
}

#[test]
fn a_dispatch_and_an_idle_stop_cannot_pass_each_other() {
    // Whichever takes the lock first wins, and the other sees it. A request
    // routed on belief from before the stop must not be sent into a model
    // being taken down; a stop must not be claimed under a request.
    let (h, music) = one_model("idle-claim", false);

    assert!(h.runtime.claim_for_stop_for_test(&music.id));
    assert!(
        h.runtime.enter_dispatch(&music.target).is_err(),
        "a dispatch was counted against a model an idle stop had claimed"
    );
    h.runtime.release_stop_claim_for_test(&music.id);

    let hold = h.runtime.enter_dispatch(&music.target).unwrap().unwrap();
    assert!(
        !h.runtime.claim_for_stop_for_test(&music.id),
        "an idle stop claimed a model with a request in flight"
    );
    h.runtime.leave_dispatch(hold);
    assert!(h.runtime.claim_for_stop_for_test(&music.id));
    h.runtime.release_stop_claim_for_test(&music.id);
}
