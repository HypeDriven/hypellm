//! Integration tests for fleet orchestration, against the simulated agent.
//!
//! Specification-extension 16 requires "full eviction-and-start sequences,
//! drain expiry, rollback, stale observation, divergence adoption, crash-and-
//! recover with outstanding leases. Deterministic clock, no network."
//!
//! Every test here drives the *real* client over a *real* Unix socket against a
//! conformant agent that verifies the handshake HMAC and enforces its own
//! allowlist. The clock is a `TestClock`, and `Clock::sleep` advances it rather
//! than blocking, so a three-minute model load takes microseconds and the
//! deadline arithmetic is exact.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::ids::{
    AcceleratorId, AgentId, ArtifactId, DeploymentId, HostId, PoolId, TargetId,
};
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
    let runtime = FleetRuntime::new(
        Arc::new(fleet),
        KEY.to_vec(),
        dynamic,
        telemetry,
        Arc::new(store),
    )
    .expect("an enabled fleet with deployments yields a runtime");

    Harness {
        runtime: Arc::new(runtime),
        clock,
        agent,
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

#[test]
fn a_cold_deployment_is_started_and_becomes_ready() {
    let socket = socket_in("start");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(2))
            .with_state("spark-music3", "stopped")
    });

    h.runtime.observe();
    let snapshot = h.runtime.snapshot();
    assert!(
        snapshot.belief_is_fresh(h.clock.now_millis(), 30_000),
        "the first observation must produce fresh belief"
    );

    let outcome = hypellm_fleet::plan::plan(
        &snapshot,
        &DemandSnapshot::default(),
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    );
    let PlanOutcome::Plan(plan) = outcome else {
        panic!("expected a plan, got {outcome:?}");
    };
    assert!(!plan.evicts(), "an empty host needs no eviction");

    assert_eq!(
        h.runtime.ensure_ready(&music.target, &plan, "abc", 900_000),
        ActivationResult::Ready
    );

    let verbs = h.agent.verbs();
    assert!(
        verbs.iter().any(|v| v.starts_with("ACTIVATE spark-music3 ")),
        "the router must have asked for the activation: {verbs:?}"
    );
    assert_eq!(h.agent.state_of("spark-music3").as_deref(), Some("ready"));
    assert!(
        h.runtime.snapshot().state_of(&music.id).is_serving(),
        "belief must reflect the deployment the router just started"
    );
    let (acquired, released) = h.runtime.ledger().accounting();
    assert_eq!((acquired, released), (1, 1));
}

#[test]
fn readiness_is_confirmed_by_observation_and_not_by_the_verb_returning() {
    // A TCP connect is not readiness, and neither is an accepted `ACTIVATE`.
    // This agent drives its activation to `ready` while its *inventory* keeps
    // reporting the deployment stopped — which is the shape of a container that
    // started and then died, or a probe that passed against the wrong port.
    //
    // The executor must believe the inventory.
    let socket = socket_in("ready");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            // Reported verbatim and never updated by the state machine, so the
            // inventory disagrees with the activation's own report.
            .with_raw_deployment(r#"{"id":"spark-music3","state":"stopped"}"#)
    });

    h.runtime.observe();
    let snapshot = h.runtime.snapshot();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &DemandSnapshot::default(),
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("expected a plan");
    };

    assert_eq!(
        h.runtime.ensure_ready(&music.target, &plan, "abc", 900_000),
        ActivationResult::Failed {
            code: "fleet_activation_failed"
        },
        "an activation the inventory does not confirm is not a ready deployment"
    );
    let (acquired, released) = h.runtime.ledger().accounting();
    assert_eq!((acquired, released), (1, 1), "the lease is still released once");
}

#[test]
fn an_agent_that_never_becomes_ready_ends_at_the_deadline_and_releases_its_lease() {
    let socket = socket_in("hang");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::Hangs)
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();

    let snapshot = h.runtime.snapshot();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &DemandSnapshot::default(),
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("expected a plan");
    };

    let result = h.runtime.ensure_ready(&music.target, &plan, "abc", 30_000);
    assert_eq!(
        result,
        ActivationResult::Failed {
            code: "fleet_activation_timeout"
        }
    );
    // The obligation Appendix B places on reservations, applied to leases: a
    // leaked one would pin the host out of service until expiry.
    let (acquired, released) = h.runtime.ledger().accounting();
    assert_eq!(acquired, released, "every lease acquired was released");
    assert_eq!(h.runtime.ledger().slots_held(&HostId::new("spark").unwrap()), 0);
    assert!(
        h.agent.verbs().iter().any(|v| v.starts_with("CANCEL ")),
        "a timed-out activation is cancelled at the agent"
    );
}

#[test]
fn an_agent_naming_a_deployment_the_configuration_does_not_declare_is_ignored() {
    // The trust boundary, end to end: the agent reports a deployment nobody
    // declared, and it changes nothing the router believes.
    let socket = socket_in("unknown");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_state("spark-music3", "stopped")
            .with_raw_deployment(r#"{"id":"attacker-owned","state":"ready"}"#)
    });
    h.runtime.observe();

    let snapshot = h.runtime.snapshot();
    assert_eq!(snapshot.inventory.deployments.len(), 1);
    assert_eq!(snapshot.inventory.unknown_identifiers, 1);
    assert!(
        !snapshot
            .inventory
            .deployments
            .contains_key(&did("attacker-owned"))
    );
}

#[test]
fn a_digest_mismatch_stops_every_mutating_verb() {
    // The router and the agent disagreeing about what an identifier means is
    // exactly the moment not to send a verb that stops a model.
    let socket = socket_in("mismatch");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let dir = TempDir::new("fleet-mismatch");
    let agent = SimulatedAgent::start(
        &socket,
        AgentScript::empty("sha256-a-different-fleet", KEY)
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1)),
    );
    let clock: Arc<TestClock> = Arc::new(TestClock::new());
    let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0).unwrap();
    let telemetry = Arc::new(Telemetry::new(logger(&clock), b"pseudonym-key"));
    let runtime = FleetRuntime::new(
        Arc::new(fleet),
        KEY.to_vec(),
        Arc::clone(&clock) as Arc<dyn Clock>,
        telemetry,
        Arc::new(store),
    )
    .unwrap();

    runtime.observe();
    assert!(
        !runtime.snapshot().digest_agreed,
        "a mismatch must be recorded as a mismatch"
    );

    let outcome = hypellm_fleet::plan::plan(
        &runtime.snapshot(),
        &DemandSnapshot::default(),
        &music.target,
        &context(clock.now_millis(), 900_000),
    );
    assert_eq!(
        outcome,
        PlanOutcome::Infeasible(
            hypellm_core::decision::ExclusionReason::FleetConfigurationMismatch
        )
    );
    assert!(
        !agent.verbs().iter().any(|v| v.starts_with("ACTIVATE")),
        "no mutating verb may be issued while the digests disagree: {:?}",
        agent.verbs()
    );
}

#[test]
fn a_replayed_handshake_is_refused_by_the_agent() {
    // Defence in depth — reaching the socket already needs the owner's
    // privileges — but a captured handshake that could be replayed would be a
    // needless gift.
    let socket = socket_in("replay");
    let mut agent = SimulatedAgent::start(
        &socket,
        AgentScript::empty("sha256-digest", KEY),
    );
    let client = hypellm_net::fleet::FleetAgentClient::new(
        socket.clone(),
        std::time::Duration::from_secs(2),
    );

    let first = client.open(KEY, "sha256-digest").expect("first handshake");
    drop(first);
    let second = client.open(KEY, "sha256-digest").expect("second handshake");
    drop(second);
    assert_eq!(
        agent.handshakes(),
        2,
        "each handshake uses a fresh nonce, so both are accepted"
    );

    // Replaying one of them by hand is refused.
    let hello = hypellm_fleet::protocol::hello_hmac(KEY, "deadbeef", "sha256-digest");
    let line = format!("HELLO 1 deadbeef sha256-digest {hello}\n");
    assert!(send_raw(&socket, &line).starts_with("OK "));
    assert_eq!(
        send_raw(&socket, &line).trim_end(),
        "ERR replayed_nonce",
        "a nonce the agent has already accepted must not be accepted again"
    );
    agent.stop();
}

#[test]
fn an_unauthenticated_caller_learns_nothing_about_the_fleet() {
    let socket = socket_in("unauth");
    let mut agent = SimulatedAgent::start(
        &socket,
        AgentScript::empty("sha256-digest", KEY).with_state("spark-music3", "ready"),
    );
    assert_eq!(send_raw(&socket, "OBSERVE\n").trim_end(), "ERR unauthenticated");
    assert_eq!(
        send_raw(&socket, "ACTIVATE spark-music3 l-1 1000\n").trim_end(),
        "ERR unauthenticated"
    );
    agent.stop();
}

#[test]
fn a_wrong_key_cannot_open_a_session() {
    let socket = socket_in("badkey");
    let mut agent = SimulatedAgent::start(&socket, AgentScript::empty("sha256-digest", KEY));
    let client = hypellm_net::fleet::FleetAgentClient::new(
        socket.clone(),
        std::time::Duration::from_secs(2),
    );
    let error = client
        .open(b"the-wrong-key-entirely-0123456789", "sha256-digest")
        .expect_err("must be refused");
    assert_eq!(error.code(), "fleet_agent_refused");
    agent.stop();
}

/// Send one line and read one line back, outside the client.
fn send_raw(path: &str, line: &str) -> String {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path).expect("connect");
    stream.write_all(line.as_bytes()).expect("write");
    stream.flush().expect("flush");
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    let _ = reader.read_line(&mut reply);
    reply
}

#[test]
fn a_full_eviction_and_start_sequence_stops_one_model_and_starts_another() {
    // The worked example, executed: 114 GiB offered after the host
    // reservation, a 64 GiB audio model the router started itself, and a
    // 64 GiB music model that cannot fit beside it.
    let socket = socket_in("evict");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    let mut h3 = deployment("spark-h3", "spark:h3", 64 * GIB);
    h3.min_resident_ms = 0;
    fleet.deployments.insert(music.id.clone(), music.clone());
    fleet.deployments.insert(h3.id.clone(), h3.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(2))
            .with_deployment("spark-h3", Behaviour::ReadyAfter(1))
            .with_state("spark-h3", "stopped")
            .with_state("spark-music3", "stopped")
    });
    start_through_router(&h, &h3.target);

    let mut demand = DemandSnapshot::default();
    demand.rate_per_minute.insert(Capability::TextToMusic, 500);
    demand.idle_ms.insert(h3.id.clone(), u64::MAX);

    let snapshot = h.runtime.snapshot();
    assert!(
        snapshot.is_router_owned(&h3.id),
        "a deployment the router started is one it may stop"
    );
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &demand,
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("expected an evicting plan");
    };
    assert_eq!(plan.eviction_set(), vec![&h3.id]);

    assert_eq!(
        h.runtime.ensure_ready(&music.target, &plan, "abc", 900_000),
        ActivationResult::Ready
    );

    let verbs = h.agent.verbs();
    let deactivate = verbs
        .iter()
        .position(|v| v.starts_with("DEACTIVATE spark-h3 "))
        .expect("the audio model is stopped");
    let activate = verbs
        .iter()
        .rposition(|v| v.starts_with("ACTIVATE spark-music3 "))
        .expect("the music model is started");
    assert!(
        deactivate < activate,
        "memory must be freed before it is claimed: {verbs:?}"
    );

    // The evicted deployment enters its cooldown, so an immediate request for
    // it does *not* swap back.
    let snapshot = h.runtime.snapshot();
    assert_eq!(
        hypellm_fleet::plan::plan(
            &snapshot,
            &DemandSnapshot::default(),
            &h3.target,
            &context(h.clock.now_millis(), 900_000),
        ),
        PlanOutcome::Infeasible(hypellm_core::decision::ExclusionReason::DeploymentInDwell),
        "a just-evicted deployment is inside its cooldown"
    );
}

#[test]
fn a_failed_activation_after_an_eviction_brings_the_evicted_model_back() {
    // The fleet is worse off than it started: one model stopped, none started.
    // The rollback is bounded and best-effort, and its outcome is recorded
    // either way.
    let socket = socket_in("rollback");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    let mut h3 = deployment("spark-h3", "spark:h3", 64 * GIB);
    h3.min_resident_ms = 0;
    fleet.deployments.insert(music.id.clone(), music.clone());
    fleet.deployments.insert(h3.id.clone(), h3.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::FailsAfter(1))
            .with_deployment("spark-h3", Behaviour::ReadyAfter(1))
            .with_state("spark-h3", "stopped")
            .with_state("spark-music3", "stopped")
    });
    start_through_router(&h, &h3.target);

    let mut demand = DemandSnapshot::default();
    demand.rate_per_minute.insert(Capability::TextToMusic, 500);
    demand.idle_ms.insert(h3.id.clone(), u64::MAX);

    let snapshot = h.runtime.snapshot();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &demand,
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("expected an evicting plan");
    };

    assert_eq!(
        h.runtime.ensure_ready(&music.target, &plan, "abc", 900_000),
        ActivationResult::Failed {
            code: "fleet_activation_failed"
        }
    );

    let verbs = h.agent.verbs();
    let activations = verbs
        .iter()
        .filter(|v| v.starts_with("ACTIVATE spark-h3 "))
        .count();
    assert_eq!(
        activations, 2,
        "the audio model is started once by the setup and once by the rollback: {verbs:?}"
    );
    // Two leases: the one that brought the audio model up, and the one that
    // failed trying to replace it. Both released.
    let (acquired, released) = h.runtime.ledger().accounting();
    assert_eq!((acquired, released), (2, 2));
}

#[test]
fn a_deployment_the_router_did_not_start_is_used_but_never_evicted() {
    // The default is that the router will use what it finds and will not take
    // it away. An operator who started a container by hand should not have to
    // fight the router to keep it.
    let socket = socket_in("adopt");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    let mut h3 = deployment("spark-h3", "spark:h3", 64 * GIB);
    h3.min_resident_ms = 0;
    fleet.deployments.insert(music.id.clone(), music.clone());
    fleet.deployments.insert(h3.id.clone(), h3.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_deployment("spark-h3", Behaviour::ReadyAfter(1))
            // Already running when the router first looks.
            .with_state("spark-h3", "ready")
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();

    let snapshot = h.runtime.snapshot();
    assert!(
        !snapshot.is_router_owned(&h3.id),
        "a deployment found running is adopted for routing, not for eviction"
    );
    assert!(
        snapshot.state_of(&h3.id).is_serving(),
        "it is still used: adoption is about eviction, not eligibility"
    );

    let mut demand = DemandSnapshot::default();
    demand.rate_per_minute.insert(Capability::TextToMusic, 5_000);
    demand.idle_ms.insert(h3.id.clone(), u64::MAX);
    assert_eq!(
        hypellm_fleet::plan::plan(
            &snapshot,
            &demand,
            &music.target,
            &context(h.clock.now_millis(), 900_000),
        ),
        PlanOutcome::Infeasible(
            hypellm_core::decision::ExclusionReason::HostCapacityInsufficient
        ),
        "however badly the music model is wanted, an unmanaged deployment is not evicted"
    );
}

#[test]
fn belief_that_has_aged_out_refuses_to_plan() {
    let socket = socket_in("stale");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();

    // Well past `observation_max_age_ms` with nothing new observed.
    h.clock.advance(60_000);
    let snapshot = h.runtime.snapshot();
    assert_eq!(
        hypellm_fleet::plan::plan(
            &snapshot,
            &DemandSnapshot::default(),
            &music.target,
            &context(h.clock.now_millis(), 900_000),
        ),
        PlanOutcome::Infeasible(hypellm_core::decision::ExclusionReason::FleetStateStale)
    );
    assert!(
        !h.agent
            .verbs()
            .iter()
            .any(|v| v.starts_with("ACTIVATE") || v.starts_with("DEACTIVATE")),
        "no plan executes on stale belief"
    );
}

#[test]
fn a_missing_artifact_is_refused_rather_than_fetched_without_permission() {
    let socket = socket_in("artifact");
    let mut fleet = spark(&socket);
    let mut music = deployment("spark-music3", "spark:music3", 8 * GIB);
    music.artifact = Some(ArtifactId::new("music3-arm64").unwrap());
    fleet.artifacts.insert(
        ArtifactId::new("music3-arm64").unwrap(),
        hypellm_fleet::model::Artifact {
            id: ArtifactId::new("music3-arm64").unwrap(),
            kind: hypellm_fleet::model::ArtifactKind::Image,
            arch: Arch::Aarch64,
            size_bytes: 20 * GIB,
            digest: format!("sha256:{}", "0".repeat(64)),
            source: "mirror-local".to_owned(),
        },
    );
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();

    let snapshot = h.runtime.snapshot();
    assert_eq!(
        hypellm_fleet::plan::plan(
            &snapshot,
            &DemandSnapshot::default(),
            &music.target,
            &context(h.clock.now_millis(), 900_000),
        ),
        PlanOutcome::Infeasible(hypellm_core::decision::ExclusionReason::ArtifactUnavailable),
        "fetch is off by default and separately permissioned"
    );
}

#[test]
fn an_agent_that_goes_away_mid_activation_does_not_leak_its_lease() {
    let socket = socket_in("vanish");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let mut h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(4))
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();

    let snapshot = h.runtime.snapshot();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &snapshot,
        &DemandSnapshot::default(),
        &music.target,
        &context(h.clock.now_millis(), 900_000),
    ) else {
        panic!("expected a plan");
    };

    h.agent.stop();
    let result = h.runtime.ensure_ready(&music.target, &plan, "abc", 900_000);
    assert_eq!(
        result,
        ActivationResult::Failed {
            code: "fleet_unavailable"
        }
    );
    let (acquired, released) = h.runtime.ledger().accounting();
    assert_eq!(acquired, released, "an agent outage must not leak a lease");
    assert_eq!(
        h.runtime.ledger().slots_held(&HostId::new("spark").unwrap()),
        0
    );
}

#[test]
fn a_request_arriving_during_an_activation_waits_for_it_rather_than_dispatching() {
    // Batching only works if the requests that did *not* pay for the swap are
    // actually served by it. Without this, a burst of ten requests produces one
    // activation and nine failovers into a model that has not finished loading
    // — which is the same number of failed requests as no batching at all, plus
    // the swap.
    let socket = socket_in("await");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "starting")
    });
    h.runtime.observe();

    // The deployment is coming up: the planner says so, and a request must not
    // be dispatched into it yet.
    let snapshot = h.runtime.snapshot();
    assert!(matches!(
        hypellm_fleet::plan::plan(
            &snapshot,
            &DemandSnapshot::default(),
            &music.target,
            &context(h.clock.now_millis(), 900_000),
        ),
        PlanOutcome::AlreadyActivating { .. }
    ));

    // Nothing will ever move it to `ready` in this fixture — the agent's state
    // map is what `OBSERVE` reports and no verb has been sent — so the wait
    // must end at the deadline rather than hanging.
    let waited = h.runtime.await_ready(&music.target, 10_000);
    assert_eq!(waited, Err("fleet_activation_timeout"));
}

#[test]
fn waiting_for_a_deployment_that_is_already_serving_returns_at_once() {
    let socket = socket_in("await-ready");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "ready")
    });
    h.runtime.observe();
    assert_eq!(h.runtime.await_ready(&music.target, 10_000), Ok(0));
}

#[test]
fn waiting_stops_when_the_activation_fails_rather_than_running_to_the_deadline() {
    // A request that kept waiting after the model gave up would hold a
    // connection and an admission slot for the whole deadline, and then fail
    // anyway.
    let socket = socket_in("await-fail");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet, |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "failed")
    });
    h.runtime.observe();
    let before = h.clock.now_millis();
    assert_eq!(
        h.runtime.await_ready(&music.target, 600_000),
        Err("fleet_activation_failed")
    );
    assert_eq!(
        h.clock.now_millis(),
        before,
        "a terminal failure ends the wait immediately"
    );
}

#[test]
fn a_configuration_reload_that_changes_the_fleet_is_adopted() {
    // A publication swaps the shared configuration pointer and tells the fleet
    // runtime nothing. Without reconciliation the router would keep planning
    // against the fleet it started with — and compute a handshake digest its
    // agent no longer agrees with, so every orchestrated target would go
    // ineligible for a reason pointing at the agent rather than at the reload.
    let socket = socket_in("reload");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());

    let h = harness(fleet.clone(), |script| {
        script
            .with_deployment("spark-music3", Behaviour::ReadyAfter(1))
            .with_state("spark-music3", "stopped")
    });
    h.runtime.observe();
    let before = h.runtime.config().digest();

    // A second deployment appears, as a publication would introduce one.
    let mut next = (*h.runtime.config()).clone();
    let h3 = deployment("spark-h3", "spark:h3", 32 * GIB);
    next.deployments.insert(h3.id.clone(), h3.clone());
    h.runtime.adopt_fleet(Arc::new(next));

    assert_ne!(
        h.runtime.config().digest(),
        before,
        "adding a deployment must change the digest both sides compare"
    );
    assert!(h.runtime.config().deployments.contains_key(&h3.id));
    assert!(
        h.runtime.snapshot().observation_age_ms(h.clock.now_millis()).is_none(),
        "belief is about the old fleet until the next observation, and must not \
         be carried across"
    );
}

#[test]
fn an_operator_override_survives_a_reload_and_is_dropped_when_its_deployment_is() {
    // An operator who pinned something during an incident should not have it
    // silently unpinned by an unrelated publication — and an override naming a
    // deployment the new configuration does not declare has nothing left to
    // mean.
    let socket = socket_in("override");
    let mut fleet = spark(&socket);
    let music = deployment("spark-music3", "spark:music3", 64 * GIB);
    let h3 = deployment("spark-h3", "spark:h3", 32 * GIB);
    fleet.deployments.insert(music.id.clone(), music.clone());
    fleet.deployments.insert(h3.id.clone(), h3.clone());

    let h = harness(fleet, |script| script.with_state("spark-music3", "stopped"));
    let control = hypellm_router::fleet::FleetControlAdapter::new(Arc::clone(&h.runtime));
    use hypellm_admin_api::FleetControl as _;
    control
        .patch(
            "spark-music3",
            hypellm_admin_api::DeploymentPatch {
                pinned: Some(true),
                ..hypellm_admin_api::DeploymentPatch::default()
            },
        )
        .expect("patch applies");
    assert!(h.runtime.config().deployments[&music.id].pinned);

    // A publication that keeps the deployment keeps the pin.
    let mut next = (*h.runtime.config()).clone();
    next.deployments.get_mut(&music.id).map(|d| {
        d.pinned = false;
        d.start_ms = 42;
    });
    h.runtime.adopt_fleet(Arc::new(next));
    assert!(
        h.runtime.config().deployments[&music.id].pinned,
        "the override outlives the reload"
    );
    assert_eq!(h.runtime.config().deployments[&music.id].start_ms, 42);

    // A publication that removes it drops the override.
    let mut next = (*h.runtime.config()).clone();
    next.deployments.remove(&music.id);
    h.runtime.adopt_fleet(Arc::new(next));
    assert!(!h.runtime.config().deployments.contains_key(&music.id));
}
