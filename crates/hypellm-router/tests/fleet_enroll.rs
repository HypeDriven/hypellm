//! Enrollment offers, against the simulated agent (specification 26.8).
//!
//! The property under test is the ordering the design rests on: an approved
//! slave reaches the agent only once its records are **published**, the offer
//! is what resolves the digest mismatch a publication causes, and a quiet
//! fleet is not re-offered the same thing every observation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::ids::{AcceleratorId, AgentId, HostId, PoolId};
use hypellm_core::time::{Clock, TestClock};
use hypellm_fleet::enroll::{EnrollmentRegistry, NewEnrollment, parse_registration, token_digest};
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, Host, HostState,
    Readiness,
};
use hypellm_net::fleet_sim::{AgentScript, SimulatedAgent};
use hypellm_router::fleet::FleetRuntime;
use hypellm_store::{Store, TempDir};
use hypellm_telemetry::{Logger, MemorySink, Severity, Telemetry};
use std::sync::Arc;

const KEY: &[u8] = b"a-fleet-key-for-these-tests-0123456789";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GIB: u64 = 1024 * 1024 * 1024;

fn socket_in(name: &str) -> String {
    format!("/tmp/hypellm-enroll-{name}-{}.sock", std::process::id())
}

fn host(id: &str) -> Host {
    Host {
        id: HostId::new(id).unwrap(),
        agent: AgentId::new("local").unwrap(),
        arch: Arch::X86_64,
        state: HostState::Enabled,
        reserved_memory_bytes: 0,
        max_concurrent_activations: 1,
    }
}

fn accelerator(id: &str, host: &str) -> Accelerator {
    Accelerator {
        id: AcceleratorId::new(id).unwrap(),
        host: HostId::new(host).unwrap(),
        kind: AcceleratorKind::Cuda,
        memory_bytes: 24 * GIB,
        pool: PoolId::new(id).unwrap(),
    }
}

/// A fleet with one hand-written host, and — when `published` — the enrolled
/// one as an approver would have published it.
fn fleet(socket: &str, published: bool) -> FleetConfig {
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
    fleet.hosts.insert(HostId::new("spark").unwrap(), host("spark"));
    fleet
        .accelerators
        .insert(AcceleratorId::new("gb10").unwrap(), accelerator("gb10", "spark"));
    // One hand-written deployment, so a runtime exists. Enrollment does not
    // need one — see `offers_reach_the_agent_before_any_deployment_exists`.
    fleet.deployments.insert(
        hypellm_core::ids::DeploymentId::new("spark-music").unwrap(),
        Deployment {
            id: hypellm_core::ids::DeploymentId::new("spark-music").unwrap(),
            target: hypellm_core::ids::TargetId::new("spark:music").unwrap(),
            accelerator: AcceleratorId::new("gb10").unwrap(),
            artifact: None,
            memory_bytes: GIB,
            start_ms: 1_000,
            stop_ms: 1_000,
            drain_ms: 1_000,
            probe_ms: 1_000,
            readiness: Readiness::HttpOk,
            min_resident_ms: 0,
            evictable: true,
            pinned: false,
            autostart: true,
            retention_weight: 0,
            max_drainable_inflight: 0,
            force_stop: false,
        },
    );
    if published {
        fleet.hosts.insert(HostId::new("rig").unwrap(), host("rig"));
        fleet.accelerators.insert(
            AcceleratorId::new("rig-gpu0").unwrap(),
            accelerator("rig-gpu0", "rig"),
        );
    }
    fleet
}

const REPORT: &str = r#"{"address":"192.168.1.20","arch":"x86_64","hostname":"rig","ssh_user":"albert","data_dir":"/home/albert/.hypellm","memory_bytes":68719476736,"gpus":[{"index":0,"name":"RTX 4090","memory_bytes":25769803776}],"ssh_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M host@x","device_key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX5iBIxDSO2VYlfFZRE/T1VJfwE4OL9kokNcCposqRRI=\n-----END PUBLIC KEY-----\n","kit_version":"1.0.0"}"#;

struct Harness {
    runtime: FleetRuntime,
    agent: SimulatedAgent,
    registry: Arc<EnrollmentRegistry>,
    offerer: Arc<hypellm_router::fleet::EnrollmentOfferer>,
    fleet: FleetConfig,
    _dir: TempDir,
}

/// The agent starts on the *unpublished* fleet's digest, as an agent does
/// before it has heard of the new host, and moves to the published one when
/// it accepts an offer naming a host.
fn harness(name: &str, published: bool) -> Harness {
    let dir = TempDir::new("fleet-enroll");
    let socket = socket_in(name);
    let before = fleet(&socket, false).digest();
    let after = fleet(&socket, true).digest();
    let agent = SimulatedAgent::start(
        &socket,
        AgentScript::empty(before, KEY).with_digest_after_enroll(after),
    );

    let clock: Arc<TestClock> = Arc::new(TestClock::new());
    let dynamic: Arc<dyn Clock> = clock.clone();
    let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0).unwrap();
    let store = Arc::new(store);
    let telemetry: Arc<Telemetry> = Arc::new(Telemetry::new(
        Logger::new(
            Box::new(MemorySink::new()),
            Severity::Info,
            Arc::clone(&dynamic),
        ),
        b"pseudonym-key",
    ));
    let registry = Arc::new(EnrollmentRegistry::new(Arc::new(
        hypellm_admin_api::enroll::StoreJournal::new(Arc::clone(&store)),
    )));
    let offerer = Arc::new(hypellm_router::fleet::EnrollmentOfferer::new(
        Arc::clone(&registry),
        Arc::clone(&telemetry),
    ));
    let runtime = FleetRuntime::new(
        Arc::new(fleet(&socket, published)),
        KEY.to_vec(),
        dynamic,
        Arc::clone(&telemetry),
        store,
    )
    .expect("an enabled fleet yields a runtime")
    .with_enrollments(Arc::clone(&offerer));
    Harness {
        runtime,
        agent,
        registry,
        offerer,
        fleet: fleet(&socket, published),
        _dir: dir,
    }
}

fn approve(registry: &EnrollmentRegistry) -> String {
    let enrollment = registry
        .issue(
            NewEnrollment {
                id: "00000000000000a1".to_owned(),
                host: HostId::new("rig").unwrap(),
                agent: AgentId::new("local").unwrap(),
                token_digest: token_digest(TOKEN),
                issued_by: "user:operator".to_owned(),
                ttl_ms: 60_000,
            },
            1,
        )
        .unwrap();
    let report = wire_json::parse_str(REPORT, &wire_json::Limits::SMALL).unwrap();
    registry
        .register(TOKEN, parse_registration(&report).unwrap(), 2)
        .unwrap();
    registry
        .approve(&enrollment.id, "user:operator", 3, "draft-1".to_owned())
        .unwrap();
    enrollment.id
}

fn enroll_verbs(agent: &SimulatedAgent) -> usize {
    agent.verbs().iter().filter(|v| v.starts_with("ENROLL ")).count()
}

#[test]
fn a_published_enrollment_is_offered_and_resolves_the_digest_mismatch() {
    let h = harness("published", true);
    approve(&h.registry);

    h.runtime.observe();

    let offers = h.agent.offers();
    assert_eq!(offers.len(), 1, "one offer, naming the published host");
    let offer = String::from_utf8(offers[0].clone()).unwrap();
    assert!(offer.contains(r#""id":"rig""#), "{offer}");
    assert!(offer.contains("192.168.1.20"), "the pinned address: {offer}");
    assert!(offer.contains("ssh-ed25519 AAAA"), "the pinned host key: {offer}");
    assert!(offer.contains(r#""index":0"#), "the GPU index: {offer}");
    assert!(!offer.contains("spark"), "hand-written hosts are not offered: {offer}");

    // The offer is what made the digests agree, so the same observation went
    // on to read an inventory rather than stopping at a mismatch.
    let verbs = h.agent.verbs();
    let enroll_at = verbs.iter().position(|v| v.starts_with("ENROLL ")).unwrap();
    assert!(
        verbs[enroll_at..].iter().any(|v| v == "OBSERVE"),
        "observation proceeded after the offer: {verbs:?}"
    );

    // Nothing changed and the agent agrees: no second offer.
    h.runtime.observe();
    assert_eq!(enroll_verbs(&h.agent), 1);
}

#[test]
fn an_approval_that_is_not_yet_published_is_not_offered() {
    // Approval drafts the records; until a second person publishes them the
    // router does not route to the host, and the agent must not hold it.
    let h = harness("unpublished", false);
    approve(&h.registry);

    h.runtime.observe();

    for offer in h.agent.offers() {
        let offer = String::from_utf8(offer).unwrap();
        assert_eq!(offer, r#"{"hosts":[]}"#, "an unpublished host was offered");
    }
}

#[test]
fn a_revocation_is_offered_as_the_host_withdrawn() {
    let h = harness("revoked", true);
    let id = approve(&h.registry);
    h.runtime.observe();
    assert_eq!(enroll_verbs(&h.agent), 1);

    h.registry.revoke(&id, "user:operator", 10).unwrap();
    h.runtime.observe();

    let offers = h.agent.offers();
    assert_eq!(offers.len(), 2, "the change is offered");
    assert_eq!(
        String::from_utf8(offers[1].clone()).unwrap(),
        r#"{"hosts":[]}"#,
        "a revoked host is withdrawn from the agent"
    );
}

#[test]
fn offers_reach_the_agent_before_any_deployment_exists() {
    // A fleet with no deployment has no runtime, and enrolling the first
    // machine is exactly when that is true. The router's housekeeping calls
    // the offerer directly then; this is that call.
    let h = harness("no-runtime", true);
    approve(&h.registry);
    let mut fleet = h.fleet.clone();
    fleet.deployments.clear();
    assert!(!fleet.is_active(), "no runtime would be built for this fleet");

    let accepted = h.offerer.offer(&fleet, KEY, true);

    assert_eq!(accepted, vec![AgentId::new("local").unwrap()]);
    assert_eq!(h.agent.offers().len(), 1);
}

#[test]
fn a_router_with_no_enrollments_never_speaks_the_verb() {
    let h = harness("silent", true);
    h.runtime.observe();
    h.runtime.observe();
    assert_eq!(enroll_verbs(&h.agent), 0, "{:?}", h.agent.verbs());
}
