//! Image sync between slaves, and the checksums it is verified against
//! (specification 26.12).
//!
//! Real client, real Unix socket, the simulated agent, a `TestClock`. The
//! simulated agent stands in for the relay: a `COPY` it accepts completes
//! only when what the source "sent" hashes to the image ID the router asked
//! for, and a completed copy appears in the next inventory on the
//! destination. What these tests check is the router's half — which source it
//! picks, what it refuses, what it learns and keeps, and what it audits.

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
    Accelerator, AcceleratorKind, Arch, Artifact, ArtifactKind, Deployment, FleetAgent,
    FleetConfig, Host, HostState, ImageId, Readiness,
};
use hypellm_fleet::plan::{PlanContext, PlanOutcome, PlanStep};
use hypellm_net::fleet_sim::{AgentScript, Behaviour, SimulatedAgent};
use hypellm_router::fleet::{ActivationResult, FleetRuntime};
use hypellm_store::audit::AuditAction;
use hypellm_store::frame::RecordKind;
use hypellm_store::{Store, TempDir};
use hypellm_telemetry::{Logger, MemorySink, Severity, Telemetry};
use std::sync::Arc;

const KEY: &[u8] = b"a-fleet-key-for-these-tests-0123456789";
const STORE_KEY: &[u8] = b"a-store-mac-key-for-these-tests";
const GIB: u64 = 1024 * 1024 * 1024;

fn image(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn host(id: &str) -> Host {
    Host {
        id: HostId::new(id).unwrap(),
        agent: AgentId::new("local").unwrap(),
        arch: Arch::Aarch64,
        state: HostState::Enabled,
        reserved_memory_bytes: 0,
        max_concurrent_activations: 1,
    }
}

/// Two hosts. `music3` is deployed on `rig` only; `spark` is where a verified
/// copy of its image lives.
fn fleet(socket: &str, pinned: Option<&str>) -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = true;
    fleet.default_policy.allow_fetch = true;
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
    for name in ["rig", "spark"] {
        fleet.hosts.insert(HostId::new(name).unwrap(), host(name));
        let accelerator = AcceleratorId::new(format!("{name}-gpu0")).unwrap();
        fleet.accelerators.insert(
            accelerator.clone(),
            Accelerator {
                id: accelerator,
                host: HostId::new(name).unwrap(),
                kind: AcceleratorKind::Cuda,
                memory_bytes: 24 * GIB,
                pool: PoolId::new(format!("{name}-gpu0")).unwrap(),
            },
        );
    }
    let artifact = ArtifactId::new("music3").unwrap();
    fleet.artifacts.insert(
        artifact.clone(),
        Artifact {
            id: artifact.clone(),
            kind: ArtifactKind::Image,
            arch: Arch::Aarch64,
            size_bytes: GIB,
            digest: format!("sha256:{}", "0".repeat(64)),
            image_id: pinned.map(|p| ImageId::parse(p).unwrap()),
            source: "mirror".to_owned(),
        },
    );
    fleet.deployments.insert(
        DeploymentId::new("rig-music3").unwrap(),
        Deployment {
            id: DeploymentId::new("rig-music3").unwrap(),
            target: TargetId::new("rig:music3").unwrap(),
            accelerator: AcceleratorId::new("rig-gpu0").unwrap(),
            artifact: Some(artifact),
            memory_bytes: 8 * GIB,
            start_ms: 60_000,
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
        },
    );
    fleet
}

struct Harness {
    runtime: Arc<FleetRuntime>,
    clock: Arc<TestClock>,
    agent: SimulatedAgent,
    store: Arc<Store>,
}

fn socket_in(name: &str) -> String {
    format!("/tmp/hypellm-copy-{name}-{}.sock", std::process::id())
}

fn harness(
    fleet: FleetConfig,
    dir: &TempDir,
    script: impl FnOnce(AgentScript) -> AgentScript,
) -> Harness {
    let socket = fleet.agents.values().next().unwrap().socket.clone();
    let _ = std::fs::remove_file(&socket);
    let digest = fleet.digest();
    let agent = SimulatedAgent::start(
        &socket,
        script(
            AgentScript::empty(digest, KEY)
                .with_deployment("rig-music3", Behaviour::ReadyAfter(1))
                .with_state("rig-music3", "stopped")
                .with_artifact("music3")
                .with_observed_host("rig")
                .with_observed_host("spark"),
        ),
    );
    let clock: Arc<TestClock> = Arc::new(TestClock::new());
    let (store, _) = Store::open(dir.path(), STORE_KEY, 0).unwrap();
    let store = Arc::new(store);
    let dynamic: Arc<dyn Clock> = clock.clone();
    let telemetry = Arc::new(Telemetry::new(
        Logger::new(Box::new(MemorySink::new()), Severity::Info, Arc::clone(&dynamic)),
        b"pseudonym-key",
    ));
    let runtime = FleetRuntime::new(
        Arc::new(fleet),
        KEY.to_vec(),
        dynamic,
        telemetry,
        Arc::clone(&store),
    )
    .expect("an enabled fleet yields a runtime");
    Harness {
        runtime: Arc::new(runtime),
        clock,
        agent,
        store,
    }
}

fn context(now_ms: u64) -> PlanContext {
    PlanContext {
        now_ms,
        deadline_remaining_ms: 900_000,
        effort_multiplier: 1,
        effort_headroom_ms: 5_000,
        may_activate: true,
        may_fetch: true,
        capability: Some(Capability::TextToMusic),
        priority_bonus: 0,
    }
}

fn audits(h: &Harness, action: AuditAction) -> usize {
    h.store
        .audit_records(None, 500)
        .unwrap()
        .iter()
        .filter(|(_, r)| r.event.action == action)
        .count()
}

fn start(h: &Harness) -> (Vec<PlanStep>, ActivationResult) {
    h.runtime.observe();
    let target = TargetId::new("rig:music3").unwrap();
    let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
        &h.runtime.snapshot(),
        &DemandSnapshot::default(),
        &target,
        &context(h.clock.now_millis()),
    ) else {
        panic!("the activation must be plannable");
    };
    let result = h.runtime.ensure_ready(&target, &plan, "copy-test", 900_000);
    (plan.steps, result)
}

#[test]
fn a_cold_host_gets_its_image_by_verified_copy_and_the_copy_names_only_tokens() {
    let dir = TempDir::new("copy-planned");
    let h = harness(fleet(&socket_in("planned"), Some(&image('a'))), &dir, |s| {
        s.with_placement("music3", "spark", &image('a'))
    });

    let (steps, result) = start(&h);
    assert!(
        matches!(&steps[0], PlanStep::Copy { from, to, .. }
            if from.as_str() == "spark" && to.as_str() == "rig"),
        "a verified peer must be preferred to the registry: {steps:?}"
    );
    assert_eq!(result, ActivationResult::Ready);
    assert_eq!(h.agent.placement("music3", "rig"), Some(image('a')));

    let copy = h
        .agent
        .verbs()
        .into_iter()
        .find(|v| v.starts_with("COPY "))
        .expect("a COPY crossed the socket");
    let tokens: Vec<&str> = copy.split(' ').collect();
    assert_eq!(tokens.len(), 6, "{copy}");
    assert_eq!(&tokens[..4], ["COPY", "music3", "spark", "rig"]);
    assert!(tokens[4].parse::<u64>().is_ok(), "{copy}");
    assert_eq!(tokens[5], image('a'));
    assert!(
        h.agent.verbs().iter().all(|v| !v.starts_with("FETCH ")),
        "nothing went to the registry"
    );
    assert_eq!(audits(&h, AuditAction::FleetCopy), 1);
}

#[test]
fn a_tampered_relay_loads_nothing_and_the_model_is_not_started() {
    let dir = TempDir::new("copy-tampered");
    let h = harness(fleet(&socket_in("tampered"), Some(&image('a'))), &dir, |s| {
        s.with_placement("music3", "spark", &image('a'))
            // The source claims the kept ID, but what it actually sends
            // hashes to something else.
            .with_relay_yielding("music3", &image('e'))
    });

    let (_, result) = start(&h);
    assert!(
        matches!(result, ActivationResult::Failed { .. }),
        "a copy that failed verification must not count as acquired: {result:?}"
    );
    assert_eq!(h.agent.placement("music3", "rig"), None, "nothing was loaded on rig");
    assert!(
        h.agent.verbs().iter().all(|v| !v.starts_with("ACTIVATE ")),
        "the model must not be started on an image that did not verify: {:?}",
        h.agent.verbs()
    );
}

#[test]
fn a_host_holding_another_image_under_the_name_is_neither_started_nor_a_source() {
    let dir = TempDir::new("copy-liar");
    // `rig` holds something else under `music3`, and is audited for it. It
    // must not be activated as if it held the model: the planner acquires
    // the real image first, from the honest host.
    let h = harness(fleet(&socket_in("liar"), Some(&image('a'))), &dir, |s| {
        s.with_placement("music3", "spark", &image('a'))
            .with_placement("music3", "rig", &image('b'))
    });
    h.runtime.observe();
    let snapshot = h.runtime.snapshot();
    let music3 = ArtifactId::new("music3").unwrap();
    let rig = HostId::new("rig").unwrap();
    assert!(snapshot.artifact_tampered(&music3, &rig));
    assert!(!snapshot.artifact_ready(&music3, &rig));
    assert_eq!(snapshot.copy_source(&music3, &HostId::new("spark").unwrap()), None);
    assert_eq!(audits(&h, AuditAction::FleetArtifactTampered), 1);
    // Reported once, not on every observation.
    h.runtime.observe();
    assert_eq!(audits(&h, AuditAction::FleetArtifactTampered), 1);

    // The operator path refuses a tampered source outright.
    assert_eq!(
        h.runtime
            .copy_artifact(&music3, &rig, &HostId::new("spark").unwrap())
            .err(),
        Some("copy_source_unverified")
    );
    assert!(h.agent.verbs().iter().all(|v| !v.starts_with("COPY ")));

    let (steps, result) = start(&h);
    assert!(
        matches!(&steps[0], PlanStep::Copy { from, .. } if from.as_str() == "spark"),
        "{steps:?}"
    );
    assert_eq!(result, ActivationResult::Ready);
    assert_eq!(h.agent.placement("music3", "rig"), Some(image('a')));
}

#[test]
fn a_learned_checksum_is_kept_durably_and_survives_a_restart() {
    let dir = TempDir::new("copy-learned");
    let music3 = ArtifactId::new("music3").unwrap();
    {
        let h = harness(fleet(&socket_in("learn-1"), None), &dir, |s| {
            s.with_placement("music3", "spark", &image('a'))
        });
        h.runtime.observe();
        assert_eq!(
            h.runtime.snapshot().kept_checksum(&music3).map(ImageId::as_str),
            Some(image('a').as_str())
        );
        assert_eq!(
            h.store
                .records_of_kinds(&[RecordKind::ArtifactChecksum])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(audits(&h, AuditAction::FleetChecksumLearned), 1);
        // Learned once: a second observation writes nothing new.
        h.runtime.observe();
        assert_eq!(
            h.store
                .records_of_kinds(&[RecordKind::ArtifactChecksum])
                .unwrap()
                .len(),
            1
        );
    }

    // After a restart the honest host has gone and a liar reports a
    // different ID, verified as far as its own registry check goes. The
    // anchor is what was kept, not what is reported now.
    let h = harness(fleet(&socket_in("learn-2"), None), &dir, |s| {
        s.with_placement("music3", "rig", &image('b'))
    });
    h.runtime.recover();
    let snapshot = h.runtime.snapshot();
    assert_eq!(
        snapshot.kept_checksum(&music3).map(ImageId::as_str),
        Some(image('a').as_str())
    );
    assert!(snapshot.artifact_tampered(&music3, &HostId::new("rig").unwrap()));
}

#[test]
fn verified_hosts_that_disagree_teach_nothing() {
    let dir = TempDir::new("copy-conflict");
    let h = harness(fleet(&socket_in("conflict"), None), &dir, |s| {
        s.with_placement("music3", "spark", &image('a'))
            .with_placement("music3", "rig", &image('b'))
    });
    h.runtime.observe();
    assert_eq!(
        h.runtime
            .snapshot()
            .kept_checksum(&ArtifactId::new("music3").unwrap()),
        None
    );
    assert!(
        h.store
            .records_of_kinds(&[RecordKind::ArtifactChecksum])
            .unwrap()
            .is_empty()
    );
}
