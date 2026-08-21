//! The `/admin/v1/fleet` surface.
//!
//! Specification-extension 17. The properties asserted here are the ones a
//! reviewer would want checked: nothing is served without a permission, an
//! operator action is refused unless it was also *recorded*, a simulation
//! changes nothing, and an absent fleet says so rather than rendering rows that
//! read as a healthy idle one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

mod harness;

use harness::{Harness, TENANT_A, TestSession};
use hypellm_admin_api::{DeploymentPatch, FleetControl};
use hypellm_core::ids::{
    AcceleratorId, AgentId, DeploymentId, HostId, PoolId, TargetId,
};
use hypellm_core::rbac::Role;
use hypellm_fleet::activation::ActivationRecord;
use hypellm_fleet::demand::DemandSnapshot;
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, Host, HostState,
    Readiness,
};
use hypellm_fleet::plan::PlanOutcome;
use hypellm_fleet::state::FleetSnapshot;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// A fleet control that records what it was asked and answers as scripted.
#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<String>>,
    activations: AtomicU32,
    refuse: Mutex<Option<&'static str>>,
}

impl Recorder {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn record(&self, what: &str) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(what.to_owned());
        }
    }

    fn refusing(code: &'static str) -> Arc<Self> {
        let recorder = Arc::new(Self::default());
        if let Ok(mut refuse) = recorder.refuse.lock() {
            *refuse = Some(code);
        }
        recorder
    }

    fn refusal(&self) -> Option<&'static str> {
        self.refuse.lock().ok().and_then(|r| *r)
    }
}

fn fleet() -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = true;
    fleet.agents.insert(
        AgentId::new("local").unwrap(),
        FleetAgent {
            id: AgentId::new("local").unwrap(),
            socket: "/run/hypellm/fleet.sock".to_owned(),
            observation_interval_ms: 5_000,
            observation_max_age_ms: 30_000,
            request_timeout_ms: 5_000,
        },
    );
    fleet.hosts.insert(
        HostId::new("spark").unwrap(),
        Host {
            id: HostId::new("spark").unwrap(),
            agent: AgentId::new("local").unwrap(),
            arch: Arch::Aarch64,
            state: HostState::Enabled,
            reserved_memory_bytes: 16,
            max_concurrent_activations: 1,
        },
    );
    fleet.accelerators.insert(
        AcceleratorId::new("gb10").unwrap(),
        Accelerator {
            id: AcceleratorId::new("gb10").unwrap(),
            host: HostId::new("spark").unwrap(),
            kind: AcceleratorKind::Unified,
            memory_bytes: 140,
            pool: PoolId::new("spark-unified").unwrap(),
        },
    );
    fleet.deployments.insert(
        DeploymentId::new("spark-music3").unwrap(),
        Deployment {
            id: DeploymentId::new("spark-music3").unwrap(),
            target: TargetId::new("spark:music3").unwrap(),
            accelerator: AcceleratorId::new("gb10").unwrap(),
            artifact: None,
            memory_bytes: 64,
            start_ms: 1,
            stop_ms: 1,
            drain_ms: 1,
            probe_ms: 1,
            readiness: Readiness::HttpOk,
            min_resident_ms: 1,
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

impl FleetControl for Recorder {
    fn snapshot(&self) -> Arc<FleetSnapshot> {
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(fleet());
        snapshot.observed = true;
        snapshot.observed_at_ms = 1_000;
        Arc::new(snapshot)
    }
    fn demand(&self) -> DemandSnapshot {
        DemandSnapshot::default()
    }
    fn history(&self) -> Vec<ActivationRecord> {
        Vec::new()
    }
    fn activate(&self, deployment: &str) -> Result<String, &'static str> {
        self.record(&format!("activate:{deployment}"));
        if let Some(code) = self.refusal() {
            return Err(code);
        }
        self.activations.fetch_add(1, Ordering::SeqCst);
        Ok(deployment.to_owned())
    }
    fn deactivate(&self, deployment: &str) -> Result<String, &'static str> {
        self.record(&format!("deactivate:{deployment}"));
        if let Some(code) = self.refusal() {
            return Err(code);
        }
        Ok(deployment.to_owned())
    }
    fn fetch(&self, artifact: &str, host: &str) -> Result<String, &'static str> {
        self.record(&format!("fetch:{artifact}:{host}"));
        if let Some(code) = self.refusal() {
            return Err(code);
        }
        Ok(artifact.to_owned())
    }
    fn patch(&self, deployment: &str, patch: DeploymentPatch) -> Result<(), &'static str> {
        self.record(&format!("patch:{deployment}:{patch:?}"));
        if let Some(code) = self.refusal() {
            return Err(code);
        }
        Ok(())
    }
    fn simulate(&self, target: &str, _patience_ms: u64) -> Result<PlanOutcome, &'static str> {
        self.record(&format!("simulate:{target}"));
        Ok(PlanOutcome::Infeasible(
            hypellm_core::decision::ExclusionReason::DeploymentInDwell,
        ))
    }
    fn now_ms(&self) -> u64 {
        2_000
    }
}

fn harness_with(control: Arc<Recorder>) -> (Harness, Arc<Recorder>) {
    let shared: Arc<dyn FleetControl> = Arc::clone(&control) as Arc<dyn FleetControl>;
    (Harness::builder().fleet(shared).build(), control)
}

fn session(admin: &Harness, role: Role) -> TestSession {
    admin.session("user:operator", TENANT_A, &[role])
}

/// Whether the durable audit chain holds an event with this action.
fn audited(admin: &Harness, action: &str) -> bool {
    let auditor = admin.auditor();
    let response = admin.get(&auditor, "/admin/v1/audit");
    response.body_contains(action)
}

#[test]
fn a_router_with_no_fleet_says_so_rather_than_serving_empty_rows() {
    // The honesty rule: a screen with no backing endpoint renders an explicit
    // "not available", never plausible-looking rows that read as a healthy
    // idle fleet.
    let admin = Harness::builder().build();
    let session = session(&admin, Role::Operator);
    let response = admin.get(&session, "/admin/v1/fleet");
    assert_eq!(response.status, 404);
    assert!(
        response.body_contains("not configured"),
        "the refusal must say why, not merely 404"
    );
}

#[test]
fn the_fleet_view_requires_a_permission() {
    let (admin, _) = harness_with(Arc::new(Recorder::default()));
    // A viewer holds `read_summary` and not `read_fleet`: host identifiers,
    // memory figures, and co-residency are not summary data.
    let viewer = session(&admin, Role::Viewer);
    let response = admin.get(&viewer, "/admin/v1/fleet");
    assert_eq!(response.status, 403);

    let operator = session(&admin, Role::Operator);
    let response = admin.get(&operator, "/admin/v1/fleet");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.json().get("enabled").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn an_activation_requires_the_fleet_permission_and_is_audited() {
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));

    // A policy editor may simulate but not act.
    let editor = session(&admin, Role::PolicyEditor);
    let refused = admin.post(&editor, "/admin/v1/fleet/deployments/spark-music3:activate", "{}");
    assert_eq!(refused.status, 403);
    assert!(
        recorder.calls().is_empty(),
        "an unauthorized caller must not reach the fleet at all"
    );

    let operator = session(&admin, Role::Operator);
    let response = admin.post(&operator, "/admin/v1/fleet/deployments/spark-music3:activate", "{}");
    assert_eq!(response.status, 200);
    assert_eq!(recorder.calls(), vec!["activate:spark-music3".to_owned()]);
    assert!(
        audited(&admin, "fleet.activate"),
        "every model that starts is traceable to who asked"
    );
}

#[test]
fn a_refused_activation_is_reported_with_the_reason_and_not_audited_as_success() {
    let (admin, recorder) = harness_with(Recorder::refusing("deployment_in_dwell"));
    let operator = session(&admin, Role::Operator);
    let response = admin.post(&operator, "/admin/v1/fleet/deployments/spark-music3:activate", "{}");
    assert_eq!(response.status, 409);
    assert!(!recorder.calls().is_empty());
    assert!(
        !audited(&admin, "fleet.activate"),
        "an action that did not happen must not be recorded as though it did"
    );
}

#[test]
fn a_fetch_needs_its_own_permission_which_no_default_role_carries() {
    // The one action on which a single request can cost the fleet hours of
    // bandwidth and hundreds of gigabytes of disk.
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));
    for role in [Role::Operator, Role::PolicyEditor, Role::CredentialManager] {
        let session = admin.session("user:operator", TENANT_A, &[role]);
        let response = admin.post(
            &session,
            "/admin/v1/fleet/artifacts/music3:fetch",
            r#"{"host":"spark"}"#,
        );
        assert_eq!(
            response.status, 403,
            "{role:?} must not be able to start a download"
        );
    }
    assert!(recorder.calls().is_empty());
}

#[test]
fn a_simulation_touches_nothing_and_needs_only_the_simulate_permission() {
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));
    let editor = session(&admin, Role::PolicyEditor);
    let response = admin.post(
        &editor,
        "/admin/v1/fleet:simulate",
        r#"{"target":"spark:music3","patience_ms":900000}"#,
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.json().get("reason").and_then(|v| v.as_str()),
        Some("deployment_in_dwell"),
        "a simulation says why, which is the whole point of asking"
    );
    assert_eq!(recorder.calls(), vec!["simulate:spark:music3".to_owned()]);
    assert_eq!(
        recorder.activations.load(Ordering::SeqCst),
        0,
        "a simulation must not activate anything"
    );
}

#[test]
fn a_deployment_patch_must_ask_for_something() {
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));
    let operator = session(&admin, Role::Operator);
    let response =
        admin.patch_without_if_match(&operator, "/admin/v1/fleet/deployments/spark-music3", "{}");
    assert_eq!(response.status, 400);
    assert!(recorder.calls().is_empty());

    let response = admin.patch_without_if_match(
        &operator,
        "/admin/v1/fleet/deployments/spark-music3",
        r#"{"pinned":true}"#,
    );
    assert_eq!(response.status, 200);
    assert!(recorder.calls()[0].starts_with("patch:spark-music3"));
}

#[test]
fn a_mutating_fleet_action_needs_a_csrf_token() {
    // The same rule every other mutation follows; asserted here because these
    // are the mutations that stop production models.
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));
    let operator = session(&admin, Role::Operator);
    let response = admin
        .request(harness::method_post(), "/admin/v1/fleet/deployments/spark-music3:activate")
        .as_session(&operator)
        .without_csrf()
        .json("{}")
        .send();
    assert_eq!(response.status, 403);
    assert!(recorder.calls().is_empty());
}

#[test]
fn the_activations_view_is_readable_by_an_operator() {
    let (admin, _) = harness_with(Arc::new(Recorder::default()));
    let operator = session(&admin, Role::Operator);
    let response = admin.get(&operator, "/admin/v1/fleet/activations");
    assert_eq!(response.status, 200);
    assert!(response.json().get("items").is_some());
}

#[test]
fn an_unknown_fleet_action_is_a_not_found_rather_than_a_silent_success() {
    let (admin, recorder) = harness_with(Arc::new(Recorder::default()));
    let operator = session(&admin, Role::Operator);
    let response = admin.post(&operator, "/admin/v1/fleet/deployments/spark-music3:obliterate", "{}");
    assert_eq!(response.status, 404);
    assert!(recorder.calls().is_empty());
}
