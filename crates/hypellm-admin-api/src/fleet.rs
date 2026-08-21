//! The `/admin/v1/fleet` surface.
//!
//! Specification-extension 17. Seven endpoints, following the conventions the
//! rest of the management API already keeps: explicit JSON, stable error codes,
//! `If-Match` on mutation, and permissions checked before anything is read.
//!
//! # Why this is a trait rather than a direct dependency
//!
//! The live fleet — sockets, sessions, leases, budgets — lives in the router,
//! which depends on this crate rather than the other way round. `FleetControl`
//! is the same shape `CredentialSink` already uses for the same reason: the
//! management API knows *what* it may ask for and the router knows *how*.
//!
//! It speaks `hypellm-fleet` types rather than a parallel set of its own,
//! because `hypellm-fleet` is pure — no I/O, no secrets — and a second copy of
//! the domain model would be two things to keep in step.
//!
//! # What these endpoints do not reveal
//!
//! Host identifiers, memory figures, and which models are co-resident are
//! management-plane data. Nothing here is reachable from the inference
//! listener, every handler requires a permission, and the data-plane errors
//! derived from the same decisions say "capability unavailable" and name
//! nothing (extension 15).

use crate::response::{ApiError, ApiErrorCode, ApiResponse};
use hypellm_fleet::activation::ActivationRecord;
use hypellm_fleet::demand::DemandSnapshot;
use hypellm_fleet::plan::PlanOutcome;
use hypellm_fleet::state::FleetSnapshot;
use std::sync::Arc;
use wire_json::{Object, Value};

/// What an operator asked to change about a deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeploymentPatch {
    /// Anchor the deployment against automatic eviction.
    pub pinned: Option<bool>,
    /// Whether the planner may consider it for eviction at all.
    pub evictable: Option<bool>,
    /// Whether routing demand may start it.
    pub autostart: Option<bool>,
}

impl DeploymentPatch {
    /// Whether the patch asks for anything.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pinned.is_none() && self.evictable.is_none() && self.autostart.is_none()
    }
}

/// The router's fleet, as the management API may act on it.
///
/// Every method is fallible and returns a stable code rather than prose: the
/// text an operator sees is authored here, and an implementation that could
/// author it would be a path for agent-supplied strings to reach a browser.
pub trait FleetControl: Send + Sync + core::fmt::Debug {
    /// The current belief, including configuration, inventory, and leases.
    fn snapshot(&self) -> Arc<FleetSnapshot>;

    /// Live demand, for the retention figures an operator reads.
    fn demand(&self) -> DemandSnapshot;

    /// Finished activations, newest last.
    fn history(&self) -> Vec<ActivationRecord>;

    /// Start a deployment on an operator's instruction.
    ///
    /// Bypasses the demand threshold — an operator asking is demand enough —
    /// but not the dwell floor, the cooldown, or the activation budget. Those
    /// exist to protect the fleet from *any* caller, including a person.
    fn activate(&self, deployment: &str) -> Result<String, &'static str>;

    /// Stop a deployment on an operator's instruction, with a drain.
    fn deactivate(&self, deployment: &str) -> Result<String, &'static str>;

    /// Acquire an artifact onto a host.
    fn fetch(&self, artifact: &str, host: &str) -> Result<String, &'static str>;

    /// Pin, unpin, or change eviction eligibility.
    fn patch(&self, deployment: &str, patch: DeploymentPatch) -> Result<(), &'static str>;

    /// Plan for a target without touching the fleet.
    fn simulate(&self, target: &str, patience_ms: u64) -> Result<PlanOutcome, &'static str>;

    /// The monotonic clock reading the snapshot should be read against.
    fn now_ms(&self) -> u64;
}

/// Map a control failure onto a stable API error.
///
/// The router returns a short code; the sentence an operator reads is written
/// here, once, so two callers cannot be told different things about the same
/// refusal.
#[must_use]
pub fn control_error(code: &'static str) -> ApiError {
    match code {
        "unknown_deployment" => ApiError::new(
            ApiErrorCode::NotFound,
            "no such deployment is declared in the active configuration",
        ),
        "unknown_artifact" => ApiError::new(
            ApiErrorCode::NotFound,
            "no such artifact is declared in the active configuration",
        ),
        "unknown_host" => ApiError::new(
            ApiErrorCode::NotFound,
            "no such host is declared in the active configuration",
        ),
        "fleet_disabled" => ApiError::new(
            ApiErrorCode::Conflict,
            "fleet orchestration is not enabled in the active configuration",
        ),
        "fleet_budget_exhausted" => ApiError::new(
            ApiErrorCode::Conflict,
            "the host's activation allowance for the trailing hour is spent; the ceiling \
             applies to operator actions as well, because it is what bounds the worst case",
        ),
        "fleet_busy" => ApiError::new(
            ApiErrorCode::Conflict,
            "the host is already performing an activation",
        ),
        "deployment_in_dwell" => ApiError::new(
            ApiErrorCode::Conflict,
            "the deployment is inside its dwell window or its reactivation cooldown",
        ),
        "fleet_state_stale" => ApiError::new(
            ApiErrorCode::Conflict,
            "the newest fleet observation is too old to act on; no plan executes on stale \
             belief",
        ),
        "fleet_configuration_mismatch" => ApiError::new(
            ApiErrorCode::Conflict,
            "the router and the fleet agent disagree about the fleet configuration; no \
             mutating verb will be issued until they agree",
        ),
        "fleet_unavailable" | "fleet_agent_unavailable" => ApiError::new(
            ApiErrorCode::Conflict,
            "the fleet agent is not reachable",
        ),
        "fleet_activation_failed" => ApiError::new(
            ApiErrorCode::Conflict,
            "the deployment did not become ready",
        ),
        "fleet_activation_timeout" => ApiError::new(
            ApiErrorCode::Conflict,
            "the activation did not complete before its deadline",
        ),
        _ => ApiError::new(
            ApiErrorCode::InternalFault,
            "the fleet action could not be completed",
        ),
    }
}

/// Render `GET /admin/v1/fleet`.
///
/// Hosts and their accelerators, what is resident on each, the activation
/// allowance remaining, and how old the belief is. The last of those is first
/// among equals: it gates every other decision, and an operator reading a
/// healthy-looking fleet against a two-hour-old observation is being misled.
#[must_use]
pub fn render_fleet(control: &dyn FleetControl) -> Value {
    let snapshot = control.snapshot();
    let demand = control.demand();
    let now = control.now_ms();
    let config = &snapshot.config;

    let mut root = Object::new();
    root.push("enabled", Value::from(config.enabled));
    root.push("digest", Value::from(config.digest().as_str()));
    root.push("agents_reachable", Value::from(snapshot.agents_reachable));
    root.push("digest_agreed", Value::from(snapshot.digest_agreed));
    match snapshot.observation_age_ms(now) {
        // Explicitly null rather than zero. A router that has never reached its
        // agent must not read as perfectly fresh, and the honesty rule says the
        // screen shows "not available" rather than a plausible number.
        None => root.push("observation_age_ms", Value::Null),
        Some(age) => root.push(
            "observation_age_ms",
            Value::from(i64::try_from(age).unwrap_or(i64::MAX)),
        ),
    }
    root.push(
        "unknown_identifiers",
        Value::from(i64::from(snapshot.inventory.unknown_identifiers)),
    );

    let mut hosts = Vec::new();
    for host in config.hosts.values() {
        let mut object = Object::new();
        object.push("id", Value::from(host.id.as_str()));
        object.push("arch", Value::from(host.arch.as_str()));
        object.push("state", Value::from(host.state.as_str()));
        object.push(
            "reserved_memory_bytes",
            Value::from(i64::try_from(host.reserved_memory_bytes).unwrap_or(i64::MAX)),
        );
        object.push(
            "activation_budget_remaining",
            Value::from(i64::from(
                snapshot
                    .activation_budget
                    .get(&host.id)
                    .copied()
                    .unwrap_or(config.policy_for(&host.id).max_activations_per_hour),
            )),
        );
        if let Some(observation) = snapshot.inventory.hosts.get(&host.id) {
            object.push("reachable", Value::from(observation.reachable));
            object.push(
                "free_disk_bytes",
                Value::from(i64::try_from(observation.free_disk_bytes).unwrap_or(i64::MAX)),
            );
        } else {
            object.push("reachable", Value::Null);
        }

        let accelerators: Vec<Value> = config
            .accelerators
            .values()
            .filter(|a| a.host == host.id)
            .map(|accelerator| {
                let mut object = Object::new();
                object.push("id", Value::from(accelerator.id.as_str()));
                object.push("kind", Value::from(accelerator.kind.as_str()));
                object.push("pool", Value::from(accelerator.pool.as_str()));
                object.push(
                    "memory_bytes",
                    Value::from(i64::try_from(accelerator.memory_bytes).unwrap_or(i64::MAX)),
                );
                object.push(
                    "pool_capacity_bytes",
                    Value::from(
                        i64::try_from(config.pool_capacity_bytes(&accelerator.pool))
                            .unwrap_or(i64::MAX),
                    ),
                );
                object.push(
                    "pool_used_bytes",
                    Value::from(
                        i64::try_from(snapshot.pool_used_bytes(&accelerator.pool))
                            .unwrap_or(i64::MAX),
                    ),
                );
                object.push(
                    "memory_drift",
                    Value::from(snapshot.memory_drift(
                        &accelerator.pool,
                        config
                            .policy_for(&host.id)
                            .memory_drift_tolerance_permille,
                    )),
                );
                Value::Object(object)
            })
            .collect();
        object.push("accelerators", Value::Array(accelerators));
        hosts.push(Value::Object(object));
    }
    root.push("hosts", Value::Array(hosts));

    let deployments: Vec<Value> = config
        .deployments
        .values()
        .map(|deployment| {
            let state = snapshot.state_of(&deployment.id);
            let mut object = Object::new();
            object.push("id", Value::from(deployment.id.as_str()));
            object.push("target", Value::from(deployment.target.as_str()));
            object.push("accelerator", Value::from(deployment.accelerator.as_str()));
            object.push("state", Value::from(state.as_str()));
            object.push("pinned", Value::from(deployment.pinned));
            object.push("evictable", Value::from(deployment.evictable));
            object.push("autostart", Value::from(deployment.autostart));
            object.push(
                "router_owned",
                Value::from(snapshot.is_router_owned(&deployment.id)),
            );
            object.push(
                "memory_bytes",
                Value::from(i64::try_from(deployment.memory_bytes).unwrap_or(i64::MAX)),
            );
            object.push(
                "resident_for_ms",
                Value::from(
                    i64::try_from(snapshot.resident_for_ms(&deployment.id, now))
                        .unwrap_or(i64::MAX),
                ),
            );
            object.push(
                "min_resident_ms",
                Value::from(i64::try_from(deployment.min_resident_ms).unwrap_or(i64::MAX)),
            );
            object.push(
                "cooldown_until_ms",
                Value::from(
                    i64::try_from(
                        snapshot
                            .cooldown_until_ms
                            .get(&deployment.id)
                            .copied()
                            .unwrap_or(0),
                    )
                    .unwrap_or(i64::MAX),
                ),
            );
            object.push(
                "idle_ms",
                match demand.idle(&deployment.id) {
                    u64::MAX => Value::Null,
                    idle => Value::from(i64::try_from(idle).unwrap_or(i64::MAX)),
                },
            );
            object.push(
                "leased",
                Value::from(snapshot.leases.contains_key(&deployment.id)),
            );
            Value::Object(object)
        })
        .collect();
    root.push("deployments", Value::Array(deployments));

    Value::Object(root)
}

/// Render `GET /admin/v1/fleet/activations`.
///
/// The "why was this evicted" view: every finished activation, what it
/// displaced, how it ended, and how long it took.
#[must_use]
pub fn render_activations(control: &dyn FleetControl) -> Value {
    let now = control.now_ms();
    let items: Vec<Value> = control
        .history()
        .iter()
        .rev()
        .map(|record| {
            let mut object = Object::new();
            object.push("deployment", Value::from(record.lease.deployment.as_str()));
            object.push("host", Value::from(record.host.as_str()));
            object.push("state", Value::from(record.state.as_str()));
            object.push(
                "outcome",
                record
                    .outcome
                    .map_or(Value::Null, |o| Value::from(o.as_str())),
            );
            object.push(
                "duration_ms",
                Value::from(i64::try_from(record.duration_ms(now)).unwrap_or(i64::MAX)),
            );
            object.push("detail", Value::from(record.detail));
            object.push(
                "decision",
                if record.lease.decision_id.is_empty() {
                    Value::Null
                } else {
                    Value::from(record.lease.decision_id.as_str())
                },
            );
            object.push(
                "evicted",
                Value::Array(
                    record
                        .evicted
                        .iter()
                        .map(|d| Value::from(d.as_str()))
                        .collect(),
                ),
            );
            Value::Object(object)
        })
        .collect();

    let mut root = Object::new();
    root.push("items", Value::Array(items));
    Value::Object(root)
}

/// Render a plan, or the reason there is none.
///
/// The whole point of a pure planner: an operator can ask what the router would
/// do, and why, without the fleet moving. Being able to ask a scheduler what it
/// is about to do is the difference between an operable system and a haunted
/// one.
#[must_use]
pub fn render_plan(outcome: &PlanOutcome) -> Value {
    let mut root = Object::new();
    root.push("class", Value::from(outcome.residency_class().as_str()));
    root.push(
        "eta_ms",
        Value::from(i64::try_from(outcome.eta_ms()).unwrap_or(i64::MAX)),
    );

    match outcome {
        PlanOutcome::Infeasible(reason) => {
            root.push("reason", Value::from(reason.code()));
            root.push("steps", Value::Array(Vec::new()));
        }
        PlanOutcome::Plan(plan) => {
            root.push("deployment", Value::from(plan.deployment.as_str()));
            root.push("host", Value::from(plan.host.as_str()));
            let steps: Vec<Value> = plan
                .steps
                .iter()
                .map(|step| {
                    let mut object = Object::new();
                    object.push("kind", Value::from(step.kind()));
                    match step {
                        hypellm_fleet::plan::PlanStep::Evict(d)
                        | hypellm_fleet::plan::PlanStep::Activate(d) => {
                            object.push("deployment", Value::from(d.as_str()));
                        }
                        hypellm_fleet::plan::PlanStep::Fetch { artifact, host } => {
                            object.push("artifact", Value::from(artifact.as_str()));
                            object.push("host", Value::from(host.as_str()));
                        }
                    }
                    Value::Object(object)
                })
                .collect();
            root.push("steps", Value::Array(steps));

            let mut trace = Object::new();
            let t = &plan.trace;
            trace.push(
                "required_bytes",
                Value::from(i64::try_from(t.required_bytes).unwrap_or(i64::MAX)),
            );
            trace.push(
                "free_bytes",
                Value::from(i64::try_from(t.free_bytes).unwrap_or(i64::MAX)),
            );
            trace.push(
                "freed_bytes",
                Value::from(i64::try_from(t.freed_bytes).unwrap_or(i64::MAX)),
            );
            trace.push("incoming_value", Value::from(t.incoming_value));
            trace.push("retained_value", Value::from(t.retained_value));
            trace.push("required_value", Value::from(t.required_value));
            trace.push(
                "budget_remaining",
                Value::from(i64::from(t.budget_remaining)),
            );
            root.push("trace", Value::Object(trace));
        }
        PlanOutcome::AlreadyResident | PlanOutcome::AlreadyActivating { .. } => {
            root.push("steps", Value::Array(Vec::new()));
        }
    }
    Value::Object(root)
}

/// The body of a successful operator action.
#[must_use]
pub fn render_accepted(activation: &str) -> ApiResponse {
    let mut root = Object::new();
    root.push("activation", Value::from(activation));
    root.push("accepted", Value::from(true));
    ApiResponse::ok(&Value::Object(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::ids::{
        AcceleratorId, AgentId, DeploymentId, HostId, PoolId, TargetId,
    };
    use hypellm_fleet::model::{
        Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, Host, HostState,
        Readiness,
    };

    #[derive(Debug)]
    struct Fake {
        snapshot: Arc<FleetSnapshot>,
        now: u64,
    }

    impl FleetControl for Fake {
        fn snapshot(&self) -> Arc<FleetSnapshot> {
            Arc::clone(&self.snapshot)
        }
        fn demand(&self) -> DemandSnapshot {
            DemandSnapshot::default()
        }
        fn history(&self) -> Vec<ActivationRecord> {
            Vec::new()
        }
        fn activate(&self, _deployment: &str) -> Result<String, &'static str> {
            Err("fleet_disabled")
        }
        fn deactivate(&self, _deployment: &str) -> Result<String, &'static str> {
            Err("fleet_disabled")
        }
        fn fetch(&self, _artifact: &str, _host: &str) -> Result<String, &'static str> {
            Err("fleet_disabled")
        }
        fn patch(&self, _deployment: &str, _patch: DeploymentPatch) -> Result<(), &'static str> {
            Err("fleet_disabled")
        }
        fn simulate(&self, _target: &str, _patience_ms: u64) -> Result<PlanOutcome, &'static str> {
            Err("fleet_disabled")
        }
        fn now_ms(&self) -> u64 {
            self.now
        }
    }

    fn fleet() -> FleetConfig {
        let mut fleet = FleetConfig::empty();
        fleet.enabled = true;
        fleet.agents.insert(
            AgentId::new("local").expect("id"),
            FleetAgent {
                id: AgentId::new("local").expect("id"),
                socket: "/run/hypellm/fleet.sock".to_owned(),
                observation_interval_ms: 5_000,
                observation_max_age_ms: 30_000,
                request_timeout_ms: 5_000,
            },
        );
        fleet.hosts.insert(
            HostId::new("spark").expect("id"),
            Host {
                id: HostId::new("spark").expect("id"),
                agent: AgentId::new("local").expect("id"),
                arch: Arch::Aarch64,
                state: HostState::Enabled,
                reserved_memory_bytes: 16,
                max_concurrent_activations: 1,
            },
        );
        fleet.accelerators.insert(
            AcceleratorId::new("gb10").expect("id"),
            Accelerator {
                id: AcceleratorId::new("gb10").expect("id"),
                host: HostId::new("spark").expect("id"),
                kind: AcceleratorKind::Unified,
                memory_bytes: 140,
                pool: PoolId::new("spark-unified").expect("id"),
            },
        );
        fleet.deployments.insert(
            DeploymentId::new("spark-music3").expect("id"),
            Deployment {
                id: DeploymentId::new("spark-music3").expect("id"),
                target: TargetId::new("spark:music3").expect("id"),
                accelerator: AcceleratorId::new("gb10").expect("id"),
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

    #[test]
    fn a_router_that_has_never_observed_reports_a_null_age_rather_than_zero() {
        // The honesty rule, in one field. A dashboard showing a router that has
        // never reached its agent as perfectly fresh is worse than one showing
        // nothing.
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(fleet());
        let control = Fake {
            snapshot: Arc::new(snapshot),
            now: 60_000,
        };
        let rendered = render_fleet(&control);
        assert_eq!(rendered.get("observation_age_ms"), Some(&Value::Null));
    }

    #[test]
    fn the_fleet_view_reports_pool_capacity_after_the_host_reservation() {
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(fleet());
        snapshot.observed = true;
        snapshot.observed_at_ms = 1_000;
        let control = Fake {
            snapshot: Arc::new(snapshot),
            now: 2_000,
        };
        let rendered = render_fleet(&control);
        let hosts = rendered.get("hosts").and_then(Value::as_array).expect("hosts");
        let accelerators = hosts
            .first()
            .and_then(|h| h.get("accelerators"))
            .and_then(Value::as_array)
            .expect("accelerators");
        let capacity = accelerators
            .first()
            .and_then(|a| a.get("pool_capacity_bytes"))
            .and_then(Value::as_i64);
        assert_eq!(capacity, Some(140 - 16));
        assert_eq!(
            rendered.get("observation_age_ms").and_then(Value::as_i64),
            Some(1_000)
        );
    }

    #[test]
    fn a_refusal_carries_a_sentence_the_router_did_not_author() {
        // The agent is trusted to actuate, not to write text an operator reads.
        // Every message here is a literal in this file.
        for code in [
            "unknown_deployment",
            "fleet_budget_exhausted",
            "deployment_in_dwell",
            "fleet_configuration_mismatch",
            "something-the-agent-made-up",
        ] {
            let error = control_error(code);
            assert!(!error.message.is_empty());
            assert!(
                !error.message.contains(code),
                "a code must never be echoed into the sentence an operator reads: {code}"
            );
        }
    }
}
