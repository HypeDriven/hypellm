//! Observation, belief, and intent.
//!
//! Four things, never conflated. Conflating them is how orchestrators come to
//! fight their operators.
//!
//! | | Source | Trust |
//! |---|---|---|
//! | **Configuration** | The activated fleet snapshot | Authoritative for what *may* exist |
//! | **Observation** | The agent's `OBSERVE` reply | Untrusted input; the only source of what *is* |
//! | **Intent** | The router's own leases in durable state | Authoritative for what the router *asked for* |
//! | **Belief** | The last valid observation plus its age | Advisory, and expires |
//!
//! # The agent's report is untrusted input
//!
//! It arrives as JSON over a socket. It is parsed by `wire-json` under explicit
//! limits; unknown identifiers are dropped and counted rather than adopted;
//! every numeric field is range-checked; and a reply that violates a bound
//! fails the whole observation rather than partially updating belief. A
//! half-applied observation is worse than none, because the router would then
//! plan against a mixture of two moments.

use crate::model::{Arch, FleetConfig};
use core::fmt;
use hypellm_core::ids::{AcceleratorId, ArtifactId, DeploymentId, HostId, LeaseId, TargetId};
use hypellm_core::target::Capability;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use wire_json::{Limits, Value};

/// Maximum bytes of inventory the router will accept from an agent.
pub const MAX_INVENTORY_BYTES: usize = 256 * 1024;

/// Maximum hosts one inventory may describe.
pub const MAX_INVENTORY_HOSTS: usize = 64;

/// Maximum accelerators one inventory may describe.
pub const MAX_INVENTORY_ACCELERATORS: usize = 256;

/// Maximum deployments one inventory may describe.
pub const MAX_INVENTORY_DEPLOYMENTS: usize = 512;

/// Maximum artifact placements one inventory may describe.
pub const MAX_INVENTORY_ARTIFACTS: usize = 1_024;

/// JSON limits applied to an inventory payload.
///
/// A named constant rather than `Limits::SMALL`, because the inventory is
/// larger than a claims document and the bound is part of the protocol rather
/// than an implementation detail of one call site.
#[must_use]
pub fn inventory_limits() -> Limits {
    Limits::SMALL.with_max_input_bytes(MAX_INVENTORY_BYTES)
}

/// The lifecycle state the agent reports for a deployment.
///
/// A closed vocabulary. An unrecognised state fails the observation rather
/// than mapping to something plausible: an agent and a router that disagree
/// about what a state means must not act on the disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservedState {
    /// Accepted, not yet acted on.
    Pending,
    /// Finishing in-flight work before stopping.
    Draining,
    /// Stopping.
    Stopping,
    /// Acquiring an artifact.
    Fetching,
    /// Starting.
    Starting,
    /// Started; readiness not yet confirmed.
    Probing,
    /// Ready to serve.
    Ready,
    /// Terminal failure.
    Failed,
    /// Not running.
    Stopped,
    /// Cancelled before completion.
    Cancelled,
}

impl ObservedState {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::Fetching => "fetching",
            Self::Starting => "starting",
            Self::Probing => "probing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parse an agent-supplied token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "draining" => Self::Draining,
            "stopping" => Self::Stopping,
            "fetching" => Self::Fetching,
            "starting" => Self::Starting,
            "probing" => Self::Probing,
            "ready" => Self::Ready,
            "failed" => Self::Failed,
            "stopped" => Self::Stopped,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    /// Whether the deployment can serve traffic in this state.
    #[must_use]
    pub const fn is_serving(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether the deployment is holding memory in this state.
    ///
    /// A starting model has already begun mapping weights, and a draining one
    /// has not released them. Treating either as free is how a planner starts
    /// a second model into memory the first has not given back.
    #[must_use]
    pub const fn holds_memory(self) -> bool {
        matches!(
            self,
            Self::Draining | Self::Stopping | Self::Starting | Self::Probing | Self::Ready
        )
    }

    /// Whether the deployment is on its way up.
    #[must_use]
    pub const fn is_activating(self) -> bool {
        matches!(self, Self::Pending | Self::Fetching | Self::Starting | Self::Probing)
    }

    /// Whether this is a terminal state for an activation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Failed | Self::Stopped | Self::Cancelled
        )
    }

    /// Every state, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Pending,
            Self::Draining,
            Self::Stopping,
            Self::Fetching,
            Self::Starting,
            Self::Probing,
            Self::Ready,
            Self::Failed,
            Self::Stopped,
            Self::Cancelled,
        ]
    }
}

impl fmt::Display for ObservedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the agent reports about one deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentObservation {
    /// Which deployment.
    pub deployment: DeploymentId,
    /// Its lifecycle state.
    pub state: ObservedState,
    /// Memory the agent observes it using, as reported by the accelerator.
    ///
    /// Zero when the agent cannot tell. Observed rather than configured, so
    /// the router can detect drift between the declaration and the hardware.
    pub observed_memory_bytes: u64,
    /// How long it has been in this state.
    pub state_age_ms: u64,
    /// Requests the agent believes are in flight against it.
    ///
    /// Advisory: the router's own admission accounting is authoritative for
    /// its traffic, and this covers work the router did not send.
    pub inflight: u32,
}

/// What the agent reports about one accelerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratorObservation {
    /// Which accelerator.
    pub accelerator: AcceleratorId,
    /// Memory in use, from the device.
    pub used_memory_bytes: u64,
    /// Memory the device reports in total.
    pub total_memory_bytes: u64,
}

/// What the agent reports about one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostObservation {
    /// Which host.
    pub host: HostId,
    /// Whether the agent could reach it.
    pub reachable: bool,
    /// Free disk on the volume artifacts are stored on.
    pub free_disk_bytes: u64,
    /// Architecture the host reports.
    ///
    /// Compared against the configured one; a mismatch is a divergence worth
    /// auditing rather than something to adopt, because an artifact was chosen
    /// against the configured value.
    pub arch: Option<Arch>,
}

/// Where an artifact is, and whether it is usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPlacement {
    /// Which artifact.
    pub artifact: ArtifactId,
    /// Which host holds it.
    pub host: HostId,
    /// Whether the whole artifact is present.
    pub present: bool,
    /// Whether the agent has verified its digest.
    ///
    /// An unverified artifact is not activatable. The router does not verify
    /// digests itself — it never holds the bytes — so this is the agent's
    /// assertion and the reason `FETCH` and `ACTIVATE` are separate verbs.
    pub verified: bool,
    /// Bytes present, for a partial fetch.
    pub bytes_present: u64,
}

/// One complete, valid observation of the fleet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Host reports, by identifier.
    pub hosts: BTreeMap<HostId, HostObservation>,
    /// Accelerator reports, by identifier.
    pub accelerators: BTreeMap<AcceleratorId, AcceleratorObservation>,
    /// Deployment reports, by identifier.
    pub deployments: BTreeMap<DeploymentId, DeploymentObservation>,
    /// Artifact placements, keyed by artifact and host.
    pub artifacts: BTreeMap<(ArtifactId, HostId), ArtifactPlacement>,
    /// Identifiers the agent named that the configuration does not declare.
    ///
    /// Counted, never adopted. A non-zero count means the two sides' fleets
    /// have diverged and is worth an operator's attention, but it must not
    /// change a routing decision — adopting an identifier the router cannot
    /// resolve would be taking the agent's word for what exists.
    pub unknown_identifiers: u32,
}

/// Why an inventory was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    /// The payload was not valid JSON within the limits.
    Malformed,
    /// The payload exceeded a declared bound.
    TooLarge {
        /// Which bound.
        what: &'static str,
    },
    /// A field held a value outside its permitted range.
    OutOfRange {
        /// Which field.
        field: &'static str,
    },
    /// A field held a token outside its closed vocabulary.
    UnknownToken {
        /// Which field.
        field: &'static str,
    },
}

impl InventoryError {
    /// Stable code for logs and metrics.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "inventory_malformed",
            Self::TooLarge { .. } => "inventory_too_large",
            Self::OutOfRange { .. } => "inventory_out_of_range",
            Self::UnknownToken { .. } => "inventory_unknown_token",
        }
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("the inventory payload is not valid JSON"),
            Self::TooLarge { what } => write!(f, "the inventory exceeds the {what} bound"),
            Self::OutOfRange { field } => write!(f, "inventory field '{field}' is out of range"),
            Self::UnknownToken { field } => {
                write!(f, "inventory field '{field}' holds an unrecognised value")
            }
        }
    }
}

impl std::error::Error for InventoryError {}

/// Read a bounded unsigned integer from an agent-supplied field.
///
/// A negative or oversized number is an error rather than a clamp: the agent
/// is reporting what the hardware said, and a figure the router had to correct
/// is a figure it should not plan against.
fn observed_u64(
    value: &Value,
    key: &str,
    field: &'static str,
) -> Result<u64, InventoryError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v.as_u64().ok_or(InventoryError::OutOfRange { field }),
    }
}

fn observed_u32(
    value: &Value,
    key: &str,
    field: &'static str,
) -> Result<u32, InventoryError> {
    let raw = observed_u64(value, key, field)?;
    u32::try_from(raw).map_err(|_| InventoryError::OutOfRange { field })
}

/// Parse an agent inventory against the declared fleet.
///
/// Anything the configuration does not declare is dropped and counted. That is
/// the whole security property of this function: a compromised or confused
/// agent can withhold information, and can lie about the state of a deployment
/// the router already knows about — which the divergence and drift rules
/// handle — but it cannot introduce a host, an accelerator, a deployment, or an
/// artifact that the administrator did not write down.
pub fn parse_inventory(
    payload: &[u8],
    fleet: &FleetConfig,
) -> Result<Inventory, InventoryError> {
    if payload.len() > MAX_INVENTORY_BYTES {
        return Err(InventoryError::TooLarge { what: "payload" });
    }
    let value =
        wire_json::parse(payload, &inventory_limits()).map_err(|_| InventoryError::Malformed)?;

    let mut inventory = Inventory::default();
    let mut unknown: u32 = 0;

    if let Some(Value::Array(items)) = value.get("hosts") {
        if items.len() > MAX_INVENTORY_HOSTS {
            return Err(InventoryError::TooLarge { what: "hosts" });
        }
        for item in items {
            let Some(raw) = item.get("id").and_then(Value::as_str) else {
                return Err(InventoryError::OutOfRange { field: "hosts.id" });
            };
            let Ok(id) = HostId::new(raw) else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            if !fleet.hosts.contains_key(&id) {
                unknown = unknown.saturating_add(1);
                continue;
            }
            let arch = match item.get("arch").and_then(Value::as_str) {
                None => None,
                Some(token) => Some(Arch::parse(token).ok_or(InventoryError::UnknownToken {
                    field: "hosts.arch",
                })?),
            };
            inventory.hosts.insert(
                id.clone(),
                HostObservation {
                    host: id,
                    reachable: item.get("reachable").and_then(Value::as_bool).unwrap_or(true),
                    free_disk_bytes: observed_u64(item, "free_disk_bytes", "hosts.free_disk_bytes")?,
                    arch,
                },
            );
        }
    }

    if let Some(Value::Array(items)) = value.get("accelerators") {
        if items.len() > MAX_INVENTORY_ACCELERATORS {
            return Err(InventoryError::TooLarge {
                what: "accelerators",
            });
        }
        for item in items {
            let Some(raw) = item.get("id").and_then(Value::as_str) else {
                return Err(InventoryError::OutOfRange {
                    field: "accelerators.id",
                });
            };
            let Ok(id) = AcceleratorId::new(raw) else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            if !fleet.accelerators.contains_key(&id) {
                unknown = unknown.saturating_add(1);
                continue;
            }
            let used = observed_u64(
                item,
                "used_memory_bytes",
                "accelerators.used_memory_bytes",
            )?;
            let total = observed_u64(
                item,
                "total_memory_bytes",
                "accelerators.total_memory_bytes",
            )?;
            if total > 0 && used > total {
                // A device cannot use more than it has. Refusing rather than
                // clamping keeps a broken agent from producing a pool figure
                // the planner would treat as authoritative.
                return Err(InventoryError::OutOfRange {
                    field: "accelerators.used_memory_bytes",
                });
            }
            inventory.accelerators.insert(
                id.clone(),
                AcceleratorObservation {
                    accelerator: id,
                    used_memory_bytes: used,
                    total_memory_bytes: total,
                },
            );
        }
    }

    if let Some(Value::Array(items)) = value.get("deployments") {
        if items.len() > MAX_INVENTORY_DEPLOYMENTS {
            return Err(InventoryError::TooLarge {
                what: "deployments",
            });
        }
        for item in items {
            let Some(raw) = item.get("id").and_then(Value::as_str) else {
                return Err(InventoryError::OutOfRange {
                    field: "deployments.id",
                });
            };
            let Ok(id) = DeploymentId::new(raw) else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            if !fleet.deployments.contains_key(&id) {
                unknown = unknown.saturating_add(1);
                continue;
            }
            let state_token = item
                .get("state")
                .and_then(Value::as_str)
                .ok_or(InventoryError::OutOfRange {
                    field: "deployments.state",
                })?;
            let state = ObservedState::parse(state_token).ok_or(InventoryError::UnknownToken {
                field: "deployments.state",
            })?;
            inventory.deployments.insert(
                id.clone(),
                DeploymentObservation {
                    deployment: id,
                    state,
                    observed_memory_bytes: observed_u64(
                        item,
                        "memory_bytes",
                        "deployments.memory_bytes",
                    )?,
                    state_age_ms: observed_u64(item, "state_age_ms", "deployments.state_age_ms")?,
                    inflight: observed_u32(item, "inflight", "deployments.inflight")?,
                },
            );
        }
    }

    if let Some(Value::Array(items)) = value.get("artifacts") {
        if items.len() > MAX_INVENTORY_ARTIFACTS {
            return Err(InventoryError::TooLarge { what: "artifacts" });
        }
        for item in items {
            let (Some(raw_artifact), Some(raw_host)) = (
                item.get("id").and_then(Value::as_str),
                item.get("host").and_then(Value::as_str),
            ) else {
                return Err(InventoryError::OutOfRange {
                    field: "artifacts.id",
                });
            };
            let (Ok(artifact), Ok(host)) = (ArtifactId::new(raw_artifact), HostId::new(raw_host))
            else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            if !fleet.artifacts.contains_key(&artifact) || !fleet.hosts.contains_key(&host) {
                unknown = unknown.saturating_add(1);
                continue;
            }
            inventory.artifacts.insert(
                (artifact.clone(), host.clone()),
                ArtifactPlacement {
                    artifact,
                    host,
                    present: item.get("present").and_then(Value::as_bool).unwrap_or(false),
                    verified: item.get("verified").and_then(Value::as_bool).unwrap_or(false),
                    bytes_present: observed_u64(item, "bytes_present", "artifacts.bytes_present")?,
                },
            );
        }
    }

    inventory.unknown_identifiers = unknown;
    Ok(inventory)
}

/// The router's own record of what it asked for.
///
/// Written to the durable log *before* the mutating verb is sent, which is
/// what makes crash recovery tractable: on restart the router replays leases,
/// asks the agent for each activation's status, and reconciles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Identifier. Idempotency key at the agent.
    pub id: LeaseId,
    /// The deployment it covers.
    pub deployment: DeploymentId,
    /// What was asked for.
    pub operation: LeaseOperation,
    /// When the lease was written.
    pub issued_ms: u64,
    /// When it expires if nothing reports back.
    pub expires_ms: u64,
    /// The decision that caused it, as 32 hex characters, or empty for an
    /// operator action.
    pub decision_id: String,
}

/// What a lease authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOperation {
    /// Bring a deployment up.
    Activate,
    /// Take a deployment down.
    Deactivate,
    /// Acquire an artifact onto a host.
    Fetch,
}

impl LeaseOperation {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::Fetch => "fetch",
        }
    }

    /// Parse from a durable record.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "activate" => Self::Activate,
            "deactivate" => Self::Deactivate,
            "fetch" => Self::Fetch,
            _ => return None,
        })
    }
}

/// Everything the planner reads, sampled once and immutable.
///
/// Shared by `Arc` and never re-read mid-decision. A planner that sampled
/// twice could filter a target under one belief and rank it under another,
/// which breaks the determinism Appendix B requires once fleet state is live
/// state.
#[derive(Debug, Clone)]
pub struct FleetSnapshot {
    /// The activated fleet configuration.
    pub config: Arc<FleetConfig>,
    /// The newest valid observation.
    pub inventory: Inventory,
    /// When that observation was taken, on the router's monotonic clock.
    pub observed_at_ms: u64,
    /// Whether any observation has ever succeeded.
    ///
    /// Distinct from an old one: a router that has never reached its agent
    /// must not report an age of zero and route as if the fleet were healthy.
    pub observed: bool,
    /// Leases the router currently holds, by deployment.
    pub leases: BTreeMap<DeploymentId, Lease>,
    /// When each deployment last became ready, by the router's clock.
    ///
    /// The basis of the dwell floor. Taken from the router's own observation
    /// history rather than from the agent's `state_age_ms`, because dwell is
    /// the router's promise not to thrash and must not be resettable by an
    /// agent that restarts and reports a fresh age.
    pub ready_since_ms: BTreeMap<DeploymentId, u64>,
    /// Deployments the router did not start, and therefore does not own.
    pub unmanaged: BTreeSet<DeploymentId>,
    /// When each deployment may next be activated, from cooldown and flap
    /// backoff.
    pub cooldown_until_ms: BTreeMap<DeploymentId, u64>,
    /// Activation budget remaining per host.
    pub activation_budget: BTreeMap<HostId, u32>,
    /// Refined time estimates, in milliseconds, learned from observation.
    pub observed_timings: BTreeMap<DeploymentId, Timings>,
    /// Whether the router and its agents agree on the fleet digest.
    pub digest_agreed: bool,
    /// Whether every configured agent is reachable.
    pub agents_reachable: bool,
    /// The capability verb each deployment's target serves.
    ///
    /// Projected in by the caller rather than read from a `Target`, because
    /// this crate holds no target records: `PolicySnapshot` owns those, and a
    /// fleet crate that reached into routing configuration would be two
    /// sources of truth for one fact. A deployment absent from this map has an
    /// unclassified target, and its retention value rests on recency and the
    /// operator's weight.
    pub deployment_capabilities: BTreeMap<DeploymentId, Capability>,
}

/// Observed lifecycle durations for one deployment.
///
/// Each is an EWMA over completed operations, clamped to a quarter and four
/// times the declared figure so that one anomalous observation cannot make the
/// planner believe a 20 GB model loads instantly. Observation improves the
/// estimate; it does not overrule the administrator by an order of magnitude.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// Observed start duration.
    pub start_ms: Option<u64>,
    /// Observed stop duration.
    pub stop_ms: Option<u64>,
    /// Observed drain duration.
    pub drain_ms: Option<u64>,
    /// Observed probe duration.
    pub probe_ms: Option<u64>,
    /// Observed fetch duration.
    pub fetch_ms: Option<u64>,
}

/// How far the clamp lets observation move a declared figure.
pub const TIMING_CLAMP_FACTOR: u64 = 4;

/// Blend a declared figure with an observation, within the clamp.
#[must_use]
pub fn refine_timing(declared: u64, observed: Option<u64>) -> u64 {
    let Some(observed) = observed else {
        return declared;
    };
    if declared == 0 {
        return observed;
    }
    let floor = declared.div_euclid(TIMING_CLAMP_FACTOR).max(1);
    let ceiling = declared.saturating_mul(TIMING_CLAMP_FACTOR);
    observed.clamp(floor, ceiling)
}

impl FleetSnapshot {
    /// An empty snapshot for a router with no fleet configured.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            config: Arc::new(FleetConfig::empty()),
            inventory: Inventory::default(),
            observed_at_ms: 0,
            observed: false,
            leases: BTreeMap::new(),
            ready_since_ms: BTreeMap::new(),
            unmanaged: BTreeSet::new(),
            cooldown_until_ms: BTreeMap::new(),
            activation_budget: BTreeMap::new(),
            observed_timings: BTreeMap::new(),
            digest_agreed: true,
            agents_reachable: true,
            deployment_capabilities: BTreeMap::new(),
        }
    }

    /// Age of the newest observation, in milliseconds.
    ///
    /// `None` when no observation has ever succeeded — which is *not* the same
    /// as an age of zero, and callers must treat it as at least as stale as
    /// the oldest permitted belief.
    #[must_use]
    pub fn observation_age_ms(&self, now_ms: u64) -> Option<u64> {
        if !self.observed {
            return None;
        }
        Some(now_ms.saturating_sub(self.observed_at_ms))
    }

    /// Whether belief is fresh enough to plan against.
    #[must_use]
    pub fn belief_is_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        self.observation_age_ms(now_ms)
            .is_some_and(|age| age <= max_age_ms)
    }

    /// The observed state of a deployment, or `Stopped` if it is not reported.
    ///
    /// Absence means not running. That is the conservative reading in the
    /// direction that matters: believing a model is up when it is not sends a
    /// request into a refused connection, while believing it is down at worst
    /// costs an activation the budget already bounds.
    #[must_use]
    pub fn state_of(&self, deployment: &DeploymentId) -> ObservedState {
        self.inventory
            .deployments
            .get(deployment)
            .map_or(ObservedState::Stopped, |o| o.state)
    }

    /// In-flight work the agent reports against a deployment.
    #[must_use]
    pub fn inflight(&self, deployment: &DeploymentId) -> u32 {
        self.inventory
            .deployments
            .get(deployment)
            .map_or(0, |o| o.inflight)
    }

    /// Whether the router started this deployment and may therefore stop it.
    #[must_use]
    pub fn is_router_owned(&self, deployment: &DeploymentId) -> bool {
        !self.unmanaged.contains(deployment)
    }

    /// Memory currently committed in a pool.
    ///
    /// Takes the larger of the declared sum and the observed device figure.
    /// Declared figures may be optimistic; observed figures are what will
    /// actually run out, and planning against a declaration the hardware
    /// disagrees with produces an activation that runs out of memory after two
    /// minutes of load — the most expensive possible failure.
    #[must_use]
    pub fn pool_used_bytes(&self, pool: &hypellm_core::ids::PoolId) -> u64 {
        let declared: u64 = self
            .config
            .deployments_in_pool(pool)
            .into_iter()
            .filter(|d| self.state_of(&d.id).holds_memory())
            .map(|d| d.memory_bytes)
            .fold(0u64, u64::saturating_add);

        let observed: u64 = self
            .config
            .accelerators_in_pool(pool)
            .into_iter()
            .filter_map(|a| self.inventory.accelerators.get(&a.id))
            .map(|o| o.used_memory_bytes)
            .fold(0u64, u64::saturating_add);

        declared.max(observed)
    }

    /// Memory a pool has free for a new deployment.
    #[must_use]
    pub fn pool_free_bytes(&self, pool: &hypellm_core::ids::PoolId) -> u64 {
        self.config
            .pool_capacity_bytes(pool)
            .saturating_sub(self.pool_used_bytes(pool))
    }

    /// Whether the declared and observed figures for a pool have drifted apart.
    ///
    /// Reported rather than corrected: the planner already uses the larger
    /// figure, and an operator needs to know that their declarations no longer
    /// describe the machine.
    #[must_use]
    pub fn memory_drift(&self, pool: &hypellm_core::ids::PoolId, tolerance_permille: u32) -> bool {
        let declared: u64 = self
            .config
            .deployments_in_pool(pool)
            .into_iter()
            .filter(|d| self.state_of(&d.id).holds_memory())
            .map(|d| d.memory_bytes)
            .fold(0u64, u64::saturating_add);
        if declared == 0 {
            return false;
        }
        let observed: u64 = self
            .config
            .accelerators_in_pool(pool)
            .into_iter()
            .filter_map(|a| self.inventory.accelerators.get(&a.id))
            .map(|o| o.used_memory_bytes)
            .fold(0u64, u64::saturating_add);
        let allowed = declared.saturating_add(
            declared
                .saturating_mul(u64::from(tolerance_permille))
                .div_euclid(1_000),
        );
        observed > allowed
    }

    /// Whether an artifact is present and verified on a host.
    #[must_use]
    pub fn artifact_ready(&self, artifact: &ArtifactId, host: &HostId) -> bool {
        self.inventory
            .artifacts
            .get(&(artifact.clone(), host.clone()))
            .is_some_and(|p| p.present && p.verified)
    }

    /// Free disk the agent reports for a host.
    #[must_use]
    pub fn free_disk_bytes(&self, host: &HostId) -> u64 {
        self.inventory
            .hosts
            .get(host)
            .map_or(0, |o| o.free_disk_bytes)
    }

    /// How long a deployment has been ready, in milliseconds.
    #[must_use]
    pub fn resident_for_ms(&self, deployment: &DeploymentId, now_ms: u64) -> u64 {
        self.ready_since_ms
            .get(deployment)
            .map_or(0, |since| now_ms.saturating_sub(*since))
    }

    /// The target a deployment serves, if the configuration still declares it.
    #[must_use]
    pub fn target_of(&self, deployment: &DeploymentId) -> Option<&TargetId> {
        self.config.deployments.get(deployment).map(|d| &d.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Accelerator, AcceleratorKind, Deployment, Host, HostState, Readiness};
    use hypellm_core::ids::{AgentId, PoolId};

    fn fleet() -> FleetConfig {
        let mut fleet = FleetConfig::empty();
        fleet.hosts.insert(
            HostId::new("spark").expect("id"),
            Host {
                id: HostId::new("spark").expect("id"),
                agent: AgentId::new("local").expect("id"),
                arch: Arch::Aarch64,
                state: HostState::Enabled,
                reserved_memory_bytes: 1_000,
                max_concurrent_activations: 1,
            },
        );
        fleet.accelerators.insert(
            AcceleratorId::new("gb10").expect("id"),
            Accelerator {
                id: AcceleratorId::new("gb10").expect("id"),
                host: HostId::new("spark").expect("id"),
                kind: AcceleratorKind::Unified,
                memory_bytes: 10_000,
                pool: PoolId::new("spark-unified").expect("id"),
            },
        );
        fleet.deployments.insert(
            DeploymentId::new("spark-chat").expect("id"),
            Deployment {
                id: DeploymentId::new("spark-chat").expect("id"),
                target: TargetId::new("spark:chat").expect("id"),
                accelerator: AcceleratorId::new("gb10").expect("id"),
                artifact: None,
                memory_bytes: 4_000,
                start_ms: 1_000,
                stop_ms: 100,
                drain_ms: 100,
                probe_ms: 100,
                readiness: Readiness::HttpOk,
                min_resident_ms: 1_000,
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
    fn an_identifier_the_configuration_does_not_declare_is_dropped_and_counted() {
        // The security property of the whole observation path. A compromised
        // agent can withhold, and can lie about a deployment the router
        // already knows about; it cannot introduce one.
        let payload = br#"{
            "deployments": [
                {"id": "spark-chat", "state": "ready"},
                {"id": "attacker-owned", "state": "ready"}
            ],
            "hosts": [{"id": "not-a-host", "free_disk_bytes": 1}]
        }"#;
        let inventory = parse_inventory(payload, &fleet()).expect("parses");
        assert_eq!(inventory.deployments.len(), 1);
        assert!(
            inventory
                .deployments
                .contains_key(&DeploymentId::new("spark-chat").expect("id"))
        );
        assert!(inventory.hosts.is_empty());
        assert_eq!(inventory.unknown_identifiers, 2);
    }

    #[test]
    fn an_unrecognised_state_token_fails_the_whole_observation() {
        // Partially adopting a report means planning against a mixture of two
        // moments. Refusing the lot leaves the previous belief in place, which
        // then ages out and fails closed on its own.
        let payload = br#"{"deployments":[{"id":"spark-chat","state":"warming-up"}]}"#;
        assert_eq!(
            parse_inventory(payload, &fleet()),
            Err(InventoryError::UnknownToken {
                field: "deployments.state"
            })
        );
    }

    #[test]
    fn a_device_reporting_more_used_than_it_has_is_refused() {
        let payload = br#"{"accelerators":[
            {"id":"gb10","used_memory_bytes":20000,"total_memory_bytes":10000}]}"#;
        assert_eq!(
            parse_inventory(payload, &fleet()),
            Err(InventoryError::OutOfRange {
                field: "accelerators.used_memory_bytes"
            })
        );
    }

    #[test]
    fn a_negative_number_is_an_error_rather_than_a_clamp_to_zero() {
        // `-1` read as zero would report a full accelerator as empty.
        let payload = br#"{"accelerators":[{"id":"gb10","used_memory_bytes":-1}]}"#;
        assert_eq!(
            parse_inventory(payload, &fleet()),
            Err(InventoryError::OutOfRange {
                field: "accelerators.used_memory_bytes"
            })
        );
    }

    #[test]
    fn never_having_observed_is_not_an_age_of_zero() {
        let snapshot = FleetSnapshot::empty();
        assert_eq!(snapshot.observation_age_ms(10_000), None);
        assert!(!snapshot.belief_is_fresh(10_000, 30_000));
    }

    #[test]
    fn the_pool_takes_the_larger_of_declared_and_observed_use() {
        // Declared figures may be optimistic. Observed figures are what will
        // actually run out, so the planner must not be talked into believing
        // there is room by a declaration the hardware disagrees with.
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(fleet());
        snapshot.observed = true;
        snapshot.inventory.deployments.insert(
            DeploymentId::new("spark-chat").expect("id"),
            DeploymentObservation {
                deployment: DeploymentId::new("spark-chat").expect("id"),
                state: ObservedState::Ready,
                observed_memory_bytes: 7_000,
                state_age_ms: 0,
                inflight: 0,
            },
        );
        let pool = PoolId::new("spark-unified").expect("id");
        assert_eq!(snapshot.pool_used_bytes(&pool), 4_000);

        snapshot.inventory.accelerators.insert(
            AcceleratorId::new("gb10").expect("id"),
            AcceleratorObservation {
                accelerator: AcceleratorId::new("gb10").expect("id"),
                used_memory_bytes: 7_000,
                total_memory_bytes: 10_000,
            },
        );
        assert_eq!(snapshot.pool_used_bytes(&pool), 7_000);
        // Capacity is 10,000 less the host's 1,000 reservation.
        assert_eq!(snapshot.pool_free_bytes(&pool), 2_000);
        assert!(snapshot.memory_drift(&pool, 100));
    }

    #[test]
    fn observation_may_refine_a_declared_timing_but_not_overrule_it() {
        // One anomalous observation must not make the planner believe a 20 GB
        // model loads in a second.
        assert_eq!(refine_timing(180_000, Some(174_000)), 174_000);
        assert_eq!(refine_timing(180_000, Some(10)), 45_000);
        assert_eq!(refine_timing(180_000, Some(u64::MAX)), 720_000);
        assert_eq!(refine_timing(180_000, None), 180_000);
    }
}
