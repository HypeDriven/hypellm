//! The fleet domain model: hosts, accelerators, deployments, artifacts.
//!
//! Four entities join the specification 5 model. Every one is
//! administrator-configured, and none is nameable or influenceable by a client
//! request. The identifiers defined here are the only tokens that cross the
//! agent socket, and the agent resolves each against its own allowlist — so a
//! compromised router can reorder declared deployments but cannot introduce
//! one.
//!
//! # Why these four and not fewer
//!
//! Conflating any two of them produces a model that cannot express a real
//! fleet:
//!
//! - A **target** is a model as served by one provider endpoint. It already
//!   exists (`hypellm_core::target::Target`) and is unchanged here.
//! - A **deployment** is that target's *lifecycle on one accelerator*. Two
//!   targets may share weights — the same model with and without a vision
//!   projector is two capability declarations, two memory footprints, and two
//!   deployments — so lifecycle cannot live on the target.
//! - An **accelerator** is addressed individually, because a host with a
//!   4 GB GT 1030 and an 11 GB GTX 1080 Ti has exactly one useful device and
//!   "the host has 15 GB" is false in every way that matters.
//! - An **artifact** is architecture-scoped, because an x86-64 image will never
//!   run on an ARM64 host, and discovering that after a 40 GB download is the
//!   most expensive way to learn it.

use core::fmt;
use hypellm_core::ids::{
    AcceleratorId, AgentId, ArtifactId, DeploymentId, HostId, PoolId, TargetId,
};
use std::collections::{BTreeMap, BTreeSet};

/// A machine architecture.
///
/// Two values, because the fleet has two and a third would need a real
/// decision about what "compatible" means rather than an enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arch {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}

impl Arch {
    /// Stable configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "x86_64" | "amd64" => Self::X86_64,
            "aarch64" | "arm64" => Self::Aarch64,
            _ => return None,
        })
    }

    /// Every architecture, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::X86_64, Self::Aarch64]
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operational state an administrator can set on a host.
///
/// Mirrors `hypellm_core::target::AdminState` deliberately: an operator who
/// has learned what draining a target means should not have to learn a second
/// vocabulary for draining a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// Available for placement.
    Enabled,
    /// Accepting no new activations; resident deployments keep serving.
    Drain,
    /// Withdrawn for planned work.
    Maintenance,
    /// Configured but switched off.
    Disabled,
}

impl HostState {
    /// Whether new work may be placed on this host.
    #[must_use]
    pub const fn admits_activation(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether deployments already resident here may still serve.
    ///
    /// Drain stops new *activations*, not existing traffic — the same
    /// distinction target draining makes, and for the same reason: taking a
    /// warm model out of rotation the moment an operator plans maintenance
    /// wastes the load that has already been paid for.
    #[must_use]
    pub const fn admits_traffic(self) -> bool {
        matches!(self, Self::Enabled | Self::Drain)
    }

    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Drain => "drain",
            Self::Maintenance => "maintenance",
            Self::Disabled => "disabled",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "enabled" => Self::Enabled,
            "drain" => Self::Drain,
            "maintenance" => Self::Maintenance,
            "disabled" => Self::Disabled,
            _ => return None,
        })
    }
}

/// How readiness is confirmed after a deployment starts.
///
/// A TCP connect is not readiness (specification 13): a llama.cpp server
/// accepts connections long before it has finished mapping 20 GB of weights,
/// and a router that believes otherwise sends the first request into a
/// timeout and opens a circuit breaker on a model that was working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// The agent's health probe returned success.
    HttpOk,
    /// The agent completed a trivial inference against the deployment.
    ///
    /// Slower and much stronger: it is the only check that distinguishes "the
    /// process is up" from "the model is loaded".
    Inference,
    /// The container reports healthy to its runtime.
    ContainerHealthy,
}

impl Readiness {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpOk => "http_ok",
            Self::Inference => "inference",
            Self::ContainerHealthy => "container_healthy",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http_ok" => Self::HttpOk,
            "inference" => Self::Inference,
            "container_healthy" => Self::ContainerHealthy,
            _ => return None,
        })
    }
}

/// What kind of thing an artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A container image.
    Image,
    /// Model weights.
    Weights,
}

impl ArtifactKind {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Weights => "weights",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "image" => Self::Image,
            "weights" => Self::Weights,
            _ => return None,
        })
    }
}

/// The kind of accelerator a deployment runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceleratorKind {
    /// A discrete CUDA device with its own VRAM.
    Cuda,
    /// Unified memory shared with the host.
    Unified,
    /// CPU inference, drawing on host RAM.
    Cpu,
}

impl AcceleratorKind {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Unified => "unified",
            Self::Cpu => "cpu",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "cuda" => Self::Cuda,
            "unified" => Self::Unified,
            "cpu" => Self::Cpu,
            _ => return None,
        })
    }
}

/// A configured fleet agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetAgent {
    /// Identifier.
    pub id: AgentId,
    /// Unix socket path. Owner-only; never a network address.
    pub socket: String,
    /// How often to ask for an inventory.
    pub observation_interval_ms: u64,
    /// How old belief may get before the router fails closed.
    pub observation_max_age_ms: u64,
    /// Deadline for one socket exchange.
    pub request_timeout_ms: u64,
}

/// A machine in the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// Identifier. A bounded metric label.
    pub id: HostId,
    /// Which configured agent manages it.
    pub agent: AgentId,
    /// Machine architecture. Filters artifact eligibility.
    pub arch: Arch,
    /// Operational state.
    pub state: HostState,
    /// Memory never offered to deployments.
    ///
    /// On a unified-memory host this is the operating system's and other
    /// services' share, and must be set generously: the Spark's 140 GB is not
    /// 140 GB of model.
    pub reserved_memory_bytes: u64,
    /// Bound on in-flight fleet work for this host.
    pub max_concurrent_activations: u32,
}

/// One accelerator on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accelerator {
    /// Identifier, globally unique.
    pub id: AcceleratorId,
    /// Owning host.
    pub host: HostId,
    /// What kind of device it is.
    pub kind: AcceleratorKind,
    /// Total memory.
    pub memory_bytes: u64,
    /// The budget this accelerator draws from.
    ///
    /// Accelerators sharing a pool share one figure. Unified memory is
    /// modelled by giving the accelerator and the host the same pool, so a
    /// resident model correctly reduces host RAM availability. Defaults to a
    /// pool of the accelerator's own, which is right for a discrete GPU.
    pub pool: PoolId,
}

/// The placement of a routable target onto an accelerator.
///
/// At most one deployment per target: a model runnable in two places is two
/// targets sharing an alias, which is what keeps `Target` unchanged by this
/// design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// Identifier. The only token that crosses the agent socket.
    pub id: DeploymentId,
    /// The target this serves.
    pub target: TargetId,
    /// Where it runs.
    pub accelerator: AcceleratorId,
    /// The artifact it needs, if any is modelled.
    pub artifact: Option<ArtifactId>,
    /// Conservative administrator-declared memory reservation.
    ///
    /// Deliberately conservative: it is the figure the planner subtracts from
    /// a pool before deciding a model fits. Observation refines it upward when
    /// the hardware disagrees (see `state::MemoryDrift`), never downward.
    pub memory_bytes: u64,
    /// Declared time to start, in milliseconds.
    ///
    /// Not a formality: a 20 GB Q5 GGUF with a speculative-decoding sidecar
    /// takes minutes to become ready, and every planning decision is dominated
    /// by this number.
    pub start_ms: u64,
    /// Declared time to stop once drained.
    pub stop_ms: u64,
    /// How long in-flight work is given to finish before a stop.
    pub drain_ms: u64,
    /// Declared time for the readiness probe to pass after start.
    pub probe_ms: u64,
    /// How readiness is confirmed.
    pub readiness: Readiness,
    /// Dwell floor: once ready, the planner may not evict for this long.
    ///
    /// The primary anti-thrash control and the only hard floor. Every other
    /// mechanism is an economic argument that adversarial demand can talk into
    /// a swap; this one cannot be argued with.
    pub min_resident_ms: u64,
    /// Whether the planner may ever evict it.
    pub evictable: bool,
    /// Whether an operator has anchored it.
    pub pinned: bool,
    /// Whether routing demand may start it, or only an operator.
    pub autostart: bool,
    /// Administrator weight feeding `retention_value`.
    pub retention_weight: i64,
    /// In-flight requests above which the deployment is not drainable.
    pub max_drainable_inflight: u32,
    /// Whether a drain that times out may stop the deployment anyway.
    ///
    /// Opt-in, and audited when it fires. Stopping a container mid-stream to
    /// serve someone else's request is a decision an operator must make
    /// deliberately and be able to find afterwards.
    pub force_stop: bool,
}

impl Deployment {
    /// Declared time from "decide to start" to "ready", excluding eviction.
    #[must_use]
    pub const fn declared_start_to_ready_ms(&self) -> u64 {
        self.start_ms.saturating_add(self.probe_ms)
    }

    /// Declared time from "decide to stop" to "memory freed".
    #[must_use]
    pub const fn declared_stop_ms(&self) -> u64 {
        self.drain_ms.saturating_add(self.stop_ms)
    }
}

/// A distributable model or image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Identifier.
    pub id: ArtifactId,
    /// What kind of thing it is.
    pub kind: ArtifactKind,
    /// Architecture it runs on. Must match the host's.
    pub arch: Arch,
    /// Size on disk.
    pub size_bytes: u64,
    /// Content digest, as `sha256:<hex>`.
    ///
    /// A string rather than a parsed digest because the agent is what verifies
    /// it, and the router's job is to carry the administrator's declaration to
    /// the agent unaltered rather than to reinterpret it.
    pub digest: String,
    /// Administrator-configured source name. Never client-supplied.
    pub source: String,
}

/// Governance limits, either fleet-wide or scoped to one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetPolicy {
    /// Activations permitted per host per hour.
    ///
    /// The hard ceiling that makes the feature safe to enable. Whatever
    /// defeats the economic arguments, this one is arithmetic, and the failure
    /// mode when it engages is a clean, explained rejection.
    pub max_activations_per_hour: u32,
    /// How far incoming demand must exceed an eviction set's retention value,
    /// in permille.
    ///
    /// Eviction is permitted only when demand *exceeds* the set's value by
    /// this margin, not merely equals it. Without a margin, a scheduler at
    /// equilibrium oscillates by construction.
    pub eviction_margin_permille: u32,
    /// Most deployments one plan may stop.
    ///
    /// A plan that stops four models to start one is nearly always a
    /// misconfigured fleet rather than a good idea, and the cap turns that
    /// into a visible rejection instead of a five-minute outage.
    pub max_eviction_set: u32,
    /// Queued demand at which a cold activation is triggered.
    pub activation_min_demand: u32,
    /// How long the oldest queued request may wait before triggering one.
    pub activation_max_wait_ms: u64,
    /// How long after eviction a deployment may not be re-activated.
    pub reactivation_cooldown_ms: u64,
    /// Window within which repeated activate/evict cycles accrue backoff.
    pub flap_window_ms: u64,
    /// Ceiling on accrued flap backoff.
    pub max_flap_cooldown_ms: u64,
    /// Whether artifact acquisition is permitted at all.
    pub allow_fetch: bool,
    /// Free disk required beyond an artifact's size before a fetch starts.
    pub fetch_disk_headroom_bytes: u64,
    /// Observed-over-declared memory ratio, in permille, that counts as drift.
    pub memory_drift_tolerance_permille: u32,
    /// Whether a deployment observed running but not started by this router
    /// may be evicted by it.
    ///
    /// Off by default: the router will use what it finds and will not take it
    /// away. An operator who started a container by hand should not have to
    /// fight the router to keep it.
    pub adopt_unmanaged: bool,
}

impl FleetPolicy {
    /// The specification-extension 9 defaults.
    pub const DEFAULT: Self = Self {
        max_activations_per_hour: 12,
        eviction_margin_permille: 250,
        max_eviction_set: 2,
        activation_min_demand: 1,
        activation_max_wait_ms: 20_000,
        reactivation_cooldown_ms: 120_000,
        flap_window_ms: 900_000,
        max_flap_cooldown_ms: 3_600_000,
        allow_fetch: false,
        fetch_disk_headroom_bytes: 16 * 1024 * 1024 * 1024,
        memory_drift_tolerance_permille: 100,
        adopt_unmanaged: false,
    };
}

impl Default for FleetPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The whole administrator-declared fleet.
///
/// Immutable once built and shared by `Arc`, like `PolicySnapshot`. The digest
/// binds it: the agent computes the same one independently over the same
/// canonical form, and the handshake refuses to proceed when the two disagree.
#[derive(Debug, Clone, Default)]
pub struct FleetConfig {
    /// Agents by identifier.
    pub agents: BTreeMap<AgentId, FleetAgent>,
    /// Hosts by identifier.
    pub hosts: BTreeMap<HostId, Host>,
    /// Accelerators by identifier.
    pub accelerators: BTreeMap<AcceleratorId, Accelerator>,
    /// Deployments by identifier.
    pub deployments: BTreeMap<DeploymentId, Deployment>,
    /// Artifacts by identifier.
    pub artifacts: BTreeMap<ArtifactId, Artifact>,
    /// The fleet-wide policy.
    pub default_policy: FleetPolicy,
    /// Per-host policy overrides.
    pub host_policies: BTreeMap<HostId, FleetPolicy>,
    /// Whether orchestration is switched on.
    ///
    /// Parsed and validated even when false, so a fleet can be written and
    /// checked before it is enabled.
    pub enabled: bool,
}

impl FleetConfig {
    /// An empty fleet: the configuration every existing deployment has.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether any orchestration applies at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && !self.deployments.is_empty()
    }

    /// The deployment serving a target, if one is declared.
    #[must_use]
    pub fn deployment_for_target(&self, target: &TargetId) -> Option<&Deployment> {
        self.deployments.values().find(|d| &d.target == target)
    }

    /// The accelerator a deployment runs on.
    #[must_use]
    pub fn accelerator_of(&self, deployment: &Deployment) -> Option<&Accelerator> {
        self.accelerators.get(&deployment.accelerator)
    }

    /// The host a deployment runs on.
    #[must_use]
    pub fn host_of(&self, deployment: &Deployment) -> Option<&Host> {
        self.accelerator_of(deployment)
            .and_then(|a| self.hosts.get(&a.host))
    }

    /// The policy in force for a host: its override, or the fleet default.
    #[must_use]
    pub fn policy_for(&self, host: &HostId) -> FleetPolicy {
        self.host_policies
            .get(host)
            .copied()
            .unwrap_or(self.default_policy)
    }

    /// Accelerators drawing on one pool.
    #[must_use]
    pub fn accelerators_in_pool(&self, pool: &PoolId) -> Vec<&Accelerator> {
        self.accelerators
            .values()
            .filter(|a| &a.pool == pool)
            .collect()
    }

    /// Deployments placed on accelerators in one pool, in identifier order.
    #[must_use]
    pub fn deployments_in_pool(&self, pool: &PoolId) -> Vec<&Deployment> {
        // Iterating the `BTreeMap` gives identifier order, which is what makes
        // eviction-set selection independent of map iteration order (Appendix
        // B). A `HashMap` here would make plans nondeterministic in a way that
        // only shows up under load.
        self.deployments
            .values()
            .filter(|d| {
                self.accelerator_of(d)
                    .is_some_and(|a| &a.pool == pool)
            })
            .collect()
    }

    /// Total memory a pool offers to deployments.
    ///
    /// The sum of its accelerators' memory, minus the reservation of each
    /// distinct host that contributes one. The host reservation is subtracted
    /// once per host rather than once per accelerator: two GPUs in one machine
    /// do not each owe the operating system its share.
    #[must_use]
    pub fn pool_capacity_bytes(&self, pool: &PoolId) -> u64 {
        let accelerators = self.accelerators_in_pool(pool);
        let total: u64 = accelerators
            .iter()
            .map(|a| a.memory_bytes)
            .fold(0u64, u64::saturating_add);
        let hosts: BTreeSet<&HostId> = accelerators.iter().map(|a| &a.host).collect();
        let reserved: u64 = hosts
            .iter()
            .filter_map(|h| self.hosts.get(*h))
            .map(|h| h.reserved_memory_bytes)
            .fold(0u64, u64::saturating_add);
        total.saturating_sub(reserved)
    }

    /// The canonical text the fleet digest is computed over.
    ///
    /// Deliberately explicit rather than derived from the configuration file:
    /// the agent holds its own copy of the fleet and must be able to compute
    /// the same digest without parsing HypeLLM's configuration grammar. Only
    /// the fields both sides must agree on appear — identifiers, placement, and
    /// architecture. Timings and governance are the router's business alone and
    /// are excluded, so tuning a dwell floor does not force an agent restart.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        let mut out = String::new();
        for host in self.hosts.values() {
            out.push_str("host ");
            out.push_str(host.id.as_str());
            out.push(' ');
            out.push_str(host.arch.as_str());
            out.push(' ');
            out.push_str(host.agent.as_str());
            out.push('\n');
        }
        for accelerator in self.accelerators.values() {
            out.push_str("accelerator ");
            out.push_str(accelerator.id.as_str());
            out.push(' ');
            out.push_str(accelerator.host.as_str());
            out.push('\n');
        }
        for deployment in self.deployments.values() {
            out.push_str("deployment ");
            out.push_str(deployment.id.as_str());
            out.push(' ');
            out.push_str(deployment.accelerator.as_str());
            out.push('\n');
        }
        for artifact in self.artifacts.values() {
            out.push_str("artifact ");
            out.push_str(artifact.id.as_str());
            out.push(' ');
            out.push_str(artifact.arch.as_str());
            out.push(' ');
            out.push_str(&artifact.digest);
            out.push('\n');
        }
        out
    }

    /// SHA-256 of [`FleetConfig::canonical_form`], lowercase hex.
    #[must_use]
    pub fn digest(&self) -> String {
        hypellm_crypto::digest(self.canonical_form().as_bytes()).to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hid(s: &str) -> HostId {
        HostId::new(s).expect("host id")
    }
    fn aid(s: &str) -> AcceleratorId {
        AcceleratorId::new(s).expect("accelerator id")
    }
    fn pid(s: &str) -> PoolId {
        PoolId::new(s).expect("pool id")
    }

    fn host(id: &str, reserved: u64) -> Host {
        Host {
            id: hid(id),
            agent: AgentId::new("local").expect("agent id"),
            arch: Arch::Aarch64,
            state: HostState::Enabled,
            reserved_memory_bytes: reserved,
            max_concurrent_activations: 1,
        }
    }

    fn accelerator(id: &str, host: &str, pool: &str, memory: u64) -> Accelerator {
        Accelerator {
            id: aid(id),
            host: hid(host),
            kind: AcceleratorKind::Unified,
            memory_bytes: memory,
            pool: pid(pool),
        }
    }

    #[test]
    fn a_host_reservation_is_subtracted_once_however_many_accelerators_share_a_pool() {
        // The failure this guards against is specific: a machine with two GPUs
        // in one pool owing the operating system its share twice, which
        // silently shrinks the pool by a whole reservation and makes a model
        // that fits look like one that does not.
        let mut fleet = FleetConfig::empty();
        fleet.hosts.insert(hid("node0"), host("node0", 8_000));
        fleet
            .accelerators
            .insert(aid("gt1030"), accelerator("gt1030", "node0", "shared", 4_000));
        fleet
            .accelerators
            .insert(aid("gtx1080"), accelerator("gtx1080", "node0", "shared", 11_000));

        assert_eq!(fleet.pool_capacity_bytes(&pid("shared")), 15_000 - 8_000);
    }

    #[test]
    fn a_unified_pool_shared_with_its_host_offers_less_than_the_device_reports() {
        // The Spark: ~140 GB of unified memory, of which a generous share
        // belongs to the operating system and everything else on the machine.
        // A planner that believed the device figure would place three models
        // that cannot co-reside.
        let mut fleet = FleetConfig::empty();
        fleet
            .hosts
            .insert(hid("spark"), host("spark", 17_179_869_184));
        fleet.accelerators.insert(
            aid("gb10"),
            accelerator("gb10", "spark", "spark-unified", 140_384_485_376),
        );
        assert_eq!(
            fleet.pool_capacity_bytes(&pid("spark-unified")),
            140_384_485_376 - 17_179_869_184
        );
    }

    #[test]
    fn the_digest_ignores_timings_and_changes_with_placement() {
        // The digest binds what both sides must agree on. Retuning a dwell
        // floor is the router's business and must not force an agent restart;
        // moving a deployment to a different accelerator is not.
        let mut fleet = FleetConfig::empty();
        fleet.hosts.insert(hid("spark"), host("spark", 0));
        fleet
            .accelerators
            .insert(aid("gb10"), accelerator("gb10", "spark", "p", 10));
        fleet
            .accelerators
            .insert(aid("gb11"), accelerator("gb11", "spark", "p", 10));
        let deployment = Deployment {
            id: DeploymentId::new("spark-music3").expect("deployment id"),
            target: TargetId::new("spark:music3").expect("target id"),
            accelerator: aid("gb10"),
            artifact: None,
            memory_bytes: 1,
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
        };
        fleet
            .deployments
            .insert(deployment.id.clone(), deployment.clone());
        let before = fleet.digest();

        let mut retimed = deployment.clone();
        retimed.min_resident_ms = 600_000;
        retimed.start_ms = 999_999;
        fleet.deployments.insert(retimed.id.clone(), retimed);
        assert_eq!(fleet.digest(), before, "timings are the router's alone");

        let mut moved = deployment;
        moved.accelerator = aid("gb11");
        fleet.deployments.insert(moved.id.clone(), moved);
        assert_ne!(
            fleet.digest(),
            before,
            "placement is what both sides must agree on"
        );
    }
}
