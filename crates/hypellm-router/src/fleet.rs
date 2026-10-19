//! The fleet runtime: observation, planning, and actuation.
//!
//! `hypellm-fleet` decides; this executes. The split is the same one
//! `hypellm-core` and this crate already have, and for the same reason: a
//! planner that could reach the socket would eventually acquire a shortcut to
//! it, and a plan that cannot be produced without side effects cannot be
//! simulated.
//!
//! # Ordering, and why it is what it is
//!
//! The request lifecycle gains one step, placed deliberately (specification-
//! extension 7.4):
//!
//! ```text
//! 4. compute eligible targets — now including residency classification
//! 5. rank, reserve admission capacity
//! 6. NEW — if the chosen candidate is not resident: acquire the activation
//!    lease, execute the plan, await readiness or fail over
//! 7. adapter, stream, normalize, meter, release everything exactly once
//! ```
//!
//! Admission is reserved **before** the activation lease, and both release on
//! every path. Evicting a running model and *then* discovering the tenant is
//! over quota is exactly the unforced error Appendix B's ordering exists to
//! prevent.
//!
//! Activation failure occurs strictly before upstream acceptance, so
//! specification 6.5 failover applies unchanged and the prohibition on splicing
//! after semantic output is untouched.

use hypellm_core::admission::PriorityClass;
use hypellm_core::decision::{ExclusionReason, ResidencyClass};
use hypellm_core::ids::{
    ActivationId, AgentId, AliasId, ArtifactId, DeploymentId, HostId, LeaseId, PoolId, TargetId,
};
use hypellm_core::policy::PolicySnapshot;
use hypellm_core::target::Capability;
use hypellm_core::time::{Clock, Signal};
use hypellm_fleet::activation::{
    ActivationLedger, ActivationOutcome, ActivationRecord, ActivationState, LeaseRelease,
    lease_for,
};
use hypellm_fleet::demand::{DemandSnapshot, DemandTracker};
use hypellm_fleet::durable::{ActivationSummary, FlapRecord};
use hypellm_fleet::governance::{ActivationQueue, Budgets, FlapCounter, QueueAdmission};
use hypellm_fleet::model::{FleetConfig, FleetPolicy, ImageId};
use hypellm_fleet::plan::{Plan, PlanContext, PlanOutcome, PlanStep};
use hypellm_fleet::state::{FleetSnapshot, Inventory, Lease, ObservedState, Timings};
use hypellm_net::fleet::{FleetAgentClient, FleetError, FleetSession};
use hypellm_store::audit::{AuditAction, AuditEvent, AuditOutcome};
use hypellm_store::frame::RecordKind;
use hypellm_store::Store;
use hypellm_telemetry::{Field, LabelName, Labels, Telemetry, names};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// How long the executor waits between `STATUS` polls.
///
/// Bounded and modest: a model load is measured in minutes, so polling faster
/// buys nothing and spends a socket round trip per poll. Slower would add up to
/// a second of latency to a short activation.
const POLL_INTERVAL_MS: u64 = 1_000;

/// The smallest useful activation deadline.
///
/// A caller whose deadline is shorter than this never reaches the executor —
/// the planner's feasibility check refuses first — so this is a floor on the
/// value handed to the agent rather than a policy.
const MIN_AGENT_DEADLINE_MS: u64 = 5_000;

/// How many tampered (artifact, host) pairs, and how many conflicting
/// artifacts, are remembered as already reported. Bounded so a fleet of
/// liars cannot grow it; past the bound a pair is simply not re-audited.
const MAX_REPORTED_ARTIFACT_PAIRS: usize = 1_024;

/// Per-target fleet standing, computed once per routing decision.
///
/// Sampled once and shared, so a target cannot be filtered under one belief and
/// ranked under another. This is the concrete form of the "fleet snapshot is
/// sampled once per decision and never re-read mid-scoring" bound.
#[derive(Debug, Clone, Default)]
pub struct FleetView {
    classes: BTreeMap<TargetId, ResidencyClass>,
    etas: BTreeMap<TargetId, u64>,
    plans: BTreeMap<TargetId, Arc<Plan>>,
    observation_age_ms: Option<u64>,
}

impl FleetView {
    /// The class computed for a target, or `Unmanaged` if it has no deployment.
    #[must_use]
    pub fn class(&self, target: &TargetId) -> ResidencyClass {
        self.classes
            .get(target)
            .copied()
            .unwrap_or(ResidencyClass::Unmanaged)
    }

    /// The estimated time to ready for a target.
    #[must_use]
    pub fn eta_ms(&self, target: &TargetId) -> u64 {
        self.etas.get(target).copied().unwrap_or(0)
    }

    /// The plan computed for a target, if one was.
    #[must_use]
    pub fn plan(&self, target: &TargetId) -> Option<&Arc<Plan>> {
        self.plans.get(target)
    }

    /// Age of the observation this view was computed against.
    #[must_use]
    pub const fn observation_age_ms(&self) -> Option<u64> {
        self.observation_age_ms
    }

    /// Whether anything here requires fleet work.
    #[must_use]
    pub fn requires_activation(&self) -> bool {
        self.classes.values().any(|c| c.requires_activation())
    }
}

/// What the executor did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationResult {
    /// The deployment is ready; dispatch may proceed.
    Ready,
    /// It did not become ready. The caller fails over to the next candidate.
    Failed {
        /// A stable, router-authored reason.
        ///
        /// Never agent text, and never a host name: specification-extension 15
        /// makes fleet topology management-plane data, and a data-plane error
        /// that named a host would disclose it to every caller.
        code: &'static str,
    },
}

/// Everything the router needs to observe and actuate a fleet.
#[derive(Debug)]
pub struct FleetRuntime {
    /// The fleet as configured, with operator overrides applied.
    ///
    /// Rebuilt whenever the configuration is activated or an override changes,
    /// and read as an immutable `Arc` everywhere else. Applying overrides here
    /// rather than at each read site means the planner sees one fleet: a pin an
    /// operator set in the last minute is a pin, not a special case every
    /// caller has to remember to consult.
    config: RwLock<Arc<FleetConfig>>,
    /// The fleet exactly as configuration declared it.
    ///
    /// Kept so that an override can be *removed* — clearing a pin has to
    /// restore what the file says, not what the previous override said.
    declared: RwLock<Arc<FleetConfig>>,
    /// Operator overrides, by deployment.
    overrides: RwLock<BTreeMap<DeploymentId, hypellm_admin_api::DeploymentPatch>>,
    /// The capability verb each deployment's target serves, projected from the
    /// routing snapshot so the planner does not have to hold `Target` records.
    capabilities: RwLock<BTreeMap<DeploymentId, Capability>>,
    /// One link per configured agent: its client and its open session.
    ///
    /// Rebuilt whenever the declared fleet changes, which is what lets a
    /// published configuration add an agent — and what makes every session
    /// re-handshake under the new digest. A session authenticated against the
    /// old digest is agreement about a fleet that no longer exists.
    links: RwLock<BTreeMap<AgentId, Arc<AgentLink>>>,
    /// The key the handshake is authenticated with.
    ///
    /// Held as bytes rather than as a typed secret because it is passed
    /// straight to an HMAC. It is never logged, never rendered, and never sent:
    /// only the tag derived from it crosses the socket.
    key: Vec<u8>,
    /// The newest valid belief.
    snapshot: RwLock<Arc<FleetSnapshot>>,
    /// Live demand.
    demand: DemandTracker,
    /// Per-host activation allowances.
    budgets: Budgets,
    /// Per-deployment cooldown and flap backoff.
    flap: FlapCounter,
    /// Per-capability demand batching.
    queue: ActivationQueue,
    /// In-flight activations and the exactly-once lease accounting.
    ledger: ActivationLedger,
    /// Serialises the commit step of an activation: re-checking a plan
    /// against every lease held right now, and taking its own.
    ///
    /// Plans are made concurrently from whatever snapshot each request holds,
    /// so two can each be sound alone and unsound together. Held only for the
    /// in-memory check and the ledger update — never across I/O.
    admission: Mutex<()>,
    /// Observed lifecycle durations, refining the declared ones.
    timings: RwLock<BTreeMap<DeploymentId, Timings>>,
    /// Deployments observed running that this router did not start.
    unmanaged: RwLock<BTreeSet<DeploymentId>>,
    /// Monotonic counter behind lease identifiers.
    lease_counter: AtomicU64,
    /// Whether every configured agent answered its last handshake.
    agents_reachable: AtomicBool,
    /// Whether every configured agent agrees about the fleet digest.
    digest_agreed: AtomicBool,
    /// Activations performed, for the thrash ratio.
    activations_total: AtomicU64,
    /// Requests served from a deployment this router activated.
    served_after_activation: AtomicU64,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// Metrics and logs.
    telemetry: Arc<Telemetry>,
    /// Durable state.
    store: Arc<Store>,
    /// Delivers approved, published enrollments to the agents
    /// (specification 26.8).
    enrollments: Option<Arc<EnrollmentOfferer>>,
    /// Wakes parked requests when the fleet changes: a commitment taken or
    /// released, an activation settled, an observation adopted, a stop done
    /// (specification 26.10).
    wake: Signal,
    /// Requests dispatched to each deployment and not yet finished, and the
    /// deployments an idle stop has claimed. One lock for both, which is what
    /// makes an idle stop and a dispatch unable to pass each other.
    dispatch: Mutex<DispatchBook>,
    /// Capabilities whose last gated activation was refused, and until when
    /// they are left out of the ranking (specification 26.11).
    ///
    /// A contender that cannot actually be activated — its plan refused for
    /// budget, capacity or dwell — would otherwise sit at the top of the
    /// ranking and hold every other capability waiting for the same host.
    refused_until: Mutex<BTreeMap<DeploymentId, u64>>,
    /// Requests and jobs parked per alias and priority class: how many, and
    /// since when the oldest (specification 26.11, orchestration §11.9). The
    /// demand the scheduler ranks, counted per alias because an alias names
    /// the models a request could use — two chat models share a capability
    /// and are exactly what it must tell apart — and per class because the
    /// highest class waiting is what ranks first.
    parked_aliases: Mutex<BTreeMap<(AliasId, PriorityClass), (u32, u64)>>,
    /// The deployments each alias's permitted targets resolve to, projected
    /// from the routing snapshot like `capabilities`.
    alias_deployments: RwLock<BTreeMap<AliasId, Vec<DeploymentId>>>,
    /// Image IDs learned and kept, by artifact (specification 26.12).
    ///
    /// Written only after the learning record is durable, so what is held
    /// here is never more than what a restart would restore.
    checksums: RwLock<BTreeMap<ArtifactId, ImageId>>,
    /// (artifact, host) pairs already audited as tampered, so a host that
    /// stays tampered is reported once rather than every observation.
    tampered_seen: Mutex<BTreeSet<(ArtifactId, HostId)>>,
    /// Artifacts already reported as having disagreeing verified hosts.
    conflicts_seen: Mutex<BTreeSet<ArtifactId>>,
}

/// Dispatches in flight against idle stops in progress.
#[derive(Debug, Default)]
struct DispatchBook {
    in_flight: BTreeMap<DeploymentId, u32>,
    stopping: BTreeSet<DeploymentId>,
}

/// A dispatch counted against a deployment, to be finished exactly once with
/// [`FleetRuntime::leave_dispatch`].
#[derive(Debug)]
#[must_use = "a dispatch counted against a deployment must be finished, or the deployment is never idle"]
pub struct DispatchHold {
    deployment: DeploymentId,
}

/// Delivers each agent the hosts it should hold by enrollment
/// (specification 26.8).
///
/// Separate from [`FleetRuntime`] because a fleet with no deployment yet has
/// no runtime, and enrolling the first machine is exactly when that is true.
/// The runtime calls it before each observation; with no runtime, the
/// router's housekeeping does.
#[derive(Debug)]
pub struct EnrollmentOfferer {
    registry: Arc<hypellm_fleet::enroll::EnrollmentRegistry>,
    /// The digest of the last offer each agent accepted.
    offered: Mutex<BTreeMap<AgentId, String>>,
    telemetry: Arc<Telemetry>,
}

impl EnrollmentOfferer {
    /// An offerer over `registry`.
    #[must_use]
    pub fn new(
        registry: Arc<hypellm_fleet::enroll::EnrollmentRegistry>,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        Self {
            registry,
            offered: Mutex::new(BTreeMap::new()),
            telemetry,
        }
    }

    /// Offer each agent in `config` its enrolled hosts, returning the agents
    /// that accepted an offer this call.
    ///
    /// Sent when the offer differs from the one the agent last accepted, or
    /// whenever `agreed` is false — a newly published host is the usual cause
    /// of a disagreement, and the offer is what resolves it. Never sent while
    /// the agent agrees and nothing changed, so a quiet fleet costs nothing;
    /// and never sent to an agent no enrollment was ever approved for, so a
    /// router that does not use enrollment never speaks this verb.
    ///
    /// One connection per offer, closed after it: no mutating verb can follow
    /// on a session whose digests disagree.
    pub fn offer(&self, config: &FleetConfig, key: &[u8], agreed: bool) -> Vec<AgentId> {
        let digest = config.digest();
        let mut accepted_by = Vec::new();
        for (agent_id, agent) in &config.agents {
            let hosts = hypellm_fleet::enroll::offer_for_agent(
                &self.registry.approved_for(agent_id),
                config,
                agent_id,
            );
            let Some(payload) = hypellm_fleet::enroll::encode_offer(&hosts) else {
                continue;
            };
            let fingerprint = hypellm_fleet::enroll::offer_digest(&payload);
            let last = self
                .offered
                .lock()
                .map_or(None, |o| o.get(agent_id).cloned());
            // An agent no enrollment was ever approved for has nothing to
            // hear, whatever the digests say: its disagreement has another
            // cause, and an empty offer would not resolve it.
            if hosts.is_empty() && !self.registry.ever_approved_for(agent_id) {
                continue;
            }
            if agreed && last.as_deref() == Some(fingerprint.as_str()) {
                continue;
            }
            let client = FleetAgentClient::new(
                agent.socket.clone(),
                Duration::from_millis(agent.request_timeout_ms.max(1_000)),
            );
            match client.enroll(key, &digest, &payload) {
                Ok(accepted) => {
                    if let Ok(mut offered) = self.offered.lock() {
                        offered.insert(agent_id.clone(), fingerprint);
                    }
                    let count = u64::try_from(hosts.len()).unwrap_or(u64::MAX);
                    let event = if u64::from(accepted) < count {
                        hypellm_telemetry::Event::warn("fleet.enrollment_partially_accepted")
                    } else {
                        hypellm_telemetry::Event::info("fleet.enrollment_offered")
                    };
                    self.telemetry.log(
                        &event
                            .str_field(Field::Component, agent_id.as_str())
                            .int_field(Field::Count, u64::from(accepted)),
                    );
                    accepted_by.push(agent_id.clone());
                }
                Err(error) => {
                    self.telemetry.log(
                        &hypellm_telemetry::Event::warn("fleet.enrollment_offer_failed")
                            .str_field(Field::Component, agent_id.as_str())
                            .str_field(Field::Code, error.code()),
                    );
                }
            }
        }
        accepted_by
    }
}

/// One configured agent: how to reach it and the session currently open.
#[derive(Debug)]
struct AgentLink {
    client: FleetAgentClient,
    session: Mutex<Option<FleetSession>>,
}

/// A fresh link per declared agent, with no session open.
fn agent_links(config: &FleetConfig) -> BTreeMap<AgentId, Arc<AgentLink>> {
    config
        .agents
        .values()
        .map(|agent| {
            let link = AgentLink {
                client: FleetAgentClient::new(
                    agent.socket.clone(),
                    Duration::from_millis(agent.request_timeout_ms.max(1_000)),
                ),
                session: Mutex::new(None),
            };
            (agent.id.clone(), Arc::new(link))
        })
        .collect()
}

impl FleetRuntime {
    /// Build a runtime for a declared fleet.
    ///
    /// Returns `None` when orchestration is switched off or no fleet is
    /// declared, which is what every configuration written before this feature
    /// existed produces. A `None` runtime is not a degraded one: routing
    /// behaves exactly as it did, because a target with no deployment record
    /// classifies `Unmanaged`.
    #[must_use]
    pub fn new(
        config: Arc<FleetConfig>,
        key: Vec<u8>,
        clock: Arc<dyn Clock>,
        telemetry: Arc<Telemetry>,
        store: Arc<Store>,
    ) -> Option<Self> {
        if !config.is_active() {
            return None;
        }
        let links = agent_links(&config);

        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::clone(&config);

        Some(Self {
            config: RwLock::new(Arc::clone(&config)),
            declared: RwLock::new(config),
            overrides: RwLock::new(BTreeMap::new()),
            capabilities: RwLock::new(BTreeMap::new()),
            links: RwLock::new(links),
            key,
            snapshot: RwLock::new(Arc::new(snapshot)),
            demand: DemandTracker::new(),
            budgets: Budgets::new(),
            flap: FlapCounter::new(),
            queue: ActivationQueue::new(),
            ledger: ActivationLedger::new(),
            admission: Mutex::new(()),
            timings: RwLock::new(BTreeMap::new()),
            unmanaged: RwLock::new(BTreeSet::new()),
            lease_counter: AtomicU64::new(0),
            agents_reachable: AtomicBool::new(false),
            digest_agreed: AtomicBool::new(true),
            activations_total: AtomicU64::new(0),
            served_after_activation: AtomicU64::new(0),
            clock,
            telemetry,
            store,
            enrollments: None,
            wake: Signal::new(),
            dispatch: Mutex::new(DispatchBook::default()),
            refused_until: Mutex::new(BTreeMap::new()),
            parked_aliases: Mutex::new(BTreeMap::new()),
            alias_deployments: RwLock::new(BTreeMap::new()),
            checksums: RwLock::new(BTreeMap::new()),
            tampered_seen: Mutex::new(BTreeSet::new()),
            conflicts_seen: Mutex::new(BTreeSet::new()),
        })
    }

    /// Offer approved, published enrollments to the agents on each
    /// observation.
    #[must_use]
    pub fn with_enrollments(mut self, offerer: Arc<EnrollmentOfferer>) -> Self {
        self.enrollments = Some(offerer);
        self
    }

    /// The declared fleet.
    #[must_use]
    pub fn config(&self) -> Arc<FleetConfig> {
        self.config
            .read()
            .map_or_else(|p| Arc::clone(&p.into_inner()), |g| Arc::clone(&g))
    }

    /// The newest belief.
    #[must_use]
    pub fn snapshot(&self) -> Arc<FleetSnapshot> {
        self.snapshot
            .read()
            .map_or_else(|p| Arc::clone(&p.into_inner()), |g| Arc::clone(&g))
    }

    /// Live demand, for the management view and the planner.
    #[must_use]
    pub fn demand_snapshot(&self) -> DemandSnapshot {
        let mut snapshot = self.demand.snapshot(self.clock.now_millis());
        // The batching queue's depth is the demand that has not been served
        // yet, which is the number the eviction comparison actually needs: a
        // capability with ten requests waiting is worth more than one with a
        // high historical rate and nobody waiting.
        for (capability, depth) in self.queue.depths() {
            snapshot.queued.insert(capability, depth);
        }
        snapshot
    }

    /// The activation ledger, for the management view.
    #[must_use]
    pub const fn ledger(&self) -> &ActivationLedger {
        &self.ledger
    }

    /// Per-host activation allowances, for the management view and the
    /// planner.
    ///
    /// Each host is measured against its *own* policy. Reading every host
    /// through `default_policy` reported a host with a per-host override
    /// against the wrong ceiling — and the planner reads this figure, so a
    /// host allowed fewer activations than the default looked as if it had
    /// allowance left, and one allowed more looked exhausted.
    #[must_use]
    pub fn budget_snapshot(&self) -> BTreeMap<HostId, u32> {
        let config = self.config();
        let now = self.clock.now_millis();
        config
            .hosts
            .keys()
            .map(|host| {
                let policy = config.policy_for(host);
                (host.clone(), self.budgets.remaining(host, &policy, now))
            })
            .collect()
    }

    /// The current snapshot with the ledger's commitments as of now.
    ///
    /// Leases and eviction sets change on every activation, far more often
    /// than observation runs, so they are refreshed here rather than waiting
    /// for the next inventory.
    fn with_commitments(&self) -> FleetSnapshot {
        let mut next = (*self.snapshot()).clone();
        next.leases = self.ledger.leases_by_deployment();
        next.evicting = self.ledger.evicting();
        next
    }

    /// Publish the ledger's current commitments into the planner's snapshot.
    fn publish_commitments(&self) {
        if let Ok(mut guard) = self.snapshot.write() {
            let mut next = (**guard).clone();
            next.leases = self.ledger.leases_by_deployment();
            next.evicting = self.ledger.evicting();
            *guard = Arc::new(next);
        }
        self.wake.notify();
    }

    /// Record that a request asked for a capability.
    pub fn record_request(&self, capability: Capability) {
        self.demand
            .record_request(capability, self.clock.now_millis());
    }

    /// Record that a deployment served a request.
    pub fn record_served(&self, target: &TargetId) {
        let config = self.config();
        if let Some(deployment) = config.deployment_for_target(target) {
            self.demand
                .record_served(&deployment.id, self.clock.now_millis());
        }
    }

    /// Project the capability of each deployment's target from routing policy.
    ///
    /// Called on activation of a new configuration. The verb comes from the
    /// aliases that publish the target, because a `target` record declares a
    /// list and the demand signal needs one — the first in configuration order,
    /// which is stable because the target's list is.
    pub fn adopt_policy(&self, snapshot: &PolicySnapshot) {
        let config = self.config();
        let mut map = BTreeMap::new();
        for deployment in config.deployments.values() {
            let Some(target) = snapshot.targets.get(&deployment.target) else {
                continue;
            };
            if let Some(verb) = target.capabilities.verbs.first() {
                map.insert(deployment.id.clone(), *verb);
            }
        }
        if let Ok(mut guard) = self.capabilities.write() {
            *guard = map;
        }
        let mut aliases = BTreeMap::new();
        for alias in snapshot.aliases.values() {
            let deployments: Vec<DeploymentId> = alias
                .permitted_targets
                .iter()
                .filter_map(|target| config.deployment_for_target(target))
                .map(|deployment| deployment.id.clone())
                .collect();
            if !deployments.is_empty() {
                aliases.insert(alias.id.clone(), deployments);
            }
        }
        if let Ok(mut guard) = self.alias_deployments.write() {
            *guard = aliases;
        }
    }

    /// Adopt a newly activated configuration, if it changed the fleet.
    ///
    /// A policy publication swaps the shared configuration pointer; nothing
    /// tells this runtime. Without this, a reload that added a host or moved a
    /// deployment would leave the router planning against the fleet it started
    /// with — and, worse, computing a handshake digest the agent no longer
    /// agrees with, so every orchestrated target would go ineligible with a
    /// reason that pointed at the agent rather than at the reload.
    ///
    /// Compared by digest rather than by pointer: an activation that changed
    /// only routing policy must not discard belief, because belief is what
    /// gates every fleet decision and rebuilding it costs an observation
    /// interval.
    pub fn sync_configuration(&self, config: &hypellm_config::ValidatedConfig) {
        let declared = self
            .declared
            .read()
            .map_or_else(|p| Arc::clone(&p.into_inner()), |g| Arc::clone(&g));
        if declared.digest() != config.fleet.digest()
            || declared.enabled != config.fleet.enabled
        {
            self.adopt_fleet(Arc::clone(&config.fleet));
        }
        // The capability projection is rebuilt either way: a target's declared
        // verb can change without the fleet digest moving, and the demand
        // signal reads it.
        self.adopt_policy(&config.snapshot);
    }

    /// Replace the declared fleet after a configuration activation.
    ///
    /// Overrides survive: an operator who pinned a deployment during an
    /// incident should not have it silently unpinned by an unrelated reload.
    /// An override naming a deployment the new configuration does not declare
    /// is dropped, because there is nothing left for it to mean.
    pub fn adopt_fleet(&self, config: Arc<FleetConfig>) {
        if let Ok(mut guard) = self.declared.write() {
            *guard = Arc::clone(&config);
        }
        if let Ok(mut links) = self.links.write() {
            *links = agent_links(&config);
        }
        if let Ok(mut overrides) = self.overrides.write() {
            overrides.retain(|id, _| config.deployments.contains_key(id));
        }
        let config = self.rebuild_effective();
        if let Ok(mut guard) = self.config.write() {
            *guard = Arc::clone(&config);
        }
        // Belief is about the old fleet until the next observation. Marking it
        // unobserved rather than keeping it is the fail-closed reading: an
        // identifier may mean something different now.
        if let Ok(mut guard) = self.snapshot.write() {
            let mut next = FleetSnapshot::empty();
            next.config = config;
            *guard = Arc::new(next);
        }
    }

    // -- Observation -------------------------------------------------------

    /// Ask every agent for its inventory and rebuild belief.
    ///
    /// One failure does not discard the whole picture: each agent contributes
    /// the hosts it manages, and an agent that cannot be reached leaves its
    /// hosts unobserved, which ages out and fails closed on its own.
    pub fn observe(&self) {
        if let Some(offerer) = &self.enrollments {
            let agreed = self.digest_agreed.load(Ordering::SeqCst);
            for agent in offerer.offer(&self.config(), &self.key, agreed) {
                // The agent rewrote its table, and it closes any session
                // authenticated against the old one. Dropping ours first saves
                // this observation a refused verb.
                if let Some(link) = self.links().get(&agent) {
                    if let Ok(mut session) = link.session.lock() {
                        *session = None;
                    }
                }
            }
        }
        let config = self.config();
        let digest = config.digest();
        let now = self.clock.now_millis();

        let mut merged = Inventory::default();
        let mut all_reachable = true;
        let mut all_agree = true;

        for (agent_id, link) in self.links() {
            match self.with_session(&link, &digest, |session| {
                session.observe(&config)
            }) {
                Ok(inventory) => {
                    merged.hosts.extend(inventory.hosts);
                    merged.accelerators.extend(inventory.accelerators);
                    merged.deployments.extend(inventory.deployments);
                    merged.artifacts.extend(inventory.artifacts);
                    merged.unknown_identifiers = merged
                        .unknown_identifiers
                        .saturating_add(inventory.unknown_identifiers);
                }
                Err(error) => {
                    all_reachable = false;
                    if matches!(error, FleetError::DigestMismatch { .. }) {
                        all_agree = false;
                        self.audit_mismatch(&agent_id, &error);
                    }
                    self.telemetry.log(
                        &hypellm_telemetry::Event::warn("fleet.observation_failed")
                            .str_field(Field::Component, agent_id.as_str())
                            .str_field(Field::Code, error.code()),
                    );
                }
            }
        }

        self.agents_reachable.store(all_reachable, Ordering::SeqCst);
        self.digest_agreed.store(all_agree, Ordering::SeqCst);

        if merged.unknown_identifiers > 0 {
            self.telemetry.log(
                &hypellm_telemetry::Event::warn("fleet.unknown_identifiers")
                    .int_field(Field::Count, u64::from(merged.unknown_identifiers))
                    .str_field(
                        Field::Detail,
                        "an agent named deployments or hosts this configuration does not \
                         declare; they were dropped",
                    ),
            );
        }

        self.adopt_inventory(merged, now, all_reachable, all_agree);
        self.publish_observation_metrics(now);
        self.wake.notify();
    }

    /// Fold a fresh inventory into belief, detecting divergence and drift.
    fn adopt_inventory(
        &self,
        inventory: Inventory,
        now_ms: u64,
        agents_reachable: bool,
        digest_agreed: bool,
    ) {
        let config = self.config();
        let previous = self.snapshot();

        // Readiness timestamps are the router's own record, not the agent's.
        // Dwell is the router's promise not to thrash, and an agent that
        // restarts and reports a fresh age must not be able to reset it.
        let mut ready_since = previous.ready_since_ms.clone();
        for (id, observation) in &inventory.deployments {
            if observation.state.is_serving() {
                ready_since.entry(id.clone()).or_insert(now_ms);
            } else {
                ready_since.remove(id);
            }
        }
        ready_since.retain(|id, _| config.deployments.contains_key(id));

        // A deployment observed running that no lease of ours covers, and that
        // was not already known to us, is adopted as resident for routing but
        // is *not* router-owned. The default is that the router will use what
        // it finds and will not take it away.
        let held: BTreeSet<DeploymentId> = self
            .ledger
            .leases_by_deployment()
            .keys()
            .cloned()
            .collect();
        if let Ok(mut unmanaged) = self.unmanaged.write() {
            for (id, observation) in &inventory.deployments {
                if observation.state.holds_memory()
                    && !held.contains(id)
                    && !previous.ready_since_ms.contains_key(id)
                    && !unmanaged.contains(id)
                {
                    unmanaged.insert(id.clone());
                    self.audit_divergence(id, observation.state);
                }
                if !observation.state.holds_memory() {
                    unmanaged.remove(id);
                }
            }
        }

        let mut next = FleetSnapshot::empty();
        next.config = Arc::clone(&config);
        next.inventory = inventory;
        next.observed_at_ms = now_ms;
        next.observed = agents_reachable || !next.inventory.deployments.is_empty();
        next.leases = self.ledger.leases_by_deployment();
        next.evicting = self.ledger.evicting();
        next.ready_since_ms = ready_since;
        next.unmanaged = self
            .unmanaged
            .read()
            .map(|u| u.clone())
            .unwrap_or_default();
        next.cooldown_until_ms = self.flap.snapshot();
        next.activation_budget = self.budget_snapshot();
        next.observed_timings = self
            .timings
            .read()
            .map(|t| t.clone())
            .unwrap_or_default();
        next.digest_agreed = digest_agreed;
        next.agents_reachable = agents_reachable;
        next.deployment_capabilities = self
            .capabilities
            .read()
            .map(|c| c.clone())
            .unwrap_or_default();
        next.learned_checksums = self.keep_checksums(&config, &next.inventory);

        // Memory drift is reported, not corrected: the planner already uses
        // the larger of the declared and observed figures, and an operator
        // needs to know their declarations no longer describe the machine.
        let pools: BTreeSet<PoolId> = config
            .accelerators
            .values()
            .map(|a| a.pool.clone())
            .collect();
        for pool in pools {
            // The pool's own host's policy, as for the budget.
            let policy = config
                .accelerators_in_pool(&pool)
                .first()
                .map_or(config.default_policy, |a| config.policy_for(&a.host));
            if next.memory_drift(&pool, policy.memory_drift_tolerance_permille) {
                self.audit_drift(&pool);
            }
        }

        if let Ok(mut guard) = self.snapshot.write() {
            *guard = Arc::new(next);
        }
    }

    fn publish_observation_metrics(&self, now_ms: u64) {
        let snapshot = self.snapshot();
        let config = self.config();
        for agent in config.agents.keys() {
            let age = snapshot
                .observation_age_ms(now_ms)
                // No observation is reported as the maximum age rather than as
                // zero. A dashboard that showed a router which has never
                // reached its agent as perfectly fresh is worse than one that
                // showed nothing.
                .unwrap_or(u64::from(u32::MAX));
            self.telemetry.metrics.gauge_set(
                names::FLEET_OBSERVATION_AGE_MS,
                "Age of the newest valid fleet observation.",
                &Labels::one(LabelName::Agent, agent.as_str()),
                i64::try_from(age).unwrap_or(i64::MAX),
            );
        }
        for accelerator in config.accelerators.values() {
            let used = snapshot.pool_used_bytes(&accelerator.pool);
            self.telemetry.metrics.gauge_set(
                names::FLEET_RESIDENT_BYTES,
                "Memory committed on an accelerator.",
                &Labels::one(LabelName::Accelerator, accelerator.id.as_str()),
                i64::try_from(used).unwrap_or(i64::MAX),
            );
        }
        for (host, remaining) in self.budget_snapshot() {
            self.telemetry.metrics.gauge_set(
                names::FLEET_BUDGET_REMAINING,
                "Activations left in a host's hourly allowance.",
                &Labels::one(LabelName::Host, host.as_str()),
                i64::from(remaining),
            );
        }
        let activations = self.activations_total.load(Ordering::SeqCst);
        let served = self.served_after_activation.load(Ordering::SeqCst);
        if served > 0 {
            let ratio = activations.saturating_mul(1_000).div_euclid(served);
            self.telemetry.metrics.gauge_set(
                names::FLEET_THRASH_RATIO,
                "Activations per thousand requests served from activated deployments.",
                &Labels::new(),
                i64::try_from(ratio).unwrap_or(i64::MAX),
            );
        }
    }

    // -- Planning ----------------------------------------------------------

    /// The clock reading a caller should stamp its `PlanContext` with.
    ///
    /// Exposed so that the context and the snapshot are taken against the same
    /// moment: a caller that read the clock separately could build a context
    /// from one instant and plan against belief from another.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_millis()
    }

    /// Classify every target an alias permits, once, for one decision.
    ///
    /// Takes the whole `PlanContext` rather than its fields: eight loose
    /// arguments of which four are booleans is a call site nobody can read, and
    /// two transposed permissions would compile.
    #[must_use]
    pub fn view_for(&self, targets: &[TargetId], context: &PlanContext) -> FleetView {
        let snapshot = self.snapshot();
        let demand = self.demand_snapshot();
        let now = context.now_ms;

        let mut view = FleetView {
            observation_age_ms: snapshot.observation_age_ms(now),
            ..FleetView::default()
        };
        for target in targets {
            if snapshot.config.deployment_for_target(target).is_none() {
                continue;
            }
            let outcome = hypellm_fleet::plan::plan(&snapshot, &demand, target, context);
            view.classes.insert(target.clone(), outcome.residency_class());
            view.etas.insert(target.clone(), outcome.eta_ms());
            if let PlanOutcome::Plan(plan) = outcome {
                view.plans.insert(target.clone(), Arc::from(*plan));
            }
        }
        view
    }

    /// Start cold deployments whose capability is already busy, before a
    /// request asks for one.
    ///
    /// Specification-extension 9.8, and off unless a host's `fleet_policy`
    /// declares `prewarm_min_rate_per_minute`. Returns the deployments it
    /// started, which is what the caller logs.
    ///
    /// # What keeps a bad predictor from being worse than no predictor
    ///
    /// The prediction here is deliberately the dullest one available — "this
    /// capability is being asked for at least this often, and something that
    /// serves it is cold" — because the sophistication of the predictor is not
    /// what bounds the damage. Three other things are:
    ///
    /// - **The same budget.** `ensure_ready` spends `max_activations_per_hour`
    ///   whoever asked, so prediction cannot exceed the ceiling; at worst it
    ///   spends the hour's allowance earlier than demand would have.
    /// - **The same governance.** Dwell, cooldown and flap backoff are enforced
    ///   inside `plan`, so a deployment just evicted is not predicted back.
    /// - **Never evicting.** A plan that would stop something is abandoned, not
    ///   executed. Displacing a running model on a guess is precisely how the
    ///   swap rate doubles — the fleet pays a stop *and* a start, and the
    ///   evicted model's own traffic then pays for it again.
    ///
    /// One deployment per pass, so a fleet that has just become busy warms up
    /// over several observation intervals rather than in one burst that the
    /// per-host concurrent-activation limit would reject anyway.
    pub fn prewarm(&self) -> Option<DeploymentId> {
        let config = self.config();
        let snapshot = self.snapshot();
        let demand = self.demand_snapshot();
        let now = self.clock.now_millis();

        // Stale belief is not a basis for a *speculative* swap. The request
        // path already refuses to plan against an expired observation; doing
        // this on one would spend the hour's budget on a guess about a fleet
        // the router has not seen recently.
        let max_age = config
            .agents
            .values()
            .map(|a| a.observation_max_age_ms)
            .min()
            .unwrap_or(0);
        if max_age > 0 && snapshot.observation_age_ms(now).is_none_or(|age| age > max_age) {
            return None;
        }

        for deployment in config.deployments.values() {
            let target = deployment.target.clone();
            // The host comes from the accelerator, which is where the
            // deployment's placement actually lives.
            let Some(host) = config
                .accelerator_of(deployment)
                .map(|accelerator| accelerator.host.clone())
            else {
                continue;
            };
            let policy = config.policy_for(&host);
            if policy.prewarm_min_rate_per_minute == 0 {
                continue;
            }
            let Some(capability) = self.capability_of(&deployment.id) else {
                // No capability axis, so there is no demand signal to predict
                // from. Not an error: an alias that predates capabilities keeps
                // working, it just never pre-warms.
                continue;
            };
            if demand.rate(capability) < u64::from(policy.prewarm_min_rate_per_minute) {
                continue;
            }

            // Built as an ordinary plan, so every rule the request path obeys
            // applies unchanged. `may_activate` is the *router's* own authority
            // here, not a caller's: nobody asked for this.
            let context = PlanContext {
                now_ms: now,
                // No request, so no deadline. The activation is bounded by the
                // deployment's own `start_ms` and the lease expiry, which is
                // what bounds a demand-driven one after admission too.
                deadline_remaining_ms: u64::MAX,
                effort_multiplier: 1,
                effort_headroom_ms: 0,
                may_activate: true,
                // Never. A fetch on a prediction is hours of bandwidth and
                // hundreds of gigabytes of disk spent on a guess, and
                // specification-extension 12 makes it a separate permission for
                // exactly that reason.
                may_fetch: false,
                capability: Some(capability),
                priority_bonus: 0,
            };

            let PlanOutcome::Plan(plan) = hypellm_fleet::plan::plan(
                &snapshot, &demand, &target, &context,
            ) else {
                continue;
            };
            if plan.evicts() || plan.fetches() {
                continue;
            }

            let decision = format!("prewarm-{}", self.activations_total.load(Ordering::SeqCst));
            if matches!(
                self.ensure_ready(&target, &plan, &decision, u64::MAX),
                ActivationResult::Ready
            ) {
                return Some(plan.deployment.clone());
            }
            // A refusal is not a reason to try the next one in the same pass:
            // whatever refused it — the budget, the host's concurrent
            // activation limit — applies to the others too.
            return None;
        }
        None
    }

    /// Register a deployment's capability directly.
    ///
    /// Production derives this from the activated policy snapshot in
    /// [`Self::adopt_policy`]; the fleet integration suite has no
    /// `PolicySnapshot` to derive it from, so it plants the same map.
    #[cfg(any(test, feature = "test-harness"))]
    pub fn set_capability_for_test(&self, deployment: &DeploymentId, capability: Capability) {
        if let Ok(mut guard) = self.capabilities.write() {
            guard.insert(deployment.clone(), capability);
        }
    }

    /// Refine the class of a resident target using live in-flight counts.
    ///
    /// `Resident` and `ResidentBusy` are one rung apart on the warmth ladder,
    /// and the difference is whether the deployment is already carrying work.
    /// The planner cannot know that — in-flight accounting is the router's —
    /// so the distinction is applied here.
    pub fn mark_busy(&self, view: &mut FleetView, target: &TargetId, in_flight: u32) {
        if in_flight > 0 && view.class(target) == ResidencyClass::Resident {
            view.classes
                .insert(target.clone(), ResidencyClass::ResidentBusy);
        }
    }

    // -- Execution ---------------------------------------------------------

    /// Make a target ready, or explain why it could not be.
    ///
    /// Every path through this function releases the lease exactly once, and
    /// every path that spent an activation allowance either uses it or refunds
    /// it. That is not `Drop`'s job: a leaked lease pins a host out of service
    /// until expiry, which is a slow, confusing outage that reads as a capacity
    /// problem.
    pub fn ensure_ready(
        &self,
        target: &TargetId,
        plan: &Plan,
        decision_id: &str,
        deadline_ms: u64,
    ) -> ActivationResult {
        let config = self.config();
        let policy = config.policy_for(&plan.host);
        let now = self.clock.now_millis();

        let Some(host) = config.hosts.get(&plan.host) else {
            return ActivationResult::Failed {
                code: "fleet_unavailable",
            };
        };

        // The allowance, before anything durable is written. A plan that
        // cannot be paid for must not leave a lease behind.
        if !self.budgets.try_spend(&plan.host, &policy, now) {
            return ActivationResult::Failed {
                code: "fleet_budget_exhausted",
            };
        }

        let lease_id = self.next_lease_id();
        let lease = lease_for(plan, lease_id.clone(), decision_id.to_owned(), &policy, now);

        // Commit: re-check the plan against every lease held at this instant
        // and take the host slot, as one step. The plan was made from a
        // snapshot that may predate another request's commitment, and
        // without this two plans that were each sound alone — the same
        // deployment, the same victim, the same free memory — both ran.
        {
            let _commit = match self.admission.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let committed = self.with_commitments();
            if hypellm_fleet::plan::revalidate(&committed, plan).is_err() {
                self.budgets.refund(&plan.host, &policy, now);
                return ActivationResult::Failed {
                    code: "fleet_busy",
                };
            }
            let record = ActivationRecord::from_plan(plan, lease.clone(), now);
            if self
                .ledger
                .acquire_exclusive(record, host.max_concurrent_activations)
                .is_err()
            {
                self.budgets.refund(&plan.host, &policy, now);
                return ActivationResult::Failed {
                    code: "fleet_busy",
                };
            }
            self.publish_commitments();
        }

        // Claim every idle victim against new dispatches, as idle stop claims
        // what it stops (specification 26.10). The gate let this plan through
        // because nothing was running on them; without the claim, a request
        // routed a moment earlier — a lower-class job taken by another worker
        // as the last one finished, say — could still be dispatched into a
        // model this plan is about to stop, and the swap the gate chose would
        // wait out a whole generation (orchestration §11.9). A victim already
        // carrying work is not claimed: it is drained, as before.
        let claimed: Vec<DeploymentId> = plan
            .eviction_set()
            .into_iter()
            .filter(|victim| self.claim_for_stop(victim))
            .cloned()
            .collect();

        // Durable before the mutating verb. This is the whole basis of crash
        // recovery: a router that died between the write and the verb replays
        // the lease and asks the agent what happened; one that died between the
        // verb and the write would have no idea it had started anything.
        //
        // After the slot, not before it. Written first, a lease refused a slot
        // stayed in the log with no closing record, and every restart audited
        // it as an activation that had gone missing.
        if self
            .store
            .append(
                RecordKind::FleetLease,
                &hypellm_fleet::durable::encode_lease(&lease),
            )
            .is_err()
        {
            let _ = self.ledger.release(
                &lease_id,
                ActivationOutcome::Failed,
                "the lease could not be made durable",
                now,
            );
            self.publish_commitments();
            self.budgets.refund(&plan.host, &policy, now);
            for victim in &claimed {
                self.release_stop_claim(victim);
            }
            return ActivationResult::Failed {
                code: "fleet_unavailable",
            };
        }

        self.ledger.transition(&lease_id, ActivationState::LeaseHeld);
        self.activations_total.fetch_add(1, Ordering::SeqCst);

        let outcome = self.run_plan(target, plan, &lease_id, deadline_ms, &policy);

        let (activation_outcome, result) = match outcome {
            Ok(()) => (ActivationOutcome::Succeeded, ActivationResult::Ready),
            Err(code) => {
                // A failure after eviction leaves the fleet worse than it was:
                // something stopped, nothing started. The rollback is bounded
                // and best-effort, and its own failure quarantines rather than
                // retrying — a rollback storm can itself become the outage.
                let rolled = if plan.evicts() {
                    self.rollback(plan, &lease_id, &policy)
                } else {
                    None
                };
                let outcome = match rolled {
                    None => ActivationOutcome::Failed,
                    Some(true) => ActivationOutcome::FailedAndRolledBack,
                    Some(false) => ActivationOutcome::FailedAndQuarantined,
                };
                (outcome, ActivationResult::Failed { code })
            }
        };

        self.finish(&lease_id, activation_outcome, plan);
        // After the plan, rolled back or not: a stopped victim needs no claim,
        // and one a rollback restarted serves again from here.
        for victim in &claimed {
            self.release_stop_claim(victim);
        }
        if let Some(capability) = self.capability_of(&plan.deployment) {
            self.queue.settle(capability);
        }
        self.wake.notify();
        result
    }

    /// Execute a plan's steps in order.
    fn run_plan(
        &self,
        target: &TargetId,
        plan: &Plan,
        lease: &LeaseId,
        deadline_ms: u64,
        policy: &FleetPolicy,
    ) -> Result<(), &'static str> {
        let config = self.config();
        let started = self.clock.now_millis();
        let expiry = started.saturating_add(deadline_ms);

        for step in &plan.steps {
            if self.clock.now_millis() >= expiry {
                return Err("fleet_activation_timeout");
            }
            match step {
                PlanStep::Evict(victim) => {
                    self.ledger.transition(lease, ActivationState::Draining);
                    let Some(deployment) = config.deployments.get(victim) else {
                        return Err("fleet_unavailable");
                    };
                    let agent = self.agent_for(&plan.host)?;
                    let activation = self
                        .call(&agent, |session| {
                            session.deactivate(victim, lease, deployment.drain_ms)
                        })
                        .map_err(|_| "fleet_unavailable")?;
                    self.ledger.transition(lease, ActivationState::Stopping);
                    self.await_terminal(&agent, &activation, expiry)?;
                    self.after_eviction(victim, plan, policy);
                }
                PlanStep::Fetch { artifact, host } => {
                    self.ledger.transition(lease, ActivationState::Fetching);
                    let agent = self.agent_for(host)?;
                    let activation = self
                        .call(&agent, |session| {
                            session.fetch(artifact, host, remaining(expiry, self.clock.now_millis()))
                        })
                        .map_err(|_| "fleet_unavailable")?;
                    self.await_terminal(&agent, &activation, expiry)?;
                    self.audit(
                        AuditAction::FleetFetch,
                        artifact.as_str(),
                        AuditOutcome::Success,
                        &plan.deployment,
                    );
                }
                PlanStep::Copy { artifact, from, to } => {
                    self.ledger.transition(lease, ActivationState::Fetching);
                    let image_id = self
                        .snapshot()
                        .kept_checksum(artifact)
                        .cloned()
                        .ok_or("fleet_unavailable")?;
                    let agent = self.agent_for(to)?;
                    let activation = self
                        .call(&agent, |session| {
                            session.copy(
                                artifact,
                                from,
                                to,
                                remaining(expiry, self.clock.now_millis()),
                                &image_id,
                            )
                        })
                        .map_err(|_| "fleet_unavailable")?;
                    self.await_terminal(&agent, &activation, expiry)?;
                    self.audit_copy(artifact, from, to, &image_id);
                    // The copy is believed when the destination is *observed*
                    // holding the kept image, not when the verb says so.
                    self.observe();
                    if !self.snapshot().artifact_ready(artifact, to) {
                        return Err("fleet_activation_failed");
                    }
                }
                PlanStep::Activate(deployment) => {
                    self.ledger.transition(lease, ActivationState::Starting);
                    let agent = self.agent_for(&plan.host)?;
                    let activation = self
                        .call(&agent, |session| {
                            session.activate(
                                deployment,
                                lease,
                                remaining(expiry, self.clock.now_millis()),
                            )
                        })
                        .map_err(|_| "fleet_unavailable")?;
                    self.ledger.transition(lease, ActivationState::Probing);
                    self.await_terminal(&agent, &activation, expiry)?;
                    // Readiness is confirmed by observation, not by the verb
                    // returning. A TCP connect is not readiness, and neither is
                    // an accepted `ACTIVATE`.
                    self.observe();
                    if !self.snapshot().state_of(deployment).is_serving() {
                        return Err("fleet_activation_failed");
                    }
                    self.ledger.transition(lease, ActivationState::Ready);
                    let elapsed = self.clock.now_millis().saturating_sub(started);
                    self.record_timing(deployment, elapsed);
                    self.telemetry.metrics.histogram_observe(
                        names::FLEET_TIME_TO_READY_MS,
                        "Time from decision to a deployment serving.",
                        &Labels::one(LabelName::Deployment, deployment.as_str()),
                        elapsed,
                    );
                    self.audit(
                        AuditAction::FleetActivate,
                        deployment.as_str(),
                        AuditOutcome::Success,
                        deployment,
                    );
                    self.served_after_activation.fetch_add(1, Ordering::SeqCst);
                    let _ = target;
                }
            }
        }
        Ok(())
    }

    /// Poll one activation until it reaches a terminal state or time runs out.
    fn await_terminal(
        &self,
        agent: &AgentId,
        activation: &ActivationId,
        expiry_ms: u64,
    ) -> Result<(), &'static str> {
        loop {
            let now = self.clock.now_millis();
            if now >= expiry_ms {
                // Cancellation is best-effort and its own failure is not the
                // caller's problem: the lease still expires, and the next
                // observation reconciles.
                let _ = self.call(agent, |session| session.cancel(activation));
                return Err("fleet_activation_timeout");
            }
            let status = self
                .call(agent, |session| session.status(activation))
                .map_err(|_| "fleet_unavailable")?;
            match status.state {
                ObservedState::Ready | ObservedState::Stopped => return Ok(()),
                ObservedState::Failed => return Err("fleet_activation_failed"),
                ObservedState::Cancelled => return Err("fleet_activation_cancelled"),
                _ => {}
            }
            self.clock.sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
    }

    /// Record an eviction's consequences: cooldown, audit, metric.
    fn after_eviction(&self, victim: &DeploymentId, plan: &Plan, policy: &FleetPolicy) {
        let now = self.clock.now_millis();
        let until = self.flap.record_eviction(victim, policy, now);
        self.persist_flap(victim, until, now);
        self.telemetry.count(
            names::FLEET_EVICTIONS,
            "Deployments displaced, by host and reason.",
            &Labels::new()
                .with(LabelName::Host, plan.host.as_str())
                .with(LabelName::Reason, "displaced"),
        );
        self.audit(
            AuditAction::FleetEvict,
            victim.as_str(),
            AuditOutcome::Success,
            &plan.deployment,
        );
    }

    /// Bring back an eviction set after the activation it made room for failed.
    ///
    /// Returns `Some(true)` when everything came back, `Some(false)` when
    /// something did not, and `None` when there was nothing to restore.
    fn rollback(&self, plan: &Plan, lease: &LeaseId, policy: &FleetPolicy) -> Option<bool> {
        let victims = plan.eviction_set();
        if victims.is_empty() {
            return None;
        }
        self.ledger
            .transition(lease, ActivationState::RollbackPending);
        let config = self.config();
        let mut all_back = true;
        for victim in victims {
            let Some(deployment) = config.deployments.get(victim) else {
                all_back = false;
                continue;
            };
            // The rollback is subject to the same budget as any other
            // activation, so a rollback storm cannot itself become the outage.
            let now = self.clock.now_millis();
            if !self.budgets.try_spend(&plan.host, policy, now) {
                all_back = false;
                continue;
            }
            let Ok(agent) = self.agent_for(&plan.host) else {
                all_back = false;
                continue;
            };
            let restored = self
                .call(&agent, |session| {
                    session.activate(
                        &deployment.id,
                        lease,
                        deployment.declared_start_to_ready_ms().max(MIN_AGENT_DEADLINE_MS),
                    )
                })
                .is_ok();
            if restored {
                // The deployment it was evicted for is gone, so its cooldown is
                // meaningless and would only delay bringing it back.
                self.flap.clear(&deployment.id);
            } else {
                all_back = false;
            }
            self.audit(
                AuditAction::FleetRollback,
                deployment.id.as_str(),
                if restored {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Failed
                },
                &plan.deployment,
            );
        }
        self.ledger.transition(
            lease,
            if all_back {
                ActivationState::RollbackDone
            } else {
                ActivationState::RollbackFailed
            },
        );
        Some(all_back)
    }

    /// Release the lease exactly once and record the outcome durably.
    fn finish(&self, lease: &LeaseId, outcome: ActivationOutcome, plan: &Plan) {
        let now = self.clock.now_millis();
        let detail = match outcome {
            ActivationOutcome::Succeeded => "the deployment became ready",
            ActivationOutcome::Failed => "the activation failed",
            ActivationOutcome::FailedAndRolledBack => "the activation failed and was rolled back",
            ActivationOutcome::FailedAndQuarantined => {
                "the activation failed and the eviction set could not be restored"
            }
            ActivationOutcome::Cancelled => "the activation was cancelled",
        };
        let released = self.ledger.release(lease, outcome, detail, now);
        self.publish_commitments();
        match released {
            LeaseRelease::Released => {}
            LeaseRelease::AlreadyReleased | LeaseRelease::Unknown => {
                // Not a panic and not silence: releasing a lease twice would
                // return a host slot a *different* activation now holds, so the
                // second attempt is refused and reported rather than performed.
                self.telemetry.log(
                    &hypellm_telemetry::Event::warn("fleet.lease_release_refused")
                        .str_field(Field::Detail, "the lease was already released"),
                );
                return;
            }
        }
        self.telemetry.count(
            names::FLEET_ACTIVATIONS,
            "Activations attempted, by host and outcome.",
            &Labels::new()
                .with(LabelName::Host, plan.host.as_str())
                .with(LabelName::Outcome, outcome.as_str()),
        );
        let summary = ActivationSummary {
            deployment: plan.deployment.clone(),
            host: plan.host.clone(),
            outcome,
            duration_ms: now,
            evicted: plan.eviction_set().into_iter().cloned().collect(),
            decision_id: String::new(),
            finished_ms: now,
            operation: hypellm_fleet::state::LeaseOperation::Activate,
        };
        let _ = self.store.append(
            RecordKind::FleetActivation,
            &hypellm_fleet::durable::encode_activation(&summary),
        );
    }

    // -- Batching ----------------------------------------------------------

    /// Stop a deployment on an operator's instruction.
    ///
    /// Drains first: in-flight requests get `drain_ms` to finish. This is the
    /// one path that stops a model without something else wanting its memory,
    /// so it takes no eviction decision and consults no demand — an operator
    /// asked, and the audit record says who.
    pub fn deactivate(&self, deployment: &DeploymentId) -> Result<(), &'static str> {
        self.deactivate_because(deployment, None)
    }

    /// [`Self::deactivate`], with the reason recorded on its audit event.
    fn deactivate_because(
        &self,
        deployment: &DeploymentId,
        reason: Option<&'static str>,
    ) -> Result<(), &'static str> {
        let config = self.config();
        let record = config
            .deployments
            .get(deployment)
            .ok_or("unknown_deployment")?;
        let accelerator = config
            .accelerator_of(record)
            .ok_or("unknown_deployment")?;
        let agent = self.agent_for(&accelerator.host)?;
        let lease = self.next_lease_id();
        let policy = config.policy_for(&accelerator.host);

        // Durable before the verb, as for an activation: a router that died in
        // between must be able to find out what it had asked for.
        let durable = Lease {
            id: lease.clone(),
            deployment: deployment.clone(),
            operation: hypellm_fleet::state::LeaseOperation::Deactivate,
            issued_ms: self.clock.now_millis(),
            expires_ms: self
                .clock
                .now_millis()
                .saturating_add(record.declared_stop_ms().saturating_mul(3).max(120_000)),
            decision_id: String::new(),
        };
        if self
            .store
            .append(
                RecordKind::FleetLease,
                &hypellm_fleet::durable::encode_lease(&durable),
            )
            .is_err()
        {
            return Err("fleet_unavailable");
        }

        // Every path from here closes the lease exactly once: this is the only
        // exit between writing it and returning. An unclosed lease is audited
        // as a lost activation on every restart.
        let started = self.clock.now_millis();
        let outcome = (|| {
            let activation = self
                .call(&agent, |session| {
                    session.deactivate(deployment, &lease, record.drain_ms)
                })
                .map_err(|_| "fleet_unavailable")?;
            let expiry = self
                .clock
                .now_millis()
                .saturating_add(record.declared_stop_ms().saturating_mul(3).max(60_000));
            self.await_terminal(&agent, &activation, expiry)
        })();
        let finished = self.clock.now_millis();
        let closing = ActivationSummary {
            deployment: deployment.clone(),
            host: accelerator.host.clone(),
            outcome: if outcome.is_ok() {
                ActivationOutcome::Succeeded
            } else {
                ActivationOutcome::Failed
            },
            duration_ms: finished.saturating_sub(started),
            evicted: Vec::new(),
            decision_id: String::new(),
            finished_ms: finished,
            operation: hypellm_fleet::state::LeaseOperation::Deactivate,
        };
        let closed = self.store.append(
            RecordKind::FleetActivation,
            &hypellm_fleet::durable::encode_activation(&closing),
        );
        outcome?;
        if closed.is_err() {
            // The stop happened; only its closing record is missing, and the
            // next restart will say so. Reported, not hidden.
            self.telemetry.log(
                &hypellm_telemetry::Event::warn("fleet.lease_close_failed")
                    .str_field(Field::Detail, "the deactivation's closing record was not written"),
            );
        }
        let now = self.clock.now_millis();
        let until = self.flap.record_eviction(deployment, &policy, now);
        self.persist_flap(deployment, until, now);
        match reason {
            None => self.audit(
                AuditAction::FleetDeactivate,
                deployment.as_str(),
                AuditOutcome::Success,
                deployment,
            ),
            Some(reason) => {
                let _ = self.store.append_audit(AuditEvent {
                    timestamp_millis: self.clock.now_millis(),
                    actor: "router".to_owned(),
                    tenant: None,
                    action: AuditAction::FleetDeactivate,
                    object: Some(deployment.as_str().to_owned()),
                    outcome: AuditOutcome::Success,
                    reason: Some(hypellm_core::sensitive::Capped::new(reason, 512)),
                    request_id: None,
                    source: Some(deployment.as_str().to_owned()),
                });
            }
        }
        self.observe();
        Ok(())
    }

    /// Acquire an artifact onto a host on an operator's instruction.
    pub fn fetch_artifact(
        &self,
        artifact: &hypellm_core::ids::ArtifactId,
        host: &HostId,
    ) -> Result<String, &'static str> {
        let config = self.config();
        let declared = config.artifacts.get(artifact).ok_or("unknown_artifact")?;
        let host_record = config.hosts.get(host).ok_or("unknown_host")?;
        if declared.arch != host_record.arch {
            // An x86-64 image will never run on an ARM64 host, so downloading
            // it there is hours of bandwidth spent on something unusable.
            return Err("unknown_host");
        }
        let policy = config.policy_for(host);
        if !policy.allow_fetch {
            return Err("fleet_disabled");
        }
        let needed = declared
            .size_bytes
            .saturating_add(policy.fetch_disk_headroom_bytes);
        if self.snapshot().free_disk_bytes(host) < needed {
            return Err("fleet_unavailable");
        }
        let agent = self.agent_for(host)?;
        let activation = self
            .call(&agent, |session| {
                session.fetch(artifact, host, 3_600_000)
            })
            .map_err(|_| "fleet_unavailable")?;
        let _ = self.store.append_audit(AuditEvent {
            timestamp_millis: self.clock.now_millis(),
            actor: "router".to_owned(),
            tenant: None,
            action: AuditAction::FleetFetch,
            object: Some(artifact.as_str().to_owned()),
            outcome: AuditOutcome::Success,
            reason: None,
            request_id: None,
            source: Some(host.as_str().to_owned()),
        });
        Ok(activation.into_string())
    }

    /// Copy an artifact between hosts on an operator's instruction
    /// (specification 26.12).
    ///
    /// Held to the same rules as a planned copy: both hosts declared and of
    /// the artifact's architecture, a kept checksum to verify against, a
    /// source reporting exactly that checksum, fetch permitted by policy on
    /// the destination, and room on its disk. The agent does the relaying and
    /// the hashing; this only refuses what could not succeed.
    pub fn copy_artifact(
        &self,
        artifact: &ArtifactId,
        from: &HostId,
        to: &HostId,
    ) -> Result<String, &'static str> {
        let config = self.config();
        let declared = config.artifacts.get(artifact).ok_or("unknown_artifact")?;
        let source = config.hosts.get(from).ok_or("unknown_host")?;
        let destination = config.hosts.get(to).ok_or("unknown_host")?;
        if from == to || declared.arch != source.arch || declared.arch != destination.arch {
            return Err("unknown_host");
        }
        let policy = config.policy_for(to);
        if !policy.allow_fetch {
            return Err("fleet_disabled");
        }
        let snapshot = self.snapshot();
        let image_id = snapshot
            .kept_checksum(artifact)
            .cloned()
            .ok_or("checksum_unknown")?;
        if !snapshot.artifact_ready(artifact, from) {
            // Covers both "the source does not have it" and "the source has
            // something else under its name": a tampered host is never a
            // source, whoever asks.
            return Err("copy_source_unverified");
        }
        let needed = declared
            .size_bytes
            .saturating_add(policy.fetch_disk_headroom_bytes);
        if snapshot.free_disk_bytes(to) < needed {
            return Err("fleet_unavailable");
        }
        let agent = self.agent_for(to)?;
        let activation = self
            .call(&agent, |session| {
                session.copy(artifact, from, to, 3_600_000, &image_id)
            })
            .map_err(|_| "fleet_unavailable")?;
        self.audit_copy(artifact, from, to, &image_id);
        Ok(activation.into_string())
    }

    fn audit_copy(&self, artifact: &ArtifactId, from: &HostId, to: &HostId, image: &ImageId) {
        let _ = self.store.append_audit(AuditEvent {
            timestamp_millis: self.clock.now_millis(),
            actor: "router".to_owned(),
            tenant: None,
            action: AuditAction::FleetCopy,
            object: Some(artifact.as_str().to_owned()),
            outcome: AuditOutcome::Success,
            reason: Some(hypellm_core::sensitive::Capped::new(
                &format!("from {from} to {to}, verified against {image}"),
                512,
            )),
            request_id: None,
            source: Some(to.as_str().to_owned()),
        });
    }

    /// Learn, keep and police artifact checksums from one inventory
    /// (specification 26.12), returning the learned set the snapshot carries.
    ///
    /// A learned checksum is appended to the log *before* it is kept: a
    /// checksum held in memory but not on disk would be a trust anchor a
    /// restart could silently replace with whatever the next host reports.
    fn keep_checksums(
        &self,
        config: &FleetConfig,
        inventory: &Inventory,
    ) -> BTreeMap<ArtifactId, ImageId> {
        let mut kept = self.checksums.read().map(|k| k.clone()).unwrap_or_default();
        let learning = hypellm_fleet::checksum::learn(config, &kept, inventory);
        for (artifact, image_id, host) in learning.learned {
            let record = hypellm_fleet::checksum::ChecksumRecord {
                artifact: artifact.clone(),
                image_id: image_id.clone(),
                host: host.clone(),
                at_millis: self.clock.wall_millis(),
            };
            if self
                .store
                .append(
                    RecordKind::ArtifactChecksum,
                    &hypellm_fleet::checksum::encode_record(&record),
                )
                .is_err()
            {
                // Not kept, so not trusted: the next observation tries again.
                continue;
            }
            let _ = self.store.append_audit(AuditEvent {
                timestamp_millis: self.clock.wall_millis(),
                actor: "router".to_owned(),
                tenant: None,
                action: AuditAction::FleetChecksumLearned,
                object: Some(artifact.as_str().to_owned()),
                outcome: AuditOutcome::Success,
                reason: Some(hypellm_core::sensitive::Capped::new(
                    &format!("{image_id}, first verified on {host}"),
                    512,
                )),
                request_id: None,
                source: Some(host.as_str().to_owned()),
            });
            kept.insert(artifact, image_id);
        }
        if let Ok(mut guard) = self.checksums.write() {
            guard.clone_from(&kept);
        }

        if let Ok(mut seen) = self.conflicts_seen.lock() {
            for artifact in learning.conflicts {
                if seen.len() < MAX_REPORTED_ARTIFACT_PAIRS && seen.insert(artifact.clone()) {
                    self.telemetry.log(
                        &hypellm_telemetry::Event::warn("fleet.checksum_conflict")
                            .str_field(Field::Component, artifact.as_str())
                            .str_field(
                                Field::Detail,
                                "verified hosts report different image IDs for this artifact; \
                                 none is kept until they agree or image_id is pinned",
                            ),
                    );
                }
            }
        }

        let tampered = hypellm_fleet::checksum::tampered(config, &kept, inventory);
        if let Ok(mut seen) = self.tampered_seen.lock() {
            seen.retain(|pair| tampered.contains(pair));
            for (artifact, host) in &tampered {
                if seen.len() >= MAX_REPORTED_ARTIFACT_PAIRS
                    || !seen.insert((artifact.clone(), host.clone()))
                {
                    continue;
                }
                let _ = self.store.append_audit(AuditEvent {
                    timestamp_millis: self.clock.wall_millis(),
                    actor: "router".to_owned(),
                    tenant: None,
                    action: AuditAction::FleetArtifactTampered,
                    object: Some(artifact.as_str().to_owned()),
                    outcome: AuditOutcome::Failed,
                    reason: Some(hypellm_core::sensitive::Capped::new(
                        "the host reports an image under this artifact's name that does not \
                         match the kept checksum; it is neither activated with it nor used as \
                         a copy source",
                        512,
                    )),
                    request_id: None,
                    source: Some(host.as_str().to_owned()),
                });
            }
        }
        kept
    }

    /// Wait for a deployment that is already coming up.
    ///
    /// This is what makes batching real rather than nominal. Without it, a
    /// request arriving while a model is starting is classified `Activating`,
    /// stays a candidate, and is dispatched straight into a connection the
    /// model has not opened yet — so the burst that the queue was supposed to
    /// amortise turns into a burst of failovers instead.
    ///
    /// Bounded by the caller's deadline and by observation: the loop ends when
    /// the deployment is serving, when it reaches a terminal state that is not
    /// serving, or when time runs out. Returns the milliseconds waited.
    pub fn await_ready(&self, target: &TargetId, deadline_ms: u64) -> Result<u64, &'static str> {
        let config = self.config();
        let Some(deployment) = config.deployment_for_target(target) else {
            return Ok(0);
        };
        let started = self.clock.now_millis();
        let expiry = started.saturating_add(deadline_ms);
        loop {
            let seen = self.wake.generation();
            let snapshot = self.snapshot();
            if snapshot.state_of(&deployment.id).is_serving() {
                return Ok(self.clock.now_millis().saturating_sub(started));
            }
            // Coming up by observation *or by lease*: between the activation
            // committing and the agent first reporting it, the inventory
            // still says `stopped`, and a rider that read only the inventory
            // gave up on an activation that was about to succeed.
            if !snapshot.is_coming_up(&deployment.id) {
                // It stopped, failed, or was cancelled while we waited. Not
                // ready, and not going to be under this lease.
                return Err("fleet_activation_failed");
            }
            let now = self.clock.now_millis();
            if now >= expiry {
                return Err("fleet_activation_timeout");
            }
            // Woken early when the activation settles or belief changes, so a
            // rider is served as soon as the one who paid for the start is.
            //
            // Observed only when nothing woke it. Every observation notifies,
            // so riders that each observed on waking would wake one another
            // into a loop of `OBSERVE` verbs.
            let woke = self.clock.wait_signal(
                &self.wake,
                seen,
                Duration::from_millis(POLL_INTERVAL_MS.min(expiry.saturating_sub(now))),
            );
            if woke == seen {
                self.observe();
            }
        }
    }

    /// Whether this request should pay for an activation, or wait for one.
    ///
    /// Ten music requests over two minutes should cost one swap, not ten. The
    /// queue is bounded and deadline-aware, and a request told to wait is told
    /// how long it would be before the queue triggers on its own. A trigger is
    /// then put to the churn-aware gate (specification 26.11): it goes only if
    /// it ranks first among everything waiting for the plan's host.
    ///
    /// `class` is the asker's priority class, which the gate ranks it by when
    /// nothing has counted it as parked yet.
    #[must_use]
    pub fn admit_to_queue(&self, capability: Capability, plan: &Plan, class: PriorityClass) -> QueueAdmission {
        let config = self.config();
        let policy = config.policy_for(&plan.host);
        let admission = self
            .queue
            .admit(capability, &policy, self.clock.now_millis());
        self.gated(capability, plan, &policy, admission, class)
    }

    /// Note that a waiting request has stopped waiting, for any reason.
    pub fn leave_queue(&self, capability: Capability) {
        self.queue.leave(capability);
    }

    // -- Parking (specification 26.10) -------------------------------------

    /// The signal parked requests wait on.
    #[must_use]
    pub const fn wake_signal(&self) -> &Signal {
        &self.wake
    }

    /// Count a parked request as waiting for `capability` for as long as it
    /// is parked. `false` when the capability's queue is full, in which case
    /// [`Self::unpark`] must not be called.
    #[must_use]
    pub fn park(&self, capability: Capability) -> bool {
        self.queue.park(capability, self.clock.now_millis())
    }

    /// Count a queued job as parked demand for `capability`, within the share
    /// of its queue jobs may hold
    /// ([`hypellm_fleet::governance::MAX_JOBS_QUEUED_PER_CAPABILITY`]).
    /// `false` when that share is full, in which case [`Self::unpark`] must
    /// not be called.
    #[must_use]
    pub fn park_job(&self, capability: Capability) -> bool {
        self.queue.park_up_to(
            capability,
            self.clock.now_millis(),
            hypellm_fleet::governance::MAX_JOBS_QUEUED_PER_CAPABILITY,
        )
    }

    /// Count a parked request or queued job as demand for `alias` at
    /// `class`, for the scheduler (specification 26.11). Exactly once per
    /// successful [`Self::park`], and undone with [`Self::unpark_alias`]
    /// at the same class.
    pub fn park_alias(&self, alias: &AliasId, class: PriorityClass) {
        let now = self.clock.now_millis();
        let mut book = match self.parked_aliases.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = book.entry((alias.clone(), class)).or_insert((0, now));
        if entry.0 == 0 {
            entry.1 = now;
        }
        entry.0 = entry.0.saturating_add(1);
    }

    /// Stop counting a parked request against `alias` at `class`.
    pub fn unpark_alias(&self, alias: &AliasId, class: PriorityClass) {
        let mut book = match self.parked_aliases.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (alias.clone(), class);
        if let Some(entry) = book.get_mut(&key) {
            entry.0 = entry.0.saturating_sub(1);
            if entry.0 == 0 {
                book.remove(&key);
            }
        }
    }

    /// Stop counting a parked request. Exactly once per successful
    /// [`Self::park`].
    pub fn unpark(&self, capability: Capability) {
        self.queue.leave(capability);
        // Depth changed, which is an input to an idle stop and to the next
        // parked request's trigger.
        self.wake.notify();
    }

    /// Whether a parked request should now pay for its activation.
    ///
    /// [`Self::admit_to_queue`] without counting the caller again.
    #[must_use]
    pub fn poll_queue(&self, capability: Capability, plan: &Plan, class: PriorityClass) -> QueueAdmission {
        let config = self.config();
        let policy = config.policy_for(&plan.host);
        let admission = self.queue.poll(capability, &policy, self.clock.now_millis());
        self.gated(capability, plan, &policy, admission, class)
    }

    // -- Churn-aware scheduling (specification 26.11) ----------------------

    /// Put a trigger the batching queue granted to the scheduling gate.
    ///
    /// A deferred trigger is withdrawn from the queue, so no later request
    /// reads "an activation is coming" when none is, and the caller is told to
    /// wait: it parks, and the next round — woken when the host settles or
    /// the loaded model goes quiet — asks the gate again.
    fn gated(
        &self,
        capability: Capability,
        plan: &Plan,
        policy: &FleetPolicy,
        admission: QueueAdmission,
        class: PriorityClass,
    ) -> QueueAdmission {
        if admission != QueueAdmission::Activate {
            return admission;
        }
        let now = self.clock.now_millis();
        let snapshot = self.with_commitments();
        let mut contenders = self.contenders(&plan.host, &snapshot, Some(&plan.deployment), now);
        if !contenders.iter().any(|c| c.deployment == plan.deployment) {
            // A request on its first attempt is not parked yet, so nothing has
            // counted it. It is ranked as one request that has just arrived —
            // not waved through as if nothing else were waiting.
            contenders.push(hypellm_fleet::schedule::Contender {
                deployment: plan.deployment.clone(),
                waiting: 1,
                oldest_ms: now,
                restore_cost_ms: self.restore_cost(&snapshot, &plan.deployment),
                class,
            });
        }
        let victims_busy = {
            let in_flight = self.dispatches_in_flight();
            plan.eviction_set().iter().any(|victim| {
                in_flight.get(*victim).copied().unwrap_or(0) > 0 || snapshot.inflight(victim) > 0
            })
        };
        let asking = hypellm_fleet::schedule::Asking {
            deployment: &plan.deployment,
            evicts: plan.evicts(),
            victims_busy,
        };
        match hypellm_fleet::schedule::gate(&asking, &contenders, now, policy) {
            hypellm_fleet::schedule::Verdict::Proceed(why) => {
                if matches!(
                    why,
                    hypellm_fleet::schedule::Proceed::Ranked
                        | hypellm_fleet::schedule::Proceed::Starving
                ) {
                    self.count_schedule(&plan.host, why.as_str());
                }
                QueueAdmission::Activate
            }
            hypellm_fleet::schedule::Verdict::Defer(why) => {
                self.queue.untrigger(capability);
                self.count_schedule(&plan.host, why.as_str());
                QueueAdmission::Wait { retry_in_ms: 0 }
            }
        }
    }

    /// Every deployment requests are parked for on `host`, as the scheduler
    /// sees it (specification 26.11).
    ///
    /// Demand is the parked requests per alias, summed over the deployments
    /// on this host each alias could use that are not already serving or
    /// coming up; age is the oldest of them. A deployment whose last gated
    /// activation was refused is left out until its refusal lapses, except
    /// when it is the one asking — it must still be able to try again. Built
    /// from ordered maps, so the list's order is the deployments' order.
    fn contenders(
        &self,
        host: &HostId,
        snapshot: &FleetSnapshot,
        asking: Option<&DeploymentId>,
        now_ms: u64,
    ) -> Vec<hypellm_fleet::schedule::Contender> {
        let config = &snapshot.config;
        let refused = match self.refused_until.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let parked = match self.parked_aliases.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let aliases = match self.alias_deployments.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut demand: BTreeMap<DeploymentId, (u32, u64, PriorityClass)> = BTreeMap::new();
        for ((alias, class), (waiting, oldest_ms)) in &parked {
            for deployment in aliases.get(alias).into_iter().flatten() {
                let Some(declared) = config.deployments.get(deployment) else {
                    continue;
                };
                if config.host_of(declared).map(|h| &h.id) != Some(host)
                    || snapshot.state_of(deployment).is_serving()
                    || snapshot.is_coming_up(deployment)
                    || (Some(deployment) != asking
                        && refused.get(deployment).is_some_and(|until| *until > now_ms))
                {
                    continue;
                }
                let entry = demand
                    .entry(deployment.clone())
                    .or_insert((0, *oldest_ms, *class));
                entry.0 = entry.0.saturating_add(*waiting);
                entry.1 = entry.1.min(*oldest_ms);
                entry.2 = entry.2.min(*class);
            }
        }
        demand
            .into_iter()
            .map(|(deployment, (waiting, oldest_ms, class))| hypellm_fleet::schedule::Contender {
                restore_cost_ms: self.restore_cost(snapshot, &deployment),
                deployment,
                waiting,
                oldest_ms,
                class,
            })
            .collect()
    }

    /// Expected milliseconds from deciding to load a deployment to its
    /// serving: the start refined by observation, plus the declared probe.
    fn restore_cost(&self, snapshot: &FleetSnapshot, deployment: &DeploymentId) -> u64 {
        let Some(declared) = snapshot.config.deployments.get(deployment) else {
            return 0;
        };
        let observed = snapshot.observed_timings.get(deployment).copied();
        hypellm_fleet::state::refine_timing(declared.start_ms, observed.and_then(|t| t.start_ms))
            .saturating_add(declared.probe_ms)
    }

    /// Note that an activation the gate let through was refused, so the
    /// deployment stops outranking others for a while.
    ///
    /// For `activation_max_wait_ms`, at least a second: long enough for the
    /// next contender to be gated through, short enough that a deployment
    /// refused for a passing reason is soon back in line.
    pub fn note_refused(&self, deployment: &DeploymentId, host: &HostId) {
        let policy = self.config().policy_for(host);
        let now = self.clock.now_millis();
        let until = now.saturating_add(policy.activation_max_wait_ms.max(1_000));
        let mut book = match self.refused_until.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        book.retain(|_, until| *until > now);
        book.insert(deployment.clone(), until);
        drop(book);
        self.wake.notify();
    }

    /// What each host would load next, for the fleet view.
    #[must_use]
    pub fn next_activations(&self) -> Vec<hypellm_fleet::schedule::NextActivation> {
        let config = self.config();
        let snapshot = self.with_commitments();
        let now = self.clock.now_millis();
        let mut out = Vec::new();
        for host in config.hosts.keys() {
            let policy = config.policy_for(host);
            let contenders = self.contenders(host, &snapshot, None, now);
            let ready: Vec<_> = contenders
                .iter()
                .filter(|c| c.is_ready(now, &policy))
                .cloned()
                .collect();
            let ranked = if policy.max_reorder_wait_ms == 0 {
                // Arrival order: the oldest waiter.
                let mut ordered: Vec<_> = ready.iter().collect();
                ordered.sort_by(|a, b| {
                    a.oldest_ms
                        .cmp(&b.oldest_ms)
                        .then_with(|| a.deployment.cmp(&b.deployment))
                });
                ordered
            } else {
                hypellm_fleet::schedule::rank(&ready, now, &policy)
            };
            let Some(first) = ranked.first() else {
                continue;
            };
            let reason = if policy.max_reorder_wait_ms == 0 {
                "arrival_order"
            } else if first.is_starving(now, &policy) {
                "starving"
            } else if ranked.len() > 1 {
                "ranked"
            } else {
                "uncontended"
            };
            out.push(hypellm_fleet::schedule::NextActivation {
                host: host.clone(),
                deployment: first.deployment.clone(),
                waiting: first.waiting,
                waited_ms: first.age_ms(now),
                reason,
                contenders: contenders.len(),
            });
        }
        out
    }

    fn count_schedule(&self, host: &HostId, outcome: &str) {
        self.telemetry.count(
            names::FLEET_SCHEDULE_DECISIONS,
            "Churn-aware scheduling decisions, by host and outcome.",
            &Labels::one(LabelName::Host, host.as_str()).with(LabelName::Outcome, outcome),
        );
    }

    /// Count a job taken out of queue order, `reordered` or `starving`.
    pub fn count_job_schedule(&self, outcome: &str) {
        self.telemetry.count(
            names::FLEET_SCHEDULE_DECISIONS,
            "Churn-aware scheduling decisions, by host and outcome.",
            &Labels::one(LabelName::Outcome, outcome),
        );
    }

    /// How a job's alias stands on the fleet right now, for job ordering.
    ///
    /// `Warm` when any of its targets is unmanaged or has a deployment
    /// serving; `Activating` when one is coming up; otherwise `Cold`, keyed
    /// by the first deployment in the alias's own target order, so jobs one
    /// activation would serve group together.
    #[must_use]
    pub fn job_class(&self, targets: &[TargetId]) -> hypellm_fleet::schedule::JobClass {
        let config = self.config();
        let snapshot = self.with_commitments();
        let mut activating = false;
        let mut cold: Option<&DeploymentId> = None;
        for target in targets {
            let Some(deployment) = config.deployment_for_target(target) else {
                return hypellm_fleet::schedule::JobClass::Warm;
            };
            if snapshot.state_of(&deployment.id).is_serving() {
                return hypellm_fleet::schedule::JobClass::Warm;
            }
            if snapshot.is_coming_up(&deployment.id) {
                activating = true;
            } else if cold.is_none() {
                cold = Some(&deployment.id);
            }
        }
        if activating {
            return hypellm_fleet::schedule::JobClass::Activating;
        }
        cold.map_or(hypellm_fleet::schedule::JobClass::Warm, |d| {
            hypellm_fleet::schedule::JobClass::Cold(d.as_str().to_owned())
        })
    }

    /// The fleet-wide reordering bound, for the job queue.
    #[must_use]
    pub fn max_reorder_wait_ms(&self) -> u64 {
        self.config().default_policy.max_reorder_wait_ms
    }

    // -- Dispatch accounting and idle stop (specification 26.10) -----------

    /// Count a dispatch against the deployment serving `target`.
    ///
    /// `Ok(None)` for a target with no deployment. `Err` when an idle stop
    /// has claimed the deployment: the request must not be sent into a model
    /// that is being taken down, and treats the target as draining.
    pub fn enter_dispatch(&self, target: &TargetId) -> Result<Option<DispatchHold>, &'static str> {
        let config = self.config();
        let Some(deployment) = config.deployment_for_target(target) else {
            return Ok(None);
        };
        let mut book = match self.dispatch.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if book.stopping.contains(&deployment.id) {
            return Err("deployment_stopping");
        }
        let count = book.in_flight.entry(deployment.id.clone()).or_insert(0);
        *count = count.saturating_add(1);
        drop(book);
        self.demand
            .record_served(&deployment.id, self.clock.now_millis());
        Ok(Some(DispatchHold {
            deployment: deployment.id.clone(),
        }))
    }

    /// Finish a dispatch counted by [`Self::enter_dispatch`].
    ///
    /// The deployment's idle clock restarts here, at the end of its last
    /// request rather than the beginning: a model that has just spent ten
    /// minutes streaming one answer has not been idle for ten minutes.
    pub fn leave_dispatch(&self, hold: DispatchHold) {
        let mut book = match self.dispatch.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut quiet = false;
        if let Some(count) = book.in_flight.get_mut(&hold.deployment) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                book.in_flight.remove(&hold.deployment);
                quiet = true;
            }
        }
        drop(book);
        self.demand
            .record_served(&hold.deployment, self.clock.now_millis());
        if quiet {
            // A swap deferred because this model was carrying work
            // (specification 26.11) may go now; wake whoever parked for it
            // rather than leaving them to the next slice.
            self.wake.notify();
        }
    }

    /// Claim a deployment for a stop, unless a dispatch holds it.
    ///
    /// Taken under the lock [`Self::enter_dispatch`] takes, so exactly one of
    /// the two wins: a dispatch already counted refuses the claim, and a claim
    /// already taken refuses the dispatch.
    pub(crate) fn claim_for_stop(&self, deployment: &DeploymentId) -> bool {
        let mut book = match self.dispatch.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        book.in_flight.get(deployment).copied().unwrap_or(0) == 0
            && book.stopping.insert(deployment.clone())
    }

    /// Release a claim taken by [`Self::claim_for_stop`].
    pub(crate) fn release_stop_claim(&self, deployment: &DeploymentId) {
        match self.dispatch.lock() {
            Ok(mut book) => book.stopping.remove(deployment),
            Err(poisoned) => poisoned.into_inner().stopping.remove(deployment),
        };
        self.wake.notify();
    }

    /// [`Self::claim_for_stop`], for tests of the race it settles.
    #[cfg(any(test, feature = "test-harness"))]
    pub fn claim_for_stop_for_test(&self, deployment: &DeploymentId) -> bool {
        self.claim_for_stop(deployment)
    }

    /// [`Self::release_stop_claim`], for tests of the race it settles.
    #[cfg(any(test, feature = "test-harness"))]
    pub fn release_stop_claim_for_test(&self, deployment: &DeploymentId) {
        self.release_stop_claim(deployment);
    }

    /// Requests dispatched and not finished, by deployment.
    #[must_use]
    pub fn dispatches_in_flight(&self) -> BTreeMap<DeploymentId, u32> {
        match self.dispatch.lock() {
            Ok(guard) => guard.in_flight.clone(),
            Err(poisoned) => poisoned.into_inner().in_flight.clone(),
        }
    }

    /// Requests parked or queued for a cold capability, in total.
    #[must_use]
    pub fn parked_total(&self) -> u32 {
        self.queue
            .depths()
            .values()
            .fold(0_u32, |sum, depth| sum.saturating_add(*depth))
    }

    /// Stop the deployments nothing is using, at most one per host.
    ///
    /// The predicate is `hypellm_fleet::idle`, over belief refreshed with the
    /// ledger's commitments. Each stop then *claims* its deployment under the
    /// same lock [`Self::enter_dispatch`] takes and re-checks that nothing was
    /// dispatched to it since the predicate ran, so a request and a stop
    /// cannot pass each other: whichever takes the lock first wins, and the
    /// other sees it. Anything parked or queued for the capability after the
    /// predicate ran is re-checked after the claim for the same reason.
    ///
    /// A host performing an activation is skipped: one plan per host at a
    /// time. The stop is an ordinary deactivation — lease durable before the
    /// verb, closed exactly once, flap backoff recorded — audited with the
    /// reason `idle`.
    pub fn idle_stop(&self) -> Vec<DeploymentId> {
        let config = self.config();
        let snapshot = self.with_commitments();
        let demand = self.demand_snapshot();
        let in_flight = self.dispatches_in_flight();
        let now = self.clock.now_millis();
        let max_age = config
            .agents
            .values()
            .map(|a| a.observation_max_age_ms)
            .min()
            .unwrap_or(0);
        let candidates = hypellm_fleet::idle::idle_stops(&hypellm_fleet::idle::IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &in_flight,
            max_observation_age_ms: max_age,
            now_ms: now,
        });

        let mut stopped = Vec::new();
        for deployment in candidates {
            let Some(host) = config
                .deployments
                .get(&deployment)
                .and_then(|record| config.accelerator_of(record))
                .map(|accelerator| accelerator.host.clone())
            else {
                continue;
            };
            if self.ledger.slots_held(&host) > 0 {
                continue;
            }
            if !self.claim_for_stop(&deployment) {
                continue;
            }
            let waiting = self
                .capability_of(&deployment)
                .map_or(0, |capability| {
                    self.queue.depths().get(&capability).copied().unwrap_or(0)
                });
            let result = if waiting > 0 {
                Err("deployment_in_use")
            } else {
                self.deactivate_because(
                    &deployment,
                    Some("idle: nothing used the deployment for idle_stop_ms"),
                )
            };
            self.release_stop_claim(&deployment);
            match result {
                Ok(()) => {
                    self.telemetry.log(
                        &hypellm_telemetry::Event::info("fleet.idle_stopped")
                            .str_field(Field::Deployment, deployment.as_str())
                            .str_field(
                                Field::Detail,
                                "stopped after idle_stop_ms with nothing in flight, queued \
                                 or parked",
                            ),
                    );
                    stopped.push(deployment);
                }
                Err(code) => {
                    if code != "deployment_in_use" {
                        self.telemetry.log(
                            &hypellm_telemetry::Event::warn("fleet.idle_stop_failed")
                                .str_field(Field::Deployment, deployment.as_str())
                                .str_field(Field::Code, code),
                        );
                    }
                }
            }
        }
        stopped
    }

    // -- Recovery ----------------------------------------------------------

    /// Replay durable fleet state at startup.
    ///
    /// Leases are reconciled rather than re-asserted: the router asks the agent
    /// what happened, and an expired lease whose activation cannot be found is
    /// released and audited. Flap counters are restored, deliberately — a
    /// router bounce that reset accrued backoff would permit a fresh burst of
    /// exactly the thrash the backoff exists to stop.
    pub fn recover(&self) {
        let Ok(records) = self.store.records_of_kinds(&[
            RecordKind::FleetLease,
            RecordKind::FleetActivation,
            RecordKind::FleetFlap,
            RecordKind::ArtifactChecksum,
        ]) else {
            return;
        };
        let mut kept: BTreeMap<ArtifactId, ImageId> = BTreeMap::new();

        let mut leases: BTreeMap<LeaseId, Lease> = BTreeMap::new();
        let mut flaps: BTreeMap<DeploymentId, FlapRecord> = BTreeMap::new();
        for (kind, payload) in records {
            match kind {
                RecordKind::FleetLease => {
                    if let Some(lease) = hypellm_fleet::durable::decode_lease(&payload) {
                        leases.insert(lease.id.clone(), lease);
                    }
                }
                RecordKind::FleetActivation => {
                    if let Some(summary) =
                        hypellm_fleet::durable::decode_activation(&payload)
                    {
                        // The activation's own record closes its lease: an
                        // outcome exists, so nothing is outstanding.
                        leases.retain(|_, lease| lease.deployment != summary.deployment);
                        // Only a start teaches the start-time estimate; a
                        // closed deactivation is a stop.
                        if summary.operation == hypellm_fleet::state::LeaseOperation::Activate {
                            self.record_timing(&summary.deployment, summary.duration_ms);
                        }
                    }
                }
                RecordKind::FleetFlap => {
                    if let Some(record) = hypellm_fleet::durable::decode_flap(&payload) {
                        flaps.insert(record.deployment.clone(), record);
                    }
                }
                RecordKind::ArtifactChecksum => {
                    if let Some(record) = hypellm_fleet::checksum::decode_record(&payload) {
                        hypellm_fleet::checksum::restore(&mut kept, record);
                    }
                }
                _ => {}
            }
        }

        if let Ok(mut guard) = self.checksums.write() {
            *guard = kept;
        }
        for record in flaps.values() {
            self.flap.restore(
                &record.deployment,
                record.cycles,
                record.last_cycle_ms,
                record.until_ms,
            );
        }

        let now = self.clock.now_millis();
        for lease in leases.values() {
            // Nothing is re-issued here. The agent is idempotent per lease, so
            // re-sending would be *safe*, but it would also be a mutating verb
            // issued by a router that has not yet observed the fleet — and the
            // first rule is that no plan executes on stale belief.
            self.audit(
                AuditAction::FleetLeaseExpired,
                lease.id.as_str(),
                AuditOutcome::Success,
                &lease.deployment,
            );
            let _ = now;
        }
        self.observe();
    }

    /// Release every lease that has outlived its expiry.
    ///
    /// Called from the housekeeping loop. A lease that outlives its expiry is
    /// not evidence that the work is still running; it is evidence that
    /// whatever should have reported back did not.
    pub fn expire_leases(&self) {
        let now = self.clock.now_millis();
        let expired = self.ledger.expired(now);
        if expired.is_empty() {
            return;
        }
        for lease in expired {
            if self.ledger.release(
                &lease,
                ActivationOutcome::Cancelled,
                "the lease expired before the activation reported back",
                now,
            ) == LeaseRelease::Released
            {
                self.telemetry.log(
                    &hypellm_telemetry::Event::warn("fleet.lease_expired")
                        .str_field(Field::Detail, "released without a reported outcome"),
                );
            }
        }
        self.publish_commitments();
    }

    // -- Plumbing ----------------------------------------------------------

    fn next_lease_id(&self) -> LeaseId {
        let n = self.lease_counter.fetch_add(1, Ordering::SeqCst);
        // Wall-clock plus a counter: unique within a process, and distinct
        // across restarts because the clock moves. Uniqueness is what makes the
        // agent's per-lease idempotency mean anything.
        LeaseId::new(format!("l-{}-{n}", self.clock.now_millis()))
            .unwrap_or_else(|_| LeaseId::new("l-0").unwrap_or_else(|_| unreachable_lease()))
    }

    fn agent_for(&self, host: &HostId) -> Result<AgentId, &'static str> {
        self.config()
            .hosts
            .get(host)
            .map(|h| h.agent.clone())
            .ok_or("fleet_unavailable")
    }

    /// Run one call against an agent, re-establishing the session on a fatal
    /// error and retrying exactly once.
    fn call<T>(
        &self,
        agent: &AgentId,
        f: impl Fn(&mut FleetSession) -> Result<T, FleetError>,
    ) -> Result<T, FleetError> {
        let Some(link) = self.links().remove(agent) else {
            return Err(FleetError::Unavailable(std::io::Error::other(
                "no such fleet agent",
            )));
        };
        let digest = self.config().digest();
        self.with_session(&link, &digest, f)
    }

    /// The current links, cloned out so no lock is held across agent I/O.
    fn links(&self) -> BTreeMap<AgentId, Arc<AgentLink>> {
        self.links
            .read()
            .map_or_else(|p| p.into_inner().clone(), |g| g.clone())
    }

    fn with_session<T>(
        &self,
        link: &AgentLink,
        digest: &str,
        f: impl Fn(&mut FleetSession) -> Result<T, FleetError>,
    ) -> Result<T, FleetError> {
        let client = &link.client;
        let mut guard = match link.session.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if guard.is_none() {
            *guard = Some(client.open(&self.key, digest)?);
        }
        let Some(session) = guard.as_mut() else {
            return Err(FleetError::Unavailable(std::io::Error::other(
                "the fleet session could not be opened",
            )));
        };
        match f(session) {
            Ok(value) => Ok(value),
            Err(error) if error.is_fatal_to_session() => {
                // The router no longer knows where in the conversation it is.
                // Continuing on the same socket would risk reading one verb's
                // reply as another's, so the session is discarded and the call
                // retried once on a fresh one.
                *guard = None;
                let mut session = client.open(&self.key, digest)?;
                let result = f(&mut session);
                if result.is_ok() {
                    *guard = Some(session);
                }
                result
            }
            Err(error) => Err(error),
        }
    }

    /// Apply the current overrides to the declared fleet.
    fn rebuild_effective(&self) -> Arc<FleetConfig> {
        let declared = self
            .declared
            .read()
            .map_or_else(|p| Arc::clone(&p.into_inner()), |g| Arc::clone(&g));
        let overrides = self
            .overrides
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();
        if overrides.is_empty() {
            return declared;
        }
        let mut next = (*declared).clone();
        for (id, patch) in &overrides {
            if let Some(deployment) = next.deployments.get_mut(id) {
                if let Some(pinned) = patch.pinned {
                    deployment.pinned = pinned;
                }
                if let Some(evictable) = patch.evictable {
                    deployment.evictable = evictable;
                }
                if let Some(autostart) = patch.autostart {
                    deployment.autostart = autostart;
                }
            }
        }
        Arc::new(next)
    }

    /// Record an operator override and republish the effective fleet.
    fn apply_override(
        &self,
        deployment: &DeploymentId,
        patch: hypellm_admin_api::DeploymentPatch,
    ) {
        if let Ok(mut overrides) = self.overrides.write() {
            let entry = overrides.entry(deployment.clone()).or_default();
            if patch.pinned.is_some() {
                entry.pinned = patch.pinned;
            }
            if patch.evictable.is_some() {
                entry.evictable = patch.evictable;
            }
            if patch.autostart.is_some() {
                entry.autostart = patch.autostart;
            }
        }
        let next = self.rebuild_effective();
        if let Ok(mut guard) = self.config.write() {
            *guard = Arc::clone(&next);
        }
        // The snapshot the planner reads carries its own `Arc<FleetConfig>`, so
        // it has to be republished too or the override would not take effect
        // until the next observation.
        if let Ok(mut guard) = self.snapshot.write() {
            let mut snapshot = (**guard).clone();
            snapshot.config = next;
            *guard = Arc::new(snapshot);
        }
    }

    fn capability_of(&self, deployment: &DeploymentId) -> Option<Capability> {
        self.capabilities
            .read()
            .ok()
            .and_then(|c| c.get(deployment).copied())
    }

    fn record_timing(&self, deployment: &DeploymentId, elapsed_ms: u64) {
        if let Ok(mut timings) = self.timings.write() {
            let entry = timings.entry(deployment.clone()).or_default();
            // A plain average of the last two rather than a full EWMA: the
            // clamp in `refine_timing` already bounds how far observation can
            // move the declared figure, and a longer memory would make a fleet
            // that genuinely got slower take a very long time to say so.
            entry.start_ms = Some(match entry.start_ms {
                None => elapsed_ms,
                Some(previous) => previous.saturating_add(elapsed_ms).div_euclid(2),
            });
        }
    }

    fn persist_flap(&self, deployment: &DeploymentId, until_ms: u64, now_ms: u64) {
        let cycles = self
            .flap
            .durable_state()
            .into_iter()
            .find(|(d, _, _, _)| d == deployment)
            .map_or(1, |(_, c, _, _)| c);
        let _ = self.store.append(
            RecordKind::FleetFlap,
            &hypellm_fleet::durable::encode_flap(&FlapRecord {
                deployment: deployment.clone(),
                cycles,
                last_cycle_ms: now_ms,
                until_ms,
            }),
        );
    }

    fn audit(
        &self,
        action: AuditAction,
        object: &str,
        outcome: AuditOutcome,
        cause: &DeploymentId,
    ) {
        let _ = self.store.append_audit(AuditEvent {
            timestamp_millis: self.clock.now_millis(),
            // The actor is the router itself; the *cause* is the deployment the
            // decision was made for. Naming both is what makes every model that
            // stops traceable to a reason.
            actor: "router".to_owned(),
            tenant: None,
            action,
            object: Some(object.to_owned()),
            outcome,
            reason: if action.requires_reason() {
                Some(hypellm_core::sensitive::Capped::new(
                    "the drain deadline expired with work in flight and force_stop is enabled",
                    512,
                ))
            } else {
                None
            },
            request_id: None,
            source: Some(cause.as_str().to_owned()),
        });
    }

    fn audit_divergence(&self, deployment: &DeploymentId, state: ObservedState) {
        self.telemetry.log(
            &hypellm_telemetry::Event::warn("fleet.divergence")
                .str_field(Field::Deployment, deployment.as_str())
                .str_field(Field::Detail, state.as_str()),
        );
        self.audit(
            AuditAction::FleetDivergence,
            deployment.as_str(),
            AuditOutcome::Success,
            deployment,
        );
    }

    fn audit_drift(&self, pool: &PoolId) {
        self.telemetry.log(
            &hypellm_telemetry::Event::warn("fleet.memory_drift")
                .str_field(Field::Detail, pool.as_str()),
        );
        let _ = self.store.append_audit(AuditEvent {
            timestamp_millis: self.clock.now_millis(),
            actor: "router".to_owned(),
            tenant: None,
            action: AuditAction::FleetMemoryDrift,
            object: Some(pool.as_str().to_owned()),
            outcome: AuditOutcome::Success,
            reason: None,
            request_id: None,
            source: None,
        });
    }

    fn audit_mismatch(&self, agent: &AgentId, error: &FleetError) {
        self.telemetry.log(
            &hypellm_telemetry::Event::critical("fleet.configuration_mismatch")
                .str_field(Field::Component, agent.as_str())
                .str_field(
                    Field::Detail,
                    "the router and the agent disagree about the fleet configuration; no \
                     mutating verb will be issued",
                ),
        );
        let _ = error;
        let _ = self.store.append_audit(AuditEvent {
            timestamp_millis: self.clock.now_millis(),
            actor: "router".to_owned(),
            tenant: None,
            action: AuditAction::FleetConfigurationMismatch,
            object: Some(agent.as_str().to_owned()),
            outcome: AuditOutcome::Failed,
            reason: None,
            request_id: None,
            source: None,
        });
    }
}

/// Milliseconds left before `expiry`, floored so the agent is never handed a
/// deadline it cannot act on.
fn remaining(expiry_ms: u64, now_ms: u64) -> u64 {
    expiry_ms
        .saturating_sub(now_ms)
        .max(MIN_AGENT_DEADLINE_MS)
}

/// A lease identifier is always constructible from the alphabet used above.
///
/// Reached only if both the formatted identifier and the literal `l-0` are
/// rejected, which the identifier grammar makes impossible. Returning a value
/// rather than panicking keeps specification 18.2's "no panics on data-plane
/// input" true even for a branch that cannot be taken.
fn unreachable_lease() -> LeaseId {
    #[allow(
        clippy::expect_used,
        reason = "a startup invariant: the literal is a valid identifier by inspection, and \
                  this branch requires the identifier grammar itself to have changed"
    )]
    LeaseId::new("l").expect("a single letter is a valid identifier")
}

/// The exclusion a fleet view implies for a target, if any.
///
/// Data-plane errors derived from these say "capability unavailable" and never
/// name a host, an accelerator, or what else is loaded.
#[must_use]
pub fn exclusion_for(class: ResidencyClass) -> Option<ExclusionReason> {
    class.exclusion()
}

/// Routing live state with the fleet's answer folded in.
///
/// `HealthRegistry` answers the health, latency, queue, and capacity questions
/// exactly as before; this adds the three defaulted fleet methods. Composing
/// rather than extending `HealthRegistry` keeps the health subsystem unaware of
/// the fleet, which is what lets a deployment-free router use the same code
/// path with no fleet at all.
///
/// The view is computed **once** before routing and borrowed here, so every
/// target is filtered and ranked against one belief.
#[derive(Debug)]
pub struct FleetAwareLiveState<'a> {
    health: &'a hypellm_core::health::HealthRegistry,
    view: &'a FleetView,
}

impl<'a> FleetAwareLiveState<'a> {
    /// Wrap a health registry with a fleet view.
    #[must_use]
    pub const fn new(
        health: &'a hypellm_core::health::HealthRegistry,
        view: &'a FleetView,
    ) -> Self {
        Self { health, view }
    }
}

impl hypellm_core::policy::LiveState for FleetAwareLiveState<'_> {
    fn circuit_open(&self, target: &TargetId) -> bool {
        self.health.circuit_open(target)
    }
    fn probe_unreachable(&self, target: &TargetId) -> bool {
        self.health.probe_unreachable(target)
    }
    fn health_penalty(&self, target: &TargetId) -> i64 {
        self.health.health_penalty(target)
    }
    fn latency_penalty(&self, target: &TargetId) -> i64 {
        self.health.latency_penalty(target)
    }
    fn queue_penalty(&self, target: &TargetId) -> i64 {
        self.health.queue_penalty(target)
    }
    fn affinity_bonus(&self, target: &TargetId) -> i64 {
        self.health.affinity_bonus(target)
    }
    fn has_capacity(&self, target: &TargetId) -> bool {
        self.health.has_capacity(target)
    }
    fn admin_override(&self, target: &TargetId) -> Option<hypellm_core::target::AdminState> {
        self.health.admin_override(target)
    }
    fn failure_percent(&self, target: &TargetId) -> u32 {
        self.health.failure_percent(target)
    }
    fn residency_class(&self, target: &TargetId) -> ResidencyClass {
        self.view.class(target)
    }
    fn activation_eta_ms(&self, target: &TargetId) -> u64 {
        self.view.eta_ms(target)
    }
    fn fleet_observation_age_ms(&self) -> Option<u64> {
        self.view.observation_age_ms()
    }
}

/// The management API's view of the fleet.
///
/// The same shape `CredentialSink` uses: the management surface knows *what*
/// it may ask for, and this knows *how*. Every method returns a stable code
/// rather than prose — the sentence an operator reads is written in
/// `hypellm_admin_api::fleet`, so an agent's strings can never reach a browser
/// through this path.
#[derive(Debug)]
pub struct FleetControlAdapter {
    runtime: Arc<FleetRuntime>,
}

impl FleetControlAdapter {
    /// Wrap a runtime.
    #[must_use]
    pub const fn new(runtime: Arc<FleetRuntime>) -> Self {
        Self { runtime }
    }

    /// Plan for one deployment on an operator's behalf.
    ///
    /// Operator actions bypass the *demand* threshold — a person asking is
    /// demand enough — but not the dwell floor, the cooldown, the concurrency
    /// limit, or the activation budget. Those protect the fleet from any
    /// caller, and an operator who could step over them would find the
    /// protections absent exactly when an incident makes them want to.
    fn plan_for(&self, deployment: &DeploymentId) -> Result<Box<Plan>, &'static str> {
        let config = self.runtime.config();
        let target = config
            .deployments
            .get(deployment)
            .map(|d| d.target.clone())
            .ok_or("unknown_deployment")?;
        let snapshot = self.runtime.snapshot();
        let demand = self.runtime.demand_snapshot();
        let now = self.runtime.clock.now_millis();
        let context = PlanContext {
            now_ms: now,
            // Generous but finite: an operator action is not a request with a
            // deadline, and an unbounded one would let a plan the planner
            // thinks takes an hour be accepted as feasible.
            deadline_remaining_ms: 3_600_000,
            effort_multiplier: 1,
            effort_headroom_ms: 0,
            may_activate: true,
            may_fetch: true,
            capability: self.runtime.capability_of(deployment),
            priority_bonus: 0,
        };
        match hypellm_fleet::plan::plan(&snapshot, &demand, &target, &context) {
            PlanOutcome::Plan(plan) => Ok(plan),
            PlanOutcome::AlreadyResident => Err("fleet_activation_failed"),
            PlanOutcome::AlreadyActivating { .. } => Err("fleet_busy"),
            PlanOutcome::Infeasible(reason) => Err(reason.code()),
        }
    }
}

impl hypellm_admin_api::FleetControl for FleetControlAdapter {
    fn snapshot(&self) -> Arc<FleetSnapshot> {
        self.runtime.snapshot()
    }

    fn demand(&self) -> DemandSnapshot {
        self.runtime.demand_snapshot()
    }

    fn history(&self) -> Vec<hypellm_fleet::activation::ActivationRecord> {
        self.runtime.ledger().history()
    }

    fn activate(&self, deployment: &str) -> Result<String, &'static str> {
        let id = DeploymentId::new(deployment).map_err(|_| "unknown_deployment")?;
        let plan = self.plan_for(&id)?;
        let target = self
            .runtime
            .config()
            .deployments
            .get(&id)
            .map(|d| d.target.clone())
            .ok_or("unknown_deployment")?;
        match self
            .runtime
            .ensure_ready(&target, &plan, "", 3_600_000)
        {
            ActivationResult::Ready => Ok(id.into_string()),
            ActivationResult::Failed { code } => Err(code),
        }
    }

    fn deactivate(&self, deployment: &str) -> Result<String, &'static str> {
        let id = DeploymentId::new(deployment).map_err(|_| "unknown_deployment")?;
        self.runtime.deactivate(&id)?;
        Ok(id.into_string())
    }

    fn fetch(&self, artifact: &str, host: &str) -> Result<String, &'static str> {
        let artifact =
            hypellm_core::ids::ArtifactId::new(artifact).map_err(|_| "unknown_artifact")?;
        let host = HostId::new(host).map_err(|_| "unknown_host")?;
        self.runtime.fetch_artifact(&artifact, &host)
    }

    fn copy(&self, artifact: &str, from: &str, to: &str) -> Result<String, &'static str> {
        let artifact =
            hypellm_core::ids::ArtifactId::new(artifact).map_err(|_| "unknown_artifact")?;
        let from = HostId::new(from).map_err(|_| "unknown_host")?;
        let to = HostId::new(to).map_err(|_| "unknown_host")?;
        self.runtime.copy_artifact(&artifact, &from, &to)
    }

    fn patch(
        &self,
        deployment: &str,
        patch: hypellm_admin_api::DeploymentPatch,
    ) -> Result<(), &'static str> {
        let id = DeploymentId::new(deployment).map_err(|_| "unknown_deployment")?;
        if !self.runtime.config().deployments.contains_key(&id) {
            return Err("unknown_deployment");
        }
        self.runtime.apply_override(&id, patch);
        Ok(())
    }

    fn simulate(&self, target: &str, patience_ms: u64) -> Result<PlanOutcome, &'static str> {
        let target = TargetId::new(target).map_err(|_| "unknown_deployment")?;
        let snapshot = self.runtime.snapshot();
        let demand = self.runtime.demand_snapshot();
        let now = self.runtime.clock.now_millis();
        let capability = snapshot
            .config
            .deployment_for_target(&target)
            .and_then(|d| self.runtime.capability_of(&d.id));
        // No side effects by construction: the planner is a pure function of a
        // snapshot, so this runs the production code path and touches nothing.
        Ok(hypellm_fleet::plan::plan(
            &snapshot,
            &demand,
            &target,
            &PlanContext {
                now_ms: now,
                deadline_remaining_ms: patience_ms,
                effort_multiplier: 1,
                effort_headroom_ms: 0,
                may_activate: true,
                may_fetch: true,
                capability,
                priority_bonus: 0,
            },
        ))
    }

    fn now_ms(&self) -> u64 {
        self.runtime.clock.now_millis()
    }

    fn next_activations(&self) -> Vec<hypellm_fleet::schedule::NextActivation> {
        self.runtime.next_activations()
    }
}
