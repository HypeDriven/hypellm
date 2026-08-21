//! The planner.
//!
//! A pure function over an immutable snapshot, subject to the same rule as
//! `hypellm_core::policy`: no I/O, no secrets, no clock of its own. Purity buys
//! three operationally significant things.
//!
//! - Plans are deterministic and property-testable.
//! - Identical snapshots produce identical plans, which is what Appendix B's
//!   determinism invariant requires once fleet state is live state.
//! - `POST /admin/v1/fleet:simulate` can answer "what would you do, and why"
//!   with no side effects. Being able to ask a scheduler what it is about to do,
//!   before it does it, is the difference between an operable system and a
//!   haunted one.
//!
//! # Where the entry point lives
//!
//! The design sketch spelled this `FleetPolicy::plan`. It is a free function
//! instead, because which [`crate::model::FleetPolicy`] applies is itself part
//! of the decision — it is selected from the snapshot by host — and a method on
//! the policy would have to be handed the policy it was about to look up.

use crate::demand::DemandSnapshot;
use crate::model::{Deployment, FleetPolicy};
use crate::state::{FleetSnapshot, refine_timing};
use hypellm_core::decision::{ExclusionReason, ResidencyClass};
use hypellm_core::ids::{ArtifactId, DeploymentId, HostId, TargetId};
use hypellm_core::target::Capability;

/// The largest number of steps a plan may carry.
///
/// Two evictions, one fetch, one activation, and headroom. A plan longer than
/// this is a fleet that needs rearranging rather than a scheduler that needs
/// more rope.
pub const MAX_PLAN_STEPS: usize = 8;

/// What the planner is being asked, beyond the snapshot.
#[derive(Debug, Clone)]
pub struct PlanContext {
    /// The router's monotonic clock reading.
    pub now_ms: u64,
    /// Milliseconds left before the request's deadline.
    pub deadline_remaining_ms: u64,
    /// The reasoning tier's output multiplier, for the deadline check.
    pub effort_multiplier: u32,
    /// Generation headroom, per unit of multiplier, that must remain after the
    /// deployment becomes ready.
    pub effort_headroom_ms: u64,
    /// Whether the principal may cause an activation.
    ///
    /// The `fleet.activate` permission, resolved by the caller. A principal
    /// without it may still *use* a warm deployment: this gates causing fleet
    /// work, not reaching a model.
    pub may_activate: bool,
    /// Whether the principal may cause an artifact to be fetched.
    ///
    /// Separate from `may_activate` and not granted by default. Fetching is
    /// the one path on which a request can cost the fleet hours of bandwidth
    /// and hundreds of gigabytes of disk.
    pub may_fetch: bool,
    /// The capability the request is asking for, when the alias declares one.
    ///
    /// Drives the demand comparison. `None` means the alias predates the
    /// capability axis, in which case eviction is judged on the resident set's
    /// value alone and the incoming side contributes only its queue pressure.
    pub capability: Option<Capability>,
    /// A caller-class weight added to the incoming demand value.
    ///
    /// This is where tenant priority enters the eviction decision: a
    /// high-priority tenant's request is worth more to displace something for.
    /// Clamped into [`OPERATOR_TERM_RANGE`] like any other term.
    pub priority_bonus: i64,
}

impl PlanContext {
    /// Milliseconds that must remain after readiness for the work itself.
    #[must_use]
    pub const fn required_headroom_ms(&self) -> u64 {
        // Widening a `u32` into a `u64` is lossless — every value is
        // representable — so no truncation or sign change is possible. The
        // checked form is not callable here because `From` is not const-stable
        // and this must stay `const`, which is the same exemption
        // `ScoreTerms::rank_term` carries for the same reason.
        #[allow(clippy::as_conversions)]
        let multiplier = self.effort_multiplier as u64;
        self.effort_headroom_ms.saturating_mul(multiplier)
    }
}

/// One step of a plan.
///
/// Ordered: every eviction happens before the fetch, and the fetch before the
/// activation. The order is a property of the plan rather than of the executor,
/// so that a simulation shows the operator exactly the sequence that would run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
    /// Drain and stop a deployment to free its memory.
    Evict(DeploymentId),
    /// Acquire an artifact onto a host.
    Fetch {
        /// Which artifact.
        artifact: ArtifactId,
        /// Which host to place it on.
        host: HostId,
    },
    /// Start the deployment the plan exists for.
    Activate(DeploymentId),
}

impl PlanStep {
    /// Stable token for traces and the activations view.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Evict(_) => "evict",
            Self::Fetch { .. } => "fetch",
            Self::Activate(_) => "activate",
        }
    }
}

/// A plan and everything an operator needs to understand it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The deployment the plan makes ready.
    pub deployment: DeploymentId,
    /// The host it lands on.
    pub host: HostId,
    /// The steps, in execution order.
    pub steps: Vec<PlanStep>,
    /// Estimated milliseconds until the deployment can serve.
    pub eta_ms: u64,
    /// Why the plan looks the way it does.
    pub trace: PlanTrace,
}

impl Plan {
    /// Deployments this plan would stop.
    #[must_use]
    pub fn eviction_set(&self) -> Vec<&DeploymentId> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                PlanStep::Evict(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Whether the plan stops anything.
    #[must_use]
    pub fn evicts(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, PlanStep::Evict(_)))
    }

    /// Whether the plan downloads anything.
    #[must_use]
    pub fn fetches(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, PlanStep::Fetch { .. }))
    }
}

/// The reasoning behind a plan, in numbers an operator can check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanTrace {
    /// Memory the deployment needs.
    pub required_bytes: u64,
    /// Memory free in its pool before the plan runs.
    pub free_bytes: u64,
    /// Memory the eviction set frees.
    pub freed_bytes: u64,
    /// What the incoming demand is worth.
    pub incoming_value: i64,
    /// What the eviction set is worth keeping.
    pub retained_value: i64,
    /// The margin the incoming value had to beat.
    pub required_value: i64,
    /// Activations remaining in the host's budget.
    pub budget_remaining: u32,
}

/// The result of planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    /// The deployment is ready now; nothing to do.
    AlreadyResident,
    /// The deployment is coming up under an existing lease.
    AlreadyActivating {
        /// Estimated milliseconds until it is ready.
        eta_ms: u64,
    },
    /// A plan that would make it ready.
    Plan(Box<Plan>),
    /// It cannot be made ready, for this reason.
    Infeasible(ExclusionReason),
}

impl PlanOutcome {
    /// The residency class this outcome implies.
    #[must_use]
    pub fn residency_class(&self) -> ResidencyClass {
        match self {
            Self::AlreadyResident => ResidencyClass::Resident,
            Self::AlreadyActivating { .. } => ResidencyClass::Activating,
            Self::Plan(plan) => {
                if plan.fetches() {
                    ResidencyClass::ColdRequiresFetch
                } else if plan.evicts() {
                    ResidencyClass::ColdRequiresEviction
                } else {
                    ResidencyClass::ColdFits
                }
            }
            Self::Infeasible(reason) => ResidencyClass::Infeasible(*reason),
        }
    }

    /// Estimated milliseconds until the target can serve.
    #[must_use]
    pub fn eta_ms(&self) -> u64 {
        match self {
            Self::AlreadyResident | Self::Infeasible(_) => 0,
            Self::AlreadyActivating { eta_ms } => *eta_ms,
            Self::Plan(plan) => plan.eta_ms,
        }
    }
}

// -- Retention value --------------------------------------------------------
//
// What a resident deployment is worth keeping. Integer, saturating, closed
// inputs, with documented ranges in the style of specification 6.3's score
// terms so that the two read as one system.
//
//   retention_value = demand_term      // smoothed requests per minute
//                   + queue_term       // requests waiting for it
//                   + recency_term     // decayed time since it last served
//                   + restore_term     // start cost × how likely it is wanted
//                   + operator_term    // administrator weight
//                   − staleness_term   // long-idle deployments are cheap
//
// `restore_term` is the one that prevents the obvious failure. Without it the
// planner happily evicts the model about to be needed again, because it is
// momentarily idle, then pays its full load cost thirty seconds later.
// Weighting the *cost of restoring* something by *how likely it is to be
// wanted* is what makes the planner conservative in the right places.

/// Points per request per minute of smoothed demand.
pub const DEMAND_UNIT: i64 = 200;
/// Bound on the demand term.
pub const DEMAND_TERM_RANGE: (i64, i64) = (0, 100_000);
/// Points per request waiting on a capability.
pub const QUEUE_UNIT: i64 = 2_000;
/// Bound on the queue term.
pub const QUEUE_TERM_RANGE: (i64, i64) = (0, 50_000);
/// Bound on the recency term.
pub const RECENCY_TERM_RANGE: (i64, i64) = (0, 50_000);
/// How long a deployment's recency takes to decay to nothing.
pub const RECENCY_HORIZON_MS: u64 = 600_000;
/// Bound on the restore term.
pub const RESTORE_TERM_RANGE: (i64, i64) = (0, 100_000);
/// Bound on the administrator weight and the caller-class bonus.
pub const OPERATOR_TERM_RANGE: (i64, i64) = (-100_000, 100_000);
/// Bound on the staleness penalty.
pub const STALENESS_TERM_RANGE: (i64, i64) = (0, 50_000);
/// Idle time beyond which staleness is at its maximum.
pub const STALENESS_HORIZON_MS: u64 = 3_600_000;

fn clamp(v: i64, range: (i64, i64)) -> i64 {
    v.clamp(range.0, range.1)
}

/// What a resident deployment is worth keeping.
///
/// `capability` is the verb its target serves, used to look up demand. `None`
/// means the deployment's target declares no verb, in which case the demand and
/// queue terms are zero and its value rests on recency and the operator's
/// weight — which is the right answer for a deployment nobody has classified:
/// keep it if it is being used, and let the operator say so if it matters.
#[must_use]
pub fn retention_value(
    deployment: &Deployment,
    capability: Option<Capability>,
    demand: &DemandSnapshot,
    snapshot: &FleetSnapshot,
) -> i64 {
    let rate = capability.map_or(0, |c| demand.rate(c));
    let queued = capability.map_or(0, |c| demand.queue_depth(c));
    let idle = demand.idle(&deployment.id);

    let demand_term = clamp(
        i64::try_from(rate).unwrap_or(i64::MAX).saturating_mul(DEMAND_UNIT),
        DEMAND_TERM_RANGE,
    );
    let queue_term = clamp(
        i64::from(queued).saturating_mul(QUEUE_UNIT),
        QUEUE_TERM_RANGE,
    );

    // Recency decays linearly to nothing over the horizon. Linear rather than
    // exponential because the number has to be explicable to an operator
    // reading it in a trace, and because the horizon is the honest statement
    // of how long "recently used" means here.
    let recency_term = if idle >= RECENCY_HORIZON_MS {
        0
    } else {
        let remaining = RECENCY_HORIZON_MS.saturating_sub(idle);
        clamp(
            i64::try_from(
                remaining
                    .saturating_mul(50_000)
                    .div_euclid(RECENCY_HORIZON_MS),
            )
            .unwrap_or(0),
            RECENCY_TERM_RANGE,
        )
    };

    // The cost of being wrong: how long this would take to bring back,
    // weighted by how likely it is to be wanted. Seconds rather than
    // milliseconds so a three-minute start is 180 units rather than 180,000,
    // which keeps the product inside the range without the clamp doing all the
    // work.
    let start_seconds = i64::try_from(
        snapshot
            .observed_timings
            .get(&deployment.id)
            .and_then(|t| t.start_ms)
            .map_or(deployment.start_ms, |o| refine_timing(deployment.start_ms, Some(o)))
            .div_euclid(1_000),
    )
    .unwrap_or(0);
    let restore_term = clamp(
        start_seconds.saturating_mul(i64::try_from(rate.max(1)).unwrap_or(1)),
        RESTORE_TERM_RANGE,
    );

    let operator_term = clamp(deployment.retention_weight, OPERATOR_TERM_RANGE);

    let staleness_term = if idle == u64::MAX {
        STALENESS_TERM_RANGE.1
    } else {
        clamp(
            i64::try_from(
                idle.min(STALENESS_HORIZON_MS)
                    .saturating_mul(50_000)
                    .div_euclid(STALENESS_HORIZON_MS),
            )
            .unwrap_or(0),
            STALENESS_TERM_RANGE,
        )
    };

    demand_term
        .saturating_add(queue_term)
        .saturating_add(recency_term)
        .saturating_add(restore_term)
        .saturating_add(operator_term)
        .saturating_sub(staleness_term)
}

/// What an incoming request is worth displacing something for.
///
/// Deliberately built from the same terms as [`retention_value`], so the
/// comparison in the hysteresis check is between two figures on one scale
/// rather than two numbers that happen to be integers. The incoming side has no
/// recency or restore cost — it is not resident — and gains the caller-class
/// bonus instead.
#[must_use]
pub fn incoming_value(demand: &DemandSnapshot, context: &PlanContext) -> i64 {
    let rate = context.capability.map_or(0, |c| demand.rate(c));
    // The request being planned for is itself demand, so the queue depth is
    // read as at least one. A first request for a cold capability otherwise
    // arrives with a queue term of zero and can never displace anything, which
    // would make the first request for every capability the one that fails.
    let queued = context.capability.map_or(1, |c| demand.queue_depth(c).max(1));

    let demand_term = clamp(
        i64::try_from(rate).unwrap_or(i64::MAX).saturating_mul(DEMAND_UNIT),
        DEMAND_TERM_RANGE,
    );
    let queue_term = clamp(
        i64::from(queued).saturating_mul(QUEUE_UNIT),
        QUEUE_TERM_RANGE,
    );
    let priority = clamp(context.priority_bonus, OPERATOR_TERM_RANGE);

    demand_term
        .saturating_add(queue_term)
        .saturating_add(priority)
}

// -- The cost model ---------------------------------------------------------

/// Estimated milliseconds to bring `deployment` up, given the plan's steps.
///
/// ```text
/// time_to_ready = Σ(drain_ms + stop_ms over the eviction set)
///               + fetch_ms (if the artifact is absent)
///               + start_ms + probe_ms
/// ```
///
/// Every declared figure is refined by observation within the clamp of
/// [`crate::state::TIMING_CLAMP_FACTOR`].
fn time_to_ready_ms(
    deployment: &Deployment,
    eviction_set: &[&Deployment],
    fetch_ms: u64,
    snapshot: &FleetSnapshot,
) -> u64 {
    let observed = |d: &Deployment| snapshot.observed_timings.get(&d.id).copied().unwrap_or_default();

    let eviction_cost = eviction_set
        .iter()
        .map(|d| {
            let t = observed(d);
            refine_timing(d.drain_ms, t.drain_ms).saturating_add(refine_timing(d.stop_ms, t.stop_ms))
        })
        .fold(0u64, u64::saturating_add);

    let t = observed(deployment);
    eviction_cost
        .saturating_add(fetch_ms)
        .saturating_add(refine_timing(deployment.start_ms, t.start_ms))
        .saturating_add(refine_timing(deployment.probe_ms, t.probe_ms))
}

// -- Classification and planning --------------------------------------------

/// Plan how to make `target` ready, or explain why it cannot be.
///
/// The central rule, and the easiest one to get wrong: **only
/// [`PlanOutcome::Infeasible`] excludes.** A target that is merely not running
/// is still a candidate, ranked below a warm one. If "not currently running"
/// excluded a target, no target would ever start.
#[must_use]
pub fn plan(
    snapshot: &FleetSnapshot,
    demand: &DemandSnapshot,
    target: &TargetId,
    context: &PlanContext,
) -> PlanOutcome {
    let Some(deployment) = snapshot.config.deployment_for_target(target) else {
        // No deployment record: the target behaves exactly as it did before
        // orchestration existed, which is what keeps a deployment-free
        // configuration byte-identical in behaviour.
        return PlanOutcome::AlreadyResident;
    };

    let Some(accelerator) = snapshot.config.accelerator_of(deployment) else {
        return PlanOutcome::Infeasible(ExclusionReason::HostCapacityInsufficient);
    };
    let Some(host) = snapshot.config.hosts.get(&accelerator.host) else {
        return PlanOutcome::Infeasible(ExclusionReason::HostCapacityInsufficient);
    };
    let policy = snapshot.config.policy_for(&host.id);

    // Belief before anything else. Every judgement below is made against the
    // inventory, so a stale one poisons all of them — and a stale-state swap is
    // worse than a rejected request, because it costs minutes of fleet time and
    // can cascade.
    let max_age = snapshot
        .config
        .agents
        .get(&host.agent)
        .map_or(30_000, |a| a.observation_max_age_ms);

    let state = snapshot.state_of(&deployment.id);

    if !snapshot.digest_agreed {
        return PlanOutcome::Infeasible(ExclusionReason::FleetConfigurationMismatch);
    }
    if state.is_serving() {
        // A warm deployment keeps serving even when belief is stale or the
        // host is draining: specification 13 governs it from here, and taking
        // a working model out of rotation because an *observation* is late
        // would turn an agent hiccup into an outage.
        return PlanOutcome::AlreadyResident;
    }
    if !snapshot.agents_reachable {
        return PlanOutcome::Infeasible(ExclusionReason::FleetAgentUnavailable);
    }
    if !snapshot.belief_is_fresh(context.now_ms, max_age) {
        return PlanOutcome::Infeasible(ExclusionReason::FleetStateStale);
    }

    if state.is_activating() {
        let eta = time_to_ready_ms(deployment, &[], 0, snapshot);
        return PlanOutcome::AlreadyActivating { eta_ms: eta };
    }

    // From here the deployment is cold and something has to happen.
    if !context.may_activate || !deployment.autostart {
        return PlanOutcome::Infeasible(ExclusionReason::ActivationNotPermitted);
    }
    if !host.state.admits_activation() {
        return PlanOutcome::Infeasible(ExclusionReason::ActivationNotPermitted);
    }
    if let Some(until) = snapshot.cooldown_until_ms.get(&deployment.id) {
        if context.now_ms < *until {
            // A deployment inside its cooldown is not merely unattractive; it
            // is refused. The cooldown exists because it has just been evicted
            // or has been flapping, and both are reasons not to try again yet.
            return PlanOutcome::Infeasible(ExclusionReason::DeploymentInDwell);
        }
    }
    let budget_remaining = snapshot
        .activation_budget
        .get(&host.id)
        .copied()
        .unwrap_or(policy.max_activations_per_hour);
    if budget_remaining == 0 {
        return PlanOutcome::Infeasible(ExclusionReason::ActivationBudgetExhausted);
    }
    let in_flight = snapshot
        .config
        .deployments
        .values()
        .filter(|d| {
            snapshot
                .config
                .accelerator_of(d)
                .is_some_and(|a| a.host == host.id)
                && snapshot.state_of(&d.id).is_activating()
        })
        .count();
    if u64::try_from(in_flight).unwrap_or(u64::MAX)
        >= u64::from(host.max_concurrent_activations.max(1))
    {
        return PlanOutcome::Infeasible(ExclusionReason::ActivationBudgetExhausted);
    }

    // The artifact, before memory: a fetch is far more expensive than an
    // eviction, and a plan that evicted a running model and *then* discovered
    // the artifact was missing would have made the fleet strictly worse.
    let mut steps: Vec<PlanStep> = Vec::new();
    let mut fetch_ms = 0;
    if let Some(artifact_id) = &deployment.artifact {
        let Some(artifact) = snapshot.config.artifacts.get(artifact_id) else {
            return PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable);
        };
        if !snapshot.artifact_ready(artifact_id, &host.id) {
            if artifact.arch != host.arch {
                // An x86-64 image will never run on the Spark, and no amount
                // of downloading changes that.
                return PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable);
            }
            if !policy.allow_fetch || !context.may_fetch {
                return PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable);
            }
            let needed = artifact
                .size_bytes
                .saturating_add(policy.fetch_disk_headroom_bytes);
            if snapshot.free_disk_bytes(&host.id) < needed {
                return PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable);
            }
            fetch_ms = estimated_fetch_ms(artifact.size_bytes, snapshot, &deployment.id);
            steps.push(PlanStep::Fetch {
                artifact: artifact_id.clone(),
                host: host.id.clone(),
            });
        }
    }

    // Memory.
    let pool = &accelerator.pool;
    let free = snapshot.pool_free_bytes(pool);
    let required = deployment.memory_bytes.saturating_sub(free);

    let mut trace = PlanTrace {
        required_bytes: deployment.memory_bytes,
        free_bytes: free,
        budget_remaining,
        ..PlanTrace::default()
    };

    let eviction_set: Vec<&Deployment> = if required == 0 {
        Vec::new()
    } else {
        match select_eviction_set(snapshot, demand, deployment, required, &policy, context) {
            Ok(set) => set,
            Err(reason) => return PlanOutcome::Infeasible(reason),
        }
    };

    if !eviction_set.is_empty() {
        let freed: u64 = eviction_set
            .iter()
            .map(|d| resident_bytes(snapshot, d))
            .fold(0u64, u64::saturating_add);
        trace.freed_bytes = freed;

        let retained: i64 = eviction_set
            .iter()
            .map(|d| retention_value(d, capability_of(snapshot, d), demand, snapshot))
            .fold(0i64, i64::saturating_add);
        let incoming = incoming_value(demand, context);
        // Strictly greater, by the margin. Two capabilities of near-identical
        // value must not trade places on noise.
        let required_value = retained.saturating_add(
            retained
                .max(0)
                .saturating_mul(i64::from(policy.eviction_margin_permille))
                .div_euclid(1_000),
        );
        trace.retained_value = retained;
        trace.incoming_value = incoming;
        trace.required_value = required_value;
        if incoming <= required_value {
            // The set was evictable and large enough; it was simply not worth
            // displacing. Operationally different from having nothing to evict,
            // and the operator's lever is demand or `eviction_margin` rather
            // than waiting for a dwell window to elapse.
            return PlanOutcome::Infeasible(ExclusionReason::EvictionValueInsufficient);
        }

        for victim in &eviction_set {
            steps.push(PlanStep::Evict(victim.id.clone()));
        }
        // Evictions run before the fetch and the activation. Sorting by kind
        // keeps the plan's order the execution order even though the fetch step
        // was appended first.
        steps.sort_by_key(|step| match step {
            PlanStep::Evict(_) => 0,
            PlanStep::Fetch { .. } => 1,
            PlanStep::Activate(_) => 2,
        });
    }

    steps.push(PlanStep::Activate(deployment.id.clone()));
    if steps.len() > MAX_PLAN_STEPS {
        return PlanOutcome::Infeasible(ExclusionReason::HostCapacityInsufficient);
    }

    let eta = time_to_ready_ms(deployment, &eviction_set, fetch_ms, snapshot);
    if eta.saturating_add(context.required_headroom_ms()) > context.deadline_remaining_ms {
        return PlanOutcome::Infeasible(ExclusionReason::ActivationExceedsDeadline);
    }

    PlanOutcome::Plan(Box::new(Plan {
        deployment: deployment.id.clone(),
        host: host.id.clone(),
        steps,
        eta_ms: eta,
        trace,
    }))
}

/// The verb a deployment's target serves, when the caller supplied a map.
///
/// The fleet crate does not hold `Target` records — that is `PolicySnapshot`'s
/// job — so a deployment's capability is carried on the demand snapshot's
/// behalf by the caller. Returning `None` here means the retention value rests
/// on recency and operator weight, which is the documented behaviour for an
/// unclassified deployment.
fn capability_of(snapshot: &FleetSnapshot, deployment: &Deployment) -> Option<Capability> {
    snapshot.deployment_capabilities.get(&deployment.id).copied()
}

/// Memory a resident deployment would actually free.
///
/// The larger of its declaration and what the accelerator says it is using,
/// for the same reason `pool_used_bytes` takes the larger: the declaration is
/// a promise and the observation is the fact.
fn resident_bytes(snapshot: &FleetSnapshot, deployment: &Deployment) -> u64 {
    let observed = snapshot
        .inventory
        .deployments
        .get(&deployment.id)
        .map_or(0, |o| o.observed_memory_bytes);
    deployment.memory_bytes.max(observed)
}

/// How long acquiring an artifact is expected to take.
///
/// A configured floor plus a size-derived estimate. Deliberately crude: the
/// number exists to keep a 40 GB download from being offered against a
/// thirty-second deadline, and precision beyond that would be false.
fn estimated_fetch_ms(size_bytes: u64, snapshot: &FleetSnapshot, deployment: &DeploymentId) -> u64 {
    if let Some(observed) = snapshot
        .observed_timings
        .get(deployment)
        .and_then(|t| t.fetch_ms)
    {
        return observed;
    }
    /// Assumed throughput, in bytes per second. A gigabit link that is also
    /// carrying inference traffic.
    const ASSUMED_BYTES_PER_SECOND: u64 = 50 * 1024 * 1024;
    size_bytes
        .div_euclid(ASSUMED_BYTES_PER_SECOND)
        .saturating_mul(1_000)
        .max(30_000)
}

/// Choose the smallest admissible set of deployments to stop.
///
/// Bounded, deterministic, no combinatorial search:
///
/// 1. Exclude outright anything the operator has anchored, anything inside its
///    dwell window, anything busy, and anything the router does not own.
/// 2. Sort by retention value ascending, tie-broken by identifier ascending so
///    the order is total and independent of map iteration (Appendix B).
/// 3. Take the smallest prefix that frees enough.
///
/// The distinction between "nothing to evict" and "everything is in dwell" is
/// preserved, because the two are operationally different and an operator must
/// be able to tell them apart.
fn select_eviction_set<'a>(
    snapshot: &'a FleetSnapshot,
    demand: &DemandSnapshot,
    incoming: &Deployment,
    required_bytes: u64,
    policy: &FleetPolicy,
    context: &PlanContext,
) -> Result<Vec<&'a Deployment>, ExclusionReason> {
    let Some(accelerator) = snapshot.config.accelerator_of(incoming) else {
        return Err(ExclusionReason::HostCapacityInsufficient);
    };
    let pool = &accelerator.pool;

    let mut dwell_blocked = false;
    let mut candidates: Vec<(&Deployment, i64)> = Vec::new();

    for resident in snapshot.config.deployments_in_pool(pool) {
        if resident.id == incoming.id {
            continue;
        }
        let state = snapshot.state_of(&resident.id);
        if !state.holds_memory() {
            continue;
        }
        // An operator's anchor is not an economic argument. The planner is not
        // asked to be clever about things the operator has already decided.
        if resident.pinned || !resident.evictable {
            continue;
        }
        if !snapshot.is_router_owned(&resident.id) && !policy.adopt_unmanaged {
            continue;
        }
        // Currently activating: stopping something on its way up wastes the
        // load already paid for and produces exactly the ping-pong the dwell
        // floor exists to prevent.
        if state.is_activating() {
            continue;
        }
        if snapshot.inflight(&resident.id) > resident.max_drainable_inflight {
            continue;
        }
        if snapshot.resident_for_ms(&resident.id, context.now_ms) < resident.min_resident_ms {
            dwell_blocked = true;
            continue;
        }
        let value = retention_value(resident, capability_of(snapshot, resident), demand, snapshot);
        candidates.push((resident, value));
    }

    // Ascending by value, then by identifier. The second key is what makes the
    // order total: two deployments with equal value must not swap places
    // between two identical snapshots.
    candidates.sort_by(|(a, va), (b, vb)| va.cmp(vb).then_with(|| a.id.cmp(&b.id)));

    let cap = usize::try_from(policy.max_eviction_set.max(1)).unwrap_or(2);
    let mut set: Vec<&Deployment> = Vec::new();
    let mut freed: u64 = 0;
    for (deployment, _) in candidates {
        if freed >= required_bytes {
            break;
        }
        if set.len() >= cap {
            break;
        }
        freed = freed.saturating_add(resident_bytes(snapshot, deployment));
        set.push(deployment);
    }

    if freed < required_bytes {
        // If the shortfall is caused only by dwell exclusions, say so: waiting
        // will fix it, and rearranging the fleet will not.
        return Err(if dwell_blocked {
            ExclusionReason::DeploymentInDwell
        } else {
            ExclusionReason::HostCapacityInsufficient
        });
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Accelerator, AcceleratorKind, Arch, FleetAgent, FleetConfig, Host, HostState, Readiness,
    };
    use crate::state::{DeploymentObservation, FleetSnapshot, ObservedState};
    use hypellm_core::ids::{AcceleratorId, AgentId, PoolId};
    use std::sync::Arc;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn dep(id: &str, memory: u64) -> Deployment {
        Deployment {
            id: DeploymentId::new(id).expect("id"),
            target: TargetId::new(format!("spark:{id}")).expect("id"),
            accelerator: AcceleratorId::new("gb10").expect("id"),
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

    fn spark() -> FleetConfig {
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
                reserved_memory_bytes: 16 * GIB,
                max_concurrent_activations: 1,
            },
        );
        fleet.accelerators.insert(
            AcceleratorId::new("gb10").expect("id"),
            Accelerator {
                id: AcceleratorId::new("gb10").expect("id"),
                host: HostId::new("spark").expect("id"),
                kind: AcceleratorKind::Unified,
                memory_bytes: 130 * GIB,
                pool: PoolId::new("spark-unified").expect("id"),
            },
        );
        fleet
    }

    fn snapshot(fleet: FleetConfig) -> FleetSnapshot {
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(fleet);
        snapshot.observed = true;
        snapshot.observed_at_ms = 1_000;
        snapshot
    }

    fn ready(snapshot: &mut FleetSnapshot, id: &str, since_ms: u64, memory: u64) {
        let did = DeploymentId::new(id).expect("id");
        snapshot.inventory.deployments.insert(
            did.clone(),
            DeploymentObservation {
                deployment: did.clone(),
                state: ObservedState::Ready,
                observed_memory_bytes: memory,
                state_age_ms: 0,
                inflight: 0,
            },
        );
        snapshot.ready_since_ms.insert(did, since_ms);
    }

    /// Plan with belief taken at the same moment the decision is made.
    ///
    /// Freshness is a separate property with its own test; every other test
    /// here is about what the planner decides, and a fixture that let belief
    /// age out silently would turn all of them into staleness tests.
    fn plan_now(
        snapshot: &FleetSnapshot,
        demand: &DemandSnapshot,
        target: &TargetId,
        now_ms: u64,
    ) -> PlanOutcome {
        let mut fresh = snapshot.clone();
        fresh.observed_at_ms = now_ms;
        plan(&fresh, demand, target, &context(now_ms))
    }

    fn context(now_ms: u64) -> PlanContext {
        PlanContext {
            now_ms,
            deadline_remaining_ms: 900_000,
            effort_multiplier: 1,
            effort_headroom_ms: 5_000,
            may_activate: true,
            may_fetch: false,
            capability: Some(Capability::TextToMusic),
            priority_bonus: 0,
        }
    }

    #[test]
    fn a_deployment_inside_its_dwell_window_is_never_evicted() {
        // The adversarial shape: the dwell-protected deployment is exactly the
        // one the planner most wants to evict — idle, cheap to restore, and
        // large enough on its own to make room.
        // The worked example's numbers: 114 GiB offered after the host
        // reservation, a pinned 26 GiB chat model that every harness depends
        // on, a 48 GiB audio model six minutes into a ten-minute dwell floor,
        // and a 64 GiB music model that cannot fit alongside either.
        let mut fleet = spark();
        let music = dep("spark-music3", 64 * GIB);
        let h3 = dep("spark-h3", 48 * GIB);
        let mut chat = dep("spark-qwen38", 26 * GIB);
        chat.pinned = true;
        fleet.deployments.insert(music.id.clone(), music.clone());
        fleet.deployments.insert(h3.id.clone(), h3.clone());
        fleet.deployments.insert(chat.id.clone(), chat.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-qwen38", 0, 26 * GIB);
        ready(&mut snap, "spark-h3", 1_000, 48 * GIB);
        let now = 1_000 + 360_000;

        let outcome = plan_now(&snap, &DemandSnapshot::default(), &music.target, now);
        assert_eq!(
            outcome,
            PlanOutcome::Infeasible(ExclusionReason::DeploymentInDwell),
            "six minutes into a ten-minute dwell floor is not evictable"
        );

        // Four minutes later it is, and the plan appears.
        let later = 1_000 + 601_000;
        let mut demand = DemandSnapshot::default();
        demand.rate_per_minute.insert(Capability::TextToMusic, 30);
        demand.idle_ms.insert(h3.id.clone(), 600_000);
        let outcome = plan_now(&snap, &demand, &music.target, later);
        let PlanOutcome::Plan(plan) = outcome else {
            panic!("expected a plan once dwell has elapsed, got {outcome:?}");
        };
        assert_eq!(plan.eviction_set(), vec![&h3.id]);
    }

    #[test]
    fn a_pinned_deployment_never_appears_in_an_eviction_set() {
        // Adversarial: the pin is also the *cheapest* option — idle, no
        // demand, and exactly large enough. A planner that scored pins rather
        // than filtering them would take it every time.
        let mut fleet = spark();
        let music = dep("spark-music3", 64 * GIB);
        let mut chat = dep("spark-chat", 64 * GIB);
        chat.pinned = true;
        chat.min_resident_ms = 0;
        fleet.deployments.insert(music.id.clone(), music.clone());
        fleet.deployments.insert(chat.id.clone(), chat.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-chat", 0, 64 * GIB);

        let mut demand = DemandSnapshot::default();
        demand.idle_ms.insert(chat.id.clone(), u64::MAX);
        demand.rate_per_minute.insert(Capability::TextToMusic, 100);

        assert_eq!(
            plan_now(&snap, &demand, &music.target, 1_000_000),
            PlanOutcome::Infeasible(ExclusionReason::HostCapacityInsufficient),
        );
    }

    #[test]
    fn no_eviction_occurs_without_the_configured_hysteresis_margin() {
        // Two capabilities of near-identical value must not trade places. The
        // resident deployment here is worth *slightly* less than the incoming
        // demand — enough to lose a bare comparison, not enough to beat the
        // 25% margin.
        let mut fleet = spark();
        let music = dep("spark-music3", 64 * GIB);
        let mut h3 = dep("spark-h3", 64 * GIB);
        h3.min_resident_ms = 0;
        fleet.deployments.insert(music.id.clone(), music.clone());
        fleet.deployments.insert(h3.id.clone(), h3.clone());
        let mut snap = snapshot(fleet);
        snap.deployment_capabilities
            .insert(h3.id.clone(), Capability::AudioToVideo);
        ready(&mut snap, "spark-h3", 0, 64 * GIB);

        let mut demand = DemandSnapshot::default();
        // Both busy, the incumbent marginally less so.
        demand.rate_per_minute.insert(Capability::AudioToVideo, 40);
        demand.rate_per_minute.insert(Capability::TextToMusic, 44);
        demand.idle_ms.insert(h3.id.clone(), 0);

        let outcome = plan_now(&snap, &demand, &music.target, 1_000_000);
        assert_eq!(
            outcome,
            PlanOutcome::Infeasible(ExclusionReason::EvictionValueInsufficient),
        );

        // A decisive difference does displace it.
        demand.rate_per_minute.insert(Capability::TextToMusic, 500);
        let outcome = plan_now(&snap, &demand, &music.target, 1_000_000);
        assert!(matches!(outcome, PlanOutcome::Plan(_)), "got {outcome:?}");
    }

    #[test]
    fn a_cold_target_beyond_the_effort_adjusted_deadline_is_excluded_not_activated() {
        // 180 s start + 10 s probe against a 200 s deadline fits at minimal
        // effort and does not at high, because the headroom scales with the
        // tier's multiplier. The point is that the *fleet work* is refused —
        // not that the request fails later.
        let mut fleet = spark();
        let music = dep("spark-music3", 8 * GIB);
        fleet.deployments.insert(music.id.clone(), music.clone());
        let snap = snapshot(fleet);

        let mut ctx = context(1_000);
        ctx.deadline_remaining_ms = 200_000;
        ctx.effort_multiplier = 1;
        assert!(matches!(
            plan(&snap, &DemandSnapshot::default(), &music.target, &ctx),
            PlanOutcome::Plan(_)
        ));

        ctx.effort_multiplier = 8;
        assert_eq!(
            plan(&snap, &DemandSnapshot::default(), &music.target, &ctx),
            PlanOutcome::Infeasible(ExclusionReason::ActivationExceedsDeadline),
        );
    }

    #[test]
    fn stale_belief_refuses_to_plan_but_keeps_a_warm_deployment_serving() {
        let mut fleet = spark();
        let music = dep("spark-music3", 8 * GIB);
        let chat = dep("spark-chat", 8 * GIB);
        fleet.deployments.insert(music.id.clone(), music.clone());
        fleet.deployments.insert(chat.id.clone(), chat.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-chat", 0, 8 * GIB);

        // 60 s past a 30 s maximum age.
        let now = 61_000;
        assert_eq!(
            plan(&snap, &DemandSnapshot::default(), &music.target, &context(now)),
            PlanOutcome::Infeasible(ExclusionReason::FleetStateStale),
        );
        assert_eq!(
            plan(&snap, &DemandSnapshot::default(), &chat.target, &context(now)),
            PlanOutcome::AlreadyResident,
            "a model that is up keeps serving; specification 13 governs it from here"
        );
    }

    #[test]
    fn a_principal_without_the_activation_permission_causes_no_fleet_work() {
        let mut fleet = spark();
        let music = dep("spark-music3", 8 * GIB);
        fleet.deployments.insert(music.id.clone(), music.clone());
        let snap = snapshot(fleet);

        let mut ctx = context(1_000);
        ctx.may_activate = false;
        assert_eq!(
            plan(&snap, &DemandSnapshot::default(), &music.target, &ctx),
            PlanOutcome::Infeasible(ExclusionReason::ActivationNotPermitted),
        );
    }

    #[test]
    fn an_exhausted_activation_budget_refuses_rather_than_queueing_forever() {
        let mut fleet = spark();
        let music = dep("spark-music3", 8 * GIB);
        fleet.deployments.insert(music.id.clone(), music.clone());
        let mut snap = snapshot(fleet);
        snap.activation_budget
            .insert(HostId::new("spark").expect("id"), 0);
        assert_eq!(
            plan(&snap, &DemandSnapshot::default(), &music.target, &context(1_000)),
            PlanOutcome::Infeasible(ExclusionReason::ActivationBudgetExhausted),
        );
    }

    #[test]
    fn an_unfetchable_artifact_never_produces_a_plan_that_evicts() {
        // The expensive mistake this prevents: stopping a running model, then
        // discovering the thing being started is not on the machine.
        let mut fleet = spark();
        let mut music = dep("spark-music3", 64 * GIB);
        music.artifact = Some(ArtifactId::new("music3-arm64").expect("id"));
        let mut h3 = dep("spark-h3", 64 * GIB);
        h3.min_resident_ms = 0;
        fleet.artifacts.insert(
            ArtifactId::new("music3-arm64").expect("id"),
            crate::model::Artifact {
                id: ArtifactId::new("music3-arm64").expect("id"),
                kind: crate::model::ArtifactKind::Image,
                arch: Arch::Aarch64,
                size_bytes: 20 * GIB,
                digest: "sha256:00".to_owned(),
                source: "mirror-local".to_owned(),
            },
        );
        fleet.deployments.insert(music.id.clone(), music.clone());
        fleet.deployments.insert(h3.id.clone(), h3.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-h3", 0, 64 * GIB);

        let mut demand = DemandSnapshot::default();
        demand.rate_per_minute.insert(Capability::TextToMusic, 500);
        demand.idle_ms.insert(h3.id.clone(), u64::MAX);

        // Fetch is off by default, so the artifact cannot be acquired.
        assert_eq!(
            plan_now(&snap, &demand, &music.target, 1_000_000),
            PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable),
        );
    }

    #[test]
    fn equal_snapshots_produce_equal_plans() {
        let mut fleet = spark();
        for (name, memory) in [("spark-a", 32 * GIB), ("spark-b", 32 * GIB)] {
            let mut d = dep(name, memory);
            d.min_resident_ms = 0;
            fleet.deployments.insert(d.id.clone(), d);
        }
        let music = dep("spark-music3", 64 * GIB);
        fleet.deployments.insert(music.id.clone(), music.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-a", 0, 32 * GIB);
        ready(&mut snap, "spark-b", 0, 32 * GIB);

        let mut demand = DemandSnapshot::default();
        demand.rate_per_minute.insert(Capability::TextToMusic, 500);

        let first = plan_now(&snap, &demand, &music.target, 1_000_000);
        for _ in 0..32 {
            assert_eq!(
                plan_now(&snap, &demand, &music.target, 1_000_000),
                first,
                "identical snapshots must produce identical plans"
            );
        }
    }

    #[test]
    fn a_plan_that_evicts_frees_at_least_the_required_memory() {
        let mut fleet = spark();
        let music = dep("spark-music3", 100 * GIB);
        for (name, memory) in [("spark-a", 32 * GIB), ("spark-b", 32 * GIB)] {
            let mut d = dep(name, memory);
            d.min_resident_ms = 0;
            fleet.deployments.insert(d.id.clone(), d);
        }
        fleet.deployments.insert(music.id.clone(), music.clone());
        let mut snap = snapshot(fleet);
        ready(&mut snap, "spark-a", 0, 32 * GIB);
        ready(&mut snap, "spark-b", 0, 32 * GIB);

        let mut demand = DemandSnapshot::default();
        demand.rate_per_minute.insert(Capability::TextToMusic, 500);

        let PlanOutcome::Plan(plan) = plan_now(&snap, &demand, &music.target, 1_000_000)
        else {
            panic!("expected a plan");
        };
        let free = snap.pool_free_bytes(&PoolId::new("spark-unified").expect("id"));
        assert!(
            plan.trace.freed_bytes.saturating_add(free) >= music.memory_bytes,
            "freed {} + free {} must cover {}",
            plan.trace.freed_bytes,
            free,
            music.memory_bytes
        );
    }
}
