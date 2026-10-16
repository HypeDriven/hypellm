//! Churn-aware scheduling: which waiting work goes next (specification 26.11).
//!
//! Pure, like the planner and the idle predicate: the runtime gathers the
//! inputs, this decides, and the runtime acts. Nothing here reads a clock, a
//! map's iteration order, or a socket, so equal inputs give equal answers and
//! the property suite can check the decisions over generated fleets.
//!
//! # The problem
//!
//! Warm-first routing, dwell floors, cooldowns, flap backoff and the hourly
//! budget all bound *how often* a host may swap models. None of them decides
//! *which* waiting model a free host should load next, or whether a loaded
//! model with work still queued should be displaced at all. Left to arrival
//! order, an interleaved stream — A, B, A, B — swaps on every request, and the
//! fleet spends its time loading weights instead of serving them.
//!
//! # The two decisions
//!
//! 1. **[`gate`] — may this activation go now?** When the batching queue says a
//!    capability has earned an activation, the gate compares the deployment it
//!    would load with every other deployment requests are waiting for on the
//!    same host. The best-ranked goes; the rest wait for the host to come free.
//!    A swap that would stop a model still carrying work is deferred while that
//!    model has work — the hysteresis that keeps two busy models from
//!    ping-ponging one slot.
//! 2. **[`pick_job`] — which queued job does a free worker take?** Jobs whose
//!    model is already loaded first, then jobs for a model being loaded, then
//!    cold jobs grouped by model, so one activation serves the whole group.
//!
//! # The starvation bound
//!
//! Every reordering is bounded by `max_reorder_wait_ms`. Work that has waited
//! that long is served in age order ahead of any score, whatever it would
//! displace, so reordering can delay work by at most the bound and never
//! indefinitely. Zero disables reordering: activations go first-come and jobs
//! are taken in queue order, exactly as before this module existed.
//!
//! The bound does not override the safety controls. A starving deployment
//! still needs a plan the planner accepts — dwell floor, cooldown, budget and
//! eviction margin all still apply — so "served ahead of score" means "first in
//! line", not "permitted to break the fleet's rules".

use hypellm_core::ids::DeploymentId;

use crate::model::FleetPolicy;

/// The largest `max_reorder_wait_ms` a policy may declare.
///
/// An hour. Past that, "bounded delay" stops meaning anything a caller would
/// recognise, and an operator who wants arrival order sets zero.
pub const MAX_REORDER_WAIT_MS: u64 = 3_600_000;

/// The smallest non-zero `max_reorder_wait_ms` a policy may declare.
///
/// Shorter than a typical model load, every waiting deployment would be
/// starving by the time the host came free, and the reordering would be
/// arrival order with extra steps.
pub const MIN_REORDER_WAIT_MS: u64 = 5_000;

/// One deployment that requests are waiting for a host to load.
///
/// Demand is counted per deployment rather than per capability: two chat
/// models on one host serve the same capability, and choosing between them is
/// exactly the decision this module exists to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contender {
    /// The deployment on this host the waiting requests could use.
    pub deployment: DeploymentId,
    /// Requests waiting for it.
    pub waiting: u32,
    /// When the oldest of them started waiting, on the router's clock.
    pub oldest_ms: u64,
    /// Expected milliseconds from deciding to serving, eviction excluded.
    pub restore_cost_ms: u64,
}

impl Contender {
    /// How long the oldest waiting request has waited.
    #[must_use]
    pub const fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.oldest_ms)
    }

    /// Whether the oldest request has waited past the reordering bound.
    #[must_use]
    pub const fn is_starving(&self, now_ms: u64, policy: &FleetPolicy) -> bool {
        policy.max_reorder_wait_ms != 0 && self.age_ms(now_ms) >= policy.max_reorder_wait_ms
    }

    /// Whether the batching thresholds say this deployment has earned an
    /// activation: enough demand, a long enough wait, or starvation.
    #[must_use]
    pub fn is_ready(&self, now_ms: u64, policy: &FleetPolicy) -> bool {
        self.waiting > 0
            && (self.waiting >= policy.activation_min_demand.max(1)
                || self.age_ms(now_ms) >= policy.activation_max_wait_ms
                || self.is_starving(now_ms, policy))
    }

    /// Throughput priority: waiting demand, aged, per unit of load cost.
    ///
    /// `waiting × (1000 + age in tenths of a second)`, so a second of waiting
    /// adds one percent to each request's weight, scaled by
    /// `1_000_000 / (restore_cost + 30 s)`, so a model that loads in ten
    /// seconds is worth more per waiting request than one that takes ten
    /// minutes. The 30-second floor keeps a near-instant model from dwarfing
    /// every other term. Saturating integer arithmetic throughout
    /// (specification 6.3): a pathological input saturates, never wraps.
    #[must_use]
    pub fn priority(&self, now_ms: u64) -> u64 {
        let aged = 1_000_u64.saturating_add(self.age_ms(now_ms).div_euclid(100));
        let value = u64::from(self.waiting).saturating_mul(aged);
        let cost = self.restore_cost_ms.saturating_add(30_000);
        // `cost` is at least 30 000, so the division cannot be by zero.
        value.saturating_mul(1_000_000).div_euclid(cost)
    }
}

/// Order contenders for one host: the first should be loaded next.
///
/// Expects at most one contender per deployment; the caller aggregates.
///
/// Starving contenders first, oldest first. Then everything else by
/// [`Contender::priority`], highest first, ties broken by cheaper load, then
/// older demand, then deployment identifier — a total order over the inputs'
/// *content*, so permuting the input never changes the answer.
#[must_use]
pub fn rank<'a>(contenders: &'a [Contender], now_ms: u64, policy: &FleetPolicy) -> Vec<&'a Contender> {
    let mut ranked: Vec<&Contender> = contenders.iter().collect();
    ranked.sort_by(|a, b| {
        let starving_a = a.is_starving(now_ms, policy);
        let starving_b = b.is_starving(now_ms, policy);
        starving_b
            .cmp(&starving_a)
            .then_with(|| {
                if starving_a && starving_b {
                    a.oldest_ms.cmp(&b.oldest_ms)
                } else {
                    b.priority(now_ms).cmp(&a.priority(now_ms))
                }
            })
            .then_with(|| a.restore_cost_ms.cmp(&b.restore_cost_ms))
            .then_with(|| a.oldest_ms.cmp(&b.oldest_ms))
            .then_with(|| a.deployment.cmp(&b.deployment))
    });
    ranked
}

/// Why an activation may go now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proceed {
    /// Reordering is switched off (`max_reorder_wait_ms=0`).
    Disabled,
    /// Nothing else is waiting for this host.
    Uncontended,
    /// Others are waiting, and this ranks first among them.
    Ranked,
    /// It has waited past the bound and goes ahead of score.
    Starving,
}

impl Proceed {
    /// Stable token, for metrics and the fleet view.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Uncontended => "uncontended",
            Self::Ranked => "ranked",
            Self::Starving => "starving",
        }
    }
}

/// Why an activation should wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defer {
    /// Another deployment waiting for the same host ranks higher.
    Outranked,
    /// The plan would stop a model that still has work in flight.
    WarmDemand,
}

impl Defer {
    /// Stable token, for metrics and the fleet view.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outranked => "outranked",
            Self::WarmDemand => "warm_demand",
        }
    }
}

/// The gate's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Go: this request pays for the activation.
    Proceed(Proceed),
    /// Wait for the host to come free, or the loaded model to go idle.
    Defer(Defer),
}

/// What the gate needs to know about the plan being asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asking<'a> {
    /// The deployment the plan would make ready.
    pub deployment: &'a DeploymentId,
    /// Whether the plan stops anything.
    pub evicts: bool,
    /// Whether any deployment it would stop has work in flight.
    pub victims_busy: bool,
}

/// May the activation of `asking` go now, given everything waiting for its host?
///
/// `contenders` is every deployment requests are waiting for on this host,
/// the asking one included — the caller counts the asking request in when it
/// is not yet waiting, so a newcomer is ranked rather than waved through. An asking deployment absent from them — its waiters left between
/// the queue's answer and this call — is treated as uncontended rather than
/// refused: the batching queue already said it had earned the activation, and
/// refusing on a race would strand the request that is still here.
#[must_use]
pub fn gate(asking: &Asking<'_>, contenders: &[Contender], now_ms: u64, policy: &FleetPolicy) -> Verdict {
    if policy.max_reorder_wait_ms == 0 {
        return Verdict::Proceed(Proceed::Disabled);
    }
    let own = contenders.iter().find(|c| &c.deployment == asking.deployment);
    let starving = own.is_some_and(|c| c.is_starving(now_ms, policy));

    // Hysteresis. A model still carrying work is not displaced for a model that
    // has not waited past the bound: the swap would stop work to start work,
    // and the next arrival for the stopped model would swap straight back.
    if asking.evicts && asking.victims_busy && !starving {
        return Verdict::Defer(Defer::WarmDemand);
    }
    let Some(own) = own else {
        return Verdict::Proceed(Proceed::Uncontended);
    };

    let ready: Vec<Contender> = contenders
        .iter()
        .filter(|c| c.is_ready(now_ms, policy) || c.deployment == own.deployment)
        .cloned()
        .collect();
    let ranked = rank(&ready, now_ms, policy);
    match ranked.first() {
        Some(first) if first.deployment != own.deployment => Verdict::Defer(Defer::Outranked),
        _ if starving => Verdict::Proceed(Proceed::Starving),
        _ if ranked.len() > 1 => Verdict::Proceed(Proceed::Ranked),
        _ => Verdict::Proceed(Proceed::Uncontended),
    }
}

/// What the churn-aware scheduler would load next on one host
/// (specification 26.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextActivation {
    /// The host.
    pub host: hypellm_core::ids::HostId,
    /// The deployment that ranks first.
    pub deployment: DeploymentId,
    /// Requests waiting for it.
    pub waiting: u32,
    /// How long the oldest of them has waited.
    pub waited_ms: u64,
    /// `starving` when it has waited past the bound, `ranked` when it outranks
    /// others, `uncontended` when nothing else waits for the host.
    pub reason: &'static str,
    /// How many deployments are waiting for the host, this one included.
    pub contenders: usize,
}

/// How a queued job's model stands right now.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobClass {
    /// Something that can serve it is loaded, or it needs no fleet at all.
    Warm,
    /// A deployment that can serve it is being started.
    Activating,
    /// Nothing that can serve it is running; the key groups jobs one
    /// activation would serve together.
    Cold(String),
}

/// One job a worker could take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobEntry {
    /// Submission order. Kept across re-queues, so a job that waited for
    /// capacity keeps its place.
    pub seq: u64,
    /// When it was submitted, on the router's clock.
    pub submitted_ms: u64,
    /// Whether its backoff has elapsed.
    pub due: bool,
    /// How its model stands.
    pub class: JobClass,
}

/// Which job a free worker should take, as an index into `entries`.
///
/// `entries` is in queue order. With reordering disabled, the first due entry
/// — the queue's own order, as before. Otherwise, among due entries:
///
/// 1. any that has waited past `max_reorder_wait_ms`, lowest `seq` first;
/// 2. `Warm`, lowest `seq` first;
/// 3. `Activating`, lowest `seq` first;
/// 4. `Cold`, from the group with the most due jobs (ties to the group whose
///    oldest job is oldest), lowest `seq` within it.
///
/// Tenant fairness is the starvation bound: no class or group may hold any
/// tenant's job past it. Within a class the order is submission order, which
/// is what every tenant had before.
#[must_use]
pub fn pick_job(entries: &[JobEntry], now_ms: u64, max_reorder_wait_ms: u64) -> Option<usize> {
    let due = entries.iter().enumerate().filter(|(_, e)| e.due);
    if max_reorder_wait_ms == 0 {
        return due.map(|(i, _)| i).next();
    }
    let due: Vec<(usize, &JobEntry)> = due.collect();
    let oldest = |pick: &mut dyn Iterator<Item = &(usize, &JobEntry)>| {
        pick.min_by_key(|(_, e)| e.seq).map(|(i, _)| *i)
    };

    if let Some(i) = oldest(
        &mut due
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.submitted_ms) >= max_reorder_wait_ms),
    ) {
        return Some(i);
    }
    if let Some(i) = oldest(&mut due.iter().filter(|(_, e)| e.class == JobClass::Warm)) {
        return Some(i);
    }
    if let Some(i) = oldest(&mut due.iter().filter(|(_, e)| e.class == JobClass::Activating)) {
        return Some(i);
    }

    // Cold: the biggest group, so one activation serves the most work.
    let mut groups: Vec<(&str, usize, u64)> = Vec::new();
    for (_, entry) in &due {
        if let JobClass::Cold(key) = &entry.class {
            match groups.iter_mut().find(|(k, _, _)| *k == key.as_str()) {
                Some(group) => {
                    group.1 = group.1.saturating_add(1);
                    group.2 = group.2.min(entry.seq);
                }
                None => groups.push((key.as_str(), 1, entry.seq)),
            }
        }
    }
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)).then_with(|| a.0.cmp(b.0)));
    let (key, _, _) = groups.first()?;
    oldest(
        &mut due
            .iter()
            .filter(|(_, e)| matches!(&e.class, JobClass::Cold(k) if k == key)),
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    use super::*;

    fn policy(bound: u64) -> FleetPolicy {
        FleetPolicy {
            activation_min_demand: 1,
            activation_max_wait_ms: 0,
            max_reorder_wait_ms: bound,
            ..FleetPolicy::DEFAULT
        }
    }

    fn contender(deployment: &str, waiting: u32, oldest_ms: u64) -> Contender {
        Contender {
            deployment: DeploymentId::new(deployment).expect("id"),
            waiting,
            oldest_ms,
            restore_cost_ms: 60_000,
        }
    }

    #[test]
    fn the_model_with_more_demand_is_loaded_first_whatever_arrived_first() {
        // Arrival order would load `a`, which one request asked for first, and
        // make the four requests for `b` wait a whole load and a swap.
        let policy = policy(120_000);
        let a = contender("a", 1, 0);
        let b = contender("b", 4, 1_000);
        let all = [a.clone(), b.clone()];
        let asking_a = Asking {
            deployment: &a.deployment,
            evicts: false,
            victims_busy: false,
        };
        let asking_b = Asking {
            deployment: &b.deployment,
            ..asking_a
        };
        assert_eq!(gate(&asking_a, &all, 2_000, &policy), Verdict::Defer(Defer::Outranked));
        assert_eq!(gate(&asking_b, &all, 2_000, &policy), Verdict::Proceed(Proceed::Ranked));
    }

    #[test]
    fn demand_past_the_bound_goes_first_whatever_its_score() {
        let policy = policy(120_000);
        let old = contender("old", 1, 0);
        let busy = contender("busy", 200, 119_000);
        let all = [old.clone(), busy];
        let asking = Asking {
            deployment: &old.deployment,
            evicts: false,
            victims_busy: false,
        };
        assert_eq!(gate(&asking, &all, 119_999, &policy), Verdict::Defer(Defer::Outranked));
        assert_eq!(gate(&asking, &all, 120_000, &policy), Verdict::Proceed(Proceed::Starving));
    }

    #[test]
    fn a_swap_waits_while_the_model_it_would_stop_is_working_until_the_bound() {
        let policy = policy(120_000);
        let cold = contender("cold", 9, 0);
        let all = [cold.clone()];
        let asking = Asking {
            deployment: &cold.deployment,
            evicts: true,
            victims_busy: true,
        };
        assert_eq!(gate(&asking, &all, 1_000, &policy), Verdict::Defer(Defer::WarmDemand));
        assert_eq!(gate(&asking, &all, 120_000, &policy), Verdict::Proceed(Proceed::Starving));
        let idle = Asking {
            victims_busy: false,
            ..asking
        };
        assert_eq!(gate(&idle, &all, 1_000, &policy), Verdict::Proceed(Proceed::Uncontended));
    }

    #[test]
    fn a_zero_bound_restores_first_come() {
        let policy = policy(0);
        let a = contender("a", 1, 0);
        let b = contender("b", 50, 0);
        let asking = Asking {
            deployment: &a.deployment,
            evicts: true,
            victims_busy: true,
        };
        assert_eq!(gate(&asking, &[a.clone(), b], 10, &policy), Verdict::Proceed(Proceed::Disabled));
    }

    #[test]
    fn a_contender_that_has_not_earned_an_activation_does_not_block_one_that_has() {
        // `b` has more requests but the batching queue has not triggered for
        // it; deferring `a` to it would wait for an activation nobody will ask
        // for until `b` triggers.
        let policy = FleetPolicy {
            activation_min_demand: 10,
            activation_max_wait_ms: 60_000,
            max_reorder_wait_ms: 120_000,
            ..FleetPolicy::DEFAULT
        };
        let a = contender("a", 1, 0);
        let b = contender("b", 5, 50_000);
        let asking = Asking {
            deployment: &a.deployment,
            evicts: false,
            victims_busy: false,
        };
        assert_eq!(gate(&asking, &[a.clone(), b], 60_000, &policy), Verdict::Proceed(Proceed::Uncontended));
    }

    #[test]
    fn priority_saturates_rather_than_wrapping() {
        let extreme = Contender {
            waiting: u32::MAX,
            oldest_ms: 0,
            restore_cost_ms: 0,
            ..contender("x", 1, 0)
        };
        assert_eq!(extreme.priority(u64::MAX), u64::MAX / 30_000);
        let cheap = Contender {
            restore_cost_ms: u64::MAX,
            ..extreme
        };
        assert_eq!(cheap.priority(u64::MAX), 1);
    }

    fn job(seq: u64, class: JobClass) -> JobEntry {
        JobEntry {
            seq,
            submitted_ms: seq,
            due: true,
            class,
        }
    }

    fn cold(key: &str) -> JobClass {
        JobClass::Cold(key.to_owned())
    }

    #[test]
    fn a_warm_job_is_taken_before_an_older_cold_one() {
        let entries = [job(1, cold("a")), job(2, JobClass::Warm)];
        assert_eq!(pick_job(&entries, 10, 120_000), Some(1));
    }

    #[test]
    fn cold_jobs_are_taken_by_the_largest_group_so_one_load_serves_most() {
        let entries = [
            job(1, cold("a")),
            job(2, cold("b")),
            job(3, cold("b")),
            job(4, cold("a")),
            job(5, cold("b")),
        ];
        assert_eq!(pick_job(&entries, 10, 120_000), Some(1));
    }

    #[test]
    fn a_job_past_the_bound_is_taken_first_and_a_zero_bound_is_queue_order() {
        let mut entries = vec![job(5, JobClass::Warm), job(1, cold("a"))];
        entries[1].submitted_ms = 0;
        assert_eq!(pick_job(&entries, 119_999, 120_000), Some(0));
        assert_eq!(pick_job(&entries, 120_000, 120_000), Some(1));
        assert_eq!(pick_job(&entries, 10, 0), Some(0));
    }

    #[test]
    fn a_job_still_backing_off_is_never_taken() {
        let mut entries = vec![job(1, JobClass::Warm), job(2, cold("a"))];
        entries[0].due = false;
        assert_eq!(pick_job(&entries, 10, 120_000), Some(1));
        entries[1].due = false;
        assert_eq!(pick_job(&entries, 10, 120_000), None);
    }
}
