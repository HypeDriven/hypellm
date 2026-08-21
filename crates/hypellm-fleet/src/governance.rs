//! Anti-thrash governance.
//!
//! The requirement is that the fleet must not swap models continuously. Eight
//! mechanisms, layered, each sufficient against a different failure mode. Three
//! of them are decided inside the planner because they are eligibility
//! questions — dwell, hysteresis, and the eviction-set cap. The rest live here,
//! because they carry state across decisions.
//!
//! | Mechanism | Where | What it stops |
//! |---|---|---|
//! | Dwell floor | [`crate::plan`] | A-evicts-B-evicts-A ping-pong |
//! | Hysteresis margin | [`crate::plan`] | Oscillation between near-equal capabilities |
//! | Demand batching | [`ActivationQueue`] | Ten requests costing ten swaps |
//! | Cooldown and flap backoff | [`FlapCounter`] | A deployment that keeps failing to stay up |
//! | Activation budget | [`Budgets`] | Everything else |
//! | Prefer no swap | [`crate::plan`] | Choosing an eviction host over a free one |
//! | Operator anchors | [`crate::model::Deployment`] | The planner outsmarting its operator |
//! | Predictive pre-warm | Not implemented | — |
//!
//! # Why the budget is the one that matters
//!
//! Dwell, hysteresis, and batching are economic arguments, and adversarial
//! demand can talk an economic argument into a swap. The activation budget is
//! arithmetic. Whatever defeats the arguments above, the bucket is what bounds
//! the worst case, and the failure mode when it engages is a clean, explained
//! rejection rather than a fleet that spends its afternoon loading models.
//!
//! With the defaults — a five-minute dwell floor and twelve activations an hour
//! — a host swaps at most twelve times an hour whatever demand does.

use crate::model::FleetPolicy;
use hypellm_core::ids::{DeploymentId, HostId};
use hypellm_core::target::Capability;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// One hour, the period the activation budget refills over.
pub const BUDGET_PERIOD_MS: u64 = 3_600_000;

/// Per-host activation budgets.
///
/// A **sliding window** rather than a token bucket. The distinction is not
/// academic: a bucket of twelve tokens refilling at twelve an hour permits
/// twenty-four activations in the first hour, because it starts full. The
/// safety claim this feature rests on is "twelve swaps per host per hour
/// regardless of the attacker's rate", and only a window that counts actual
/// activations in the trailing hour delivers that.
///
/// The cost is a bounded ring of at most `max_activations_per_hour`
/// timestamps per host — which is why the ceiling is also, deliberately, a
/// small number.
#[derive(Debug, Default)]
pub struct Budgets {
    inner: RwLock<BTreeMap<HostId, Vec<u64>>>,
}

/// Ceiling on how many timestamps one host's window may retain.
///
/// A misconfigured `max_activations_per_hour` must not become an unbounded
/// allocation. Anything above this is clamped, and an operator who genuinely
/// wants a host swapping more than this often has a fleet problem rather than
/// a configuration problem.
pub const MAX_WINDOW_ENTRIES: usize = 256;

impl Budgets {
    /// Create empty budgets. Every host starts with its full allowance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an activation at `at_ms` still counts against the window.
    ///
    /// Written as an addition rather than as `now - period` because the
    /// subtraction saturates at zero, which would make an activation recorded
    /// at time zero fall out of its own window immediately. Monotonic clocks
    /// do start at zero in tests, and a bound that is wrong only near the
    /// origin is a bound that is wrong exactly where it is being verified.
    const fn is_live(at_ms: u64, now_ms: u64) -> bool {
        at_ms.saturating_add(BUDGET_PERIOD_MS) > now_ms
    }

    /// Drop timestamps that have left the trailing hour.
    fn prune(window: &mut Vec<u64>, now_ms: u64) {
        window.retain(|t| Self::is_live(*t, now_ms));
    }

    fn capacity(policy: &FleetPolicy) -> usize {
        usize::try_from(policy.max_activations_per_hour)
            .unwrap_or(MAX_WINDOW_ENTRIES)
            .min(MAX_WINDOW_ENTRIES)
    }

    /// Activations remaining for a host in the trailing hour.
    #[must_use]
    pub fn remaining(&self, host: &HostId, policy: &FleetPolicy, now_ms: u64) -> u32 {
        let capacity = Self::capacity(policy);
        let Ok(map) = self.inner.read() else {
            return 0;
        };
        let used = map.get(host).map_or(0, |window| {
            window.iter().filter(|t| Self::is_live(**t, now_ms)).count()
        });
        u32::try_from(capacity.saturating_sub(used)).unwrap_or(0)
    }

    /// Spend one activation, returning whether there was one to spend.
    ///
    /// Fails closed on a poisoned lock: a budget that cannot be read is a
    /// budget that cannot authorise fleet work.
    pub fn try_spend(&self, host: &HostId, policy: &FleetPolicy, now_ms: u64) -> bool {
        let capacity = Self::capacity(policy);
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        let window = map.entry(host.clone()).or_default();
        Self::prune(window, now_ms);
        if window.len() >= capacity {
            return false;
        }
        window.push(now_ms);
        true
    }

    /// Return an activation that never happened.
    ///
    /// Called when a plan is abandoned before its mutating verb is sent. A
    /// budget spent on work that did not occur would make the ceiling tighter
    /// than the operator configured, which is the wrong direction for a limit
    /// whose whole purpose is to be predictable.
    pub fn refund(&self, host: &HostId, _policy: &FleetPolicy, now_ms: u64) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(window) = map.get_mut(host) {
                Self::prune(window, now_ms);
                window.pop();
            }
        }
    }

    /// Every host's remaining budget, for the management view.
    #[must_use]
    pub fn snapshot(&self, policy: &FleetPolicy, now_ms: u64) -> BTreeMap<HostId, u32> {
        let capacity = Self::capacity(policy);
        let Ok(map) = self.inner.read() else {
            return BTreeMap::new();
        };
        map.iter()
            .map(|(host, window)| {
                let used = window.iter().filter(|t| Self::is_live(**t, now_ms)).count();
                (
                    host.clone(),
                    u32::try_from(capacity.saturating_sub(used)).unwrap_or(0),
                )
            })
            .collect()
    }
}

/// Cooldown and exponential flap backoff, per deployment.
///
/// After eviction a deployment may not be re-activated for
/// `reactivation_cooldown_ms`. Repeated activate/evict cycles inside
/// `flap_window_ms` double the cooldown, up to `max_flap_cooldown_ms`, decaying
/// after a quiet period.
///
/// This is the reflex specification 13's circuit breaker already applies to an
/// unhealthy target. A flapping deployment is unhealthy in the same operational
/// sense and deserves the same treatment.
#[derive(Debug, Default)]
pub struct FlapCounter {
    inner: RwLock<BTreeMap<DeploymentId, FlapState>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct FlapState {
    /// Consecutive cycles inside the window.
    cycles: u32,
    /// When the most recent cycle completed.
    last_cycle_ms: u64,
    /// When re-activation becomes permitted.
    until_ms: u64,
}

impl FlapCounter {
    /// Create an empty counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a deployment was evicted, and compute its cooldown.
    ///
    /// Returns the instant at which re-activation becomes permitted.
    pub fn record_eviction(
        &self,
        deployment: &DeploymentId,
        policy: &FleetPolicy,
        now_ms: u64,
    ) -> u64 {
        let Ok(mut map) = self.inner.write() else {
            return now_ms.saturating_add(policy.reactivation_cooldown_ms);
        };
        let mut state = map.get(deployment).copied().unwrap_or_default();

        // A quiet period resets the count. Without this, a deployment that
        // flapped once at breakfast would still be serving an hour-long
        // cooldown at dinner.
        if now_ms.saturating_sub(state.last_cycle_ms) > policy.flap_window_ms {
            state.cycles = 0;
        }
        state.cycles = state.cycles.saturating_add(1);
        state.last_cycle_ms = now_ms;

        // Doubling, capped. `cycles - 1` shifts so the first eviction gets the
        // plain cooldown rather than twice it.
        let shift = state.cycles.saturating_sub(1).min(16);
        let cooldown = policy
            .reactivation_cooldown_ms
            .saturating_mul(1u64 << shift)
            .min(policy.max_flap_cooldown_ms.max(policy.reactivation_cooldown_ms));
        state.until_ms = now_ms.saturating_add(cooldown);
        map.insert(deployment.clone(), state);
        state.until_ms
    }

    /// When a deployment may next be activated.
    #[must_use]
    pub fn cooldown_until_ms(&self, deployment: &DeploymentId) -> u64 {
        self.inner
            .read()
            .ok()
            .and_then(|m| m.get(deployment).map(|s| s.until_ms))
            .unwrap_or(0)
    }

    /// Every deployment's cooldown, for the planner's snapshot.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<DeploymentId, u64> {
        let Ok(map) = self.inner.read() else {
            return BTreeMap::new();
        };
        map.iter().map(|(d, s)| (d.clone(), s.until_ms)).collect()
    }

    /// Clear a deployment's accrued backoff.
    ///
    /// An operator action, audited by the caller. It exists because a
    /// deployment that flapped for a reason since fixed should not have to sit
    /// out an hour to prove it.
    pub fn clear(&self, deployment: &DeploymentId) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(deployment);
        }
    }

    /// Restore counters replayed from the durable log.
    ///
    /// Flap counters survive restart deliberately: a router bounce that reset
    /// accrued backoff would permit a fresh burst of exactly the thrash the
    /// backoff exists to stop.
    pub fn restore(&self, deployment: &DeploymentId, cycles: u32, last_cycle_ms: u64, until_ms: u64) {
        if let Ok(mut map) = self.inner.write() {
            map.insert(
                deployment.clone(),
                FlapState {
                    cycles,
                    last_cycle_ms,
                    until_ms,
                },
            );
        }
    }

    /// The durable form of every counter: cycles, last cycle, and expiry.
    #[must_use]
    pub fn durable_state(&self) -> Vec<(DeploymentId, u32, u64, u64)> {
        let Ok(map) = self.inner.read() else {
            return Vec::new();
        };
        map.iter()
            .map(|(d, s)| (d.clone(), s.cycles, s.last_cycle_ms, s.until_ms))
            .collect()
    }
}

/// What a request waiting for a cold capability should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueAdmission {
    /// Trigger an activation now; this request is the one that pays for it.
    Activate,
    /// Wait: an activation is already coming, or demand has not accumulated.
    Wait {
        /// Milliseconds until the queue would trigger on its own.
        retry_in_ms: u64,
    },
    /// The queue for this capability is full.
    Full,
}

/// Bounded per-capability demand batching.
///
/// Requests for a cold capability accumulate here rather than each triggering
/// its own evaluation. A swap starts when accumulated demand reaches
/// `activation_min_demand`, or when the oldest queued request has waited
/// `activation_max_wait_ms` — whichever comes first.
///
/// This converts thrash into throughput: ten music requests over two minutes
/// should cost one swap, not ten.
#[derive(Debug, Default)]
pub struct ActivationQueue {
    inner: RwLock<BTreeMap<Capability, QueueState>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct QueueState {
    /// Requests waiting.
    waiting: u32,
    /// When the oldest of them arrived.
    oldest_ms: u64,
    /// Whether an activation has already been triggered for this capability.
    triggered: bool,
}

/// Most requests one capability's queue may hold.
///
/// Bounded like everything else a request can create. Past this the caller is
/// refused rather than enqueued, because an unbounded queue in front of a
/// three-minute model load is a way to accumulate an unbounded number of
/// requests that will all miss their deadlines together.
pub const MAX_QUEUED_PER_CAPABILITY: u32 = 256;

impl ActivationQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask what a request waiting for `capability` should do.
    pub fn admit(
        &self,
        capability: Capability,
        policy: &FleetPolicy,
        now_ms: u64,
    ) -> QueueAdmission {
        let Ok(mut map) = self.inner.write() else {
            // Fail toward activating rather than waiting: the budget and the
            // dwell floor still bound what can happen, and a lock failure that
            // silently stalled every cold request would be an outage with no
            // explanation.
            return QueueAdmission::Activate;
        };
        let state = map.entry(capability).or_insert(QueueState {
            waiting: 0,
            oldest_ms: now_ms,
            triggered: false,
        });
        if state.waiting >= MAX_QUEUED_PER_CAPABILITY {
            return QueueAdmission::Full;
        }
        if state.waiting == 0 {
            state.oldest_ms = now_ms;
        }
        state.waiting = state.waiting.saturating_add(1);

        if state.triggered {
            // Somebody already paid for the swap; this request rides on it.
            return QueueAdmission::Wait { retry_in_ms: 0 };
        }

        let waited = now_ms.saturating_sub(state.oldest_ms);
        let enough_demand = state.waiting >= policy.activation_min_demand.max(1);
        let waited_long_enough = waited >= policy.activation_max_wait_ms;
        if enough_demand || waited_long_enough {
            state.triggered = true;
            return QueueAdmission::Activate;
        }
        QueueAdmission::Wait {
            retry_in_ms: policy.activation_max_wait_ms.saturating_sub(waited),
        }
    }

    /// Note that a waiting request has left the queue, for any reason.
    pub fn leave(&self, capability: Capability) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(state) = map.get_mut(&capability) {
                state.waiting = state.waiting.saturating_sub(1);
                if state.waiting == 0 {
                    state.triggered = false;
                }
            }
        }
    }

    /// Note that the activation this queue triggered has finished.
    ///
    /// Clears the trigger so the *next* period of cold demand can pay for its
    /// own swap. Called on success and on failure alike: leaving the flag set
    /// after a failed activation would make every subsequent request wait for
    /// something that is never coming.
    pub fn settle(&self, capability: Capability) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(state) = map.get_mut(&capability) {
                state.triggered = false;
            }
        }
    }

    /// How many requests are waiting per capability.
    #[must_use]
    pub fn depths(&self) -> BTreeMap<Capability, u32> {
        let Ok(map) = self.inner.read() else {
            return BTreeMap::new();
        };
        map.iter()
            .filter(|(_, s)| s.waiting > 0)
            .map(|(c, s)| (*c, s.waiting))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostId {
        HostId::new("spark").expect("host id")
    }

    fn deployment() -> DeploymentId {
        DeploymentId::new("spark-music3").expect("deployment id")
    }

    #[test]
    fn the_activation_budget_is_a_hard_ceiling_whatever_demand_does() {
        // The property the whole feature's safety rests on. An attacker
        // alternating two capabilities cannot exceed the configured rate,
        // however fast they send.
        let budgets = Budgets::new();
        let policy = FleetPolicy::DEFAULT;
        // Six simulated hours, asking every second. The assertion is made on
        // every trailing hour, not just the total, because an average that
        // hides a burst is exactly what a bucket would have produced.
        let mut spent_at: Vec<u64> = Vec::new();
        for second in 0..(6 * 3_600u64) {
            let now = second.saturating_mul(1_000);
            if budgets.try_spend(&host(), &policy, now) {
                spent_at.push(now);
            }
        }
        for window_end in (0..(6 * 3_600_000u64)).step_by(60_000) {
            let in_window = spent_at
                .iter()
                .filter(|t| **t <= window_end && t.saturating_add(BUDGET_PERIOD_MS) > window_end)
                .count();
            assert!(
                u32::try_from(in_window).unwrap_or(u32::MAX) <= policy.max_activations_per_hour,
                "{in_window} activations in the hour ending at {window_end}, against a \
                 ceiling of {}",
                policy.max_activations_per_hour
            );
        }
        assert!(!spent_at.is_empty(), "the budget must permit some work");
    }

    #[test]
    fn an_allowance_returns_only_when_the_activation_that_used_it_leaves_the_window() {
        // The window is what makes "twelve per hour" true rather than
        // "twelve, then twelve more". Nothing comes back until the oldest
        // activation is genuinely an hour old.
        let budgets = Budgets::new();
        let policy = FleetPolicy::DEFAULT;
        for _ in 0..policy.max_activations_per_hour {
            assert!(budgets.try_spend(&host(), &policy, 1));
        }
        assert!(!budgets.try_spend(&host(), &policy, 1));
        assert!(!budgets.try_spend(&host(), &policy, BUDGET_PERIOD_MS));
        assert!(
            budgets.try_spend(&host(), &policy, BUDGET_PERIOD_MS + 2),
            "an hour and a moment after the first, one allowance is back"
        );
    }

    #[test]
    fn a_refund_returns_a_budget_spent_on_work_that_never_happened() {
        let budgets = Budgets::new();
        let policy = FleetPolicy::DEFAULT;
        let before = budgets.remaining(&host(), &policy, 0);
        assert!(budgets.try_spend(&host(), &policy, 0));
        assert_eq!(budgets.remaining(&host(), &policy, 0), before - 1);
        budgets.refund(&host(), &policy, 0);
        assert_eq!(budgets.remaining(&host(), &policy, 0), before);
    }

    #[test]
    fn repeated_flapping_accrues_backoff_and_a_quiet_period_clears_it() {
        let counter = FlapCounter::new();
        let policy = FleetPolicy::DEFAULT;
        let first = counter.record_eviction(&deployment(), &policy, 0);
        assert_eq!(first, policy.reactivation_cooldown_ms);

        let second = counter.record_eviction(&deployment(), &policy, 1_000);
        assert_eq!(
            second,
            1_000 + policy.reactivation_cooldown_ms * 2,
            "a second cycle inside the window doubles the cooldown"
        );

        // Nothing for well over the flap window: the count resets.
        let quiet = policy.flap_window_ms * 3;
        let third = counter.record_eviction(&deployment(), &policy, quiet);
        assert_eq!(third, quiet + policy.reactivation_cooldown_ms);
    }

    #[test]
    fn backoff_never_exceeds_its_configured_ceiling() {
        let counter = FlapCounter::new();
        let policy = FleetPolicy::DEFAULT;
        let mut last = 0;
        for cycle in 0..40u64 {
            last = counter.record_eviction(&deployment(), &policy, cycle);
        }
        assert!(
            last.saturating_sub(39) <= policy.max_flap_cooldown_ms,
            "cooldown {last} exceeded the ceiling"
        );
    }

    #[test]
    fn ten_requests_for_one_cold_capability_trigger_one_activation() {
        // The point of batching, stated as a test: a burst costs one swap.
        let queue = ActivationQueue::new();
        let policy = FleetPolicy::DEFAULT;
        let mut activations = 0;
        for _ in 0..10 {
            if queue.admit(Capability::TextToMusic, &policy, 1_000) == QueueAdmission::Activate {
                activations += 1;
            }
        }
        assert_eq!(activations, 1);
        assert_eq!(queue.depths().get(&Capability::TextToMusic), Some(&10));
    }

    #[test]
    fn a_failed_activation_does_not_leave_every_later_request_waiting_forever() {
        let queue = ActivationQueue::new();
        let policy = FleetPolicy::DEFAULT;
        assert_eq!(
            queue.admit(Capability::TextToMusic, &policy, 0),
            QueueAdmission::Activate
        );
        queue.settle(Capability::TextToMusic);
        assert_eq!(
            queue.admit(Capability::TextToMusic, &policy, 1_000),
            QueueAdmission::Activate,
            "after a settled activation the next demand may pay for its own"
        );
    }

    #[test]
    fn the_queue_is_bounded_and_refuses_rather_than_growing() {
        let queue = ActivationQueue::new();
        let policy = FleetPolicy::DEFAULT;
        for _ in 0..MAX_QUEUED_PER_CAPABILITY {
            let _ = queue.admit(Capability::TextToMusic, &policy, 0);
        }
        assert_eq!(
            queue.admit(Capability::TextToMusic, &policy, 0),
            QueueAdmission::Full
        );
    }
}
