//! Demand: what the fleet is being asked for, and how badly.
//!
//! The planner needs two numbers per capability — a rate and a queue depth —
//! and one per deployment: how long since it last served anything. Together
//! they decide what is worth keeping resident and what an incoming request is
//! worth displacing.
//!
//! # What is deliberately not here
//!
//! **No prompt content, ever.** The demand signal is a count of requests per
//! capability and nothing else. Specification-extension 21 settles this
//! explicitly, and the reason is not privacy alone: a demand signal derived
//! from request *content* would be a path by which a prompt influenced a plan,
//! which specification-extension 2 forbids outright.
//!
//! **No persistence.** Demand rebuilds from traffic after a restart.
//! Persisting an advisory statistic so it survives an outage is how a
//! scheduler ends up acting confidently on data from before the outage — the
//! moment when it is least likely to still be true.

use hypellm_core::ids::DeploymentId;
use hypellm_core::target::Capability;
use hypellm_core::time::Ewma;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// The demand figures one planning decision reads.
///
/// A plain snapshot: taken once, immutable, and passed to a pure function, so
/// that identical snapshots produce identical plans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemandSnapshot {
    /// Requests per minute per capability, smoothed.
    pub rate_per_minute: BTreeMap<Capability, u64>,
    /// Requests currently waiting for each capability to become available.
    pub queued: BTreeMap<Capability, u32>,
    /// Milliseconds since each deployment last served a request.
    ///
    /// Absent means "never, as far as this router knows", which is treated as
    /// maximally stale.
    pub idle_ms: BTreeMap<DeploymentId, u64>,
}

impl DemandSnapshot {
    /// Smoothed request rate for a capability.
    #[must_use]
    pub fn rate(&self, capability: Capability) -> u64 {
        self.rate_per_minute.get(&capability).copied().unwrap_or(0)
    }

    /// Requests waiting on a capability.
    #[must_use]
    pub fn queue_depth(&self, capability: Capability) -> u32 {
        self.queued.get(&capability).copied().unwrap_or(0)
    }

    /// Milliseconds since a deployment last served, saturating when unknown.
    #[must_use]
    pub fn idle(&self, deployment: &DeploymentId) -> u64 {
        self.idle_ms.get(deployment).copied().unwrap_or(u64::MAX)
    }
}

/// How often a rate sample is folded in, in milliseconds.
///
/// The tracker counts arrivals into a bucket and folds the bucket into the
/// average when the window closes. Counting into a bucket rather than
/// observing one sample per request keeps the request path to a single atomic
/// increment.
pub const DEMAND_WINDOW_MS: u64 = 10_000;

/// Live demand accounting.
///
/// Lives outside the planner because it mutates: the planner is pure and reads
/// a [`DemandSnapshot`]. Nothing here does I/O or holds a clock — callers pass
/// the time in, exactly as they do for `hypellm_core::admission`.
#[derive(Debug, Default)]
pub struct DemandTracker {
    inner: RwLock<TrackerState>,
}

#[derive(Debug, Default)]
struct TrackerState {
    /// Smoothed arrivals per minute, per capability.
    rate: BTreeMap<Capability, Ewma>,
    /// Arrivals in the current window, per capability.
    window: BTreeMap<Capability, u64>,
    /// When the current window opened.
    window_started_ms: u64,
    /// Requests waiting for a capability right now.
    queued: BTreeMap<Capability, u32>,
    /// When each deployment last served a request.
    last_served_ms: BTreeMap<DeploymentId, u64>,
}

impl DemandTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request for a capability.
    pub fn record_request(&self, capability: Capability, now_ms: u64) {
        let Ok(mut state) = self.inner.write() else {
            // A poisoned lock means a writer panicked. Demand is advisory
            // (specification 13: "live metrics are advisory; policy remains
            // the authority"), so dropping a sample is the right failure —
            // refusing the request over a statistic would not be.
            return;
        };
        state.roll_window(now_ms);
        *state.window.entry(capability).or_insert(0) = state
            .window
            .get(&capability)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    /// Record that a deployment served a request.
    pub fn record_served(&self, deployment: &DeploymentId, now_ms: u64) {
        if let Ok(mut state) = self.inner.write() {
            state.last_served_ms.insert(deployment.clone(), now_ms);
        }
    }

    /// Note that a request has begun waiting for a cold capability.
    pub fn enter_queue(&self, capability: Capability) {
        if let Ok(mut state) = self.inner.write() {
            let entry = state.queued.entry(capability).or_insert(0);
            *entry = entry.saturating_add(1);
        }
    }

    /// Note that a waiting request has stopped waiting, for any reason.
    ///
    /// Called on success, failure, timeout, and cancellation, for the same
    /// reason a reservation is released on every path: a gauge that only counts
    /// up is worse than no gauge, because it reads as load that is not there.
    pub fn leave_queue(&self, capability: Capability) {
        if let Ok(mut state) = self.inner.write() {
            let entry = state.queued.entry(capability).or_insert(0);
            *entry = entry.saturating_sub(1);
        }
    }

    /// Take an immutable snapshot for one planning decision.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> DemandSnapshot {
        let Ok(state) = self.inner.read() else {
            return DemandSnapshot::default();
        };

        // The open window is included at its pro-rata rate rather than
        // ignored, so that the first burst of demand for a cold capability is
        // visible immediately instead of ten seconds later — which is exactly
        // the moment the planner is being asked whether to start it.
        let elapsed = now_ms.saturating_sub(state.window_started_ms).max(1);
        let mut rate_per_minute = BTreeMap::new();
        for (capability, ewma) in &state.rate {
            rate_per_minute.insert(*capability, ewma.value_or(0));
        }
        for (capability, count) in &state.window {
            let partial = count.saturating_mul(60_000).div_euclid(elapsed);
            let entry = rate_per_minute.entry(*capability).or_insert(0);
            *entry = (*entry).max(partial);
        }

        DemandSnapshot {
            rate_per_minute,
            queued: state
                .queued
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(c, n)| (*c, *n))
                .collect(),
            idle_ms: state
                .last_served_ms
                .iter()
                .map(|(d, t)| (d.clone(), now_ms.saturating_sub(*t)))
                .collect(),
        }
    }
}

impl TrackerState {
    /// Close the current window if it has elapsed, folding it into the average.
    fn roll_window(&mut self, now_ms: u64) {
        if self.window_started_ms == 0 {
            self.window_started_ms = now_ms;
            return;
        }
        if now_ms.saturating_sub(self.window_started_ms) < DEMAND_WINDOW_MS {
            return;
        }
        // Every capability that has ever been seen gets a sample, including a
        // zero for the ones that saw nothing this window. Without the zeroes an
        // idle capability's rate would stay at whatever it last was, and a
        // model nobody has asked for in an hour would look as valuable as one
        // being asked for now.
        let seen: Vec<Capability> = self
            .rate
            .keys()
            .copied()
            .chain(self.window.keys().copied())
            .collect();
        for capability in seen {
            let count = self.window.get(&capability).copied().unwrap_or(0);
            let per_minute = count.saturating_mul(60_000).div_euclid(DEMAND_WINDOW_MS);
            self.rate
                .entry(capability)
                .or_insert_with(Ewma::smooth)
                .observe(per_minute);
        }
        self.window.clear();
        self.window_started_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(s: &str) -> DeploymentId {
        DeploymentId::new(s).expect("deployment id")
    }

    #[test]
    fn a_burst_of_demand_for_a_cold_capability_is_visible_before_the_window_closes() {
        // The moment the planner is asked "is this worth a swap" is the moment
        // the first requests arrive. A rate that only updated every ten seconds
        // would report zero demand for the burst that triggered the question.
        let tracker = DemandTracker::new();
        for _ in 0..5 {
            tracker.record_request(Capability::TextToMusic, 1_000);
        }
        let snapshot = tracker.snapshot(2_000);
        assert!(
            snapshot.rate(Capability::TextToMusic) > 0,
            "the open window must contribute"
        );
    }

    #[test]
    fn a_capability_nobody_asks_for_decays_toward_zero() {
        let tracker = DemandTracker::new();
        for _ in 0..100 {
            tracker.record_request(Capability::Chat, 0);
        }
        // Roll many windows with no traffic at all.
        let mut now = 0;
        for _ in 0..200 {
            now += DEMAND_WINDOW_MS;
            tracker.record_request(Capability::TextToMusic, now);
        }
        let snapshot = tracker.snapshot(now);
        assert_eq!(
            snapshot.rate(Capability::Chat),
            0,
            "an idle capability must not keep the value it had when it was busy"
        );
    }

    #[test]
    fn leaving_a_queue_never_underflows_below_zero() {
        // The counter is decremented on success, failure, timeout, and
        // cancellation, and a double decrement is a bug that must not turn
        // into a very large queue depth.
        let tracker = DemandTracker::new();
        tracker.enter_queue(Capability::Chat);
        tracker.leave_queue(Capability::Chat);
        tracker.leave_queue(Capability::Chat);
        assert_eq!(tracker.snapshot(0).queue_depth(Capability::Chat), 0);
    }

    #[test]
    fn a_deployment_never_seen_serving_is_maximally_idle() {
        let tracker = DemandTracker::new();
        let snapshot = tracker.snapshot(10_000);
        assert_eq!(snapshot.idle(&deployment("spark-music3")), u64::MAX);

        tracker.record_served(&deployment("spark-music3"), 4_000);
        let snapshot = tracker.snapshot(10_000);
        assert_eq!(snapshot.idle(&deployment("spark-music3")), 6_000);
    }
}
