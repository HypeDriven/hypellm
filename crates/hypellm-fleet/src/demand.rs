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
    /// When the current window opened, or `None` before the first sample.
    window_started_ms: Option<u64>,
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
    ///
    /// Rolls every window that has closed by `now_ms` first, so a capability
    /// that has gone quiet decays whether or not anything else is being asked
    /// for. The rates used to move only when a request arrived, so a fleet
    /// that fell idle kept its last busy figures indefinitely and the planner
    /// protected models nobody had called for an hour.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> DemandSnapshot {
        let Ok(mut state) = self.inner.write() else {
            return DemandSnapshot::default();
        };
        state.roll_window(now_ms);

        // The open window is included rather than ignored, so that the first
        // burst of demand for a cold capability is visible immediately instead
        // of ten seconds later — which is exactly the moment the planner is
        // being asked whether to start it.
        //
        // It is scaled over the *whole* window, never over the part that has
        // elapsed. Pro-rating over elapsed time made one request a millisecond
        // after a roll read as 60 000 a minute, which is enough demand for a
        // single call to evict a warm resident. Over the full window the open
        // bucket can only ever report what the same count would report once
        // the window closed: an early burst reads low, never high.
        let mut rate_per_minute = BTreeMap::new();
        for (capability, ewma) in &state.rate {
            rate_per_minute.insert(*capability, ewma.value_or(0));
        }
        for (capability, count) in &state.window {
            let partial = count.saturating_mul(60_000).div_euclid(DEMAND_WINDOW_MS);
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

/// The most closed windows folded in one roll.
///
/// A tracker idle for a day would otherwise fold thousands of zero samples in
/// one call. At a 10% weight, 256 zero samples shrink a rate by a factor of
/// roughly 10^11, which takes any rate a request path can produce to zero in
/// integer arithmetic; folding more changes nothing but the time taken.
const MAX_WINDOWS_PER_ROLL: u64 = 256;

impl TrackerState {
    /// Close every window that has elapsed, folding each into the average.
    ///
    /// The window holding the open bucket's counts is folded first; every
    /// further elapsed window saw no traffic and folds as a zero. Pure: the
    /// time is passed in.
    fn roll_window(&mut self, now_ms: u64) {
        let Some(started) = self.window_started_ms else {
            self.window_started_ms = Some(now_ms);
            return;
        };
        let elapsed = now_ms.saturating_sub(started);
        if elapsed < DEMAND_WINDOW_MS {
            return;
        }
        let closed = elapsed.div_euclid(DEMAND_WINDOW_MS);
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
            let ewma = self.rate.entry(capability).or_insert_with(Ewma::smooth);
            ewma.observe(per_minute);
            for _ in 1..closed.min(MAX_WINDOWS_PER_ROLL) {
                ewma.observe(0);
            }
        }
        self.window.clear();
        // Aligned to the window grid rather than reset to `now_ms`, so the
        // open window's age — and therefore when it next closes — does not
        // depend on when somebody happened to look.
        self.window_started_ms =
            Some(started.saturating_add(closed.saturating_mul(DEMAND_WINDOW_MS)));
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
    fn one_request_just_after_a_window_opens_is_not_read_as_a_flood() {
        // Pro-rating the open window over the milliseconds elapsed made a
        // single request one millisecond in read as 60 000 a minute — more
        // than enough for one call to evict a warm resident.
        let tracker = DemandTracker::new();
        tracker.record_request(Capability::TextToMusic, 1_000);
        let snapshot = tracker.snapshot(1_001);
        let rate = snapshot.rate(Capability::TextToMusic);
        assert!(rate > 0, "the open window must still contribute");
        assert!(
            rate <= 60_000u64.div_euclid(DEMAND_WINDOW_MS),
            "one request read as {rate} a minute"
        );
    }

    #[test]
    fn demand_decays_while_nothing_at_all_is_asked_for() {
        // The average used to move only on `record_request`. A fleet that went
        // completely quiet kept its busy figures forever, so the planner kept
        // protecting models nobody was calling.
        let tracker = DemandTracker::new();
        let mut now = 0;
        for _ in 0..30 {
            for _ in 0..50 {
                tracker.record_request(Capability::Chat, now);
            }
            now += DEMAND_WINDOW_MS;
        }
        let busy = tracker.snapshot(now).rate(Capability::Chat);
        assert!(busy > 0, "the fixture must build up some demand");

        // An hour with no requests of any kind; only snapshots are taken.
        let idle = tracker.snapshot(now + 3_600_000).rate(Capability::Chat);
        assert_eq!(idle, 0, "an hour of silence left the rate at {idle} (was {busy})");
    }

    #[test]
    fn a_snapshot_does_not_change_what_a_later_snapshot_reports() {
        // Rolling at snapshot time must be the same arithmetic as rolling at
        // request time: taking a snapshot mid-way is an observation, not an
        // event.
        let observed = DemandTracker::new();
        let unobserved = DemandTracker::new();
        for step in 0..40u64 {
            let now = step * 3_000;
            observed.record_request(Capability::Chat, now);
            unobserved.record_request(Capability::Chat, now);
            let _ = observed.snapshot(now + 1_500);
        }
        assert_eq!(observed.snapshot(200_000), unobserved.snapshot(200_000));
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
