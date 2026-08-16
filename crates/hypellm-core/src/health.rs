//! Health tracking, circuit breaking, and the live state routing consults.
//!
//! Specification 13:
//!
//! - Passive health records connect/handshake errors, first-byte latency,
//!   stream completion, protocol errors, and normalized status classes.
//! - Circuit states are closed, open, and half-open, with minimum sample
//!   counts, rolling windows, cooldown with bounded exponential increase, and
//!   limited half-open probes.
//! - Health is per endpoint **and operation/model class**: "a failed embedding
//!   path does not necessarily disable chat".
//! - "Live metrics are advisory; policy remains the authority."
//!
//! The last point is why this module implements [`LiveState`] by producing
//! *penalties* and one boolean filter, rather than making selection decisions
//! itself.

use crate::canonical::Operation;
use crate::event::UpstreamErrorClass;
use crate::ids::TargetId;
use crate::policy::LiveState;
use crate::target::AdminState;
use crate::time::{Clock, Ewma, Histogram};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Circuit breaker configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Minimum samples in the window before the breaker may open.
    ///
    /// Without this, one failure on a freshly configured target opens its
    /// circuit at a 100% error rate over a sample size of one.
    pub min_samples: u32,
    /// Failure percentage, 0-100, at which the breaker opens.
    pub failure_threshold_percent: u32,
    /// Length of the rolling window in milliseconds.
    pub window_millis: u64,
    /// First cooldown before a half-open probe is allowed.
    pub base_cooldown_millis: u64,
    /// Ceiling on the exponentially increasing cooldown.
    pub max_cooldown_millis: u64,
    /// Concurrent probes permitted while half-open.
    pub half_open_probes: u32,
    /// Consecutive probe successes required to close the breaker.
    pub half_open_successes_to_close: u32,
}

impl BreakerConfig {
    /// Defaults suitable for a remote provider.
    pub const DEFAULT: Self = Self {
        min_samples: 20,
        failure_threshold_percent: 50,
        window_millis: 30_000,
        base_cooldown_millis: 1_000,
        max_cooldown_millis: 60_000,
        half_open_probes: 1,
        half_open_successes_to_close: 3,
    };
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests flow normally.
    Closed,
    /// Requests are refused until the cooldown expires.
    Open,
    /// A limited number of probes are permitted.
    HalfOpen,
}

impl BreakerState {
    /// Stable name for metrics and traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// How long a target's preference is ramped back after its breaker closes.
///
/// Specification 22.1 step 13's "gradual weight restoration". A target that has
/// just recovered is *probably* healthy — two probes succeeded — and the ramp
/// exists because "probably" is not "certainly", and the cost of being wrong is
/// the full load arriving at something still recovering, which reopens the
/// breaker and makes the outage longer.
///
/// Thirty seconds is long enough that a target with a cold cache or a
/// reconnecting pool serves a growing share rather than all of it at once, and
/// short enough that a genuinely recovered target is not held back through an
/// incident.
pub const WEIGHT_RESTORATION_MILLIS: u64 = 30_000;

/// A rolling window of successes and failures.
///
/// Two buckets that alternate: samples land in the current bucket, and when the
/// window elapses the buckets rotate. This keeps the memory constant and the
/// window bounded (specification 13: "EWMA and fixed-bucket histograms avoid
/// unbounded samples") without storing per-sample timestamps.
#[derive(Debug)]
struct RollingCounts {
    window_millis: u64,
    current_start_ms: u64,
    current_success: u32,
    current_failure: u32,
    previous_success: u32,
    previous_failure: u32,
}

impl RollingCounts {
    const fn new(window_millis: u64, now_ms: u64) -> Self {
        Self {
            window_millis,
            current_start_ms: now_ms,
            current_success: 0,
            current_failure: 0,
            previous_success: 0,
            previous_failure: 0,
        }
    }

    fn rotate_if_needed(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.current_start_ms);
        if elapsed < self.window_millis {
            return;
        }
        if elapsed >= self.window_millis.saturating_mul(2) {
            // More than two windows of silence: everything is stale.
            self.previous_success = 0;
            self.previous_failure = 0;
        } else {
            self.previous_success = self.current_success;
            self.previous_failure = self.current_failure;
        }
        self.current_success = 0;
        self.current_failure = 0;
        self.current_start_ms = now_ms;
    }

    fn record(&mut self, success: bool, now_ms: u64) {
        self.rotate_if_needed(now_ms);
        if success {
            self.current_success = self.current_success.saturating_add(1);
        } else {
            self.current_failure = self.current_failure.saturating_add(1);
        }
    }

    fn totals(&mut self, now_ms: u64) -> (u32, u32) {
        self.rotate_if_needed(now_ms);
        (
            self.current_success.saturating_add(self.previous_success),
            self.current_failure.saturating_add(self.previous_failure),
        )
    }
}

/// One circuit breaker, for a (target, operation class) pair.
#[derive(Debug)]
pub struct Breaker {
    config: BreakerConfig,
    inner: Mutex<BreakerInner>,
}

#[derive(Debug)]
struct BreakerInner {
    state: BreakerState,
    counts: RollingCounts,
    /// When the current open period ends.
    open_until_ms: u64,
    /// Consecutive open periods, used for the exponential cooldown.
    consecutive_opens: u32,
    /// Probes currently in flight while half-open.
    probes_in_flight: u32,
    /// Consecutive probe successes while half-open.
    probe_successes: u32,
    /// When the breaker last closed after having been open.
    ///
    /// Specification 22.1 step 13 asks for "half-open probes, gradual weight
    /// restoration, and compare errors/latency". The probes existed; the ramp
    /// did not, so a target went from refusing everything to competing at full
    /// preference the instant its second probe succeeded — and if it was
    /// recovering rather than recovered, the load that arrived proved it by
    /// reopening the breaker.
    ///
    /// `None` once the ramp has finished, or for a breaker that has never
    /// opened.
    closed_at_ms: Option<u64>,
}

impl Breaker {
    /// Create a closed breaker.
    #[must_use]
    pub fn new(config: BreakerConfig, now_ms: u64) -> Self {
        Self {
            config,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                counts: RollingCounts::new(config.window_millis, now_ms),
                open_until_ms: 0,
                consecutive_opens: 0,
                probes_in_flight: 0,
                probe_successes: 0,
                closed_at_ms: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerInner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Current state, after applying any elapsed cooldown.
    pub fn state(&self, now_ms: u64) -> BreakerState {
        let mut inner = self.lock();
        self.transition_if_cooled(&mut inner, now_ms);
        inner.state
    }

    /// How much of a target's preference has been restored since its breaker
    /// closed, as a fraction in thousandths.
    ///
    /// 1000 means fully restored, which is the answer for a breaker that has
    /// never opened — a target with no failure history is not penalised for
    /// having no history.
    ///
    /// Rises linearly over [`WEIGHT_RESTORATION_MILLIS`]. Deliberately never
    /// returns 0: the ramp is a **score** term and specification 6.3 is
    /// explicit that health never becomes an eligibility filter. A target whose
    /// breaker has closed is *permitted*; it is merely less preferred than one
    /// that has been healthy all along, and if it is the only candidate it must
    /// still be chosen.
    #[must_use]
    pub fn restoration_permille(&self, now_ms: u64) -> u64 {
        let inner = self.lock();
        let Some(closed_at) = inner.closed_at_ms else {
            return 1000;
        };
        let elapsed = now_ms.saturating_sub(closed_at);
        if elapsed >= WEIGHT_RESTORATION_MILLIS {
            return 1000;
        }
        // Floor of 100, so a just-recovered target keeps a tenth of its
        // preference rather than being effectively excluded by arithmetic.
        //
        // Integer division is deliberate and the truncation is harmless: this
        // is a preference weight in thousandths, and rounding a ramp down by
        // one part in a thousand delays full restoration by 30 ms. Floating
        // point here would trade an exactly-reproducible score — which
        // Appendix B's determinism requirement rests on — for precision that
        // means nothing.
        #[allow(
            clippy::integer_division,
            reason = "a preference ramp in thousandths; truncation costs 30ms of \
                      restoration and keeps the score exactly reproducible"
        )]
        let progress = elapsed.saturating_mul(900) / WEIGHT_RESTORATION_MILLIS.max(1);
        100_u64.saturating_add(progress)
    }

    fn transition_if_cooled(&self, inner: &mut BreakerInner, now_ms: u64) {
        if inner.state == BreakerState::Open && now_ms >= inner.open_until_ms {
            inner.state = BreakerState::HalfOpen;
            inner.probes_in_flight = 0;
            inner.probe_successes = 0;
        }
    }

    /// Whether a request may be sent right now.
    ///
    /// While half-open this consumes a probe slot; the caller must report the
    /// result with [`Breaker::record`], which returns the slot.
    pub fn try_admit(&self, now_ms: u64) -> bool {
        let mut inner = self.lock();
        self.transition_if_cooled(&mut inner, now_ms);
        match inner.state {
            BreakerState::Closed => true,
            BreakerState::Open => false,
            BreakerState::HalfOpen => {
                if inner.probes_in_flight < self.config.half_open_probes {
                    inner.probes_in_flight += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record an outcome.
    pub fn record(&self, success: bool, now_ms: u64) {
        let mut inner = self.lock();
        self.transition_if_cooled(&mut inner, now_ms);
        inner.counts.record(success, now_ms);

        match inner.state {
            BreakerState::HalfOpen => {
                inner.probes_in_flight = inner.probes_in_flight.saturating_sub(1);
                if success {
                    inner.probe_successes += 1;
                    if inner.probe_successes >= self.config.half_open_successes_to_close {
                        inner.state = BreakerState::Closed;
                        inner.consecutive_opens = 0;
                        inner.probe_successes = 0;
                        inner.closed_at_ms = Some(now_ms);
                        // Clear the window so a freshly recovered target is not
                        // immediately reopened by its own failure history.
                        inner.counts = RollingCounts::new(self.config.window_millis, now_ms);
                    }
                } else {
                    // A failed probe reopens immediately with a longer cooldown.
                    self.open(&mut inner, now_ms);
                }
            }
            BreakerState::Closed => {
                if !success {
                    let (ok, fail) = inner.counts.totals(now_ms);
                    let total = ok.saturating_add(fail);
                    if total >= self.config.min_samples {
                        let percent = u64::from(fail)
                            .saturating_mul(100)
                            .checked_div(u64::from(total))
                            .unwrap_or(0);
                        if percent >= u64::from(self.config.failure_threshold_percent) {
                            self.open(&mut inner, now_ms);
                        }
                    }
                }
            }
            BreakerState::Open => {}
        }
    }

    fn open(&self, inner: &mut BreakerInner, now_ms: u64) {
        inner.state = BreakerState::Open;
        inner.probes_in_flight = 0;
        inner.probe_successes = 0;
        inner.consecutive_opens = inner.consecutive_opens.saturating_add(1);
        // Bounded exponential increase: doubling, capped. An unbounded backoff
        // would take a recovered target out of service indefinitely.
        let shift = (inner.consecutive_opens - 1).min(16);
        let cooldown = self
            .config
            .base_cooldown_millis
            .saturating_mul(1u64 << shift)
            .min(self.config.max_cooldown_millis);
        inner.open_until_ms = now_ms.saturating_add(cooldown);
    }

    /// Force the breaker open, for operator quarantine.
    pub fn force_open(&self, now_ms: u64, duration_ms: u64) {
        let mut inner = self.lock();
        inner.state = BreakerState::Open;
        inner.open_until_ms = now_ms.saturating_add(duration_ms);
        inner.probes_in_flight = 0;
        inner.probe_successes = 0;
    }

    /// Force the breaker closed and clear its history.
    pub fn force_close(&self, now_ms: u64) {
        let mut inner = self.lock();
        inner.state = BreakerState::Closed;
        inner.consecutive_opens = 0;
        inner.probes_in_flight = 0;
        inner.probe_successes = 0;
        inner.counts = RollingCounts::new(self.config.window_millis, now_ms);
    }

    /// Failure percentage over the rolling window.
    // An integer percentage is the intended unit: the numerator is scaled by
    // 100 before the division, `total` is proven non-zero by the early return
    // above, and the breaker compares against integer thresholds.
    #[allow(clippy::integer_division)]
    pub fn failure_percent(&self, now_ms: u64) -> u32 {
        let mut inner = self.lock();
        let (ok, fail) = inner.counts.totals(now_ms);
        let total = ok.saturating_add(fail);
        if total == 0 {
            return 0;
        }
        u32::try_from(u64::from(fail).saturating_mul(100) / u64::from(total)).unwrap_or(100)
    }
}

/// Health for one (target, operation class) pair.
#[derive(Debug)]
pub struct TargetHealth {
    /// The circuit breaker.
    pub breaker: Breaker,
    /// Smoothed time to first byte, in milliseconds.
    pub first_byte_ewma: Ewma,
    /// Distribution of total request latency.
    pub latency: Histogram,
    /// Requests currently in flight, for the queue term.
    in_flight: AtomicU32,
    /// Cumulative counters for exposition.
    total_requests: AtomicU64,
    total_failures: AtomicU64,
}

impl TargetHealth {
    /// Create health state for a target.
    #[must_use]
    pub fn new(config: BreakerConfig, now_ms: u64) -> Self {
        Self {
            breaker: Breaker::new(config, now_ms),
            first_byte_ewma: Ewma::smooth(),
            latency: Histogram::latency_ms(),
            in_flight: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }

    /// Record a successful exchange.
    pub fn record_success(&self, first_byte_ms: u64, total_ms: u64, now_ms: u64) {
        self.first_byte_ewma.observe(first_byte_ms);
        self.latency.observe(total_ms);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.breaker.record(true, now_ms);
    }

    /// Record a failure.
    ///
    /// Only classes that say something about the *target* count against health;
    /// specification 13 keeps client-caused failures out of the breaker so that
    /// one caller cannot take a target out of service.
    pub fn record_failure(&self, class: UpstreamErrorClass, now_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if class.affects_health() {
            self.total_failures.fetch_add(1, Ordering::Relaxed);
            self.breaker.record(false, now_ms);
        }
    }

    /// Note that a request started.
    pub fn enter(&self) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    /// Note that a request finished.
    pub fn exit(&self) {
        // Saturating: a double-exit must not wrap to four billion in flight,
        // which would make the target look permanently saturated.
        let _ = self
            .in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Requests currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Total requests observed.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Total health-affecting failures observed.
    #[must_use]
    pub fn total_failures(&self) -> u64 {
        self.total_failures.load(Ordering::Relaxed)
    }
}

/// The key for per-target, per-operation-class health.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HealthKey {
    /// The target.
    pub target: TargetId,
    /// The operation class.
    ///
    /// Specification 13: "a failed embedding path does not necessarily disable
    /// chat".
    pub operation: Operation,
}

/// The health registry, and the router's [`LiveState`] implementation.
#[derive(Debug)]
pub struct HealthRegistry {
    clock: Arc<dyn Clock>,
    config: BreakerConfig,
    entries: RwLock<BTreeMap<HealthKey, Arc<TargetHealth>>>,
    /// Targets an operator has quarantined, with the reason recorded elsewhere
    /// in the audit chain.
    quarantined: RwLock<BTreeMap<TargetId, u64>>,
    /// Per-target maximum concurrency, for the queue penalty.
    capacities: RwLock<BTreeMap<TargetId, u32>>,
    /// How many requests a target may have waiting for capacity, on top of the
    /// ones in flight.
    queue_allowance: RwLock<BTreeMap<TargetId, u32>>,
    /// Operator-set administrative states, overriding the configured one.
    ///
    /// Specification 13 makes drain and maintenance operational actions that
    /// take effect immediately. The configured state lives in the policy
    /// snapshot and only changes through a published draft; this is the live
    /// override an operator sets from the management API.
    ///
    /// Held in memory only. A restart re-reads the configuration, so a drain
    /// set here does not survive one — recorded in `docs/deferred-issues.md`
    /// rather than left for an operator to discover.
    admin_states: RwLock<BTreeMap<TargetId, AdminState>>,
}

impl HealthRegistry {
    /// Create a registry.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, config: BreakerConfig) -> Self {
        Self {
            clock,
            config,
            entries: RwLock::new(BTreeMap::new()),
            quarantined: RwLock::new(BTreeMap::new()),
            capacities: RwLock::new(BTreeMap::new()),
            queue_allowance: RwLock::new(BTreeMap::new()),
            admin_states: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get or create health state for a target and operation.
    pub fn entry(&self, target: &TargetId, operation: Operation) -> Arc<TargetHealth> {
        let key = HealthKey {
            target: target.clone(),
            operation,
        };
        if let Ok(map) = self.entries.read() {
            if let Some(h) = map.get(&key) {
                return Arc::clone(h);
            }
        }
        let created = Arc::new(TargetHealth::new(self.config, self.clock.now_millis()));
        if let Ok(mut map) = self.entries.write() {
            return Arc::clone(map.entry(key).or_insert(created));
        }
        created
    }

    /// Declare a target's concurrency capacity, so the queue term is meaningful.
    pub fn set_capacity(&self, target: &TargetId, max_concurrency: u32) {
        if let Ok(mut map) = self.capacities.write() {
            map.insert(target.clone(), max_concurrency);
        }
    }

    /// Declare how many requests may wait for this target's capacity.
    ///
    /// Routing treats capacity as an eligibility filter (Appendix B: security,
    /// residency, and capability constraints are filters, never penalties — and
    /// capacity is filtered the same way). A target at its concurrency limit is
    /// therefore excluded outright, which is right when nothing can wait for it
    /// and wrong the moment a queue is configured: the request would be refused
    /// by routing before admission ever got the chance to make it wait.
    ///
    /// Widening the filter by the queue allowance keeps the target eligible for
    /// exactly as long as it can actually accept work, and excludes it again
    /// once the queue is full too. It stays a filter; only the definition of
    /// "can accept" now matches what admission will do.
    pub fn set_queue_allowance(&self, target: &TargetId, max_queued: u32) {
        if let Ok(mut map) = self.queue_allowance.write() {
            map.insert(target.clone(), max_queued);
        }
    }

    /// Set an operator override for a target's administrative state.
    ///
    /// `None` clears the override, restoring the configured state.
    pub fn set_admin_state(&self, target: &TargetId, state: Option<AdminState>) {
        if let Ok(mut map) = self.admin_states.write() {
            match state {
                Some(AdminState::Enabled) | None => map.remove(target),
                Some(other) => map.insert(target.clone(), other),
            };
        }
    }

    /// The operator override for a target, if one is set.
    #[must_use]
    pub fn admin_state(&self, target: &TargetId) -> Option<AdminState> {
        // A live quarantine outranks any other override: specification 13 says
        // "manual quarantine overrides automated recovery", and it must not be
        // cleared by an operator setting a weaker state without going through
        // the quarantine permission.
        if self.is_quarantined(target) {
            return Some(AdminState::Quarantined);
        }
        self.admin_states
            .read()
            .ok()
            .and_then(|m| m.get(target).copied())
    }

    /// Quarantine a target until `until_wall_millis`.
    ///
    /// Specification 13: manual quarantine overrides automated recovery.
    pub fn quarantine(&self, target: &TargetId, until_wall_millis: u64) {
        if let Ok(mut map) = self.quarantined.write() {
            map.insert(target.clone(), until_wall_millis);
        }
    }

    /// Lift a quarantine.
    pub fn release_quarantine(&self, target: &TargetId) {
        if let Ok(mut map) = self.quarantined.write() {
            map.remove(target);
        }
    }

    /// Whether a target is currently quarantined.
    #[must_use]
    pub fn is_quarantined(&self, target: &TargetId) -> bool {
        let now = self.clock.wall_millis();
        self.quarantined
            .read()
            .ok()
            .and_then(|m| m.get(target).copied())
            .is_some_and(|until| until > now)
    }

    /// Whether any operation class for this target has an open circuit.
    fn any_circuit_open(&self, target: &TargetId) -> bool {
        let now = self.clock.now_millis();
        let Ok(map) = self.entries.read() else {
            return false;
        };
        map.iter()
            .filter(|(k, _)| k.target == *target)
            .any(|(_, h)| h.breaker.state(now) == BreakerState::Open)
    }

    /// The worst failure percentage across this target's operation classes.
    fn worst_failure_percent(&self, target: &TargetId) -> u32 {
        let now = self.clock.now_millis();
        let Ok(map) = self.entries.read() else {
            return 0;
        };
        map.iter()
            .filter(|(k, _)| k.target == *target)
            .map(|(_, h)| h.breaker.failure_percent(now))
            .max()
            .unwrap_or(0)
    }

    /// The least-restored operation's ramp for a target.
    ///
    /// Worst-of across operations, matching `worst_failure_percent`: a target
    /// whose embeddings breaker just closed has not fully recovered, whatever
    /// its chat breaker says.
    fn worst_restoration_permille(&self, target: &TargetId, now_ms: u64) -> u64 {
        let Ok(map) = self.entries.read() else {
            return 1000;
        };
        map.iter()
            .filter(|(k, _)| k.target == *target)
            .map(|(_, h)| h.breaker.restoration_permille(now_ms))
            .min()
            .unwrap_or(1000)
    }

    fn slowest_first_byte(&self, target: &TargetId) -> Option<u64> {
        let Ok(map) = self.entries.read() else {
            return None;
        };
        map.iter()
            .filter(|(k, _)| k.target == *target)
            .filter_map(|(_, h)| h.first_byte_ewma.value())
            .max()
    }

    fn total_in_flight(&self, target: &TargetId) -> u32 {
        let Ok(map) = self.entries.read() else {
            return 0;
        };
        map.iter()
            .filter(|(k, _)| k.target == *target)
            .map(|(_, h)| h.in_flight())
            .sum()
    }
}

impl LiveState for HealthRegistry {
    fn circuit_open(&self, target: &TargetId) -> bool {
        self.is_quarantined(target) || self.any_circuit_open(target)
    }

    fn admin_override(&self, target: &TargetId) -> Option<AdminState> {
        self.admin_state(target)
    }

    fn failure_percent(&self, target: &TargetId) -> u32 {
        self.worst_failure_percent(target)
    }

    fn health_penalty(&self, target: &TargetId) -> i64 {
        // Linear in the observed failure percentage, over the documented range.
        let percent = i64::from(self.worst_failure_percent(target));
        let observed = -(percent * 500).clamp(0, 50_000);

        // Specification 22.1 step 13's gradual weight restoration, expressed
        // where it belongs: as part of the *health score term*, not as a
        // separate filter. A target whose breaker recently closed is permitted
        // and merely less preferred, so if it is the only candidate it is still
        // chosen — which is what keeps this a score and not an exclusion
        // (specification 6.3).
        //
        // Applied as an additional penalty scaled by how much of the ramp
        // remains, and clamped into the same documented range so it cannot push
        // the term outside it.
        let now = self.clock.now_millis();
        let restored = self.worst_restoration_permille(target, now);
        let ramp_penalty = -i64::try_from(
            (1000_u64.saturating_sub(restored)).saturating_mul(25),
        )
        .unwrap_or(0);
        (observed.saturating_add(ramp_penalty)).clamp(-50_000, 0)
    }

    fn latency_penalty(&self, target: &TargetId) -> i64 {
        // Piecewise, so that a fast target is not penalised for noise and a
        // very slow one saturates rather than dominating the score.
        let Some(ms) = self.slowest_first_byte(target) else {
            return 0;
        };
        let penalty = match ms {
            0..=100 => 0,
            101..=500 => 5_000,
            501..=1_000 => 15_000,
            1_001..=5_000 => 30_000,
            _ => 50_000,
        };
        -penalty
    }

    // Scoring is integer fixed-point with saturating arithmetic
    // (specification 6.3): the utilisation percentage is scaled by 100 before
    // the division, and the divisor is forced to at least 1, so this can
    // neither divide by zero nor lose a step that would change the ordering.
    #[allow(clippy::integer_division)]
    fn queue_penalty(&self, target: &TargetId) -> i64 {
        let in_flight = i64::from(self.total_in_flight(target));
        let capacity = self
            .capacities
            .read()
            .ok()
            .and_then(|m| m.get(target).copied())
            .filter(|c| *c > 0);
        match capacity {
            None => -(in_flight.saturating_mul(100)).clamp(0, 50_000),
            Some(cap) => {
                let used_percent = in_flight.saturating_mul(100) / i64::from(cap).max(1);
                -(used_percent.saturating_mul(500)).clamp(0, 50_000)
            }
        }
    }

    fn affinity_bonus(&self, _target: &TargetId) -> i64 {
        // Conversation and cache affinity are tracked by the streaming layer,
        // which supplies its own LiveState wrapper when it has a hint. The
        // registry itself has no affinity information.
        0
    }

    fn has_capacity(&self, target: &TargetId) -> bool {
        let capacity = self
            .capacities
            .read()
            .ok()
            .and_then(|m| m.get(target).copied());
        let queue = self
            .queue_allowance
            .read()
            .ok()
            .and_then(|m| m.get(target).copied())
            .unwrap_or(0);
        match capacity {
            None | Some(0) => true,
            Some(cap) => self.total_in_flight(target) < cap.saturating_add(queue),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_recovered_target_has_its_preference_restored_gradually() {
        // Specification 22.1 step 13: "half-open probes, gradual weight
        // restoration". The probes existed; the ramp did not, so a target went
        // from refusing everything to competing at full preference the instant
        // its second probe succeeded — and if it was recovering rather than
        // recovered, the load that arrived proved it by reopening the breaker.
        let breaker = Breaker::new(BreakerConfig::DEFAULT, 0);

        // A breaker that has never opened is fully restored: no failure history
        // is not something to penalise.
        assert_eq!(breaker.restoration_permille(0), 1000);

        // Trip it, cool it, and close it with probes.
        let mut now = 0u64;
        for _ in 0..64 {
            breaker.record(false, now);
        }
        assert_eq!(breaker.state(now), BreakerState::Open);
        now += BreakerConfig::DEFAULT.base_cooldown_millis * 4;
        assert_eq!(breaker.state(now), BreakerState::HalfOpen);
        for _ in 0..BreakerConfig::DEFAULT.half_open_successes_to_close {
            assert!(breaker.try_admit(now));
            breaker.record(true, now);
        }
        assert_eq!(breaker.state(now), BreakerState::Closed);

        // Immediately after closing, preference is heavily reduced but never
        // zero — the ramp is a score term, not an exclusion.
        let at_close = breaker.restoration_permille(now);
        assert!(
            (100..300).contains(&at_close),
            "just-recovered restoration was {at_close}"
        );

        // It rises, monotonically.
        let midway = breaker.restoration_permille(now + WEIGHT_RESTORATION_MILLIS / 2);
        assert!(midway > at_close, "{midway} did not rise above {at_close}");

        // And completes.
        assert_eq!(
            breaker.restoration_permille(now + WEIGHT_RESTORATION_MILLIS),
            1000
        );
        assert_eq!(
            breaker.restoration_permille(now + WEIGHT_RESTORATION_MILLIS * 10),
            1000
        );
    }

    #[test]
    fn the_restoration_ramp_is_a_score_term_and_never_an_exclusion() {
        // Specification 6.3 and Appendix B: health is a score, never a filter.
        // A ramped target must remain *eligible* — if it is the only candidate
        // it has to be chosen, or a recovery would look like an outage.
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, BreakerConfig::DEFAULT);
        let target = tid("local:m");

        let health = registry.entry(&target, Operation::Chat);
        for _ in 0..64 {
            health.record_failure(UpstreamErrorClass::ServerError, clock.now_millis());
        }
        clock.advance(BreakerConfig::DEFAULT.base_cooldown_millis * 4);
        for _ in 0..BreakerConfig::DEFAULT.half_open_successes_to_close {
            assert!(health.breaker.try_admit(clock.now_millis()));
            health.record_success(1, 1, clock.now_millis());
        }
        assert_eq!(health.breaker.state(clock.now_millis()), BreakerState::Closed);

        // Penalised...
        let penalty = registry.health_penalty(&target);
        assert!(penalty < 0, "a just-recovered target should score lower");
        // ...within the documented range, so it cannot overflow or dominate.
        assert!(penalty >= crate::decision::ScoreTerms::HEALTH_RANGE.0);
        // ...and *not* excluded: the breaker is closed and capacity is intact.
        assert!(!registry.circuit_open(&target));
        assert!(registry.has_capacity(&target));

        // Once the ramp completes the penalty is the observed-failure one only.
        clock.advance(WEIGHT_RESTORATION_MILLIS);
        assert!(registry.health_penalty(&target) > penalty);
    }


    use super::*;
    use crate::time::TestClock;

    fn tid(s: &str) -> TargetId {
        TargetId::new(s).unwrap()
    }

    fn config() -> BreakerConfig {
        BreakerConfig {
            min_samples: 4,
            failure_threshold_percent: 50,
            window_millis: 10_000,
            base_cooldown_millis: 1_000,
            max_cooldown_millis: 8_000,
            half_open_probes: 1,
            half_open_successes_to_close: 2,
        }
    }

    // -- Breaker ------------------------------------------------------------

    #[test]
    fn breaker_needs_minimum_samples_before_opening() {
        // A single failure on a new target must not open its circuit.
        let b = Breaker::new(config(), 0);
        b.record(false, 0);
        assert_eq!(b.state(0), BreakerState::Closed);
        b.record(false, 0);
        assert_eq!(b.state(0), BreakerState::Closed);
        b.record(false, 0);
        assert_eq!(b.state(0), BreakerState::Closed);
        // The fourth sample reaches min_samples at 100% failure.
        b.record(false, 0);
        assert_eq!(b.state(0), BreakerState::Open);
    }

    #[test]
    fn breaker_stays_closed_below_the_threshold() {
        let b = Breaker::new(config(), 0);
        for _ in 0..10 {
            b.record(true, 0);
        }
        for _ in 0..4 {
            b.record(false, 0);
        }
        // 4 failures in 14 samples is under 50%.
        assert_eq!(b.state(0), BreakerState::Closed);
        assert_eq!(b.failure_percent(0), 28);
    }

    #[test]
    fn open_breaker_refuses_until_cooldown_then_half_opens() {
        let b = Breaker::new(config(), 0);
        for _ in 0..4 {
            b.record(false, 0);
        }
        assert_eq!(b.state(0), BreakerState::Open);
        assert!(!b.try_admit(0));
        assert!(!b.try_admit(999));

        // Cooldown elapses.
        assert_eq!(b.state(1_000), BreakerState::HalfOpen);
        assert!(b.try_admit(1_000), "one probe is allowed");
        assert!(!b.try_admit(1_000), "only half_open_probes concurrently");
    }

    #[test]
    fn half_open_closes_after_enough_successes() {
        let b = Breaker::new(config(), 0);
        for _ in 0..4 {
            b.record(false, 0);
        }
        assert_eq!(b.state(1_000), BreakerState::HalfOpen);

        assert!(b.try_admit(1_000));
        b.record(true, 1_000);
        assert_eq!(b.state(1_000), BreakerState::HalfOpen, "one success is not enough");

        assert!(b.try_admit(1_100));
        b.record(true, 1_100);
        assert_eq!(b.state(1_100), BreakerState::Closed);
        assert!(b.try_admit(1_100));
    }

    #[test]
    fn failed_probe_reopens_with_a_longer_cooldown() {
        let b = Breaker::new(config(), 0);
        for _ in 0..4 {
            b.record(false, 0);
        }
        // First open: 1s cooldown.
        assert_eq!(b.state(1_000), BreakerState::HalfOpen);
        assert!(b.try_admit(1_000));
        b.record(false, 1_000);
        assert_eq!(b.state(1_000), BreakerState::Open);

        // Second open: 2s cooldown, so 1s later it is still open.
        assert_eq!(b.state(2_000), BreakerState::Open);
        assert_eq!(b.state(3_000), BreakerState::HalfOpen);
    }

    #[test]
    fn cooldown_growth_is_bounded() {
        let b = Breaker::new(config(), 0);
        for _ in 0..4 {
            b.record(false, 0);
        }
        let mut now = 0u64;
        // Drive many consecutive opens; the cooldown must stop at the ceiling.
        for _ in 0..20 {
            now += 100_000; // far past any cooldown
            assert_eq!(b.state(now), BreakerState::HalfOpen);
            assert!(b.try_admit(now));
            b.record(false, now);
        }
        // The cooldown is capped at max_cooldown_millis, so the breaker is
        // half-open again that long after the last failure — not longer.
        assert_eq!(b.state(now + 8_000), BreakerState::HalfOpen);
    }

    #[test]
    fn rolling_window_forgets_old_failures() {
        let b = Breaker::new(config(), 0);
        for _ in 0..3 {
            b.record(false, 0);
        }
        assert_eq!(b.state(0), BreakerState::Closed);
        // Two full windows later, the old failures are out of scope.
        assert_eq!(b.failure_percent(25_000), 0);
        b.record(false, 25_000);
        assert_eq!(
            b.state(25_000),
            BreakerState::Closed,
            "stale failures must not combine with a fresh one to open the breaker"
        );
    }

    #[test]
    fn force_open_and_close_are_operator_overrides() {
        let b = Breaker::new(config(), 0);
        b.force_open(0, 5_000);
        assert_eq!(b.state(0), BreakerState::Open);
        assert!(!b.try_admit(4_999));
        assert_eq!(b.state(5_000), BreakerState::HalfOpen);

        b.force_close(6_000);
        assert_eq!(b.state(6_000), BreakerState::Closed);
        assert!(b.try_admit(6_000));
    }

    // -- Per-operation isolation --------------------------------------------

    #[test]
    fn a_failed_embedding_path_does_not_disable_chat() {
        // Specification 13, stated almost verbatim.
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("openai:gpt");

        let embeddings = registry.entry(&target, Operation::Embeddings);
        for _ in 0..4 {
            embeddings.record_failure(UpstreamErrorClass::ServerError, clock.now_millis());
        }
        assert_eq!(
            embeddings.breaker.state(clock.now_millis()),
            BreakerState::Open
        );

        let chat = registry.entry(&target, Operation::Chat);
        assert_eq!(
            chat.breaker.state(clock.now_millis()),
            BreakerState::Closed,
            "the chat path must be unaffected"
        );
    }

    #[test]
    fn client_errors_do_not_open_the_breaker() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let h = registry.entry(&tid("t"), Operation::Chat);

        for _ in 0..100 {
            h.record_failure(UpstreamErrorClass::InvalidRequest, clock.now_millis());
            h.record_failure(UpstreamErrorClass::ContextOverflow, clock.now_millis());
            h.record_failure(UpstreamErrorClass::RateLimited, clock.now_millis());
        }
        assert_eq!(h.breaker.state(clock.now_millis()), BreakerState::Closed);
        assert_eq!(h.total_failures(), 0);
        assert_eq!(h.total_requests(), 300);
    }

    // -- LiveState ----------------------------------------------------------

    #[test]
    fn registry_reports_open_circuits_to_routing() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");
        assert!(!registry.circuit_open(&target));

        let h = registry.entry(&target, Operation::Chat);
        for _ in 0..4 {
            h.record_failure(UpstreamErrorClass::Connection, clock.now_millis());
        }
        assert!(registry.circuit_open(&target));
    }

    #[test]
    fn quarantine_overrides_automated_recovery() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");

        registry.quarantine(&target, clock.wall_millis() + 60_000);
        assert!(registry.circuit_open(&target));
        assert!(registry.is_quarantined(&target));

        // Even a perfectly healthy breaker stays excluded.
        let h = registry.entry(&target, Operation::Chat);
        for _ in 0..50 {
            h.record_success(10, 20, clock.now_millis());
        }
        assert!(registry.circuit_open(&target), "quarantine must win");

        registry.release_quarantine(&target);
        assert!(!registry.circuit_open(&target));
    }

    #[test]
    fn quarantine_expires_on_wall_clock_time() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");
        registry.quarantine(&target, clock.wall_millis() + 1_000);
        assert!(registry.is_quarantined(&target));
        clock.advance(1_001);
        assert!(!registry.is_quarantined(&target));
    }

    #[test]
    fn penalties_stay_within_documented_ranges() {
        use crate::decision::ScoreTerms;
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");
        registry.set_capacity(&target, 4);

        let h = registry.entry(&target, Operation::Chat);
        for _ in 0..200 {
            h.record_failure(UpstreamErrorClass::ServerError, clock.now_millis());
            h.first_byte_ewma.observe(120_000);
            h.enter();
        }

        let health = registry.health_penalty(&target);
        let latency = registry.latency_penalty(&target);
        let queue = registry.queue_penalty(&target);
        assert!((ScoreTerms::HEALTH_RANGE.0..=ScoreTerms::HEALTH_RANGE.1).contains(&health));
        assert!((ScoreTerms::LATENCY_RANGE.0..=ScoreTerms::LATENCY_RANGE.1).contains(&latency));
        assert!((ScoreTerms::QUEUE_RANGE.0..=ScoreTerms::QUEUE_RANGE.1).contains(&queue));
    }

    #[test]
    fn a_healthy_idle_target_has_no_penalties() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");
        let h = registry.entry(&target, Operation::Chat);
        for _ in 0..20 {
            h.record_success(20, 100, clock.now_millis());
        }
        assert_eq!(registry.health_penalty(&target), 0);
        assert_eq!(registry.latency_penalty(&target), 0);
        assert_eq!(registry.queue_penalty(&target), 0);
        assert!(registry.has_capacity(&target));
    }

    #[test]
    fn capacity_filter_reflects_in_flight_requests() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("t");
        registry.set_capacity(&target, 2);
        let h = registry.entry(&target, Operation::Chat);

        assert!(registry.has_capacity(&target));
        h.enter();
        assert!(registry.has_capacity(&target));
        h.enter();
        assert!(!registry.has_capacity(&target));
        h.exit();
        assert!(registry.has_capacity(&target));
    }

    #[test]
    fn in_flight_never_wraps_below_zero() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let h = registry.entry(&tid("t"), Operation::Chat);
        h.exit();
        h.exit();
        assert_eq!(h.in_flight(), 0, "a double exit must not wrap");
    }

    #[test]
    fn unknown_capacity_never_blocks_admission() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());
        let target = tid("never-configured");
        assert!(registry.has_capacity(&target));
        assert_eq!(registry.queue_penalty(&target), 0);
    }

    #[test]
    fn latency_penalty_is_monotonic_in_latency() {
        let clock = Arc::new(TestClock::new());
        let registry = HealthRegistry::new(Arc::clone(&clock) as Arc<dyn Clock>, config());

        let mut last = 1i64;
        for (i, ms) in [50u64, 300, 800, 3_000, 60_000].iter().enumerate() {
            let target = tid(&format!("t{i}"));
            let h = registry.entry(&target, Operation::Chat);
            h.first_byte_ewma.observe(*ms);
            let penalty = registry.latency_penalty(&target);
            assert!(penalty <= last, "penalty for {ms}ms was not monotonic");
            last = penalty;
        }
    }
}
