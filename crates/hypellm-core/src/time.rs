//! Monotonic time, deadlines, and an injectable clock.
//!
//! Specification 17: "Time synchronization status is monitored; monotonic
//! clocks govern durations and deadlines." A deadline computed from wall-clock
//! time can move backwards across an NTP step, which would either expire a live
//! request or keep a dead one alive.
//!
//! The [`Clock`] trait exists so that admission control, circuit breakers, and
//! token buckets are testable without sleeping. Every test in this workspace
//! that involves time uses [`TestClock`]; none uses `thread::sleep`.
//!
//! # Two monotonic resolutions
//!
//! [`Clock::now_millis`] *bounds* work: deadlines, retry budgets, breaker
//! windows, token-bucket refills. A millisecond tick is free there, because
//! being a tick late on a five-second deadline changes nothing.
//!
//! [`Clock::now_micros`] *measures* work. Specification 19 sets router overhead
//! at "p50 < 2 ms, p99 < 10 ms"; a millisecond clock cannot express that
//! judgement, because every sample under target reads as 0 or 1 and the
//! quantisation error on the p99 is a tenth of the whole budget. Anything whose
//! value is compared against the specification 19 targets — the decision trace's
//! `routing_micros`, the `hypellm-bench` harness — must read this one.

use core::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A source of monotonic time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Monotonic milliseconds since an arbitrary fixed origin.
    ///
    /// Only differences are meaningful. The origin is process start for the
    /// system clock, which keeps the value small enough that arithmetic on it
    /// cannot overflow within any plausible uptime.
    fn now_millis(&self) -> u64;

    /// Monotonic microseconds since the same origin as [`Clock::now_millis`].
    ///
    /// The measurement resolution. `now_micros() / 1000 == now_millis()` for
    /// every implementation here, so the two never disagree about which
    /// millisecond it is; the microsecond reading simply carries the fraction
    /// that the millisecond reading discards.
    ///
    /// Use this for any interval whose *size* is the answer — router overhead,
    /// benchmark samples — and `now_millis` for any interval whose *expiry* is
    /// the answer. A microsecond origin overflows `u64` after roughly 584,000
    /// years of uptime, so the arithmetic is as safe as the millisecond one.
    fn now_micros(&self) -> u64;

    /// Wall-clock milliseconds since the Unix epoch.
    ///
    /// For timestamps in audit records and expiry comparisons that must survive
    /// a restart. Never for measuring an interval.
    fn wall_millis(&self) -> u64;
}

/// The production clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Create a clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        // `Instant` is monotonic and non-decreasing on every supported
        // platform, so this cannot go backwards.
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn now_micros(&self) -> u64 {
        // Same `Instant` origin as `now_millis`, so the two readings are two
        // resolutions of one measurement rather than two clocks that can drift.
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn wall_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A clock that only moves when a test moves it.
#[derive(Debug)]
pub struct TestClock {
    /// Monotonic time is held in microseconds so that a test can exercise the
    /// sub-millisecond path; `now_millis` truncates it.
    monotonic_micros: AtomicU64,
    wall: AtomicU64,
}

impl TestClock {
    /// Create a clock at monotonic 0 and a fixed wall time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            monotonic_micros: AtomicU64::new(0),
            // 2026-01-01T00:00:00Z, an arbitrary fixed point so that tests
            // producing timestamps are reproducible.
            wall: AtomicU64::new(1_767_225_600_000),
        }
    }

    /// Advance both clocks by `millis`.
    pub fn advance(&self, millis: u64) {
        self.monotonic_micros
            .fetch_add(millis.saturating_mul(1000), Ordering::SeqCst);
        self.wall.fetch_add(millis, Ordering::SeqCst);
    }

    /// Advance monotonic time alone by `micros`, leaving the wall clock still.
    ///
    /// For tests of sub-millisecond measurement. The wall clock is deliberately
    /// not moved: it has no sub-millisecond resolution to move by, and pushing
    /// it a rounded amount would fabricate skew for [`ClockSyncMonitor`].
    pub fn advance_micros(&self, micros: u64) {
        self.monotonic_micros.fetch_add(micros, Ordering::SeqCst);
    }

    /// Move wall-clock time without moving monotonic time, simulating an NTP
    /// step. Monotonic-derived deadlines must be unaffected.
    pub fn skew_wall(&self, delta: i64) {
        let current = self.wall.load(Ordering::SeqCst);
        let next = if delta.is_negative() {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            current.saturating_add(delta.unsigned_abs())
        };
        self.wall.store(next, Ordering::SeqCst);
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    // Truncating microseconds to whole milliseconds is the intended unit
    // conversion, not a lost-precision accident: `now_micros` is the exact
    // reading and callers that need sub-millisecond resolution use it.
    #[allow(clippy::integer_division)]
    fn now_millis(&self) -> u64 {
        self.monotonic_micros.load(Ordering::SeqCst) / 1000
    }

    fn now_micros(&self) -> u64 {
        self.monotonic_micros.load(Ordering::SeqCst)
    }

    fn wall_millis(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }
}

/// An end-to-end deadline.
///
/// Specification 18.2: "Every I/O operation has a deadline and cancellation
/// path." A `Deadline` is passed down the whole request path; every wait
/// derives its timeout from [`Deadline::remaining`] so that no individual step
/// can extend the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    at_millis: u64,
}

impl Deadline {
    /// A deadline `budget` from now.
    #[must_use]
    pub fn after(clock: &dyn Clock, budget: Duration) -> Self {
        let ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
        Self {
            at_millis: clock.now_millis().saturating_add(ms),
        }
    }

    /// A deadline at an absolute monotonic instant.
    #[must_use]
    pub const fn at(at_millis: u64) -> Self {
        Self { at_millis }
    }

    /// The absolute monotonic instant.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.at_millis
    }

    /// Whether the deadline has passed.
    #[must_use]
    pub fn is_expired(self, clock: &dyn Clock) -> bool {
        clock.now_millis() >= self.at_millis
    }

    /// Time left, saturating at zero.
    #[must_use]
    pub fn remaining(self, clock: &dyn Clock) -> Duration {
        Duration::from_millis(self.at_millis.saturating_sub(clock.now_millis()))
    }

    /// The earlier of two deadlines.
    ///
    /// A per-attempt budget must never outlive the request budget, so combining
    /// takes the minimum rather than the sum.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        Self {
            at_millis: self.at_millis.min(other.at_millis),
        }
    }

    /// Cap a proposed wait so it cannot exceed the remaining budget.
    ///
    /// Specification 6.5: "Retry-After is capped by the remaining deadline."
    #[must_use]
    pub fn cap(self, clock: &dyn Clock, proposed: Duration) -> Duration {
        proposed.min(self.remaining(clock))
    }
}

/// Exponentially weighted moving average over an integer-valued sample.
///
/// Specification 13 requires EWMA and fixed-bucket histograms so that live
/// metrics cannot grow without bound. The state is a single value.
#[derive(Debug)]
pub struct Ewma {
    /// Fixed-point value, scaled by [`Ewma::SCALE`].
    scaled: AtomicU64,
    /// Smoothing numerator over 1024: a value of 102 is roughly a 10% weight
    /// on each new sample.
    alpha_num: u64,
    initialised: AtomicU64,
}

impl Ewma {
    /// Fixed-point scale. Integer arithmetic only: specification 6.3 requires
    /// integer fixed-point to avoid floating-point drift, and the same
    /// reasoning applies to the latency inputs that feed scoring.
    pub const SCALE: u64 = 1024;

    /// Create with a smoothing factor expressed as `alpha_num / 1024`.
    #[must_use]
    pub fn new(alpha_num: u64) -> Self {
        Self {
            scaled: AtomicU64::new(0),
            alpha_num: alpha_num.clamp(1, Self::SCALE),
            initialised: AtomicU64::new(0),
        }
    }

    /// A 10% weight on each new sample.
    #[must_use]
    pub fn smooth() -> Self {
        Self::new(102)
    }

    /// Record a sample.
    // Dividing by `SCALE` is the fixed-point descale that keeps the average in
    // the same units as the samples; specification 6.3 requires this to be
    // integer arithmetic, so truncation here is the specified behaviour.
    #[allow(clippy::integer_division)]
    pub fn observe(&self, sample: u64) {
        let scaled_sample = sample.saturating_mul(Self::SCALE);
        if self.initialised.swap(1, Ordering::SeqCst) == 0 {
            self.scaled.store(scaled_sample, Ordering::SeqCst);
            return;
        }
        // Read-modify-write under contention may lose an update. That is
        // acceptable: this is an advisory signal (specification 13, "live
        // metrics are advisory; policy remains the authority"), and a lock
        // here would be on the request path.
        let prev = self.scaled.load(Ordering::SeqCst);
        let next = (prev.saturating_mul(Self::SCALE - self.alpha_num))
            .saturating_add(scaled_sample.saturating_mul(self.alpha_num))
            / Self::SCALE;
        self.scaled.store(next, Ordering::SeqCst);
    }

    /// The current average, or `None` before the first sample.
    // Same fixed-point descale as `observe`: integer by specification 6.3.
    #[allow(clippy::integer_division)]
    #[must_use]
    pub fn value(&self) -> Option<u64> {
        if self.initialised.load(Ordering::SeqCst) == 0 {
            return None;
        }
        Some(self.scaled.load(Ordering::SeqCst) / Self::SCALE)
    }

    /// The current average, or `default` before the first sample.
    #[must_use]
    pub fn value_or(&self, default: u64) -> u64 {
        self.value().unwrap_or(default)
    }
}

/// A fixed-bucket histogram.
///
/// Bucket boundaries are compiled in so that the memory cost is constant and
/// independent of the values observed (specification 13: "fixed-bucket
/// histograms avoid unbounded samples").
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [u64],
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    total: AtomicU64,
}

/// Latency buckets in milliseconds, covering router overhead through provider
/// timeouts.
pub const LATENCY_BUCKETS_MS: &[u64] = &[
    1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000,
];

impl Histogram {
    /// Create a histogram with the given upper bounds, plus an implicit
    /// overflow bucket.
    #[must_use]
    pub fn new(bounds: &'static [u64]) -> Self {
        let counts = (0..bounds.len() + 1).map(|_| AtomicU64::new(0)).collect();
        Self {
            bounds,
            counts,
            sum: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// A latency histogram in milliseconds.
    #[must_use]
    pub fn latency_ms() -> Self {
        Self::new(LATENCY_BUCKETS_MS)
    }

    /// Record a sample.
    pub fn observe(&self, value: u64) {
        let idx = self
            .bounds
            .iter()
            .position(|b| value <= *b)
            .unwrap_or(self.bounds.len());
        if let Some(c) = self.counts.get(idx) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of samples.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Sum of all samples.
    #[must_use]
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// Cumulative counts paired with their upper bounds, for text exposition.
    ///
    /// The final entry has no bound and represents the overflow bucket.
    #[must_use]
    pub fn buckets(&self) -> Vec<(Option<u64>, u64)> {
        let mut out = Vec::with_capacity(self.counts.len());
        let mut cumulative = 0u64;
        for (i, c) in self.counts.iter().enumerate() {
            cumulative += c.load(Ordering::Relaxed);
            out.push((self.bounds.get(i).copied(), cumulative));
        }
        out
    }

    /// The bucket upper bound at or above which `quantile` of samples fall.
    ///
    /// Bucketed, so this is an upper bound on the true quantile, not an exact
    /// value. Specification 19.1 requires reporting distributions; this is the
    /// cheap always-on estimate, not the benchmark harness's measurement.
    #[must_use]
    pub fn quantile_upper_bound(&self, quantile_num: u64, quantile_den: u64) -> Option<u64> {
        let total = self.count();
        if total == 0 || quantile_den == 0 {
            return None;
        }
        // Round the rank *up*: the q-quantile is the smallest bucket bound at
        // or below which at least a q fraction of samples fall. Rounding down
        // would report p99.9 of a 100-sample set as the 99th sample, hiding the
        // single slowest one — which is exactly the sample a tail latency
        // target exists to catch.
        let target = total
            .saturating_mul(quantile_num)
            .div_ceil(quantile_den)
            .max(1);
        let mut cumulative = 0u64;
        for (i, c) in self.counts.iter().enumerate() {
            cumulative += c.load(Ordering::Relaxed);
            if cumulative >= target {
                return Some(self.bounds.get(i).copied().unwrap_or(u64::MAX));
            }
        }
        None
    }
}

/// Format a wall-clock millisecond timestamp as RFC 3339 UTC.
///
/// Audit records and management responses need a human-readable timestamp, and
/// the dependency policy admits no date library. The conversion is pure
/// arithmetic over the proleptic Gregorian calendar.
// Calendar arithmetic is exact integer division by definition — each divisor is
// a whole number of the unit being extracted (1000 ms per second, 86_400 s per
// day, 3600 s per hour, 60 s per minute) and the remainder is carried by the
// `%` on the following line. Floating point would be wrong here, not more
// precise.
#[allow(clippy::integer_division)]
#[must_use]
pub fn format_rfc3339(wall_millis: u64) -> String {
    let secs = wall_millis / 1000;
    let millis = wall_millis % 1000;
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Days since the Unix epoch to a civil date.
///
/// Howard Hinnant's `civil_from_days`, shifted to an epoch of 0000-03-01 so
/// that the leap day falls at the end of the year and the month arithmetic has
/// no special cases.
// Every division below is an exact step of Hinnant's algorithm over unsigned
// days: the truncation is what selects the era, year-of-era, and month index.
// Rewriting in floating point would break the algorithm outright.
#[allow(clippy::integer_division)]
fn civil_from_days(days_since_epoch: u64) -> (u64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// A guard that records how long a scope took, without any global state.
///
/// Timed in microseconds even when only the millisecond reading is wanted: a
/// scope short enough to matter is short enough for the millisecond difference
/// of two endpoint readings to be dominated by where the tick boundary fell.
#[derive(Debug)]
pub struct Stopwatch<'a> {
    clock: &'a dyn Clock,
    start_micros: u64,
}

impl<'a> Stopwatch<'a> {
    /// Start timing.
    #[must_use]
    pub fn start(clock: &'a dyn Clock) -> Self {
        Self {
            clock,
            start_micros: clock.now_micros(),
        }
    }

    /// Microseconds elapsed.
    #[must_use]
    pub fn elapsed_micros(&self) -> u64 {
        self.clock.now_micros().saturating_sub(self.start_micros)
    }

    /// Milliseconds elapsed, truncated.
    // Truncation is the documented contract of this accessor; callers that
    // need the exact figure call `elapsed_micros`.
    #[allow(clippy::integer_division)]
    #[must_use]
    pub fn elapsed_millis(&self) -> u64 {
        self.elapsed_micros() / 1000
    }
}

/// Tracks whether the wall clock appears to be synchronised, by comparing
/// wall-clock movement against monotonic movement.
///
/// Specification 17: "Time synchronization status is monitored."
#[derive(Debug)]
pub struct ClockSyncMonitor {
    last: Mutex<Option<(u64, u64)>>,
    max_skew_millis: u64,
    skew_events: AtomicU64,
}

impl ClockSyncMonitor {
    /// Create a monitor that flags a step larger than `max_skew_millis`.
    #[must_use]
    pub fn new(max_skew_millis: u64) -> Self {
        Self {
            last: Mutex::new(None),
            max_skew_millis,
            skew_events: AtomicU64::new(0),
        }
    }

    /// Sample both clocks. Returns true when a step was detected.
    pub fn sample(&self, clock: &dyn Clock) -> bool {
        let now = (clock.now_millis(), clock.wall_millis());
        let mut guard = match self.last.lock() {
            Ok(g) => g,
            // A poisoned lock here means a panic in another sampler. The
            // monitor is diagnostic, so degrade rather than propagate.
            Err(poisoned) => poisoned.into_inner(),
        };
        let stepped = match *guard {
            None => false,
            Some((prev_mono, prev_wall)) => {
                let mono_delta = now.0.saturating_sub(prev_mono);
                let wall_delta = now.1.abs_diff(prev_wall);
                wall_delta.abs_diff(mono_delta) > self.max_skew_millis
            }
        };
        *guard = Some(now);
        if stepped {
            self.skew_events.fetch_add(1, Ordering::Relaxed);
        }
        stepped
    }

    /// Number of steps observed since start.
    #[must_use]
    pub fn skew_events(&self) -> u64 {
        self.skew_events.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_only_moves_when_told() {
        let c = TestClock::new();
        assert_eq!(c.now_millis(), 0);
        assert_eq!(c.now_millis(), 0);
        c.advance(500);
        assert_eq!(c.now_millis(), 500);
    }

    #[test]
    fn deadline_expiry_and_remaining() {
        let c = TestClock::new();
        let d = Deadline::after(&c, Duration::from_millis(1000));
        assert!(!d.is_expired(&c));
        assert_eq!(d.remaining(&c), Duration::from_millis(1000));
        c.advance(400);
        assert_eq!(d.remaining(&c), Duration::from_millis(600));
        c.advance(600);
        assert!(d.is_expired(&c));
        assert_eq!(d.remaining(&c), Duration::ZERO);
        // Remaining saturates rather than wrapping.
        c.advance(10_000);
        assert_eq!(d.remaining(&c), Duration::ZERO);
    }

    #[test]
    fn deadlines_are_immune_to_wall_clock_steps() {
        // The reason deadlines use the monotonic clock at all.
        let c = TestClock::new();
        let d = Deadline::after(&c, Duration::from_millis(1000));
        c.skew_wall(-3_600_000); // NTP steps an hour backwards
        assert!(!d.is_expired(&c));
        assert_eq!(d.remaining(&c), Duration::from_millis(1000));
        c.skew_wall(7_200_000); // and then two hours forwards
        assert!(!d.is_expired(&c));
        c.advance(1000);
        assert!(d.is_expired(&c));
    }

    #[test]
    fn deadline_min_takes_the_earlier() {
        let c = TestClock::new();
        let request = Deadline::after(&c, Duration::from_millis(5000));
        let attempt = Deadline::after(&c, Duration::from_millis(1000));
        assert_eq!(request.min(attempt), attempt);
        assert_eq!(attempt.min(request), attempt);
    }

    #[test]
    fn deadline_caps_a_proposed_wait() {
        let c = TestClock::new();
        let d = Deadline::after(&c, Duration::from_millis(1000));
        // A provider asking for a 60 second Retry-After cannot extend the
        // request past its deadline.
        assert_eq!(d.cap(&c, Duration::from_secs(60)), Duration::from_millis(1000));
        assert_eq!(d.cap(&c, Duration::from_millis(200)), Duration::from_millis(200));
        c.advance(1000);
        assert_eq!(d.cap(&c, Duration::from_secs(60)), Duration::ZERO);
    }

    #[test]
    fn ewma_starts_at_the_first_sample() {
        let e = Ewma::smooth();
        assert_eq!(e.value(), None);
        assert_eq!(e.value_or(42), 42);
        e.observe(100);
        assert_eq!(e.value(), Some(100));
    }

    #[test]
    fn ewma_converges_toward_new_samples() {
        let e = Ewma::smooth();
        e.observe(100);
        for _ in 0..200 {
            e.observe(200);
        }
        let v = e.value().unwrap();
        assert!((195..=200).contains(&v), "converged to {v}");
    }

    #[test]
    fn ewma_is_stable_against_a_single_outlier() {
        let e = Ewma::smooth();
        for _ in 0..50 {
            e.observe(100);
        }
        e.observe(100_000);
        let v = e.value().unwrap();
        // A 10% weight means one outlier moves the average by about a tenth of
        // the gap, not to the outlier itself.
        assert!(v < 20_000, "single outlier moved the average to {v}");
        assert!(v > 100);
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let h = Histogram::latency_ms();
        for v in [1, 3, 7, 40, 900, 999_999] {
            h.observe(v);
        }
        assert_eq!(h.count(), 6);
        let buckets = h.buckets();
        assert_eq!(buckets.last().unwrap().1, 6, "final cumulative is the total");
        assert_eq!(buckets.last().unwrap().0, None, "overflow bucket has no bound");
        // Cumulative counts never decrease.
        for pair in buckets.windows(2) {
            assert!(pair[1].1 >= pair[0].1);
        }
    }

    #[test]
    fn histogram_quantiles_are_upper_bounds() {
        let h = Histogram::latency_ms();
        for _ in 0..99 {
            h.observe(5);
        }
        h.observe(50_000);
        let p50 = h.quantile_upper_bound(50, 100).unwrap();
        assert_eq!(p50, 5);
        let p999 = h.quantile_upper_bound(999, 1000).unwrap();
        assert!(p999 >= 30_000, "p99.9 was {p999}");
    }

    #[test]
    fn empty_histogram_has_no_quantile() {
        let h = Histogram::latency_ms();
        assert_eq!(h.quantile_upper_bound(50, 100), None);
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum(), 0);
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(1_000), "1970-01-01T00:00:01.000Z");
        assert_eq!(format_rfc3339(1_767_225_600_000), "2026-01-01T00:00:00.000Z");
        // A leap day.
        assert_eq!(format_rfc3339(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        assert_eq!(format_rfc3339(1_767_225_600_123), "2026-01-01T00:00:00.123Z");
    }

    #[test]
    fn stopwatch_measures_monotonic_elapsed() {
        let c = TestClock::new();
        let w = Stopwatch::start(&c);
        assert_eq!(w.elapsed_millis(), 0);
        c.advance(250);
        assert_eq!(w.elapsed_millis(), 250);
        assert_eq!(w.elapsed_micros(), 250_000);
    }

    #[test]
    fn stopwatch_resolves_below_a_millisecond() {
        // The defect this resolution exists to fix: a 900 µs scope measured on
        // a millisecond clock reads as zero, and specification 19's 2 ms target
        // cannot be judged from a series of zeroes.
        let c = TestClock::new();
        let w = Stopwatch::start(&c);
        c.advance_micros(900);
        assert_eq!(w.elapsed_micros(), 900);
        assert_eq!(w.elapsed_millis(), 0);
    }

    #[test]
    fn micro_and_milli_readings_never_disagree() {
        let c = TestClock::new();
        for step in [1u64, 999, 1, 500_000, 7] {
            c.advance_micros(step);
            assert_eq!(
                c.now_millis(),
                c.now_micros() / 1000,
                "the two resolutions must name the same millisecond"
            );
        }
    }

    #[test]
    fn advancing_micros_does_not_fabricate_wall_clock_skew() {
        let c = TestClock::new();
        let m = ClockSyncMonitor::new(1);
        assert!(!m.sample(&c));
        let wall_before = c.wall_millis();
        c.advance_micros(400);
        assert_eq!(c.wall_millis(), wall_before);
    }

    #[test]
    fn system_clock_micros_are_monotonic_and_finer_than_millis() {
        let c = SystemClock::new();
        let mut last = c.now_micros();
        let mut distinct = 0u32;
        for _ in 0..10_000 {
            let now = c.now_micros();
            assert!(now >= last, "monotonic microseconds went backwards");
            if now != last {
                distinct += 1;
            }
            last = now;
        }
        // A loop this short would produce at most a couple of distinct
        // millisecond readings; seeing many distinct microsecond readings is
        // what proves the source is genuinely finer and not millis * 1000.
        assert!(
            distinct > 2,
            "only {distinct} distinct microsecond readings over 10k samples"
        );
    }

    #[test]
    fn clock_sync_monitor_detects_a_step() {
        let c = TestClock::new();
        let m = ClockSyncMonitor::new(1000);
        assert!(!m.sample(&c), "first sample establishes a baseline");
        c.advance(5_000);
        assert!(!m.sample(&c), "both clocks moved together");
        assert_eq!(m.skew_events(), 0);

        c.advance(1_000);
        c.skew_wall(3_600_000);
        assert!(m.sample(&c), "a one hour wall step must be detected");
        assert_eq!(m.skew_events(), 1);
    }

    #[test]
    fn system_clock_is_monotonic_non_decreasing() {
        let c = SystemClock::new();
        let mut last = c.now_millis();
        for _ in 0..1000 {
            let now = c.now_millis();
            assert!(now >= last, "monotonic clock went backwards");
            last = now;
        }
        assert!(c.wall_millis() > 1_700_000_000_000, "wall clock looks unset");
    }
}
