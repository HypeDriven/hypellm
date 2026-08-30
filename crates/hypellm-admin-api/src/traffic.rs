//! A bounded rolling window of completed requests: rate and latency.
//!
//! Specification 15.3 requires the overview screen to show "request rate,
//! latency, errors, active streams, capacity". The metric registry answers none
//! of those directly. It holds cumulative counters and cumulative histograms —
//! `hypellm_requests_total` since the router started, and a
//! `hypellm_router_overhead_milliseconds` distribution over every request it
//! has ever served. Dividing either by uptime gives the average since boot,
//! which on a router that was busy yesterday and idle now reads as busy. A rate
//! needs a window, and a window has to be measured rather than inferred.
//!
//! This module is that window: a fixed ring of [`SLOTS`] time slots of
//! [`SLOT_MILLIS`] each, written on the completion path and summed on read. It
//! is the same shape as [`crate::UsageAggregate`] and lives beside it for the
//! same reason — the dimensions are known at completion and nowhere later.
//!
//! # Three decisions
//!
//! **It is scoped by tenant.** Appendix B: "management visibility never exceeds
//! the caller's tenant and permissions." A router-wide request rate tells a
//! viewer in one tenant how much traffic every other tenant is sending, which
//! is the same disclosure the overview's tenant count was narrowed to avoid.
//! Each tenant gets its own ring, and a caller is shown theirs. On a
//! single-tenant deployment — the common case — that is the whole router.
//!
//! **Nothing here grows with traffic.** The ring is fixed-size and allocated
//! once per tenant; a slot is recycled by overwriting it, never by allocating.
//! The tenant map is capped at [`MAX_TENANTS`], and a sample belonging to no
//! tracked tenant is counted as unattributed rather than admitted — which the
//! reader is told, because a tenant whose samples were dropped must not be
//! shown a confident zero.
//!
//! **The latency figures are bucket upper bounds, and say so.** Quantiles come
//! from [`hypellm_core::time::LATENCY_BUCKETS_MS`], so a reported p99 of 25 ms
//! means "at or below 25 ms", not "25 ms". Specification 19.1's measured
//! distributions are `hypellm-bench`'s job, against the decision trace's
//! microsecond field; this is the cheap always-on estimate and is labelled as
//! one all the way out to the screen.

use crate::usage::UsageStatus;
use hypellm_core::ids::TenantId;
use hypellm_core::time::LATENCY_BUCKETS_MS;
use std::collections::BTreeMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// How much time one slot covers.
///
/// Ten seconds is the resolution at which a rate stops being noise: a router
/// serving one request a second puts ten samples in a slot, which is enough for
/// the shortest window below to mean something. Finer slots would multiply the
/// per-tenant footprint for a figure nobody reads that closely.
pub const SLOT_MILLIS: u64 = 10_000;

/// How many slots one tenant's ring holds.
pub const SLOTS: usize = 30;

/// The longest window that can be summarised, in milliseconds.
pub const WINDOW_MILLIS: u64 = SLOT_MILLIS * 30;

/// The largest number of tenants tracked at once.
///
/// A tenant is administrator-configured — it arrives from a verified API key or
/// a management session, never from a request field — so this is a bound on the
/// deployment rather than on an attacker. It exists so that a configuration
/// with a pathological number of tenants costs a bounded amount of memory
/// instead of one ring each.
pub const MAX_TENANTS: usize = 64;

/// Bucket count: one per bound in [`LATENCY_BUCKETS_MS`], plus the overflow.
const BUCKETS: usize = 17;
const _: () = assert!(
    BUCKETS == LATENCY_BUCKETS_MS.len() + 1,
    "the bucket array must match the shared latency bounds"
);

/// The largest latency bound a sample can be attributed to.
///
/// A quantile that lands past this is reported as absent rather than as the
/// bound, because "at least two minutes" and "two minutes" are different
/// answers and only one of them is true.
#[must_use]
pub fn largest_bucket_millis() -> u64 {
    LATENCY_BUCKETS_MS.last().copied().unwrap_or(0)
}

/// One completed request, as the window records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSample {
    /// The outcome class, in the same closed vocabulary the usage screen uses.
    pub status: UsageStatus,
    /// Router processing time, excluding upstream time, in milliseconds.
    pub router_millis: u64,
    /// Total upstream exchange time, when a target was reached at all.
    ///
    /// `None` for a request refused before dispatch — no target eligible, over
    /// quota, malformed. Counting those as zero-latency upstream exchanges
    /// would make a router that is refusing everything look like the fastest
    /// one in the fleet.
    pub upstream_millis: Option<u64>,
    /// Input tokens accounted, from either provenance.
    pub input_tokens: u64,
    /// Output tokens accounted, from either provenance.
    pub output_tokens: u64,
}

/// A latency distribution over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencySummary {
    /// How many samples the window holds.
    pub samples: u64,
    /// Arithmetic mean, in milliseconds. `None` when there are no samples.
    pub mean_millis: Option<u64>,
    /// Median, as a bucket upper bound.
    pub p50_millis: Option<u64>,
    /// 90th percentile, as a bucket upper bound.
    pub p90_millis: Option<u64>,
    /// 99th percentile, as a bucket upper bound.
    pub p99_millis: Option<u64>,
    /// Samples above [`largest_bucket_millis`], which no quantile can name.
    pub above_largest_bucket: u64,
}

/// What one window of one tenant's traffic adds up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSummary {
    /// The window that was asked for, in milliseconds.
    pub window_millis: u64,
    /// The span the summed slots actually cover, in milliseconds.
    ///
    /// Less than `window_millis` on a router that has not been up that long,
    /// and never zero. This is the denominator a rate must be computed
    /// against: dividing by the nominal window on a router thirty seconds old
    /// reports a fifth of the traffic it is really taking.
    pub covered_millis: u64,
    /// Whether the router has been observing for the whole window.
    pub complete: bool,
    /// Requests that completed in the window, whatever their outcome.
    pub requests: u64,
    /// Requests refused because of the caller or the policy.
    pub client_errors: u64,
    /// Requests refused for capacity or quota.
    pub throttled: u64,
    /// Requests the router or a provider failed.
    pub server_errors: u64,
    /// Input tokens accounted in the window.
    pub input_tokens: u64,
    /// Output tokens accounted in the window.
    pub output_tokens: u64,
    /// Router overhead, excluding upstream time.
    pub router: LatencySummary,
    /// Upstream exchange time, over the requests that reached a target.
    pub upstream: LatencySummary,
}

impl TrafficSummary {
    /// Requests that completed without an error.
    #[must_use]
    pub const fn successes(&self) -> u64 {
        self.requests
            .saturating_sub(self.client_errors)
            .saturating_sub(self.throttled)
            .saturating_sub(self.server_errors)
    }
}

/// The rolling window.
#[derive(Debug)]
pub struct TrafficWindow {
    /// Monotonic milliseconds at which observation began.
    started_millis: u64,
    /// One ring per tenant, created on that tenant's first completed request.
    rings: RwLock<BTreeMap<TenantId, Ring>>,
    /// Samples dropped because [`MAX_TENANTS`] rings were already in use.
    unattributed: AtomicU64,
}

impl TrafficWindow {
    /// Begin observing at `started_millis`, on the monotonic clock.
    #[must_use]
    pub fn new(started_millis: u64) -> Self {
        Self {
            started_millis,
            rings: RwLock::new(BTreeMap::new()),
            unattributed: AtomicU64::new(0),
        }
    }

    /// Fold one completed request into `tenant`'s ring.
    ///
    /// Silent on a poisoned lock, like every other reporting view in this
    /// crate: losing a dashboard sample is not a reason to fail a request that
    /// has already been served.
    pub fn record(&self, tenant: &TenantId, sample: &TrafficSample, now_millis: u64) {
        let interval = interval_of(now_millis);
        let Ok(mut rings) = self.rings.write() else {
            return;
        };
        if !rings.contains_key(tenant) && rings.len() >= MAX_TENANTS {
            self.unattributed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let ring = rings.entry(tenant.clone()).or_insert_with(Ring::empty);
        let Some(slot) = ring.slot_mut(interval) else {
            return;
        };
        slot.requests = slot.requests.saturating_add(1);
        match sample.status {
            UsageStatus::Success => {}
            UsageStatus::ClientError => {
                slot.client_errors = slot.client_errors.saturating_add(1);
            }
            UsageStatus::Throttled => slot.throttled = slot.throttled.saturating_add(1),
            UsageStatus::ServerError => {
                slot.server_errors = slot.server_errors.saturating_add(1);
            }
        }
        slot.input_tokens = slot.input_tokens.saturating_add(sample.input_tokens);
        slot.output_tokens = slot.output_tokens.saturating_add(sample.output_tokens);
        slot.router.observe(sample.router_millis);
        if let Some(upstream) = sample.upstream_millis {
            slot.upstream.observe(upstream);
        }
    }

    /// Sum `tenant`'s traffic over the `window_millis` ending now.
    ///
    /// `None` means the tenant is not being attributed — [`MAX_TENANTS`] rings
    /// were already in use when it first appeared — which is a different fact
    /// from "no traffic" and must not be rendered as a zero. A tenant that
    /// simply has not been asked for anything gets an empty summary.
    ///
    /// `window_millis` is clamped into `[SLOT_MILLIS, WINDOW_MILLIS]`. It is
    /// the only figure a caller influences and the ring is fixed either way,
    /// so no request can widen what the window holds.
    #[must_use]
    pub fn summary(
        &self,
        tenant: &TenantId,
        window_millis: u64,
        now_millis: u64,
    ) -> Option<TrafficSummary> {
        let slots = slots_for(window_millis);
        let newest = interval_of(now_millis);

        let totals = {
            let rings = self.rings.read().ok()?;
            match rings.get(tenant) {
                Some(ring) => ring.sum(newest, slots),
                None if rings.len() >= MAX_TENANTS => return None,
                None => Totals::default(),
            }
        };

        let spanned = spanned_millis(now_millis, slots);
        let observed = now_millis.saturating_sub(self.started_millis).max(1);
        let covered = spanned.min(observed);
        Some(TrafficSummary {
            window_millis: nominal_millis(slots),
            covered_millis: covered,
            complete: spanned <= observed,
            requests: totals.requests,
            client_errors: totals.client_errors,
            throttled: totals.throttled,
            server_errors: totals.server_errors,
            input_tokens: totals.input_tokens,
            output_tokens: totals.output_tokens,
            router: totals.router.summarize(),
            upstream: totals.upstream.summarize(),
        })
    }

    /// How many tenants currently hold a ring.
    #[must_use]
    pub fn tenants_tracked(&self) -> usize {
        self.rings.read().map_or(0, |rings| rings.len())
    }

    /// Samples dropped because every ring was already in use.
    ///
    /// Reported rather than hidden: it is the only signal that a tenant's
    /// figures are missing rather than idle.
    #[must_use]
    pub fn unattributed_samples(&self) -> u64 {
        self.unattributed.load(Ordering::Relaxed)
    }
}

impl Default for TrafficWindow {
    /// A window that began observing at monotonic zero, which is process start.
    fn default() -> Self {
        Self::new(0)
    }
}

/// The slot index a monotonic instant falls in.
#[allow(
    clippy::integer_division,
    reason = "flooring to the enclosing slot is the definition of the index; \
              a remainder would name no slot"
)]
const fn interval_of(now_millis: u64) -> u64 {
    now_millis / SLOT_MILLIS
}

/// How many slots a requested window covers, clamped to what the ring holds.
fn slots_for(window_millis: u64) -> usize {
    let clamped = window_millis.clamp(SLOT_MILLIS, WINDOW_MILLIS);
    let slots = clamped.div_ceil(SLOT_MILLIS);
    usize::try_from(slots).unwrap_or(SLOTS).clamp(1, SLOTS)
}

/// The nominal length of a window of `slots` slots.
fn nominal_millis(slots: usize) -> u64 {
    u64::try_from(slots)
        .unwrap_or(0)
        .saturating_mul(SLOT_MILLIS)
}

/// The real time the summed slots span, ending at `now_millis` inclusive.
///
/// Exact rather than nominal. The oldest slot began at the top of its interval
/// and the newest is however far into its own, so a "one minute" window read
/// two seconds into a slot covers fifty-two seconds — and a rate computed
/// against sixty would understate the router by a seventh.
fn spanned_millis(now_millis: u64, slots: usize) -> u64 {
    let whole = u64::try_from(slots.saturating_sub(1))
        .unwrap_or(0)
        .saturating_mul(SLOT_MILLIS);
    let into_current = now_millis.saturating_sub(interval_of(now_millis).saturating_mul(SLOT_MILLIS));
    whole.saturating_add(into_current).saturating_add(1)
}

/// A latency distribution being accumulated.
#[derive(Debug, Clone, Copy)]
struct Latency {
    counts: [u64; BUCKETS],
    samples: u64,
    sum: u64,
}

impl Latency {
    const EMPTY: Self = Self {
        counts: [0; BUCKETS],
        samples: 0,
        sum: 0,
    };

    fn observe(&mut self, millis: u64) {
        let index = LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        if let Some(count) = self.counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
        self.samples = self.samples.saturating_add(1);
        self.sum = self.sum.saturating_add(millis);
    }

    fn merge(&mut self, other: &Self) {
        for (into, from) in self.counts.iter_mut().zip(other.counts.iter()) {
            *into = into.saturating_add(*from);
        }
        self.samples = self.samples.saturating_add(other.samples);
        self.sum = self.sum.saturating_add(other.sum);
    }

    /// The bucket upper bound at or below which `num/den` of samples fall.
    ///
    /// `None` when the quantile lands in the overflow bucket, which has no
    /// upper bound to report.
    fn quantile(&self, num: u64, den: u64) -> Option<u64> {
        if self.samples == 0 || den == 0 {
            return None;
        }
        let threshold = self.samples.saturating_mul(num).div_ceil(den);
        let mut cumulative = 0u64;
        for (index, count) in self.counts.iter().enumerate() {
            cumulative = cumulative.saturating_add(*count);
            if cumulative >= threshold {
                return LATENCY_BUCKETS_MS.get(index).copied();
            }
        }
        None
    }

    #[allow(
        clippy::integer_division,
        reason = "a mean in whole milliseconds; the series it summarises is \
                  itself bucketed to the millisecond"
    )]
    fn summarize(&self) -> LatencySummary {
        let mean = (self.samples > 0).then(|| self.sum / self.samples);
        LatencySummary {
            samples: self.samples,
            mean_millis: mean,
            p50_millis: self.quantile(50, 100),
            p90_millis: self.quantile(90, 100),
            p99_millis: self.quantile(99, 100),
            above_largest_bucket: self.counts.last().copied().unwrap_or(0),
        }
    }
}

/// One slot of one tenant's ring.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// Which interval this slot holds, or `None` if it has never been written.
    ///
    /// Carried in the slot rather than derived from its position, because a
    /// ring position is reused every [`WINDOW_MILLIS`] and the interval is the
    /// only thing that distinguishes this minute's traffic from last hour's.
    interval: Option<u64>,
    requests: u64,
    client_errors: u64,
    throttled: u64,
    server_errors: u64,
    input_tokens: u64,
    output_tokens: u64,
    router: Latency,
    upstream: Latency,
}

impl Slot {
    const EMPTY: Self = Self {
        interval: None,
        requests: 0,
        client_errors: 0,
        throttled: 0,
        server_errors: 0,
        input_tokens: 0,
        output_tokens: 0,
        router: Latency::EMPTY,
        upstream: Latency::EMPTY,
    };
}

/// One tenant's fixed ring.
#[derive(Debug)]
struct Ring {
    slots: [Slot; SLOTS],
}

impl Ring {
    fn empty() -> Self {
        Self {
            slots: [Slot::EMPTY; SLOTS],
        }
    }

    /// The slot for `interval`, recycled if it currently holds an older one.
    fn slot_mut(&mut self, interval: u64) -> Option<&mut Slot> {
        let ring_len = u64::try_from(SLOTS).ok()?;
        let position = usize::try_from(interval % ring_len).ok()?;
        let slot = self.slots.get_mut(position)?;
        if slot.interval != Some(interval) {
            *slot = Slot::EMPTY;
            slot.interval = Some(interval);
        }
        Some(slot)
    }

    /// Sum the `count` intervals ending at `newest`, inclusive.
    ///
    /// Filtered on the interval each slot claims rather than on its position,
    /// so a slot holding traffic from before the window — the ring has not
    /// wrapped past it yet — contributes nothing instead of being counted as
    /// current.
    fn sum(&self, newest: u64, count: usize) -> Totals {
        let span = u64::try_from(count.saturating_sub(1)).unwrap_or(0);
        let oldest = newest.saturating_sub(span);
        let mut totals = Totals::default();
        for slot in &self.slots {
            let Some(interval) = slot.interval else {
                continue;
            };
            if interval < oldest || interval > newest {
                continue;
            }
            totals.add(slot);
        }
        totals
    }
}

/// The running sum of a set of slots.
#[derive(Debug, Clone, Copy)]
struct Totals {
    requests: u64,
    client_errors: u64,
    throttled: u64,
    server_errors: u64,
    input_tokens: u64,
    output_tokens: u64,
    router: Latency,
    upstream: Latency,
}

impl Default for Totals {
    fn default() -> Self {
        Self {
            requests: 0,
            client_errors: 0,
            throttled: 0,
            server_errors: 0,
            input_tokens: 0,
            output_tokens: 0,
            router: Latency::EMPTY,
            upstream: Latency::EMPTY,
        }
    }
}

impl Totals {
    fn add(&mut self, slot: &Slot) {
        self.requests = self.requests.saturating_add(slot.requests);
        self.client_errors = self.client_errors.saturating_add(slot.client_errors);
        self.throttled = self.throttled.saturating_add(slot.throttled);
        self.server_errors = self.server_errors.saturating_add(slot.server_errors);
        self.input_tokens = self.input_tokens.saturating_add(slot.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(slot.output_tokens);
        self.router.merge(&slot.router);
        self.upstream.merge(&slot.upstream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("tenant identifier")
    }

    fn sample(status: UsageStatus, router_ms: u64, upstream_ms: Option<u64>) -> TrafficSample {
        TrafficSample {
            status,
            router_millis: router_ms,
            upstream_millis: upstream_ms,
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    #[test]
    fn a_sample_older_than_the_window_is_not_counted_in_it() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), 0);

        // Still inside a one-minute window.
        let near = window
            .summary(&acme, 60_000, 30_000)
            .expect("acme is tracked");
        assert_eq!(near.requests, 1);

        // Ninety seconds later the sample has fallen out of the same window,
        // even though the ring still physically holds it.
        let far = window
            .summary(&acme, 60_000, 90_000)
            .expect("acme is tracked");
        assert_eq!(far.requests, 0, "a stale slot must not be summed");
    }

    #[test]
    fn a_recycled_slot_does_not_carry_the_traffic_it_replaced() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), 5_000);

        // Exactly one full ring later: the same position, a different interval.
        let later = WINDOW_MILLIS + 5_000;
        window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), later);

        let summary = window
            .summary(&acme, WINDOW_MILLIS, later)
            .expect("acme is tracked");
        assert_eq!(
            summary.requests, 1,
            "the wrapped slot must be overwritten, not added to"
        );
    }

    #[test]
    fn the_covered_span_never_exceeds_how_long_the_router_has_been_observing() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), 4_000);

        let summary = window
            .summary(&acme, 300_000, 4_000)
            .expect("acme is tracked");
        assert_eq!(summary.covered_millis, 4_000);
        assert!(!summary.complete, "four seconds is not five minutes");
    }

    #[test]
    fn a_full_window_reports_the_span_it_actually_covers() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        // Six slots back plus two seconds into the current one.
        let now = 6 * SLOT_MILLIS + 2_000;
        window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), now);

        let summary = window.summary(&acme, 60_000, now).expect("acme is tracked");
        assert_eq!(summary.window_millis, 60_000);
        // Five whole slots behind the current one, plus the 2 000 ms elapsed in
        // it, plus the millisecond `now` itself falls in.
        assert_eq!(summary.covered_millis, 5 * SLOT_MILLIS + 2_001);
        assert!(summary.complete);
    }

    #[test]
    fn outcomes_are_counted_in_their_own_classes() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        for status in [
            UsageStatus::Success,
            UsageStatus::Success,
            UsageStatus::ClientError,
            UsageStatus::Throttled,
            UsageStatus::ServerError,
        ] {
            window.record(&acme, &sample(status, 1, Some(10)), 1_000);
        }

        let summary = window
            .summary(&acme, 60_000, 1_000)
            .expect("acme is tracked");
        assert_eq!(summary.requests, 5);
        assert_eq!(summary.client_errors, 1);
        assert_eq!(summary.throttled, 1);
        assert_eq!(summary.server_errors, 1);
        assert_eq!(summary.successes(), 2);
    }

    #[test]
    fn a_request_that_reached_no_target_records_no_upstream_latency() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        window.record(&acme, &sample(UsageStatus::Throttled, 2, None), 1_000);

        let summary = window
            .summary(&acme, 60_000, 1_000)
            .expect("acme is tracked");
        assert_eq!(summary.requests, 1);
        assert_eq!(summary.router.samples, 1);
        assert_eq!(
            summary.upstream.samples, 0,
            "a refusal is not a fast upstream exchange"
        );
        assert_eq!(summary.upstream.p50_millis, None);
    }

    #[test]
    fn a_quantile_is_the_bucket_upper_bound_not_the_sample() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        // Every sample is 3 ms, which falls in the (2, 5] bucket.
        for _ in 0..100 {
            window.record(&acme, &sample(UsageStatus::Success, 3, Some(3)), 1_000);
        }

        let summary = window
            .summary(&acme, 60_000, 1_000)
            .expect("acme is tracked");
        assert_eq!(summary.router.p50_millis, Some(5));
        assert_eq!(summary.router.p99_millis, Some(5));
        assert_eq!(summary.router.mean_millis, Some(3));
    }

    #[test]
    fn a_quantile_past_the_largest_bucket_is_absent_rather_than_clamped() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        for _ in 0..10 {
            window.record(
                &acme,
                &sample(UsageStatus::Success, largest_bucket_millis() + 1, None),
                1_000,
            );
        }

        let summary = window
            .summary(&acme, 60_000, 1_000)
            .expect("acme is tracked");
        assert_eq!(
            summary.router.p50_millis, None,
            "the overflow bucket has no upper bound to report"
        );
        assert_eq!(summary.router.above_largest_bucket, 10);
    }

    #[test]
    fn one_tenants_traffic_never_appears_in_another_tenants_window() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        let other = tenant("beta");
        for _ in 0..7 {
            window.record(&acme, &sample(UsageStatus::Success, 1, Some(10)), 1_000);
        }

        let theirs = window
            .summary(&other, 60_000, 1_000)
            .expect("an untouched tenant is idle, not unattributed");
        assert_eq!(theirs.requests, 0);
        assert_eq!(window.summary(&acme, 60_000, 1_000).map(|s| s.requests), Some(7));
    }

    #[test]
    fn a_tenant_past_the_cap_is_reported_as_unattributed_not_as_idle() {
        let window = TrafficWindow::new(0);
        for index in 0..MAX_TENANTS {
            let id = tenant(&format!("tenant-{index}"));
            window.record(&id, &sample(UsageStatus::Success, 1, Some(10)), 1_000);
        }
        assert_eq!(window.tenants_tracked(), MAX_TENANTS);

        let overflowing = tenant("one-too-many");
        window.record(&overflowing, &sample(UsageStatus::Success, 1, Some(10)), 1_000);

        assert_eq!(window.tenants_tracked(), MAX_TENANTS, "the map is bounded");
        assert_eq!(window.unattributed_samples(), 1);
        assert_eq!(
            window.summary(&overflowing, 60_000, 1_000),
            None,
            "a dropped tenant must not be shown a confident zero"
        );
    }

    #[test]
    fn a_requested_window_wider_than_the_ring_is_clamped_to_the_ring() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        let summary = window
            .summary(&acme, u64::MAX, WINDOW_MILLIS)
            .expect("acme is tracked");
        assert_eq!(summary.window_millis, WINDOW_MILLIS);
    }

    #[test]
    fn a_requested_window_narrower_than_a_slot_is_one_slot() {
        let window = TrafficWindow::new(0);
        let acme = tenant("acme");
        let summary = window.summary(&acme, 0, SLOT_MILLIS).expect("acme is tracked");
        assert_eq!(summary.window_millis, SLOT_MILLIS);
    }
}
