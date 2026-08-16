//! Sorted-sample distribution summaries.
//!
//! Specification 21 (`Performance`) requires benchmarks to "report
//! distributions, not averages", and specification 19 states the router
//! overhead target as a pair of quantiles — p50 < 2 ms, p99 < 10 ms. A mean
//! cannot answer either question: the arithmetic mean of a latency series is
//! dominated by the tail when the tail is bad and hides the tail when the bulk
//! is good, and there is no mean that a p99 target can be checked against.
//!
//! # Why sorted samples rather than buckets
//!
//! `hypellm_core::time::Histogram` is the right structure for the always-on
//! metrics path: constant memory, no allocation per observation, safe to feed
//! from a request. It reports a bucket *bound*, not a value. With the
//! millisecond bucket set the router publishes, every sample inside the
//! specification 19 budget lands in the first bucket, so the histogram can
//! never distinguish a healthy p99 from one at nine times the p50.
//!
//! A benchmark runs offline, on a fixed and known iteration count, and wants
//! the exact order statistic. So this module keeps every sample, sorts once,
//! and indexes. The cost is memory proportional to the sample count, which is
//! why [`Samples`] is capacity-bounded at construction and counts what it drops
//! rather than growing (specification 18.2: no unbounded buffer).

use core::fmt;

/// A bounded collection of microsecond samples.
///
/// Samples beyond `capacity` are counted in [`Distribution::overflowed`] and
/// discarded. A harness that silently kept growing would make a benchmark of a
//  long soak run indistinguishable from a memory leak.
#[derive(Debug)]
pub struct Samples {
    label: &'static str,
    unit: Unit,
    values: Vec<u64>,
    capacity: usize,
    overflowed: u64,
}

/// What a sample counts.
///
/// Carried so a report cannot present microseconds under a millisecond heading;
/// the two differ by a factor of a thousand and every specification 19 target
/// is written in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Microseconds.
    Micros,
    /// A dimensionless count, such as events per stream.
    Count,
}

impl Unit {
    /// The suffix used when rendering a value.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Micros => "us",
            Self::Count => "",
        }
    }
}

/// The largest number of samples any one series retains.
///
/// 1,048,576 `u64` values is 8 MiB — enough for a long open-loop run, small
/// enough that a mistaken iteration count fails as a truncated report rather
/// than as an out-of-memory kill.
pub const MAX_SAMPLES: usize = 1 << 20;

impl Samples {
    /// Create a series that retains up to `capacity` samples.
    ///
    /// `capacity` is clamped to [`MAX_SAMPLES`].
    #[must_use]
    pub fn new(label: &'static str, unit: Unit, capacity: usize) -> Self {
        let capacity = capacity.min(MAX_SAMPLES);
        Self {
            label,
            unit,
            values: Vec::with_capacity(capacity),
            capacity,
            overflowed: 0,
        }
    }

    /// Record one sample.
    pub fn push(&mut self, value: u64) {
        if self.values.len() >= self.capacity {
            self.overflowed = self.overflowed.saturating_add(1);
            return;
        }
        self.values.push(value);
    }

    /// How many samples are retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Sort and summarise. Consumes the samples, because the sort is in place
    /// and a second summary of the same series would re-sort sorted data and
    /// look cheaper than the first.
    #[must_use]
    pub fn summarize(mut self) -> Distribution {
        self.values.sort_unstable();
        let count = u64::try_from(self.values.len()).unwrap_or(u64::MAX);
        let sum: u64 = self.values.iter().copied().fold(0u64, u64::saturating_add);
        Distribution {
            label: self.label,
            unit: self.unit,
            count,
            overflowed: self.overflowed,
            min: self.values.first().copied().unwrap_or(0),
            max: self.values.last().copied().unwrap_or(0),
            p50: nearest_rank(&self.values, 500, 1000),
            p90: nearest_rank(&self.values, 900, 1000),
            p99: nearest_rank(&self.values, 990, 1000),
            p999: nearest_rank(&self.values, 999, 1000),
            sum,
        }
    }
}

/// The order statistic at `num / den`, by the nearest-rank definition.
///
/// Rank is rounded *up*: the q-quantile is the smallest value at or below which
/// at least a q fraction of samples fall. Rounding down would report the p99.9
/// of a hundred samples as the 99th, which is the one sample a tail target
/// exists to catch. This matches `Histogram::quantile_upper_bound` in
/// `hypellm-core`, deliberately: two quantile definitions in one codebase produce
/// two answers for the same data and an argument about which is real.
///
/// No interpolation. An interpolated quantile invents a value that was never
/// observed, and a latency report should only contain measurements.
fn nearest_rank(sorted: &[u64], num: u64, den: u64) -> u64 {
    if sorted.is_empty() || den == 0 {
        return 0;
    }
    let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
    let rank = count.saturating_mul(num).div_ceil(den).max(1);
    let index = usize::try_from(rank.saturating_sub(1)).unwrap_or(0);
    sorted.get(index.min(sorted.len().saturating_sub(1))).copied().unwrap_or(0)
}

/// A summarised series.
#[derive(Debug, Clone)]
pub struct Distribution {
    /// What was measured.
    pub label: &'static str,
    /// What the numbers count.
    pub unit: Unit,
    /// Retained sample count.
    pub count: u64,
    /// Samples discarded because the series was full.
    pub overflowed: u64,
    /// Smallest sample.
    pub min: u64,
    /// Largest sample.
    pub max: u64,
    /// Median.
    pub p50: u64,
    /// 90th percentile.
    pub p90: u64,
    /// 99th percentile.
    pub p99: u64,
    /// 99.9th percentile.
    pub p999: u64,
    /// Sum of all retained samples.
    pub sum: u64,
}

impl Distribution {
    /// The arithmetic mean.
    ///
    /// Deliberately not a field, and never rendered on its own: it exists so a
    /// reader can see how far the median sits from it, which is the cheapest
    /// signal that a series is skewed. Reporting it alone is the thing
    /// specification 21 forbids.
    /// Truncating division is intended: every sample is a whole microsecond (or
    /// a whole event), so a fractional mean would claim a resolution the clock
    /// does not have. `checked_div` rather than `/` so an empty series is
    /// handled by the type rather than by a guard a later edit could drop.
    #[must_use]
    pub fn mean(&self) -> u64 {
        self.sum.checked_div(self.count).unwrap_or(0)
    }

    /// A fixed-width row for the report table.
    #[must_use]
    pub fn row(&self) -> String {
        format!(
            "{:<26} {:>9} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            self.label,
            self.count,
            self.min,
            self.p50,
            self.p90,
            self.p99,
            self.p999,
            self.max,
            self.mean(),
        )
    }

    /// The header matching [`Distribution::row`].
    #[must_use]
    pub fn header() -> String {
        format!(
            "{:<26} {:>9} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "series", "n", "min", "p50", "p90", "p99", "p99.9", "max", "mean",
        )
    }
}

impl fmt::Display for Distribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.row())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(values: &[u64]) -> Distribution {
        let mut s = Samples::new("t", Unit::Micros, values.len().max(1));
        for v in values {
            s.push(*v);
        }
        s.summarize()
    }

    #[test]
    fn quantiles_of_a_known_series_are_exact() {
        // 1..=100, so the k-th percentile is exactly k.
        let values: Vec<u64> = (1..=100).collect();
        let d = series(&values);
        assert_eq!(d.count, 100);
        assert_eq!(d.min, 1);
        assert_eq!(d.max, 100);
        assert_eq!(d.p50, 50);
        assert_eq!(d.p90, 90);
        assert_eq!(d.p99, 99);
        // Nearest-rank rounds up, so p99.9 of 100 samples is the largest.
        assert_eq!(d.p999, 100);
    }

    #[test]
    fn input_order_does_not_change_the_summary() {
        let ascending: Vec<u64> = (1..=100).collect();
        let mut descending = ascending.clone();
        descending.reverse();
        let a = series(&ascending);
        let b = series(&descending);
        assert_eq!((a.p50, a.p99, a.min, a.max), (b.p50, b.p99, b.min, b.max));
    }

    #[test]
    fn a_tail_the_mean_hides_is_visible_in_the_quantiles() {
        // The failure mode the "distributions, not averages" rule exists for:
        // 998 samples at 100 us and two at 100 ms average to well under the
        // 2 ms p50 target, while the p99.9 is ten times over the 10 ms one.
        let mut values = vec![100u64; 998];
        values.push(100_000);
        values.push(100_000);
        let d = series(&values);
        assert!(d.mean() < 2_000, "the mean is {} us", d.mean());
        assert_eq!(d.p50, 100, "the bulk looks healthy");
        assert_eq!(d.p99, 100, "and so does the p99");
        assert_eq!(d.p999, 100_000, "the outliers must surface in the tail");
        assert_eq!(d.max, 100_000);
    }

    #[test]
    fn a_single_sample_is_every_quantile() {
        let d = series(&[7]);
        assert_eq!((d.count, d.min, d.p50, d.p99, d.p999, d.max), (1, 7, 7, 7, 7, 7));
    }

    #[test]
    fn an_empty_series_reports_zeroes_rather_than_panicking() {
        let d = Samples::new("t", Unit::Micros, 8).summarize();
        assert_eq!(d.count, 0);
        assert_eq!(d.p50, 0);
        assert_eq!(d.mean(), 0);
    }

    #[test]
    fn capacity_is_a_hard_bound_and_overflow_is_reported() {
        let mut s = Samples::new("t", Unit::Micros, 4);
        for v in 0..100u64 {
            s.push(v);
        }
        assert_eq!(s.len(), 4);
        let d = s.summarize();
        assert_eq!(d.count, 4);
        assert_eq!(d.overflowed, 96, "dropped samples must be counted, not hidden");
    }

    #[test]
    fn capacity_is_clamped_to_the_module_maximum() {
        let s = Samples::new("t", Unit::Micros, usize::MAX);
        assert_eq!(s.capacity, MAX_SAMPLES);
    }

    #[test]
    fn the_report_row_lines_up_with_its_header() {
        let d = series(&[1, 2, 3]);
        let header = Distribution::header();
        let row = d.row();
        assert_eq!(
            header.len(),
            row.len(),
            "header and row must be the same width\n{header}\n{row}"
        );
    }
}
