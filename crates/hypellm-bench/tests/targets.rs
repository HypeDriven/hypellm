//! The performance regression tripwire.
//!
//! Specification 2.3 makes performance a release acceptance gate and
//! specification 19 states the numbers: warm router overhead p50 < 2 ms,
//! p99 < 10 ms, at 70% rated load, excluding edge/provider network.
//!
//! # These thresholds are NOT the specification's targets
//!
//! Read this before changing a number below.
//!
//! The specification's figures apply to a release build, on known production
//! hardware, at 70% of rated load, with a real policy and real providers. This
//! file satisfies none of those conditions:
//!
//! - `cargo test` builds the **debug** profile unless told otherwise, which is
//!   several times slower than the release binary the specification describes.
//! - CI runners are shared, oversubscribed, and throttled; a p99 there measures
//!   the neighbours as much as the router.
//! - The scenarios are closed-loop and unloaded, so "at 70% rated load" is not
//!   exercised at all.
//! - The fixture policy has one alias over one target, which is the cheapest
//!   possible routing decision.
//!
//! So the constants here are a **tripwire**: deliberately far above what the
//! code does today and far below the specification's target, positioned to
//! catch a change that moves router overhead by orders of magnitude — an
//! accidental allocation per candidate, a lock on the routing path, a linear
//! scan turned quadratic — while never failing because a runner was busy.
//!
//! Passing this test is evidence of no gross regression. It is **not** evidence
//! that the specification 19 target is met. That claim requires
//! `cargo run --release -p hypellm-bench` on the target hardware under load, and
//! the retained result specification 21.1 asks for.

use hypellm_bench::distribution::Distribution;
use hypellm_bench::report::{TARGET_P50_MICROS, TARGET_P99_MICROS};
use hypellm_bench::scenarios::{self, Plan, ScenarioReport};

/// Tripwire median, in microseconds: half of specification 19's 2 ms target.
///
/// For calibration, on an unloaded development machine at the time of writing:
/// release `router_overhead` p50 was about 6 µs, debug about 45 µs. So this
/// leaves roughly 20x headroom over the profile `cargo test` actually builds,
/// which absorbs a throttled shared runner, and still trips at half the
/// specification's number rather than at it.
const TRIPWIRE_P50_MICROS: u64 = 1_000;

/// Tripwire tail, in microseconds: half of specification 19's 10 ms target.
///
/// Same calibration: release p99 about 9 µs, debug about 105 µs. The tail is the
/// noisier of the two on a shared runner — one descheduled iteration moves it —
/// so it gets the larger absolute allowance.
const TRIPWIRE_P99_MICROS: u64 = 5_000;

/// Small enough to keep the suite fast, large enough for a p99 to mean
/// something. 200 samples put the p99 at the 198th value, so it is a real order
/// statistic rather than a synonym for the maximum.
fn plan(iterations: usize) -> Plan {
    Plan {
        iterations,
        warmup: iterations / 4,
    }
}

/// Check one scenario against the tripwire and against internal consistency.
fn assert_within_tripwire(report: &ScenarioReport, series_label: &str) {
    assert_eq!(
        report.failures, 0,
        "{}: {} iteration(s) failed, so the samples are the error path, not the router",
        report.name, report.failures
    );

    let series = report
        .series(series_label)
        .unwrap_or_else(|| panic!("{} has no `{series_label}` series", report.name));

    assert!(series.count > 0, "{}: no samples", report.name);
    assert_eq!(
        series.overflowed, 0,
        "{}: samples were dropped, so the quantiles are of a truncated series",
        report.name
    );

    // Order statistics must be monotone. A violation means the summary is
    // wrong, which would make every threshold below meaningless.
    assert!(series.min <= series.p50, "{}: min > p50", report.name);
    assert!(series.p50 <= series.p90, "{}: p50 > p90", report.name);
    assert!(series.p90 <= series.p99, "{}: p90 > p99", report.name);
    assert!(series.p99 <= series.p999, "{}: p99 > p99.9", report.name);
    assert!(series.p999 <= series.max, "{}: p99.9 > max", report.name);

    assert!(
        series.p50 < TRIPWIRE_P50_MICROS,
        "{}/{series_label} p50 is {} us, over the {TRIPWIRE_P50_MICROS} us tripwire \
         (specification 19 target is {TARGET_P50_MICROS} us on release hardware). \
         Full distribution:\n{}\n{}",
        report.name,
        series.p50,
        Distribution::header(),
        series.row()
    );
    assert!(
        series.p99 < TRIPWIRE_P99_MICROS,
        "{}/{series_label} p99 is {} us, over the {TRIPWIRE_P99_MICROS} us tripwire \
         (specification 19 target is {TARGET_P99_MICROS} us on release hardware). \
         Full distribution:\n{}\n{}",
        report.name,
        series.p99,
        Distribution::header(),
        series.row()
    );
}

#[test]
fn the_routing_decision_stays_far_under_the_target() {
    let report = scenarios::routing_decision(plan(2_000));
    assert_within_tripwire(&report, "route");
}

#[test]
fn non_streaming_router_overhead_stays_far_under_the_target() {
    let report = scenarios::chat_non_streaming(plan(200));
    assert_within_tripwire(&report, "router_overhead");
}

#[test]
fn streaming_router_overhead_stays_far_under_the_target() {
    let report = scenarios::chat_streaming(plan(200));
    assert_within_tripwire(&report, "router_overhead");
}

#[test]
fn the_tripwire_sits_below_the_specification_target() {
    // The relationship the comment above asserts, stated as a test so that
    // raising a tripwire past the specification's own number — which would make
    // this suite green while the release gate failed — is a build failure.
    assert!(
        TRIPWIRE_P50_MICROS < TARGET_P50_MICROS,
        "a tripwire at or above the specification target cannot protect it"
    );
    assert!(
        TRIPWIRE_P99_MICROS < TARGET_P99_MICROS,
        "a tripwire at or above the specification target cannot protect it"
    );
}

#[test]
fn end_to_end_latency_is_reported_but_not_asserted_on() {
    // `pipeline_total` includes the loopback upstream, so it measures the
    // machine's socket path as much as the router. It is in the report because
    // specification 19.1 asks for the direct-versus-routed comparison, and it is
    // deliberately not a gate: making it one would turn a busy runner into a
    // performance regression.
    let report = scenarios::chat_non_streaming(plan(100));
    assert_eq!(report.failures, 0);

    let total = report.series("pipeline_total").expect("a total series");
    let direct = report.series("upstream_direct").expect("a direct series");
    let overhead = report.series("router_overhead").expect("an overhead series");

    assert!(total.count > 0 && direct.count > 0);
    assert!(
        overhead.p50 <= total.p50,
        "the overhead cannot exceed the end-to-end time that contains it: \
         overhead p50 {} us, total p50 {} us",
        overhead.p50,
        total.p50
    );
}

#[test]
fn every_scenario_reports_a_distribution_and_not_a_single_number() {
    // Specification 21: "benchmarks report distributions, not averages." The
    // gate is structural — a report that lost its quantiles would still print,
    // and a reader would have no way to tell.
    for report in scenarios::all(100) {
        for series in &report.series {
            let row = series.row();
            let fields: Vec<&str> = row.split_whitespace().collect();
            assert!(
                fields.len() >= 9,
                "{}/{} rendered {} fields; a distribution row needs label, n, min, \
                 four quantiles, max, and mean: {row}",
                report.name,
                series.label,
                fields.len()
            );
        }
    }
}
