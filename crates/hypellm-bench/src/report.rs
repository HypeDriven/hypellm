//! Rendering a run as text.
//!
//! Specification 21.1 requires benchmark results to be retained with the
//! release artifact, so the output is plain text with fixed column widths: it
//! diffs cleanly between runs, needs no viewer, and cannot be mistaken for a
//! machine-readable format that something downstream might start parsing.
//!
//! The rendering rule this module enforces is that no series is ever printed as
//! a single number. Every row carries `n`, `min`, four quantiles, `max`, and the
//! mean together (specification 21: "report distributions, not averages"), and
//! the targets block states what was compared against what.

use crate::distribution::Distribution;
use crate::scenarios::ScenarioReport;

/// Specification 19's median target for router overhead, in microseconds.
pub const TARGET_P50_MICROS: u64 = 2_000;

/// Specification 19's tail target for router overhead, in microseconds.
pub const TARGET_P99_MICROS: u64 = 10_000;

/// The series each scenario is judged on.
///
/// Named once so the report, the binary, and the regression test cannot drift
/// into judging different numbers.
pub const JUDGED_SERIES: &str = "router_overhead";

/// The series the decision-only scenario is judged on.
pub const JUDGED_SERIES_DECISION: &str = "route";

/// Render one scenario.
#[must_use]
pub fn render_scenario(report: &ScenarioReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("## {}\n", report.name));
    out.push_str(&format!("{}\n\n", report.what));
    out.push_str("all values in microseconds unless the series says otherwise\n\n");
    out.push_str(&Distribution::header());
    out.push('\n');
    for series in &report.series {
        out.push_str(&series.row());
        out.push('\n');
    }
    out.push('\n');
    if report.failures > 0 {
        out.push_str(&format!(
            "!! {} iteration(s) did not complete; the samples below exclude them,\n\
             !! and any nonzero count here invalidates the run.\n\n",
            report.failures
        ));
    }
    let overflowed: u64 = report.series.iter().map(|s| s.overflowed).sum();
    if overflowed > 0 {
        out.push_str(&format!(
            "!! {overflowed} sample(s) were discarded because a series hit its capacity.\n\n"
        ));
    }
    for note in &report.notes {
        out.push_str("note: ");
        out.push_str(note);
        out.push('\n');
    }
    out
}

/// Render the specification 19 verdict for a run.
///
/// The verdict is advisory in this output: the machine it ran on is unknown, and
/// specification 19 qualifies its target with "at 70% rated load", which this
/// harness does not generate. It says what was measured and how it compares, and
/// leaves the acceptance decision to whoever knows the hardware.
#[must_use]
pub fn render_targets(reports: &[ScenarioReport]) -> String {
    let mut out = String::new();
    out.push_str("## specification 19 targets\n\n");
    out.push_str("p50 < 2000 us, p99 < 10000 us, warm, excluding edge/provider network.\n");
    out.push_str(
        "This run is closed-loop and unloaded, so the specification's \"at 70% rated\n\
         load\" qualifier is NOT satisfied. Read the verdict as a smoke test.\n\n",
    );
    out.push_str(&format!(
        "{:<26} {:>10} {:>10} {:>10}\n",
        "scenario", "p50", "p99", "verdict"
    ));
    for report in reports {
        let label = if report.name == "routing_decision" {
            JUDGED_SERIES_DECISION
        } else {
            JUDGED_SERIES
        };
        let Some(series) = report.series(label) else {
            out.push_str(&format!(
                "{:<26} {:>10} {:>10} {:>10}\n",
                report.name, "-", "-", "MISSING"
            ));
            continue;
        };
        let verdict = if report.failures > 0 {
            "INVALID"
        } else if series.p50 < TARGET_P50_MICROS && series.p99 < TARGET_P99_MICROS {
            "within"
        } else {
            "OVER"
        };
        out.push_str(&format!(
            "{:<26} {:>10} {:>10} {:>10}\n",
            report.name, series.p50, series.p99, verdict
        ));
    }
    out
}

/// Render a whole run.
#[must_use]
pub fn render_run(reports: &[ScenarioReport]) -> String {
    let mut out = String::new();
    out.push_str("# hypellm-bench\n\n");
    out.push_str(
        "Router overhead is the work the router does on its own behalf: alias\n\
         resolution, eligibility, ranking, and protocol translation. It excludes\n\
         the provider, which is a fake in-process upstream here.\n\n",
    );
    for report in reports {
        out.push_str(&render_scenario(report));
        out.push('\n');
    }
    out.push_str(&render_targets(reports));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::{self, Plan};

    fn tiny() -> Vec<ScenarioReport> {
        vec![
            scenarios::routing_decision(Plan {
                iterations: 20,
                warmup: 2,
            }),
            scenarios::chat_non_streaming(Plan {
                iterations: 5,
                warmup: 1,
            }),
        ]
    }

    #[test]
    fn a_rendered_scenario_shows_every_quantile_column() {
        let reports = tiny();
        let text = render_scenario(&reports[0]);
        for column in ["min", "p50", "p90", "p99", "p99.9", "max"] {
            assert!(text.contains(column), "the report omits {column}:\n{text}");
        }
        assert!(text.contains("routing_decision"));
    }

    #[test]
    fn the_mean_never_appears_without_its_distribution() {
        // The rule specification 21 states: a report may include a mean, but
        // never as the only summary. The header is emitted as one string, so
        // the presence of `mean` implies the presence of the quantiles.
        let header = Distribution::header();
        assert!(header.contains("mean"));
        assert!(header.contains("p50") && header.contains("p99"));
    }

    #[test]
    fn the_targets_block_names_a_verdict_per_scenario() {
        let reports = tiny();
        let text = render_targets(&reports);
        for report in &reports {
            assert!(text.contains(report.name), "no verdict for {}", report.name);
        }
        assert!(
            text.contains("70% rated"),
            "the report must not imply the loaded target was measured"
        );
    }

    #[test]
    fn a_full_run_renders_without_panicking() {
        let text = render_run(&tiny());
        assert!(text.starts_with("# hypellm-bench"));
        assert!(text.contains("specification 19 targets"));
    }
}
