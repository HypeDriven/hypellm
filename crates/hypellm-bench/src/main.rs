//! `hypellm-bench`: run the router benchmark scenarios and print a report.
//!
//! Specification 21 (`Performance`) and 2.3 (`Release acceptance`). See
//! `MODULE.md` for what the numbers do and do not mean.
//!
//! ```text
//! cargo run --release -p hypellm-bench --offline
//! cargo run --release -p hypellm-bench --offline -- --scale 10
//! ```
//!
//! `--scale N` divides every scenario's iteration count by `N`, for a quick
//! smoke run. Scaling down widens the confidence interval on the tail
//! quantiles; a p99.9 over 50 samples is just the maximum wearing a label.
//!
//! Run it under `--release`. A debug build measures the debug build's overhead,
//! which is several times the release figure and has no relationship to the
//! specification 19 target.

#![forbid(unsafe_code)]
// Specification 18.2, matching the escalation in `lib.rs`. A binary is its own
// crate root, so the library's `deny` does not reach this file.
#![cfg_attr(not(test), deny(clippy::integer_division))]

use hypellm_bench::report;
use hypellm_bench::scenarios;
use std::process::ExitCode;

/// Usage text, printed for `--help` and for anything unrecognised.
const USAGE: &str = "\
hypellm-bench — router overhead distributions (specification 19, 21)

usage: hypellm-bench [--scale N]

  --scale N   divide every scenario's iteration count by N (default 1)
  --help      print this text

Exits nonzero when a scenario had failed iterations, which invalidates its
samples. Being over the specification 19 target is reported, not enforced:
this binary does not know what hardware it is on.
";

fn main() -> ExitCode {
    let mut scale: usize = 1;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--scale" => {
                let Some(value) = args.next() else {
                    eprintln!("--scale needs a value\n\n{USAGE}");
                    return ExitCode::FAILURE;
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed > 0 => scale = parsed,
                    _ => {
                        eprintln!("--scale needs a positive integer, got {value:?}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            other => {
                eprintln!("unrecognised argument {other:?}\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    let reports = scenarios::all(scale);
    print!("{}", report::render_run(&reports));

    if reports.iter().any(|r| r.failures > 0) {
        eprintln!("\nrun invalid: at least one scenario had failed iterations");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
