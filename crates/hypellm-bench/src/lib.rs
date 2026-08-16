//! The HypeLLM Router benchmark harness.
//!
//! Specification 21 (`Performance`) requires "Microbench, end-to-end benchmark,
//! overload, soak, memory fragmentation" and specification 2.3 makes those
//! results a release acceptance gate. Specification 19 states the number this
//! crate exists to produce: **warm router overhead p50 < 2 ms, p99 < 10 ms,
//! excluding edge/provider network**.
//!
//! ```text
//!  scenarios.rs     run one shape of request many times, in process
//!       │
//!  Clock::now_micros    the measurement resolution (hypellm-core::time)
//!       │
//!  distribution.rs  sort the samples, report order statistics
//!       │
//!  main.rs          print a table an operator can read and diff
//! ```
//!
//! # Why this is a binary and not `#[bench]`
//!
//! `#[bench]` and `test::Bencher` are unstable and require a nightly compiler.
//! Specification 21.1 requires the release artifact's compiler version to be
//! retained alongside its benchmark results, and pinning the whole workspace to
//! nightly to obtain a timing loop is a poor trade. A plain `[[bin]]` needs
//! nothing that stable Rust does not already provide, and the dependency policy
//! of specification 4 rules out every third-party benchmark framework anyway.
//!
//! # Why the samples are kept and sorted
//!
//! Specification 21: "benchmarks report distributions, not averages." An
//! average is the one summary that can be simultaneously true and useless for a
//! quantile target — see [`distribution`] for the reasoning and for the test
//! that demonstrates it on a series whose mean passes while its tail fails.
//!
//! # What this harness does not do
//!
//! Specification 19.1 lists a larger suite than this crate implements. The gaps
//! are named rather than papered over, here and in `MODULE.md`:
//!
//! - **Open-loop load.** Every scenario is closed-loop and single-threaded. The
//!   "70% rated load" qualifier on specification 19's target is therefore *not*
//!   satisfied: these numbers are for an unloaded router.
//! - **Overload, soak, and memory.** No admission-rejection storm, no 24-hour
//!   run, no RSS sampling, no fragmentation measurement.
//! - **Adversarial corpora, slow clients, cancellations, tool calls, large
//!   prompts, embeddings.** Not exercised.
//! - **Connection reuse.** The fake upstream closes after each response, so
//!   pooled reuse is never on the measured path.
//!
//! Treat a passing run as evidence about the routing and translation path on an
//! idle machine, and nothing more.

#![forbid(unsafe_code)]
// Specification 18.2. The workspace sets these to `warn`; this crate has no
// remaining sites, so the escalation makes a new one a build failure rather
// than one more line of output nobody reads. Only `integer_division` is listed
// because it is the only one of the 18.2 lints this crate ever tripped: there
// is no `as`, no unchecked index, and no `panic!` on any path here.
#![cfg_attr(not(test), deny(clippy::integer_division))]

pub mod distribution;
pub mod report;
pub mod scenarios;

pub use distribution::{Distribution, Samples, Unit};
pub use scenarios::{Plan, ScenarioReport};
