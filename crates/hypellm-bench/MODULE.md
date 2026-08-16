# Module: hypellm-bench

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Platform (primary), Security (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `src/lib.rs` and `src/main.rs`; `unsafe_code = "forbid"` inherited from the workspace lints. |
| External dependencies | None. Rust standard library plus the workspace path dependencies `hypellm-core`, `hypellm-router`, `hypellm-adapters`. No benchmark framework, no statistics library, no plotting. |
| Fuzz targets | **None, and none are required.** This crate parses no untrusted input: its only input is `--scale N` from an operator's own command line. The fuzz targets specification 21 requires belong to the parsers (`wire-http1`, `wire-json`, `wire-sse`, `hypellm-config`) and are tracked in `crates/hypellm-test-corpus/MODULE.md`. |

Platform owns this crate because the numbers it produces gate a release
(specification 2.3, `Performance`). Security is secondary because a benchmark
that quietly measures the error path, or whose thresholds are relaxed to make a
red build green, removes a gate without removing the appearance of one.

## What this crate is for

Specification 19 states the router's performance contract:

> Warm router overhead — p50 < 2 ms, p99 < 10 ms at 70% rated load, excluding
> edge/provider network.

Specification 21 (`Performance`) requires microbenchmarks and end-to-end
benchmarks, and adds the reporting rule: **"benchmarks report distributions, not
averages"**. Specification 21.1 requires the benchmark results to be retained
with the release artifact. This crate produces those numbers and that report.

```
cargo run --release -p hypellm-bench --offline
cargo run --release -p hypellm-bench --offline -- --scale 10   # quick smoke run
```

Run it under `--release`. A debug build measures the debug build.

## The measurement defect this crate exposed, and the fix

`DecisionTrace::routing_micros` is named in microseconds and is the value the
router publishes as its own overhead. It was computed as the difference of two
`Clock::now_millis()` readings.

At millisecond granularity, a 2 ms target cannot be measured at all: every
healthy sample reads as 0 or 1, the quantisation error on a p99 is a tenth of
the entire specification 19 budget, and the number stored in the field was a
thousand times smaller than its name claimed. The decision explorer
(`web/views/decisions.js`) already rendered the field as microseconds, so the
value shown to operators was wrong by three orders of magnitude.

The fix, made alongside this crate:

| Change | File |
|---|---|
| `Clock::now_micros()` added as a required trait method; `SystemClock` reads the same `Instant` origin as `now_millis`, `TestClock` stores microseconds and truncates for `now_millis` | `crates/hypellm-core/src/time.rs` |
| `TestClock::advance_micros` added, so sub-millisecond behaviour is testable without sleeping | `crates/hypellm-core/src/time.rs` |
| `Stopwatch` re-based on microseconds, gaining `elapsed_micros` | `crates/hypellm-core/src/time.rs` |
| `pipeline::execute` measures routing with `now_micros`, so `routing_micros` is genuinely microseconds | `crates/hypellm-router/src/pipeline.rs` |
| `hypellm_router_overhead_milliseconds` and the `router_ms` log field keep their published unit; the trace's microseconds are converted with `div_ceil` at the emit site | `crates/hypellm-router/src/pipeline.rs` |

The published metric was deliberately **not** converted to microseconds.
Changing the unit of a series that deployments already scrape and alert on would
silently reinterpret every threshold. The consequence is that
`hypellm_router_overhead_milliseconds` cannot distinguish 1 µs from 1000 µs, which
is exactly why specification 19's target is judged by this crate against
`routing_micros` and not by scraping that series.

## Scope, and the "a benchmark is not a load test" rule

| Does | Does not |
|---|---|
| Measure `PolicySnapshot::route` in isolation | Generate open-loop or concurrent load |
| Measure non-streaming and streaming chat end to end against `hypellm_router::testing::FakeUpstream` | Reach any network beyond 127.0.0.1 |
| Report p50/p90/p99/p99.9, min, max, n, and the mean beside them | Report a mean on its own |
| Compare routed against direct-to-provider latency (specification 19.1) | Measure a real provider, TLS, or DNS |
| Fail CI on an order-of-magnitude regression | Certify that specification 19's target is met |

## Honest gaps

Specification 19.1 describes a larger suite than this crate implements. Every
row below is **not implemented**. None of it is approximated, stubbed, or
partially covered; treat each as an open gap in release evidence.

| Specification 19 / 19.1 requirement | Status |
|---|---|
| "at 70% rated load" | **Not implemented.** Every scenario is closed-loop and single-threaded. The measured numbers are for an idle router; the specification's qualifier is not exercised. |
| Open-loop tests | **Not implemented.** |
| Controllable first-token delay, token cadence, errors, malformed frames, stalls, disconnects | **Not implemented.** `FakeUpstream` answers canned responses immediately. |
| Large prompts, tools, embeddings, slow clients, cancellations | **Not implemented.** One two-message chat request, streaming and buffered. |
| CPU and memory comparison; base < 100 MiB, per-connection < 8 KiB (specification 19) | **Not implemented.** Nothing here samples RSS or allocation. |
| Connection reuse (specification 19) | **Not measured.** `FakeUpstream` serves one request per connection, so the non-streaming scenario declares `Connection: close` to avoid benchmarking a failed reuse. Pooled reuse is never on the measured path. |
| Configuration reload, pointer swap < 1 ms | **Not implemented.** |
| Overload behaviour, admission rejection under pressure | **Not implemented.** |
| Soak with reloads, credential rotation, DNS changes, circuit transitions, log rotation, audit checkpointing | **Not implemented.** |
| Adversarial parser corpus, header fragmentation, slowloris, oversized SSE, deep JSON, retry storms | **Not implemented.** The corpus itself does not exist — see `crates/hypellm-test-corpus/MODULE.md`. |
| Result retention with the release artifact (specification 21.1) | **Not implemented.** The report is printed to stdout; nothing archives it. |

Two further limitations of what *is* implemented:

- **`router_overhead` is a reconstruction.** It is the pipeline's own
  `routing_micros` plus the adapter's encode and decode calls re-run on the same
  inputs in the same iteration. The pipeline does not instrument its own
  translate step, so the reported figure excludes the pipeline's call overhead
  around those adapter calls. `overhead_by_diff` (end-to-end minus a bare socket
  exchange with the same upstream) is reported alongside as an independent
  estimate; a large disagreement between the two means one of them is wrong.
- **The routing decision is below the clock's resolution.** On release builds the
  `route` series reports a p50 of 0 µs. That means "under one microsecond", not
  "free". A finer measurement would need a hardware counter, which the dependency
  policy of specification 4 does not admit.

## Threat notes

- **A benchmark that measures the error path reports improvement as things
  break.** An error is faster than success: a routing failure skips the adapter,
  and a connection refusal skips the upstream. Every scenario therefore checks
  the outcome and counts non-success in `ScenarioReport::failures`; the report
  prints a banner and the binary exits nonzero when that count is nonzero, and
  failed iterations contribute no samples.
- **Thresholds are a security-adjacent control and moving them is a change to a
  gate.** The tripwire constants in `tests/targets.rs` exist to catch a
  regression. Raising one to make a red build green disables the gate while
  leaving the suite green — the same failure mode specification 21.1 guards
  against for golden expectations. `the_tripwire_sits_below_the_specification_target`
  is a structural check that a tripwire can never be raised past specification
  19's own number.
- **A benchmark that claims more than it measured is a false assurance.** The
  report's verdict block states explicitly that the "70% rated load" qualifier
  was not satisfied, and the regression test's module header states that its
  thresholds are not the specification's targets. Deleting either turns a smoke
  test into an unearned release claim.
- **Test-only code must not reach the data plane.** This crate depends on
  `hypellm-router`, not the other way round, and nothing in `hypellm-router`
  references it. It is a workspace member so that it is built, linted, and
  scanned by `depscan`; it is not linked into the router binary.
- **No secrets, no prompts, no network.** The fixture credential is the literal
  `test-provider-secret` from `hypellm_router::testing`, the prompt is a fixture
  string, and the only destination is `127.0.0.1` on an ephemeral port bound by
  the harness itself. Nothing here reads an environment variable, a credential
  file, or a configuration path.
- **A measurement clock is not a deadline clock.** `Clock::now_micros` exists for
  measurement. Using it for a deadline would not be wrong, but mixing the two
  resolutions in one comparison would be; deadlines stay on `now_millis`
  throughout the workspace.

## Limits

Specification 18.2: no unbounded buffer may originate from a request. Nothing
here originates from a request, but the same discipline applies, because an
unbounded sample buffer turns a mistyped iteration count into an out-of-memory
kill rather than a truncated report.

| Input / resource | Limit | Enforced by |
|---|---|---|
| Retained samples per series | 1,048,576 (`distribution::MAX_SAMPLES`), 8 MiB of `u64` | `Samples::new` clamps the requested capacity; `Samples::push` counts overflow instead of growing |
| Samples discarded on overflow | Counted in `Distribution::overflowed`, printed as a banner, asserted zero in tests | `report::render_scenario`, `tests/targets.rs` |
| Iterations, routing scenario | 20,000 measured + 2,000 warmup (`Plan::DECISION`) | compile-time constant |
| Iterations, end-to-end scenarios | 500 measured + 50 warmup (`Plan::END_TO_END`) | compile-time constant |
| Command-line arguments | `--scale N` (positive integer) and `--help`; anything else exits nonzero | `main.rs` |
| Concurrency | One request at a time, one thread, one fake upstream thread | scenario structure |
| Sockets | Loopback only, ephemeral port chosen by `FakeUpstream`; 5 s read and write timeouts on the direct-comparison socket | `scenarios::direct_exchange`, `hypellm_router::testing` |
| Filesystem | One `TempDir` per fixture, created and removed by `hypellm_router::testing` | `hypellm-store::TempDir` |
| Output | Plain text to stdout; nothing is written to disk | `main.rs` |

## Public API

| Item | Purpose |
|---|---|
| `distribution::Samples` | Bounded microsecond sample collector |
| `distribution::Distribution` | Sorted-sample summary: n, min, p50, p90, p99, p99.9, max, sum, mean |
| `distribution::Unit` | Microseconds or a dimensionless count, so a report cannot mislabel a series |
| `distribution::MAX_SAMPLES` | The retention bound |
| `scenarios::Plan` | Measured iterations and warmup, with `DECISION` / `END_TO_END` defaults and `scaled` |
| `scenarios::ScenarioReport` | Name, description, series, failure count, caveats |
| `scenarios::routing_decision` | `PolicySnapshot::route` alone |
| `scenarios::chat_non_streaming` | Buffered chat end to end over the fake upstream |
| `scenarios::chat_streaming` | Streamed chat end to end over the fake upstream |
| `scenarios::all` | Every scenario at its default plan, optionally scaled |
| `report::render_run` / `render_scenario` / `render_targets` | Fixed-width text rendering |
| `report::TARGET_P50_MICROS` / `TARGET_P99_MICROS` | Specification 19's targets, in microseconds, defined once |

Quantiles use the nearest-rank definition with the rank rounded **up**, matching
`hypellm_core::time::Histogram::quantile_upper_bound`. Two quantile definitions in
one codebase produce two answers for the same data and an argument about which
one is real. No interpolation: an interpolated quantile invents a value that was
never observed, and a latency report should contain only measurements.

## Why a binary and not `#[bench]`

`#[bench]` and `test::Bencher` are unstable and require a nightly compiler.
Specification 21.1 requires the release artifact's compiler version to be
retained with its benchmark results, and moving the workspace to nightly to
obtain a timing loop is a poor trade for a project whose dependency policy
(specification 4) already rules out every third-party benchmark framework. A
plain `[[bin]]` plus an ordinary `#[test]` needs nothing beyond stable Rust.
