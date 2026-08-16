# Module: hypellm-telemetry

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Platform (primary), Security (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `src/lib.rs`; `unsafe_code = "forbid"` inherited from the workspace lints. |
| External dependencies | None. Three workspace path dependencies: `hypellm-core`, `hypellm-crypto`, `wire-json`. No registry crates, no exporter SDK, no agent. |
| Fuzz targets | **None exist.** The targets this module requires are listed under [Fuzz targets](#fuzz-targets), all marked not yet implemented. |

Platform owns this crate: it is the exposition and log-emission path, and its
failure modes are operational — cardinality, allocation, blocking writes.
Security holds the second signature because two of its three responsibilities are
security controls in disguise. The label and field vocabularies are the
mechanism that keeps specification 17's high-cardinality and sensitive-value
prohibitions from being a convention, and `Pseudonymizer` holds long-lived key
material. Changes to `LabelName`, `Field`, or `Pseudonymizer` are security
changes.

## Scope, and the "the vocabulary is the control" rule

Specification 18.1 assigns this crate "bounded structured logs, counters,
histograms, text exposition". Specification 17 fixes the shape: metrics are
local-first text for a platform collector to scrape, logs are newline-delimited
JSON, high-cardinality labels are forbidden, and identity correlation goes
through deterministic pseudonyms.

The defining decision is that both vocabularies are **closed enums**, not
strings. `Labels::with` accepts a `LabelName` variant; `Event::str_field` accepts
a `Field` variant. There is no `labels.with("user_id", …)` and no
`event.field("prompt", …)` — those are compile errors, not runtime rejections.
A runtime allowlist fails open the first time someone adds a dimension in a
hurry; a closed enum fails at build time and shows up in review. Two unit tests
assert the negative directly: `the_vocabulary_excludes_high_cardinality_dimensions`
(metrics) and `the_field_vocabulary_excludes_request_content` (logs).

| Provides | Where | Specification |
|---|---|---|
| Closed metric label vocabulary, 13 names (one reserved) | `metrics::LabelName` | 17 (high-cardinality prohibition) |
| Counters, gauges, fixed-bucket histograms | `metrics::Registry` | 17 (`Metrics`) |
| Text exposition, `# HELP` / `# TYPE` / samples | `Registry::exposition` | 17 (local-first, no embedded exporter) |
| Closed log field vocabulary, 26 fields | `logs::Field` | 17 (`Structured logs`) |
| Newline-delimited JSON events, capped fields | `logs::Event`, `logs::Logger` | 17, 10 (capped strings) |
| Keyed, domain-separated identity pseudonyms | `logs::Pseudonymizer` | 17 (deterministic pseudonyms) |
| The metric-name registry | `metrics::names`, 21 constants | 17 (required signals) |

This module deliberately does **not**:

- **Embed an agent, exporter, or push client.** It opens no socket, resolves no
  host, and speaks no collector protocol. Specification 17 says the router does
  not embed third-party agents or exporters — partly because specification 4
  admits no such dependency, and more importantly because an in-process exporter
  with access to request state is an egress path that no configuration can close.
  Scraping is the collector's job; `exposition()` returns a `String`.
- **Own the audit chain.** Specification 17 lists Audit as a separate signal with
  integrity requirements. The hash-chained, tamper-evident audit record lives in
  `hypellm-store::audit`. This crate emits an observational log line and can carry
  a truncated chain head in `Field::AuditHead` — it does not authenticate
  anything.
- **Own the decision trace.** Policy digest, candidates, exclusion reason codes,
  and integer score terms are produced by `hypellm-core::decision` as structured
  values. This crate only flattens selected scalars into a log line.
- **Implement cryptography.** Pseudonyms are HMAC-SHA-256 from `hypellm-crypto`.
  No digest, no encoding, and no comparison is reimplemented here (specification
  4, "no novel cryptography").
- **Own time.** `Clock`, `format_rfc3339`, `Histogram`, and `LATENCY_BUCKETS_MS`
  come from `hypellm-core::time`. The logger holds an `Arc<dyn Clock>` so that
  tests are deterministic and so that no module reads the clock directly.
- **Scrub free text.** There is no PII detector and no regex redactor, because
  there is no free-text field to scrub. Prompts, completions, tool arguments, and
  provider bodies are excluded by the vocabulary rather than filtered out of it.
  A scrubber would imply that arbitrary text may be passed in, which is exactly
  the property this design refuses.
- **Manage log destinations.** `Sink` is a one-method trait; the crate ships
  `StderrSink` and `MemorySink` only. No file sink, no rotation, no retention, no
  syslog. Where output goes is a deployment concern (specification 20).

## Threat notes

- **`Pseudonymizer` leaks its key through derived `Debug` — open defect.**
  `logs.rs` declares `#[derive(Debug)] pub struct Pseudonymizer { key: Vec<u8> }`.
  The derived implementation prints the key bytes, and `Telemetry` also derives
  `Debug` while holding a `Pseudonymizer` field, so a single `{:?}` on the
  telemetry facade — in a diagnostic log line, an error path, or a panic message —
  discloses the 256-bit pseudonym key sourced from
  `hypellm_crypto::random::secret_256` and persisted as `pseudonym.key`. Disclosure
  is retroactive: the key is stable for the life of the file, so anyone holding it
  can de-anonymize every historical log line by enumerating candidate tenant and
  principal identifiers, whose space is small. Specification 10 requires
  redaction types for crash reports, traces, and errors; specification 7.1
  requires secret material behind redacting `Debug`/`Display`. The key must be
  held in `hypellm_core::sensitive::Sensitive` or `hypellm_crypto::Secret<32>`, or
  `Debug` must be hand-written to print `Pseudonymizer { key: [redacted] }`. The
  `Vec<u8>` is also not zeroed on drop, unlike `Secret<N>`.
- **Pseudonyms are 48 bits and never rotate.** `Pseudonymizer::pseudonym`
  truncates the HMAC tag to 6 bytes. 48 bits is ample against accidental
  collision at any plausible tenant count, but it is a *linkage* identifier with
  no epoch: a principal's pseudonym is identical across every log line the
  deployment ever writes. That is the intended correlation property, and it is
  also the privacy cost — a pseudonymous log is not an anonymous one, and it
  should be retained and access-controlled as identity-bearing data.
  Domain separation (`tenant` vs `principal`) is enforced by prefixing the HMAC
  input and is covered by `pseudonyms_are_stable_and_domain_separated`.
- **Attacker-driven metric cardinality, and the metrics-blinding attack it
  becomes.** `LabelName::Alias` and `LabelName::Target` are the two label names
  whose values can trace back to request content — a client chooses the model
  string in `requested_model`. `MAX_SERIES_PER_METRIC` stops that from exhausting
  memory. The backstop used to convert a memory attack into an observability
  attack — a full table blinded the metric for the life of the process — so a
  full table now admits a new series by evicting the stalest one, provided that
  series has gone `STALE_AFTER_ACCESSES` (8 × the cap) accesses untouched. A
  table full of *live* series still folds rather than evicting: that is a
  genuinely high-cardinality metric, and evicting from it would only thrash. The
  eviction scan runs once per `SCAN_INTERVAL` (256) insert attempts, because it
  is O(series) under the write lock and the path that triggers it is the
  sprayer's own. `hypellm_metric_series_evicted_total` and
  `hypellm_metric_series_overflowed_total` make both visible, so a metric that has
  stopped attributing says so instead of looking healthy.
  The control is still upstream: emit sites must label with the *resolved* alias
  or target identifier from the active policy snapshot, never the raw client
  string. Today no production call site uses `LabelName::Alias`; that must stay a
  deliberate decision rather than an accident.
- **Overflow folding is kind-dependent, and only the meaningful kind folds.**
  A sum of counters that could not be attributed answers a question; a gauge
  folded with unrelated gauges is last-write-wins across things that have
  nothing to do with each other, and merged histograms describe no distribution
  that exists. Only counters get an overflow series now — gauge and histogram
  observations past the cap are dropped and counted, because a number that looks
  like data and describes nothing is worse than an absent sample. The overflow
  series carries `LabelName::Overflow` (`hypellm_overflow="true"`), a reserved name
  no emit site uses; it used to be `{outcome="overflow"}`, indistinguishable in
  the exposition from a legitimate `Outcome` value.
- **Log-line forging via field values, defended by delegation.** The output
  format is newline-delimited JSON, so a value containing a newline followed by a
  plausible JSON object would inject a synthetic log record — a way for an
  attacker-influenced string (an upstream error message, a model name) to write
  attacker-chosen `severity` and `event` values into the audit-adjacent record.
  The defence is `wire_json::to_string`, which escapes C0 controls; the property
  is pinned by `hostile_field_values_cannot_forge_a_log_line`. Note that this
  crate does not escape anything itself — log-forging resistance is entirely
  inherited from `wire-json`'s encoder, and a regression there is a log-integrity
  vulnerability here.
- **Exposition-line forging, defended by narrowing rather than escaping.** The
  text exposition format has no escape mechanism this crate could rely on, so
  `sanitize_value` narrows instead: it keeps ASCII alphanumerics and `-._:/` and
  replaces everything else with `_`. A quote, newline, backslash, space, or brace
  cannot survive into a sample line. Narrowing is the right choice precisely
  because it cannot be got wrong in the way escaping can — there is no escaping
  round-trip to disagree about. `label_values_are_narrowed_not_escaped` pins it.
- **Duplicate JSON keys are producible, and the router's own parser rejects
  them.** `Event::str_field` appends to a `Vec`, and `wire_json::Object::push`
  appends without a duplicate check. Calling the same field twice on one event —
  easy to do in a builder chain assembled across branches — emits a line with a
  repeated key. `wire_json::Limits` sets `reject_duplicate_keys: true` in every
  profile, so the router's own parser would reject a line the router itself
  wrote, and third-party log consumers disagree about whether first or last wins.
  That is a parser differential the emitter can cause. No test covers it.
- **Telemetry fails silently, including for security signals.** Every lock
  acquisition in `Registry`, `MemorySink`, and the exposition path uses `.ok()?`
  or `map_or`, so a poisoned `RwLock`/`Mutex` degrades to *no metric recorded* and
  *no error surfaced* — `exposition()` returns an empty string on a poisoned
  registry lock. `StderrSink` likewise discards the `writeln!` result. This is the
  correct trade for the data plane (specification 18.2 forbids panics on
  data-plane input, and a logging failure must not fail a request), but it means
  the disappearance of `AUTH_FAILURES` is indistinguishable from an absence of
  auth failures. Alerting must be built on positive liveness signals, not on the
  absence of a counter.
- **`StderrSink` still blocks the emitting thread, and is no longer on the
  request path.** `write_line` takes the process-wide stderr lock and writes
  synchronously with no deadline, so a stalled pipe would block every emitter —
  a data-path stall introduced by observability. `QueueingSink` puts one fixed
  writer thread behind a bounded queue (`MAX_QUEUED_LINES`, 4 096), and
  `Telemetry::stderr` composes the two, so a stalled reader now stalls only the
  writer. **A caller constructing `Logger::new(Box::new(StderrSink), …)`
  directly reintroduces the stall** — the router did exactly that until this was
  wired, and it is the mistake to watch for.
  Drops are oldest-first (during an incident the newest lines matter most) and
  counted, and the count is emitted with the next line that gets through.
  `Drop` joins the writer so shutdown drains: the lines most worth keeping are
  the ones written just before a process stopped.
- **Log volume is bounded per unit time, by a second-order control.** Per event
  code, `PER_CODE_PER_WINDOW` (2 000) lines per second, so a flood of one code
  cannot starve another of the writer. `Critical` is never limited — it is the
  severity for things an operator must not miss.
  The number is high on purpose: the queue, not the rate limit, is what bounds
  memory and protects the data path, and a low limit would throttle ordinary
  per-request logging to defend against a flood that admission control has
  already bounded. Suppression is reported rather than silent.
- **Wall-clock timestamps are not monotonic.** `Logger::emit` stamps lines with
  `clock.wall_millis()`. A clock step backwards produces out-of-order timestamps
  and can make an incident timeline appear to loop. Specification 17 requires
  monotonic clocks to govern durations and deadlines — durations reaching this
  crate as `int_field` values must be measured monotonically by the caller, never
  differenced from these timestamps. `names::CLOCK_STEPS` exists to make steps
  visible; nothing here enforces its use.
- **`MemorySink` is unbounded and publicly exported from a production crate.**
  It accumulates every line in a `Vec<String>` with no cap and a manual `clear()`.
  It is a test aid but is not `#[cfg(test)]`, so it links into the router binary
  and is one configuration mistake away from being an in-process memory leak
  proportional to log volume.
- **Prompts are inert here by construction.** No `Field` or `LabelName` variant
  can carry prompt, message, completion, tool-argument, credential, or body
  content, and there is no dynamic key. This is the crate's contribution to
  specification 10.1's "prompt injection affecting control plane" row: content
  that never enters telemetry cannot be read back out of a dashboard or a log
  search as though it were router state.

## Limits

Values below were read from the source; the enforcing constant or expression is
named for each. Rows marked **Not enforced** are honest gaps, not assurances.

| Input / resource | Limit | Enforced by | Status |
|---|---|---|---|
| Log string field value | 256 bytes, truncated on a UTF-8 character boundary | `logs::MAX_FIELD_LEN` via `hypellm_core::sensitive::Capped::new` in `Event::str_field` | Enforced |
| Distinct log fields | 26, the `Field` variants | closed enum; `Field::all()` | Enforced structurally |
| Fields attached to one event | none — `Event::fields` is an unbounded `Vec`, and the same field may be pushed repeatedly | — | **Not enforced.** Bounded in practice only because every call site is static router code |
| Total log line length | none — derived from field count × 256 bytes plus the fixed `ts`/`severity`/`event` prefix | — | **Not enforced.** No cap on the assembled line |
| Log emission rate | none — no sampling, rate limit, or dedup | — | **Not enforced** |
| Integer log field value | Values above `i64::MAX` are rendered as an approximate `f64` by `wire_json::Value::from(u64)` | `wire-json` `From<u64>` | Enforced, lossy at the top of the range |
| Pseudonym output | 12 hex characters (48 bits) | `hex::encode_prefix(&tag, 6)` in `Pseudonymizer::pseudonym` | Enforced |
| Pseudonymizer key | any length accepted; HMAC-SHA-256 hashes keys over 64 bytes down to 32 | `hypellm_crypto::hmac_sha256_parts` | Enforced by the primitive |
| Metric label value | 64 input characters, each retained character ASCII, so ≤ 64 bytes out; empty becomes `none` | `metrics::MAX_LABEL_VALUE_LEN` via `sanitize_value` | Enforced |
| Label character set | ASCII alphanumerics plus `-._:/`; all else replaced with `_` | `sanitize_value` | Enforced |
| Labels per series | 12, the `LabelName` variants; `Labels::with` replaces rather than appends on a repeated name | closed enum; `LabelName::all()` | Enforced structurally |
| Series per metric | 2,000, plus one `{hypellm_overflow="true"}` counter series, so 2,001 map entries | `metrics::MAX_SERIES_PER_METRIC` checked in `Registry::with_series` | Enforced |
| Series staleness before eviction | 8 × the series cap, counted in accesses to that metric, not milliseconds | `metrics::STALE_AFTER_ACCESSES` | Enforced |
| Distinct metric names | 21 today; registration requires a `&'static str`, so no request-derived name can create one | `Registry::ensure` signature; `metrics::names` | Enforced structurally |
| Histogram buckets per series | 16 bounds plus one overflow bucket = 17 `AtomicU64` counters | `hypellm_core::time::LATENCY_BUCKETS_MS` | Enforced |
| Histogram sample value | none — `histogram_observe` accepts any `u64`; `sum.fetch_add` wraps silently rather than aborting, because `overflow-checks` does not apply to atomic intrinsics | — | **Not enforced.** A bogus sample (e.g. an underflowed duration) corrupts `_sum` |
| Counter value | wraps at `u64::MAX` via `fetch_add`, silently | — | Wrap is unreachable in practice; noted because it is silent |
| Registry resident memory | bounded: (metric names) × 2,001 series × (one atomic, or a 17-counter histogram) | the two caps above | Enforced |
| Exposition document size | none — `exposition()` materializes every metric, series, and histogram bucket line into one `String`. At full cardinality a single histogram metric renders 2,001 × 19 ≈ 38,000 lines; at ~100 B/line that is ~4 MB per histogram metric, and roughly ten times that with maximal label sets | — | **Not enforced.** Bounded by the cardinality caps, but the bound is large and the buffer is not streamed |
| Captured lines in `MemorySink` | none | — | **Not enforced** (test aid, but publicly exported) |
| Sink write deadline | none — `StderrSink::write_line` blocks | — | **Not enforced** |

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is a seeded, deterministic mutation engine
in `hypellm-test-corpus::fuzz`, driven from ordinary `tests/fuzz.rs` targets.
All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table. None cover this
crate: it contains no parser, so the targets below fuzz an **encoder against a
parser or a grammar**, which is where an encoder's differentials live.

This crate's fuzzable surface is unusual: it contains no parser. Every target
below fuzzes an **encoder against a parser or a grammar**, which is where an
encoder's differentials live.

| Target | Property to hold | Specification |
|---|---|---|
| `telemetry_log_line` | For arbitrary field values and combinations, `Event::to_json_line` yields exactly one line, containing no raw newline, that `wire_json::parse_str` accepts under `Limits::SMALL` — including the duplicate-key case, which currently violates it | 21 (`Fuzz`), 17 |
| `telemetry_exposition` | For arbitrary label values and series, every non-comment line of `Registry::exposition` is `name[{labels}] value` with a numeric value, quotes appear only as the label-quoting pair, and no line contains a newline or an unbalanced brace | 21 (`Fuzz`), 17 |
| `telemetry_label_sanitizer` | `sanitize_value` output is always non-empty, at most `MAX_LABEL_VALUE_LEN` bytes, drawn only from the permitted character set, and never panics or slices mid-character on arbitrary UTF-8 | 21 (`Fuzz`), 3.2 |
| `telemetry_field_cap` | `Capped::new` at `MAX_FIELD_LEN` never splits a UTF-8 character, never exceeds the cap, and is idempotent, for arbitrary multi-byte input | 21 (`Fuzz`), 10 |
| `telemetry_registry_ops` | Under an arbitrary interleaving of counter/gauge/histogram operations and label sets, series count never exceeds `MAX_SERIES_PER_METRIC + 1`, exposition remains well-formed, and repeated renders of an unchanged registry are byte-identical | 21 (`Fuzz`, `Property`), 17 |

**Required, not yet implemented:** all five.

Also required by specification 21 and absent: a property test that no `Field` or
`LabelName` value can carry an attacker-supplied byte into an unescaped position,
and a secret-leakage test asserting that `{:?}` on `Telemetry`, `Logger`, and
`Pseudonymizer` contains no key material — the latter fails today, per the first
threat note.

## Public API

See `lib.rs`, `logs.rs`, and `metrics.rs`. The surface is deliberately small and
almost entirely closed:

- `Telemetry` — the facade a request handler holds: `metrics`, `logger`,
  `pseudonyms`. Constructed by `new` or `stderr`; `Send + Sync`, intended to be
  shared behind an `Arc`.
- `metrics::{Registry, Labels, LabelName, MetricKind, sanitize_value, names}` —
  counters, gauges, histograms, and the exposition renderer.
- `logs::{Event, Field, Severity, Logger, Sink, StderrSink, MemorySink,
  Pseudonymizer}` — event construction, severity filtering, and emission.
- Constants: `logs::MAX_FIELD_LEN`, `metrics::MAX_LABEL_VALUE_LEN`,
  `metrics::MAX_SERIES_PER_METRIC`.

There is no dynamic label key, no dynamic log field key, no runtime allowlist, no
metric unregistration, no exporter configuration, and no way to change a
`Logger`'s minimum severity after construction — a level change requires building
a new `Logger`, which is a gap for runtime reconfiguration under specification
11's atomic activation model. `Sink` is the single extension point; anything it
is given is already capped, narrowed, and escaped.
