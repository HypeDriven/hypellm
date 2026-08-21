# Module: hypellm-core

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` is declared in `lib.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library plus one workspace path dependency: `hypellm-crypto` (for `Digest`, held as an opaque value in `PolicySnapshot` and `DecisionTrace`). |
| Fuzz targets | **None exist in this repository yet.** The targets this module requires are listed under [Fuzz targets](#fuzz-targets) below. |

## Scope and the "decides but never acts" rule

Specification 18.1 describes this crate as "canonical types, routing, quotas,
retries, decision traces; pure and heavily property-tested". Specification 18.3
fixes the contract that gives the word *pure* its teeth:
`PolicySnapshot::route(ctx, req, live)` "returns ranked eligible candidates plus
exclusion reasons; no I/O".

What this module owns:

| Area | Module | Governing section |
|---|---|---|
| Canonical request shape | `canonical` | 5.1 |
| Identifier newtypes and their alphabet | `ids` | 5, 10.1 |
| Providers, targets, declared capabilities, capability verbs | `target` | 5, 23, 26.1 |
| Precedence, deny/pin, eligibility, scoring | `policy` | 6.1–6.3 |
| Candidates, exclusions, score terms, residency class, traces | `decision` | 6.3, 17, 26.4 |
| Hierarchical token buckets and reservations | `admission` | 12 |
| Circuit breakers, EWMA, live state | `health` | 13 |
| Canonical stream events and the failover gate | `event` | 6.5, 14 |
| Management roles and permissions | `rbac` | 9.3 |
| Address classification for the egress guard | `netaddr` | 10 |
| Monotonic clock, deadlines, bounded metrics | `time` | 17, 18.2 |
| Client-facing error contract | `error` | 8.2 |
| Redacting carriers | `sensitive` | 10, 18.2 |

What this module deliberately does **not** do, and where it lives instead:

- **No I/O of any kind.** No socket, file, DNS lookup, or process. Live signals
  reach routing only through the [`LiveState`] trait, whose methods return
  already-sampled values, so a decision cannot block or observe a moving target
  mid-evaluation. This is also what lets specification 15.4's draft simulation
  run the production code path "without provider invocation".
- **No credentials.** `CredentialRef` is an opaque handle; nothing in this crate
  can resolve it. Credential access is the adapter boundary's sole privilege
  (7.1, 10). `Provider::credential_ref` being `None` on a remote target is an
  *eligibility* fact (`CredentialScopeMismatch`), not a lookup.
- **No wire parsing.** No HTTP, JSON, or SSE bytes reach this crate. `wire-*`
  and the adapters produce `CanonicalRequest` and `CanonicalEvent`; the router
  core never re-parses a client payload and never sees a provider one.
- **No name resolution and no connection.** `netaddr` classifies an address that
  somebody else already resolved. Resolver pinning against DNS rebinding is
  `hypellm-net`; load-time endpoint rejection is `hypellm-config`. Classification is
  one of three layers, not the SSRF control by itself.
- **No cryptography.** `hypellm_crypto::Digest` is carried and compared, never
  computed here.
- **No size enforcement on request bodies.** Prompt bytes, message counts, tool
  counts, and stream volume are bounded at the wire boundary (3.2). See
  [Limits](#limits) for exactly which of those this crate does and does not
  enforce.

## Threat notes

**Determinism is a security property, not an optimization.** Appendix B requires
that equal request, policy snapshot, and live state produce equal ordered
candidates; a decision that cannot be reproduced cannot be audited. Enforcement
is structural: every collection that affects ordering is a `BTreeMap`/`BTreeSet`
or a `Vec`, never a hash map, and `route` sorts by `(score descending, target id
ascending)` so the result is independent of input order. The single permitted
source of variation is `deterministic_jitter`, FNV-1a over the target id mixed
with the request id by SplitMix64 — deliberately not `DefaultHasher`, which is
randomly seeded per process and would make two routers disagree and a replay
fail to reproduce. Introducing a `HashMap`, an unstable sort keyed on score
alone, or any ambient randomness silently breaks the invariant; nothing in the
type system catches it.

**Filter-versus-score confusion.** Specification 6.3: "security constraints
never appear as score penalties — they are eligibility filters."
`PolicySnapshot::evaluate` returns `Err(ExclusionReason)` and never constructs a
`Candidate`, and `ScoreTerms` has no field a security reason could be written
into. `ExclusionReason::is_security_constraint` exists so a test can assert the
set stays a filter set. The realistic failure is an editor "softening" a
residency or allowlist check into a large negative weight to make a target
selectable in an emergency; that would be a compliance bypass expressed as a
tuning change.

**Rank inversion by weight.** A rank-0 preference must beat any combination of
optimization terms. That holds only because `MAX_NON_RANK_MAGNITUDE` (400,999)
stays strictly below `RANK_UNIT` (1,000,000), and because `ScoreTerms::clamped`
bounds every term before summation. Two live hazards: widening any term's range
without re-checking the sum, and constructing `ScoreTerms` outside
`PolicySnapshot::score` — the clamp is applied *there*, not in a constructor, so
a hand-built `ScoreTerms` is unclamped and its `total()` merely saturates.

**Deny stickiness.** `MergedBindings::is_denied` resolves matching rules by
`(precedence level, selector specificity)` and, on an exact tie, ORs the deny
bits so an ambiguous allow/deny pair fails closed. A lower-precedence binding
therefore cannot re-enable a higher-precedence deny (6.1). The same fail-closed
tie rule governs `PolicySnapshot::authorizes`, which is default-deny: an alias
with no matching grant is invisible, which is what makes "the models endpoint
reveals only authorized aliases" hold without a second mechanism.

**Reservation accounting.** Appendix B requires exactly-once release on success,
error, timeout, and cancellation. `Reservation::finish` is guarded by an
`AtomicBool::swap`, so `commit` followed by `Drop` releases once;
`AdmissionController::reserve` rolls back every scope already acquired when a
narrower scope rejects, because without that a target-layer rejection would leak
a global and a tenant slot on every attempt — and a busy router rejects a great
deal. Specification 18.2 is explicit that `Drop` is not relied upon for
*accounting*: the reconciled numbers come from `commit`, and `Drop` only
guarantees *capacity*.

**Actual usage reconciles against the reservation timestamp.** When provider
usage exceeds the pre-admission estimate, `Scope::release` charges the overage
without advancing the token bucket's refill clock into the future. Property and
regression tests verify that the bucket subsequently refills and that estimated
and actual charges reconcile conservatively.

**Unbounded, unevicted scope maps.** `AdmissionController::tenant_scope` and
`principal_scope` insert a `Scope` for every tenant and principal observed and
never remove one. The keys are authenticated and each is capped at
`MAX_ID_LEN`, so this is not attacker-driven in the usual sense — but the
cardinality is bounded by the identity store, not by anything in this crate. A
deployment that mints a principal per workload grows router memory
monotonically. `HealthRegistry::entry` is bounded (configured targets ×
operations) and is not affected.

**`ResponseAccumulator` has no ceiling.** `text`, `reasoning`, `tool_calls`, and
`embeddings` grow with whatever the upstream sends, and every `ToolCallDelta`
linearly scans `tool_calls` for its index — so a provider emitting N distinct
indices costs O(N²) comparisons and N allocations. The type is correct about
*identity* (index travels on the event so interleaved calls never concatenate,
per 14) but says nothing about *volume*. Bounding event size and count is the
caller's obligation (3.2, 14); a caller that pumps an unbounded stream through
this type has an unbounded buffer.

**Redaction is hand-written and unchecked.** `CanonicalRequest`, `Message`,
`ContentPart`, `ImageSource`, `ToolCall`, `CanonicalEvent`, and `ToolCallDelta`
each carry a manual `Debug` that prints shape and byte counts only. There is no
derive and no compiler assistance: adding a field that holds prompt text, model
output, or a caller-supplied URL without also editing that `Debug` leaks it into
the first log line or panic message that formats the value. `Sensitive<T>` is
the general carrier for anything not covered, and is intentionally not `Clone`
so that `#[derive(Clone)]` on an enclosing struct cannot silently duplicate
secret material.

**Identifiers are an injection boundary in four contexts.** `ids::validate`
admits only `[A-Za-z0-9._:-]` and at most `MAX_ID_LEN` bytes because identifiers
are concatenated into store keys, printed into the native configuration grammar
(11.1), emitted into newline-delimited logs, and used as metric labels. Each of
those has a delimiter — `/`, whitespace, `"`, `=`, newline, NUL — that must not
appear inside a value. `RequestId::parse` requires exactly 32 *lowercase* hex
characters so a request id has one spelling, and therefore one metric label and
one audit key. Relaxing either alphabet re-opens all four contexts at once.

**Address-class confusion (SSRF).** `classify_ipv6` decodes IPv4-mapped
(`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), and NAT64 (`64:ff9b::/96`)
forms *before* classifying, so `::ffff:169.254.169.254` is `Metadata` and not
`Global`; a classifier that only inspected the outer family would route straight
to the instance-metadata service. `EgressProfile::permits` refuses `Metadata`,
`Multicast`, `Broadcast`, `Unspecified`, `Reserved`, and `SharedAddressSpace`
under *every* profile, including one with all four permission flags set — there
is no configuration that reaches the metadata service. Two honest caveats:
`is_valid_host` is a syntax/typo check on administrator-configured values and
not a security boundary (it accepts `_` in labels), and this module cannot
defend against rebinding at all, because it never resolves anything.

**Token estimation must never under-count.** `estimated_input_tokens` is
`ceil(bytes / 2)` plus 8 per message, computed with saturating arithmetic, which
is pessimistic against a real tokenizer's 3–4 bytes per token. Under-counting
would admit a request past a quota that should have held it, so the bias is
deliberate. This crate implements no tokenizer; specification 12's "selected
target tokenizer when available" is the caller's substitution.

**Time.** Deadlines are monotonic-only and immune to NTP steps, but a `Deadline`
is a bare monotonic millisecond value with no clock identity — one created
against a different `Clock` instance, or carried across a restart, is
meaningless. Quarantine expiry deliberately uses `wall_millis` so it survives a
restart, which means a backwards wall-clock step lengthens a quarantine and a
forwards step shortens it; `ClockSyncMonitor` detects such a step but does not
correct for it. `Ewma::observe` is a lossy read-modify-write under contention,
acceptable only because live metrics are advisory and policy remains the
authority (13).

**Trace disclosure.** `DecisionTrace` and `RouteOutcome::exclusions` name target
identifiers and the policy digest. They contain no prompt, credential, or
upstream URL by construction — no field can hold one — but they do describe the
deployment's topology. Returning them is gated on `ReadDecisionTraces` and on
the caller's tenant (Appendix B: "management visibility never exceeds the
caller's tenant and permissions"); this crate provides the redaction, not the
gate.

## Limits

Enforced in this crate:

| Input | Limit | Enforced by |
|---|---|---|
| Identifier length | 128 bytes | `ids::MAX_ID_LEN`, checked in `ids::validate` |
| Identifier alphabet | `[A-Za-z0-9._:-]`, non-empty | `ids::validate` |
| `RequestId` text form | exactly 32 lowercase hex characters | `RequestId::parse` |
| `temperature` | finite, `0.0..=2.0` | `Sampling::validate` |
| `top_p` | finite, `0.0..=1.0` | `Sampling::validate` |
| `frequency_penalty`, `presence_penalty` | finite, `-2.0..=2.0` | `Sampling::validate` |
| Stop sequences | 8 | `Sampling::validate` |
| Cost class | `0..=9`, clamped rather than rejected | `CostClass::new` |
| Preference rank | 64, clamped | `ScoreTerms::MAX_RANK` via `rank_term` |
| Each score term | per-term range constants | `ScoreTerms::clamped` |
| Sum of non-rank terms | 400,999 — strictly below `RANK_UNIT` (1,000,000) | `ScoreTerms::MAX_NON_RANK_MAGNITUDE` |
| Score arithmetic | saturating `i64`; no wrap, no panic | `ScoreTerms::total` |
| Error detail string | 256 bytes, truncated on a char boundary | `Capped::log_field` via `RouterError::new` |
| Error `param` string | 64 bytes | `RouterError::with_param` |
| Generic log field | 256 bytes | `Capped::log_field` |
| Host string | 253 bytes total, 63 bytes per label | `netaddr::is_valid_host` |
| Breaker cooldown | doubling with the shift capped at 16, then `max_cooldown_millis` (default 60,000 ms) | `Breaker::open` |
| Breaker window memory | two buckets, constant regardless of sample count | `RollingCounts` |
| Latency histogram | 16 fixed bounds plus one overflow bucket | `time::LATENCY_BUCKETS_MS` |
| EWMA state | one `u64`, no sample retention | `time::Ewma` |
| Concurrency / request rate / token rate | per scope; `0` means unlimited | `ScopeLimits`, `Scope::try_acquire` |
| Queue depth | `ScopeLimits::max_queued`; `0` means no queue at all | `Scope::join_queue` |
| Queue wait | caller-supplied budget, mandatory (3.2); `Duration::ZERO` never waits | `AdmissionController::reserve_queued` |
| Token-bucket level | capped at capacity, so a refund cannot mint burst | `TokenBucket::refund` |

**Not enforced here.** Listing these as limits would be a false assurance:

| Input | Status |
|---|---|
| Prompt bytes, message count, content-part count | No cap. `CanonicalRequest` accepts whatever it is handed; bounding belongs at the wire boundary (3.2). |
| Tool count, tool schema size, response-format schema size | No cap. |
| Embedding vector length and count | No cap, in `CanonicalEvent::Embedding` or in the accumulator. |
| `ResponseAccumulator` total size | No cap; grows with the stream. |
| Distinct tool-call indices per response | No cap; lookup is a linear scan, so cost is quadratic. |
| Targets, bindings, grants, aliases in a snapshot | No cap. `route` is O(permitted targets × merged rules) per request. |
| Admission tenant/principal scope cardinality | No cap and no eviction. |
| `ScoreTerms` clamping | Applied by `PolicySnapshot::score` only, not by any constructor. |
| Deadline magnitude | Not validated; a caller may construct an arbitrarily distant `Deadline`. |

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is instead a seeded, deterministic
mutation engine in `hypellm-test-corpus::fuzz`, driven from ordinary
`tests/fuzz.rs` targets so that `cargo test` runs it and a failing seed is
reproducible by number rather than by corpus file.

All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table.

This crate's obligation under specification 18.2 is the *property* half —
"router selection has property tests for determinism, precedence, deny/pin
behavior, and overflow" — and that layer exists: `tests/properties.rs`, 14
properties over Appendix B, each run across 400 seeded cases from a
deterministic generator. `tests/capability.rs` adds sixteen more over the
specification 26.1 contract and the 26.4 warmth ladder — the document-modality
filter, the effort multiplier at reservation, the quality floor, and the three
guarantees about what a client hint cannot do.

| Property | Invariant |
|---|---|
| `equal_inputs_produce_equal_ordered_candidates` | Equal (request, snapshot, live) ⇒ equal ordered candidates |
| `candidate_order_does_not_depend_on_the_order_bindings_were_written` | No map-iteration order leaks into the result |
| `the_tie_break_is_seeded_by_request_id_and_nothing_else` | The one permitted source of nondeterminism |
| `adding_a_deny_never_adds_a_candidate` | Deny monotonicity |
| `a_lower_precedence_allow_cannot_re_enable_a_higher_precedence_deny` | A higher-precedence deny is sticky downward |
| `a_pin_without_fallback_admits_only_the_pinned_target` | Pin semantics |
| `a_healthy_pin_always_outranks_its_own_fallbacks` | — |
| `an_unavailable_pin_without_fallback_fails_closed` | Hard pins fail closed |
| `scores_never_overflow_however_extreme_the_weights` | Saturating fixed-point arithmetic |
| `the_candidate_order_is_a_total_order` | — |
| `every_permitted_target_is_either_a_candidate_or_carries_an_exclusion` | No target disappears unexplained |
| `every_reservation_is_released_exactly_once` | Reservation conservation |
| `committing_and_dropping_the_same_reservation_releases_it_once` | — |
| `concurrency_is_never_exceeded_under_interleaved_reservations` | — |

The capability contract's own properties, in `tests/capability.rs`:

| Property | Invariant |
|---|---|
| `a_document_request_is_excluded_from_a_target_without_the_document_modality` | Modality is a filter, and it is applied before anything is started |
| `a_document_url_is_never_dereferenced_and_never_influences_routing` | Two requests differing only in a document URL produce identical decisions |
| `a_document_costs_a_configured_constant_rather_than_its_byte_length` | The estimate does not depend on a document's size |
| `a_reasoning_effort_reserves_its_multiplied_output_budget` | The multiplier is applied at reservation, not after |
| `an_unsupported_effort_tier_excludes_rather_than_downgrades` | No silent downgrade |
| `an_unset_effort_is_never_refused_by_a_target_that_declares_tiers` | `Unset` is the absence of a request, not a tier |
| `a_quality_floor_excludes_a_lower_tier_target_even_when_it_is_cheaper` | A floor is a filter, not a preference |
| `a_quality_floor_and_a_cost_ceiling_are_independent` | Neither is derived from the other |
| `a_target_that_does_not_declare_the_aliases_verb_is_excluded` | The verb cannot be derived from operation and modality |
| `an_alias_that_declares_no_verb_routes_exactly_as_it_did_before` | The compatibility promise |
| `the_warmth_ladder_spacing_exceeds_the_maximum_hint_bonus` | The arithmetic every hint guarantee rests on |
| `a_client_hint_never_makes_an_ineligible_target_eligible` | — |
| `a_client_hint_never_outranks_a_warmer_target` | …and does break a tie between equally warm ones |
| `a_client_hint_never_outranks_a_priority_binding` | Rank dominates |
| `a_cold_rank_zero_target_still_outranks_a_warm_rank_one_target` | Warmth is a preference, not a filter |
| `an_infeasible_residency_class_excludes_and_every_other_class_does_not` | If "not running" excluded, nothing would ever start |

Fuzz targets this module still needs:

| Target | Property | Status |
|---|---|---|
| `id_validate` | Arbitrary bytes into every `*Id::new`: never panics; accepts exactly the documented alphabet and length. | Required, not yet implemented (§21) |
| `request_id_parse` | Arbitrary text into `RequestId::parse`; round-trips with `to_hex` for accepted input. | Required, not yet implemented (§21) |
| `policy_route` | Structured snapshot/request/live triples: never panics; repeated and input-permuted evaluation yields identical ordered candidates; no denied or non-pinned target ever appears. | Required, not yet implemented (§21) |
| `score_terms` | Arbitrary `i64` terms: `clamped().total()` never panics under overflow checks and `non_rank_total().abs() < RANK_UNIT`. | Required, not yet implemented (§21) |
| `event_accumulator` | Arbitrary `CanonicalEvent` sequences: tool-call identity and ordering preserved; accumulated size stays proportional to input. | Required, not yet implemented (§21) |
| `netaddr_classify` | Arbitrary 4- and 16-byte addresses: no profile ever permits `Metadata`; an IPv6 form carrying an IPv4 address classifies identically to that address. | Required, not yet implemented (§21) |
| `admission_reserve` | Arbitrary reserve/commit/drop interleavings: `acquired == released` once idle; no scope exceeds `max_concurrency`. | Required, not yet implemented (§21) |
| `capped_truncate` | Arbitrary strings and caps: never exceeds the cap, never splits a UTF-8 boundary. | Required, not yet implemented (§21) |
| `format_rfc3339` | Arbitrary `u64` milliseconds: never panics, always produces a well-formed RFC 3339 UTC timestamp. | Required, not yet implemented (§21) |

The generator in `tests/properties.rs` is a seeded xorshift, not a shrinking
property framework — specification 4 admits no such dependency. A failure is
reproducible by seed number, but it is reported at whatever size the generator
produced rather than minimised, so diagnosing one means reading the printed
case. The per-module `#[cfg(test)]` blocks and `lib.rs`'s `invariant_tests`
remain, and cover the specific scenarios an author thought of; the property
layer covers the ones nobody did.

## Public API

See `lib.rs`. Notes for a caller:

- [`LiveState`] is the seam. Implement it to inject health; `IdealLiveState`
  reports everything healthy and is what policy simulation uses.
- `rbac::Role` is re-exported as `ManagementRole` because `canonical::Role` is a
  message role. The two would read identically at a call site and mean entirely
  different things.
- Nothing in the public surface can hold a secret. `Sensitive<T>` is provided so
  that callers which do can render safely by default.
- `AdmissionController::reserve` never waits; `reserve_queued` may, and is what
  the request path uses. Both return the same rejections, so a caller that does
  not want to block loses nothing but the queue. `PriorityClass` and
  `set_class`/`class_for` carry specification 12's queue ordering; the class is
  a property of the *requests* a scope covers, which is why it is stored beside
  the scopes rather than inside them.
- `HealthRegistry::set_queue_allowance` must be kept in step with the target
  quota's `max_queued`. Routing filters on capacity, so a target that will queue
  has to stay *eligible* while it can queue — otherwise the request is excluded
  by policy before admission ever gets to make it wait.
- `ExclusionReason::all`, `Operation::all`, `ErrorCode::all`,
  `Permission::all`, `Role::all`, `ProviderFamily::all`, and
  `UpstreamErrorClass::all` exist so that exhaustiveness is testable from
  outside the crate; adding a variant without a producer or a mapping fails an
  existing test rather than shipping as dead documentation.

[`LiveState`]: src/policy.rs
