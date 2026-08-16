# Module: hypellm-test-corpus

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `src/lib.rs`; `unsafe_code = "forbid"` inherited from the workspace lints. |
| External dependencies | None. `Cargo.toml` declares no `[dependencies]` and no `[dev-dependencies]` — not even workspace path dependencies. Rust standard library only. |
| Fuzz targets | **None exist.** This crate is the declared home of the fuzz corpora required by specification 21; the required targets are listed under [Fuzz targets](#fuzz-targets) and are all unimplemented. |

Security owns this crate — not because it is test code, but because its contents
are the *oracle* for the security suite (specification 21: SSRF, smuggling,
CSRF/CORS, tenant isolation, secret leakage). A weakened expectation here is
indistinguishable from a passing test. Platform owns the CI wiring and the
recording tooling.

## Current state

The crate holds six data modules and one expectation type. Nothing in it
performs I/O, and nothing in it asserts.

| Module | Contents | Specification |
|---|---|---|
| `outcome` | `Outcome`: accept / incomplete / reject-with-one-of-these-codes | 21 |
| `http1` | 45 request-head vectors, including the request-smuggling corpus | 10.1, 21 |
| `json` | 44 document vectors: grammar, extensions, escapes, duplicate keys | 3.1, 21 |
| `sse` | 22 stream vectors with the events each must dispatch | 14, 21 |
| `limits` | 11 boundary inputs generated at the specification 3.2 bounds | 3.2 |
| `golden` | 11 responses, 6 streams, 1 embeddings body, 15 failures, in 3 dialects | 7, 21 |
| `harness` | 5 versioned harness-compatibility profiles | 8.1 |

Every vector carries a stable name, the raw bytes, the required outcome, a
rationale, and the specification clause it derives from. A corpus whose entries
do not say what should happen can only find panics; it cannot find a parser that
accepts something it must refuse.

Expectations are spelled as the stable *error code strings* the parser crates
publish (`HttpErrorKind::code`, `wire_json::ErrorKind::code`,
`SseError::code`, `UpstreamErrorClass::as_str`) rather than as enum values.
Specification 8.2 makes those codes part of the client contract, so pinning the
code catches a rename that changes what a client sees — and it is what allows
this crate to stay dependency-free.

### Consumers

| Crate | Test file | What it checks |
|---|---|---|
| `wire-http1` | `tests/corpus.rs` | Every vector's outcome and code; smuggling vectors additionally force a connection close; boundary cases; every prefix of an accepted vector reports incomplete |
| `wire-json` | `tests/corpus.rs` | Every vector's outcome and code; errors do not echo the document; depth boundaries |
| `wire-sse` | `tests/corpus.rs` | Every vector's outcome and dispatched events; byte-at-a-time delivery produces identical events; buffer boundaries; failures are sticky |
| `hypellm-adapters` | `tests/golden_corpus.rs` | Every golden response, stream, embedding, and failure decodes as recorded; no provider text reaches the client detail |

Each of those crates takes this one as a `[dev-dependencies]` path dependency.
Because this crate declares no dependencies of its own, that is possible from
`wire-json` and `wire-http1` as well, with no dependency cycle anywhere.

### Not migrated

The parser crates still carry their own inline copies of most of these vectors
(`wire-http1/src/request.rs` and its `smuggling_tests` module,
`wire-json/src/parse.rs`, `wire-sse/src/parse.rs`). They are deliberately left
in place: deleting working coverage in exchange for a refactor is not an
improvement, and specification 21.1 requires two-person review for parser
changes. Consolidating those suites onto this corpus is follow-up work that has
**not** been done.

`hypellm-adapters::testing` remains the source of canonical request fixtures and
is deliberately `pub` rather than `#[cfg(test)]`. This crate does not duplicate
it.

## Scope, and the "the corpus is not a harness" rule

Specification 18.1 assigns this crate "golden requests/responses, malformed
input, provider stream fixtures". Specification 21 requires integration tests to
run against *recorded* golden servers, and specification 8.1 requires versioned
harness-compatibility profiles rather than a claim of universal compatibility.

| Holds | Why here |
|---|---|
| Golden client requests and expected canonical forms | One definition shared by adapter, wire, and compatibility suites (specification 21, `Integration`) |
| Recorded provider responses and SSE event streams | Deterministic replay without network egress (specification 21, `Integration`) |
| Malformed/adversarial input corpora | Smuggling, header fragmentation, deep JSON, oversized SSE (specification 19.1) |
| Harness-compatibility profile fixtures | Per-profile endpoints, headers, SSE detail, tool-call and cancellation behavior (specification 8.1) |

This module deliberately does **not**:

- **Perform I/O.** It opens no sockets, resolves no hosts, spawns no server, and
  reads no files at runtime. Fixtures are compile-time constants, and the
  boundary inputs of `limits` are built in memory by the test that asked for
  them — specification 4.1 forbids implicit file discovery, and a corpus that
  resolves paths at runtime is a path-traversal surface inside the test harness.
- **Assert.** It supplies inputs and expected outputs; the comparison lives in
  the crate under test. A corpus that also owns the assertion can silently
  redefine what "correct" means for every consumer at once. The tests inside
  this crate check the corpus against *itself* — unique names, non-empty codes,
  a rationale on every entry, boundary generators producing the sizes they
  claim — and never against a parser.
- **Replay against live providers.** The opt-in live-sandbox tests of
  specification 21 are not driven from here; this crate has no credentials, no
  endpoints, and no transport.
- **Ship into the router binary.** It is a `[dev-dependencies]`-only member.
  `hypellm-router` must never depend on it.

## Threat notes

- **The corpus is a permanent, greppable plaintext log.** A recorded golden
  response originates from a real provider exchange, which carries
  `Authorization` headers, API keys, organization and account identifiers,
  cookies, and real prompt/completion text. Specification 10 keeps credentials
  behind opaque handles and specification 17 keeps prompt bodies out of logs by
  default — a fixture committed unredacted defeats both, permanently and in
  version history. **Every fixture in `golden` is synthetic and hand-written for
  this reason**; the only key-shaped string in the crate is
  `sk-hypellm-golden-not-a-real-key`, and a unit test fails if a fixture grows a
  string that looks like a live credential. If a recording tool is ever built,
  redaction MUST happen at capture time, not at review time; a reviewer scanning
  a 4 MiB SSE transcript is not a control.
- **Goldens are a trust anchor, and updating them is a security change.** The
  assertion that a smuggling vector yields `conflicting_framing` lives in this
  crate as data. A routine "refresh the goldens" commit that turns an expected
  rejection into an expected acceptance disables a security test while leaving
  the suite green. Changes to attack-corpus expectations require the same
  two-person review specification 21.1 mandates for parser changes. `http1`
  exposes `smuggling()` precisely so that selection is reviewable as a unit.
- **Fixture drift produces false assurance.** If this crate built its own
  `CanonicalRequest` instead of using `hypellm_adapters::testing`, the golden
  suite would validate a request the router never sends. It does not build one.
- **A self-confirming corpus proves nothing.** A malformed-input corpus
  populated by sampling what the in-repo parser already rejects cannot surface a
  parser differential. Vectors here are derived from the specification and from
  external references (smuggling variants, RFC 8259 extensions, SSE framing
  edge cases), and several are inputs where two plausible readings disagree —
  that disagreement is the finding.
- **Attack fixtures are inert data and must stay that way.** The corpus contains
  byte sequences engineered to be misinterpreted. None of them may be fed to the
  configuration parser as configuration, used to construct a destination, or
  interpolated into an endpoint. Specification 11.1 admits no includes and no
  environment expansion precisely so that data cannot become directives; the
  same rule binds test data.
- **Unbounded corpus growth is a build-time denial of service.** Fuzz corpora
  and recorded streams grow monotonically unless minimized. The bounded-work
  discipline of specification 3.2 applies to the repository too, which is why
  the 32 KiB, 64 KiB, and 256 KiB boundary inputs are *generated* rather than
  committed.
- **Test-only code reaching the data plane.** Fixtures name plausible endpoints
  and model identifiers. If this crate ever became a normal dependency of
  `hypellm-router`, those values would be linked into the production binary. The
  dependency direction is the control.

## Limits

| Input / resource | Required bound | Enforced by | Status |
|---|---|---|---|
| Single committed fixture | Small enough to review inline; the largest is under 1 KiB | Review | **Not mechanically enforced** — no size constant exists |
| Total corpus on disk | Bounded and minimized per fuzz target; no unminimized crash inputs retained | none | **Not enforced** — no fuzz corpus exists |
| HTTP head fixtures | Must span the 32 KiB default and its `+1` rejection case (specification 3.2) | `limits::http_head_size_cases` | **Enforced**, and `wire-http1/tests/corpus.rs` asserts the constant still equals `Limits::DEFAULT.max_head_bytes` |
| HTTP header count | Must span the 100-field default and its `+1` rejection case | `limits::http_header_count_cases` | **Enforced**, constant cross-checked in the consumer test |
| JSON depth fixtures | Must span the 64-level bound in both array and object form | `limits::json_depth_cases` | **Enforced**, constant cross-checked in the consumer test |
| SSE stream fixtures | Must span the 256 KiB per-stream buffered-data bound (specification 3.2, 14) | `limits::sse_line_length_cases` | **Enforced**, constant cross-checked in the consumer test |
| JSON body size | Must span the 16 MiB body bound and the 8 MiB string bound | none | **Not covered** — a 16 MiB generated input would dominate the suite's runtime; the smaller bounds stand in for it |
| SSE per-event size | Must span the 1 MiB accumulated-event bound | none | **Not covered** |
| Runtime allocation | Zero for the static vectors; the `limits` generators allocate their input and nothing else | Construction | **Enforced by construction** |
| Runtime file reads | Zero (specification 4.1, no implicit file discovery) | Construction | **Enforced by construction** — the crate has no `std::fs` use |

Fixtures that *exceed* a production limit are expected and required — they are
how rejection at the boundary is tested. The bound in this table is on the
artifact committed to the repository, not on the value the parser is asked to
accept.

### The limits are restated, not linked

`limits.rs` declares `HTTP_DEFAULT_MAX_HEAD_BYTES`, `JSON_DEFAULT_MAX_DEPTH`
and friends as its own constants, because a dependency-free crate cannot read
`wire_http1::Limits::DEFAULT`. Nothing at compile time keeps the two in step.
The consumer tests assert equality at runtime, so a bound changed in one place
and not the other fails the suite rather than silently producing a "boundary"
case that no longer sits on the boundary — but the check exists only where a
consumer test was written.

## Fuzz targets

This crate is the fuzz engine as well as the corpus home. `src/fuzz.rs` is a
seeded, deterministic mutator — there is no `fuzz/` directory and no libFuzzer
harness, because specification 4 admits no such dependency — and consumers drive
it from ordinary `tests/fuzz.rs` targets so that `cargo test` runs them and a
failing case is reproducible by seed number rather than by corpus file.

Targets written against it today: `wire-json` (6), `wire-http1` (7), `wire-sse`
(8), `hypellm-config` (7), `hypellm-store` (7). The table below is specification
21's full required set; the "Seeds available" column says what this crate can
supply for the ones still outstanding.

| Target | Corpus | Seeds available | Specification |
|---|---|---|---|
| `http1_request` | Header fragmentation, smuggling, chunked framing | `http1::all`, `limits::http_head_size_cases` | 21 (`Fuzz`), 19.1 |
| `json_value` | Depth, string length, number edge cases, bounded work | `json::all`, `limits::json_depth_cases` | 21 (`Fuzz`), 3.2 |
| `sse_events` | CRLF/LF mixing, multi-line `data`, comments, oversized events, terminal markers | `sse::all`, `limits::sse_line_length_cases` | 21 (`Fuzz`), 14 |
| `config_grammar` | Native line-oriented records, unknown fields, quoting | **none** | 21 (`Fuzz`), 11.1 |
| `provider_events` | Per-provider-family stream decoding and error mapping | `golden::streams`, `golden::failures` | 21 (`Fuzz`), 7.1 |
| `admin_api` | Management request bodies and schema validation | **none** | 21 (`Fuzz`), 16 |
| `state_recovery` | Framed-log replay, corrupt and truncated tails | **none** | 21 (`Fuzz`), 11.2 |

**Required, not yet implemented:** all seven.

Known documentation discrepancy: `crates/hypellm-crypto/MODULE.md` lists
`sha256_stream`, `base64_roundtrip`, and `hex_roundtrip` as fuzz targets and
points at this crate. Those targets do not exist here or elsewhere. That entry
overstates the current state and should be corrected to the "required, not yet
implemented" form used above.

## Honest gaps

Stated plainly, because a reader who trusts this corpus needs them before they
trust a passing suite.

1. **Nothing was recorded from a live provider.** Every fixture in `golden` is
   synthetic. A passing run proves the decoders handle the documented shapes; it
   cannot prove a provider still sends them. Closing this needs a recording tool
   with capture-time redaction, which does not exist.
2. **No coding harness has been run against the router.** The profiles in
   `harness` are the specification 8.1 *classes* written out as data. No named
   third-party tool has been measured, and the three profiles describing
   third-party tooling each carry that statement in their
   `known_limitations` — a unit test fails if one drops it. Specification 8.1's
   requirement to include "representative popular coding harnesses selected at
   release time" is unmet.
3. **Nothing binds the harness profiles to the router's route table.** The
   profile tests confirm each endpoint is one specification 8 defines; no test
   starts a listener and confirms the router answers it.
4. **Four of specification 21's seven fuzz rows have no target.** Provider
   events, the management API, and the two corpora marked "none" above are
   still unfuzzed; see the table.
5. **The parser crates' inline vectors are not migrated.** See "Not migrated".
6. **The `/v1/responses` fixtures cover only the documented event sequence.**
   Specification 8 marks that surface MUST for new integrations and requires
   "streaming event normalization"; the corpus now records it in both framings,
   including the `.done` events that repeat delivered content and the absence of
   a `[DONE]` sentinel. What it still cannot cover is the rest of the event
   vocabulary — reasoning, web-search, and file-search items — which the decoder
   ignores by design and no fixture exercises.
7. **Reasoning content has no golden fixture.** Both adapters decode
   `reasoning_content` and `thinking` blocks; no recorded fixture exercises
   them, so `ExpectedCompletion::reasoning` is empty everywhere.
8. **Config-grammar, admin-API, and state-recovery corpora do not exist.**
   Specification 11.1, 16, and 11.2 respectively.

## Public API

Data and lookups only. No trait for "run a golden test", no comparison helpers,
no configurable recording — those belong to the consuming crate or to a separate
recording tool outside the workspace test path.

```text
outcome::Outcome                       accept / incomplete / reject(codes)
http1::{HttpVector, HttpCategory}      all(), in_category(), smuggling(), by_name()
json::{JsonVector, JsonCategory}       all(), in_category(), by_name()
sse::{SseVector, SseCategory,          all(), in_category(), by_name()
      ExpectedEvent}
limits::BoundaryCase                   http_head_size_cases(), http_header_count_cases(),
                                       json_depth_cases(), sse_line_length_cases(), all()
golden::{GoldenResponse, GoldenStream, responses(), streams(), embeddings(), failures(),
         GoldenEmbeddings, GoldenFailure,   response_by_name(), stream_by_name()
         ExpectedCompletion, ExpectedFinish,
         ExpectedToolCall, ExpectedEmbedding,
         StreamFrame, FailurePath, GoldenFamily,
         GoldenDialect}
harness::{HarnessProfile, HarnessEndpoint,  all(), by_id()
          Requirement, StreamingProfile,
          ToolCallingProfile, ModelListing,
          Cancellation}
```
