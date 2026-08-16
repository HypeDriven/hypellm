# Module: wire-json

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace. |
| External dependencies | None. `Cargo.toml` has no `[dependencies]` section at all — not even a workspace path dependency. Rust standard library only. |
| Fuzz targets | None implemented. Required targets are listed under "Fuzz targets" below. |

This crate is a leaf of the dependency graph and is depended on by
`hypellm-adapters`, `hypellm-admin-api`, `hypellm-auth`, `hypellm-net`, `hypellm-router`,
`hypellm-store`, and `hypellm-telemetry`. Every JSON byte that crosses a trust
boundary — client request bodies, provider responses, streaming event payloads,
OIDC token responses, structured log lines, stored records — passes through this
parser. A defect here is reachable from every ingress in the system.

## Scope and the "one strict grammar, no accommodation" rule

Specification 18.1 asks for a "small strict JSON tokenizer/parser/serializer with
depth and size limits". Specification 3.1 requires the request lifecycle to
reject ambiguous input rather than normalise it. This module is the single
implementation of RFC 8259 in the workspace; there is deliberately no second,
more permissive path for "difficult" upstreams.

What it does:

| Concern | Reference | Why the router needs it |
|---|---|---|
| Strict RFC 8259 parsing | RFC 8259 | Client bodies, provider responses, management payloads |
| Explicit per-call-site limits | Specification 3.2 | Bounded work on adversarial input |
| Ordered value tree | Specification 6, 11.1 | Determinism; never infer ordering from map iteration |
| Compact serialization | Specification 7.1, 14 | Provider requests and streaming frames |
| Key-sorted canonical serialization | Specification 11.1 | Configuration digests, audit records |
| Content-free errors | Specification 10, 8.2 | Prompts are sensitive; error codes are a stable client contract |

What it deliberately does **not** do:

- **No incremental or streaming parse.** `parse` consumes one complete document
  and rejects trailing content. Specification 14 assigns frame boundary
  detection to `wire-sse`; this crate then parses each delimited event whole
  under `Limits::STREAM_EVENT`. There is no resumable reader, and callers must
  not treat `UnexpectedEnd` as "read more bytes" without their own framing.
- **No schema validation.** `field_str`, `field_i64` and friends check one field
  at a time. Tool-call argument schemas (specification 5.1, 14) are the
  adapters' problem, and the router never executes them.
- **No dialect support.** No JSON5, NDJSON, JSON Pointer, JSON Patch, JSONPath,
  comments, or BSON. Each is a grammar an attacker could aim at a component that
  understands it while another does not.
- **No byte-preserving passthrough.** The parser decodes into a `Value`; the
  serializer re-encodes. Input bytes are not retained. A document that goes in
  and comes out is semantically equal but not necessarily byte-equal (see the
  number-fidelity threat below). Anything that must be compared or digested is
  compared over `to_canonical_vec`, never over reserialized-and-diffed bytes.
- **No cryptography and no digesting.** Canonical bytes are produced here;
  hashing them is `hypellm-crypto`'s job.
- **Not RFC 8785 (JCS).** "Canonical" here means: recursively key-sorted, UTF-8,
  compact, with Rust's shortest-round-trip float formatting. That is stable
  across processes and builds of this workspace, which is what a configuration
  digest needs, but it is *not* JCS — JCS would render `1.0` as `1`. Do not
  assume a digest computed here matches one computed by an external tool.

## Threat notes

- **Parser differentials are the primary threat, not memory safety.** The router
  reads a document to make an authorization and routing decision; an upstream
  reads the same document to produce output. If the two disagree about what the
  bytes mean, the attacker picks the interpretation. `parse` therefore rejects
  every lenient extension rather than normalising it: comments, trailing commas,
  single-quoted strings, unquoted keys, `NaN`/`Infinity`, leading `+`, leading
  zeros, bare `.5`, `1.`, `1e`, hex literals, a UTF-8 BOM, form feed / vertical
  tab / NBSP as whitespace, raw C0 control characters inside strings, invalid
  UTF-8, lone surrogates, and trailing content after the top-level value. Each
  has a test in `parse.rs`. **Adding an accommodation for a misbehaving provider
  reopens this class and is a two-person-review change (specification 21.1).**
- **Duplicate keys are refused, not resolved.** `{"model":"cheap","model":"expensive"}`
  is a routing-decision attack: this parser takes the first occurrence, most
  JavaScript upstreams take the last. `reject_duplicate_keys` is `true` in all
  three presets and the document is rejected outright rather than the router
  picking a side. The `false` setting exists for callers parsing documents this
  workspace itself produced; **setting it on a data-plane path silently restores
  first-wins semantics and the differential with it.**
- **Number fidelity is a semantic hazard the type system only half prevents.**
  Integers that fit `i64` are kept exact (token counts and budgets are money —
  see `value.rs`). An integer larger than `i64::MAX` is *not* rejected; RFC 8259
  permits it, so it degrades to `f64`. `as_i64`/`field_i64` then fail with a
  `TypeError`, which is the intended fail-closed path — but `opt_field_f64` will
  hand back a silently rounded value, and re-serializing that value emits
  `1.2345678901234567e19` where the input said `12345678901234567890`. Any code
  that compares a normalized request digest, or forwards a numeric field it did
  not itself validate, must go through the integer accessors.
- **Quadratic work in duplicate-key detection.** `Object` is a `Vec` of pairs and
  `contains_key` is a linear scan, so parsing an object costs O(n²) key
  comparisons. Per object this is capped by `max_object_entries`, but a single
  16 MiB body can carry a few hundred maximally-sized objects, and the total
  comparison count reaches the order of 10^10. String comparison rejects on
  length first, so this is slow rather than fatal, and the HTTP layer's
  endpoint-specific body cap (specification 3.2) is the real mitigation — but on
  the default 16 MiB limit this is the cheapest known way to burn router CPU
  with one request. It is the first thing a `json_parse_arbitrary` fuzz target
  with a work budget should find, and it is why the adversarial-corpus
  requirement in specification 19.1 names deep JSON explicitly.
- **Recursion depth is bounded on the way in, not on the way out.**
  `parse_value` recurses, and `max_depth` (64 by default) bounds it. Nothing
  bounds the recursion in `write_value`, `Value::sort_keys_recursive`, or the
  compiler-generated `Drop` glue for a nested `Value`. For values that came from
  `parse` this is safe by construction. For values assembled programmatically it
  is not: a caller that builds a deeply nested tree in a loop can overflow the
  stack during serialization or drop. With `panic = "abort"` in the release
  profile, that is a process abort, not a request failure.
- **`with_max_depth` has no ceiling.** It accepts any `u32`. A caller that
  derives a limit from configuration rather than naming a preset can configure a
  depth that overflows the parser's stack before `DepthExceeded` ever fires.
  Callers must use `Limits::DEFAULT`, `SMALL`, or `STREAM_EVENT`, narrowing only.
- **Errors must stay content-free.** Specification 10 makes prompts, tool
  arguments, and provider bodies sensitive by default. `JsonError` carries an
  `ErrorKind` and a byte offset and nothing else; `Display` never quotes the
  input; `ErrorKind::code()` returns a stable string for the specification 8.2
  error contract. `TypeError` names a field path and the expected and found
  *type names* — never the value. The `error_never_echoes_input` and
  `type_error_names_field_without_echoing_value` tests guard this. **A caller
  that passes an attacker-supplied key name into `field_str` puts that name into
  `TypeError::path`; field names in accessor calls must be code literals.**
- **The serializer fails soft on non-finite floats.** A `Number::Float` holding
  NaN or an infinity is written as `null`, because JSON cannot express it and
  emitting `NaN` would produce a document this very parser rejects. Parsed input
  can never reach that state (`NumberOutOfRange`), so this only fires for values
  built in-process — but it means an arithmetic bug upstream of serialization
  becomes a `null` field at a provider rather than a loud error.
- **Output is not HTML- or script-safe.** `write_string` escapes the C0 range
  and, defensively, U+2028/U+2029 — but not `<`, `>`, `&`, or `/`. Output must
  never be interpolated into an HTML or `<script>` context. Specification 15.1
  already forbids HTML string injection in the SPA (build DOM nodes); this crate
  does not provide a second line of defence for code that ignores that.
- **`max_input_bytes` is a check on an already-materialized slice.** `parse`
  takes `&[u8]`, so by the time the limit is enforced the caller has the bytes in
  memory. Memory bounding is the HTTP body reader's responsibility
  (specification 3.2, default 16 MiB, endpoint-specific); this limit is a
  second, in-depth check and a bound on parsing work, not an allocation guard.
- **Panics.** No `unwrap`, `expect`, `panic!`, `unreachable!`, or integer
  division appears outside `#[cfg(test)]`. Slice indexing is used in five places
  in `parse.rs` and `write.rs`, each immediately preceded by the bounds check
  that makes it total. All arithmetic on `pos` is bounded by `max_input_bytes`,
  well under `usize` range; `overflow-checks` is on in the release profile, so a
  regression here aborts rather than wraps.

## Limits

Enforced. Every parse call names a `Limits` value; the three presets are the
only ones a data-plane caller should use.

| Bound | Field | DEFAULT | SMALL | STREAM_EVENT | Enforced by |
|---|---|---|---|---|---|
| Total input | `max_input_bytes` | 16 MiB | 1 MiB | 2 MiB | `parse()` length check before the BOM, UTF-8, and grammar passes → `InputTooLarge` |
| Nesting depth | `max_depth` | 64 | 32 | 32 | depth counter entering `parse_array` / `parse_object` → `DepthExceeded` |
| Decoded string | `max_string_bytes` | 8 MiB | 64 KiB | 1 MiB | `parse_string`: authoritative check on the decoded `String` at the closing quote, plus incremental checks per escape and per literal run → `StringTooLong` |
| Elements per array | `max_array_items` | 100 000 | 10 000 | 4 096 | `parse_array` before each element → `ArrayTooLong` |
| Entries per object | `max_object_entries` | 10 000 | 2 000 | 512 | `parse_object` before each entry → `ObjectTooLarge` |
| Duplicate keys | `reject_duplicate_keys` | reject | reject | reject | `parse_object` linear `contains_key` → `DuplicateKey` |

`DEFAULT` matches the specification 3.2 row "JSON depth / string length — 64
levels / 8 MiB default" and the 16 MiB inbound-body default. `STREAM_EVENT` is
the bounded-event-size requirement of specification 14. `with_max_input_bytes`
and `with_max_depth` narrow a preset; nothing in the type prevents them widening
one.

Not enforced — stated here because a false assurance is worse than a known gap:

| Not bounded | Consequence | Mitigation today |
|---|---|---|
| Numeric token length | A 16 MiB run of digits is scanned and handed to `f64::from_str` | Bounded transitively by `max_input_bytes` only |
| Serialization / sort / drop depth | Stack overflow on a programmatically built deep tree | Parsed values are bounded by `max_depth`; built values are the caller's responsibility |
| Ceiling on `max_depth` | A configured depth can exceed the usable stack | Use the presets; narrow only |
| Total node count / allocated bytes of the value tree | Peak memory is a multiple of input size, not a fixed cap | Bounded transitively by `max_input_bytes` |
| Output size of `to_string` / `write_to` | Escaping expands up to 6x (one control byte becomes a six-byte unicode escape) | Per-stream watermark (specification 3.2, 256 KiB) is enforced by the caller |
| `to_canonical_string` working set | Clones the whole value before sorting: ~2× peak | Canonical form is a control-plane path, under `Limits::SMALL` |

## Fuzz targets

`tests/fuzz.rs` — six targets, run by `cargo test -p wire-json`, driven by the
seeded mutation engine in `hypellm-test-corpus::fuzz` over `hypellm-test-corpus::json`.
There is no `fuzz/` directory and no libFuzzer harness, because specification 4
admits no such dependency; a failing case is reproducible by seed number.

| Target | Property asserted |
|---|---|
| `no_mutation_of_the_corpus_panics_the_parser` | Termination and no panic |
| `the_depth_limit_holds_on_mutated_input` | `max_depth` is exact |
| `deeply_nested_input_is_refused_rather_than_overflowing_the_stack` | The recursion bound is a refusal, not a crash |
| `an_oversize_document_is_refused_without_being_buffered_whole` | Size is checked before allocation |
| `truncation_at_every_offset_is_handled` | Every prefix of a valid document is a clean error |
| `random_bytes_are_rejected_without_panicking` | Unstructured input |

Still outstanding:

Specification 21 requires a JSON fuzz layer and specification 18.2 requires
protocol parsers to be fuzzed. The targets this module needs, in priority order:

| Target | Property asserted | Status |
|---|---|---|
| Arbitrary parsing | Mutated corpus values terminate with bounded work under every parser profile | Implemented in `tests/fuzz.rs` |
| Limits | Every accepted mutation remains within depth, string, array and object bounds | Implemented in `tests/fuzz.rs` |
| Round trip | Parse, serialize and parse preserves accepted values | Implemented in `tests/fuzz.rs` |
| Canonical stability | Object key order does not alter canonical output | Implemented in `tests/fuzz.rs` |
| Strictness | Mutations cannot enable duplicate keys or unsupported grammar extensions | Implemented in `tests/fuzz.rs` |
| Prefixes and escapes | Truncated prefixes terminate safely and escaped strings round-trip | Implemented in `tests/fuzz.rs` |

Until these exist, the adversarial-corpus gate in specification 19.1 and the
"known attack corpus produces bounded work" gate in 21.1 are unmet for JSON.

## Public API

See `lib.rs`. Four modules, re-exported flat: `Limits`; `parse` / `parse_str` /
`JsonError` / `ErrorKind`; `Value` / `Number` / `Object` / `TypeError` with
`object` and `array` constructors; `to_string` / `to_vec` / `write_to` /
`to_canonical_string` / `to_canonical_vec` / `write_string` / `escape_string`.

The surface is intentionally narrow. There is no derive macro and no
serde-style typed mapping (specification 4.1 forbids proc macros outright), no
streaming reader, no mutation API beyond `Object::push` / `push_opt` /
`sort_keys`, and no pretty-printer. `Object::push_opt` exists because
specification 5.1 distinguishes an unset sampling parameter from a null one, and
omitting a key is a different message to a provider than sending `null`.
