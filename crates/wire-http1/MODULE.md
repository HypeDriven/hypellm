# Module: wire-http1

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library only; no path dependencies on other workspace crates. |
| Fuzz targets | `tests/fuzz.rs` — 7 targets over the head parser and framing, driven by `hypellm-test-corpus::fuzz`. See [Fuzz targets](#fuzz-targets). |

## Scope and the "no normalization" rule

Specification 18.1 assigns this crate "strict bounded HTTP/1.1 server/client
state machines where platform edge does not supply normalized transport", and
specification 25 fixes the version envelope: "HTTP/1.1 inside normalized
boundary for v1; edge provides HTTP/2/3."

What this module implements is the byte-level framing layer in both directions:

| Surface | Reference | Why the router needs it |
|---|---|---|
| Request head parsing | RFC 9112 §2–§6 | The router's outermost trust boundary; produces `RequestHead` |
| Response head parsing | RFC 9112 §4 | A provider is untrusted (spec 8.2 `upstream_invalid_response`) |
| Body framing | RFC 9112 §6 | Fixed-length, `chunked`, and close-delimited decoding for streams |
| Request encoding | spec 7 | Adapter-side serialization to a configured authority |
| Response encoding | spec 8.2 | Status line, headers, and framing the router itself chose |
| Error → status mapping | spec 8.2 | Stable codes with no echo of the offending bytes |

The distinguishing design choice is that the parser **refuses ambiguity rather
than resolving it**. Specification 10.1 requires a "single strict parser [that
rejects] TE/CL ambiguity and invalid duplicate headers", and every smuggling
technique is a *disagreement* between two parsers about where a message ends.
Anything a conforming implementation could read two ways is an error, not a
normalization.

What this module deliberately does **not** do:

- **No I/O, no sockets, no timeouts, no connection lifetime.** Every entry point
  is a pure function or a state machine over a caller-supplied buffer that
  returns `ParseStatus::Incomplete` instead of blocking. Deadlines, cancellation,
  backpressure, and the specification 3.2 per-stream 256 KiB buffered-data
  watermark belong to `hypellm-net` and are **not enforced here**.
- **No URI normalization or percent-decoding.** `RequestHead::target` is kept
  exactly as received. `/v1/..%2f..%2fadmin/v1/keys` stays encoded, because
  decoding before the router compares a path is how a traversal becomes a route
  match. Splitting on the first `?` into `path` and `query` is the only
  transformation applied.
- **No routing, policy, or authorization decisions.** Unrecognized methods are
  carried as `Method::Other` for the listener to answer 405; the parser bounds
  and validates, it does not decide.
- **No content coding.** A `Transfer-Encoding` list such as `gzip, chunked` is
  rejected outright rather than decompressed, because decompressing
  attacker-controlled bytes before authentication is unbounded work by
  definition. `Content-Encoding` is carried through untouched.
- **No proxy behaviour.** Absolute-form, authority-form, and `//`-prefixed
  targets are rejected (`NonOriginFormTarget`). Specification 2.2 makes general
  reverse proxying a non-goal and specification 10 forbids any client-controlled
  value selecting a destination; accepting a proxy-form target is the first half
  of exactly that.
- **No HTTP/2, HTTP/3, HTTP/0.9, or upgrade handling.** `Version::parse` accepts
  the two exact byte strings `HTTP/1.1` and `HTTP/1.0` and nothing else.

## Threat notes

- **Request smuggling is the primary threat, and the control is refusal.**
  `Content-Length` with `Transfer-Encoding` (`ConflictingFraming`), any repeat of
  a `header::SINGLE_VALUED` field (`DuplicateHeader`), whitespace before a colon
  (`WhitespaceBeforeColon`), obsolete line folding (`ObsoleteLineFolding`), bare
  CR or bare LF anywhere in a head (`MalformedRequestLine` /
  `MalformedStatusLine`), a `Transfer-Encoding` that is not exactly `chunked`,
  and a non-decimal `Content-Length` are all hard errors. The published
  techniques are held as a corpus in `lib.rs::smuggling_tests`.
- **A rejection must close the connection.** Once framing is in doubt, the bytes
  still buffered on that connection cannot be attributed to any request, and
  reusing it is how a smuggled prefix becomes the next caller's request line.
  `HttpErrorKind::must_close()` returns true for every kind except
  `UnsupportedVersion`. **This is a declaration, not an enforcement**: the value
  is advisory and the listener in `hypellm-net` is responsible for honouring it.
  A listener that ignores `must_close()` reintroduces the whole threat class.
- **Upstream responses are as dangerous as client requests.** Provider
  connections are pooled and reused, so a response whose end is ambiguous puts a
  prefix on the *next* tenant's response. `parse_response_head` therefore applies
  the same duplicate, folding, bare-LF, and TE/CL rules to an upstream as
  `parse_request_head` applies to a client.
- **Internal parser differential.** The single most likely way this crate fails
  is by disagreeing with *itself*. `request::split_crlf` and
  `client::split_crlf_strict`, and `request::parse_header_line` and
  `client::parse_header_line`, are near-identical duplicates, and
  `client::RequestBuilder::new` carries a third copy of the target/host charset
  rules from `request::parse_target` and `request::validate_host` — one which
  does **not** apply `Limits::max_target_bytes`. Any edit to one copy that is not
  mirrored in the others creates precisely the disagreement this crate exists to
  prevent. Treat these as a single reviewed unit.
- **Case-sensitivity footgun in header lookup.** `Headers` lowercases on insert
  and `Headers::get` guards its argument with a `debug_assert!` only. In a
  release build, `get("Content-Length")` returns `None` silently. Every framing
  and security lookup in this crate uses a lowercase literal today; a future
  lookup that does not would not fail a test build, it would simply stop seeing
  the header.
- **The outbound builders are laxer than the inbound parsers.**
  `RequestBuilder::header` and `ResponseBuilder::header` use
  `Headers::append_unchecked`, which skips the `SINGLE_VALUED` duplicate check,
  and neither builder bounds header count or total head size. Two calls with the
  same name emit two fields — a message this crate's own parser would reject.
  Adapters and the admin API must not pass a caller-derived header *name* to
  these builders. CR/LF/NUL in a *value* is still rejected by `is_field_value`,
  which is what stops response splitting; `ResponseBuilder::header_lossy` drops
  such a value silently by design and must be used only for optional diagnostics.
- **Quadratic rescan under slow delivery.** `find_head_end` runs
  `buf.windows(4).position(..)` from offset zero on every call, and the request
  parser additionally runs `scan_for_bare_terminators` over the whole partial
  buffer. A client that delivers a head one byte per packet costs O(n²) byte
  comparisons — bounded by `max_head_bytes`, so roughly 5·10⁸ window comparisons
  per connection at the 32 KiB default. Bounded, but a real slowloris
  amplification factor; the mitigation is the head cap plus the read deadline in
  `hypellm-net`, not anything in this crate.
- **Close-delimited bodies are bounded in total, contrary to the note in
  `limits.rs`.** `BodyDecoder::emit` accumulates `decoded` for *every* framing
  including `BodyFraming::UntilClose`, and the counter is never reset when the
  caller drains `out`. A `text/event-stream` response therefore fails with
  `BodyTooLarge` once its cumulative payload passes `Limits::UPSTREAM`'s 64 MiB,
  even though the doc comment on that constant states streaming responses are
  "bounded per event by `wire_sse` rather than in total". The code is the
  conservative behaviour; the comment is wrong and long streams will terminate.
- **Truncation is an error, not a short answer.** `BodyDecoder::finish` returns
  `UnexpectedEof` for any state other than `Done` or `UntilClose`. A caller that
  treated a truncated upstream body as a complete one would hand a silently
  clipped completion to the client.
- **Errors must not echo input.** `HttpError` carries only a `kind`; `Display`
  renders a fixed phrase with no CR, LF, or caller bytes, and `code()` values are
  stable and distinct. This is what keeps a transport failure — which happens
  before authentication and before routing — from becoming an oracle.
- **Trailers cannot re-open a decided question.** `header::FORBIDDEN_TRAILERS`
  rejects `transfer-encoding`, `content-length`, `host`, `authorization`,
  `proxy-authorization`, `trailer`, `te`, `expect`, `cookie`, `set-cookie`, and
  `content-encoding` in a chunked trailer section: framing and authentication
  were settled from the head, and a trailer that redeclares them is a smuggling
  attempt.
- **Integer handling.** Chunk sizes accumulate through `checked_mul`/`checked_add`
  and fail with `InvalidChunkSize` on overflow; `emit` uses `saturating_add`
  before comparing against the body bound. `Content-Length` is capped at 19
  characters before `u64::from_str`, so the parse cannot be the overflow site.

## Limits

Bounds are supplied per call as a `Limits` value; the three profiles are
`Limits::DEFAULT` (inference listener), `Limits::ADMIN` (management listener),
and `Limits::UPSTREAM` (provider responses). Values below are `DEFAULT`.

| Input | Limit | Enforced by |
|---|---|---|
| Message head bytes | 32 KiB default, 64 KiB hard ceiling (spec 3.2) | `Limits::max_head_bytes`, floored through `Limits::clamped()` against `HARD_MAX_HEAD_BYTES` on entry to both head parsers; checked both on a complete head and on an over-long incomplete one |
| Header field count | 100 (`ADMIN` 64) | `Limits::max_header_count`, checked against the CRLF line count before any header is allocated |
| Request target bytes | 8 KiB (`ADMIN` 2 KiB) | `Limits::max_target_bytes` in `request::parse_target` |
| Method token bytes | 32 (`ADMIN` 16) | `Limits::max_method_bytes` in `request::parse_request_line` |
| Body bytes | 16 MiB (`ADMIN` 1 MiB, `UPSTREAM` 64 MiB); spec 3.2 default is 16 MiB | `Limits::max_body_bytes`, checked twice — against the declared `Content-Length` in `request_body_framing`/`response_body_framing`, and against bytes actually produced in `BodyDecoder::emit` |
| Chunk-size line bytes | 256 (`ADMIN` 128) | `Limits::max_chunk_line_bytes` via `BodyDecoder::take_line`; the internal `line_buf` may reach `max + 2` bytes before the error fires |
| Trailer section bytes | 4 KiB (`ADMIN` 1 KiB) | `Limits::max_trailer_bytes`, applied per line in `take_line` and cumulatively via `BodyDecoder::trailer_bytes`; the cumulative check runs after the line is counted, so the section may overshoot by one line |
| `Content-Length` digits | 19 characters, ASCII digits only | `request::parse_content_length` |
| Chunk-size hex digits | 16, plus checked accumulation | `body::parse_chunk_size` |
| `Host` value | 255 bytes, `[A-Za-z0-9.\-:\[\]_]` only | `request::validate_host` — a hardcoded constant, **not** a `Limits` field |
| Status code | three ASCII digits in 100–599 | `client::parse_status_line` |
| Target charset | visible ASCII `0x21..=0x7E`, origin form, no `//` prefix | `request::parse_target` |
| Header name / value charset | RFC 9110 `tchar` / VCHAR+SP+HTAB+`obs-text`, values must be UTF-8 | `header::is_token`, `header::is_field_value`, `Headers::append` |

Known gaps, stated rather than papered over:

- `Limits::clamped()` clamps **only** `max_head_bytes`. A misconfigured
  `max_body_bytes`, `max_header_count`, or `max_trailer_bytes` is accepted as
  written; there is no hard ceiling on those.
- **Neither builder is bounded.** `RequestBuilder` and `ResponseBuilder` take no
  `Limits` and apply no cap on header count, target length, or serialized head
  size. Outbound head size is the caller's responsibility.
- The specification 3.2 per-stream 256 KiB buffered-data watermark is **not**
  implemented here. `BodyDecoder::decode` appends to a caller-owned `Vec` and
  bounds only cumulative decoded length.
- Transient allocation during head parsing is bounded but amplifying:
  `split_crlf` materializes a `Vec` of one slice descriptor per CRLF line, so a
  head of empty lines at the 64 KiB ceiling costs roughly 512 KiB of transient
  descriptors. Bounded by `max_head_bytes`, not separately capped.

## Fuzz targets

Specification 21 requires a fuzz layer covering "HTTP, JSON, SSE, configuration,
provider events, management API, state recovery", and 21.1 requires that a known
attack corpus "produces bounded work and stable error responses".

`tests/fuzz.rs` — seven targets, run by `cargo test -p wire-http1`, driven by
the seeded mutation engine in `hypellm-test-corpus::fuzz`. There is no `fuzz/`
directory and no libFuzzer harness, because specification 4 admits no such
dependency; a failing case is reproducible by seed number.

| Target | Property asserted |
|---|---|
| `no_mutation_of_the_corpus_panics_the_head_parser` | Termination and no panic over mutations of the attack corpus |
| `an_accepted_head_never_declares_two_framings` | The smuggling invariant: `Content-Length` and `Transfer-Encoding` are never both accepted |
| `an_accepted_head_carries_no_control_bytes_in_its_fields` | No CR, LF, or NUL survives into a parsed field |
| `the_head_size_limit_holds_on_mutated_input` | `max_head_bytes` is exact, not approximate |
| `an_incomplete_head_is_never_reported_as_complete` | Truncation is never mistaken for a whole message |
| `random_bytes_are_rejected_without_panicking` | Unstructured input |
| `a_head_of_many_short_headers_is_bounded_by_the_count_limit` | The many-small-headers shape |

The corpus these mutate is `hypellm-test-corpus::http1` plus the inline `#[test]`
vectors in `lib.rs::smuggling_tests`. Still outstanding:

| Target | Property to assert | Status |
|---|---|---|
| Request and response heads | Mutated corpus heads terminate with bounded allocations and stable outcomes | Implemented in `tests/fuzz.rs` |
| Chunked bodies | Mutated chunk framing never exceeds body limits or reports consumption past input | Implemented in `tests/fuzz.rs` |
| Split delivery | Fragmented and whole delivery produce equivalent parser outcomes | Implemented in `tests/fuzz.rs` |
| Framing safety | Smuggling mutations never turn ambiguous framing into accepted pipelined requests | Implemented in `tests/fuzz.rs` |
| Builders | Emitted messages reparse under the corresponding wire profile | Implemented in `tests/fuzz.rs` |

Until these land, the smuggling corpus in `lib.rs` and the byte-at-a-time and
split-read tests in `request.rs`, `client.rs`, and `body.rs` are the only
coverage of these properties.

## Public API

See `lib.rs`. Re-exported surface: `parse_request_head`, `parse_response_head`,
`ParseStatus`, `RequestHead`, `ResponseHead`, `RequestBuilder`,
`ResponseBuilder`, `BodyDecoder`, `encode_chunk`, `encode_last_chunk`,
`continue_response`, `reason_phrase`, `Headers`, `trim_ows`, `Limits`, `Method`,
`Version`, `BodyFraming`, `HttpError`, `HttpErrorKind`.

Parsing is a pure function over a buffer, so the same code serves a blocking
socket, a recorded golden fixture, and a fuzz driver. There is no configurable
leniency, no normalization mode, no upgrade path, and no way to raise
`max_head_bytes` past the specification's hard ceiling.

Specification 21 requires two-person review for parser changes. Because the
duplicated line-splitting and header-parsing routines in `request.rs` and
`client.rs` must stay in lockstep, review any edit to one against the other.
