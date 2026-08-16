# Module: wire-sse

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` inherited from the workspace root and restated in `lib.rs`. |
| External dependencies | None. Rust standard library only; the crate has no `[dependencies]` section at all, not even a workspace path dependency. |
| Fuzz targets | `tests/fuzz.rs` — 8 targets over the incremental parser and its bounds, driven by `hypellm-test-corpus::fuzz`. See [Fuzz targets](#fuzz-targets). |

## Scope and the "framing only" rule

Specification 14 makes this crate responsible for exactly one thing: turning a
byte stream into complete Server-Sent Events frames, and turning router-produced
frames back into bytes. "SSE parsing handles CRLF/LF, multiple data lines,
comments, bounded event size, and terminal markers."

| Responsibility | Where |
|---|---|
| Incremental line splitting over LF, CRLF, and bare CR | `parse::SseParser::push` |
| WHATWG `EventSource` field semantics (`data`/`event`/`id`/`retry`, one leading space stripped, unknown fields ignored, data-less events not dispatched) | `parse::SseParser::finish_line`, `next_event` |
| Hard ceilings on line, event, and field-name size, with typed sticky errors | `parse::SseLimits`, `parse::SseError` |
| Frame-safe encoding of payloads, event names, comments, keepalives, and `retry` | `encode::*` |
| Recognition of the OpenAI-profile terminal marker | `encode::DONE_MARKER`, `SseEvent::is_done_marker` |

What this module deliberately does **not** do:

- **It does not parse JSON.** `SseEvent::data` is an opaque `String`. Specification
  14 requires that "JSON fragments are assembled only within declared provider
  event boundaries"; this crate establishes the boundary and hands the bytes to
  `wire-json` through the adapter. It has no view of tool calls, deltas, or usage.
- **It does not interpret provider semantics.** Mapping `event: content_block_delta`
  to a canonical event is adapter work (specification 10). This crate knows one
  provider-specific string, `[DONE]`, and only as a convenience predicate.
- **It does no I/O, holds no credentials, and starts no tasks.** It is a state
  machine over caller-supplied `&[u8]` and a formatter into a caller-supplied
  `String`. Sockets, deadlines, backpressure watermarks, and cancellation belong
  to the caller (specification 3.2, 14).
- **It does not decide failover.** It reports a typed error; specification 6.5 and
  the `AttemptPhase` logic in `hypellm-router::dispatch` decide whether that error
  may be retried. See the note on stickiness below.
- **It applies no reconnection logic.** `retry:` is parsed and surfaced; the crate
  never acts on it. The router does not reconnect to upstreams on a `retry`
  directive.

## Threat notes

- **Frame injection through payload content.** A model completion is attacker-
  influenceable text that the router re-emits to a client. A raw `\n\n` inside a
  `data:` line would forge a frame boundary and let prompt content synthesize
  events the model never produced. `encode::write_data_lines` splits every payload
  on `\n` and `\r` into separate `data:` lines, and `push_single_line` replaces CR
  and LF with a space in event names and comments. The encoder tests assert the
  property directly (`event_name_cannot_inject_a_frame`,
  `comment_cannot_inject_a_frame`). Any new encoder entry point must route field
  values through one of those two helpers.
- **Encoding is lossy on CR, by design.** `write_data_lines` normalizes `\r\n` and
  bare `\r` to `\n`, so encode-then-decode is *not* byte-identical for payloads
  containing carriage returns — it is identical modulo that normalization. An
  adapter that assumes byte-exact passthrough of upstream content will be wrong on
  such payloads. Do not use this crate to relay bytes that must survive intact.
- **Split-terminator differential.** A CRLF landing across two socket reads is the
  classic incremental-parser bug: treating the CR and the LF as two terminators
  turns the LF into a blank line and dispatches the event one frame early,
  splitting a JSON payload in half and producing a decode error attributed to the
  provider. `pending_cr` carries the half-terminator across `push` calls; the test
  `crlf_split_across_chunks_is_one_terminator` pins it. Any refactor of `push` must
  preserve chunk-boundary independence — that is the single most valuable property
  a fuzz target here can check.
- **Truncation must not look like completion.** An upstream cut mid-frame leaves an
  unterminated line. `finish` discards it rather than dispatching a truncated JSON
  fragment, and `has_incomplete_tail` exists so the caller can distinguish a
  truncated stream from a clean end of stream. **As of this writing no caller in
  the workspace invokes either method** — `hypellm-router::dispatch::pump_sse_stream`
  ends on decoder completion or terminator only. Until a caller checks
  `has_incomplete_tail` before dropping the parser, a stream severed after the last
  complete frame is indistinguishable from a normal finish. This is an open gap,
  not a control.
- **Errors are sticky and fatal on purpose.** Once `failed` is set, every
  subsequent `push`, `next_event`, and `drain` returns the same error. A malformed
  frame means event boundaries can no longer be trusted, so continuing to parse
  would let an attacker-shaped stream resynchronize on a boundary of its choosing.
  The router maps these to `upstream_invalid_response` (502, specification 12). If
  the error arrives after semantic output has reached the client, specification 6.5
  forbids splicing a replacement response — the stream must end with a normalized
  error, never a second model response.
- **Known divergence: no BOM handling.** WHATWG `EventSource` strips a leading
  U+FEFF from the stream. This parser does not. A stream beginning with a UTF-8
  BOM yields a first field named `"\u{feff}data"`, which is silently ignored as an
  unknown field; because a data-less event is not dispatched, the entire first
  frame disappears with no error. No provider in scope is known to emit a BOM, but
  this is a real parser differential and a silent-loss path, so it is recorded
  rather than assumed harmless.
- **Terminal-marker confusion.** `is_done_marker` compares `data.trim()` against
  `[DONE]`, so any payload whose trimmed form equals that literal ends the stream.
  For the OpenAI profile the payload is JSON and cannot collide; a provider whose
  stream carries bare text could truncate a response early. Adapters should prefer
  their own `is_stream_terminator` (as `hypellm-adapters::openai` does) rather than
  treating this predicate as universal.
- **Completion content in `Debug` output.** `SseEvent` derives `Debug` and its
  `data` field holds raw model output. Specifications 7.1 and 17 forbid logging
  prompt/completion bodies by default; there is no `Sensitive` wrapper here.
  Never log an `SseEvent`, an `SseEvent` collection, or a `Vec<u8>` chunk fed to
  `push`. `SseError` is safe to log: its `Display` and `code` strings are fixed
  and echo no upstream bytes.
- **Stall without error.** A stream of comment lines (`: keepalive`) parses
  forever, allocates nothing permanent, and produces no events. The parser has no
  time budget and no event-count budget; a peer that never sends data is a live
  connection as far as this crate is concerned. Slow-upstream and slow-client
  detection is the caller's deadline (specification 3.2, 14).
- **Allocation churn under many short lines.** `finish_line` takes `line_buf` by
  `core::mem::take`, so the buffer restarts at zero capacity after every line. A
  stream of millions of one-byte lines forces one allocation per line. Bounded and
  not a leak, but it is a cheap way for an upstream to spend router CPU.
- **Unbounded prompts are not a threat vector here.** Client input never reaches
  this parser; it only ever sees upstream response bytes and adapter-produced
  encoder input. Specification 8's rule that prompts are inert data is upheld
  trivially — nothing in this crate branches on payload content except the
  `[DONE]` comparison noted above.

## Limits

Defaults come from `SseLimits::DEFAULT`; every value is caller-overridable via
`SseParser::new`.

| Input / resource | Enforced maximum | Enforced by |
|---|---|---|
| Single line held in the assembly buffer | 256 KiB (specification 3.2 per-stream figure) | `SseLimits::max_buffer_bytes`, checked in `push` before each byte is appended; violation is `SseError::LineTooLong` |
| Accumulated `data` payload for one event | 1 MiB | `SseLimits::max_event_bytes`, checked in `next_event` before appending (the joining `\n` counts); violation is `SseError::EventTooLarge` |
| Field name length | 64 bytes | `SseLimits::max_field_name_bytes`, checked in `finish_line`; violation is `SseError::FieldNameTooLong` |
| Line encoding | UTF-8 required per line | `String::from_utf8` in `finish_line`; violation is `SseError::InvalidUtf8` |
| `retry:` value | `u64` range; anything else, including negatives, is ignored rather than clamped | `value.parse::<u64>()` in `next_event` |
| `id:` value | Rejected outright if it contains NUL, per `EventSource` | `value.contains('\u{0}')` in `next_event` |

Gaps — resources this crate does **not** bound:

| Resource | Status |
|---|---|
| `pending` completed-line queue | **Not bounded.** A caller that calls `push` repeatedly without `next_event`/`drain` grows the queue without limit. In practice `hypellm-router::dispatch` drains after every push, so residency is one read chunk — but that is a caller contract, not an enforced invariant. |
| `event:` and `id:` field values retained on `current` | **Not counted against `max_event_bytes`.** Each is bounded only indirectly by the line ceiling, so up to 256 KiB apiece can be held alongside a 1 MiB `data` accumulator. |
| Peak per-stream parser residency | Worst case is roughly `max_buffer_bytes + max_event_bytes + 2 × max_buffer_bytes` ≈ 1.75 MiB with defaults, plus `pending`. This **exceeds** the 256 KiB per-stream figure of specification 3.2, which the `SseLimits::DEFAULT` doc comment cites. Deployments targeting the 20,000-concurrent-stream goal of specification 2 should lower `max_event_bytes` explicitly rather than rely on the default. |
| Encoder output size | **Not bounded.** Every `encode_*` function appends to a caller-owned `String` and never inspects its length. Byte accounting and watermarks live in the caller. |
| Events returned by `drain` | **Not bounded** except transitively by `pending`. |
| Time / event count per stream | **Not bounded.** No deadline or frame budget exists in this crate. |

## Fuzz targets

Specification 21 lists SSE in the required fuzz layer. `tests/fuzz.rs` — eight
targets, run by `cargo test -p wire-sse`, driven by the seeded mutation engine
in `hypellm-test-corpus::fuzz`. There is no `fuzz/` directory and no libFuzzer
harness, because specification 4 admits no such dependency.

| Target | Property asserted |
|---|---|
| `no_mutation_of_the_corpus_panics_the_parser` | Termination and no panic |
| `an_arbitrary_chunk_split_produces_the_same_decision_as_the_whole` | Incremental parsing agrees with whole-input parsing at every split |
| `an_event_that_is_never_terminated_is_refused_at_its_bound` | An unterminated event cannot grow without limit |
| `the_default_limits_also_bound_an_unterminated_event` | The same, under shipped defaults rather than test-sized ones |
| `a_single_line_that_never_ends_is_refused_by_the_buffer_bound` | The no-newline shape of the same |
| `a_single_oversize_event_is_refused` | The per-event bound |
| `random_bytes_are_handled_without_panicking` | Unstructured input |
| `truncation_at_every_offset_is_handled` | Every prefix is a clean state |

Still outstanding:

| Target | Property to assert | Status |
|---|---|---|
| `sse_parse_chunked` | Arbitrary bytes split at arbitrary boundaries produce the same event sequence as the same bytes pushed whole, and never panic. Generalizes the hand-written `byte_at_a_time_matches_whole_input` test to adversarial split points. | Required, not yet implemented (§21) |
| `sse_limits_hold` | For arbitrary `SseLimits` and arbitrary input, `buffered() <= max_buffer_bytes` and every returned `data.len() <= max_event_bytes` at all times, and a limit error is sticky. | Required, not yet implemented (§21) |
| `sse_encode_roundtrip` | For an arbitrary payload and event name, `encode_event` followed by a parse yields exactly one event whose data equals the CR-normalized payload — no payload can forge a frame boundary. | Required, not yet implemented (§21) |
| `sse_provider_events` | Recorded provider stream fixtures with injected corruption (truncated frames, interleaved comments, oversized events) reach a typed error or a well-formed event, never a partial dispatch. Depends on the specification 21 fixture corpus. | Required, not yet implemented (§21) |

## Public API

Re-exported from `lib.rs`: `SseParser`, `SseLimits`, `SseEvent`, `SseError` from
`parse`; `DONE_MARKER`, `encode_data`, `encode_event`, `encode_done`,
`encode_comment`, `encode_keepalive`, `encode_retry` from `encode`.

The parse surface is push/drain and nothing else — no callbacks, no owned reader,
no async. `push` accepts bytes, `next_event`/`drain` yield assembled events,
`finish` marks upstream close, `has_incomplete_tail` reports truncation, and
`buffered` exposes residency for watermark accounting. The encode surface is a set
of free functions that append to a caller-owned `String`; there is no encoder
object and no hidden state, which is what makes frame-boundary sanitization
auditable at each call site. Consumers today are `hypellm-router` (dispatch and the
client-facing stream), `hypellm-adapters`, and `hypellm-net`.

Two-person review applies to any change in this crate: it is a parser on the data
path (specification 21).
