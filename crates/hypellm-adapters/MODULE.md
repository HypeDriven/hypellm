# Module: hypellm-adapters

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace. |
| External dependencies | None. Rust standard library plus the workspace path dependencies `hypellm-core`, `wire-json`, `wire-sse`. |
| Fuzz targets | `tests/fuzz.rs` — 9 targets over recorded provider events, driven by `hypellm-test-corpus::fuzz`. See [Fuzz targets](#fuzz-targets). |

Specification 21.1 requires two-person review for "adapter credential handling".
That gate applies to `contract.rs` and to either adapter's `encode_headers`.

## Scope and the "adapters decide nothing" rule

This module is the only code in the router that touches provider credentials and
the only code that speaks a provider-native wire format. Specification 7 draws
the boundary and the trait in `contract.rs` is shaped to make it structural
rather than advisory:

> They contain only typed conversion, strict parsing, endpoint paths,
> authentication header construction, stream decoding, and error mapping. They
> cannot make routing decisions, read arbitrary files, resolve arbitrary hosts,
> or expose credentials in errors.

| Concern | Where it lives | Why not here |
|---|---|---|
| Target selection, failover, retry budget | `hypellm-core` routing, caller | No `Adapter` method receives a `PolicySnapshot` or a candidate list |
| Sockets, TLS, DNS, deadlines, cancellation | `hypellm-net`, `wire-http1` | Every `Adapter` method is pure and performs no I/O |
| HTTP framing and header-value validation | `wire-http1` (`Headers::append_unchecked`) | `SensitiveHeaders` is a name/value list, not a serializer |
| SSE framing, event size, terminal marker | `wire-sse` | This module decodes one already-framed event's payload |
| Credential storage, rotation, resolution | credential store, `hypellm-store` | The adapter borrows a `CredentialHandle` for the length of one header build |
| Choosing a provider family at runtime | configuration → `ProviderFamily` | `adapter_for` is a total `match` over a closed enum; specification 2.2 forbids dynamic plugins |

Two further boundaries the code holds deliberately:

- **No schema repair.** A tool's `parameters_json` and a JSON-schema response
  format are parsed to confirm they are JSON and re-serialized unchanged. An
  unsupported schema is *rejected* (`invalid_tool_schema`,
  `invalid_response_schema`), never rewritten — the model was prompted against
  the client's schema.
- **No capability inference.** Nothing is deduced from a model name
  (specification 7, Moonshot row). `validate` reads only the target's declared
  `Capabilities`; the five OpenAI-compatible families share one encoder and
  differ solely in what their targets declare.

Prompt content is inert throughout: decoded provider text becomes
`CanonicalEvent` payloads and is never consulted for a destination, a path, or a
credential. `path_for` returns a `&'static str` from a closed match, and the
host/port/base path come from the administrator-configured `Endpoint` in
`RequestMeta` (specification 10).

## Threat notes

**Provider messages are the primary leak vector, and they are dropped.**
`safe_detail` is always one of the fixed strings in `safe_detail_for`; the
provider's `message` field is never copied into it. Those messages routinely
echo the prompt (`"Invalid prompt: '…'"`) or an internal hostname. Only the
provider's `type`/`code` token survives, through `sanitize_provider_code`, which
narrows to `[A-Za-z0-9_.-]` and 64 bytes so it cannot carry newlines or ANSI
escapes into a log. Tests in both adapters and in `lib.rs` assert this for every
family; treat those tests as the specification-10 control, not as coverage.

**A hostile or compromised upstream can steer classification.**
`classify_error_object` derives `UpstreamErrorClass` from provider-controlled
strings, and the class drives both retriability (specification 6.5) and health
accounting. An upstream that labels a genuine failure `authentication_error`
suppresses circuit-breaker input, because `Authentication.affects_health()` is
`false`; one that labels a permanent failure `rate_limit_error` makes the router
retry and fail over. The Anthropic adapter additionally substring-matches the
provider's *message* (`"max_tokens"`, `"context"`) to reach `ContextOverflow` —
the message is not forwarded, but it does influence routing. The provider type
takes precedence over the HTTP status here, so status is not a floor.

**A truncated response can decode as a clean stop.** Decoding is total and
tolerant: unknown content-block types and unrecognised event names are ignored,
absent fields default. Both adapters then synthesise a terminal event —
`OpenAiAdapter::decode_response` appends `Finish { Stop }` when no terminal event
was produced, and `AnthropicAdapter::decode_response` always appends one,
defaulting an absent or unparsable `stop_reason` to `Stop`. A response that was
actually cut short upstream is therefore presentable to the client as a normal
completion. This is the response-confusion risk for this crate and the reason
`decode_response` must not be the only integrity check on a non-streaming
exchange.

**Credential handling fails open in one place.** `encode_headers` writes the
authorization header only inside `if let Some(secret) = credential.expose_str()`.
A credential whose bytes are not valid UTF-8 yields *no* header and the request
is dispatched unauthenticated; the resulting 401 classifies as `Authentication`,
which does not affect health, so the misconfiguration presents as a quiet
per-request failure. Refusing to encode would be the fail-closed behaviour.

**Redaction covers `push_secret` only.** `SensitiveHeaders::Debug` prints values
in full for headers added with `push`, by design — `content-type` and `accept`
stay readable in a trace. The consequence is that `x-request-id` and the
client-supplied `idempotency-key` appear verbatim in debug output. Credentials go
through `push_secret` in both adapters; any new credential-bearing header must
too. `SensitiveHeaders` and `CredentialHandle` are not `Clone`, so neither can be
retained past the header build.

**Header-value hygiene is not enforced here.** `meta.request_id` and
`meta.idempotency_key` are placed into header values verbatim, and the
idempotency key is client-supplied. CR/LF rejection lives downstream in
`wire-http1::Headers::append_unchecked` (`is_field_value`). This module is not a
defence against request splitting on its own; a caller that serialises
`SensitiveHeaders` by any other path reintroduces the hole.

**Parser differential with the upstream.** Client-supplied JSON (tool schemas,
response schemas, historical tool-call arguments) is parsed by `wire-json` and
re-emitted by `wire_json::to_vec` rather than passed through as text. Round-trip
fidelity is therefore load-bearing: any divergence in number formatting, large
integers, or escape handling changes the document the provider's parser sees
relative to the one the router validated. `Limits::reject_duplicate_keys` is
`true` on every parse in this crate, which removes the classic first-key/last-key
differential.

**Tool-call identity can collapse.** Specification 14 requires call identity and
ordered argument deltas to survive. Both adapters clamp an unrepresentable index
to `0` — `anthropic::block_index` and the OpenAI streaming fallback both end in
`unwrap_or(0)` — so a provider emitting indices above `u32::MAX` would merge two
calls' argument fragments into one. This needs a buggy or hostile upstream, not a
client. Relatedly, `anthropic::encode_messages` substitutes `{}` for a historical
tool call whose recorded arguments are not valid JSON, silently altering the
conversation replayed to the provider rather than failing.

**Embedding values are narrowed lossily.** `openai::decode_response` maps each
element through `f64 as f32`; magnitudes outside the `f32` range saturate to
infinity and precision is lost without a diagnostic. The client receives a vector
that is not exactly what the provider returned.

**Resource shape.** Streaming decode is per-event, so specification 14's
"MUST NOT buffer an entire completion" holds on the stream path. Non-streaming
`decode_response` takes a fully materialised `&[u8]`, bounded by
`Limits::DEFAULT`. The request-size check runs *after* `to_vec`, so encoding can
transiently allocate more than `MAX_REQUEST_BYTES` before rejecting; the bound is
a check on the result, not a cap on the work.

## Limits

| Input / resource | Enforced maximum | Enforced by |
|---|---|---|
| Encoded request body | 32 MiB | `contract::MAX_REQUEST_BYTES`, checked after serialization in both `encode_request` implementations |
| Non-streaming response body | 16 MiB input, depth 64, 8 MiB per string, 100 000 array items, 10 000 object entries | `wire_json::Limits::DEFAULT` at `parse` |
| One streaming event payload | 2 MiB input, depth 32, 1 MiB per string, 4 096 array items, 512 object entries | `wire_json::Limits::STREAM_EVENT` at `parse_str` |
| Provider error body read for classification | 1 MiB input, depth 32, 64 KiB per string | `wire_json::Limits::SMALL`; an oversized body simply fails to parse and classification falls back to status alone |
| Tool parameter schema, response JSON schema, replayed tool-call arguments | 1 MiB, depth 32 | `wire_json::Limits::SMALL` in `encode_tools`, `encode_response_format`, `anthropic::encode_messages` |
| Duplicate JSON object keys | Rejected | `Limits::reject_duplicate_keys = true` on every profile used here |
| Recorded provider error code | 64 characters, then 64 bytes | `contract::sanitize_provider_code` |
| Client-visible error detail | 200 bytes | `Capped::new(_, 200)` in `ErrorClassification::safe_detail` and `ValidationFailure::new` |
| Requested output tokens | Target's declared `capabilities.max_output_tokens` | `validate`, code `max_tokens_too_large` |
| Anthropic `max_tokens` when the client omits one | Target's declared `capabilities.max_output_tokens`; a target declaring `0` is refused | `anthropic::encode_request`, `validate` code `max_tokens_undeclared` |

Bounds this module does **not** enforce, stated plainly so no one reads the table
as complete:

- **No cap on message count, content parts per message, tool count, or embedding
  input count.** These are bounded only upstream by the inbound body limit
  (specification 3.2) and afterwards by the 32 MiB check on the encoded result.
- **No cap on canonical events produced from one response.** A body at the
  `Limits::DEFAULT` array ceiling can yield up to 100 000 `Embedding` events.
- **No SSE-level bound.** Event framing and `max_event_bytes` (1 MiB default)
  belong to `wire-sse`; `decode_stream_event` trusts that its `data` argument was
  already bounded.
- **`retry_after_secs` is never populated.** All four construction sites set it
  to `None`. `Adapter::classify_error` receives only `(status, body)`, so the
  `Retry-After` header specification 7.1 lists in `decode_response(status,
  headers, body_stream)` is not reachable from inside an adapter; specification
  6.5's "Retry-After is capped by the remaining deadline" must therefore be
  satisfied by the caller reading the header itself. This is a known gap in the
  trait shape, not an oversight in the implementations.
- **No timing-side-channel control.** Nothing here compares secrets;
  `SensitiveHeaders` lookups are ordinary string comparisons over header names.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is instead a seeded, deterministic
mutation engine in `hypellm-test-corpus::fuzz`, driven from ordinary
`tests/fuzz.rs` targets so that `cargo test` runs it and a failing seed is
reproducible by number rather than by corpus file.

All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table.

Specification 21 requires fuzzing of "provider events", and `tests/fuzz.rs` is
that suite: nine targets seeded from every recorded fixture in
`hypellm-test-corpus::golden`, so each mutation starts from bytes a real provider
sent.

| Target | Property asserted |
|---|---|
| `no_mutation_of_a_recorded_stream_frame_panics_a_decoder` | Termination over both families and every event-name shape |
| `no_mutation_of_a_recorded_body_panics_a_decoder` | The same for bodies, across the status range |
| `a_non_success_status_never_decodes_to_a_completion` | The silent-success failure: a 500 whose body parses must not be handed to the caller as a completion |
| `a_classified_error_never_carries_the_provider_body_to_the_client` | Specification 10: a planted marker never reaches `safe_detail`; `provider_code` stays bounded and alphabet-narrowed |
| `a_classification_is_deterministic` | A retry decision that varied between reads would make specification 6.5 unprovable |
| `an_oversize_stream_event_is_refused_rather_than_decoded` | `Limits::STREAM_EVENT`, whose length the provider controls entirely |
| `deeply_nested_provider_json_is_refused_rather_than_overflowing_the_stack` | The recursion bound is a refusal, not a crash |
| `random_bytes_are_handled_without_panicking` | Unstructured input |
| `every_recorded_fixture_is_reachable_as_a_seed` | A seed set that silently shrank would leave the rest fuzzing a fraction of the corpus while still passing |

Note what the fourth target does *not* assert: `provider_code` deliberately
carries the provider's own error-type token, so requiring it to be empty would
be requiring the field not to work. What is required of it is the narrowing.

Still outstanding:

| Target | Property to assert | Status |
|---|---|---|
| `openai_stream_event` | Arbitrary UTF-8 into `OpenAiAdapter::decode_stream_event` terminates, allocates within `Limits::STREAM_EVENT`, and never panics | Required, not yet implemented (§21) |
| `anthropic_stream_event` | As above, across arbitrary and absent `event_name` values, including the `error` branch | Required, not yet implemented (§21) |
| `openai_response_body` | Arbitrary bytes at arbitrary status into `decode_response`: no panic, and a non-2xx status always yields `Err` | Required, not yet implemented (§21) |
| `anthropic_response_body` | As above, plus that a decoded sequence always ends in a terminal event | Required, not yet implemented (§21) |
| `error_classification` | For arbitrary `(status, body)`, no byte sequence from `body` appears in `safe_detail`, and `provider_code` stays inside the sanitized alphabet | Required, not yet implemented (§21) |
| `request_encode_roundtrip` | For an arbitrary `CanonicalRequest`, `encode_request` either errors or produces valid JSON within `MAX_REQUEST_BYTES` that re-parses under `Limits::DEFAULT` | Required, not yet implemented (§21) |
| `tool_schema_passthrough` | An arbitrary JSON schema that parses is byte-for-byte semantically identical after encode/decode — the parser-differential property above | Required, not yet implemented (§21) |

## Public API

See `lib.rs`. The surface is `adapter_for(ProviderFamily) -> &'static dyn
Adapter`, the `Adapter` trait, and the contract types (`CredentialHandle`,
`SensitiveHeaders`, `RequestMeta`, `ValidationFailure`, `ErrorClassification`).
There is no registration function, no lookup table an operator can extend, and no
path by which a request selects an adapter; adding a family is a compile error
until `adapter_for` is updated.

`testing` is deliberately `pub` rather than `#[cfg(test)]` so that
`hypellm-test-corpus` and the compatibility suite build the same canonical requests
the unit tests use — two suites with subtly different fixtures is how a golden
test passes against something the router never sends. The cost is that the
fixtures compile into the library, and they use `.expect(…)` on constant inputs,
which sits outside the startup/test carve-out in specification 18.2. The
expectations are unreachable from any data-plane input; gating the module behind
a feature would remove the deviation entirely.
