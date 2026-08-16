# Module: hypellm-router

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Platform (primary), Security (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` is declared in both `lib.rs` and `main.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library plus workspace path dependencies: `hypellm-adapters`, `hypellm-admin-api`, `hypellm-auth`, `hypellm-config`, `hypellm-core`, `hypellm-crypto`, `hypellm-net`, `hypellm-store`, `hypellm-telemetry`, `wire-http1`, `wire-json`, `wire-sse`. |
| Fuzz targets | None exist. Six are required; see [Fuzz targets](#fuzz-targets). |

Ownership is Platform-primary because the crate's centre of gravity is the
listener, the process lifecycle, and the request pipeline. Three areas inside it
are nonetheless Security-review surface under specification 21.1 and must not be
changed by one person: `routes::authenticate` and the scope gate in
`InferenceHandler::inference`; the two client-protocol parsers in `protocol/`;
and `dispatch::build_headers` / `state::CredentialStore`, which are the only
places in this crate that touch provider credentials.

## Scope, and what this module deliberately does not do

Specification 18.1 assigns this crate "Binary, startup validation, listener
orchestration, privilege drop, shutdown". In practice it is the seam that turns
client bytes into a canonical request, walks specification 3.1's lifecycle, and
turns canonical events back into client bytes:

| Layer | File | Responsibility |
|---|---|---|
| Accept and frame | `server.rs` | Bounded accept loop, strict head/body read, slow-client and keep-alive timeouts, overload shedding |
| Dispatch | `routes.rs` | Exact undecoded path match, authentication, scope gate, health/metrics, `/v1/models` visibility |
| Translate | `protocol/` | OpenAI and Anthropic dialects into `CanonicalRequest`, canonical events back out as JSON or SSE |
| Lifecycle | `pipeline.rs` | Route once, reserve, attempt, meter, audit, record the decision trace |
| Attempt | `dispatch.rs` | Encode, connect, send, stream, classify — and track how far the exchange got |
| Assemble | `startup.rs`, `main.rs` | Validate configuration, open the store, check reachability, bind, serve, drain |
| Management mount | `admin.rs` | Mount `hypellm-admin-api` and the static application on a separate listener |

What it does **not** do, and must not start doing:

- **No routing decisions.** `PolicySnapshot::route` in `hypellm-core` decides;
  `pipeline::execute` calls it exactly once per request and walks the returned
  order. Re-routing between attempts would let a mid-request reload change the
  candidate list, which Appendix B forbids.
- **No provider knowledge.** Endpoint paths, auth header shapes, wire encodings,
  and error classification live in `hypellm-adapters`. This crate holds an
  `&dyn Adapter` and asks.
- **No parsing of its own.** HTTP framing, JSON, and SSE are parsed by
  `wire-http1`, `wire-json`, and `wire-sse` under named limit sets. The
  `protocol/` modules consume an already-parsed `Value`; they do not scan bytes.
- **No proxying.** No client byte reaches a provider and no provider byte reaches
  a client. Everything crosses the canonical model, which is what stops a
  provider quirk from becoming part of the client contract.
- **No destination selection from input.** No client-controlled value reaches a
  host, port, SNI, credential handle, file path, or socket (specification 10).
  A `data:` image URI is decomposed for the adapter; a non-`data:` URL is carried
  as opaque text and never fetched.
- **No management surface on the data plane.** `/admin/v1` is only reachable
  through `AdminHandler` on the management listener (specification 3).

### A stated concurrency deviation

Specification 3.2 requires "a fixed set of event-loop workers". This crate uses
one thread per connection from a bounded pool, capped at accept time by
`ServerConfig::max_connections`. The deviation is recorded in
`docs/deferred-issues.md` and in the `server.rs` module comment: an epoll loop
needs either `unsafe` FFI, which specification 18.2 forbids workspace-wide, or an
approved crate under specification 4's exception profile. Every bound, deadline,
and cancellation path is still enforced; what is lost is the 20,000-concurrent-
stream target of specification 2.1.

## Threat notes

These are the threats specific to what this code does, not the generic list.
The first two are known defects, not hypotheticals.

- **Group membership is never checked against the principal.**
  `routes::groups_for` walks `config.roles` and returns *every* `RoleSubject::Group`
  it finds, discarding the principal entirely (the two `Principal` arms both
  return `None`). Every authenticated caller therefore presents as a member of
  every group named in any role binding, and those groups flow straight into
  `RoutingContext::groups`, which is what `PolicySnapshot::route` filters grants
  and bindings on. Any `grant scope=group:…` is effectively a grant to all
  authenticated callers, across tenants. This breaks specification 9.3 and
  Appendix B's tenant-isolation invariant and is the highest-severity open item
  in this crate.
- **The data-plane listener discloses configuration before authentication.**
  `InferenceHandler::handle` answers `/health/live`, `/health/ready`, and
  `/metrics` before calling `authenticate`. Readiness returns
  `config_version` and `config_digest`; the metrics exposition carries
  `LabelName::Target` values taken from configured target identifiers, plus alias
  and operation dimensions. Anyone who can reach the inference port can enumerate
  target names and fingerprint the active configuration. Specification 8 requires
  the health endpoints to expose "no sensitive provider detail", and does not put
  `/metrics` on the inference listener at all — it belongs behind the management
  listener or a scope.
- **Failover splicing.** Specification 6.5's rule — never emit failover output
  after client-visible semantic bytes — is carried by exactly one value:
  `AttemptPhase`, set at each failure site in `dispatch::attempt` and consulted by
  `AttemptFailure::may_failover`. It is deliberately *not* inferred from the error
  kind. Any refactor that derives the phase from an error, or that lets
  `pipeline::execute` continue its loop after `saw_output`, re-opens the ability
  to splice a second model's tokens into a stream the client is already reading.
  The truth table is pinned by tests in `dispatch.rs`.
- **Credential material in a `Debug` rendering.** `CredentialStore::with_secret`
  is a scoped borrow with no owned getter, so a secret cannot outlive header
  construction — that part is sound. But `CredentialStore` *derives* `Debug` over
  `RwLock<BTreeMap<CredentialRef, Vec<u8>>>`, so `{:?}` on it prints the key
  bytes as a numeric array. The existing test only asserts that the UTF-8 spelling
  does not appear. `RouterState` derives `Debug` too and holds it. Specification
  7.1 and 10 require a redacting type here; today the protection is that nothing
  logs router state, which is a convention rather than a boundary.
- **Cross-tenant connection reuse via an ambiguous pool key.**
  `RouterState::credential_class` builds `format!("{tenant}:{reference}")`, and
  `:` is a legal identifier character (`hypellm_core::ids::validate`). Tenant `a:b`
  with credential `c` produces the same class as tenant `a` with credential `b:c`,
  so two tenants could share a pooled socket. Identifiers come from operator
  configuration rather than from callers, which bounds the exposure, but the key
  should be built from a length-prefixed or delimiter-free encoding.
- **Request smuggling and framing confusion.** Framing is decided once, by
  `wire-http1`, and `serve_connection` treats any `HttpError` as terminal: it
  writes a stable error and breaks the loop rather than continuing, so bytes left
  in the buffer after an ambiguous request are never attributed to a following
  one. Streaming responses have no length, so `InferenceHandler::stream` always
  returns `Disposition::Close`. Both behaviours are load-bearing; a "recover and
  continue" path would reintroduce specification 10.1's smuggling row.
- **Path confusion.** `routes::is_known_path` and `protocol_for` match the raw,
  undecoded path with `==`, and `admin::serve_static` matches against an explicit
  allowlist of relative filenames instead of joining a request path onto a root.
  There is no normalisation step to walk and no traversal surface. Adding prefix
  matching or a decode-then-match step would create both.
- **Resource exhaustion by slow drip.** Every socket read carries
  `read_timeout`, but there is no aggregate deadline on assembling a request head
  or body. A client sending one byte just inside the timeout occupies a connection
  and a thread for as long as its byte budget lasts. The only real bound is
  `max_connections` (4096 inference, 256 management) and the 512 KiB thread stack;
  past the cap the listener answers 429 and closes rather than queueing. See
  [Limits not enforced](#limits-not-enforced).
- **Upstream is untrusted.** Provider responses are read under
  `wire_http1::Limits::UPSTREAM` and `SseParser::with_default_limits()`, and a
  malformed event stream is a `ProtocolViolation` that ends the attempt rather
  than a parse that keeps going. Provider error text never reaches the client:
  `AttemptFailure::from_classification` copies only `ErrorClassification::safe_detail`
  and a capped `provider_code`, and an upstream `Authentication` failure maps to
  `InternalFault` so a router credential problem cannot be mistaken for the
  caller's key being wrong (specification 8.2).
- **Prompt injection into the control plane.** Client-supplied `hypellm_routing`
  hints are dropped silently unless the principal holds
  `rbac::Permission::OperateTargets`; `prefer_target` is validated into a
  `TargetId` and resolved against configured targets by the router core, never
  used as an address. Prompts, tool schemas, and image URLs are carried as inert
  data. Nothing in `protocol/` interprets a field as configuration, destination,
  or credential.
- **The control socket is unauthenticated.** `main.rs` binds a Unix socket and
  acts on a bare `shutdown`/`drain` line. Its only protection is filesystem
  permission on the containing directory; the router creates it under the process
  umask and does not `chmod` it. Anything that can open it can stop the router.
  Specification 20.1 requires graceful shutdown to exist; it does not authorise an
  unauthenticated trigger.
- **Entropy failure degrades identity rather than failing closed.**
  `routes.rs` and `admin.rs` both use `random::u128_value().unwrap_or(0)` /
  `unwrap_or_else(…"0"×32)`. If `/dev/urandom` is unavailable, every request is
  assigned id `0`, and the decision trace, audit record, and `X-Request-Id`
  correlation collapse silently. A refusal would be the safer failure.
- **Reservation conservation.** `pipeline::execute` reserves before any outbound
  I/O and either `commit`s with reconciled usage or `drop`s the reservation on the
  same iteration, so a failed attempt returns its capacity before the next one
  asks. Appendix B says `Drop` alone is not trusted for accounting; the explicit
  `drop(reservation)` in the failure arm is there to keep the release visible at
  the site that owns it. Any `?` inserted between `reserve` and that arm leaks
  capacity for the life of the process.

## Limits

Every value below is enforced by the named constant or field. The inference and
management listeners differ, so both are given.

| Input | Inference | Management | Enforced by |
|---|---|---|---|
| Simultaneous connections | 4096 | 256 | `ServerConfig::max_connections`, checked before per-connection state is allocated; over the cap the peer gets 429 `capacity_exhausted` |
| Requests per connection | 1000 | 200 | `ServerConfig::max_requests_per_connection` |
| Per-read / per-write timeout | 30 s | 15 s | `ServerConfig::read_timeout` / `write_timeout`, applied as socket options |
| Idle keep-alive | 75 s | 30 s | `ServerConfig::keepalive_timeout` |
| Connection thread stack | 512 KiB | 512 KiB | `std::thread::Builder::stack_size` in `Server::serve` |
| Request head bytes | 32 KiB | 16 KiB | `wire_http1::Limits::DEFAULT` / `::ADMIN` `.max_head_bytes` (hard ceiling 64 KiB, `HARD_MAX_HEAD_BYTES`) |
| Header fields | 100 | 64 | `Limits::max_header_count` |
| Request target bytes | 8 KiB | 2 KiB | `Limits::max_target_bytes` |
| Method token bytes | 32 | 16 | `Limits::max_method_bytes` |
| Request body bytes | 16 MiB | 1 MiB | `Limits::max_body_bytes` via `BodyDecoder` — fixed, not configurable; see below |
| Chunk-size line / trailer | 256 B / 4 KiB | 128 B / 1 KiB | `Limits::max_chunk_line_bytes`, `max_trailer_bytes` |
| JSON input bytes | `settings.max_body_bytes` (default 16 MiB) | — | `JsonLimits::DEFAULT.with_max_input_bytes(...)` in `InferenceHandler::inference` |
| JSON depth / string / array / object | 64 levels / 8 MiB / 100 000 items / 10 000 entries | — | `wire_json::Limits::DEFAULT`; duplicate keys rejected |
| Upstream response head / body | 32 KiB / 64 MiB | — | `wire_http1::Limits::UPSTREAM` in `dispatch::attempt` (cumulative across chunks) |
| Upstream SSE line buffer / event | 256 KiB / 1 MiB | — | `SseParser::with_default_limits()` (`SseLimits::DEFAULT`) |
| Decoded upstream stream event JSON | 2 MiB, depth 32 | — | `wire_json::Limits::STREAM_EVENT`, applied inside the adapter |
| Attempts per request | `settings.max_attempts`, default 3, floor 1 | — | the candidate loop in `pipeline::execute` |
| Retry budget | `settings.retry_budget_ms`, default 30 s | — | `Deadline::after`, then `min` with the request deadline |
| End-to-end deadline | `settings.default_deadline_ms`, default 120 s | — | `Deadline::after` in `InferenceHandler::inference`, checked each attempt |
| Admission queue wait | `min(settings.queue_timeout_ms` (default 5 s)`, deadline remaining)` | — | `pipeline::execute` → `AdmissionController::reserve_queued`; zero never waits |
| Admission queue depth | `quota queued=`, default 0 (no queue) | — | `ScopeLimits::max_queued` in `Scope::join_queue` |
| Background threads | 4 fixed: accept loop, management listener, housekeeping, and the metrics listener when `settings metrics_listen` names one | — | `Router::run`; none is created per request (3.2) |
| Control socket path | 100 bytes | — | `startup::MAX_UNIX_PATH`, checked before bind |
| Platform secret file | ≥ 32 bytes each, five files | — | `Secrets::from_dir` |

### Limits not enforced

Stated plainly, because a false assurance here is worse than a gap:

- **`settings.max_body_bytes` does not reach the transport.** `startup::Router::assemble`
  binds with `ServerConfig::inference()`, whose `limits` field is the hardcoded
  `Limits::DEFAULT`. The configured value is applied only to the JSON parser. An
  operator who sets `max_body_bytes=1048576` still has 16 MiB read off the wire
  and buffered before the JSON layer refuses it.
- **`ServerConfig` is not configurable at all.** Connection cap, timeouts,
  keep-alive, and requests-per-connection are compile-time constants in
  `ServerConfig::inference()` / `::management()`; no settings field reaches them.
- **No aggregate deadline on request assembly.** `read_head` and `read_body` loop
  with only a per-read socket timeout. Total time to receive a head or body is
  unbounded as long as each individual read completes.
- **No explicit stream watermarks.** Specification 14 asks for high/low
  watermarks that pause upstream reads. Backpressure here is emergent: the
  per-connection thread blocks in `StreamSink::push`, which stops it calling
  `connection.read_body`. The effect is correct for the blocking model, but there
  is no watermark to tune and none to assert on.
- **The full decoded event list is retained per streaming attempt.**
  `dispatch::attempt` pushes every decoded `CanonicalEvent` into `collected` so
  usage and native model can be read after the stream ends. Bytes still reach the
  client incrementally, so specification 14's "MUST NOT buffer an entire
  completion" holds for latency — but memory for one attempt is bounded only
  transitively, by the 64 MiB `Limits::UPSTREAM.max_body_bytes` cumulative cap.
- **No privilege drop.** Specification 18.1 names it as this crate's
  responsibility and 20.1 requires an unprivileged user. `startup.rs` binds
  listeners and serves; it never drops privileges or scrubs the environment.
  Today that is a deployment-image responsibility, undeclared in code.
- **`testing` is a non-gated public module.** `pub mod testing;` has no `cfg` or
  feature guard, so `FakeUpstream`, `TestRouter`, and a fixed store MAC key of
  `b"test-store-mac-key"` are part of the released library's public API. Nothing
  in the binary references them, but the surface is real and should be behind a
  `test-harness` feature.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is a seeded, deterministic mutation engine
in `hypellm-test-corpus::fuzz`, driven from ordinary `tests/fuzz.rs` targets so
that `cargo test` runs it and a failing seed is reproducible by number rather
than by corpus file. All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table. `hypellm-core` carries the
property layer in `tests/properties.rs`.

`tests/fuzz.rs` covers the client-facing protocol parsers — `parse_chat_request`,
`parse_responses_request`, `parse_embeddings_request`, and
`parse_messages_request` — with nine targets. Beyond termination they assert the
Appendix B property that begins here: no mutation may produce a
`CanonicalRequest` whose tenant, principal, request id, residency, or cost
ceiling differs from the authenticated context, and no hint survives from a
principal not permitted one. Each of those targets counts its own successful
parses and fails if none were reached, because a property test that never
reaches its assertion is decoration.

The remaining targets below — the connection-level ones, and the stream
renderers — are still requirements rather than facts:

| Target | Drives | Status |
|---|---|---|
| `client_chat_request` | `protocol::openai::parse_chat_request` over arbitrary bodies | Required, not yet implemented (§21) |
| `client_messages_request` | `protocol::anthropic::parse_messages_request` | Required, not yet implemented (§21) |
| `client_embeddings_request` | `protocol::openai::parse_embeddings_request` | Required, not yet implemented (§21) |
| `inference_head_and_body` | `server::serve_connection` end to end against a raw byte stream, for framing and smuggling | Required, not yet implemented (§21) |
| `upstream_stream_decode` | `dispatch::stream_events` against an adversarial SSE/chunked upstream | Required, not yet implemented (§21) |
| `event_render_roundtrip` | canonical events through `StreamSink` and the two renderers, re-parsed with `wire-sse` and `wire-json` | Required, not yet implemented (§21) |

Every target must assert bounded work and a stable error, per specification 21.1:
no panic, no allocation beyond the declared limits, and an error body containing
no fragment of the input.

Coverage today is unit tests inside each module plus
`crates/hypellm-router/tests/end_to_end.rs`, which exercises the assembled router
against `testing::FakeUpstream`. That is integration coverage, not fuzz coverage,
and it does not satisfy specification 21's fuzz row.

## Public API

See `lib.rs`. The crate is a library plus a thin binary so the pipeline is
testable without spawning a process; `main.rs` contributes argument parsing, exit
codes (2 configuration, 3 state, 4 listener, 5 secrets), and the control socket,
and nothing else.

The surface a caller is expected to use is small: `startup::Router::assemble` and
`Router::serve` to run a node, `startup::check_config` for `--check`, and
`server::Handler` to add a listener. Everything else is public because the
integration tests and the benchmark harness must build the *same* router the
binary builds — `pipeline::execute`, `dispatch::attempt`, and the `protocol`
renderers are exposed for that reason, not as a stable extension point.

`server::ListenerMetrics` is optional and per-plane. A `Server` without one is
still correct; it simply publishes no connection or byte counters, which is the
right default for the benchmark harness and for tests that assert on behaviour
rather than on telemetry. Specification 3.1 keeps the data and management planes
separate, so the label is `inference` or `management` and never shared — a
combined counter would undo that separation in the one view an operator reads
during an incident.
