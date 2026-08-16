# Module: hypellm-net

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library plus workspace path dependencies: `hypellm-core`, `hypellm-crypto`, `hypellm-auth`, `wire-http1`, `wire-json`, `wire-sse`; `hypellm-store` for tests only. |
| Fuzz targets | **None for this crate yet.** Four are required — see [Fuzz targets](#fuzz-targets). |

Two declared dependencies are not used by `src/` today: `wire-sse` appears only
in a streaming integration test, and `hypellm-crypto` is unreferenced. Neither is
a supply-chain concern (both are workspace crates), but the manifest overstates
the real coupling.

## Scope

This crate is the only place the router opens an outbound socket. It owns four
things:

| Concern | Module | Specification |
|---|---|---|
| Resolve, classify, pin, dial a destination | `egress` | 10, 10.1 (SSRF / DNS rebinding) |
| One bounded, deadline-driven upstream HTTP/1.1 exchange | `client` | 14, 18.2 |
| Connection reuse keyed for credential isolation | `pool` | 19, 22.2 |
| Clients for the platform TLS helper and the identity verifier | `helper` | 4, 9.1 |

### What this module deliberately does not do

Specification 4 (`TLS reality`) and 9.1 (`OIDC dependency boundary`) both draw
the line at the same place, and this crate sits on the router's side of it.

- **No TLS.** There is no handshake, no certificate validation, no cipher
  selection, no session resumption here. `TlsHelper::connect` sends one line to
  a Unix socket and receives back a transport carrying the session's plaintext.
  If the helper is absent, `Egress::acquire` returns an error; it never falls
  back to a cleartext socket carrying a provider credential.
- **No JWT verification.** `VerifierClient` submits a token and reads back a
  claims document. It performs no signature check, and `parse_claims`
  deliberately does **not** validate `iss`, `aud`, `exp`, or `nonce` — those live
  in `hypellm_auth::oidc::validate_claims` so that a check cannot be quietly
  skipped on one of two paths.
- **No DNS implementation.** `SystemResolver` calls the platform resolver. The
  "controlled resolver" of specification 10 is the classification that follows,
  not a bespoke DNS parser in the trusted computing base.
- **No routing decisions.** Nothing here ranks, scores, or selects a target.
  `Egress::acquire` takes an already-chosen `Endpoint` and `EgressProfile`.
- **No credentials.** No type in this crate holds, reads, or constructs a
  provider credential. Authorization headers are built inside the adapter
  boundary and arrive here as opaque request bytes. The pool key carries a
  *credential isolation class* string, never a credential.
- **No URLs.** There is no public function anywhere in the crate that accepts a
  URL, a redirect, or a client-supplied host. Every destination originates as a
  validated-configuration `Endpoint`. Proxy environment variables (`HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) are never read.
- **No protocol parsing.** Head and body parsing is `wire-http1`; claims parsing
  is `wire-json`. This crate supplies bytes and bounds, and interprets neither.

## Threat notes

- **SSRF and DNS rebinding (10.1).** The defence is structural: `Dialer::connect`
  accepts only a `PinnedDestination`, never a host and port, and the only
  production path that yields one is `Resolver::resolve`, which classifies every
  candidate through `hypellm_core::netaddr::classify` and pins the first address
  the `EgressProfile` permits as a concrete `SocketAddr`. A second DNS answer
  has nothing to attach to. `AddressClass::Metadata` is refused by *every*
  profile including `LOCAL` — `EgressProfile::permits` returns `false` for it
  unconditionally, and IPv4-mapped forms such as `::ffff:169.254.169.254`
  classify as `Metadata` too. **Caveat:** `PinnedDestination` has public fields,
  so the type is a discipline, not a capability — a struct literal bypasses
  classification entirely. Only tests do this today; making the fields private
  behind a constructor would turn the discipline into an enforced invariant.
- **Pool hits skip classification.** `Egress::acquire` consults
  `ConnectionPool::take` *before* `Resolver::resolve`, so a pool hit never faces
  the address-class check. `pool_key` therefore includes the `EgressProfile`
  alongside scheme, host, port, credential class, and protocol: a connection can
  only be reused under the profile it was opened for, which is what keeps a
  socket established under a permissive profile from serving a request made
  under a stricter one. Any new component of the decision to connect must join
  the key for the same reason.
- **Reuse failures are not upstream failures.** A pooled connection can be
  closed by the peer at any point while it is idle, and that close is only
  observable by attempting the exchange. `UpstreamConnection::is_pooled`
  distinguishes a reused socket from a fresh one so the caller can tell the two
  apart, and `Egress::dial_fresh` opens a connection bypassing the pool — but
  **not** the egress guard, which it applies exactly as `acquire` does. The
  retry policy itself lives in the router's dispatch layer, not here: this crate
  still contains no retry loop.

  `is_pooled` on its own is **not** sufficient grounds to replay a request, and
  a caller that treats it that way has a specification 6.5 defect. A live pooled
  connection can also fail while reading the head — a timeout, a partial head —
  and there the provider may have read the request and begun work. That is what
  `UpstreamConnection::has_received_any` is for: a close with zero bytes ever
  received is the idle-socket case and is replayable; anything else is not.
- **Cross-tenant reuse (19).** The credential isolation class is a key
  component, so two tenants using different provider credentials against the
  same endpoint never share a socket. This matters where a provider binds
  authentication to the connection rather than to the request: sharing would
  send one tenant's request under another's credential. `drain_key` exists so a
  single credential rotation (22.2 step 17) closes only the affected sockets.
- **Response desynchronisation.** A pooled connection whose framing is in doubt
  becomes the next caller's answer. `UpstreamConnection` poisons itself on a
  head that exceeds `MAX_HEAD_BUFFER`, on truncation before or during the body,
  on `Connection: close`, and in `finish_body` whenever the body ended at EOF
  rather than at its declared boundary. `ConnectionPool::put` closes rather than
  stores anything not `is_reusable()`, so a caller cannot pool a bad socket by
  mistake. TE/CL ambiguity is rejected upstream in `wire-http1` and surfaces as
  `UpstreamError::Protocol`.
- **Hostile upstream resource exhaustion.** A provider is not trusted (8.2 has a
  dedicated `upstream_invalid_response` status). The head phase is bounded by
  `MAX_HEAD_BUFFER`; `fill` grows the buffer by a fixed `READ_CHUNK` and
  reclaims the consumed prefix rather than growing without bound. **Gap:** there
  is no per-stream high/low watermark in this crate. Specification 3.2's 256 KiB
  per-stream budget and 14's backpressure rules are the caller's responsibility
  today — `read_body` will keep appending to the caller's `Vec` and
  `read_body_to_end` is bounded only by the `BodyDecoder`'s own
  `max_body_bytes`.
- **Blocking, undeadlined DNS.** `SystemResolver::lookup` calls
  `ToSocketAddrs::to_socket_addrs`, which has no timeout and no cancellation
  path. Specification 3.2 requires blocking DNS to run on a bounded worker pool
  and 18.2 requires every I/O to have a deadline. Neither is satisfied inside
  this crate; a hostile or failing resolver stalls the calling thread. This is a
  known gap, not a delegated concern.
- **A hostile helper's strings.** The TLS helper is trusted to terminate TLS,
  not to author text the router will echo. Its status line is capped at
  `MAX_STATUS_LINE` and any `ERR` code passes `sanitize_code`, which truncates
  to 64 characters and maps everything outside `[A-Za-z0-9_-]` to `_` — closing
  terminal-escape and quote injection into logs and error bodies.
- **Helper over-read discards bytes.** `TlsHelper::connect` reads the status
  line through a temporary `BufReader` over a cloned handle, then returns the
  *original* stream. `BufReader::read` into a one-byte buffer fills its internal
  buffer first, so any bytes the helper writes in the same flush as `OK\n` are
  buffered and then dropped when the `BufReader` falls out of scope. Today the
  helper has nothing to send at that moment, because the router writes its
  request only after `connect` returns. A helper that ever pipelines would
  silently lose the head of its first response. Do not remove this note without
  removing the `BufReader`.
- **The verifier as an identity oracle.** Failure must never read as success:
  an unreachable verifier maps to `OidcError::VerifierUnavailable` and a refusal
  to `OidcError::SignatureInvalid` — both rejections. `parse_claims` returns
  `None` without `iss` or `sub`, and defaults `email_verified` to `false` so an
  absent claim cannot read as verified. Note one imprecision: a token over
  `MAX_TOKEN_BYTES` is reported as `ReplyTooLarge` and therefore reaches the
  caller as `VerifierUnavailable`, so an oversized-token attack shows up in
  metrics as an availability problem rather than a rejected credential.
- **Error text is for operators, not clients.** `EgressError` and
  `HelperError` `Display` include the configured host and the underlying
  `io::Error` text. Those values are administrator-supplied, but per 10 and 17
  they must not be echoed to a caller verbatim or used as a metric label. The
  stable `code()` strings (`destination_refused`, `resolution_failed`,
  `invalid_host`, `connect_failed`, `connect_timeout`, `upstream_truncated`,
  `upstream_timeout`, `upstream_io_error`, `upstream_head_too_large`,
  `helper_unavailable`, `helper_refused`, `helper_protocol_violation`,
  `helper_reply_too_large`) are the public surface.
- **Prompts are inert (10.1).** Request bytes pass through `send` and
  `write_chunk` as an opaque slice. Nothing in this crate inspects them, and no
  value derived from them can reach a destination, a `Host`, an SNI name, a
  socket path, or a pool key.

## Limits

Enforced within this crate:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Buffered response-head bytes | 128 KiB | `client::MAX_HEAD_BUFFER`; poisons the connection and returns `HeadTooLarge` |
| Socket read increment | 16 KiB | `client::READ_CHUNK` |
| Helper status line | 256 bytes | `helper::MAX_STATUS_LINE` → `ReplyTooLarge` |
| Verifier claims document | 64 KiB | `helper::MAX_CLAIMS_BYTES`, checked against the declared length before allocating |
| Token submitted for verification | 16 KiB | `helper::MAX_TOKEN_BYTES`, checked before any socket is opened |
| Helper-supplied error code | 64 chars, `[A-Za-z0-9_-]` | `helper::sanitize_code` |
| Idle connections per pool key | 32 (default) | `PoolConfig::max_idle_per_key` |
| Idle connections overall | 512 (default) | `PoolConfig::max_idle_total` |
| Idle connection lifetime | 60 s (default) | `PoolConfig::idle_timeout_millis`, checked in `take` and `sweep` |
| Connect / read / write deadline | Caller-supplied | `Egress::connect_timeout`, `UpstreamConnection::apply_deadline`; clamped to ≥ 1 ms in `Dialer::connect` and `Transport::set_timeouts` so an exhausted budget fails fast instead of meaning "block forever" to the kernel |
| Destination host syntax | ≤ 253 bytes, labels ≤ 63 | `hypellm_core::netaddr::is_valid_host`, before resolution |

Applied by this crate but defined elsewhere, and therefore only as tight as the
caller makes them:

| Input | Limit | Source |
|---|---|---|
| Response head bytes / header count | 32 KiB / 100 | `wire_http1::Limits::UPSTREAM`, passed into `read_head` by the caller |
| Response body bytes | 64 MiB | `wire_http1::Limits::UPSTREAM` via the caller's `BodyDecoder` |
| Chunk-size line / trailer bytes | 256 B / 4 KiB | `wire_http1::Limits::UPSTREAM` |
| Claims JSON depth / string / input | 32 / 64 KiB / 1 MiB | `wire_json::Limits::SMALL`, fixed by `VerifierClient::verify` |

Not enforced — stated so the gap is not mistaken for a control:

- **Per-stream buffered data (3.2: 256 KiB).** No watermark exists here; see the
  resource-exhaustion note above.
- **Concurrent outbound connections.** `ConnectionPool` bounds *idle* sockets
  only. Nothing in this crate caps how many exchanges are in flight; that bound
  belongs to admission control in `hypellm-core`.
- **DNS resolution time.** No deadline; see the blocking-DNS note above.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is a seeded, deterministic mutation engine
in `hypellm-test-corpus::fuzz`, driven from ordinary `tests/fuzz.rs` targets so
that `cargo test` runs it and a failing seed is reproducible by number rather
than by corpus file. All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table. `hypellm-core` carries the
property layer in `tests/properties.rs`.

None cover this crate yet. The following are required by specification 21
(Fuzz: HTTP, provider events, state recovery) and 18.2 ("configuration and
protocol parsers are fuzzed"):

| Target | Surface | Status |
|---|---|---|
| `upstream_response` | Arbitrary bytes, split at arbitrary offsets, through `UpstreamConnection::read_head` and `read_body`. Asserts bounded allocation and no panic. | Required, not yet implemented (§21) |
| `helper_status_line` | Arbitrary helper replies through `read_status_line` and `sanitize_code`. Asserts the 256-byte bound and that no output escapes the identifier alphabet. | Required, not yet implemented (§21) |
| `verifier_claims` | Arbitrary `VERIFY` replies through `VerifierClient::exchange` and `parse_claims`. Asserts no claim is fabricated from a malformed document. | Required, not yet implemented (§21) |
| `egress_resolve` | Arbitrary host strings and resolver answers through `Resolver::resolve`. Asserts the invariant that no address whose class the profile refuses is ever pinned. | Required, not yet implemented (§21) |

The `egress_resolve` invariant is also a property test obligation under 21
(Property: bounded allocation) and 21.1 (Security: SSRF).

## Public API

See `lib.rs`. The surface is `Egress` plus the four modules' types:
`Resolver` / `Resolve` / `StaticResolver` / `SystemResolver`,
`PinnedDestination` / `DestinationAddress` / `Dialer` / `Transport` /
`EgressError`, `UpstreamConnection` / `UpstreamError`, `ConnectionPool` /
`PoolConfig` / `pool_key`, and `TlsHelper` / `VerifierClient` / `HelperError`.

The narrowness is the point. There is no function taking a URL, no redirect
follower, no retry loop, and no proxy support; the only production path to a
dialable `PinnedDestination` is `Resolver::resolve`. Widening any of those, or
loosening the pinning discipline noted above, requires two-person security
review under 21.1.
