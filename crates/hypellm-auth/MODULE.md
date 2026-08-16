# Module: hypellm-auth

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace. |
| External dependencies | None. Rust standard library plus workspace path dependencies: `hypellm-core`, `hypellm-crypto`, `wire-json`. |
| Fuzz targets | **None for this crate yet.** Required targets are listed under [Fuzz targets](#fuzz-targets). |

`wire-json` is declared in `Cargo.toml` but is not referenced by any source file
in this crate today. It is a dependency on paper only; either the OIDC token
exchange body parsing lands here and uses it, or the declaration should be
dropped.

## Scope, and the "no verification, no transport" rule

This crate establishes **who a caller is** and **what that identity is permitted
to do**. Specification 18.1: "auth — API keys, sessions, OIDC verifier boundary
client, RBAC." Specification 9.2 lists four ways a principal is established and
each has a home here:

| Method | Module | What is authoritative |
|---|---|---|
| Router API key | `apikey` | `HMAC(server_key, "hypellm.apikey.v1" ‖ key_id ‖ secret)` against a stored verifier |
| Google OIDC session | `oidc`, `session` | Claims of an already-verified token, plus a server-side session digest |
| Local peer credentials | `peer` | An administrator-declared uid → principal mapping |
| Break-glass | `session::AuthMethod::BreakGlass` | A preprovisioned local credential handled exactly as an API key |

What this crate deliberately does **not** do:

- **No signature verification.** Specification 9.1's dependency boundary: "JWT
  signature verification and HTTPS are cryptographic security functions… Never
  write novel signature or TLS code merely to satisfy 'no dependencies'." The
  `oidc::TokenVerifier` trait is the seam. Its implementation lives in
  `hypellm-net` as a client of the platform verifier socket. Nothing in this crate
  parses a JWT, inspects a `kid`, or touches issuer keys.
- **No transport, no I/O, no sockets.** The crate never opens a connection,
  never performs the authorization-code exchange, and never reads a file. It
  produces a URL string and consumes claims; someone else moves the bytes.
- **No credential storage or resolution.** Provider credentials are the
  adapters' business (specification 10). The only key material here is the
  server-side HMAC key each store is constructed with.
- **No password hashing.** The router has no passwords.
- **No throttling.** There is no lockout, backoff, or attempt counter on key or
  session verification. Rate limiting for the auth surface belongs to the
  listener; this crate assumes it exists and does not provide it.
- **No claim checking inside the verifier.** `TokenVerifier::verify` is
  documented as forbidden from validating `iss`, `aud`, `exp`, or `nonce`;
  `oidc::validate_claims` is the single place those are checked. Splitting the
  checks across two components is how one gets skipped.

## Threat notes

### Secret-bearing values redact diagnostic output

`NewKey`, `KeyStore`, `IssuedSession`, `SessionStore`, OIDC transactions and
transaction stores use hand-written `Debug` implementations that redact
one-time tokens and derivation keys. Digest records expose only a shortened
digest representation. Tests assert that API keys, session/CSRF tokens, PKCE
values and store keys do not appear in diagnostic output.

### Credential-oracle leakage through error differentiation

Verification distinguishes `UnknownKey`, `BadSecret`, `Revoked`, `Expired`, and
`SourceNotPermitted` internally, and `AuthFailure::to_router_error` collapses
all of them to one `unauthenticated` response with an identical detail string
(tested in `lib.rs::failures_do_not_disclose_which_check_failed`). Only
`ScopeNotPermitted` and the session's CSRF/origin/permission/reauth rejections
report `forbidden`, which is correct — those callers are already authenticated.
The internal codes are distinct and are intended for audit and metrics. **They
must not reach a client response body, a header, or a metric label keyed by
anything the caller controls.** Specification 8.2 gives `unauthenticated` no
sub-codes precisely because the distinction is an oracle.

### Timing side channels on credential comparison

All secret-vs-candidate comparisons route through `hypellm_crypto::ct::eq`: the
key verifier, the session CSRF token, the OIDC `state`, and the `nonce`. Two
consequences to preserve:

- `KeyStore::verify` computes the candidate digest **before** checking whether
  the record exists, and compares against a zero dummy on the miss path, so an
  unknown prefix and a wrong secret cost approximately the same. Reordering
  those lines reintroduces a "does this key id exist" oracle.
- `Digest: PartialEq` is constant-time but `Digest: Ord` is deliberately not.
  Ordering is used only for `BTreeMap` placement over one-way digests. Do not
  "fix" the inconsistency by making `cmp` constant-time, and do not authenticate
  with `cmp`.

The lookup is not fully constant-time in aggregate: `BTreeMap` probe depth
varies with the stored key set. The digests are HMAC outputs the caller cannot
shape, so this is accepted.

### Forced eviction of in-flight sign-ins

`TransactionStore::begin` evicts the oldest transaction once `MAX_TRANSACTIONS`
(4096) is reached rather than refusing to start a sign-in. `begin` is reachable
**before** authentication, so anyone able to hit the sign-in start endpoint can
issue 4096 requests and evict every legitimate in-flight transaction, turning
every concurrent sign-in into `oidc_unknown_transaction`. This fails closed, not
open, but it is a usable denial of service against management access. The
mitigation must be a rate limit on the sign-in start endpoint at the listener;
this crate does not provide one.

`SessionStore::issue` has the same eviction shape at `max_sessions` (10 000),
but `issue` is reachable only after successful authentication, so the exposure
is far smaller. Both eviction paths are an O(n) `min_by_key` scan performed
while holding the write lock, at every insert once the table is at capacity —
4096 and 10 000 entries respectively. `invalidate_principal` and `sessions_for`
are also O(n) under the lock.

### Silent failure on lock poisoning

Every store maps a poisoned `RwLock` to a benign-looking value rather than
propagating an error, because specification 18.2 forbids panics on data-plane
input. The failure modes are not uniform:

- `KeyStore::insert` and `TransactionStore::begin` **silently discard** the
  record. Subsequent verification fails closed.
- `KeyStore::revoke` returns `false`. Specification 22.3 requires revocation to
  take effect "immediately"; a caller that ignores this return value believes a
  compromised key was revoked when it was not. **The return value is
  load-bearing and must be checked.**
- `SessionStore::validate` returns `SessionRejection::Unknown`, and `sweep` /
  `invalidate_principal` return 0.

A poisoned lock requires a panic while the lock was held, which the coding rules
already forbid — but the degraded behaviour should be surfaced as a health
signal rather than absorbed.

### Identity-header spoofing

`peer::TrustedEdge::resolve` returns an identity only when the peer address is
in `trusted_peers` **and** the forwarded value is a workload the administrator
declared. The default (`TrustedEdge::none()`) trusts nothing, and an unknown
peer address (`None`) is never trusted. This is the control for specification 3's
"never trusts inbound forwarding headers except from configured peers". The
danger is at the call site, not here: the header must be read only on a listener
marked edge-facing, and the peer address passed in must be the real socket peer,
never a value parsed out of `X-Forwarded-For`.

`PeerMap` has no implicit rules — uid 0 is not special, and an empty map
authenticates nobody.

### Open redirect and parameter injection on the sign-in path

An open redirect on an OIDC redirect URI is a token-theft primitive.
`sanitize_return_path` reduces anything that is not a single in-application
absolute path to `/`: absolute URLs, protocol-relative `//host`, backslash forms
some browsers normalise, `://` anywhere, control characters (which would
otherwise permit header injection), and anything over 512 bytes.
`percent_encode` passes only RFC 3986 unreserved characters, so a hostile
`client_id` or `redirect_uri` from configuration cannot inject a second
`redirect_uri` parameter into the authorization URL.

Every endpoint in the authorization URL comes from `OidcConfig`. There is no
code path that reads an issuer, token endpoint, or redirect URI from a request —
specification 9.1: "No discovery URL or redirect is supplied by the browser."

### Session fixation, replay, and CSRF

- Session tokens are 256-bit random values; only `HMAC(digest_key, token)` is
  stored. A leaked session table yields verifiers, not cookies.
- The CSRF token is `HMAC(digest_key, "hypellm.csrf.v1" ‖ session_digest)` —
  derived, so it cannot drift out of sync, and keyed, so a script that can read
  the cookie still cannot compute it. It rotates with the session.
- `rotate` removes the old digest and inserts the new one, so a token fixed
  before sign-in is dead after it (specification 9.1: "Rotate on authentication
  and privilege change").
- `TransactionStore::take` removes the transaction **before** validating state
  or expiry, so a sign-in attempt is strictly single-use and a probed
  transaction cannot be completed afterwards.
- `origin_permitted(None, …)` returns `true`, because browsers omit `Origin` on
  same-origin safe methods. **This means origin checking alone never authorizes
  a mutation.** A state-changing handler must call `verify_csrf` as well;
  specification 9.1 requires both, and the origin check is the weaker half.
- `cookie_value` compares names exactly, rejects values containing whitespace or
  `;`, and returns only the first occurrence — a lenient parser is how an
  attacker-set sibling cookie gets picked up instead of the real one.

### Audit-trail fidelity

`Principal::from_key` sets `method: AuthMethod::LocalPeer` for every
key-authenticated principal. A caller that authenticated with a router API key
is recorded and exported as having used Unix socket peer credentials. This is
not an authentication bypass — scopes, roles, tenant, and `key_id` are all
correct — but it corrupts the audit and metrics view of *how* a principal
authenticated, and specification 22.3's incident workflow ("search authorized
audit/usage by key pseudonym") depends on that field being right. `AuthMethod`
has no `ApiKey` variant to assign; adding one is the fix.

Separately, `Principal::from_session` correctly yields an empty scope set: a
browser session authorizes management actions, never inference. A session that
could also drive the inference API would let a CSRF on the admin UI spend a
tenant's token budget.

### Identity mapping

`IdTokenClaims::identity_key` is `iss|sub`. Specification 9.1: "Email is an
attribute, not the stable identity key." An email address can be reassigned
within a domain; a subject cannot. `hd` is an authorization input and "not proof
of group membership" — groups on `Principal` come from local role bindings or a
provisioned directory sync, never inferred from an email domain.

## Limits

Enforced in this crate:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Presented API key string | 256 bytes | `apikey::parse_key` (bare literal — no named constant) |
| API key identifier field | exactly 16 chars, lowercase hex only | `apikey::KEY_ID_LEN`, alphabet check in `parse_key` |
| Generated key secret | 32 bytes → 43 base64url chars | `apikey::SECRET_BYTES` |
| Principal / tenant / key identifiers | 128 bytes | `hypellm_core::ids::MAX_ID_LEN` |
| Session cookie token | 1–128 bytes before lookup | `session::SessionStore::validate` (bare literal) |
| Generated session token | 32 bytes → 43 base64url chars | `session::TOKEN_BYTES` |
| Session idle lifetime | 30 min | `session::SessionPolicy::DEFAULT.idle_millis` |
| Session absolute lifetime | 12 h | `SessionPolicy::DEFAULT.absolute_millis` |
| Reauthentication window | 5 min | `SessionPolicy::DEFAULT.reauthentication_millis` |
| Concurrent sessions | 10 000, oldest-by-activity evicted | `SessionPolicy::max_sessions`, `SessionStore::issue` |
| OIDC transaction handle | 1–128 bytes before lookup | `oidc::TransactionStore::take` (bare literal) |
| Open OIDC transactions | 4096, oldest evicted | `oidc::MAX_TRANSACTIONS` |
| OIDC transaction lifetime | 10 min | `oidc::TRANSACTION_TTL_MILLIS` |
| Post-sign-in return path | 512 bytes, single absolute path | `oidc::sanitize_return_path` |
| Forwarded workload identity | 1–256 bytes | `peer::TrustedEdge::resolve` |
| CIDR prefix length | > 32 (v4) / > 128 (v6) matches nothing | `apikey::in_network` |

Not enforced here — stated plainly rather than implied:

- **Secret field length in a presented key is not pinned.** `parse_key` requires
  only that the secret be non-empty; a well-formed prefix followed by ~230 bytes
  of arbitrary data is accepted into the HMAC. Total work stays under the
  256-byte cap, so this is bounded, not unbounded — but it is not the 43
  characters a genuine key carries.
- **`bearer_token` applies no length bound.** It is safe to call only after the
  HTTP layer has bounded the header (specification 3.2); `parse_key` is the
  first place a size check happens.
- **`KeyStore` record count is unbounded.** Records arrive from administrator
  action and from store recovery; nothing here caps the map.
- **`IdTokenClaims` field sizes are unbounded.** `sub`, `email`, `hd`, `name`,
  and the `aud` vector are whatever the `TokenVerifier` implementation returns.
  The bound must be imposed by that implementation, in `hypellm-net`.
- **Configuration-derived collections are unbounded here**: `hosted_domains`,
  `trusted_peers`, `workloads`, the CORS allowlist passed to `origin_permitted`,
  and the `scopes` / `roles` vectors on a record. The configuration layer owns
  those maxima.
- **No attempt-rate limit, lockout, or replay cache.** Specification 9.2's
  "signed workload assertion" method, which requires a replay cache, is not
  implemented in this crate at all.
- **No wall-clock source.** Every expiry check takes `now_*_millis` as a
  parameter. Clock skew and monotonicity are the caller's problem; the crate is
  deterministic and testable as a result, and `saturating_sub` / `saturating_add`
  are used throughout so a skewed clock cannot wrap a lifetime.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is a seeded, deterministic mutation engine
in `hypellm-test-corpus::fuzz`, driven from ordinary `tests/fuzz.rs` targets so
that `cargo test` runs it and a failing seed is reproducible by number rather
than by corpus file. All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table. `hypellm-core` carries the
property layer in `tests/properties.rs`.

None cover this crate yet; nothing below is implemented. This is the required
set under specification 21 ("Fuzz: HTTP, JSON, SSE, configuration, provider events,
management API, state recovery") and 18.2 ("Configuration and protocol parsers
are fuzzed").

Required, not yet implemented:

| Target | Surface | Property to assert |
|---|---|---|
| `auth_apikey_parse` (§21) | `apikey::parse_key` over arbitrary bytes | Never panics; accepts only `hypellmk_<16 hex>_<non-empty>`; rejects ≥ 256 bytes before any lookup |
| `auth_bearer_token` (§21) | `apikey::bearer_token` | Never panics on arbitrary header bytes; never returns an empty token |
| `auth_cookie_value` (§21) | `session::cookie_value` | Never panics; never returns a value for a name that is not an exact match; never returns a value containing `;` or whitespace |
| `auth_return_path` (§21) | `oidc::sanitize_return_path` | Output is always `/` or a single absolute in-application path; never contains `\`, `://`, a control character, or a leading `//` |
| `auth_percent_encode` (§21) | `oidc::percent_encode` | Output contains none of `& = ? # % /` except as `%XX` escapes; round-trips under a reference decoder |
| `auth_oidc_claims` (§21) | `oidc::validate_claims` over arbitrary claims and configs | Never panics; never returns `Ok` when `iss`, `aud`, `nonce`, `exp`, `email_verified`, or `hd` fails its rule; arithmetic saturates rather than wrapping |
| `auth_session_lifecycle` (§21, state recovery) | Stateful sequence of `issue`/`validate`/`rotate`/`invalidate`/`sweep` | Table never exceeds `max_sessions`; an invalidated or rotated-away token never validates again; a CSRF token never verifies against a different session |
| `auth_key_lifecycle` (§21, state recovery) | Stateful sequence of `create`/`verify`/`revoke`/`insert` | A revoked key never verifies; a verifier never authenticates a different `key_id`; no generated key string ever contains an ambiguous separator |

Specification 21.1 additionally requires that every change to this crate go
through two-person security review, and that its secret-bearing types pass
log/error/crash redaction tests — see the derived-`Debug` gap above, which such
a test would currently fail.

## Public API

`SessionStore::issue_for` takes an explicit absolute lifetime and is what
specification 22.4's time-limited break-glass session is built on. It only ever
*shortens*: the lifetime is clamped to the policy's, so a misconfigured caller
cannot mint a session that outlives the one every other session obeys.


See `lib.rs`. The crate root re-exports `Principal`, `AuthFailure`, and the
principal types from each module. Several items are reachable only by module
path and are the ones most likely to be missed when wiring a listener:

- `apikey::bearer_token` — `Authorization` header extraction.
- `session::cookie_value`, `session::origin_permitted` — cookie and CORS
  helpers; `origin_permitted` must be paired with `SessionStore::verify_csrf`.
- `oidc::validate_claims`, `oidc::code_challenge_s256`,
  `oidc::sanitize_return_path`, `oidc::percent_encode`.
- `peer::PeerMap`, `peer::PeerSource` — the uid mapping is not re-exported at
  the root, only `PeerIdentity` and `TrustedEdge` are.

`oidc::TokenVerifier` is the crate's one outward-facing trait and the boundary
described in specification 9.1. It is implemented outside this crate. Nothing in
the public surface accepts a caller-supplied endpoint, host, or key handle:
every destination is a field of `OidcConfig`, and every HMAC key is supplied
once at store construction from the platform secret facility.
