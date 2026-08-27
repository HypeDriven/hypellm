# Module: hypellm-admin-api

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace. |
| External dependencies | None. Rust standard library plus the workspace path dependencies `hypellm-auth`, `hypellm-config`, `hypellm-core`, `hypellm-crypto`, `hypellm-fleet`, `hypellm-store`, `hypellm-telemetry`, `wire-http1`, `wire-json`. |
| Fuzz targets | Implemented in `tests/fuzz.rs`: nine seeded mutation properties over authentication, authorization, CSRF, tenant isolation, error redaction and bounded request handling. |

## Scope and the control-plane boundary

This module is the `/admin/v1` surface of specification 16, and the enforcement
point for specification 15.4's API behaviour: explicit JSON schemas, ETags,
`If-Match` on mutation, pagination cursors, stable error codes, and request IDs.
It owns the authorization gate for management actions and four bounded
in-memory views (`DecisionCache`, `AuditIndex`, `UsageAggregate`, `DraftStore`)
that the admin screens of specification 15.3 read.

What it deliberately does **not** do is at least as important, because the crate
sits at the point where an operator's browser meets the router's most privileged
operations:

| Not done here | Where it belongs | Why |
|---|---|---|
| HTTP framing, TLS, sockets | `wire-http1`, `hypellm-router`, platform boundary (4, 20) | The crate receives an already-parsed `AdminRequest` and returns an `ApiResponse`; it never touches a file descriptor. |
| JWT signature verification, code exchange | `oidc::TokenVerifier` behind the approved boundary (9.1) | Specification 4 forbids novel signature or TLS code. `oidc_callback` hands the code to the verifier and validates the *claims* it returns; it speaks no HTTPS. |
| Reading a credential secret | Nowhere — no handler, no permission (9.3) | A credential manager "cannot read secret back". `list_credentials` renders no `secret` field, and `create_credential`/`rotate_credential` accept the value write-only. |
| Routing decisions | `hypellm-core`'s `PolicySnapshot::route` (6) | `simulate_draft` calls the production routing function over `IdealLiveState`, so a simulation cannot drift from what the router would actually decide. |
| Configuration parsing and validation | `hypellm-config` (11.1) | Draft validation is `hypellm_config::load`; this crate stores text and reports the outcome. |
| Being the audit record | `hypellm-store`'s hash chain (17) | `AuditIndex` is a lossy display view. The chain is authoritative and export reads from there. |
| Anything on the inference path | `hypellm-router::pipeline` (3) | The management path is separated "in code, scheduling, rate limits, authentication scopes, and listener configuration". This crate is that separation; it has no handle to the inference pipeline, and `AdminHandler` is mounted on its own listener with `wire_http1::Limits::ADMIN`. |

Specification 16 also lists `POST /admin/v1/targets`. It exists, and it does not
create a target — it creates a **policy draft** containing one. Targets still
come into existence only by publishing a validated draft, which keeps every
routing-relevant object under the draft → validate → approve → atomic-activate
discipline of 15.4 rather than admitting a second, unreviewed mutation path. The
response says `target_created: false` so a client cannot read it otherwise.

Because the handler writes caller-supplied values into configuration *text*, it
refuses anything outside an identifier alphabet (`is_configuration_token`)
rather than escaping it. The grammar is line-oriented and space-separated, so an
unchecked value adds records rather than a field — and a draft is approved by a
second person who reads what they were shown (`DI-047`).

### The fleet surface

Seven endpoints under `/admin/v1/fleet` (specification 26). The live fleet is
reached through the `FleetControl` trait, the same shape `CredentialSink`
already uses and for the same reason: the router depends on this crate rather
than the other way round, so the management API knows *what* it may ask for and
the router knows *how*.

Three properties are worth naming, because each is easy to lose:

- **No sentence an operator reads is authored by the router or the agent.**
  `FleetControl` returns a `&'static str` code; `fleet::control_error` maps it to
  the one message, written in this crate. An implementation that could return
  prose would be a path for agent-supplied strings to reach a browser.
- **An absent fleet answers "not configured on this router", not an empty list.**
  Per the honesty rule, a screen with no backing endpoint says so; a plausible
  empty fleet is exactly what stops an operator going to look.
- **An action is reported as successful only if it was also recorded.** Operator
  activations and deactivations go through `record_audit`, which fails the
  request when the audit record does not reach disk.

`fleet_activate` and `fleet_fetch` are separate permissions, and `fleet_fetch`
requires a fresh authentication: it is the one action on which a single request
can cost the fleet hours of bandwidth and hundreds of gigabytes of disk.

## Threat notes

- **Cross-site request forgery against a privileged session.** The gate in
  `AdminApi::handle` runs origin → session → CSRF → permission → freshness →
  `If-Match`, and the order is load-bearing: a caller from a hostile origin is
  refused before their session cookie is consulted, and an unauthenticated
  caller learns nothing about whether a resource exists. The CSRF token is
  returned in the `GET /admin/v1/session` *body*, never in a cookie, so a page
  that cannot read the response cannot forge a request with it. Note that the
  origin check fires only when an `Origin` header is present; for a request
  without one, the whole defence is the session-bound CSRF header, which a
  simple-request forgery cannot set.
- **Reflected-origin CORS.** `CorsPolicy::permits` is exact string equality with
  no suffix matching, scheme coercion, case folding, or trailing-slash
  tolerance, and no wildcard is ever emitted for any origin. The dangerous
  failure mode is not `*` with credentials — browsers already reject that — but
  reflecting an unchecked `Origin`, which works and hands any site the operator
  visits an authenticated channel to the control plane.
- **Cross-tenant disclosure through management views.** `DecisionCache::get`
  requires a tenant match and reports another tenant's trace as *absent* rather
  than forbidden, so the response does not confirm that a request with that
  identifier exists. `UsageAggregate::rows` never crosses a tenant boundary and
  refuses to attribute an overflow row to any principal, so `ReadOwnUsage` can
  never surface another principal's tokens. `list_keys` filters by
  `session.tenant`. **`list_audit` does not filter by tenant**: `AuditIndex` is
  a single global ring and `recent()` returns every record in it, so a caller
  holding `ReadAudit` in one tenant sees audit rows carrying another tenant's
  identifier. That contradicts 15.4's "management visibility never exceeds the
  caller's tenant" and needs a tenant predicate on the index read.
- **A misleading audit view.** `AuditIndex::record` reconstructs the indexed
  event from the session rather than from what was written, and synthesizes
  `AuditAction::SettingsChanged` with timestamp `0` for every action. The
  durable chain in `hypellm-store` is correct and is what an integrity check
  reads, but the audit *screen* currently reports the wrong action and epoch
  time for every management mutation routed through `record_audit`. A wrong
  action label in an audit UI is worse than a missing one.
- **Fail-closed audit.** `record_audit` propagates an append failure as
  `internal_fault` and the caller reports the action as not applied
  (18.3). `publish_draft` writes the `ConfigActivation` record durably *before*
  the pointer swap: a crash between the two leaves a record of an activation
  that did not take effect, which an operator can see, whereas the reverse
  ordering would leave a running configuration nobody is accountable for.
- **Separation of duties on publication.** The self-approval refusal lives in
  `DraftStore::prepare_publish`, keyed on the draft's author, not on the
  request. A handler-level check could be bypassed by any second code path that
  publishes; a property of the draft cannot.
- **Secret exposure surface.** A key secret is returned exactly once, from
  `create_key`, via `NewKey::into_secret()` (9.2, 15.3). `list_keys` returns no
  verifier material even though it is not the secret. Provider credential
  secrets have no read path at all.
- **Prompts must not reach the control plane.** `build_scenario` accepts a
  *size* (`input_tokens`), never prompt text, and synthesizes filler — 15.4's
  "sanitized request descriptor". A simulation endpoint that took real prompts
  would be a route for prompt content into management logs.
- **ETag correctness as a safety property.** `etag_for` digests the resource's
  *canonical* JSON (`wire_json::to_canonical_vec` + SHA-256), so key ordering
  cannot change the tag and the tag changes exactly when the resource does. A
  timestamp- or counter-derived tag would either churn — defeating the
  optimistic concurrency `If-Match` exists for — or fail to change when it must.
- **Panic-on-input reachability.** The release profile sets
  `overflow-checks = true` and `panic = "abort"`, so an arithmetic overflow or
  an allocation failure on this path terminates the process. Two inputs reach
  such a computation unbounded; see [Unbounded inputs](#unbounded-inputs).
- **`percent_decode` relies on a cross-crate invariant.** It slices
  `&value[i + 1..i + 3]` by byte index, which is panic-free only because the
  query string is guaranteed ASCII by `wire_http1::parse_target` (visible-ASCII
  only). Nothing in *this* crate enforces that, and `AdminRequest` is a public
  type any caller can construct: a non-ASCII query with a `%` before a multibyte
  character would slice across a character boundary and panic.
- **Parser differentials.** Management bodies are parsed by `wire-json` with
  `reject_duplicate_keys: true`, so `{"state":"enabled","state":"quarantined"}`
  is refused rather than resolved to whichever occurrence this crate happens to
  read.
- **Credential endpoints are stubs that report success.**
  `create_credential` and `rotate_credential` validate the request, write an
  audit record, and return `{"stored": true}` / `{"rotated": true}` — but the
  secret is bound to `let _secret` and discarded. Nothing is handed to a secret
  facility. An operator who rotates a credential here is told it worked and it
  did not. Until a secret backend exists, this is a false assurance rather than
  an unimplemented feature, and it should fail closed instead.
- **Tenant assignment at sign-in is arbitrary.** `resolve_identity` binds a
  principal by role bindings (correctly refusing to key on email, per 9.1) but
  then takes `config.tenants.keys().next()` as the tenant. In a multi-tenant
  deployment every OIDC principal lands in the first tenant by map order.

### Password sign-in is the weakest way in, and is bounded accordingly

`POST /admin/v1/auth/password` authenticates a `local_user` against a PBKDF2
verifier. It is a deviation from specification 9.2, recorded in
`docs/deferred-issues.md`, and it runs *before* any session — so an
unauthenticated caller who can reach the management listener decides how often
it runs. Three bounds follow, and each has a test:

- **A locked account is refused before the hash is computed.** Five failures in
  a minute lock one account for the rest of that window. Checking after the
  verification would still refuse the right password, so the ordering is what
  makes the lockout a bound on *work* rather than on outcomes — a verification
  is ~100 ms of CPU.
- **At most two verifications run at once.** The lockout alone does not bound
  total CPU: with enough configured accounts a caller could start one expensive
  verification per account simultaneously.
- **The failure map is keyed by a configured username.** An unknown name never
  enters it, so a caller cannot grow it; `hypellm_config::MAX_LOCAL_USERS` caps
  what a configuration can.

Not hidden, deliberately: an unknown username is refused without hashing, so it
is refused faster than a known one with a wrong password. Hashing a dummy
verifier to level the timing would hand an unauthenticated caller a CPU
amplifier. The trade is stated in `docs/deferred-issues.md`.

## Limits

Enforced in this crate:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Management request bodies (most handlers) | 1 MiB input, depth 32, 64 KiB per string, 10 000 array items, 2 000 object entries, duplicate keys rejected | `wire_json::Limits::SMALL` via `AdminRequest::json` |
| `POST /admin/v1/policies` body | `wire_json::Limits::DEFAULT` (16 MiB, depth 64, 8 MiB per string) — in practice capped at 1 MiB by the listener | `create_draft` |
| Page size | default 50, maximum 500, clamped rather than refused | `Pagination::DEFAULT_LIMIT`, `Pagination::MAX_LIMIT` |
| Pagination cursor | 256 bytes; a longer `after` is ignored, not stored | `Pagination::from_query` |
| Path segment after a route prefix | 256 bytes, must be non-empty and contain no `/` | `handlers::suffix` |
| Audit rows per response | `min(page.limit, 500)` | `list_audit` |
| Audit index depth | 2 048 records, oldest evicted | `AuditIndex::default()` |
| Decision traces retained | 4 096, oldest evicted | `DecisionCache::default()` |
| Distinct usage rows | `MAX_SERIES` = 4 096; further tuples fold into a per-tenant overflow row and `truncated` is reported | `UsageAggregate::record` |
| Usage counters | saturating `u64` addition throughout | `UsageTotals::add`, `UsageAggregate::summary` |
| Drafts retained | 256; the oldest by `created_at_millis` is evicted on overflow | `DraftStore::capacity` |
| Preflight cache lifetime | 600 s | `CorsPolicy::max_age_secs` |
| Break-glass reason | 8–256 characters, required | `MIN_BREAK_GLASS_REASON` / `MAX_BREAK_GLASS_REASON` in `break_glass` |
| Break-glass session lifetime | `settings break_glass_ttl_secs` (default 900 s), clamped to the ordinary absolute lifetime | `SessionStore::issue_for` |
| Password failures before lockout | 5 per account per 60 s window | `MAX_PASSWORD_FAILURES`, `PASSWORD_LOCKOUT_WINDOW_MILLIS` |
| Concurrent password verifications | 2 | `MAX_CONCURRENT_PASSWORD_CHECKS` |
| Tracked password-failure accounts | `hypellm_config::MAX_LOCAL_USERS` (64), and only configured names | `PasswordThrottle` |

Enforced by the management listener before this crate is entered
(`hypellm_router::server::ServerConfig::management`, `wire_http1::Limits::ADMIN`),
and relied upon here:

| Input | Limit |
|---|---|
| Request head | 16 KiB, 64 headers, 2 KiB request target |
| Request body | 1 MiB |
| Concurrent connections / requests per connection | 256 / 200 |
| Read and write deadlines | 15 s each; 30 s keep-alive |

### Unbounded inputs

These are inputs that specification 3.2 requires to be bounded and that the code
does **not** currently bound. They are listed as gaps, not as limits.

| Input | Consequence |
|---|---|
| `input_tokens` in `POST /admin/v1/policies/{id}:simulate` | `build_scenario` accepts any value that fits `u32` and evaluates `"x".repeat(n * 2)`, so a single request from a caller holding `SimulatePolicy` can request an ~8.6 GiB allocation. It needs a ceiling at or below the largest declared `max_context_tokens`. |
| `duration_seconds` in `PATCH /admin/v1/targets/{id}` (quarantine) | `patch_target` computes `wall_millis() + duration * 1000` on a `u64` derived from an unbounded `i64`. Values above ~1.8 × 10¹⁶ overflow; with `overflow-checks = true` and `panic = "abort"` that terminates the router. A quarantine also has no maximum duration. |

## Fuzz targets

Specification 21 lists the management API as a required fuzz surface, and
`tests/fuzz.rs` is that suite: nine targets driving the real `AdminApi::handle`
through the behavioural harness, so a mutation passes the gate, the session
check, and the CSRF check exactly as a request would. The engine is
`hypellm-test-corpus::fuzz`; there is no `fuzz/` directory and no libFuzzer,
because specification 4 admits no such dependency.

| Target | Property asserted |
|---|---|
| `no_mutated_body_panics_a_handler` | Every mutated body on every mutating route produces a status |
| `no_body_makes_an_unauthenticated_caller_succeed` | The gate is a property of the surface, not of a handler |
| `no_body_makes_an_unprivileged_session_succeed` | Authenticated ≠ authorized, whatever the body says |
| `a_missing_csrf_header_is_refused_however_the_body_is_shaped` | Cross-site POSTs are refused before a handler acts |
| `an_error_never_echoes_the_request_body` | A malformed management body is often a mis-pasted secret |
| `a_mutated_query_string_never_widens_a_listing` | Appendix B: visibility never exceeds the caller's tenant |
| `an_oversize_body_is_refused_rather_than_buffered` | Specification 3.2 |
| `deeply_nested_input_is_refused_rather_than_overflowing_the_stack` | The recursion bound is a refusal |
| `random_bytes_on_every_route_are_handled` | Unstructured input |

The fifth found a real leak on its first run: `unknown scope '{text}'` echoed an
unbounded caller string into a 400. Echoed values now go through `echo`, which
caps at 32 characters and narrows to an identifier alphabet — a typo still comes
back readable, a pasted key does not.

Still outstanding:

| Target | Surface | Status |
|---|---|---|
| Management request handling | Mutated bodies traverse the real handler with bounded responses and no panics | Implemented in `tests/fuzz.rs` |
| Authentication and authorization | Mutated requests cannot create unauthenticated or unprivileged success | Implemented in `tests/fuzz.rs` |
| CSRF | Mutated bodies cannot bypass a missing CSRF header | Implemented in `tests/fuzz.rs` |
| Query and tenant isolation | Mutated query strings cannot widen tenant-scoped listings | Implemented in `tests/fuzz.rs` |
| Error redaction | Planted request secrets do not appear in error responses | Implemented in `tests/fuzz.rs` |
| Draft and input bounds | Oversized and malformed management inputs fail within configured limits | Implemented in `tests/fuzz.rs` |

The security tests of 21.1 also apply and are not yet written: positive and
negative authorization cases for every privileged endpoint, tenant-isolation
cases for `decisions`, `usage`, `keys`, and `audit`, and redaction cases proving
no secret or credential value appears in any response body or error.

## Public API

See `lib.rs`. The surface is `AdminApi::handle(&AdminRequest) -> Result<ApiResponse, ApiError>`
plus the state it is constructed over (`AdminState`) and the four bounded views
that both planes share by `Arc`. `ApiErrorCode` is a closed enumeration with a
fixed status mapping, so a handler cannot invent an error code or a status at a
call site; `ApiResponse` carries the ETag rather than leaving it to the caller
to remember.

`BreakGlassPolicy` is `None` in a deployment that has not preprovisioned a
token, and the endpoint then returns 404 rather than "wrong token" — an endpoint
that exists but cannot succeed is an oracle. The policy carries a *verifier*,
never a token: specification 22.4 requires the token to be held offline, so a
copy anywhere the router can read would make reading the secrets directory
itself a way in.

**Every audit write must go through `record_audit`, not `store.append_audit`.**
The wrapper appends durably *and* indexes the event it appended; appending
directly leaves the durable chain correct and the audit view blank. That is
`DI-051`, and it has now happened three times — once through a synthesised
placeholder, once on the OIDC login path, once on break-glass. A test that
asserts only `audit_count()` will not catch it; read back through
`GET /admin/v1/audit`.

Specification 21.1 requires two-person review for changes to authentication,
parsers, policy activation, and storage integrity. Every one of those touches
this crate: the gate in `AdminApi::handle`, `break_glass`, `build_scenario`,
`publish_draft`, and `record_audit` respectively.
