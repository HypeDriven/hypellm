# HypeLLM Router — threat model

Specification 10.1 requires a threat model summary; specification 4.1 requires
per-module threat notes; Appendix C requires that "threat model and abuse cases
are current". This document is the deployment-level half. The per-module half
already exists and is **not** repeated here — each crate's `MODULE.md` carries
the threat notes, limits, and fuzz obligations for its own code, and this
document links to them rather than restating them.

| Module | Threat notes |
|---|---|
| Provider adapters, credential headers | [`crates/hypellm-adapters/MODULE.md`](../crates/hypellm-adapters/MODULE.md) |
| Management API, CSRF, tenant scoping | [`crates/hypellm-admin-api/MODULE.md`](../crates/hypellm-admin-api/MODULE.md) |
| API keys, sessions, OIDC, RBAC | [`crates/hypellm-auth/MODULE.md`](../crates/hypellm-auth/MODULE.md) |
| Configuration grammar and validation | [`crates/hypellm-config/MODULE.md`](../crates/hypellm-config/MODULE.md) |
| Routing, admission, address classes | [`crates/hypellm-core/MODULE.md`](../crates/hypellm-core/MODULE.md) |
| Digests, HMAC, randomness | [`crates/hypellm-crypto/MODULE.md`](../crates/hypellm-crypto/MODULE.md) |
| Dependency and web-asset scanning | [`crates/hypellm-devtools/MODULE.md`](../crates/hypellm-devtools/MODULE.md) |
| Egress, DNS pinning, TLS helper | [`crates/hypellm-net/MODULE.md`](../crates/hypellm-net/MODULE.md) |
| Listener, pipeline, protocol translation | [`crates/hypellm-router/MODULE.md`](../crates/hypellm-router/MODULE.md) |
| Framed log, snapshots, audit chain | [`crates/hypellm-store/MODULE.md`](../crates/hypellm-store/MODULE.md) |
| Metrics and log vocabularies | [`crates/hypellm-telemetry/MODULE.md`](../crates/hypellm-telemetry/MODULE.md) |
| HTTP/1.1, JSON, SSE parsers | [`crates/wire-http1/MODULE.md`](../crates/wire-http1/MODULE.md), [`crates/wire-json/MODULE.md`](../crates/wire-json/MODULE.md), [`crates/wire-sse/MODULE.md`](../crates/wire-sse/MODULE.md) |

> Current deployment limitations and their mitigations are listed in
> [current limitations](deferred-issues.md). Source-level details live in each
> crate's `MODULE.md`.

---

## 1. Trust boundaries

The router sits between four populations with different trust levels. Each
boundary is a place where data changes trust class, and every control in
section 4 belongs to exactly one of them.

```text
   ┌──────────────────────┐
   │ Untrusted inference  │  API key over HTTP/1.1
   │ caller (harness)     │────────────┐
   └──────────────────────┘            │  B1
                                       ▼
   ┌──────────────────────┐    ┌───────────────┐   B3   ┌──────────────────┐
   │ Semi-trusted         │───▶│ hypellm-router  │───────▶│ Hostile provider │
   │ operator (browser)   │ B2 │   process     │◀───────│ response         │
   └──────────────────────┘    └───────┬───────┘        └──────────────────┘
                                       │ B4
                                       ▼
                            ┌──────────────────────┐
                            │ State + secrets dirs │
                            └──────────────────────┘
```

### B1 — The untrusted inference caller

A coding harness holding a router API key, reaching
`crates/hypellm-router/src/server.rs` on the inference listener. It controls the
HTTP framing, the request body, the model string, prompt content, tool schemas,
and how fast it reads the response.

Trusted for: nothing except the possession of a key, which establishes a
principal, a tenant, and a scope set (`crates/hypellm-router/src/routes.rs`,
`authenticate`).

Not trusted for: its own identity claims, its tenant, its group membership, the
destination of its request, the size of anything it sends, or its willingness to
finish an exchange. `/health/live` and `/health/ready` answer this population
*before* authentication and are the only pre-auth surface on this listener
(`routes.rs`, `InferenceHandler::handle`).

### B2 — The semi-trusted operator

A human in a browser on the management listener, authenticated by Google OIDC
and authorised by RBAC (`crates/hypellm-admin-api/src/handlers.rs`,
`crates/hypellm-core/src/rbac.rs`). Operators are trusted to hold privileges, and
*not* trusted to be free of a hostile page in an adjacent tab, a stolen session
cookie, or a mistaken policy edit.

The boundary is therefore doubled: RBAC bounds what an authentic operator may
do, and origin/CSRF/`If-Match` bound what an *attacker acting through* that
operator's browser may do. Separation of duties on policy publication
(`crates/hypellm-admin-api/src/drafts.rs`, `DraftStore::prepare_publish`) bounds
what a single compromised operator can activate.

### B3 — The hostile provider response

Upstream providers are treated as untrusted input sources, not as authorities.
Everything crossing back — status codes, headers, JSON bodies, SSE frames,
error `type` strings, token indices, usage counts — is attacker-controllable in
the threat model, because a provider may be compromised, misconfigured, or
impersonated by anything that got between the router and it.

The canonical model is the boundary: no provider byte reaches a client and no
client byte reaches a provider. Both directions cross
`hypellm_core::canonical::CanonicalRequest` / `CanonicalEvent`
(`crates/hypellm-adapters/src/`, `crates/hypellm-router/src/protocol/`).

### B4 — The hostile state directory

The state directory (`log.bin`, `snapshot.bin`, `snapshot.meta`, `lock`) and the
secrets directory are on a filesystem the router does not control. The modelled
attacker has write access to those files but does **not** hold the store MAC
key, which arrives from outside the directory
(`crates/hypellm-router/src/startup.rs`, `Secrets::from_dir`).

That split is the entire basis for the store's integrity claims: CRC-32 detects
accident, HMAC-SHA-256 over protected frames detects an attacker
(`crates/hypellm-store/src/frame.rs`). An attacker who obtains the MAC key defeats
all of it, which is why the secrets directory is a separate asset below.

---

## 2. Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| **Provider credentials** | `<secrets>/credentials/<id>` on disk; `CredentialStore` in memory (`crates/hypellm-router/src/state.rs`) | Direct spend against the operator's provider accounts, and access to any data those accounts reach. Not recoverable by revoking a router key. |
| **API key verifiers + the key verifier key** | `KeyStore` (`crates/hypellm-auth/src/apikey.rs`), keyed by `<secrets>/key_verifier.key` | The verifier alone is one-way. The *key* lets an attacker mint a verifier for a secret of their choosing, i.e. forge any router API key. |
| **Session and CSRF material** | `SessionStore` (`crates/hypellm-auth/src/session.rs`), keyed by `<secrets>/session.key` | Full management-plane impersonation, including policy publication and credential rotation. The store holds only `HMAC(digest_key, token)`, so the table is worth less than the key. |
| **Prompt and completion content** | In flight only. Never logged (`crates/hypellm-telemetry/src/logs.rs` `Field`), never in a metric label, never in a decision trace, never in a config error | Disclosure of source code, secrets pasted into prompts, and business content. This is usually the highest-value data flowing through the router. |
| **The audit chain** | `log.bin` protected frames plus HMAC checkpoints (`crates/hypellm-store/src/audit.rs`) | Loss of accountability. An attacker who can rewrite history undetected can erase the record of their own privilege use. |
| **The policy snapshot** | `Activatable<ValidatedConfig>` (`crates/hypellm-store/src/activation.rs`), durable as `ConfigActivation` frames | Tampering re-points aliases at attacker-chosen targets, widens grants, or lifts denies. Policy *is* the authorization surface for routing. |
| **The store MAC key** | `<secrets>/store_mac.key` | Every integrity guarantee in B4 at once. |
| **The pseudonym key** | `<secrets>/pseudonym.key` | Retroactive de-anonymisation of every historical log line; the identifier space is small enough to enumerate. |

---

## 3. Attacker capabilities considered

Modelled:

- **Network-adjacent client.** Can open connections to the inference listener,
  send arbitrary bytes, hold connections open, and disconnect mid-stream. May
  hold a valid API key for one tenant.
- **Hostile web origin.** Can cause an authenticated operator's browser to issue
  cross-origin requests to the management listener, and can read anything a
  same-origin script could read if the SPA has an injection flaw.
- **Compromised or impersonated provider.** Returns arbitrary bytes, arbitrary
  framing, arbitrary error taxonomies, and arbitrary delays.
- **Filesystem-local attacker.** Reads and writes the state directory; does not
  hold the secrets directory.
- **Malicious or mistaken single operator.** Holds one role's permissions and
  attempts to exceed them or to act without a second reviewer.
- **Supply-chain author.** Attempts to introduce a registry dependency, a build
  script, a proc macro, or a vendored web asset.

Explicitly **not** modelled — stated so nobody reads a control as covering them:

- An attacker who holds the secrets directory. Every keyed control fails; the
  response is key rotation and re-issue, not detection.
- An attacker with code execution in the router process. `#![forbid(unsafe_code)]`
  reduces the ways to get there; it does not contain one who arrives.
- Side-channel recovery of prompt content from timing or packet sizes.
- A hostile TLS helper or identity verifier. Both are inside the trusted
  computing base by construction (specification 4, 9.1); their strings are
  sanitised (`crates/hypellm-net/src/helper.rs`, `sanitize_code`) but their
  answers are believed.
- Availability against a determined attacker who can exhaust the connection cap.
  Bounds keep the failure orderly (429/503 and close), not absent.

---

## 4. Threats and controls

Rows follow specification 10.1's summary table. Every "control" names the file
that implements it, so a reviewer can check the claim rather than trust it.

### 4.1 Dependency and supply-chain injection

| Control | Where |
|---|---|
| No registry dependency anywhere in the workspace; every dependency is a path inside the repository | `Cargo.toml` (no `[dependencies]` on a registry), enforced by `crates/hypellm-devtools/src/manifest.rs` |
| No `build.rs`, no proc macro, no dynamic loading, no shell execution | `crates/hypellm-devtools/src/rust_scan.rs` |
| `#![forbid(unsafe_code)]` at every crate root | workspace lint table plus `rust_scan.rs` check |
| No `vendor/`, no remote origin, no `eval`/`Function`/`innerHTML`/service worker in the SPA | `crates/hypellm-devtools/src/web_scan.rs` over `web/` |
| Content-addressed manifest of release inputs | `crates/hypellm-devtools/src/sbom.rs` (`depscan --manifest`) |

The gate is `cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .`
and it is also a unit test (`rust_scan::tests::scanning_this_repository_is_clean`),
so drift fails the build rather than the release. `depscan` detects accident and
drift; it is not a defence against a hostile author with commit access. That is
what two-person review under specification 21.1 is for.

### 4.2 SSRF and DNS rebinding

Three layers, none of which is sufficient alone:

| Layer | Control | Where |
|---|---|---|
| Load time | Cleartext `http` rejected except to a loopback literal or `localhost`; an IP literal whose class the declared egress profile forbids is rejected; the cloud metadata address is rejected under **every** profile; a relative `unix` path is rejected | `crates/hypellm-config/src/build.rs`, `validate_endpoint` |
| Classification | IPv4-mapped, IPv4-compatible, and NAT64 IPv6 forms are decoded *before* classification, so `::ffff:169.254.169.254` classifies as `Metadata`; `EgressProfile::permits` refuses `Metadata`, `Multicast`, `Broadcast`, `Unspecified`, `Reserved`, `SharedAddressSpace` under every profile including `LOCAL` | `crates/hypellm-core/src/netaddr.rs` |
| Connect time | `Dialer::connect` accepts only a `PinnedDestination`; the only production producer is `Resolver::resolve`, which classifies each candidate and pins the first permitted address as a concrete `SocketAddr`, so a second DNS answer has nothing to attach to | `crates/hypellm-net/src/egress.rs` |

Supporting controls: redirects are never followed and proxy environment
variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) are never read —
there is no code in `crates/hypellm-net/` that reads them. Name resolution runs on
a bounded worker pool with a deadline (`crates/hypellm-net/src/dns.rs`,
`PooledResolver`) so a hostile resolver stalls a pool worker rather than a
request thread. The connection pool key includes the egress profile
(`crates/hypellm-net/src/pool.rs`, `pool_key`), so a socket opened under a
permissive profile cannot be reused under a stricter one.

Pinning is a capability, not a convention: `PinnedDestination`'s fields are
private and its constructors are module-private, so outside `egress` the only
way to obtain one is `Resolver::resolve`, which cannot return an address it has
not classified.

### 4.3 Request smuggling

| Control | Where |
|---|---|
| One strict parser for inbound framing; no second interpretation anywhere | `crates/wire-http1/src/request.rs` |
| `Transfer-Encoding` + `Content-Length` together is rejected; duplicate `Content-Length`, duplicate `Host`, duplicate `Transfer-Encoding`, `Transfer-Encoding : chunked` with whitespace before the colon, obs-fold continuation lines, and bare-LF line endings are all rejected | `parse_request_head` and its corpus tests in `crates/wire-http1/src/lib.rs` |
| Any `HttpError` is terminal for the connection: the listener writes a stable error and closes rather than resynchronising, so bytes after an ambiguous request are never attributed to a following one | `crates/hypellm-router/src/server.rs`, `serve_connection` |
| Streaming responses have no declared length and always close the connection | `crates/hypellm-router/src/routes.rs`, `InferenceHandler::stream` → `Disposition::Close` |
| Header values containing CR or LF are rejected before they can be written outbound | `wire_http1::Headers::append_unchecked` (`is_field_value`) |

### 4.4 Cross-tenant access

| Control | Where |
|---|---|
| Grants are default-deny; an alias with no matching grant is invisible, which is what makes "the models endpoint reveals only authorized aliases" hold without a second mechanism | `crates/hypellm-core/src/policy.rs`, `authorizes` / `visible_aliases` |
| Group membership is read from `group` records filtered by the principal's own tenant — never from a token claim, never inferred from an email domain (specification 25) | `crates/hypellm-router/src/routes.rs`, `groups_for` |
| Management list endpoints filter by `session.tenant`: keys, usage, audit, decisions | `crates/hypellm-admin-api/src/handlers.rs` (`list_keys`, `list_usage`, `list_audit` → `AuditIndex::recent_for_tenant`, `decision`) |
| A decision trace belonging to another tenant is reported as **absent**, not forbidden, so the response does not confirm the request exists | `crates/hypellm-admin-api/src/decisions.rs`, `DecisionCache::get` |
| Audit rows are filtered by the caller's tenant | `crates/hypellm-admin-api/src/audit_index.rs`, `recent_for_tenant` |
| Usage rows never cross a tenant boundary and an overflow row is never attributed to a principal | `crates/hypellm-admin-api/src/usage.rs` |
| Connection reuse is keyed by a credential isolation class derived from `(tenant, credential)` | `crates/hypellm-router/src/state.rs`, `credential_class`; `crates/hypellm-net/src/pool.rs` |

`credential_class` is length-prefixed — `{len}:{tenant}:{len}:{reference}` —
so no pair of tenant and credential identifiers can collide into one pool key.

### 4.5 Credential exfiltration

| Control | Where |
|---|---|
| Adapters are the only code that touches a provider credential, and they borrow it for the length of one header build through a non-`Clone` `CredentialHandle` | `crates/hypellm-adapters/src/contract.rs`; `crates/hypellm-router/src/state.rs`, `CredentialStore::with_secret` (scoped borrow, no owned getter) |
| No management endpoint can read a credential secret back — there is no handler and no permission for it. `list_credentials` renders metadata only | `crates/hypellm-admin-api/src/handlers.rs`, `list_credentials` |
| Secrets are never written to the append-only log; they go to `<secrets>/credentials/<id>` with mode 0600 | `crates/hypellm-router/src/state.rs`, `CredentialStore::store` → `restrict_permissions` |
| Startup secrets render redacted | `crates/hypellm-router/src/startup.rs`, hand-written `Debug for Secrets`; likewise `KeyStore`, `SessionStore`, `Store`, `Pseudonymizer` |
| The metric and log vocabularies are closed enums, so there is no dynamic key a credential could be attached to | `crates/hypellm-telemetry/src/metrics.rs` (`LabelName`), `crates/hypellm-telemetry/src/logs.rs` (`Field`) |
| Provider error messages are dropped entirely; only a sanitised `type`/`code` token survives | `crates/hypellm-adapters/src/contract.rs`, `safe_detail_for` / `sanitize_provider_code` |

Known weakness: `SensitiveHeaders`' `Debug` prints values added with `push` in
full, by design, so `x-request-id` and a client-supplied `idempotency-key`
appear verbatim. Credentials go through `push_secret`. Any new
credential-bearing header must too.

### 4.6 Prompt injection affecting the control plane

Prompts are inert by construction rather than by filtering. See abuse case A1.

### 4.7 Resource exhaustion

| Control | Where |
|---|---|
| Connection cap checked before per-connection state is allocated (4096 inference / 256 management); over the cap the peer gets 429 and the socket closes | `crates/hypellm-router/src/server.rs`, `ServerConfig::max_connections` |
| An absolute wall-clock budget on assembling one request's head and body, so a one-byte-per-timeout slow-loris cannot hold a worker indefinitely | `crates/hypellm-router/src/server.rs`, `ServerConfig::request_deadline` |
| Per-read, per-write, keep-alive, and requests-per-connection bounds | `ServerConfig` |
| Head/body/target/method/header-count bounds, with a hard ceiling the configuration cannot exceed | `crates/wire-http1/src/limits.rs`, `Limits::HARD_MAX_HEAD_BYTES` |
| JSON input, depth, string, array, and object bounds, duplicate keys rejected on every profile | `crates/wire-json/src/lib.rs`, `Limits` |
| SSE line-buffer and per-event bounds | `crates/wire-sse/src/lib.rs`, `SseLimits` |
| Hierarchical admission: global, tenant, principal, target — reserved before any outbound I/O and released exactly once | `crates/hypellm-core/src/admission.rs`; `crates/hypellm-router/src/pipeline.rs` |
| Metric cardinality cap, so a sprayed model name cannot exhaust memory | `crates/hypellm-telemetry/src/metrics.rs`, `MAX_SERIES_PER_METRIC` |
| Bounded DNS worker pool and bounded queue | `crates/hypellm-net/src/dns.rs` |

Known weakness: the metric-cardinality cap still folds when a metric's table is
full of *live* series — stale series are evicted, so a metric is no
longer blinded for the life of the process, but a genuinely high-cardinality one
stops attributing and reports that it has via
`hypellm_metric_series_overflowed_total`.

### 4.8 Policy tampering

| Control | Where |
|---|---|
| Drafts are immutable text, validated off the request path | `crates/hypellm-admin-api/src/drafts.rs`; `crates/hypellm-config/src/lib.rs`, `load` |
| An author cannot publish their own draft; the refusal is a property of the draft, not a check in the handler | `DraftStore::prepare_publish` |
| Publication writes a durable `ConfigActivation` frame **before** the pointer swap, so a crash leaves a record of an activation that did not take effect rather than a running configuration nobody is accountable for | `crates/hypellm-admin-api/src/handlers.rs`, `publish_draft` |
| Activation is an atomic pointer swap; in-flight requests keep their prior snapshot | `crates/hypellm-store/src/activation.rs`, `Activatable::activate` |
| Startup resumes the last durably activated configuration rather than silently reverting to the file | `crates/hypellm-router/src/startup.rs`, `resume_activation`; an unrecoverable activation refuses to start (`StartupError::ActivationUnrecoverable`) |
| Protected frames carry HMAC-SHA-256 over header, payload, sequence, kind, and protected flag; replay requires strictly increasing sequence numbers | `crates/hypellm-store/src/frame.rs`; `crates/hypellm-store/src/log.rs`, `Log::replay` |
| Snapshot metadata is MAC-verified on read and cross-checked against a digest of the snapshot payload | `crates/hypellm-store/src/lib.rs`, `read_snapshot` |
| `If-Match` on every mutating management endpoint, with ETags digested from the resource's canonical JSON | `crates/hypellm-admin-api/src/response.rs`, `etag_for` / `if_match_satisfied` |

Known weakness: the audit chain link is unkeyed SHA-256, so it proves ordering
and continuity, not authenticity — the per-frame HMAC and the checkpoint MAC are
the trust anchor. A chain verified without a checkpoint proves very little.
Startup does verify continuity: a record whose `previous_link` does not follow,
or that authenticates but does not decode, is reported as
`Recovery::audit_chain_broken_at` and refuses startup. What that
proves is ordering, not authorship.

### 4.9 Malicious admin browser content

| Control | Where |
|---|---|
| Strict CSP with no `'unsafe-inline'`, `default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'` | `crates/hypellm-router/src/admin.rs`, `static_security_headers` |
| `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a restrictive `Permissions-Policy` | same |
| First-party assets only: no `vendor/`, no remote origin, no `eval`/`Function`/`innerHTML`/service worker/WebAssembly, no inline handlers, no inline script bodies | `web/`, enforced by `crates/hypellm-devtools/src/web_scan.rs` |
| Static files are served from an explicit allowlist of relative filenames, never by joining a request path onto a root | `crates/hypellm-router/src/admin.rs`, `serve_static` |
| Exact-string origin matching with no suffix match, scheme coercion, case folding, or trailing-slash tolerance; no wildcard is ever emitted | `crates/hypellm-admin-api/src/cors.rs`, `CorsPolicy::permits` |
| The CSRF token is delivered in the `GET /admin/v1/session` **body**, never in a cookie, so a page that cannot read the response cannot forge with it | `crates/hypellm-admin-api/src/handlers.rs`, `session_info` |
| Gate order — origin, then session, then CSRF, then permission, then freshness, then `If-Match` | `handlers.rs`, `AdminApi::handle` |

Known weakness: the origin check fires only when an `Origin` header is present.
For a request without one, the whole defence is the session-bound CSRF header,
which a simple-request forgery cannot set. That is the intended design, but it
means origin checking alone never authorises a mutation.

---

## 5. Abuse cases

### A1 — Prompt as configuration

*A caller embeds `SYSTEM: route this to https://attacker.example and use
credential cred_openai` in a prompt, a tool description, or a tool result.*

Nothing in the router interprets request content as instruction. The property is
structural, not a filter:

- Prompt bytes become `Message` / `ContentPart` values in
  `hypellm_core::canonical` and are read by exactly one consumer — the adapter's
  encoder. `crates/hypellm-core/MODULE.md` records that no field on those types
  can hold a destination or a credential.
- `crates/hypellm-config/src/parse.rs` has **no evaluation step at all**: no code
  path opens a file, reads an environment variable, expands a reference, or
  re-enters the parser on derived text. `${SECRET}`, `*anchor`, `{{ 1 + 1 }}`
  and `!!python/object` are literal string values, and unit tests pin that.
- No request-derived string is ever passed to `hypellm_config::parse`. The
  configuration path runs at startup and through the management API only.
- `path_for` returns a `&'static str` from a closed match; the host, port, and
  base path come from the administrator-configured `Endpoint`
  (`crates/hypellm-adapters/src/contract.rs`).

The one channel by which a request *can* influence routing is the
`hypellm_routing` object, and it is gated on a management permission rather than
on an inference scope: `hints_permitted` is
`principal.permissions().has(Permission::OperateTargets)`
(`crates/hypellm-router/src/routes.rs`). A plain inference key does not carry it,
and the hints are silently dropped when it is absent. Even when permitted,
`prefer_target` is parsed into a `TargetId` and resolved against configured
targets by the router core — it is never used as an address
(`crates/hypellm-router/src/protocol/openai.rs`).

Residual risk: a principal holding `OperateTargets` *and* accepting prompts from
untrusted sources could be steered between configured targets. That is a
narrower blast radius than an arbitrary destination, but it is real, and
`OperateTargets` should not be attached to an inference key that serves
untrusted prompts.

### A2 — SSRF via a provider endpoint

*An operator is persuaded to add `provider id=x family=openai scheme=https
host=metadata.internal`, or a DNS name the attacker controls resolves to
169.254.169.254 on the second lookup.*

Three independent layers must all fail (section 4.2). Concretely:

1. A literal metadata address is refused at load time under every egress profile
   (`validate_endpoint`), so `--check` fails and the router does not start.
2. A DNS name cannot be classified statically, so it passes load-time syntax
   checks. At connect time `Resolver::resolve` classifies every returned address
   and refuses to pin one the profile forbids; `Metadata` is refused
   unconditionally, including through IPv4-mapped IPv6 spellings.
3. The pinned `SocketAddr` is what `Dialer::connect` dials. A rebinding answer
   arriving after resolution has nothing to attach to, because the connection
   was already made to a pinned address and the pool key is per-endpoint.

Cleartext `http` to a non-loopback host is refused at load time, so an attacker
cannot downgrade to avoid the TLS helper. If the helper socket is absent,
`Egress::acquire` errors — it never falls back to a cleartext socket carrying a
credential (`crates/hypellm-net/src/helper.rs`, `crates/hypellm-net/src/egress.rs`).

Residual risk: an operator with `PublishPolicy` can configure any *permitted-class*
destination. Egress restriction to approved endpoints at the OS level
(specification 20.1) is a deployment control that is not implemented in code —
see [current limitations](deferred-issues.md#host-hardening-is-external).

### A3 — Request smuggling through the inference listener

*An attacker sends `Content-Length: 4` and `Transfer-Encoding: chunked` on one
request hoping the router and an upstream edge proxy disagree about where the
next request starts, then appends `POST /admin/v1/keys`.*

The combination is rejected outright, as are duplicate `Content-Length`,
duplicate `Host`, `Transfer-Encoding` with whitespace before the colon, a
`Transfer-Encoding` other than `chunked`/`identity`, obs-fold continuations, and
bare-LF terminators — the corpus is in `crates/wire-http1/src/lib.rs` and
`request.rs`. On any framing error the listener writes one stable error and
**closes**, so buffered bytes are never re-attributed
(`crates/hypellm-router/src/server.rs`).

Structurally, even a successful desynchronisation on the inference listener does
not reach `/admin/v1`: the management API is mounted on a different listener
with its own handler, and `crates/hypellm-router/src/routes.rs` matches the raw
undecoded path against an exact set with no prefix matching and no normalisation
step. A smuggled `/admin/v1/keys` on the inference port is a 404.

The specification's own control also applies: the edge normalises before the
router sees the bytes (specification 10.1, "edge normalization"). That is a
deployment obligation, not a code control.

### A4 — Cross-tenant policy and audit leakage

*An operator holding `ReadAudit` and `ReadDecisionTraces` in tenant A enumerates
tenant B's targets, requests, and spend.*

- `list_audit` reads `AuditIndex::recent_for_tenant(session.tenant, …)`, not the
  global ring. Every management audit write goes through `record_audit`, which
  durably appends and indexes the same tenant-bearing event.
- `DecisionCache::get` requires a tenant match and reports a foreign trace as
  absent, so it is not an existence oracle.
- `UsageAggregate` never crosses a tenant boundary and refuses to attribute an
  overflow row to any principal.
- `TrafficWindow` keeps one ring per tenant and `GET /admin/v1/traffic` reads
  only the caller's. A request rate measures how much work a tenant is doing, so
  a router-wide one would be the same disclosure the overview's tenant count was
  already narrowed to prevent. A tenant past the ring cap is reported as
  `attributed: false` rather than as zero traffic.
- `list_keys` filters on `session.tenant`; `revoke_key` re-filters before acting.
- Alias visibility is default-deny through `PolicySnapshot::authorizes`.

OIDC identity is explicitly configured: an `identity` record binds each
`(issuer, subject)` pair to a principal and tenant, and an account with no
matching record cannot sign in. `list_targets`, `list_providers`, `list_aliases`,
`overview` and `traffic` derive visibility from the same tenant authorization
used by `GET /v1/models`. There is no platform-wide role that bypasses tenant scoping.

### A5 — Credential disclosure through logs

*An attacker who can read the router's stderr, its metrics exposition, a crash
report, or an error response reconstructs a provider key.*

The design forbids free text rather than scrubbing it:

- There is no free-text log field. `logs::Field` is a closed enum of 26 variants;
  `metrics::LabelName` is a closed enum of 12. `labels.with("user_id", …)` and
  `event.field("prompt", …)` are compile errors, not runtime rejections
  (`crates/hypellm-telemetry/src/`).
- Every string field is capped at 256 bytes on a UTF-8 boundary
  (`hypellm_core::sensitive::Capped`).
- Log lines are encoded by `wire_json::to_string`, which escapes C0 controls, so
  a value cannot forge a synthetic log record. Exposition label values are
  *narrowed* rather than escaped — anything outside `[A-Za-z0-9-._:/]` becomes
  `_` — because narrowing has no round-trip to get wrong.
- Key material renders redacted: `Secrets`, `KeyStore`, `SessionStore`,
  `SessionStore::digest_key`, `Store::mac_key`, and `Pseudonymizer` all carry
  hand-written `Debug` implementations rather than derives.
- Provider error bodies never reach a client or a log: only
  `ErrorClassification::safe_detail` (a fixed string) and a sanitised
  `provider_code` (≤ 64 bytes, `[A-Za-z0-9_.-]`) survive.
- An upstream `Authentication` failure maps to `InternalFault` for the client, so
  a router credential problem cannot be mistaken for the caller's key being wrong
  (`crates/hypellm-router/src/dispatch.rs`).
- Prompt and completion bodies are not logged. `capture_bodies` exists in the
  configuration grammar but **nothing reads it** — there is no capture
  implementation at all, which is fail-safe for this threat.

Residual risks worth naming: a stalled log reader no longer stalls the data path
(`QueueingSink` bounds the queue and drops oldest-first, reporting what it
dropped), but lines *are* lost under sustained back-pressure, so a log stream is
not a complete record — the audit chain is; and pseudonyms are a linkage
identifier with no epoch, so a pseudonymous log must be retained and
access-controlled as identity-bearing data.

---

## 6. Current assurance boundaries

The required fuzz areas are exercised by a seeded in-repository mutator. It is
reproducible and runs under `cargo test`, but it is not coverage-guided and does
not shrink failures. A green run is evidence for the properties asserted by its
seeds and mutations, not evidence that malformed input cannot exist.

Process sandboxing and privilege management are deployment controls; see
[current limitations](deferred-issues.md#host-hardening-is-external). Break-glass
access also requires operational preparation: retain the generated token
offline and keep its principal's `role_binding` active. Test that path before an
identity-provider outage.
