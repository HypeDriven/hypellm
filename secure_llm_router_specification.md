---
title: "HypeLLM Router: Secure, High-Performance LLM Routing Gateway"
subtitle: "Implementation-grade specification for a dependency-minimal Rust control and data plane"
date: "2026-08-12"
version: "1.0"
---

# HypeLLM Router

## Secure, High-Performance LLM Routing Gateway

*Implementation-grade specification for a dependency-minimal Rust control and data plane*

| **Document**     | **Value**                                                                                 |
|------------------|-------------------------------------------------------------------------------------------|
| Status           | Normative design specification                                                            |
| Audience         | Platform, security, infrastructure, and frontend engineering                              |
| Scope            | Local and remote LLM routing; per-user/model priorities; OpenAI-compatible harness access |
| Implementation   | Rust router; standalone static HTML/CSS/JavaScript admin application                      |
| Security posture | No third-party runtime/application dependencies; explicit trusted computing base          |
| Identity         | Local service credentials plus optional Google OIDC / OAuth 2.0 sign-in                   |

> **Design intent:** A hardened and lower-latency alternative to feature-heavy LLM proxy frameworks: fewer moving parts, deterministic behavior, bounded resource consumption, auditable adapters, and no package-manager supply chain in production.

# Document conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are normative. Examples are illustrative. “Dependency-free” means the router and web app use no third-party application packages at build or runtime. Operating-system facilities and a separately managed TLS termination boundary are external platform dependencies and must be declared in the deployment profile.

| **Term**     | **Meaning**                                                                                                |
|--------------|------------------------------------------------------------------------------------------------------------|
| Principal    | Human, service account, API key, or workload identity making a request.                                    |
| Provider     | Remote or local inference service such as OpenAI, Anthropic, DeepSeek, Kimi, or llama.cpp.                 |
| Model target | A provider/model/endpoint tuple with capabilities, limits, health, and cost metadata.                      |
| Alias        | Stable client-visible model name resolved by routing policy.                                               |
| Priority     | Ordered preference expressed per principal and alias/model, independent of provider ordering.              |
| Harness      | Coding client that speaks OpenAI-compatible HTTP, Anthropic-compatible HTTP, or a documented CLI protocol. |

# 1. Executive summary

HypeLLM Router is a single-purpose LLM gateway optimized for security, predictable routing, compatibility, and low overhead. It accepts common inference protocols, authenticates the caller, resolves the requested model alias under tenant and user policy, ranks eligible targets, reserves capacity, translates the request into a provider-native wire format, streams the response with backpressure, records bounded telemetry, and applies retry/failover rules without silently changing semantic requirements.

- Per-user, per-model priority matrices with inheritance, deny rules, hard pins, weighted ties, and explainable selection.

- Local and remote targets, including llama.cpp OpenAI-compatible servers, OpenAI/ChatGPT API models, Anthropic Claude, DeepSeek, and Moonshot/Kimi.

- OpenAI-compatible endpoints for popular coding harnesses; Anthropic compatibility where useful; streaming SSE, tool calls, structured outputs, embeddings, and model discovery.

- Application-layer dependency minimization: Rust standard library by default, in-repository reviewed modules, reproducible builds, and no Cargo registry resolution in release builds.

- A completely decoupled static admin/dashboard SPA served by any static host and communicating only through a versioned management API.

- Google OIDC sign-in for humans; scoped API keys or signed workload identity for services; break-glass local administration.

> **Non-goal:** The router is not an agent framework, prompt marketplace, vector database, secrets vault, billing system, or model host. It routes inference and exposes the minimum control plane required to do so safely.

# 2. Goals, non-goals, and success criteria

## 2.1 Goals

- Add less than 2 ms p50 and 10 ms p99 router processing latency on a warm path, excluding network and provider time.

- Sustain at least 20,000 concurrent streaming connections per appropriately sized node with bounded memory and no unbounded queues.

- Make every routing outcome reconstructable from versioned policy, health snapshots, and a redacted decision trace.

- Prevent one tenant, user, provider, or slow client from exhausting global capacity.

- Permit upgrades without client reconfiguration through stable aliases and protocol contracts.

- Keep the trusted computing base small enough for practical source review and fuzzing.

- Operate in standalone, active-passive, or horizontally scaled modes without changing client behavior.

## 2.2 Non-goals

- Browser automation against consumer chat websites. Remote providers are accessed only through supported APIs.

- Scraping ChatGPT, Claude, Kimi, or other consumer sessions or reusing browser cookies.

- Transparent semantic equivalence between models. A failover may occur only when policy explicitly permits the capability and semantic delta.

- General-purpose reverse proxying. Destinations must be configured, resolved, and allowed; callers cannot supply arbitrary upstream URLs.

- Dynamic third-party plugins, Lua, WASM, shared objects, downloaded adapters, or runtime code evaluation.

## 2.3 Release acceptance

| **Area**      | **Minimum acceptance**                                                                                        |
|---------------|---------------------------------------------------------------------------------------------------------------|
| Security      | Threat model reviewed; SSRF, request smuggling, auth bypass, credential leakage, and cross-tenant tests pass. |
| Correctness   | Golden protocol corpus, routing property tests, fault-injection tests, and deterministic replay pass.         |
| Performance   | Latency, throughput, streaming backpressure, overload, and 24-hour soak targets pass.                         |
| Compatibility | Supported harness matrix passes against at least one local and two remote providers.                          |
| Operations    | Backup/restore, secret rotation, rolling upgrade, provider outage, and break-glass drills pass.               |

# 3. Architecture

The implementation SHOULD ship as two artifacts: a Rust router binary and a directory of immutable static web assets. The router separates the hot data path from the management path in code, scheduling, rate limits, authentication scopes, and listener configuration. Deployments MAY split these into distinct processes later without changing APIs.

| **Component**       | **Responsibility**                                                                           | **Trust boundary**                                                                      |
|---------------------|----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| Edge/TLS boundary   | TLS 1.2/1.3, HTTP/2 or HTTP/3 normalization, request size/time limits, client IP provenance. | Platform-managed; never trusts inbound forwarding headers except from configured peers. |
| Inference listener  | Client protocol parsing, authentication, request normalization, routing, streaming.          | Internet or internal client boundary.                                                   |
| Router core         | Eligibility, scoring, reservations, retry/failover, cancellation, accounting.                | No direct secrets in policy objects.                                                    |
| Provider adapters   | Strict outbound serialization and response parsing for a fixed provider family.              | Only adapters can access scoped provider credentials.                                   |
| Management listener | Configuration CRUD, policy simulation, audit, health, session endpoints.                     | Admin network and stronger authorization.                                               |
| State store         | Versioned configuration, key metadata, audit chain, usage aggregates.                        | Local durable filesystem or replicated platform volume.                                 |
| Static SPA          | Admin/dashboard user experience. No embedded secrets or provider calls.                      | Untrusted browser; API enforces all authorization.                                      |

## 3.1 Request lifecycle

1.  Normalize transport: reject ambiguous framing, unsupported encodings, duplicate security headers, invalid UTF-8, excessive nesting, and bodies over endpoint limits.

2.  Authenticate principal and load an immutable authorization snapshot.

3.  Parse the client protocol into a canonical request without expanding user-controlled templates.

4.  Resolve requested alias and calculate eligible targets from capabilities, policy, health, residency, context window, budget, and concurrency.

5.  Rank targets deterministically, reserve rate/concurrency capacity atomically, and attach a decision identifier.

6.  Serialize through the selected adapter, send to a predeclared upstream, and stream with bounded buffers and cancellation propagation.

7.  Normalize usage, errors, finish reasons, tool calls, and stream events back to the client protocol.

8.  Commit metering and a redacted audit/decision record; release all reservations exactly once.

## 3.2 Concurrency model

Use a fixed set of event-loop workers. Each connection is represented by an explicit state machine. Blocking DNS, filesystem synchronization, configuration compaction, and audit export MUST run on bounded worker pools. No request may create an unbounded thread, task, buffer, channel, retry loop, or log entry. Cross-worker coordination uses sharded immutable snapshots and bounded message rings. Backpressure is end-to-end: when the client stops reading, upstream reads pause before buffers exceed configured watermarks.

| **Resource**               | **Required bound**                                                             |
|----------------------------|--------------------------------------------------------------------------------|
| Inbound header bytes       | Default 32 KiB; hard maximum 64 KiB.                                           |
| Inbound JSON body          | Default 16 MiB; endpoint-specific.                                             |
| JSON depth / string length | 64 levels / 8 MiB default.                                                     |
| Per-stream buffered data   | 256 KiB default total across inbound and outbound.                             |
| Queued requests            | Per target and principal; finite; queue timeout mandatory.                     |
| Retries                    | Maximum attempts and elapsed budget; disabled after unsafe partial output.     |
| Telemetry cardinality      | Allowlisted labels only; model/user dimensions aggregated or hashed by policy. |

# 4. Dependency and supply-chain policy

The production router MUST NOT download, resolve, or execute third-party packages. Cargo.lock alone is insufficient because it still admits external source into the trusted computing base. The release profile builds with --offline against the repository and fails if crates.io dependencies, build scripts, procedural macros, dynamic loading, or generated network fetches are present.

| **Profile**                  | **Permitted**                                                                                                                                                                                        |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Strict                       | Rust standard library; workspace crates stored in the repository; OS sockets/files; externally terminated TLS. This is the default.                                                                  |
| Audited crypto/TLS exception | A fixed, vendored, source-reviewed implementation may be admitted only by security decision record, checksum manifest, fuzz corpus, and reproducible-build evidence. It is not a dynamic dependency. |
| Forbidden                    | Registry dependencies, npm packages, CDNs, remote fonts, analytics snippets, plugins, runtime downloads, browser cookie automation, unsafe FFI without review.                                       |

> **TLS reality:** Do not implement TLS or modern cryptography ad hoc. In Strict profile, terminate TLS in an approved OS/platform boundary and connect to the router over a protected local socket or mutually authenticated private link. For outbound HTTPS, use a platform-provided audited TLS helper/sidecar with a narrow CONNECT-like API and destination allowlist, or approve a vendored audited TLS implementation under the exception profile.

## 4.1 In-repository module rules

- Each module has an owner, threat notes, public API, unsafe-code declaration, fuzz targets, and maximum input/resource limits.

- unsafe Rust is denied globally. Any exception is isolated, documented with invariants, reviewed by two security owners, and tested under sanitizers/Miri where applicable.

- No build.rs, proc macros, dlopen/LoadLibrary, shell execution, environment-variable interpolation in configuration, or implicit file discovery.

- Release inputs are content-addressed; builds produce an SBOM-like internal manifest even when no external packages exist.

- Compiler and linker versions are pinned; artifacts are reproducible and signed outside the router repository.

# 5. Canonical domain model

| **Entity**       | **Key fields**                                                                                                 |
|------------------|----------------------------------------------------------------------------------------------------------------|
| Tenant           | id, status, default policy, quotas, data region, retention profile.                                            |
| Principal        | id, tenant_id, kind, status, role bindings, attributes, auth methods.                                          |
| Provider         | id, family, endpoint set, credential_ref, egress policy, enabled.                                              |
| Target           | id, provider_id, native_model, aliases, capabilities, context/output limits, cost class, health policy.        |
| Route policy     | id, version, match predicates, constraints, score terms, failover rules.                                       |
| Priority binding | principal/group/tenant selector, requested alias/model selector, ordered target preferences, weight, pin/deny. |
| Credential       | opaque reference, scope, rotation metadata; secret value never returned through management API.                |
| Decision         | request_id, policy version, candidates, exclusions, scores, chosen target, retry chain, timings.               |

## 5.1 Canonical request

| **Field**       | **Type / rule**                                                                                  |
|-----------------|--------------------------------------------------------------------------------------------------|
| request_id      | 128-bit random or validated client id; never used as authorization.                              |
| principal       | Resolved server-side; client cannot override.                                                    |
| operation       | chat, responses, embeddings, tokenize, rerank (optional).                                        |
| requested_model | Client-visible alias or explicitly permitted target id.                                          |
| messages/input  | Ordered canonical content parts: text, image reference/data, audio where supported.              |
| tools           | Name, description, strict JSON schema subset; provider conversion may reject unsupported schema. |
| sampling        | temperature, top_p, seed, penalties with explicit “unset” distinct from zero.                    |
| limits          | max_output_tokens, deadline, maximum cost class, residency.                                      |
| routing hints   | Optional allowlisted hints; ignored or rejected unless principal has permission.                 |
| stream          | Boolean plus normalized stream-options.                                                          |

# 6. Routing policy and per-user/model priority

Routing is a pure function over an immutable policy snapshot plus bounded live state. It MUST be deterministic for equal inputs except for an explicitly configured weighted tie-breaker seeded by request_id. Administrative ordering is never inferred from map iteration order.

## 6.1 Inheritance and precedence

| **Order** | **Binding scope**                                | **Effect**                                                           |
|-----------|--------------------------------------------------|----------------------------------------------------------------------|
| 1         | Explicit principal + exact requested model/alias | Highest precedence.                                                  |
| 2         | Explicit principal + model class/wildcard        | User defaults.                                                       |
| 3         | Group + exact model/alias                        | Best matching group; conflicts resolved by binding priority then id. |
| 4         | Tenant + exact model/alias                       | Tenant model policy.                                                 |
| 5         | Tenant default                                   | General tenant routing.                                              |
| 6         | Global default                                   | Only when tenant permits inheritance.                                |

A deny is sticky downward: a lower-precedence binding cannot re-enable a target denied by a higher-precedence security or compliance rule. An explicit hard pin selects only the pinned target and fails closed if unavailable unless the same binding defines an allowed emergency fallback. Preferences merge by target id; the highest-precedence value wins for each property.

## 6.2 Eligibility filters

- Principal is authorized for requested alias and operation.

- Target is enabled, healthy enough for the requested failure policy, and within a configured circuit state.

- Target supports every required modality, tool/response feature, context size, output size, streaming behavior, and data residency constraint.

- Provider endpoint is on the static destination allowlist and credential scope matches tenant and target.

- Request fits per-principal, tenant, target, and global token/request/concurrency budgets.

- Estimated cost class and actual policy ceiling permit selection.

- Target is not denied by policy, quarantine, incident override, or maintenance window.

## 6.3 Score and selection

After filtering, compute an integer fixed-point score to avoid floating-point drift:

> **Normative score:** `score = priority_rank_term + policy_weight + health_term + latency_term + queue_term + cost_term + locality_term + affinity_term + deterministic_jitter`. Each term has a documented range; saturation arithmetic prevents overflow. Security constraints never appear as score penalties—they are eligibility filters.

| **Term**             | **Default interpretation**                                                                       |
|----------------------|--------------------------------------------------------------------------------------------------|
| priority_rank_term   | User/model ordered preference; rank 0 dominates all ordinary optimization terms.                 |
| health_term          | Penalize elevated error rate, recent timeouts, half-open circuits.                               |
| latency_term         | EWMA and percentile bucket relative to operation/model class.                                    |
| queue_term           | Current reserved concurrency and predicted wait.                                                 |
| cost_term            | Configured relative cost; never derived from untrusted provider response.                        |
| locality_term        | Prefer local inference when policy, capacity, and capability allow.                              |
| affinity_term        | Short-lived cache/model warmness or conversation affinity; never overrides residency.            |
| deterministic_jitter | Optional small request-id-derived value for weighted distribution without global RNG contention. |

## 6.4 Example priority policy

Conceptual configuration (the implementation uses the native config grammar and management API; JSON shown for readability):

| **Selector**      | **Requested model** | **Preference**                                                                   |
|-------------------|---------------------|----------------------------------------------------------------------------------|
| user:operator       | code-premium        | 1 local:qwen-coder; 2 anthropic:claude-code; 3 openai:gpt-code; deny deepseek:\* |
| group:engineering | code-fast           | 1 local:\*; 2 deepseek:coder; 3 kimi:code                                        |
| tenant:default    | \*                  | 1 local healthy targets; 2 remote targets by cost/latency                        |

## 6.5 Failover semantics

- Before upstream acceptance: retry another eligible target within the total deadline and attempt budget.

- After upstream accepts but before response bytes: fail over only when request is idempotent or carries a provider-supported idempotency key.

- After any semantic output byte or tool delta reaches the client: never splice a second model response into the stream. End with a normalized error.

- Context overflow, unsupported feature, policy denial, invalid request, and authentication errors are not retriable.

- 429, connection refusal, timeout, selected 5xx, or circuit-open may fail over according to policy. Retry-After is capped by the remaining deadline.

- A model-family change must be explicitly allowed in the alias failover policy and visible in response metadata when the protocol permits.

# 7. Provider adapters

Adapters are compile-time modules selected by provider.family. They contain only typed conversion, strict parsing, endpoint paths, authentication header construction, stream decoding, and error mapping. They cannot make routing decisions, read arbitrary files, resolve arbitrary hosts, or expose credentials in errors.

| **Family**                | **Required interface**                                                                                                                                                    |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| llama.cpp                 | OpenAI-compatible /v1/chat/completions, /v1/embeddings, /v1/models; configurable native tokenize endpoint; local Unix/TCP transport.                                      |
| OpenAI / ChatGPT API      | Responses API first; Chat Completions compatibility; embeddings; tools; structured output; SSE. Uses supported developer API credentials, never consumer session cookies. |
| Anthropic Claude          | /v1/messages, system/message conversion, content block streaming, tool use/result mapping, prompt caching headers only when explicitly allowed.                           |
| DeepSeek                  | OpenAI-compatible chat endpoint with provider-specific model/capability configuration; strict base URL allowlist.                                                         |
| Moonshot/Kimi             | Supported OpenAI-compatible API surface with explicit context/tool capability map; no assumptions from model name.                                                        |
| Generic OpenAI-compatible | Opt-in only; administrator supplies fixed endpoint and complete capability declaration. Disabled by default.                                                              |

## 7.1 Adapter contract

- fn validate(canonical_request, target_caps) -\> ValidationResult

- fn encode_headers(credential_handle, request_meta) -\> SensitiveHeaders

- fn encode_request(canonical_request) -\> BoundedBytes/stream

- fn decode_response(status, headers, body_stream) -\> CanonicalEvent stream

- fn classify_error(...) -\> ErrorClass with retryability and safe client detail

- fn usage_from_events(...) -\> CanonicalUsage with provider-reported and router-estimated flags

SensitiveHeaders is a non-cloneable redacting type. Debug formatting prints only header names. Credential bytes are zeroed on release where the platform permits, never included in crash dumps, and never stored in configuration snapshots.

# 8. Client protocol and coding-harness compatibility

The primary compatibility contract is OpenAI-style HTTP because most coding harnesses can be pointed at a custom base URL. Compatibility is behavioral, not merely path-level: streaming frames, error objects, tool calls, usage reporting, cancellation, and model discovery must match documented profiles.

| **Endpoint**                    | **Requirement**                                                               |
|---------------------------------|-------------------------------------------------------------------------------|
| POST /v1/chat/completions       | MUST; streaming and non-streaming; tools; response_format subset.             |
| POST /v1/responses              | MUST for new integrations; input items, tools, streaming event normalization. |
| POST /v1/embeddings             | SHOULD; only eligible embedding targets.                                      |
| GET /v1/models                  | MUST; returns only aliases/models authorized for the principal.               |
| POST /v1/messages               | SHOULD; Anthropic-compatible client profile.                                  |
| GET /health/live, /health/ready | MUST; no sensitive provider details.                                          |
| POST /v1/tokenize               | MAY; normalized extension advertised via capabilities.                        |

## 8.1 Harness profiles

| **Harness class**                  | **Configuration pattern**                                                         | **Notes**                                                                                    |
|------------------------------------|-----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| OpenAI-compatible CLI/IDE          | Base URL = https://router.example/v1; API key = scoped router key; model = alias. | Works for tools that allow a custom OpenAI base URL.                                         |
| Anthropic-compatible coding client | Base URL = router Anthropic listener/path; router API key; model alias.           | Implement exact Messages streaming/error profile.                                            |
| Environment-driven harness         | OPENAI_BASE_URL / OPENAI_API_KEY or equivalent.                                   | Document per-tool variables; never require wrapper scripts when native configuration exists. |
| Local development                  | `http://127.0.0.1:<port>/v1` over loopback, or HTTPS edge.                         | Loopback listener defaults to local-only; remote cleartext forbidden.                        |
| Custom integration                 | Versioned canonical extension endpoints.                                          | Use advertised capabilities and request id.                                                  |

The compatibility test suite MUST include representative popular coding harnesses selected at release time. Because harness behavior changes, the project maintains versioned profiles rather than claiming universal compatibility. Each profile records required endpoints, headers, SSE details, tool-call behavior, max body, cancellation method, and known limitations.

## 8.2 Error contract

| **HTTP** | **Router code**                   | **Meaning**                                        |
|----------|-----------------------------------|----------------------------------------------------|
| 400      | invalid_request                   | Malformed or unsupported request; no retry.        |
| 401      | unauthenticated                   | Missing/invalid client authentication.             |
| 403      | forbidden                         | Authenticated but model/operation/policy denied.   |
| 404      | model_not_found                   | Alias absent or hidden for caller.                 |
| 409      | idempotency_conflict              | Same key with different normalized request digest. |
| 429      | rate_limited / capacity_exhausted | Principal quota or finite queue/capacity reached.  |
| 502      | upstream_invalid_response         | Provider violated adapter contract.                |
| 503      | no_eligible_target                | No target meets policy/health/capability.          |
| 504      | deadline_exceeded                 | End-to-end deadline expired.                       |

# 9. Authentication and authorization

## 9.1 Human sign-in with Google OIDC

Google sign-in is optional and applies to the management UI/API, not provider authentication. Use OpenID Connect Authorization Code flow with PKCE S256. The router or dedicated auth endpoint owns the callback. The static SPA creates no client secret and never stores provider tokens.

- Generate state, nonce, and PKCE verifier with a cryptographically secure OS random source; bind them to a short-lived, SameSite=Lax, HttpOnly transaction cookie.

- Use exact preconfigured issuer, authorization endpoint, token endpoint, client_id, redirect URI, and allowed hosted domains. No discovery URL or redirect is supplied by the browser.

- Exchange code server-side through the approved HTTPS boundary. Validate signature using pinned issuer keys cached with bounded lifetime; validate iss, aud, azp when required, exp, iat skew, nonce, and email_verified.

- Map immutable subject (iss, sub) to a local principal. Email is an attribute, not the stable identity key. Optional hd/domain rules are authorization inputs but not proof of group membership.

- Issue a router session identifier in a Secure, HttpOnly, SameSite=Lax cookie. Store only a digest server-side. Rotate on authentication and privilege change; short idle and absolute lifetimes.

- Protect all state-changing management requests with same-origin enforcement and a session-bound CSRF token; set a strict CORS allowlist.

- Logout invalidates the server session. Google logout is not assumed. Reauthentication is required for credential changes, role grants, break-glass actions, and policy publication.

> **OIDC dependency boundary:** JWT signature verification and HTTPS are cryptographic security functions. Strict profile delegates them to an approved local identity/TLS verifier service over a narrow authenticated local interface. The audited exception profile may embed a fixed reviewed implementation. Never write novel signature or TLS code merely to satisfy “no dependencies.”

## 9.2 Service authentication

| **Method**                | **Use**                       | **Rules**                                                                                                                                |
|---------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Router API key            | Coding harnesses and services | 256-bit random secret; display once; store keyed digest; prefix identifies key record; scopes, tenant, expiry, IP/workload restrictions. |
| mTLS identity             | Internal workloads            | Identity from verified certificate/SPIFFE-like URI supplied only by trusted edge.                                                        |
| Signed workload assertion | Platform integrations         | Fixed issuer/audience/algorithm; short lifetime; replay cache.                                                                           |
| Local peer credentials    | Same-host tools               | Unix socket peer UID/GID mapped to principal.                                                                                            |

## 9.3 RBAC and policy authorization

| **Role**           | **Representative permissions**                                                       |
|--------------------|--------------------------------------------------------------------------------------|
| Viewer             | Read sanitized health, configuration summaries, and own usage.                       |
| Operator           | Drain targets, open/close maintenance, view redacted decision traces.                |
| Policy editor      | Draft policies and simulate; cannot publish own draft by default.                    |
| Policy approver    | Review and publish signed/versioned configuration.                                   |
| Credential manager | Create/rotate/revoke provider credential references; cannot read secret back.        |
| Auditor            | Read immutable audit/export views.                                                   |
| Break-glass admin  | Time-limited full access with reauthentication, reason, alert, and mandatory review. |

# 10. Secrets, egress, and data protection

- Provider credentials are scoped to the narrowest provider/tenant/target set and retrieved by opaque handle only inside the adapter boundary.

- At rest, secrets use an OS/platform secret facility or an approved external vault accessed through a narrow local agent. If neither exists, encrypted files require an operator-supplied startup key not stored beside ciphertext.

- Upstream destinations are administrator-defined scheme/host/port tuples. Resolve DNS through a controlled resolver, reject private/link-local/metadata ranges unless the target is explicitly local, pin the validated address for the connection, and revalidate on refresh.

- Redirects are disabled. Proxy environment variables are ignored. User input never selects base URL, Host, SNI, CONNECT target, file path, or Unix socket.

- Prompt and completion bodies are not logged by default. Optional capture is per-tenant, sampled, encrypted, access-controlled, time-limited, and visibly indicated.

- Crash reports, traces, errors, and decision records use redaction types and capped strings. Authorization headers, cookies, API keys, code, prompts, tool arguments, and provider bodies are sensitive by default.

## 10.1 Threat model summary

| **Threat**                               | **Required control**                                                                                  |
|------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Dependency/supply-chain injection        | No registry/CDN dependencies; offline/reproducible build; signed source/artifact manifest.            |
| SSRF / DNS rebinding                     | Static destinations, IP class validation, resolver pinning, redirects off, metadata blocks.           |
| Request smuggling                        | Single strict parser; edge normalization; reject TE/CL ambiguity and invalid duplicate headers.       |
| Cross-tenant access                      | Principal-bound snapshots, tenant keys in every state key, authorization before existence disclosure. |
| Credential exfiltration                  | Opaque handles, redacting types, adapter-only access, egress allowlist, no debug body logs.           |
| Prompt injection affecting control plane | Prompts are inert data; never interpreted as config, destination, credential, or admin instruction.   |
| Resource exhaustion                      | Finite buffers/queues, hierarchical quotas, streaming backpressure, deadlines, parser limits.         |
| Policy tampering                         | Versioned drafts, approval separation, signed audit chain, atomic activation/rollback.                |
| Malicious admin browser content          | No inline script, strict CSP, no third-party origins, output encoding, CSRF and origin checks.        |

# 11. Configuration and durable state

Configuration is a versioned immutable document activated atomically. The runtime parses into a validated typed snapshot, resolves all references, verifies invariants, computes a digest, and swaps a single shared pointer. Requests already in flight retain the prior snapshot. Partial mutation is never visible.

## 11.1 Native configuration grammar

To avoid a parser dependency, use a deliberately small line-oriented UTF-8 grammar rather than full YAML/TOML. Each record is “type key=value …”; strings use JSON-style quoted escapes from the in-repository parser; comments begin with \# outside strings. Unknown fields are errors. Includes, environment expansion, anchors, expressions, and executable templates are forbidden. The management API emits canonical ordering.

| **Record**   | **Example purpose**                                                   |
|--------------|-----------------------------------------------------------------------|
| provider     | Family, endpoint id, credential reference, egress profile.            |
| target       | Provider, native model, capabilities, limits, health and cost class.  |
| alias        | Client-visible name and permitted target set.                         |
| binding      | Principal/group/tenant selector and per-model priorities/denies/pins. |
| quota        | Hierarchical rate, token, concurrency, and budget limits.             |
| role_binding | Principal/group to management permissions.                            |

## 11.2 Storage engine

The default embedded store is an append-only framed log plus periodic snapshot, implemented in-repository. Each frame contains magic, format version, monotonic sequence, record type, payload length, payload, and checksum/MAC as appropriate. Writes use temporary file, fsync, atomic rename, and directory fsync. Startup replays only complete valid frames and fails closed on protected-record integrity errors. Compaction runs off the request path and retains the prior snapshot until the replacement is durable.

- Single-node mode uses an exclusive process lock and supports point-in-time backup by copying a validated snapshot plus log boundary.

- Multi-node mode SHOULD use an external consensus/config distributor rather than inventing distributed consensus in v1. Nodes consume signed versioned bundles and report active digest.

- Usage counters may be eventually aggregated, but admission-critical quotas require an authoritative allocator or conservative node partitions.

- Audit records form a hash/MAC chain with periodic signed checkpoints exported to immutable storage.

# 12. Rate limits, quotas, and admission control

| **Layer**       | **Controls**                                                               |
|-----------------|----------------------------------------------------------------------------|
| Global          | Connections, requests/s, input bytes/s, output bytes/s, total concurrency. |
| Tenant          | Requests, tokens, concurrent streams, daily/monthly budget class.          |
| Principal/key   | Requests, token buckets, maximum queued requests, model permissions.       |
| Alias/model     | Operation-specific request/token and context limits.                       |
| Provider/target | Concurrency, connection pool, queue, breaker, adaptive load shed.          |

Admission uses hierarchical token buckets and concurrency semaphores with atomic reservation. Estimated input tokens use the selected target tokenizer when available; otherwise a conservative byte-based upper bound. On completion, reconcile against provider usage without granting negative-cost abuse. Queue order is weighted fair by tenant and priority class; FIFO is maintained within an equal class. Requests past deadline are removed without invoking the provider.

# 13. Health, circuit breaking, and load balancing

- Passive health records connect/handshake errors, first-byte latency, stream completion, protocol errors, and normalized status classes.

- Active probes use provider-safe low-cost endpoints and separate probe budgets. A successful TCP connect alone is not model readiness.

- Circuit states are closed, open, and half-open. Transitions use minimum sample counts, rolling windows, cooldown with bounded exponential increase, and limited half-open probes.

- Health is per endpoint and operation/model class; a failed embedding path does not necessarily disable chat.

- EWMA and fixed-bucket histograms avoid unbounded samples. Live metrics are advisory; policy remains the authority.

- Manual quarantine overrides automated recovery and requires reason, actor, expiry/review time, and audit record.

# 14. Streaming and protocol normalization

The router parses upstream streaming incrementally and emits complete client-protocol events. It MUST NOT buffer an entire completion. SSE parsing handles CRLF/LF, multiple data lines, comments, bounded event size, and terminal markers. JSON fragments are assembled only within declared provider event boundaries; incomplete or excessive events fail safely.

| **Concern**    | **Rule**                                                                                                                 |
|----------------|--------------------------------------------------------------------------------------------------------------------------|
| Backpressure   | High/low watermarks pause upstream reads; slow-client timeout cancels upstream.                                          |
| Cancellation   | Client disconnect or explicit cancel propagates immediately; adapter drains/closes connection according to reuse safety. |
| Partial errors | Emit protocol-supported error event if possible, then close. Never append failover output.                               |
| Tool calls     | Preserve call identity and ordered argument deltas; validate size and syntax but do not execute.                         |
| Usage          | Mark provider-reported vs estimated; stream usage only when protocol profile permits.                                    |
| Keepalive      | Optional comment/ping within protocol contract; never synthetic content tokens.                                          |

# 15. Static admin and dashboard web application

The web app is a separately built and deployed directory containing only first-party static HTML, CSS, JavaScript, SVG, and optional WOFF2 assets. It can be served from a different origin. It has no build-time or runtime package dependencies, CDN assets, remote fonts, telemetry SDKs, service-worker code execution, eval, WebAssembly, or direct provider access.

## 15.1 Browser architecture

| **Module**       | **Responsibility**                                                                        |
|------------------|-------------------------------------------------------------------------------------------|
| index.html       | Semantic shell, CSP-compatible external first-party files, no inline event handlers.      |
| app.js           | Router, session state, API client, abort/cancellation, error boundary.                    |
| views/\*.js      | Dashboard, targets, policies, users, keys, audit, settings; native ES modules.            |
| components/\*.js | Small DOM-construction functions or native custom elements; no HTML string injection.     |
| styles/\*.css    | Design tokens, responsive layout, print styles, reduced-motion and high-contrast support. |
| vendor/          | MUST NOT exist.                                                                           |

## 15.2 Security headers

Recommended: Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src https://router.example; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'. Also use Referrer-Policy: no-referrer, X-Content-Type-Options: nosniff, Permissions-Policy disabling unused features, and HSTS on HTTPS origins.

## 15.3 Required screens

| **Screen**        | **Capabilities**                                                                               |
|-------------------|------------------------------------------------------------------------------------------------|
| Overview          | Request rate, latency, errors, active streams, capacity, target status, configuration version. |
| Targets           | Add/edit fixed endpoints, capability declaration, maintenance/drain/quarantine, safe test.     |
| Routing policies  | Priority matrix by user/group/model, draft diff, validation, simulation, approval, rollback.   |
| Users & access    | Google-linked identities, service principals, roles, status, sessions.                         |
| API keys          | Create once, scope, expiry, last-used metadata, revoke; secret never displayed again.          |
| Credentials       | Create/rotate opaque provider credentials; values write-only.                                  |
| Usage             | Per authorized scope, model/alias, operation, status, cost class; no prompt bodies by default. |
| Decision explorer | Redacted candidate/exclusion/score/failover trace by request id.                               |
| Audit             | Actor/action/object/result, filters, export, integrity checkpoint status.                      |
| Settings          | OIDC, retention, CORS/origins, break-glass, safe deployment parameters.                        |

## 15.4 API behavior

- All management resources live under /admin/v1 and use explicit JSON schemas, ETags, If-Match on mutation, pagination cursors, stable error codes, and request IDs.

- The SPA performs optimistic UI only for reversible view state, never for security-sensitive mutations.

- Draft policy simulation accepts a sanitized request descriptor and principal selector, returning exclusions and scores without provider invocation.

- Publishing requires validation and, where configured, a distinct approver. Activation is atomic and returns the active digest.

- Cross-origin deployment uses an exact origin allowlist, credentials mode, preflight validation, and no wildcard with cookies.

# 16. Management API summary

| **Method/path**                        | **Purpose**                                                             |
|----------------------------------------|-------------------------------------------------------------------------|
| GET /admin/v1/session                  | Current principal, permissions, CSRF metadata, config digest.           |
| POST /admin/v1/auth/google/start       | Create OIDC transaction and return/redirect to fixed authorization URL. |
| GET /admin/v1/auth/google/callback     | Validate callback and establish session.                                |
| POST /admin/v1/logout                  | Invalidate session.                                                     |
| GET/POST /admin/v1/targets             | List/create targets; secrets referenced, never returned.                |
| PATCH /admin/v1/targets/{id}           | ETag-guarded update, drain, maintenance, quarantine.                    |
| GET/POST /admin/v1/policies            | List/create immutable draft.                                            |
| POST /admin/v1/policies/{id}:validate  | Structural and semantic validation.                                     |
| POST /admin/v1/policies/{id}:simulate  | Explain selection for supplied scenario.                                |
| POST /admin/v1/policies/{id}:publish   | Approval and atomic activation.                                         |
| POST /admin/v1/keys                    | Create scoped router key; one-time secret response.                     |
| DELETE /admin/v1/keys/{id}             | Revoke immediately.                                                     |
| POST /admin/v1/credentials             | Write-only secret creation.                                             |
| POST /admin/v1/credentials/{id}:rotate | Two-phase rotation with overlap window.                                 |
| GET /admin/v1/decisions/{request_id}   | Authorized redacted routing trace.                                      |
| GET /admin/v1/audit                    | Cursor-paginated authorized audit records.                              |

# 17. Observability and audit

Metrics are local first: a dependency-free text exposition endpoint and structured newline-delimited logs. A platform collector may scrape/forward them. The router does not embed third-party agents or exporters.

| **Signal**      | **Examples**                                                                                                                    |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------|
| Metrics         | Requests, active streams, tokens, bytes, queue depth/wait, target latency/error, breaker state, auth failures, config version.  |
| Structured logs | Timestamp, severity, event code, request id, tenant pseudonym, alias, chosen target id, status, timings; capped and redacted.   |
| Decision trace  | Policy digest, candidates, exclusion reason codes, integer score terms, reservations, attempts.                                 |
| Audit           | Login, role/key/credential/config changes, policy approval, break-glass, export, quarantine, rollback.                          |
| Health          | Liveness is process/event-loop; readiness requires loaded valid config and required local services, not every provider healthy. |

High-cardinality labels such as raw user id, request id, prompt, URL, and error text are forbidden in metrics. Logs apply deterministic pseudonyms when identity correlation is needed. Time synchronization status is monitored; monotonic clocks govern durations and deadlines.

# 18. Rust implementation specification

## 18.1 Workspace layout

| **Crate/module** | **Purpose**                                                                                                    |
|------------------|----------------------------------------------------------------------------------------------------------------|
| hypellm-router     | Binary, startup validation, listener orchestration, privilege drop, shutdown.                                  |
| core             | Canonical types, routing, quotas, retries, decision traces; pure and heavily property-tested.                  |
| wire-http1       | Strict bounded HTTP/1.1 server/client state machines where platform edge does not supply normalized transport. |
| wire-json        | Small strict JSON tokenizer/parser/serializer with depth and size limits.                                      |
| wire-sse         | Incremental SSE parser/encoder.                                                                                |
| adapter-\*       | Compile-time provider-family modules.                                                                          |
| auth             | API keys, sessions, OIDC verifier boundary client, RBAC.                                                       |
| store            | Framed log, snapshots, atomic configuration activation, audit chain.                                           |
| admin-api        | Versioned management handlers and schemas.                                                                     |
| telemetry        | Bounded structured logs, counters, histograms, text exposition.                                                |
| test-corpus      | Golden requests/responses, malformed input, provider stream fixtures.                                          |

## 18.2 Coding rules

- \#\![forbid(unsafe_code)\] at workspace root, except separately approved low-level crate.

- No panics on data-plane input. unwrap/expect forbidden outside startup invariants and tests.

- All integer conversions are checked; sizes use explicit maxima before allocation.

- `Sensitive<T>` implements redacted `Debug`/`Display` and is not `Clone` unless justified.

- Every I/O operation has a deadline and cancellation path. Drop alone is not relied upon for accounting correctness.

- State machines use exhaustive enums; invalid transitions return internal fault and close safely.

- Public errors are stable codes with safe detail; internal causes are chained only in redacted logs.

- Configuration and protocol parsers are fuzzed; router selection has property tests for determinism, precedence, deny/pin behavior, and overflow.

## 18.3 Internal interfaces

| **Interface**                           | **Normative behavior**                                                                           |
|-----------------------------------------|--------------------------------------------------------------------------------------------------|
| PolicySnapshot::route(ctx, req, live)   | Returns ranked eligible candidates plus exclusion reasons; no I/O.                               |
| Admission::reserve(candidate, estimate) | Atomic hierarchical reservation or typed rejection; RAII guard releases exactly once.            |
| Adapter::start(req, target, credential) | Starts bounded upstream exchange; credential inaccessible after header construction.             |
| EventPump::run(client, upstream)        | Bidirectional cancellation/backpressure; canonical event conversion.                             |
| Store::activate(validated)              | Durable commit then atomic snapshot swap; returns digest/version.                                |
| Audit::append(event)                    | Bounded fields; integrity chained; failure policy configurable but security changes fail closed. |

# 19. Performance requirements

| **Metric**                   | **Target / method**                                                                                                                                |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Warm router overhead         | p50 \< 2 ms, p99 \< 10 ms at 70% rated load, excluding edge/provider network.                                                                      |
| Time to first forwarded byte | No full-body buffering for accepted streaming protocols; bounded canonical parsing only.                                                           |
| Memory                       | Base \< 100 MiB target; per idle connection \< 8 KiB target; per active stream bounded by configured watermarks.                                   |
| Connection reuse             | Pools keyed by exact endpoint, TLS identity/profile, credential isolation class, and protocol. No cross-tenant reuse where auth binding is unsafe. |
| Configuration reload         | Validate off-path; pointer swap \< 1 ms target; no global request stop.                                                                            |
| Overload                     | Latency remains bounded through early admission rejection; no swap thrash or queue explosion.                                                      |

## 19.1 Benchmark suite

- Synthetic local upstream with controllable first-token delay, token cadence, errors, malformed frames, stalls, and disconnects.

- Open-loop and closed-loop tests across non-streaming, streaming, large prompts, tools, embeddings, slow clients, and cancellations.

- Compare direct-to-provider versus routed latency and CPU/memory; report distributions, not averages.

- Soak with config reloads, credential rotations, DNS changes, circuit transitions, log rotation, and audit checkpointing.

- Adversarial parser corpus, header fragmentation, slowloris, oversized SSE, deep JSON, many tool calls, and retry storms.

# 20. Deployment profiles

| **Profile**             | **Description**                                                                                                                                   |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Developer local         | Router binds loopback; llama.cpp over loopback/Unix socket; optional remote provider via approved TLS helper; file state with strict permissions. |
| Single secure node      | TLS edge on same host, Unix socket to router, admin listener on separate socket/network, platform secrets, system service sandbox.                |
| HA stateless data plane | Multiple routers behind edge; signed config distributor; shared/partitioned quota authority; central immutable audit sink.                        |
| Air-gapped/local-only   | No outbound egress; local targets only; local peer/API-key auth; static UI; offline update bundles.                                               |

## 20.1 Process hardening

- Dedicated unprivileged user; read-only executable/config; writable directories separated for state, audit spool, and temporary files.

- No shell, compiler, package manager, or writable executable directory in production image.

- System-call/filesystem/network sandbox appropriate to OS; outbound connections restricted to resolved approved endpoints or local helper.

- Core dumps disabled or encrypted/restricted; memory locking considered for secret pages; environment scrubbed after startup.

- Graceful shutdown stops admission, drains within deadline, cancels remainder, flushes audit/state, and exits nonzero on integrity failure.

# 21. Testing and verification

| **Layer**     | **Required tests**                                                                                                |
|---------------|-------------------------------------------------------------------------------------------------------------------|
| Unit          | Parsers, serialization, precedence, scoring, quotas, error mapping, redaction, storage frames.                    |
| Property      | Routing determinism, deny monotonicity, pin semantics, bounded allocation, round trips, reservation conservation. |
| Fuzz          | HTTP, JSON, SSE, configuration, provider events, management API, state recovery.                                  |
| Integration   | Each provider adapter against recorded golden server and opt-in live sandbox.                                     |
| Compatibility | Versioned coding-harness profiles and streaming/tool/error behavior.                                              |
| Security      | SSRF, smuggling, auth/session/CSRF/CORS, multi-tenant isolation, secret leakage, malicious admin strings.         |
| Resilience    | Provider outage, DNS failure, disk full, clock skew, slow client, corrupt tail, process kill, reload race.        |
| Performance   | Microbench, end-to-end benchmark, overload, soak, memory fragmentation.                                           |

## 21.1 Security gates

- No new external source or binary enters release without an approved exception decision.

- All privileged endpoints have positive and negative authorization tests.

- All secret-bearing types pass log/error/crash redaction tests.

- Known attack corpus produces bounded work and stable error responses.

- Two-person review for auth, parser, adapter credential handling, policy activation, and storage integrity changes.

- Release artifact provenance, compiler version, source digest, tests, and benchmark results are retained.

# 22. Operational runbooks

## 22.1 Provider outage

9.  Confirm target health and breaker reason without exposing provider credentials or prompt data.

10. Quarantine only when automatic breaking is insufficient; set expiry and incident reference.

11. Simulate critical aliases to confirm permitted fallback and capacity.

12. Do not broaden model families or residency during an incident without explicit approved policy.

13. After recovery, use half-open probes, gradual weight restoration, and compare errors/latency.

## 22.2 Credential rotation

14. Create new credential version through write-only endpoint.

15. Validate with a low-cost target-safe probe.

16. Activate new reference atomically with bounded overlap.

17. Drain/recycle connections whose authentication is connection-bound.

18. Revoke old credential, verify no use, and close the rotation audit record.

## 22.3 Compromised router API key

19. Revoke key id immediately; revocation bypasses configuration publication delay.

20. Search authorized audit/usage by key pseudonym, source constraints, models, and time.

21. Rotate downstream credentials only if evidence shows adapter/credential exposure; client keys do not grant provider secret reads.

22. Create replacement with least privilege and document incident.

## 22.4 Google identity outage

Existing sessions follow configured short lifetime; new Google logins fail closed. Authorized operators use a preprovisioned local break-glass method stored offline. Break-glass access is time-limited, reason-bound, alerting, and reviewed. The router MUST NOT disable authentication or accept unverified identity claims to restore convenience.

# 23. Migration from LiteLLM-style deployments

Migration is compatibility-led, not configuration emulation. Inventory actual client endpoints, aliases, provider models, retries, budgets, and auth assumptions. Map them into HypeLLM canonical concepts and reject ambiguous or unsafe behavior rather than importing it silently.

23. Capture a sanitized traffic/protocol profile and list every harness/version.

24. Create provider targets and aliases with explicit capabilities; do not infer capabilities solely from names.

25. Translate user/team model priorities into bindings and test with the policy simulator.

26. Run shadow decisions without sending duplicate provider requests; compare target selection and expected failover.

27. Canary selected principals using the same client base URL pattern and verify streaming/tools/errors.

28. Measure direct, incumbent-router, and HypeLLM overhead under identical upstream conditions.

29. Cut over by alias group; retain rapid DNS/edge rollback; freeze configuration during each window.

30. Remove legacy credentials and dependencies after audit confirms no traffic.

# 24. Phased implementation plan

| **Phase**            | **Scope**                                                                                             | **Exit**                                                         |
|----------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| 0 — foundations      | Threat model, protocol corpus, dependency policy, strict parsers, canonical model, benchmark harness. | Security review of interfaces and limits.                        |
| 1 — local MVP        | OpenAI chat/embeddings, llama.cpp, API keys, alias routing, static read-only dashboard, file config.  | Harness compatibility and performance targets on local provider. |
| 2 — remote providers | OpenAI, Anthropic, DeepSeek, Kimi adapters; TLS boundary; retries, breakers, quotas.                  | Golden/live sandbox tests and egress review.                     |
| 3 — control plane    | Google OIDC, RBAC, policy drafts/simulation/approval, credentials, audit, full SPA.                   | Admin security and recovery drills.                              |
| 4 — HA and hardening | Signed config distribution, quota authority, immutable audit export, fuzz/soak expansion.             | HA failure drills and production readiness review.               |

# 25. Open decisions

| **Decision**                  | **Recommended default**                                                                                                  |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| TLS/crypto profile            | Strict external audited boundary initially; consider fixed vendored implementation only after measured operational need. |
| HTTP versions                 | HTTP/1.1 inside normalized boundary for v1; edge provides HTTP/2/3.                                                      |
| State distribution            | Single-writer versioned bundles; do not build consensus in v1.                                                           |
| Tokenizer strategy            | Provider/local tokenize endpoint first; conservative estimator fallback; exact tokenizer modules only when reviewed.     |
| Cost accounting               | Configured price schedule with effective dates; provider usage reconciliation; not a billing ledger.                     |
| Group source for Google users | Local role bindings or separately provisioned directory sync; do not infer Google group membership from email domain.    |
| Generic adapter               | Disabled by default; fixed endpoint and explicit capabilities required.                                                  |

# 26. Fleet orchestration

The router routes to targets that are *already running*. This section makes "already running" a decision rather than an assumption: the router models the machines behind its targets, decides what the fleet must become to satisfy a request, and starts and stops declared deployments through an out-of-process agent.

The design reasoning is in `docs/orchestration.md`. What follows is normative; where the two disagree, this section wins.

## 26.1 The capability contract

A request is matched against a target on four independent axes, each an eligibility filter (§6.2) and never a score term.

- **Verb** — the kind of work the model does, from a closed vocabulary. Distinct from `Operation`, which is the wire shape the caller used: a music model and a speech model both take text and emit audio, and no combination of modalities distinguishes them. An alias may declare a `capability`; a target that does not declare it is excluded with `capability_unsupported`.
- **Modality** — extended with `document`. Documents are opaque bounded bytes. **The router MUST NOT parse a document**: no page counting, no text extraction, no rendering, and no format validation beyond matching a declared media type against a closed allowlist. A document URL is forwarded and never dereferenced, following the rule §10 already establishes for images.
- **Feature** — tools, structured output, streaming, as before.
- **Tier** — context, output, cost ceiling, and now a `quality_class` floor and a `reasoning_efforts` list. A request naming a tier no target supports is excluded with `reasoning_effort_unsupported` rather than silently downgraded.

Token estimation MUST NOT be byte-derived for documents. Each document part contributes a configured constant, declared per target with a router-wide default, erring high. A reasoning tier's `output_multiplier` MUST be applied **at reservation**, before outbound I/O; reserving unmultiplied would let a single JSON field consume several times the held allowance.

Inline document limits MUST be validated against `max_body_bytes` with base64 inflation applied, so a limit set that parses cannot then be refused by the body reader.

## 26.2 Trust boundary

The router MUST NOT execute a process. Actuation happens in a separate **fleet agent** across a narrow authenticated Unix socket, the third member of the family §4 (TLS helper) and §9.1 (identity verifier) already establish. The agent is platform-supplied and is part of the trusted computing base.

The socket carries **identifiers and bounded integers only** — no image name, host address, file path, container name, flag, shell fragment, or URL. The agent holds its own allowlist mapping each identifier to a machine and a command, and the router cannot extend it. A fully compromised router can reorder declared deployments; it cannot introduce one.

The handshake carries `HMAC-SHA-256(fleet.key, protocol-version ‖ nonce ‖ fleet-digest)` and the digest each side computes independently over the canonical fleet. On mismatch the router MUST issue no mutating verb and MUST exclude every orchestrated target with `fleet_configuration_mismatch`. The agent MUST reject a nonce it has already accepted.

The agent's inventory is untrusted input. It MUST be parsed under explicit limits; identifiers the configuration does not declare MUST be dropped and counted, never adopted; numeric fields MUST be range-checked; and a reply violating a bound MUST fail the whole observation rather than partially updating belief.

## 26.3 Belief, and what it gates

Configuration is authoritative for what may exist; observation is the only source of what does; the router's durable leases are authoritative for what it asked for; belief is the last valid observation plus its age, and it **expires**.

When the newest valid observation is older than `observation_max_age_ms`, cold orchestrated targets MUST become ineligible with `fleet_state_stale` and no plan may execute. Warm targets already serving continue under §13. A router that has never observed successfully MUST NOT be treated as having observed at age zero.

Divergence between observation and intent MUST be audited and re-planned **from observation**, not corrected by re-asserting intent. A deployment observed running that the router did not start is adopted as resident for routing and is **not** router-owned: it is never placed in an eviction set unless the operator opts in.

## 26.4 Planning

Planning is a pure function of an immutable snapshot: no I/O, no secrets, no clock. Equal fleet, demand, and policy snapshots MUST produce equal plans, and the same function MUST serve both the request path and `POST /admin/v1/fleet:simulate`.

Only an infeasible classification excludes. A target that is merely not running remains a candidate, ranked below a warm one — if "not currently running" excluded a target, no target would ever start.

Warmness contributes to the existing `affinity_term` (§6.3) under a split budget. No new score term is introduced and `MAX_NON_RANK_MAGNITUDE` is unchanged, so priority rank still dominates: a cold rank-0 target outranks a warm rank-1 target and the swap happens.

Eviction-set selection MUST be bounded and deterministic: exclude operator anchors, deployments inside their dwell window, busy deployments and deployments the router does not own; sort by retention value ascending with an identifier tie-break; take the smallest sufficient prefix, capped by `max_eviction_set`.

## 26.5 Governance

Five mechanisms, layered:

1. **Dwell floor.** Once ready, a deployment MUST NOT be evicted by the planner for `min_resident_ms`. This is the only hard floor and the one that bounds the worst case.
2. **Hysteresis margin.** Eviction requires incoming demand to *exceed* the evicted set's summed retention value by a configured margin, not merely equal it.
3. **Demand batching.** Requests for a cold capability accumulate in a bounded per-capability queue; one activation serves all of them.
4. **Cooldown and flap backoff.** After eviction a deployment MUST NOT be re-activated for `reactivation_cooldown_ms`, with exponential backoff on repetition, persisted across restart.
5. **Activation budget.** A sliding window per host on activations per hour. It MUST be a window rather than a token bucket: a bucket that starts full permits twice its hourly rate in the first hour, and this is the mechanism the safety claim rests on. When exhausted, cold targets on that host MUST be refused with `activation_budget_exhausted` rather than queued indefinitely.

Artifact acquisition MUST require a permission distinct from activation, MUST be off by default, and MUST verify a content digest before the artifact is activatable.

## 26.6 Ordering and accounting

The §3.1 lifecycle gains one step, placed between reservation and dispatch:

1–3. Unchanged.
4. Compute eligible targets, including the capability contract and residency classification.
5. Rank; **reserve admission capacity** using the effort- and document-adjusted estimate.
6. **New** — if the chosen candidate is not resident: acquire the activation lease, execute the plan, await readiness or fail over.
7–9. Unchanged.

Admission MUST be reserved before the activation lease. Both MUST be released exactly once on success, error, timeout, cancellation, client disconnect, deadline expiry, plan abandonment and shutdown; `Drop` alone is not trusted for either. A lease MUST be written durably **before** the mutating verb is sent, and agent verbs MUST be idempotent per lease so that re-issuing after a restart is safe.

Activation failure occurs strictly before upstream acceptance, so §6.5 failover applies unchanged and the prohibition on splicing after semantic output is untouched.

## 26.7 Disclosure

Host identifiers, memory figures, residency and activation history are management-plane data. Data-plane errors derived from a fleet decision MUST say that the capability is unavailable and MUST NOT name a host, an accelerator, or what else is loaded. Management visibility MUST NOT exceed the caller's tenant and permissions.

No prompt, tool argument, message or document may name a host, deployment, container, image, artifact or accelerator, or influence a plan by any path other than the resolved alias and its declared capability contract.

# Appendix A — Example route decision

| **Step**    | **Result**                                                                                                                                            |
|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Request     | principal user:42 asks alias code-premium, streaming tools, 120k input context, EU residency.                                                         |
| Policy      | Principal binding ranks local:qwen first, Claude second, OpenAI third; DeepSeek denied.                                                               |
| Eligibility | Local target excluded: 64k context. OpenAI target excluded: configured residency profile mismatch. Claude eligible. DeepSeek excluded by sticky deny. |
| Admission   | Claude target concurrency and tenant token reservation succeed.                                                                                       |
| Decision    | Claude chosen; policy digest p-8f…; explanation contains reason codes, no prompt.                                                                     |
| Failure     | If connection fails before acceptance, retry permitted target list is empty; return 503 no_eligible_target.                                           |

# Appendix B — Policy invariants

- A target denied by an applicable higher-precedence rule is never selected.

- A hard pin never falls back unless its own binding declares fallback.

- Security/residency/capability constraints are filters, never soft scores.

- Equal request, policy snapshot, and live-state snapshot produce equal ordered candidates.

- Every successful selection owns an admission reservation before outbound I/O.

- Every reservation is released exactly once on all success, error, timeout, and cancellation paths.

- No failover splices output after client-visible semantic bytes.

- Management visibility never exceeds the caller’s tenant and permissions.

- The models endpoint reveals only authorized aliases.

- No client-controlled value influences an upstream destination or credential handle.

Fleet orchestration (§26) adds:

- Every axis of the capability contract is an eligibility filter; none is a score term.

- The router never parses a document, never fetches a document URL, and document bytes never influence routing.

- A reasoning tier's output multiplier is applied at reservation, before outbound I/O.

- A client hint never creates eligibility, never beats warmth, and never outranks a binding. The warmth ladder's minimum adjacent gap exceeds the maximum hint bonus.

- The router never executes a process, and no identifier crossing the agent socket originates from a client.

- A deployment inside its dwell window is never evicted by the planner, and a pinned or non-evictable deployment never appears in an eviction set.

- No eviction occurs without exceeding the configured hysteresis margin, and an eviction set frees at least the required memory or the plan is refused.

- Equal fleet, demand and policy snapshots produce equal plans.

- Admission is reserved before an activation lease; both are released exactly once on every path.

- No plan executes on an observation older than its configured maximum age.

- The activation budget is a hard ceiling: when exhausted, requests are refused with a reason rather than queued indefinitely.

- No artifact is activated before its digest is verified.

- The agent handshake binds the protocol version and the fleet digest, and no nonce is accepted twice.

- Data-plane errors reveal no host, accelerator or co-resident deployment.

# Appendix C — Definition of done

- All normative requirements are traced to code, test, or explicit deferred issue.

- Strict dependency scan reports only workspace-owned Rust and static web sources.

- DOCS/API schemas and compatibility profiles are versioned.

- Threat model and abuse cases are current.

- Performance results include router overhead and overload behavior.

- Recovery from corrupt tail, disk full, provider outage, identity outage, and killed process is demonstrated.

- Static SPA passes accessibility, CSP, injection, CSRF/CORS, and privilege tests.

- Operational owners accept dashboards, alerts, runbooks, key/credential rotation, and rollback.
