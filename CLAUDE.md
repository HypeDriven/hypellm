# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

The specification is `secure_llm_router_specification.md` (v1.0, "HypeLLM Router"). It is the authority: when this file and the specification disagree, the specification wins.

The implementation is a Rust workspace of 17 crates, a static admin SPA under `web/`, and two reference out-of-process services that are deliberately **not** workspace members: the fleet agent under `agent/` and the identity verifier under `verifier/`. It is **not** feature-complete against the specification; `docs/deferred-issues.md` lists only the current limitations and accepted deviations.

The repository uses Git. Do not assume an edited working tree is disposable.

### Commands

```bash
cargo build --workspace --offline     # --offline is enforced by .cargo/config.toml
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline
cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .   # supply-chain gate
cargo run -q -p hypellm-devtools --bin depscan --offline -- --manifest # content-addressed SBOM
```

`depscan` is the mechanical enforcement of §4/§4.1/§15. It must report clean; it is not advisory, and there is no way to suppress a finding from the command line. `depscan --list-rules` prints the 20 rules it enforces.

Running the router:

```bash
cargo run -p hypellm-router -- --generate-secrets <dir>      # creates the key bundle and credentials/
cargo run -p hypellm-router -- --check --config <path>       # validate configuration; prints the fleet digest too
cargo run -p hypellm-router -- --config <path> --secrets <dir> [--static web] [--log info]
cargo run -p hypellm-router -- --shutdown --config <path> --secrets <dir>   # graceful stop
```

`--generate-secrets` prints the break-glass token **once** and stores only its verifier; the token is the operator's to keep offline (§22.4). Control-socket commands are authenticated by `<secrets>/control.key`, so use `--shutdown` rather than writing to the socket by hand — it keeps the token out of the process list.

Provider credentials are files at `<secrets>/credentials/<credential-id>`, one per `credential` record in the configuration. A declared credential with no file is a startup failure, not a warning.

### Watch out for

- **`cargo test --workspace` is the gate, and `--offline` matters.** A test that reaches the network is a bug.
- **`crates/hypellm-config/src/build.rs` is ordinary source, not a Cargo build script.** Only a `build.rs` at a package root is a build script, and §4.1 forbids those. `depscan` knows the difference; a new tool should too.
- **The panic-adjacent clippy lints are `warn` at the workspace level and `deny` at every crate root, scoped `#![cfg_attr(not(test), deny(...))]`.** §18.2 forbids `unwrap`/`expect`/unchecked indexing "outside startup invariants and tests", so `cfg(test)` is exactly the code the escalation should *not* cover — a `panic!` in an assertion is a test failure, which is the point of it. Escalating there too made the documented `--all-targets` gate fail on ~66 assertions, which does not make the data plane safer; it just means nobody runs the wider lint. Adding a bare `#![deny(clippy::…)]` at a crate root reintroduces that. Exceptions in production code carry an `#[allow]` on the smallest enclosing item with the reason it cannot fail.

## What is being built

HypeLLM Router: an LLM routing gateway in Rust plus a standalone static admin SPA. It accepts OpenAI-/Anthropic-compatible HTTP from coding harnesses, authenticates the caller, resolves a model alias under per-user/per-model priority policy, ranks eligible targets, reserves capacity, translates to a provider-native wire format, and streams back with backpressure.

Providers in scope: llama.cpp (local, OpenAI-compatible), OpenAI, Anthropic, DeepSeek, Moonshot/Kimi.

Explicit non-goals: agent framework, vector DB, secrets vault, billing system, model host, general reverse proxy, and any browser automation/cookie reuse against consumer chat sites.

## The constraints that will surprise you

These are the spec's defining decisions. Most "obvious" implementation choices violate them.

- **No third-party packages, at all.** No crates.io dependencies, no npm, no CDN assets, no remote fonts. Release builds run `--offline` against workspace-local crates and must fail if registry deps, `build.rs`, proc macros, or dynamic loading appear. `Cargo.lock` is explicitly considered insufficient. Reach for the standard library or write an in-repo module (§4).
- **Do not hand-roll TLS or crypto.** The "no dependencies" rule does *not* license novel signature/TLS code. Strict profile terminates TLS at a platform boundary and delegates JWT verification to an approved local verifier. A vendored audited TLS implementation is admissible only via a formal security decision record (§4, §9.1).
- **`#![forbid(unsafe_code)]` workspace-wide**; `unwrap`/`expect` are forbidden outside startup invariants and tests; no panics on data-plane input; all integer conversions checked (§18.2).
- **Configuration is a custom line-oriented grammar, not YAML/TOML** — records of the form `type key=value …`, JSON-style quoted strings, `#` comments, unknown fields are errors. No includes, env-var expansion, anchors, or templates (§11.1).
- **The SPA has no `vendor/` directory.** First-party HTML/CSS/ES-modules/SVG only; no eval, no inline handlers, no HTML string injection (build DOM nodes), no service-worker code execution, strict CSP (§15).
- **Everything is bounded.** No unbounded thread, task, buffer, channel, queue, retry loop, or log entry may originate from a request. Header/body/JSON-depth/stream-buffer limits are in §3.2; every I/O has a deadline and cancellation path. A request may not create an unbounded amount of *fleet work* either: activation queues, plan sizes, eviction sets and leases all carry finite maxima.
- **The router never executes a process.** Starting a container means `ssh` and `docker`, which happens in `agent/` across a narrow authenticated Unix socket carrying opaque identifiers and bounded integers only. `depscan`'s `forbidden-api` rule fails the build on `process::Command`; do not work around it (§26.2).
- **The router verifies no JWT and terminates no TLS.** §4 and §9.1 put both outside it, so `hypellm-net::helper` is a *client* for two platform services. `verifier/` is the reference identity verifier: it performs no cryptography of its own — `openssl dgst -verify` for the signature, the platform's TLS for the transport — and it validates the signature only, because `iss`/`aud`/`exp`/`nonce` are checked in exactly one place (`hypellm_auth::oidc::validate_claims`). Adding a claim check there would create the second path that design exists to prevent.

## Architecture shape

Two artifacts: the `hypellm-router` binary and a directory of immutable static web assets. The data path (inference listener) and management path (`/admin/v1`) are separated in code, scheduling, rate limits, auth scopes, and listeners — even while in one process — so they can split later without API changes.

Workspace crates as built. §18.1 names most of these; the six marked *(addition)* are not in the specification's list and each has a stated reason in its `MODULE.md`.

| Crate | Responsibility |
|---|---|
| `hypellm-router` | Binary, startup and shutdown, listeners, request pipeline, client protocol translation |
| `hypellm-core` | Canonical types, routing policy, scoring, admission, health/breakers, decision traces. Pure: no I/O, no secrets |
| `hypellm-config` | The §11.1 line-oriented grammar, schema, reference resolution, digest *(addition)* |
| `hypellm-store` | Append-only framed log, snapshots, atomic activation, audit hash chain |
| `hypellm-fleet` | Fleet domain model, observation, the pure planner, anti-thrash governance, activation state machine, agent protocol codec *(addition)* |
| `hypellm-auth` | API keys, OIDC transactions and sessions, peer/edge identity |
| `hypellm-adapters` | Compile-time provider families. The only code that touches provider credentials |
| `hypellm-net` | Egress guard, bounded upstream client, connection pool, DNS pool, TLS/verifier helpers *(addition)* |
| `hypellm-crypto` | SHA-256, HMAC, CRC-32, base64, hex, constant-time compare, OS randomness *(addition)* — see its `MODULE.md`; it deliberately implements **no** TLS, asymmetric signatures, or JWT verification |
| `hypellm-admin-api` | `/admin/v1` surface, CORS/CSRF, drafts, usage and audit views |
| `hypellm-telemetry` | Bounded metrics and structured logs with closed label vocabularies |
| `wire-http1`, `wire-json`, `wire-sse` | Strict bounded parsers written in-repo |
| `hypellm-test-corpus` | Protocol vectors, golden provider fixtures, harness profiles |
| `hypellm-devtools` | `depscan`: the supply-chain and static-web gate, plus the build manifest *(addition)* |
| `hypellm-bench` | The §19.1 benchmark harness *(addition)* |

Every crate carries a `MODULE.md` — §4.1 requires owner, threat notes, public API, unsafe-code declaration, fuzz targets, and resource limits. `depscan` checks they exist and are filled in.

Layer responsibilities that matter when placing new code:

- **Router core** decides; it holds no secrets and does no I/O. `PolicySnapshot::route(ctx, req, live)` returns ranked candidates plus exclusion reasons.
- **Adapters** are the *only* code that touches provider credentials. They do typed conversion, endpoint paths, auth header construction, stream decoding, error mapping — and nothing else. They make no routing decisions, read no files, resolve no arbitrary hosts.
- **Store** owns the append-only framed log + snapshots. Config activation is: validate off-path → durable commit → atomic pointer swap. In-flight requests keep their prior snapshot; partial mutation is never visible.
- **Fleet** decides what the fleet must *become*; it holds no socket, no clock and no secret. `plan(&FleetSnapshot, &DemandSnapshot, &TargetId, &PlanContext)` is pure, so the same function serves the request path and `POST /admin/v1/fleet:simulate`. The socket lives in `hypellm-net::fleet`, the runtime in `hypellm-router::fleet`, and the process that runs `ssh` and `docker` is in `agent/`, outside the build.

## Invariants to preserve in any change

Appendix B is the checklist; the ones most easily broken by ordinary edits:

- Security, residency, and capability constraints are **eligibility filters, never score penalties**. Scoring is integer fixed-point with saturating arithmetic (§6.3).
- A higher-precedence deny is sticky downward — no lower-precedence binding can re-enable it. Hard pins fail closed unless their own binding declares fallback (§6.1).
- Equal (request, policy snapshot, live state) ⇒ equal ordered candidates. The only permitted nondeterminism is a `request_id`-seeded tie-break; never map iteration order.
- Every selection holds an admission reservation *before* outbound I/O, and every reservation is released exactly once on success, error, timeout, and cancellation. `Drop` alone is not trusted for accounting.
- **Never splice failover output after client-visible semantic bytes.** Fail over freely before upstream acceptance; only for idempotent requests after acceptance; never after the first content or tool delta — emit a normalized error and close (§6.5).
- **Fleet: only `Infeasible` excludes.** A target that is merely not running is still a candidate, ranked below a warm one. If "not currently running" excluded a target, no target would ever start (§26.4).
- **Fleet: admission is reserved before the activation lease**, and both release exactly once on every path. Evicting a running model and *then* discovering the tenant is over quota is the unforced error the ordering exists to prevent.
- **Fleet: no plan executes on stale belief.** Past `observation_max_age_ms` cold targets are ineligible; warm ones keep serving. A stale-state swap costs minutes of fleet time and can cascade.
- No client-controlled value may influence an upstream destination, Host/SNI, credential handle, file path, or socket. Destinations are administrator-configured tuples; redirects off; proxy env vars ignored (§10).
- The models endpoint and all management responses reveal only what the caller's tenant and permissions allow.
- Prompts are inert data — never interpreted as configuration, destination, credential, or admin instruction.

## Secrets and redaction

Credentials live behind opaque handles resolved only inside the adapter boundary. The break-glass token is the one secret the router deliberately cannot read: it holds a digest, because §22.4 requires the token to live offline. `SensitiveHeaders` and `Sensitive<T>` implement redacting `Debug`/`Display` and are not `Clone` without justification. Prompt/completion bodies are not logged by default. Metrics forbid high-cardinality labels (raw user id, request id, prompt, URL, error text) — use deterministic pseudonyms when correlation is needed (§7.1, §10, §17).

## Testing expectations

§21 defines the required layers: unit, property (routing determinism, deny monotonicity, pin semantics, reservation conservation), fuzz (HTTP, JSON, SSE, config, provider events, management API, state recovery), integration against recorded golden servers, versioned harness-compatibility profiles, security (SSRF, smuggling, CSRF/CORS, tenant isolation, secret leakage), resilience (corrupt tail, disk full, clock skew, slow client, reload race), and performance (p50 < 2 ms / p99 < 10 ms router overhead; benchmarks report distributions, not averages).

All layers except a few fuzz rows now exist:

- **Property** — `crates/hypellm-core/tests/properties.rs`: 14 properties over Appendix B (routing determinism, deny monotonicity, pin semantics, reservation conservation, score overflow), each across 400 seeded cases. `crates/hypellm-core/tests/capability.rs` adds 16 over the §26.1 contract, and `crates/hypellm-fleet/tests/properties.rs` 12 over the §26.4/§26.5 fleet invariants.
- **Fuzz** — `tests/fuzz.rs` in `wire-json` (6), `wire-http1` (7), `wire-sse` (8), `hypellm-config` (7), `hypellm-store` (7), `hypellm-adapters` (9), `hypellm-admin-api` (9), `hypellm-router` (9), `hypellm-fleet` (8: agent inventory, agent replies, lease accounting), and `hypellm-net` (5: the identity verifier boundary — no claim fabricated from a malformed reply, no identity from a refusal). That is all seven areas §21 names, plus the client protocol parsers. There is **no `fuzz/` directory and no libFuzzer** — §4 admits no such dependency. The engine is a seeded deterministic mutator in `hypellm-test-corpus::fuzz`, driven from ordinary `#[test]` functions so `cargo test` runs it and a failure is reproducible by seed number.
- **What that does not mean.** It is not coverage-guided and does not shrink, so it finds what its seeds and mutation strategies reach. A failing case prints at whatever size it was generated.

A fuzz target that only asserts "does not panic" is close to worthless here. Each of these asserts a property the code could plausibly violate — no silent widening, no leaked body, no identity taken from a caller, no unauthenticated success — and three of them have found real defects. When adding one, write the property first.

Keep fuzz documentation aligned with the suites that exist. The required seven areas are present; module-specific optional targets may still be absent and must not be claimed as implemented.

- **Fleet integration** — `crates/hypellm-router/tests/fleet.rs` drives the real client over a real Unix socket against `hypellm_net::fleet_sim::SimulatedAgent`, which verifies the handshake HMAC and enforces its own allowlist. `Clock::sleep` advances a `TestClock` rather than blocking, so a three-minute model load takes microseconds and the deadline arithmetic is exact. No SSH, no Docker, no network.

### What a test here is for

The bar is not coverage, it is *would this catch the bug*. Assert the security or state property, not merely the response status. When adding a test:

- Name the property, not the function: `a_healthy_pin_outranks_its_own_emergency_fallback`, not `test_pin`.
- Make the fixture adversarial. A pin test where the pin is also the cheapest target proves nothing.
- **Verify the test fails without the fix.** Comment out the fix, watch it go red, put it back. A regression test that passes either way is decoration.
- When a handler reports success, assert the underlying state changed — not just the status code.

## Build order

The spec's phased plan (§24) is the intended sequence: 0 foundations (threat model, protocol corpus, strict parsers, canonical model, benchmark harness) → 1 local MVP (llama.cpp + OpenAI chat/embeddings, API keys, alias routing, read-only dashboard) → 2 remote adapters → 3 control plane (Google OIDC, RBAC, policy drafts/simulation/approval, full SPA) → 4 HA and hardening.

Open decisions with recommended defaults are in §25 — check there before designing TLS profile, HTTP version support, state distribution, or tokenizer strategy.

## Honesty

This is a security artifact, and its documentation is read as one. Two rules follow:

- **Never describe something as implemented when it is not.** A `MODULE.md` claiming fuzz targets that do not exist, or a handler replying `stored: true` after discarding the secret, is worse than an acknowledged gap — it removes the reason anyone would go looking.
- **When a capability is missing, say so where the reader will be.** The SPA screens with no backing endpoint render an explicit "not available yet" rather than plausible-looking rows. Keep public documentation focused on current behavior; closed defects belong in version control, not in current limitations.

`docs/deferred-issues.md` lists current limitations. Add a newly confirmed limitation there rather than quietly working around it, and remove it when the limitation is resolved.
