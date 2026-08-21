# Capability orchestration across a managed fleet

**Status: built, with four stated exceptions.** Phases 5 through 8 are implemented: the capability contract, the fleet domain model and agent protocol, observation, planning, activation with leases and rollback, anti-thrash governance, the management surface, and the SPA screens. `crates/hypellm-fleet` is the planner, `crates/hypellm-net/src/fleet.rs` the socket, `crates/hypellm-router/src/fleet.rs` the runtime, and `agent/` the reference agent that reaches the slaves.

Four things described here are **not** implemented, and are recorded in [current limitations](deferred-issues.md) rather than approximated: `POST /v1/jobs` (§11), predictive pre-warm (§9.8, which this document already defers), resumable artifact fetches (§12), and Windows-host actuation. Two implemented details deviate from the design below and are marked **[as built]** where they occur — the `HELLO` line carries the fleet digest, and the activation budget is a sliding window rather than a token bucket. Both changes were forced by building it, and both are explained at the point they appear.

This document remains written in the specification's normative voice. `secure_llm_router_specification.md` §26 now carries the normative summary; this is the reasoning behind it.

**Reference convention.** `spec §N` refers to `secure_llm_router_specification.md`. A bare `§N` refers to a section of this document.

**Specification relationship.** This extends spec §5, §5.1, §6, §11.1, §12, §13, §16, §17, §21 and §24. It does not amend spec §4, §4.1, §10, §15 or §18.2, and every design decision below is constrained by them. Where the specification must change, the change is stated explicitly rather than implied.

---

## 1. What this adds

HypeLLM Router today routes a request to a target that is *already running*, chosen from an alias's permitted set. Every target is assumed permanently available; the only variability is health, capacity and policy.

Two assumptions break at once when the fleet is real.

**The first is availability.** A single accelerator host has finite memory, and the models an operator wants to offer do not fit simultaneously. On the DGX Spark, MiniMax-H3, MiniMax-Music3 and the Qwen3.8 27B chat service can be resident together only by leaving roughly 4 GiB of headroom, which is not enough to run any of them at length. Offering all three as routable targets means accepting that a request for one may have to stop another.

**The second is expressiveness.** A request carries more intent than "alias plus operation". A caller wanting a 27B model at Q5 to read a PDF with medium reasoning effort is stating four separate requirements — a model tier, a document modality, a reasoning budget, and implicitly a latency tolerance. The canonical request models none of the last three. Routing them correctly is not a provider passthrough problem: reasoning effort changes token counts and therefore admission reservations, and document input changes which targets are eligible at all. On this fleet that distinction is concrete — the Spark's Qwen3.8 deliberately runs **without** the vision projector to preserve memory headroom, so it cannot serve a document request no matter how much VRAM is free.

This feature addresses both, because they are the same problem seen from two ends: deciding what the fleet must become in order to satisfy what a request actually asked for.

- A request is matched against a **capability contract** with four axes — verb, modality, feature, tier (§3) — rather than a single label.
- The router models every **host**, its **accelerators**, and which **deployments** are resident (§5).
- When the best way to satisfy a contract is to start a cold deployment, the router produces an explicit **plan**: what to stop, what to start, and what that costs in time. The plan is a pure function of a snapshot, so it can be simulated without touching the fleet (§8).
- Plans are subject to **anti-thrash governance** — dwell floors, hysteresis margins, activation budgets, demand batching, cooldowns — so oscillating demand converges instead of destroying throughput (§9).
- If an artifact is present on no host it may be **acquired**, under explicit permission and budget, verified by digest, onto an architecture-compatible host with sufficient disk (§12).

### 1.1 Non-goals

This is not a container orchestrator and must not become one. Out of scope: general workload scheduling, replica abstractions, service discovery for non-inference services, image building, host autoscaling, cluster networking, and any control over containers not declared as inference deployments in HypeLLM's own configuration. The router observes and toggles a **closed, administrator-declared set** and nothing else.

It is also not a distributed scheduler. Placement decisions are made by one router process against its own snapshot. Multi-node coordination inherits the constraint already recorded in [current limitations](deferred-issues.md): independent nodes are not a cluster. Two routers must not manage one host (§10.4).

It does not parse or interpret user content. Adding a document modality (§3.3) explicitly does **not** add a PDF parser to the data plane.

### 1.2 The fleet this is designed against

Validated against a real five-host fleet. Hosts are named by their configured
identifier throughout — an address is a deployment detail, and the design turns
on what each machine *is*:

| Host | Accelerator | Memory | Constraint that matters |
|---|---|---|---|
| `rtx4090` | RTX 4090 Laptop | 16 GB VRAM | Four services at once; MOSS-SoundEffect v2 is on-disk, un-containerised, and consumes nearly the whole GPU. |
| `node0` | GT 1030 (idx 0) + GTX 1080 Ti (idx 1) | 4 GB + 11 GB | **Two accelerators of very different capability.** Placement must select `device=1`, not merely "the host". Hosts the fleet's only vision model. |
| `cache` | GT 1030 | 2 GB | CPU/RAM/disk host (Threadripper, 101 GB, 5.9 TB free). Not an inference target; the natural artifact cache. |
| `rtx5090` | RTX 5090 | 32 GB VRAM | Best discrete GPU; also runs unrelated production services that must never be evicted. |
| `spark` | NVIDIA GB10 | ~140 GB **unified** | **ARM64.** Unified memory is shared with the host, so a VRAM-only model is wrong. Three large models contend. Vision deliberately not loaded. |

Four consequences are load-bearing below: accelerators are addressed individually (§5.2); memory is a per-pool quantity with a host reservation, because unified memory is not VRAM (§5.2); artifacts are architecture-scoped, because an x86-64 image will never run on the Spark (§12); and **the same weights can back two targets with different capability declarations** — Qwen3.8 with and without the vision projector are different memory footprints and different eligibility (§1.3).

### 1.3 Model, alias, target, deployment, artifact

Five distinct things. Conflating any two of them produces a design that cannot express this fleet, so they are defined before anything else.

| Term | What it is | Client-visible? |
|---|---|---|
| **Model** | A set of weights. Not a router concept. Has no identifier in configuration. | No |
| **Artifact** | The distributable form of a model or image — digest, size, architecture. What gets fetched. | No |
| **Target** | A model *as served by one provider endpoint*, with a full capability declaration and limits. `spark:qwen38-q5`. | Only if an alias exposes it |
| **Deployment** | A target's *lifecycle on one accelerator* — memory cost, start/stop times, dwell rules. New in this design. | No |
| **Alias** | The client-visible name. Resolves to a permitted set of targets. `requested_model` is typed `AliasId`. | **Yes — this is what the client sends** |

The router does not map a request to a model. It maps an alias to a *set* of targets and ranks them. This is deliberate: spec Appendix B requires that no client-controlled value influence an upstream destination, and an alias is the indirection that makes that true.

**The practical guidance, which is not currently written down anywhere and should be: name aliases after models.** Nothing prevents

```text
alias id=qwen3.8-27b-q5 capability=chat targets=spark:qwen38-q5,rtx5090:qwen38-q5
```

A client then sends `"model": "qwen3.8-27b-q5"` — model-centric, works unmodified with any OpenAI harness — while the router chooses between two hosts under administrator policy. The caller experiences direct model selection; the operator retains destination control. Host selection is therefore **not a new routing dimension**: it falls out of the existing alias→target ranking, now informed by residency (§7).

Three corollaries worth stating because each one has bitten someone:

- **Quantization is target identity, not a request parameter.** Q5 and Q4 of one model are two targets with different memory, quality and cost. Your fleet already has exactly this pair. Expose the choice by declaring two aliases, or one alias with both targets and a quality tier (§3.5).
- **The same weights may back two targets.** Qwen3.8 with the vision projector loaded is a different capability declaration and a different `memory_bytes` than the same weights without it. Two targets, two deployments, one artifact.
- **A target belongs to exactly one host.** A model runnable in two places is two targets sharing an alias. `Target` is unchanged by this design.

---

## 2. What does not change

Stated first because the temptation to violate each is real.

1. **The router does not execute processes.** spec §4.1 forbids shell execution and depscan's `forbidden-api` rule fails the build on `process::Command`. The router will never invoke `ssh`, `docker` or `powershell.exe`. Actuation happens in a separate out-of-process **fleet agent** across a narrow authenticated local socket (§4).
2. **The router does not parse user content.** Adding a document modality does not add a document parser. Document bytes are opaque, bounded, and forwarded (§3.3).
3. **Security, residency and capability constraints remain eligibility filters, never score penalties** (spec §6.2, §6.3, Appendix B). Warmness is a preference; authorization is not.
4. **The spec §6.3 score term list is closed and its bound is proven.** No new score term. Warmness and client hints share the existing `affinity_term` under a split budget (§7.2).
5. **Priority rank still dominates.** `ScoreTerms::RANK_UNIT` (1,000,000) exceeds `MAX_NON_RANK_MAGNITUDE` (400,999), so a cold rank-0 target outranks a warm rank-1 target and the swap happens. An operator's explicit preference is not silently overturned by what happens to be loaded — which is also why warmth must not become a filter.
6. **Client hints never create eligibility.** A permitted hint may reorder targets that are already eligible. It may not make an ineligible target eligible, and it may not outrank a priority binding (§3.6).
7. **Prompts are inert data.** No prompt, tool argument, message or document may name a host, deployment, container, image, artifact or accelerator, or influence a plan by any path other than the resolved alias and the declared capability contract.
8. **Everything is bounded.** Activation queues, plan sizes, eviction sets, inventory payloads, document counts, fetch sizes, retries and leases carry finite maxima. A request may not create an unbounded amount of *fleet work* any more than an unbounded buffer.
9. **Targets without a deployment record behave exactly as they do today.** A deployment-free configuration produces byte-identical routing behaviour.

---

## 3. The capability contract

The current model asks one question of a target: does it serve this operation, with these modalities, tools, context and residency? That is enough to route chat between two chat models. It is not enough to decide that a document request cannot go to a projector-less deployment, or that a high-effort request needs four times the token reservation.

A **capability contract** is what a request requires and what a target declares, across four independent axes. Every axis is an eligibility filter (spec §6.2), never a score term.

### 3.1 The four axes

| Axis | Question | Request source | Target declaration |
|---|---|---|---|
| **Verb** | What kind of work is this? | Alias's declared capability | `capabilities` |
| **Modality** | What inputs does it carry? | Derived from content parts | `modalities` |
| **Feature** | What behaviours must work? | Tools, structured output, streaming, reasoning | `Capabilities` booleans |
| **Tier** | How large, how good, how hard? | Context, output, quality floor, cost ceiling, effort | `max_context_tokens`, `quality_class`, `cost_class`, `reasoning_efforts` |

Verb and feature exist in some form today. Modality exists but is incomplete. Tier is partial — context and cost are modelled, quality and effort are not. The three additions below complete it.

### 3.2 Capability verbs

A closed vocabulary — never a client-supplied string, both because spec §10 forbids client-controlled routing inputs and because spec §17 forbids unbounded metric labels:

`chat`, `vision`, `document`, `embeddings`, `rerank`, `text-to-speech`, `text-to-music`, `text-to-sfx`, `text-to-image`, `text-to-video`, `image-to-video`, `audio-to-video`, `lipsync`.

`Capability` is distinct from `Operation`. `Operation` is the wire shape the client used; `Capability` is the work the model does. A music model and a TTS model both take text and emit audio, and no combination of modalities distinguishes them — which is why the verb axis cannot be derived and must be declared.

`alias` gains `capability`; `target` gains a `capabilities` list. A target not declaring the alias's verb is excluded with `capability_unsupported`.

### 3.3 Modalities, including documents

`Modality` is extended from `Text | Image | Audio` to include **`Document`**, and `ContentPart` gains:

```rust
Document {
    /// Declared media type, from a closed allowlist (`application/pdf`, …).
    media_type: DocumentType,
    /// Inline base64, or a URL the router forwards and never fetches.
    source: DocumentSource,
}
```

`DocumentSource` mirrors the existing `ImageSource` exactly, including the rule its own comment already states: **a URL is forwarded to the provider and never fetched by the router**, because fetching a caller-named URL would make the router an SSRF proxy (spec §10). The provider retrieves it under its own egress policy, and only when the target declares the modality. Reusing this shape rather than inventing an upload endpoint means documents inherit a boundary that is already reasoned about and tested.

**The router must never parse the document.** No page counting, no text extraction, no rendering, no format validation beyond the declared media type against a closed allowlist. A document is opaque bounded bytes forwarded to a target that declared the modality. Adding a PDF parser to the data plane would put a notoriously hostile format in front of untrusted input, in a codebase whose entire parser strategy is small, strict, in-repository and fuzzed. It is not a close call.

Two consequences follow, and both are the reason this is a design decision rather than an enum variant:

**Token estimation cannot be byte-derived.** spec §12 requires "a conservative byte-based upper bound" when no tokenizer is available; the implementation currently uses `ceil(bytes / 2)` in `hypellm_core::canonical::estimated_input_tokens`. That is conservative for text and meaningless for documents: a scanned PDF is megabytes and few tokens, a dense text PDF is the reverse, and a page rendered as an image costs a fixed model-dependent amount. Since the router cannot count pages without parsing, it must use a **configured conservative constant per document part** — `document_token_estimate`, declared per target with a global default, erring high — added to the byte-based estimate for the remaining content. An operator tuning this is choosing between rejecting large documents and admitting them past a quota, and should be told so.

**Bounds are mandatory, and inline documents are bounded by the body limit they live inside.** `max_body_bytes` defaults to 16 MiB, and base64 inflates payloads by roughly 4/3, so an inline document budget must be set against the encoded size, not the decoded one:

| Bound | Default | Why |
|---|---|---|
| `max_documents_per_request` | 4 | Caps reservation and provider cost per request. |
| `max_document_bytes` | 4 MiB decoded | Per inline part. |
| `max_inline_document_bytes` | 8 MiB decoded | Aggregate. At ~10.7 MiB encoded this leaves headroom inside the 16 MiB body. |

Configuration validation rejects a set of limits whose encoded aggregate cannot fit `max_body_bytes`, so raising one forces raising the other deliberately rather than producing requests that parse and then fail.

URL-form documents consume no body budget — and the router cannot know their size at all, since it never fetches them. That makes the conservative token constant below load-bearing rather than a convenience.

Eligibility needs no new exclusion reason: `modality_unsupported` already exists and already does the right thing. On this fleet it does something specifically useful — a document request against the Spark's projector-less Qwen3.8 is excluded and routed to `ai-qwen35-9b-vision` on `node0`, or refused with a reason. It does **not** start a container and discover the problem at the provider.

### 3.4 Reasoning effort

Absent from the canonical request today. `Capabilities.reasoning` is a boolean meaning "exposes reasoning content" — a different question, and it stays as it is.

```rust
pub enum ReasoningEffort { Unset, Minimal, Low, Medium, High }
```

`Unset` is distinct from `Minimal`, per spec §5.1's existing rule that sampling parameters carry an explicit unset distinct from zero. A target declares `reasoning_efforts` — the tiers it supports, a list rather than a boolean. A request naming a tier no eligible target supports is excluded with `reasoning_effort_unsupported`.

Effort is a **routing input, not a provider passthrough**, for three reasons that each touch a different subsystem:

**Admission.** Effort multiplies expected output tokens. Each tier carries an administrator-declared `output_multiplier` per target (default 1 / 2 / 4 / 8 for minimal / low / medium / high). The multiplier is applied *at reservation*, and reconciled against provider-reported usage on completion through the existing `Reservation::commit(actual_tokens)` path. Reserving unmultiplied would let a high-effort request consume several times what it was held to — a quota bypass that requires no malformed input at all, just a JSON field.

**Deadlines.** Effort raises expected time to completion, so the cold-start feasibility check (§7.3) must compare against effort-adjusted duration, not the base estimate. A high-effort request behind a 3-minute model load is a different proposition from a minimal-effort one.

**Adapters.** Each family maps the tier to its own parameter — OpenAI `reasoning.effort`, Anthropic a thinking-token budget, llama.cpp `--reasoning` or a no-op. This is exactly the typed conversion spec §7.1 assigns to adapters, and nothing more: adapters still make no routing decisions.

### 3.5 Quality tiers and quantization

Your fleet runs Q5_K_P with Q4_K_P downloaded as a fallback. Both serve the same alias; one is better. Nothing in the current model expresses "better".

`cost_class` cannot serve this. It is orderable, but cost and quality are not the same axis — a local Q5 may be cheaper *and* better than a remote Q4, and conflating them makes that target either unreachable or mispriced.

So `target` gains `quality_class`, an ordered class exactly symmetric with the existing `cost_class`, and `RequestLimits` gains `min_quality` as a **floor**, symmetric with the existing `max_cost` ceiling. Exclusion: `quality_floor_not_met`. No new mechanism — the same shape, the other direction.

Quantization itself remains unmodelled, and deliberately. What the router needs is memory, context, quality and cost; Q5 versus Q4 differs in precisely those four, all of which are already declared. "Q5" is the operator's label in a target id, not a concept the router reasons about.

### 3.6 Client hints

`RoutingHints.prefer_target` is currently parsed from `hypellm_routing.prefer_target`, validated as a target id, and correctly permission-gated behind `hints_permitted` — and then never read by `PolicySnapshot::route`. Only `require_local` is consulted. Its docstring promises "prefer this target if it is already eligible", which does not happen.

**The permission gate is less covered than it looks, and that must be repaired first.** The fuzz target `a_hint_is_ignored_unless_the_principal_may_supply_one` plants its hints under the key `"hypellm"`, while `parse_hints` looks up `"hypellm_routing"`. Since the key lookup is the *first* early return and the permission gate the *second*, control never reaches the gate: the function returns a default for a reason unrelated to permissions, and all three of that target's cases assert vacuously. The test would pass with the gate deleted. Repairing the key is a prerequisite for the wiring below — once `prefer_target` actually reorders candidates, a permission-gate test that cannot fail is worse than no test at all.

It fails safe, so this is a functionality gap rather than a security one. This design wires it, with semantics that keep it safe:

- A hint **reorders** targets that are already eligible. It never creates eligibility.
- It draws from a bounded slice of `affinity_term` (§7.2), so it can break a tie between comparable targets and can never beat a warmer target, a higher-ranked target, or a policy binding.
- It remains permission-gated and silently dropped otherwise, unchanged.
- An unknown or ineligible `prefer_target` is ignored, not an error — a harness that always sends one must keep working.

A hint that could outrank policy would be a client-controlled destination by a longer route, which spec Appendix B forbids. Bounding it inside affinity is what makes it admissible at all.

### 3.7 What this costs at admission

Three of these axes change the reservation, so they are computed **before** capacity is reserved, not after:

| Input | Effect on the estimate |
|---|---|
| Reasoning effort | Multiplies reserved output tokens by the tier's `output_multiplier`. |
| Documents | Adds `document_token_estimate` per part, not `bytes / 2`. |
| Quality floor / cost ceiling | Filters candidates; no estimate effect. |

Over-estimation is the correct failure direction and matches the existing posture: the current estimator deliberately errs toward over-counting, and [current limitations](deferred-issues.md) already records that this rejects some near-limit requests. These additions make it more conservative, not less.

---

## 4. Trust boundary: the fleet agent

### 4.1 Why it is a separate process

Starting a container on `spark` means running `ssh` and `docker compose`. The router cannot do this and must not be changed so that it can — the prohibition on subprocess execution is load-bearing, and a router that can spawn a shell is a different security proposition.

The specification already solves this shape twice. spec §4 delegates outbound TLS to "a platform-provided audited TLS helper/sidecar with a narrow CONNECT-like API and destination allowlist"; spec §9.1 delegates JWT verification to "an approved local identity/TLS verifier service over a narrow authenticated local interface". `crates/hypellm-net/src/helper.rs` implements both clients over a deliberately tiny line protocol on a Unix socket.

The fleet agent is the third member of that family and follows the same rules.

**The fleet agent is not a workspace crate.** It is platform-supplied, like the TLS helper and the OIDC verifier, and it joins them in the trusted computing base. The repository ships:

- the wire protocol (§4.3) as normative text;
- a **conformance corpus** in `hypellm-test-corpus` — recorded exchanges, malformed replies, protocol violations, required state transitions;
- a **simulated agent** used by every test, with a deterministic clock and scriptable latencies and failures, so `cargo test --workspace --offline` exercises the full activation path without SSH, Docker or a network.

A reference agent may live in this repository *outside the strict-profile build boundary* — not a workspace member, not built by `cargo build --workspace`, not scanned as router source. Admitting it into the workspace would require the spec §4 security-decision-record process, and there is no reason to seek that.

This is an honest cost, not a free win: the agent holds SSH keys to five machines and can start and stop containers on all of them. §15 treats it as a first-class attacker target.

### 4.2 What the agent may be told

The router sends **identifiers, never commands.** The socket carries no image name, host address, file path, container name, Docker flag, shell fragment or URL — only opaque `deployment-id` and `artifact-id` tokens both sides hold from configuration, plus bounded integers.

The agent maintains **its own** allowlist mapping each identifier to a host, SSH destination, Compose project and service. The router cannot extend it. The goal is specific: **a fully compromised router cannot cause arbitrary code to run on a slave.** It can reorder declared deployments; it cannot introduce one.

An unrecognised identifier is refused with `ERR unknown_deployment` and audited on both sides. A fleet-digest mismatch fails closed rather than warning: the router issues no mutating verb, and every orchestrated target is excluded with `fleet_configuration_mismatch` until the digests agree (§4.3).

### 4.3 Wire protocol

The same line-oriented shape as `helper.rs`, over an owner-only Unix socket, authenticated with `<secrets>/fleet.key` via `hypellm_crypto::hmac::hmac_sha256_parts` and verified with `hypellm_crypto::ct::eq`. `HELLO` carries `HMAC-SHA-256(fleet.key, protocol-version ‖ nonce ‖ fleet-digest)`, so the handshake binds both the protocol version and the fleet configuration each side claims, and the agent rejects a nonce it has already accepted.

This is deliberately **stronger than the control socket's `control.key`, and does not reuse it.** That pattern sends the hex-encoded key itself as a bearer line and constant-time-compares it (`startup.rs::authenticated_control_command`); it carries no keyed digest and binds no message. A bearer line is adequate for a local stop command and inadequate for verbs that stop production models, so the fleet socket does not inherit it. Every reply bounded; every request deadlined.

**[as built]** `HELLO` carries the router's digest as well as covering it with
the tag. The design's original form — a nonce and a tag computed over the
router's own digest — does not work: an agent whose fleet file differs computes
a *different* tag, so the handshake fails as `unauthenticated`, and the two
failures an operator most needs to tell apart — a wrong key, and a stale fleet
file on one slave — arrive as the same error. Sending the digest and covering it
with the tag keeps both properties: the tag still binds the claim, so a captured
`HELLO` cannot be edited to assert a different fleet, and the agent can compare
a digest it has actually received.

```text
→ HELLO 1 <nonce> <fleet-digest> <hmac>\n
← OK <agent-version> <fleet-digest>\n | ERR <code>\n

→ OBSERVE\n
← OK <length>\n<inventory JSON, at most 256 KiB>

→ ACTIVATE <deployment-id> <lease-id> <deadline-ms>\n
← ACCEPTED <activation-id>\n | ERR <code>\n

→ DEACTIVATE <deployment-id> <lease-id> <drain-ms>\n
← ACCEPTED <activation-id>\n | ERR <code>\n

→ FETCH <artifact-id> <host-id> <deadline-ms>\n
← ACCEPTED <activation-id>\n | ERR <code>\n

→ STATUS <activation-id>\n
← OK <state> <detail-code> <progress-permille>\n

→ CANCEL <activation-id>\n
← OK\n | ERR <code>\n
```

`<fleet-digest>` is the SHA-256 of the canonical fleet configuration both sides derive independently. On mismatch the router issues no mutating verb, marks every orchestrated target ineligible with `fleet_configuration_mismatch`, and audits it. A router and an agent that disagree about what an identifier means must not act on that disagreement.

`ACTIVATE`, `DEACTIVATE` and `FETCH` are **asynchronous and idempotent per `lease-id`**; re-sending returns the same `activation-id`. This is what makes restart recovery tractable (§10.4).

States are a closed vocabulary: `pending`, `draining`, `stopping`, `fetching`, `starting`, `probing`, `ready`, `failed`, `stopped`, `cancelled`.

Inventory JSON is parsed by `wire-json` under explicit `Limits`. **The agent's report is untrusted input.** Unknown identifiers are dropped and counted, never adopted; numeric fields are range-checked; a reply violating a bound fails the whole observation rather than partially updating belief.

### 4.4 Agent obligations

Normative, and testable against the conformance corpus:

- Runs as its own unprivileged user, separate from the router.
- Per-host SSH keys restricted by a forced `command=` in the slave's `authorized_keys`, with `no-pty`, `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding`. The agent's key must not grant an interactive shell.
- Never interpolates a router-supplied value into a command line. Router input selects a row in the agent's own table; it never becomes an argument.
- Applies its own independent per-host activation rate limit. A router bug must not be able to exhaust the fleet through the agent.
- Verifies artifact digests before an artifact becomes activatable, and refuses activation of an unverified artifact.
- Reports memory as observed from the accelerator, not as configured, so the router can detect drift (§6.3).
- Bounds and truncates every reported field.

---

## 5. Fleet domain model

Four entities join spec §5. All administrator-configured; none nameable or influenceable by a client request.

### 5.1 Host

| Field | Meaning |
|---|---|
| `id` | Stable identifier; a bounded metric label. |
| `agent` | Which configured fleet-agent socket manages it. |
| `arch` | `x86_64` or `aarch64`. Filters artifact eligibility. |
| `status` | `enabled`, `drain`, `maintenance`, `disabled`. Mirrors `AdminState` semantics. |
| `reserved_memory_bytes` | Never offered to deployments. On a unified-memory host this is the OS's and other services' share, and must be set generously. |
| `max_concurrent_activations` | Bound on in-flight fleet work per host. Default 1. |

### 5.2 Accelerator

A host has one or more. Placement targets an accelerator, because `node0` has a GT 1030 and a GTX 1080 Ti and only one is useful.

| Field | Meaning |
|---|---|
| `host` | Owning host. |
| `id` | Local index or name as the agent addresses it (`device=1`). |
| `kind` | `cuda`, `unified`, `cpu`. |
| `memory_bytes` | Total. |
| `pool` | Optional. Accelerators sharing a pool draw from one budget. **Unified memory is modelled by giving accelerator and host the same pool**, so a resident model correctly reduces host RAM availability. |

### 5.3 Deployment

The placement of a routable target onto an accelerator, plus lifecycle costs. **At most one deployment per target** (§1.3).

| Field | Meaning |
|---|---|
| `id` | The only token that crosses the agent socket. |
| `target` | The `target` record served. |
| `accelerator` | Where it runs. |
| `artifact` | Weights/image required (§12). |
| `memory_bytes` | Conservative administrator-declared reservation. |
| `start_ms`, `stop_ms`, `drain_ms`, `probe_ms` | Declared lifecycle costs; refined by observation (§8.2). |
| `readiness` | How readiness is confirmed. A TCP connect is not readiness (spec §13). |
| `min_resident_ms` | Dwell floor. **The primary anti-thrash control** (§9.1). |
| `evictable`, `pinned` | Operator anchors (§9.7). |
| `autostart` | Whether routing demand may start it, or only an operator. |

`start_ms` is not a formality: a 20 GB Q5 GGUF with a speculative-decoding sidecar takes minutes to become ready, and every decision below is dominated by that number.

### 5.4 Artifact

| Field | Meaning |
|---|---|
| `id`, `kind` | `image` or `weights`. |
| `digest`, `size_bytes` | SHA-256, content-addressed. Verified before use. |
| `arch` | Must match the host. The Spark is `aarch64`. |
| `source` | Administrator-configured registry or mirror. Never client-supplied. |

One artifact may back several deployments — the vision and non-vision Qwen3.8 targets share weights and differ only in projector loading and declared capability (§1.3).

---

## 6. Fleet state: observation, belief and intent

Four distinct things, never conflated. Conflating them is how orchestrators come to fight their operators.

| | Source | Trust |
|---|---|---|
| **Configuration** | The activated policy snapshot | Authoritative for what *may* exist |
| **Observation** | The agent's `OBSERVE` reply | Untrusted input; the only source of what *is* |
| **Intent** | The router's own leases in durable state | Authoritative for what the router *asked for* |
| **Belief** | Last valid observation plus its age | Advisory, and expires |

### 6.1 Belief expires

Observation runs on a bounded interval (default 5 s) and immediately after any activation reaches a terminal state. If the newest valid observation is older than `observation_max_age_ms` (default 30 s), the router **fails closed**: cold orchestrated targets become ineligible with `fleet_state_stale` and no plan may execute. Warm targets already serving traffic continue under spec §13 as usual.

Acting on stale belief is how a scheduler stops a container something else already restarted, or starts one twice. A stale-state swap is worse than a rejected request, because it costs minutes of fleet time and can cascade.

### 6.2 Divergence is audited, not silently corrected

When observation disagrees with intent the router records `fleet.divergence` with deployment, expected state, observed state and observation age, then re-plans **from observation**. It does not re-assert intent. An operator who stopped a container by hand should not have to fight the router to keep it stopped; the correct response is to route elsewhere and say so.

A deployment observed running that the router did not start is **adopted as resident** for routing but is **not router-owned**: never placed in an eviction set unless `adopt_unmanaged=true`. The default is that the router will use what it finds and will not take it away.

### 6.3 Memory drift

If observed accelerator usage exceeds the declared sum for resident deployments by more than `memory_drift_tolerance` (default 10%), the planner **uses the observed figure**, records `fleet.memory_drift`, and continues. Declared figures may be optimistic; observed figures are what will actually run out. Planning against a declaration the hardware disagrees with produces an activation that OOMs after two minutes of load — the most expensive possible failure.

---

## 7. Routing integration

### 7.1 Residency classification

Each orchestrated surviving-eligibility target is classified against the fleet snapshot into exactly one state:

| Class | Meaning |
|---|---|
| `Resident` | Ready now. |
| `Activating` | Already coming up under an existing lease; ETA known. |
| `ColdFits` | Not resident; free pool memory suffices. |
| `ColdRequiresEviction` | Not resident; requires stopping a computed set. |
| `ColdRequiresFetch` | Artifact absent from the host; acquisition first. |
| `Infeasible(reason)` | Cannot be made ready. |

Only `Infeasible` produces an exclusion. The other five remain candidates, ranked by §7.2. This is the central decision and easy to get wrong: **if "not currently running" excluded a target, no target would ever start.**

New `ExclusionReason` variants, in two groups.

*Capability contract (§3), independent of the fleet:*

| Code | Cause |
|---|---|
| `capability_unsupported` | Target does not declare the alias's verb. |
| `reasoning_effort_unsupported` | Target does not support the requested tier. |
| `quality_floor_not_met` | Target's `quality_class` is below the request's floor. |

*Fleet:*

| Code | Cause |
|---|---|
| `activation_exceeds_deadline` | Effort-adjusted time-to-ready exceeds remaining deadline (§7.3). |
| `activation_budget_exhausted` | Host activation bucket empty (§9.5). |
| `activation_not_permitted` | Principal lacks `fleet.activate`, or deployment is not `autostart`. |
| `artifact_unavailable` | Absent and fetch not permitted, budgeted or feasible. |
| `host_capacity_insufficient` | No admissible eviction set frees enough memory. |
| `fleet_state_stale` | Belief older than `observation_max_age_ms`. |
| `fleet_agent_unavailable` | Agent socket unreachable. |
| `fleet_configuration_mismatch` | Router and agent digests disagree. |
| `deployment_in_dwell` | Would require evicting inside a dwell window (§9.1). |
| `eviction_value_insufficient` | An admissible eviction set exists, but incoming demand does not exceed its summed `retention_value` by `eviction_margin` (§9.2). |

`modality_unsupported` is reused unchanged for documents (§3.3). Every reason appears in the decision trace with no prompt content and is visible in the decision explorer.

### 7.2 The affinity budget

spec §6.3 defines `affinity_term` as "short-lived cache/model warmness or conversation affinity", range `(0, 50_000)`. That is precisely what warmness needs, and the specification anticipated it. No new score term, no change to `MAX_NON_RANK_MAGNITUDE`, and the proven rank-dominance bound is untouched.

Two things now share the term, so the range is **split** rather than contended:

| Contributor | Slice | Values |
|---|---|---|
| **Warmness** | 0 – 40,000 | `Resident` idle 40,000 · `Resident` loaded 32,000 · `Activating` 24,000 · `ColdFits` 16,000 · `ColdRequiresEviction` 8,000 · `ColdRequiresFetch` 0 |
| **Client hint** (§3.6) | 0 – 6,000 | `prefer_target` match 6,000, otherwise 0 |
| **Conversation affinity** | 0 – 4,000 | Reserved; not implemented |

The precedence this produces is the intended one, and each step matters:

- A warm target beats a cold one at equal rank.
- A **hint cannot beat warmth.** The ladder is spaced so every adjacent gap is 8,000, which exceeds the 6,000 hint slice; the spacing is chosen for exactly this reason and a property test asserts it. A client asking for a cold target when a warm equivalent exists gets the warm one.
- A hint **can** break a tie between two equally-warm eligible targets, which is its entire legitimate purpose.
- **Nothing here beats rank.** A cold rank-0 pin still outranks a warm rank-1 target, and the router performs the swap. An operator wanting warmth to dominate expresses that by ranking, not by hoping the arithmetic works out.

### 7.3 Deadlines make cold targets honest

Estimated time-to-ready, adjusted for reasoning effort (§3.4), is compared against the request's remaining deadline before a cold target is offered. A 90-second model load cannot serve a 30-second deadline, and pretending otherwise converts a fast failure into a slow one.

This is the strongest argument for the asynchronous job API (§11): a request *allowed* to wait ten minutes makes a cold, evicting, even fetching target legitimately eligible, and lets the fleet do work that synchronous semantics can only reject.

### 7.4 Ordering within the request pipeline

The spec §3.1 lifecycle gains one step, placed deliberately:

1–3. Unchanged (normalize, authenticate, parse — now including document parts, effort and quality floor).
4. Compute eligible targets — now the full four-axis contract (§3) plus residency classification.
5. Rank deterministically, **reserve admission capacity** using the effort- and document-adjusted estimate (§3.7). Unchanged in ordering: spec Appendix B requires the reservation before outbound I/O.
6. **New — if the chosen candidate is not `Resident`: acquire the host activation lease, execute the plan, await readiness or fail over.**
7–9. Unchanged (adapter, stream, normalize, meter, release *all* reservations and leases exactly once).

Admission is reserved **before** the activation lease, and both release on every path. Evicting a running model and *then* discovering the tenant is over quota is exactly the unforced error Appendix B's ordering exists to prevent.

Activation failure occurs strictly before upstream acceptance, so spec §6.5 failover applies unchanged. No new failover rule is required, and the prohibition on splicing after semantic output is untouched.

---

## 8. The planner

### 8.1 Shape

A pure function in a new `hypellm-fleet` crate, subject to the same rule as `hypellm-core`: no I/O, no secrets, no clock of its own.

```rust
FleetPolicy::plan(
    &FleetSnapshot,      // observation + intent + age, immutable
    &DemandSnapshot,     // EWMA demand and queue depth per capability
    &Target,             // what we want ready
    &PlanContext,        // deadline, effort, principal class, permissions, now_ms
) -> PlanOutcome         // Plan { steps, eta_ms, trace } | Infeasible(reason)
```

Purity buys three operationally significant things: plans are deterministic and property-testable; identical snapshots produce identical plans, which is what Appendix B's determinism invariant requires once fleet state is live state; and `POST /admin/v1/fleet:simulate` can answer "what would you do, and why" with no side effects. Being able to ask a scheduler what it is about to do, before it does it, is the difference between an operable system and a haunted one.

Fleet state reaches routing through the existing `LiveState` trait, extended with **defaulted** methods (`residency_class`, `activation_eta_ms`, `fleet_observation_age_ms`) so every current implementor compiles unchanged — the pattern `admin_override` and `failure_percent` already use. The snapshot is sampled once per decision and never re-read mid-scoring.

### 8.2 Cost model

Integer milliseconds, saturating, no floating point.

```text
time_to_ready = Σ(drain_ms + stop_ms over the eviction set)
              + fetch_ms (if the artifact is absent)
              + start_ms + probe_ms
```

Declared values start it; each is refined by an EWMA over observed durations, clamped to `[declared / 4, declared × 4]` so one anomalous observation cannot make the planner believe a model loads instantly. Observation improves the estimate; it does not overrule the administrator by an order of magnitude.

### 8.3 Eviction set selection

Bounded, deterministic, no combinatorial search.

1. `required_bytes = deployment.memory_bytes − free_bytes_in_pool`. If `≤ 0` the class is `ColdFits`; no eviction.
2. Take resident deployments in the pool and **exclude outright**: `pinned`, `evictable=false`, not router-owned (§6.2), inside `min_resident_ms`, holding in-flight work above `max_drainable_inflight`, or currently activating.
3. Sort the remainder by `retention_value` ascending, tie-broken by deployment id ascending so the order is total and independent of map iteration (Appendix B).
4. Take the smallest prefix summing to `required_bytes`. If the whole list is insufficient return `host_capacity_insufficient`; if the shortfall is caused *only* by dwell exclusions return `deployment_in_dwell` instead — operationally different, and an operator must be able to tell them apart.
5. Apply the hysteresis margin (§9.2). On failure return `eviction_value_insufficient`, with the incoming demand value, the set's summed `retention_value` and the configured margin in the trace. The set was evictable and large enough; it was simply not worth displacing, and the operator's lever is demand or `eviction_margin` rather than waiting for a dwell window to elapse.

The set is capped at `max_eviction_set` (default 2). A plan that stops four models to start one is nearly always a misconfigured fleet rather than a good idea, and the cap turns that into a visible rejection instead of a five-minute outage.

### 8.4 Retention value

What a resident deployment is worth keeping. Integer, saturating, closed inputs, ranges documented in the style of spec §6.3's score terms so the two read as one system:

```text
retention_value = demand_term      // EWMA of requests per minute for its capability
                + queue_term       // requests currently waiting for it
                + recency_term     // decayed time since last served request
                + restore_term     // its own start_ms × its demand — the cost of being wrong
                + operator_term    // administrator weight, plus tenant priority class
                − staleness_term   // long-idle deployments become cheap to evict
```

`restore_term` prevents the obvious failure. Without it the planner happily evicts the model about to be needed again, because it is momentarily idle, then pays its full load cost thirty seconds later. Weighting the *cost of restoring* something by *how likely it is to be wanted* is what makes the planner conservative in the right places.

---

## 9. Anti-thrash governance

The requirement is that the fleet must not swap models continuously. Eight mechanisms, layered, each sufficient against a different failure mode, listed in the order they take effect.

### 9.1 Dwell time — `min_resident_ms`

Once `ready`, a deployment may not be evicted by the planner for `min_resident_ms` (default 300,000 ms). Operators may override; the planner may not.

This is the primary control and the only hard floor. Every other mechanism is an economic argument that adversarial demand can talk into a swap. Dwell time cannot. It alone bounds the worst case: at five minutes, a host swaps at most twelve times an hour whatever demand does. It directly prevents A-evicts-B-evicts-A ping-pong.

### 9.2 Hysteresis margin

Eviction is permitted only when incoming demand value **exceeds** the evicted set's summed `retention_value` by `eviction_margin` (default 25%), not merely equals it. Two capabilities of near-identical value must not trade places on noise. Without a margin a scheduler at equilibrium oscillates by construction.

### 9.3 Demand batching

Requests for a cold capability are held in a bounded per-capability queue rather than each triggering its own evaluation. A swap starts when accumulated demand reaches `activation_min_demand`, or the oldest queued request has waited `activation_max_wait_ms` — whichever comes first, and always before any request's deadline. All queued requests are then served by the one activation.

This converts thrash into throughput. Ten music requests over two minutes should cost one swap, not ten. The queue is bounded, deadline-aware, and shares the spec §12 admission machinery rather than being a new unbounded structure.

### 9.4 Cooldown and flap backoff

After eviction, a deployment may not be re-activated on that accelerator for `reactivation_cooldown_ms` (default 120,000 ms). Repeated activate/evict cycles within `flap_window_ms` accrue an exponentially increasing cooldown capped at `max_flap_cooldown_ms` (default 1 hour), decaying after a quiet period.

Backoff on repeated failure is the reflex spec §13's circuit breaker already applies to unhealthy targets. A flapping deployment is unhealthy in the same operational sense and deserves the same treatment.

### 9.5 Activation budget

A **sliding window** per host on activations per hour (`max_activations_per_hour`, default 12, matching the dwell floor). When exhausted, cold targets on that host become ineligible with `activation_budget_exhausted` rather than queueing indefinitely.

**[as built]** The design said token bucket, and that is wrong for the claim this mechanism makes. A bucket of twelve tokens refilling at twelve an hour permits *twenty-four* activations in the first hour, because it starts full. §15 promises "twelve swaps per host per hour regardless of the attacker's rate", and only a window that counts actual activations in the trailing hour delivers that. The cost is a bounded ring of at most `max_activations_per_hour` timestamps per host, which is one more reason the ceiling is a small number.

This is the hard ceiling that makes the feature safe to enable. Whatever defeats the economic arguments above, the bucket is arithmetic, and the failure mode when it engages is a clean, explained rejection.

### 9.6 Prefer no swap at all

Placement prefers, strictly: `Resident`, then `Activating`, then `ColdFits` on any eligible accelerator, then `ColdRequiresEviction`. Given an alias with targets on two hosts, the planner takes the host with free memory over the one requiring an eviction, even when the latter has the better accelerator. The cheapest swap is the one that does not happen.

### 9.7 Operator anchors

`pinned=true` and `evictable=false` remove a deployment from automatic eviction. The Qwen3.8 chat service every coding harness depends on, and the unrelated production services on `rtx5090`, are configured this way. The planner is not asked to be clever about things the operator has already decided.

### 9.8 Predictive pre-warm — deferred, off by default

Starting a model before it is asked for is genuinely valuable and genuinely capable of doubling the swap rate if the prediction is poor. Deferred to Phase 9, ships disabled, and gated by the same activation budget so a bad predictor cannot exceed the ceiling. Listed here so its absence earlier is a stated decision rather than an oversight.

### 9.9 Making the goal falsifiable

`hypellm_fleet_thrash_ratio` — activations divided by requests served from activated deployments — decides whether any of this works. A healthy fleet trends toward zero as batching amortises each swap. A ratio near 1 means every request costs a swap and the configuration is wrong. Publishing it turns "relatively intelligent about it" from an aspiration into something an operator can check.

---

## 10. Activation lifecycle

### 10.1 State machine

Exhaustive enum; invalid transitions return an internal fault and close safely (spec §18.2):

```text
Planned → LeaseHeld → Draining → Stopping → [Fetching] → Starting → Probing → Ready
                          ↓          ↓           ↓           ↓          ↓
                       Failed ←──────┴───────────┴───────────┴──────────┘
                          ↓
                   RollbackPending → RollbackDone | RollbackFailed
```

Every transition is deadline-bounded. Every terminal state releases the lease exactly once.

### 10.2 Draining is not optional

A deployment being evicted is quiesced — the router stops selecting it — then drained: in-flight requests finish within `drain_ms`. Only if the drain deadline expires *and* `force_stop=true` is configured is it stopped with work in flight, emitting `fleet.forced_stop` naming the affected request count.

Stopping a container mid-stream to serve someone else's request is a decision an operator must opt into explicitly and be able to find afterwards.

### 10.3 Rollback

If activation fails after eviction succeeded, the fleet is worse off than it started: one model stopped, none started. The plan carries a bounded best-effort rollback re-activating the evicted set, subject to the same budgets so a rollback storm cannot itself become the outage. The outcome is audited either way; a failed rollback quarantines the deployment for operator attention.

### 10.4 Leases and crash recovery

An activation lease is a durable record in the `hypellm-store` append-only log, written **before** the mutating verb is sent, carrying deployment, operation, expiry and the requesting decision id.

On restart the router replays leases, queries `STATUS` for each, and reconciles. Because agent verbs are idempotent per lease, re-issuing is safe. Expired leases whose activation cannot be found are released and audited.

Only one router may hold a lease on a host, enforced agent-side: the agent refuses a verb for a deployment leased to a different router instance. This is the conservative posture `ProcessLock` already takes in the store — not distributed consensus, and not claimed as such, but it prevents two routers fighting over one accelerator.

### 10.5 Every lease is released exactly once

The obligation Appendix B places on admission reservations, for the same reason: `Drop` alone is not trusted for accounting. Release happens on success, activation failure, cancellation, client disconnect, deadline expiry, plan abandonment and shutdown. A leaked lease pins a host out of service until expiry — a slow, confusing outage. This gets a conservation property test (§16).

---

## 11. Long-running generative work

Music, video and audio-to-video generation take minutes. One bounded worker thread per connection across 4,096 connections makes holding a socket for six minutes an expensive way to wait, and a cold-start swap in front of it makes it worse.

**New first-party endpoint: `POST /v1/jobs`** — not OpenAI-compatible, because no OpenAI-compatible shape fits, and announced as first-party rather than dressed up as compatibility.

```text
POST   /v1/jobs             → 202 { job_id, state, eta_ms }
GET    /v1/jobs/{id}        → state, progress, eta, error
GET    /v1/jobs/{id}/events → bounded SSE progress stream (wire-sse), resumable
GET    /v1/jobs/{id}/result → streamed artifact bytes, bounded, expiring
DELETE /v1/jobs/{id}        → cancel; releases reservations and any activation lease
```

Where a standard shape exists it is used unchanged: `/v1/audio/speech` and `/v1/images/generations` keep their OpenAI-compatible forms and simply gain orchestrated targets behind them.

Jobs carry `patience_ms` far exceeding an interactive deadline, which is what makes an eviction- or fetch-requiring target legitimately eligible (§7.3). Job records are bounded per tenant and in retention. Results stream through with bounded buffers and are **not** stored beyond a bounded time-limited spool — the router is not becoming a blob store, and spec §2.2's non-goals are not being quietly widened.

---

## 12. Artifact acquisition

"If a model is on no machine, it should be retrieved." This is the highest-risk path in the feature: the one place a request causes the fleet to consume tens or hundreds of gigabytes of disk and hours of bandwidth.

A client cannot name an artifact, a source, or a digest. Controls, all mandatory:

| Control | Rule |
|---|---|
| Permission | `fleet.fetch`, distinct from `fleet.activate`. Not granted by default. |
| Budget | Per-tenant bytes-per-period, enforced through the spec §12 admission machinery. |
| Precondition | Free disk must exceed `size_bytes` plus `fetch_disk_headroom_bytes` before starting. |
| Architecture | `artifact.arch` must match `host.arch`. The Spark is `aarch64`; an x86-64 image will never run there. |
| Verification | The agent verifies digest and size before the artifact is usable; unverified artifacts cannot be activated. |
| Concurrency | One fetch per host; `max_concurrent_fetches` fleet-wide. |
| Resumability | Fetches resume rather than restart. A 40 GB download that restarts on every transient failure never completes. |
| Cancellation | A cancelled job cancels its fetch. |

Placement chooses among architecture-compatible hosts by free disk, accelerator fit, and whether the artifact is already partially present. `cache`, with ~5.9 TB free and no serious accelerator, is the natural artifact cache, and the model should let an operator say so.

---

## 13. Configuration grammar additions

The spec §11.1 line-oriented grammar is extended with new record types and new fields on existing ones. No new syntax: same `type key=value` records, JSON-style quoted strings, `#` comments, unknown fields still errors, still no includes, environment expansion or templates.

```text
fleet_agent id=local socket="/run/hypellm/fleet.sock" \
    observation_interval_ms=5000 observation_max_age_ms=30000

host id=spark agent=local arch=aarch64 status=enabled \
    reserved_memory_bytes=17179869184 max_concurrent_activations=1

accelerator host=spark id=gb10 kind=unified pool=spark-unified \
    memory_bytes=140384485376

deployment id=spark-music3 target=spark:minimax-music3 accelerator=gb10 \
    artifact=minimax-music3-arm64 memory_bytes=64424509440 \
    start_ms=180000 stop_ms=15000 drain_ms=30000 probe_ms=10000 \
    min_resident_ms=600000 evictable=true pinned=false autostart=true \
    readiness=http_ok

artifact id=minimax-music3-arm64 kind=image arch=aarch64 \
    size_bytes=21474836480 digest="sha256:…" source=mirror-local

capability id=text-to-music operations=jobs modalities=text

fleet_policy scope=host:spark max_activations_per_hour=12 \
    eviction_margin_permille=250 max_eviction_set=2 \
    activation_min_demand=1 activation_max_wait_ms=20000 \
    reactivation_cooldown_ms=120000 allow_fetch=false
```

Existing records gain **optional fields only**, so every current configuration stays valid:

| Record | New optional fields |
|---|---|
| `alias` | `capability` |
| `target` | `capabilities`, `quality_class`, `reasoning_efforts`, `effort_multipliers`, `document_token_estimate` |
| `settings` | `fleet_enabled` (default false), `max_documents_per_request`, `max_document_bytes`, `max_inline_document_bytes`, `default_document_token_estimate` |

Slave-hosted providers use `egress=private_network`, which `hypellm-core::netaddr::EgressProfile` already supports and `hypellm-net::egress` already enforces — private destinations are permitted only where an administrator declared the profile, and remain pinned and revalidated.

Validation is off-path and fails closed on: a deployment whose `memory_bytes` exceeds its accelerator's pool; an artifact whose `arch` mismatches its host; a dangling reference; a `fleet_policy` whose budget underflows to zero; two deployments for one target; a capability required by an alias and declared by no target; an `effort_multipliers` entry for a tier absent from `reasoning_efforts`; a document limit set whose base64-encoded aggregate exceeds `max_body_bytes`.

---

## 14. Durable state

New record types in the `hypellm-store` append-only framed log, replayed at startup under existing integrity rules:

- **Activation leases** (§10.4) — written before the mutating verb; the basis of crash recovery.
- **Activation history** — bounded ring per deployment: outcome, duration, reason, decision id. Feeds the EWMA cost model (§8.2) and the "why was this evicted" view.
- **Flap counters** (§9.4) — survive restart, so a router bounce does not reset accrued backoff and permit a fresh burst of thrash.
- **Fetch progress** — resumable across restart.

Demand EWMAs are advisory and are **not** persisted; they rebuild from traffic. Persisting an advisory statistic so it survives a restart is how a scheduler ends up acting confidently on data from before an outage.

---

## 15. Security analysis

Extending spec §10.1. The fleet agent is a genuine expansion of the trusted computing base and is treated as one.

| Threat | Control |
|---|---|
| Prompt or tool argument steers the fleet | Deployments, hosts, artifacts and capabilities are administrator-configured identifiers. Only the resolved alias and its capability contract reach the planner. Prompt and document bytes never do. |
| Malicious document input | The router never parses documents (§3.3). Bytes are opaque, bounded, count-limited, and forwarded to a target that declared the modality. No parser is added to the data plane. |
| Document URL as SSRF vector | A URL-form document is forwarded and **never fetched by the router**, following the rule `ImageSource` already establishes. The provider retrieves it under its own egress policy (spec §10). |
| Reasoning effort as quota bypass | The tier's `output_multiplier` is applied **at reservation**, not after (§3.4). Reserving unmultiplied would let a single JSON field consume several times the held allowance. |
| Reservation starvation via high effort | Reservations are per-principal and refunded on completion through the existing `commit` path; a caller can only starve their own scope. |
| Client hint as destination control | A hint reorders eligible targets within a 6,000-point affinity slice; it cannot create eligibility, beat warmth, or outrank a binding (§3.6, §7.2). |
| Thrash as denial of service | Dwell floor, hysteresis margin, per-host activation bucket, per-principal activation quota, `fleet.activate` permission, and a clean eligibility rejection when exhausted (§9). |
| Storage exhaustion via fetch | `fleet.fetch` permission, per-tenant byte budget, free-disk precondition, size ceiling, digest verification, one fetch per host (§12). |
| Compromised router escalates to slaves | The agent holds its own allowlist. The socket carries opaque identifiers and integers only. A compromised router can reorder declared deployments; it cannot introduce one (§4.2). |
| Compromised agent | The agent is TCB and is stated to be. Own unprivileged user; per-host keys with forced `command=`, no pty, no forwarding; independent rate limits; bounded reports (§4.4). |
| Forged or malicious observation | HMAC-authenticated handshake binding version and fleet digest, `wire-json` under explicit limits, unknown identifiers dropped and counted, numeric fields range-checked, partial updates rejected (§4.3). |
| Replayed fleet verb | The `HELLO` HMAC covers a nonce the agent will not accept twice, so a captured handshake cannot be replayed. Note this is defence in depth: reaching the socket at all already requires the owner's privileges (§4.3). |
| Artifact substitution | Content-addressed digest verified by the agent before use; source administrator-configured; unverified artifacts cannot be activated (§12). |
| Eviction as cross-tenant attack | Tenant priority class enters `retention_value`; a deployment with in-flight work above `max_drainable_inflight` is not evictable; `force_stop` is opt-in and audited (§8.3, §10.2). |
| Capability enumeration across tenants | Capability and deployment visibility is tenant-scoped. A cold-but-declared capability is not revealed to an unauthorized principal, and `GET /v1/models` still reveals only authorized aliases (Appendix B). |
| Fleet topology leakage | Host identifiers, memory figures and residency are management-plane data. Data-plane errors say "capability unavailable"; they never name hosts, accelerators, or what else is loaded. |
| Split-brain between routers | Agent-side lease ownership refuses verbs for a deployment leased elsewhere (§10.4). |

Two abuse cases deserve naming because they are cheap to run and expensive to suffer:

1. **Alternating-capability request storm.** A low-privilege principal alternates two capabilities that cannot coexist on one host. Defence is layered: batching absorbs the first burst, the dwell floor caps swap frequency absolutely, and the activation bucket terminates the pattern with an explained rejection. Worst case with defaults is twelve swaps per host per hour regardless of the attacker's rate.
2. **Fetch amplification.** A principal requests capabilities whose artifacts are absent everywhere, each triggering a large download. Defence: fetch is off by default, separately permissioned, byte-budgeted per tenant, disk-gated per host, and limited to one concurrent fetch per host.

Changes to the agent protocol, the agent client, lease accounting, the eviction path, and the admission estimate for effort and documents require two-person review under the existing rule.

---

## 16. Testing

The bar in `CLAUDE.md` applies: assert the property, make the fixture adversarial, verify the test fails without the fix.

**Capability contract properties** in `hypellm-core`:

- `a_document_request_is_excluded_from_a_target_without_the_document_modality`
- `a_document_url_is_never_dereferenced_by_the_router` — asserted against an egress recorder, not by inspection
- `inline_document_limits_cannot_be_configured_to_exceed_the_body_limit`
- `a_reasoning_effort_reserves_its_multiplied_output_budget`
- `an_unsupported_effort_tier_excludes_rather_than_downgrades`
- `a_quality_floor_excludes_a_lower_tier_target_even_when_it_is_cheaper`
- `a_client_hint_never_makes_an_ineligible_target_eligible`
- `a_client_hint_never_outranks_a_warmer_target_or_a_binding`
- `the_warmth_ladder_spacing_exceeds_the_maximum_hint_bonus` — the arithmetic the previous property depends on

**Fleet properties** in `hypellm-fleet`, seeded, in the style of the 14 existing properties in `hypellm-core/tests/properties.rs`:

- `an_activation_never_evicts_a_deployment_inside_its_dwell_window`
- `a_plan_that_evicts_frees_at_least_the_required_memory`
- `equal_fleet_and_demand_snapshots_produce_equal_plans`
- `no_eviction_occurs_without_the_configured_hysteresis_margin`
- `a_pinned_deployment_never_appears_in_an_eviction_set`
- `the_planner_prefers_a_free_memory_host_over_an_eviction_host`
- `oscillating_demand_converges_below_the_activation_budget` — the anti-thrash property, over many rounds of adversarial alternating demand
- `every_activation_lease_is_released_exactly_once` — the fleet analogue of reservation conservation
- `a_cold_target_beyond_the_effort_adjusted_deadline_is_excluded_not_activated`
- `an_unfetchable_artifact_never_produces_a_plan_that_evicts`

Fixtures must be adversarial to be worth anything: the pin must not also be the cheapest option, the dwell-protected deployment must be the one the planner most wants to evict, and the quality-floor test's high-tier target must be the *expensive* one.

**Fuzz targets** using the seeded deterministic mutator in `hypellm-test-corpus::fuzz` — no `fuzz/` directory and no libFuzzer, per spec §4. Each asserts a property, not absence of panic:

- Agent inventory JSON — no unknown identifier is ever adopted; no numeric field escapes its range.
- Agent protocol replies — no malformed reply advances the activation state machine.
- Fleet configuration records — no accepted configuration permits a deployment exceeding its pool.
- Document content parts — no document part is ever parsed, and none escapes the count or byte bound.
- Plan execution — no interleaving of failures leaks a lease.

**Integration** against the simulated agent (§4.1): full eviction-and-start sequences, drain expiry, rollback, stale observation, divergence adoption, crash-and-recover with outstanding leases. Deterministic clock, no network — `cargo test --workspace --offline` stays honest.

**Security tests**: a prompt or document naming a deployment changes no plan; a principal without `fleet.activate` cannot cause activation by any request path; a principal without `fleet.fetch` cannot cause a byte to be downloaded; agent replies naming unknown deployments are dropped; data-plane errors leak no host identifier; a high-effort request cannot exceed its reserved token budget.

**Resilience**: agent unavailable mid-activation, agent restart mid-activation, host reboot during drain, disk full during fetch, clock skew across lease expiry, two routers contending for one host.

---

## 17. Management API and SPA

New endpoints under `/admin/v1`, following existing conventions — explicit JSON schemas, ETags, `If-Match` on mutation, cursor pagination, stable error codes:

| Method/path | Purpose |
|---|---|
| `GET /admin/v1/fleet` | Hosts, accelerators, deployments, residency, leases, budget remaining, observation age. |
| `PATCH /admin/v1/fleet/deployments/{id}` | Pin, unpin, set evictable, maintenance. ETag-guarded. |
| `POST /admin/v1/fleet/deployments/{id}:activate` | Operator-initiated, audited; bypasses demand thresholds but not dwell or budget. |
| `POST /admin/v1/fleet/deployments/{id}:deactivate` | Operator-initiated, with drain. |
| `POST /admin/v1/fleet:simulate` | Pure planner over a sanitized request descriptor. No side effects. |
| `POST /admin/v1/fleet/artifacts/{id}:fetch` | Operator-initiated acquisition. |
| `GET /admin/v1/fleet/activations` | History with outcome and reason — the "why was this evicted" view. |

SPA screens, first-party only, no `vendor/`, no inline handlers, DOM construction not HTML strings (spec §15):

- **Fleet** — host cards with memory bars, resident sets, activation budget remaining, observation age, drift warnings.
- **Activations** — a timeline of starts and stops, each with its reason code and the decision that caused it.
- **Decision explorer** — extended with the capability contract (which axis excluded each candidate) and the plan (residency class, eviction set, estimated time-to-ready).

Per the honesty rule: when `fleet_enabled=false` or no agent is configured, these screens render an explicit "not available" state. They must never render plausible-looking empty rows that read as a healthy idle fleet.

---

## 18. Telemetry

Closed label vocabularies only. `host_id`, `deployment_id`, `capability` and `effort` are administrator-configured or closed enums and are therefore bounded, so they are admissible labels — unlike user id, request id or prompt, which remain forbidden (spec §17).

| Metric | Purpose |
|---|---|
| `hypellm_fleet_activations_total{host,outcome}` | Swap volume and success rate. |
| `hypellm_fleet_evictions_total{host,reason}` | What is being displaced and why. |
| `hypellm_fleet_time_to_ready_ms{deployment}` | Histogram. Distribution, not average (spec §19.1). |
| `hypellm_fleet_resident_bytes{accelerator}` | Memory pressure. |
| `hypellm_fleet_activation_budget_remaining{host}` | How close the ceiling is. |
| `hypellm_fleet_queue_wait_ms{capability}` | The cost of batching, as experienced. |
| `hypellm_fleet_observation_age_ms{agent}` | Staleness, which gates everything. |
| `hypellm_fleet_thrash_ratio{host}` | **The KPI** (§9.9). |
| `hypellm_requests_by_effort_total{effort,outcome}` | Whether effort tiers are used as expected. |
| `hypellm_token_estimate_error{source}` | Reserved versus reconciled tokens; validates the effort multipliers and document constants. |

Audit events: `fleet.activate`, `fleet.deactivate`, `fleet.evict`, `fleet.forced_stop`, `fleet.rollback`, `fleet.fetch`, `fleet.divergence`, `fleet.memory_drift`, `fleet.lease_expired`, `fleet.configuration_mismatch`. Each names the actor — an operator, or the decision id that caused it — so every model that stops is traceable to a cause.

---

## 19. Performance and bounds

The spec §19 targets are unchanged and must stay so: warm router overhead p50 < 2 ms, p99 < 10 ms. Contract evaluation and planning run on the request path and are budgeted.

| Quantity | Bound |
|---|---|
| Contract evaluation per candidate | O(axes), no allocation. |
| Planning per decision | < 500 µs at p99. Bounded search, no allocation in the common path. |
| Fleet snapshot | Immutable, sampled once per decision, shared by `Arc`. Never re-read mid-scoring. |
| Observation payload | 256 KiB; 64 hosts; 256 accelerators; 512 deployments. |
| Documents per request | `max_documents_per_request`, default 4. |
| Inline document bytes | 4 MiB per part, 8 MiB aggregate decoded; encoded aggregate must fit `max_body_bytes` (16 MiB default). |
| Eviction set | `max_eviction_set`, default 2. |
| Plan steps | 8. |
| Concurrent activations | 1 per host by default; fleet-wide cap. |
| Activation queue | Per capability, bounded, deadline-ordered, on the spec §12 admission machinery. |
| Activation history | Bounded ring per deployment. |

A cold start is not router overhead and must not be reported as one. Benchmarks report activation latency as its own distribution; the spec §19 figures continue to measure the warm path only.

---

## 20. Phased plan

Extending spec §24. Phase 5 has **no fleet dependency at all** and ships value alone; the rest are observation-before-mutation.

| Phase | Scope | Exit |
|---|---|---|
| **5 — Request expressiveness** | Document modality, reasoning effort with multiplied reservation, quality tiers, `prefer_target` wiring, new exclusion reasons, adapter mappings. No fleet code. | A document request routes to the vision target and is refused by the projector-less one; effort multiplies reservations and reconciles; hints reorder but never elevate; the mis-keyed hint fuzz target is repaired and demonstrably fails when the permission gate is removed. |
| **6 — Fleet observation** | Agent protocol and client, inventory model, `hypellm-fleet` types, residency classification, warmness into `affinity_term`, Fleet screen, metrics. **No mutation.** | Observation matches the real five-host fleet across restarts and manual operator changes; routing is unchanged for warm targets. |
| **7 — Single-host orchestration** | Activation and deactivation, leases, drain, rollback, dwell, hysteresis, budgets, cooldown, durable state, audit. One host — the Spark, where the contention is. | Music3 ↔ Qwen3.8 swaps under real demand with a measured thrash ratio below target and no leaked leases across induced failures. |
| **8 — Fleet-wide placement** | Multi-host and multi-accelerator placement, capability routing, batching, `/v1/jobs`, simulation endpoint, decision-explorer integration. | Correct `device=1` selection on `node0`; correct ARM64/x86-64 separation; job semantics under cancellation and disconnect. |
| **9 — Acquisition and prediction** | Artifact fetch with digest verification and budgets; predictive pre-warm, shipped disabled. | Fetch drills including disk-full and interruption; pre-warm demonstrated not to raise the thrash ratio. |

Phases 5 through 8 are built. Phase 9 is partly built — `FETCH` exists, is permissioned, budgeted, disk-gated and digest-verified, and the reference agent implements it without resumability — and predictive pre-warm is not built at all. `POST /v1/jobs`, listed under phase 8, is the one part of that phase that is not: see [current limitations](deferred-issues.md#fleet-orchestration) for why, and for what an operator should do instead.

Phases 5 and 6 are each worth doing alone. Phase 5 fixes a request model that is currently unable to express what callers ask for, with no new trust boundary. Phase 6 gives an accurate read-only picture of what is loaded where, improving routing immediately, with none of the risk of actuation.

---

## 21. Open decisions

Extending spec §25. Each has a recommended default; none should be settled by implementation accident.

| Decision | Recommended default |
|---|---|
| Agent transport | Unix socket on the router host; the agent reaches slaves over SSH. Do not put an agent on each slave in v1 — one TCB component is easier to review than five. |
| Effort tier vocabulary | Four tiers plus `Unset`. Do not accept provider-specific effort strings; map in the adapter. |
| Document handling | Opaque bytes with a configured token constant. Do not extract text in the router, now or later. |
| Quality class semantics | An ordered class, administrator-assigned, exactly like `cost_class`. Do not derive it from quantization strings or model names. |
| Memory model fidelity | Declared reservation refined by observed high-water. Do not attempt per-layer VRAM prediction. |
| Demand signal | EWMA of requests per minute per capability plus queue depth. Never prompt content. |
| Multi-router coordination | Forbid it: one router per host, enforced agent-side. Revisit only with the wider cluster question. |
| Job result storage | Stream through with a bounded expiring spool. Do not become a blob store. |
| Capability vocabulary | Closed enum in the router. Adding one is a code change and a review, not a configuration string. |
| Un-containerised models (MOSS-SoundEffect) | Out of scope for Phases 5–8. Either containerise, or model as a target with no deployment record and manage residency manually. |
| Windows-host actuation | Entirely the agent's concern. The router must never learn that some hosts need `powershell.exe` interop. |

---

## 22. Worked examples

### 22.1 Capability refusal and rerouting

The request that motivated this rework: *Qwen 3.8 at Q5, medium effort, reading a PDF.*

**Configuration.** `alias id=qwen3.8-27b-q5 capability=chat targets=spark:qwen38-q5,rtx5090:qwen38-q5`. The Spark target declares `modalities=text` — its deployment runs without the vision projector, deliberately, to preserve unified-memory headroom. A separate alias `vision-standard` covers `node0:qwen35-9b-vision`, which declares `modalities=text,image,document`.

**Request.** `POST /v1/chat/completions`, `"model": "qwen3.8-27b-q5"`, one text part and one `Document` part, `reasoning_effort: "medium"`.

**Contract evaluation.** Verb `chat`: both targets pass. Modality: the request requires `Document`; neither Qwen3.8 target declares it. Both are excluded with `modality_unsupported`. **No container starts.** The caller receives a 4xx naming the unsupported modality — not a 5xx after a three-minute model load, and not a provider error after admission and metering.

This is the design working. The alternative — starting a model because the caller named it, then failing at the provider — is the failure mode the capability contract exists to prevent.

**If instead the caller had sent `"model": "vision-standard"`:** verb, modality and effort all pass against `node0:qwen35-9b-vision`. Effort `medium` carries `output_multiplier=4`, so admission reserves four times the base output estimate; the document part contributes `document_token_estimate` rather than `bytes / 2`. The reservation is reconciled against provider-reported usage on completion. If that target were cold, its effort-adjusted time-to-ready would be checked against the request deadline before it was offered as a candidate at all.

The operator lesson is worth writing into the runbook: **if you want one alias to serve both, list both targets under it.** `alias id=qwen-any capability=chat targets=spark:qwen38-q5,node0:qwen35-9b-vision` routes text to the big model and documents to the vision model automatically, because modality is a filter and the caller never has to know.

### 22.2 Eviction under memory pressure

The fleet-orchestration path, on real numbers.

**State.** `spark` (~140 GB unified, 17 GB reserved for the host) has `spark-qwen38` (chat, declared 26 GB, resident 40 minutes, dwell satisfied, steady harness demand) and `spark-h3` (audio-to-video, declared 48 GB, resident 6 minutes, idle 5 minutes). `spark-music3` (text-to-music, declared 64 GB) is cold; its artifact is present. Declared figures are the conservative reservations of §5.3 and exceed observed usage, which is why the three do not co-reside under the router's model even though a hand-tuned operator can squeeze them in.

**Request.** A principal with `fleet.activate` submits `POST /v1/jobs`, alias `music-standard`, capability `text-to-music`, `patience_ms=900000`.

**Route.** One target, `spark:minimax-music3`. Free pool memory ~49 GB against 64 GB required, so the class is `ColdRequiresEviction`. Time-to-ready is 30 s drain + 15 s stop + 180 s start + 10 s probe = 235 s, comfortably inside `patience_ms`. Affinity 8,000; it is the only candidate.

**Admission.** Tenant and principal reservations succeed and are held.

**Plan.** `spark-qwen38` is excluded — `pinned`, and independently holding in-flight work. `spark-h3` is still inside its dwell window, 6 minutes resident against a 10-minute `min_resident_ms`, so it is excluded too. No admissible eviction set remains; the plan returns `deployment_in_dwell`.

That is the correct answer at that moment and worth dwelling on: the job is queued with an explicit reason and an ETA rather than the fleet tearing down a model that has been up for six minutes. Four minutes later the queued demand is re-evaluated. `spark-h3` is now past dwell, idle, with a low `retention_value` — no demand, no queue, poor recency — that the incoming demand exceeds by more than the 25% margin.

**Execute.** Lease written durably. `DEACTIVATE spark-h3` with a 30 s drain; no in-flight work, stops in 8 s. Observation confirms ~97 GB free. `ACTIVATE spark-music3`; `starting` → `probing` → `ready` in 174 s. The `host:spark` bucket goes 12 → 11; `spark-h3` enters a 120 s cooldown; `spark-music3` starts a 10-minute dwell.

**Serve.** The job dispatches to the now-warm target. Other music jobs queued during those 174 s are served by the same activation — one swap, several jobs.

**Afterwards.** The audit chain holds `fleet.evict` naming `spark-h3`, its retention value, the margin, and the displacing decision id. `hypellm_fleet_time_to_ready_ms` records 174,000. If an H3 request arrives 30 seconds later it does **not** swap back: music3 is inside its dwell window and H3 inside its cooldown. It waits, or fails with a reason an operator can read.

---

## 23. Invariants

Extending spec Appendix B. The review checklist for any change to this subsystem.

**Capability contract**

- Every axis of the contract is an eligibility filter; none is a score term.
- The router never parses a document, never fetches a document URL, and document bytes never influence routing.
- Inline document limits fit within the endpoint body limit once base64 inflation is applied.
- A reasoning tier's output multiplier is applied at reservation, before outbound I/O.
- A client hint never creates eligibility, never beats warmth, and never outranks a binding. The warmth ladder's minimum adjacent gap exceeds the maximum hint bonus, and the affinity slices sum to no more than the term's range.
- A quality floor and a cost ceiling are independent; neither is derived from the other.

**Fleet**

- The router never executes a process, and no identifier crossing the agent socket originates from a client.
- Warmness is a preference; capability, authorization and residency remain filters. Priority rank still dominates every warmness consideration.
- A deployment inside its dwell window is never evicted by the planner.
- A pinned or non-evictable deployment never appears in an eviction set.
- No eviction occurs without exceeding the configured hysteresis margin.
- An eviction set frees at least the required memory, or the plan is refused.
- Equal fleet, demand and policy snapshots produce equal plans.
- Admission is reserved before an activation lease is acquired; both are released exactly once on every path.
- No plan executes on an observation older than `observation_max_age_ms`.
- Activation failure occurs before upstream acceptance; the no-splice-after-semantic-output rule is untouched.
- The activation budget is a hard ceiling. When exhausted, requests are refused with a reason, never queued indefinitely.
- No artifact is activated before its digest is verified.
- The agent handshake binds the protocol version and the fleet digest, and no nonce is accepted twice.
- Management visibility of fleet topology never exceeds the caller's tenant and permissions, and data-plane errors reveal no host, accelerator or co-resident deployment.
