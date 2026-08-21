# Module: hypellm-fleet

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Platform (primary), Security (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library plus workspace path dependencies: `hypellm-core`, `hypellm-crypto`, `wire-json`; `hypellm-test-corpus` for tests only. |
| Fuzz targets | Eight, in `tests/fuzz.rs`, over three surfaces. See [Fuzz targets](#fuzz-targets). |

## Why this crate exists

It is one of the six crates not named in specification 18.1's list. HypeLLM
routes a request to a target that is *already running*; this crate is what makes
"already running" a decision rather than an assumption.

It could not live in `hypellm-core`. Core is the routing policy: it answers
"which of these targets should serve this request". This answers a different
question — "what must the fleet become in order to serve it" — against a
different snapshot, on a different lifecycle, with its own governance state.
Merging them would put eviction economics and dwell timers inside the crate whose
whole claim is that routing is a pure function of policy and live state.

It also could not live in the router binary. The planner has to be callable from
`POST /admin/v1/fleet:simulate` with no side effects, and from the request path
with them, and a planner that lived beside the socket that executes it would
eventually acquire a shortcut to it.

## Scope

| Concern | Module | Specification |
|---|---|---|
| Hosts, accelerators, deployments, artifacts, governance limits | `model` | extension 5, 13 |
| Observation, belief, intent, inventory parsing | `state` | extension 6 |
| Demand rate, queue depth, idleness | `demand` | extension 8.4, 21 |
| The planner: classification, eviction sets, cost model | `plan` | extension 7, 8 |
| Dwell, hysteresis, batching, cooldown, budgets | `governance` | extension 9 |
| The activation state machine and lease accounting | `activation` | extension 10 |
| The agent wire protocol, as a codec | `protocol` | extension 4.3 |

### What this module deliberately does not do

- **No I/O of any kind.** No socket, no file, no process, no clock. Callers pass
  the time in, exactly as they do for `hypellm_core::admission`. The socket that
  carries a plan to an agent is `hypellm_net::fleet`; the process that acts on it
  is not in this repository's build at all.
- **No process execution.** Specification 4.1 forbids it and `depscan`'s
  `forbidden-api` rule fails the build on `process::Command`. Actuation happens
  out of process, across a narrow authenticated local socket, in the same shape
  specification 4 uses for TLS and 9.1 for JWT verification.
- **No secrets.** No type here holds `fleet.key`. `protocol::hello_hmac` takes the
  key as a parameter and returns a tag; the key itself is read and held by the
  router's startup path, and the client in `hypellm-net` borrows it for the
  length of one handshake.
- **No routing decisions.** Nothing here ranks targets, resolves an alias, or
  reads a request. `plan::plan` takes a `TargetId` that routing has already
  chosen to consider.
- **No prompt, message, document, or tool argument.** There is no function in the
  public surface that accepts one. This is the structural form of the invariant
  that prompts are inert: a plan cannot be influenced by content the crate has no
  way to receive.
- **No container orchestration.** No replica abstraction, no scheduling of
  non-inference workloads, no image building, no service discovery, no cluster
  networking. The router observes and toggles a closed, administrator-declared
  set, and nothing else.

## Threat notes

- **The agent's report is untrusted input.** `state::parse_inventory` runs
  `wire-json` under `inventory_limits()`, drops every identifier the
  configuration does not declare (counting them in
  `Inventory::unknown_identifiers`), range-checks every numeric field, and fails
  the *whole* observation on any violation rather than partially updating belief.
  A half-applied observation is worse than none, because the router would then
  plan against a mixture of two moments. The property this buys is precise: a
  compromised agent can withhold information, and can lie about a deployment the
  router already knows about — which the divergence and drift rules cover — but
  it cannot introduce a host, accelerator, deployment, or artifact.
- **A compromised router must not reach a slave.** Only identifiers and bounded
  integers cross the socket (`protocol::encode_request`). The identifier alphabet
  in `hypellm_core::ids` excludes whitespace and control characters, so no
  component can introduce a field or a line — there is no escaping to get wrong.
  The agent resolves each identifier against its own allowlist, which the router
  cannot extend.
- **A hostile agent's strings.** The agent is trusted to actuate, not to author
  text the router will store and echo into an operator's browser.
  `protocol::sanitize_token` truncates to 64 characters and maps everything
  outside `[A-Za-z0-9_.-]` to `_`, closing terminal-escape, newline, and quote
  injection — the same treatment `hypellm_net::helper::sanitize_code` gives the
  TLS helper. `ActivationRecord::detail` is `&'static str` for the same reason:
  the type makes an agent-supplied detail unstorable.
- **Replay.** The `HELLO` tag covers version, nonce, and fleet digest as separate
  HMAC parts, so a captured handshake cannot be replayed and a nonce ending in
  digits cannot be read as part of a version. This is defence in depth — reaching
  an owner-only socket already requires the owner's privileges.
- **Thrash as denial of service.** Five layers, in the order they engage:
  batching absorbs a burst (`ActivationQueue`), the dwell floor caps swap
  frequency absolutely (`plan::select_eviction_set`), the hysteresis margin stops
  oscillation between near-equal capabilities, cooldown and flap backoff punish
  repetition (`FlapCounter`), and the activation budget terminates the pattern
  with an explained rejection (`Budgets`). The budget is a **sliding window**
  rather than a token bucket, deliberately: a bucket that starts full permits
  twice its hourly rate in the first hour, and the safety claim this feature
  rests on is "twelve swaps per host per hour regardless of the attacker's rate".
- **Eviction as a cross-tenant attack.** Tenant priority enters as
  `PlanContext::priority_bonus`, clamped like every other term. A deployment
  with in-flight work above `max_drainable_inflight` is not evictable, a pinned
  or non-evictable one never enters a candidate set, and `force_stop` is opt-in
  and audited by the caller.
- **Storage exhaustion via fetch.** `plan::plan` refuses a fetch unless the
  host's policy allows it *and* the principal holds the separate permission
  *and* free disk exceeds size plus headroom *and* the architecture matches.
  Fetch is off by default.
- **Stale belief.** Acting on it is how a scheduler stops a container something
  else already restarted. `FleetSnapshot::belief_is_fresh` gates every plan, and
  `observation_age_ms` returns `None` — not zero — when no observation has ever
  succeeded, so a router that has never reached its agent cannot read as healthy.
- **Leaked leases.** A leaked lease pins a host out of service until expiry: a
  slow, confusing outage that looks like a capacity problem.
  `ActivationLedger::release` returns `LeaseRelease::AlreadyReleased` rather than
  releasing twice, because a double release would return a slot a *different*
  activation now holds. `accounting()` exposes the two counters so the
  conservation property is checked against something other than the map the code
  maintains.
- **Poisoned locks.** Every `RwLock` here fails in the direction that cannot
  cause fleet work: budgets refuse, flap counters return the plain cooldown, and
  demand drops a sample. The one exception is `ActivationQueue::admit`, which
  fails toward activating — the budget and dwell floor still bound what can
  happen, and a lock failure that silently stalled every cold request would be an
  outage with no explanation.

## Limits

Enforced within this crate:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Inventory payload | 256 KiB | `state::MAX_INVENTORY_BYTES`, checked against the declared length before allocation |
| Inventory hosts / accelerators / deployments / artifacts | 64 / 256 / 512 / 1024 | `state::MAX_INVENTORY_*` |
| Inventory JSON depth / string / input | `Limits::SMALL` with a raised input bound | `state::inventory_limits` |
| Agent status line | 512 bytes | `protocol::MAX_LINE` |
| Agent-supplied token | 64 chars, `[A-Za-z0-9_.-]` | `protocol::sanitize_token` |
| Status progress | 0–1000 permille | `protocol::parse_reply` |
| Plan steps | 8 | `plan::MAX_PLAN_STEPS` |
| Eviction set | `max_eviction_set`, default 2 | `plan::select_eviction_set` |
| Activations per host per hour | `max_activations_per_hour`, default 12 | `governance::Budgets`, sliding window |
| Activation window entries per host | 256 | `governance::MAX_WINDOW_ENTRIES` |
| Queued requests per capability | 256 | `governance::MAX_QUEUED_PER_CAPABILITY` |
| Flap backoff | `max_flap_cooldown_ms`, default 1 hour | `governance::FlapCounter` |
| Retained activation history | 256 records | `activation::MAX_HISTORY` |
| Concurrent activations per host | `max_concurrent_activations`, default 1 | `activation::ActivationLedger::acquire` |
| Observation-derived timing adjustment | ×¼ to ×4 of the declared figure | `state::TIMING_CLAMP_FACTOR` |
| Score and value terms | Documented ranges, saturating | `plan::*_TERM_RANGE` |

Applied by this crate but defined elsewhere:

| Input | Limit | Source |
|---|---|---|
| Identifier length and alphabet | 128 bytes, `[A-Za-z0-9._:-]` | `hypellm_core::ids` |
| Warmness contribution to the score | 40,000 of the affinity term | `hypellm_core::decision::ScoreTerms::WARMTH_SLICE` |

Not enforced — stated so the gap is not mistaken for a control:

- **Socket deadlines and reply sizes on the wire.** This crate is a codec; the
  deadline, the read bound, and the connection lifetime belong to
  `hypellm_net::fleet`.
- **Durability.** Leases and flap counters are held in memory here. Writing them
  to the append-only log before the mutating verb is the router's job, and the
  crash-recovery property depends on the router doing it.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer — specification 4 admits
no such dependency. Fuzzing is a seeded, deterministic mutation engine in
`hypellm-test-corpus::fuzz`, driven from an ordinary `tests/fuzz.rs` so that
`cargo test` runs it and a failing seed is reproducible by number.

Each target asserts a property, not the absence of a panic:

| Target | Surface | Property asserted |
|---|---|---|
| `agent_inventory_never_adopts_an_undeclared_identifier` | Mutated inventory payloads through `state::parse_inventory` | No identifier absent from the configuration is ever adopted, and no numeric field escapes its range |
| `an_inventory_that_is_refused_leaves_nothing_behind` | The same, on the failure path | A refusal carries a stable code and yields no partial inventory |
| `an_oversized_inventory_is_refused_before_it_is_parsed` | A payload past the byte bound | The bound is checked before anything is allocated |
| `no_malformed_agent_reply_advances_the_activation_state_machine` | Mutated reply lines against a live `ActivationLedger` | Parsing a reply never moves the machine; sanitised tokens stay inside the identifier alphabet; declared lengths and progress stay in range |
| `a_reply_is_never_parsed_against_a_verb_that_did_not_provoke_it` | Every reply against every verb | `OK 4096` is an inventory length after `OBSERVE` and nonsense elsewhere |
| `a_sanitised_token_never_escapes_the_identifier_alphabet` | Mutated tokens through `protocol::sanitize_token` | Length and alphabet hold for every input |
| `an_over_long_reply_line_is_refused_rather_than_read` | A line past `MAX_LINE` | Refused |
| `no_interleaving_of_lease_operations_leaks_a_lease` | Arbitrary interleavings of acquire, release, expiry, and spurious release against `ActivationLedger` | Acquisitions equal releases plus live leases; slots never diverge from live leases; a refused release returns no slot |

The property layer lives in `tests/properties.rs`, in the style of the fourteen
properties in `hypellm-core/tests/properties.rs`: twelve seeded properties over
extension 23's invariant list, each across many generated fleets. The capability
contract's own properties are in `hypellm-core/tests/capability.rs`, and the
end-to-end activation path is exercised in `hypellm-router/tests/fleet.rs`
against a conformant simulated agent on a real socket.

## Public API

See `lib.rs`. The surface is the domain model (`FleetConfig` and its records),
the snapshot (`FleetSnapshot`, `Inventory`, `Lease`), the planner (`plan`,
`Plan`, `PlanOutcome`, `PlanContext`, `retention_value`), the governance state
(`Budgets`, `FlapCounter`, `ActivationQueue`), the activation machine
(`ActivationLedger`, `ActivationState`, `ActivationRecord`), and the protocol
codec (`AgentRequest`, `AgentReply`, `encode_request`, `parse_reply`).

The narrowness is the point. There is no function that takes a request, a
prompt, a URL, a host address, a file path, or a command; no function that opens
anything; and no way to construct an `AgentRequest` naming a deployment the
caller did not already hold an identifier for. Widening any of those requires
two-person security review under 21.1, as do changes to the agent protocol, the
lease accounting, and the eviction path.
