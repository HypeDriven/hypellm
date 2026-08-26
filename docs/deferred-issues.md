# Current limitations

This page lists limitations that matter when evaluating or operating the current HypeLLM Router release. It intentionally contains only current behavior. Closed issues and superseded designs belong in version control, not in deployment guidance.

## Summary

| Area | Current limitation | Operational response |
|---|---|---|
| Concurrency | One bounded thread is used per accepted connection rather than an event loop. | Size `max_connections × connection_stack_kib`; do not plan around the specification's 20,000-stream target. |
| Process isolation | The process cannot drop privileges, install a sandbox, lock secret pages or scrub its inherited environment. | Start it as an unprivileged user and apply sandboxing, core-dump restrictions and filesystem controls in the service manager or container runtime. |
| Multi-node operation | No state replication, leader election or distributed configuration service is included. | Give every node a separate local state directory. Use `quota_partitions` when independently deployed nodes share traffic. |
| Shutdown | The router has no signal handler. | Use the authenticated control socket through `hypellm-router --shutdown`; configure the supervisor's stop command accordingly. |
| Management authentication | `/admin/v1` accepts a session cookie and nothing else. The `management:read` and `management:write` API-key scopes parse and are stored, but no handler consults them, so a key carrying them has no management access. | Mint keys from an operator session — Google OIDC, or break-glass where no provider is configured. Do not build automation that expects to authenticate to `/admin/v1` with an API key. |
| State lock in a container | The lock file records the process id, which is `1` in a PID namespace and always looks alive. A container killed rather than drained leaves a lock no later start can reclaim. | Stop the router with `--shutdown`. After a kill, delete `<state_dir>/lock` once no router process is running; `just up` does this when no container is up. |
| Streaming | Backpressure is bounded by synchronous flow control but there is no configurable stream high/low watermark. | Monitor `hypellm_stream_backpressure_milliseconds`; slow clients occupy their connection worker until a deadline or write timeout. |
| Token estimation | Admission uses a conservative byte-based estimate rather than the selected model's tokenizer. | Expect some requests near token limits to be rejected conservatively. Provider `/v1/tokenize` support does not feed admission estimates. |
| Routing hints | `prefer_target` now reorders eligible targets, within a bounded slice of the affinity term. It cannot create eligibility, beat a warmer target or outrank a binding. | Express hard preference through aliases and priority bindings; use the hint only to break ties between comparable targets. |
| Long-running generative work | There is no `/v1/jobs` endpoint. Long generations are served through ordinary synchronous requests with a long deadline. | Set a generous `default_deadline_ms` for aliases whose targets take minutes, and expect the client to hold the connection. |
| Predictive pre-warm | The router starts a deployment when demand arrives, never in anticipation of it. | Pin or pre-activate the models a shift depends on rather than relying on prediction. |
| Artifact acquisition | `FETCH` exists and is digest-verified, but the reference agent's implementation restarts rather than resumes an interrupted download. | Pre-place large artifacts out of band; keep `allow_fetch=false` unless a fetch is being supervised. |
| Cleartext to slaves | Plain HTTP is permitted to a private address under `egress=private_network`. Prompts and completions to an orchestrated slave are unencrypted on the operator's own network. | Treat the fleet network as trusted, or terminate TLS in front of each slave and use `scheme=https`. |
| Optional data lifecycle fields | `capture_bodies` and tenant `retention_days` are accepted by the grammar but have no runtime effect. | Do not rely on body capture or automatic retention. Keep capture disabled and apply retention to exported operational data externally. |
| Backups and audit export | Backup and immutable audit shipping are not scheduled automatically. | Quiesce and copy the state directory or use `Store::backup_to`; periodically call the audit export endpoint and store the result immutably. |

## Fleet orchestration

**Specification:** [orchestration.md](orchestration.md) §4–§10, §13, §17–§19. **Implementation:** `crates/hypellm-fleet`, `crates/hypellm-net/src/fleet.rs`, `crates/hypellm-router/src/fleet.rs`, `agent/`.

The router observes a declared fleet, plans against it, and starts and stops declared deployments through an out-of-process agent. What is present: the capability contract, residency classification and warmth ranking, the planner with dwell floors, hysteresis, eviction sets and activation budgets, leases with exactly-once release and crash recovery, the management surface, and the Fleet and Activations screens.

Four parts of the design are deliberately not implemented, and are listed rather than approximated:

- **`POST /v1/jobs` (§11).** Long generations use ordinary synchronous requests with a long deadline. A job API would need a durable job store, resumable progress streams and an expiring result spool; none of that exists, and building it against services that are not yet routable would be building on speculation.
- **Predictive pre-warm (§9.8).** Shipped disabled in the design and absent here. Starting a model before it is asked for is genuinely valuable and genuinely capable of doubling the swap rate when the prediction is poor.
- **Resumable fetches (§12).** The reference agent's `FETCH` runs a pull and verifies the digest afterwards. A 40 GB download that fails partway restarts.
- **Windows-host actuation.** Four of the six machines in the validated fleet are Windows hosts whose SSH lands in WSL. Driving `powershell.exe` interop from there is entirely the agent's concern — the router must never learn that some hosts need it — but the reference agent does not do it.

Two deviations from the design document are worth naming, because both were found by building it:

- **`HELLO` carries the fleet digest as well as covering it.** The design had the router send only a nonce and a tag computed over its own digest. An agent whose fleet file differs computes a different tag, so the handshake fails as `unauthenticated` — collapsing the two failures an operator most needs to tell apart. Sending the digest and covering it with the tag keeps the binding and makes a mismatch diagnosable.
- **The activation budget is a sliding window, not a token bucket.** A bucket of twelve tokens refilling at twelve an hour permits twenty-four activations in the first hour, because it starts full. The safety claim the feature rests on is "twelve swaps per host per hour regardless of the attacker's rate", and only a window that counts actual activations in the trailing hour delivers it.

## Connection model

**Specification:** §2.1, §3.2. **Implementation:** `crates/hypellm-router/src/server.rs` and `startup::listener_config`.

The inference listener accepts at most 4,096 connections by default and the management listener 256. Each accepted connection receives a bounded worker thread. The default stack reservation is 512 KiB and can be configured with `settings connection_stack_kib` from 128 KiB to 8 MiB.

This model is deterministic and bounded, but its memory cost is materially higher than an event loop. The practical connection ceiling is the smaller of `max_connections` and the memory available for worker stacks and per-connection buffers. Load-test the configured product on the deployment image.

## Host hardening is external

**Specification:** §18.1, §20.1. **Implementation:** `crates/hypellm-router/src/hardening.rs` plus deployment policy.

The workspace forbids unsafe Rust and has no platform FFI layer. As a result, operations such as `setuid`, `mlock`, signal registration and in-process seccomp installation are outside the binary.

The router reports detectable missing Linux hardening at startup, including root execution, effective capabilities, enabled core dumps, absent seccomp filtering and absent `no_new_privs`. Reports do not apply those controls. Use the complete systemd example in [deployment.md](deployment.md#shutdown) and confirm startup emits no unexpected `startup.hardening_missing` events.

## Independent nodes are not a cluster

**Specification:** §11.2, §12, §20. **Implementation:** `hypellm-store::ProcessLock` and `settings quota_partitions`.

Several router instances may serve the same upstream providers if each has its own state and secret directories. `settings quota_partitions=N` conservatively divides configured quotas so N independently deployed nodes do not multiply a tenant's aggregate allowance.

This does not synchronize API keys, sessions, audit chains, policy activation, decision traces or health state. Never point two running processes at one state directory; the PID-file lock is not a distributed lock and is unsuitable for shared or network filesystems.

## The state lock records a namespaced process id

**Specification:** §11.2. **Implementation:** `hypellm-store::ProcessLock` (`crates/hypellm-store/src/durable.rs`).

The single-writer lock is a PID file: `acquire` writes `std::process::id()`, and a later start reclaims the lock only if `/proc/<pid>` is gone. Both halves are relative to the caller's PID namespace, and inside a container the router is pid 1.

The consequence is specific to containers. A router that exits through `--shutdown` removes its lock and nothing is left behind. A router whose container is killed — `docker kill`, a `docker compose down` that reaches its grace period, an OOM kill — leaves a lock file containing `1`. The next container reads it, asks whether pid 1 is alive, finds itself, and refuses to start with `the state directory is locked by a running process (pid 1)`. The refusal is permanent until the file is deleted, and it is indistinguishable from the case the lock exists to prevent.

Deleting `<state_dir>/lock` when no router is running is safe and is what the reclaim path would have done. `just up` does it as a preflight, having first established that no router container exists.

`flock` would be namespace-independent and would release on process death, and it is not used: it needs `unsafe` FFI, which §18.2 forbids workspace-wide. See also [independent nodes are not a cluster](#independent-nodes-are-not-a-cluster).

## Graceful shutdown uses the control socket

**Specification:** §20.1. **Implementation:** `crates/hypellm-router/src/main.rs` and `server.rs`.

The router deliberately does not handle `SIGTERM`. A supervisor that sends only a signal will terminate in-flight streams. Configure its stop action to run:

```bash
hypellm-router --shutdown \
  --config /etc/hypellm/hypellm.conf \
  --secrets /etc/hypellm/secrets
```

The command authenticates to the owner-only control socket with `control.key`, stops new admission and waits for the bounded drain period.

## Streaming backpressure

**Specification:** §3.2, §14. **Implementation:** `crates/hypellm-router/src/dispatch.rs`.

Provider reads and client writes are synchronously coupled. If a client stops reading, its worker stops consuming the provider stream, which supplies backpressure without an additional unbounded queue. There is consequently no intermediate buffer on which configurable watermarks could operate.

Use request deadlines, write timeouts and the backpressure metric to detect slow consumers. Raising the connection cap does not make an individual stalled stream cheaper.

## The `prefer_target` routing hint has no effect

**Specification:** §5.1. **Implementation:** `hypellm_core::canonical::RoutingHints` and `crates/hypellm-router/src/protocol/openai.rs`.

`hypellm_routing.prefer_target` is parsed from the request body, validated as a target identifier, and correctly dropped unless the principal is permitted to supply hints. It is then never read by `PolicySnapshot::route`, which consults only `require_local`. The field's documentation comment states that it prefers the named target when that target is already eligible; no such preference is applied.

The behaviour fails safe — an unhonoured hint cannot influence a destination — so this is a functionality gap rather than a security one. Callers that send the hint receive ordinary policy-ranked selection.

## Conservative token estimation

**Specification:** §12, §25. **Implementation:** `hypellm_core::canonical::estimated_input_tokens`.

Pre-admission token estimates use `ceil(input bytes / 2)` plus per-message overhead. This intentionally errs toward over-counting. Configured price schedules and provider-reported usage are available for cost views, but the selected target's tokenizer is not consulted during admission.

## Data lifecycle and external operations

**Specification:** §10, §11.2, §17. **Implementation:** configuration schema, `Store::backup_to`, and `GET /admin/v1/audit/export`.

Prompt and completion bodies are not captured. The `capture_bodies` setting must not be interpreted as enabling capture. Tenant `retention_days` does not delete state, audit, usage or exported logs.

The router produces authenticated audit checkpoints and exposes a durable audit export endpoint, but does not push exports to remote storage. Likewise, the store supports bounded backup as a library operation but the binary has no backup scheduler or backup CLI. Deployments must provide these workflows and their retention policy.

## Security boundaries worth understanding

These are design boundaries rather than defects, but they affect deployment:

- Inbound TLS is supplied by a trusted edge; outbound TLS and OIDC signature verification are supplied by local platform helpers.
- Possession of the secrets directory defeats keyed store-integrity and authentication controls. Protect it separately from state.
- The TLS helper and OIDC verifier are part of the trusted computing base. The reference verifier in `verifier/` holds the OAuth client secret and decides which identity tokens are authentic; review it as such.
- Availability against an attacker capable of filling the configured connection cap is bounded, not guaranteed.
- API and module changes involving auth, parsers, credential handling, policy activation or storage integrity require two-person review.
