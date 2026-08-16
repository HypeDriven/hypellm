# Current limitations

This page lists limitations that matter when evaluating or operating the current HypeLLM Router release. It intentionally contains only current behavior. Closed issues and superseded designs belong in version control, not in deployment guidance.

## Summary

| Area | Current limitation | Operational response |
|---|---|---|
| Concurrency | One bounded thread is used per accepted connection rather than an event loop. | Size `max_connections × connection_stack_kib`; do not plan around the specification's 20,000-stream target. |
| Process isolation | The process cannot drop privileges, install a sandbox, lock secret pages or scrub its inherited environment. | Start it as an unprivileged user and apply sandboxing, core-dump restrictions and filesystem controls in the service manager or container runtime. |
| Multi-node operation | No state replication, leader election or distributed configuration service is included. | Give every node a separate local state directory. Use `quota_partitions` when independently deployed nodes share traffic. |
| Shutdown | The router has no signal handler. | Use the authenticated control socket through `hypellm-router --shutdown`; configure the supervisor's stop command accordingly. |
| Streaming | Backpressure is bounded by synchronous flow control but there is no configurable stream high/low watermark. | Monitor `hypellm_stream_backpressure_milliseconds`; slow clients occupy their connection worker until a deadline or write timeout. |
| Token estimation | Admission uses a conservative byte-based estimate rather than the selected model's tokenizer. | Expect some requests near token limits to be rejected conservatively. Provider `/v1/tokenize` support does not feed admission estimates. |
| Optional data lifecycle fields | `capture_bodies` and tenant `retention_days` are accepted by the grammar but have no runtime effect. | Do not rely on body capture or automatic retention. Keep capture disabled and apply retention to exported operational data externally. |
| Backups and audit export | Backup and immutable audit shipping are not scheduled automatically. | Quiesce and copy the state directory or use `Store::backup_to`; periodically call the audit export endpoint and store the result immutably. |

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
- The TLS helper and OIDC verifier are part of the trusted computing base.
- Availability against an attacker capable of filling the configured connection cap is bounded, not guaranteed.
- API and module changes involving auth, parsers, credential handling, policy activation or storage integrity require two-person review.
