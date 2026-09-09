# Current limitations

This page lists limitations that matter when evaluating or operating the current HypeLLM Router release. It intentionally contains only current behavior. Closed issues and superseded designs belong in version control, not in deployment guidance.

## Summary

| Area | Current limitation | Operational response |
|---|---|---|
| Concurrency | One bounded thread is used per accepted connection rather than an event loop. | Size `max_connections × connection_stack_kib`; do not plan around the specification's 20,000-stream target. |
| Process isolation | The process cannot drop privileges, install a sandbox, lock secret pages or scrub its inherited environment. | Start it as an unprivileged user and apply sandboxing, core-dump restrictions and filesystem controls in the service manager or container runtime. |
| Multi-node operation | Independent nodes by design, not by omission: §25 settles state distribution as "single-writer versioned bundles; do not build consensus in v1". There is no replication, leader election or distributed configuration service, and there will not be one in v1. | Give every node its own state and secrets directory. Distribute policy by exporting `GET /admin/v1/policies/active` from the writer and confirming each node's `--check` prints the same digest. Use `quota_partitions` so independently deployed nodes do not multiply a tenant's allowance. |
| Shutdown | The router has no signal handler and cannot have one: `sigaction` and `signalfd` both need `unsafe` FFI, which §18.2 forbids workspace-wide. Signals are handled *outside* it, by `supervisor/hypellm-init`. | Nothing, in the shipped container: the init is PID 1 and turns `SIGTERM` into `--shutdown`. Elsewhere, use the systemd unit's `ExecStop`, or run the init. Whatever you use, its grace period must exceed the init's 40-second drain deadline, which must exceed the listener's 30-second drain. |
| Management audit granularity | A key-authenticated management action is audited against its **principal**, as a session's actions are. The key identifier appears once — a `login` record the first time each key is used after a restart — and not on each action. | Give each automation its own principal, so the audit trail distinguishes them. Two keys sharing a principal are indistinguishable in the management audit. |
| Local password sign-in | `local_user` accounts are a deviation from the specification's four authentication methods. An unknown username is refused faster than a known one with a wrong password, which is a username oracle. | Use it to operate a deployment before an identity provider is configured, not as the steady state. Keep the management listener off untrusted networks and move to `identity` records once OIDC works. |
| Streaming | Backpressure is bounded by synchronous flow control but there is no configurable stream high/low watermark. | Monitor `hypellm_stream_backpressure_milliseconds`; slow clients occupy their connection worker until a deadline or write timeout. |
| Token estimation | Admission uses a byte-based estimate at a per-target `bytes_per_token`, not the model's tokenizer. The router never adjusts it from observed traffic. | Read `hypellm_token_estimate_error{target}`, then declare the ratio you measured with `target … bytes_per_token=N`. Leaving it undeclared reserves at 2 bytes per token, which holds some requests that would have fitted. |
| Routing hints | `prefer_target` now reorders eligible targets, within a bounded slice of the affinity term. It cannot create eligibility, beat a warmer target or outrank a binding. | Express hard preference through aliases and priority bindings; use the hint only to break ties between comparable targets. |
| Long-running generative work | `/v1/jobs` exists and is **off by default**. Jobs live in the router's memory, so a restart loses them and their results. | Enable it with `settings job_workers=N`. Treat a job identifier as valid only for this router's lifetime; a client that must survive a restart should resubmit rather than poll. |
| Predictive pre-warm | Implemented and **off by default**. The prediction is deliberately dull — a capability's smoothed rate — and it never evicts. | Turn it on per host with `fleet_policy … prewarm_min_rate_per_minute=N`, then watch `hypellm_fleet_thrash_ratio`. If it rises, the number is wrong for that fleet. |
| Artifact acquisition | `FETCH` is digest-verified and retries within the router's deadline, but resumption is at layer granularity: an interrupted layer is re-fetched, so an artifact published as one enormous layer restarts. | Prefer multi-layer artifacts. Keep `allow_fetch=false` unless a fetch is being supervised — the control is the permission, not the retry. |
| Cleartext to slaves | Plain HTTP is permitted to a private address under `egress=private_network`. Prompts and completions to an orchestrated slave are unencrypted on the operator's own network. | Treat the fleet network as trusted, or terminate TLS in front of each slave and use `scheme=https`. |
| Data lifecycle | There is no body capture: `capture_bodies=true` refuses to load. Tenant `retention_days` is a declaration the router records and never acts on. | Apply retention to exported operational data externally. Read `retention_days` from the configuration or the Settings screen as the deployment's stated intent, and enforce it with your own tooling. |
| Backups and audit export | `hypellm-router --backup` takes an exact copy on demand, but nothing schedules it, and audit export is not shipped anywhere. | Run `--backup` from the deployment's existing backup schedule; periodically call the audit export endpoint and store the result immutably. |

## Fleet orchestration

**Specification:** [orchestration.md](orchestration.md) §4–§10, §13, §17–§19. **Implementation:** `crates/hypellm-fleet`, `crates/hypellm-net/src/fleet.rs`, `crates/hypellm-router/src/fleet.rs`, `agent/`.

The router observes a declared fleet, plans against it, and starts and stops declared deployments through an out-of-process agent. What is present: the capability contract, residency classification and warmth ranking, the planner with dwell floors, hysteresis, eviction sets and activation budgets, leases with exactly-once release and crash recovery, the management surface, and the Fleet and Activations screens.

Two parts of the design are deliberately not implemented, and are listed rather than approximated:

- **Byte-level resumable fetches (§12).** The reference agent retries a failed pull within the router's deadline, and `docker pull` skips layers already in the host's content store, so an attempt resumes from what the last one finished. A layer interrupted mid-transfer is re-fetched. An artifact published as a single 40 GB layer therefore restarts, which is a property of how it was built rather than of the agent — but §12's sentence is about bytes, and this delivers it about layers.
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

## Independent nodes are not a cluster, and that is the decision

**Specification:** §11.2, §12, §20, and §25's open decision. **Implementation:** `hypellm-store::ProcessLock`, `settings quota_partitions`, and `GET /admin/v1/policies/active`.

This is the one entry here that is a *settled decision* rather than unfinished work. Specification §25 records the recommended default as "single-writer versioned bundles; do not build consensus in v1", and the implementation follows it: there is no replication, no leader election, and no distributed configuration service, and adding one would contradict a recorded architecture decision rather than complete an omission. §24's phase 4 is where signed config distribution belongs, if a deployment ever needs it.

What the single-writer bundle workflow looks like in practice: one node is the writer, where drafts are created, reviewed and published. `GET /admin/v1/policies/active` (permission `EditPolicy`) returns that node's canonical configuration text with its version and digest. An operator writes those bytes to a second node's configuration file and runs `hypellm-router --check`, which prints a digest; matching digests mean the two routers run the same policy, and it is checkable rather than asserted. Nothing is pushed, nothing elects anything, and the operator stays the single writer.

Several router instances may serve the same upstream providers if each has its own state and secret directories. `settings quota_partitions=N` conservatively divides configured quotas so N independently deployed nodes do not multiply a tenant's aggregate allowance.

This does not synchronize API keys, sessions, audit chains, policy activation, decision traces or health state. Never point two running processes at one state directory: the lock file records the holder's boot id, pid and process start time and reclaims correctly on one machine, but both of those are local facts — it is not a distributed lock and is unsuitable for shared or network filesystems.

## Graceful shutdown uses the control socket

**Specification:** §20.1. **Implementation:** `crates/hypellm-router/src/main.rs` and `server.rs`.

The router does not handle `SIGTERM`, and this is a language-level constraint rather than a choice deferred: `sigaction` and `signalfd` both require `unsafe` FFI, which §18.2 forbids workspace-wide, and there is no safe-Rust signal API. The control socket is the dependency-free equivalent.

**Signals are handled outside the router**, by [`supervisor/hypellm-init`](../supervisor/README.md) — the same shape as the TLS helper, the identity verifier and the fleet agent, each of which exists because §4 or §18.2 puts something outside the binary. The init is PID 1 in the shipped image, runs the router as its child, and turns `SIGTERM` into `hypellm-router --shutdown`. So `docker stop`, `docker compose down` and `kubectl delete pod` all drain. This matters more in a container than anywhere else: a container's PID 1 receives no default signal actions from the kernel, so a router running as PID 1 does not merely fail to drain — it ignores the signal entirely until the grace period expires and `SIGKILL` arrives.

A supervisor that sends only a signal to the *router itself*, with no init in front of it, will still terminate in-flight streams. Use `ExecStop`, or run the init.

Three numbers have to be ordered wherever this is configured, each exceeding the one before: the inference listener's `drain_timeout` (30 s), the init's `HYPELLM_DRAIN_DEADLINE` (40 s), and the supervisor's grace period (`compose.yaml` sets 45 s). Getting the order wrong reintroduces the dropped streams the chain exists to prevent, silently.

For `systemd`, `ExecStop` is more direct than an init. Configure the stop action to run:

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

## The `prefer_target` routing hint is a tie-break, not a destination

**Specification:** §5.1. **Implementation:** `hypellm_core::policy::PolicySnapshot::score` and `crates/hypellm-router/src/protocol/openai.rs`.

`hypellm_routing.prefer_target` is honoured, within deliberately narrow limits. It is parsed from the request body, validated as a target identifier, dropped unless the principal is permitted to supply hints, and then added as `ScoreTerms::HINT_SLICE` to the affinity term of the named target — read only after every eligibility filter has already passed.

What that means for a caller: the hint can break a tie between two comparable targets, and can do nothing else. It cannot make an ineligible target eligible, cannot outrank a warmer target — the warmth ladder's step exceeds the whole hint slice — and cannot outrank a priority binding, whose rank term is two orders of magnitude larger. An unknown or ineligible `prefer_target` is ignored rather than refused, so a harness that always sends one keeps working.

This bound is the reason the hint is admissible at all. A hint that could beat policy would be a client-controlled destination by a longer route, which Appendix B forbids.

## Jobs are in memory, and a restart loses them

**Specification:** [orchestration.md](orchestration.md) §11. **Implementation:** `crates/hypellm-router/src/jobs.rs` and the `/v1/jobs` routes.

`POST /v1/jobs` accepts a chat-shaped body, returns `202` with a job identifier, and releases the connection. `GET /v1/jobs/{id}` reports state, `GET /v1/jobs/{id}/events` streams state changes as SSE, `GET /v1/jobs/{id}/result` returns the completed response, and `DELETE /v1/jobs/{id}` cancels. `GET /v1/jobs` lists the caller's tenant's jobs.

It is **off unless `settings job_workers` is greater than zero**, and answers `404` otherwise: a job endpoint that accepted work with no worker to run it would report `queued` forever.

Everything a caller can grow is bounded, because a job endpoint is four §3.2 hazards at once:

| Quantity | Setting | Default |
|---|---|---|
| Worker threads, fixed at startup | `job_workers` | 0 (off) |
| Live plus retained jobs per tenant | `max_jobs_per_tenant` | 32 |
| Jobs waiting for a worker | `max_queued_jobs` | 64 |
| Result bytes held per job | `max_job_result_bytes` | 8 MiB |
| How long a finished job stays readable | `job_retention_ms` | 15 minutes |

**The limitation that matters: jobs are process state.** There is no durable job record and no disk spool. A router that restarts has an empty job table, and an identifier from before the restart is `job_not_found`. That is deliberate — a durable record saying `running` with no worker running it is worse, because a client waits on it — but it means a job identifier is valid only for one router lifetime. A client that must survive a restart resubmits.

Two smaller consequences of the same choice:

- **A result is not stored beyond its retention window**, and never on disk. §2.2's non-goals say the router is not a blob store, and `max_job_result_bytes` plus `job_retention_ms` are what keep `/v1/jobs` from making it one. A result larger than the spool fails the job naming the bound rather than arriving truncated.
- **`/events` resumes by state, not by replay.** A reconnecting client gets the job's current state immediately and then further changes. There is no event log to replay from, deliberately: storing intermediate states so a client could replay them is retention nobody asked for.

Jobs are not visible across tenants. An identifier belonging to another tenant answers `job_not_found`, identically to one that never existed and one that expired — Appendix B bounds visibility to the caller's tenant, and telling those apart would confirm that a guessed identifier names a real job.

## Predictive pre-warm is on the dullest signal that works

**Specification:** [orchestration.md](orchestration.md) §9.8. **Implementation:** `FleetRuntime::prewarm`, run from the housekeeping loop.

The router will start a cold deployment before anything asks for it, when the host's `fleet_policy` declares `prewarm_min_rate_per_minute=N` and the smoothed request rate for that deployment's capability is at least `N`. It is **zero — off — by default**, and turning it on is a per-host decision.

The predictor is deliberately unsophisticated, because how clever it is was never what bounds the damage. Three other things are:

- **The same budget.** A pre-warm spends `max_activations_per_hour` exactly as a demand-driven activation does, so prediction cannot exceed the ceiling — at worst it spends the hour's allowance sooner.
- **The same governance.** Dwell floors, reactivation cooldown and flap backoff are enforced inside `plan`, so a deployment that was just evicted is not immediately predicted back.
- **It never evicts, and never fetches.** A plan that would stop something, or download something, is abandoned rather than executed. Displacing a running model on a guess is precisely how the swap rate doubles: the fleet pays a stop *and* a start, and the evicted model's own traffic then pays for it again.

It also refuses to act on belief that has aged out, runs on the housekeeping thread so no caller ever waits behind a speculative activation, and starts at most one deployment per observation interval.

What it does not do: predict from anything but the current rate. There is no time-of-day model, no per-tenant shape, no lookahead. `hypellm_fleet_thrash_ratio` is how a deployment finds out whether the number it set is right, and it is the number to watch after enabling this.

## Management access with an API key

**Specification:** §9.2, §9.3, §16. **Implementation:** `AdminApi::key_caller` and `AdminApi::require` in `crates/hypellm-admin-api/src/handlers.rs`.

`/admin/v1` accepts a router API key as well as a session cookie, so automation — a backup schedule, a CI job that publishes policy, a scrape of the usage view — does not need a browser session. The rules are narrow, and worth knowing before building against it:

- **Scope.** The key must carry `management:read`. A mutating request additionally needs `management:write`; a read key that could POST would make the distinction the Keys screen offers a decoration.
- **Permissions come from configuration, not from the key.** The key record carries no roles. Its permissions are the `role_binding` records for its principal in the *active* configuration, resolved on every request — so withdrawing a binding de-powers every key that principal holds immediately, with nothing to find and reissue. A key whose principal has no binding is refused, and told why.
- **Two permissions no key may hold.** `BreakGlass` and `ManageKeys` are refused to a key whatever its principal's bindings say. §22.4's recovery path is a human with a token held offline; a key that could open it is that control replaced by a string in a CI secret store. And a key that can mint keys can mint a replacement for itself the moment it is revoked, which makes revocation an inconvenience rather than an ending.
- **The cookie always wins.** The key path is reached only when no session cookie was sent. CSRF exists because a browser attaches a cookie by itself; nothing attaches an `Authorization` header by itself, so the key path runs no CSRF check — and a cookie-authenticated request cannot route around the CSRF gate by adding a header.
- **`POST /admin/v1/logout` is refused for a key**, because there is no session to end. A `204` there would report that the credential had been withdrawn while the key still worked. Revoke the key instead; revocation takes effect on both planes at once.

What it does not do: a management action is attributed to the key's **principal**, exactly as a session's action is. The key identifier reaches the audit chain once per key per router lifetime, as a `login` record naming the key id, and not on each action. Two keys held by one principal are therefore indistinguishable in the management audit — give each automation its own principal.

## Conservative token estimation

**Specification:** §12, §25. **Implementation:** `hypellm_core::canonical::estimated_input_tokens_for` and `target … bytes_per_token`.

Pre-admission token estimates are `ceil(input bytes / bytes_per_token)` plus per-message framing, plus a flat constant per document. The selected target's tokenizer is not consulted: the router runs no tokenizer, and it does not call a provider's `/v1/tokenize` on the admission path — that would put a network round trip, and a second failure mode, in front of every request in order to refine a bound.

What it does instead is let an operator calibrate from measurement. `bytes_per_token` defaults to **2**, which is roughly half what real text tokenizes at, so an undeclared target reserves about twice what it uses and some requests near a quota are held that would have fitted. `hypellm_token_estimate_error{target,source}` reports reserved-minus-reconciled per target, so the ratio a deployment should declare is observable rather than guessed. Declared values are bounded to 1–8 and refused outside that.

**The router never learns this by itself, deliberately.** A gateway that widened its own quota estimate in response to traffic would end up enforcing whatever the traffic taught it, and the traffic is what the quota exists to bound. Calibration is an administrator's decision, recorded in the configuration, and it goes through the same drafting and review as any other policy change.

## Data lifecycle and external operations

**Specification:** §10, §11.2, §17. **Implementation:** configuration schema, `hypellm_router::startup::backup_state`, and `GET /admin/v1/audit/export`.

Prompt and completion bodies are not captured, and cannot be: `capture_bodies=true` is a configuration error that refuses the document, because §17 admits capture only as per-tenant, sampled, encrypted, access-controlled and time-limited, and none of that is built. A setting that read as "capture is on" while nothing captured would be worse than the missing feature.

Tenant `retention_days` loads, and does not delete state, audit, usage or exported logs. It is a declaration rather than a control: the Settings screen labels it "declared, not enforced by the router" and the API sends `retention.days_enforced: false` beside it, so the number cannot be mistaken for something acting on it.

The router produces authenticated audit checkpoints and exposes a durable audit export endpoint, but does not push exports to remote storage. `hypellm-router --backup` takes a consistent copy on demand into `settings backup_dir` — see [backup](deployment.md#backup) — but nothing schedules it. Deployments must provide the schedule, the offsite copy, and their retention policy.

## Local password sign-in is a deviation

**Specification:** §9.1, §9.2, §22.4. **Implementation:** `crates/hypellm-crypto/src/scrypt.rs`, `crates/hypellm-crypto/src/pbkdf2.rs`, `hypellm_config::LocalUser`, `AdminApi::password_sign_in`, `web/app.js`.

Specification §9.2 lists four ways a principal is established — router API key, Google OIDC session, local peer credentials, and break-glass — and a username and password is none of them. `POST /admin/v1/auth/password` and the `local_user` configuration record exist anyway, so that a deployment can be operated before an OAuth client, a redirect URI and a verifier process have been set up. It is the weakest authentication path the router has, and it is off unless a `local_user` record is declared.

What it does keep:

- The record stores an scrypt verifier (RFC 7914, `ln=15, r=8, p=1` — 32 MiB and about 100 ms), never a password. `hypellm-router --hash-password` derives one from stdin; a password is never taken from a command-line argument. Verifiers written before scrypt still authenticate so an upgrade does not lock an operator out, and the router logs `startup.password_verifier_legacy` naming each account still on the old form.
- An unparseable verifier is a configuration error at load, not an authentication failure discovered by the person who needed to sign in.
- A failed sign-in is refused identically whether the username is unknown, the password is wrong, or the body is malformed. Five failures lock one account for a minute, and the lockout is checked before the hash is computed.
- The session records `password` as its authentication method, is not a break-glass session, and both outcomes reach the audit chain.

What it does not:

- **A password is still a password.** scrypt raises the cost of an offline attack by orders of magnitude over the PBKDF2 verifier it replaced, and it does not make a guessable password safe. Treat an offline copy of the configuration as an offline copy of the password hashes, and choose accordingly.
- **An unknown username is refused without hashing anything**, so it is refused measurably faster than a known username with a wrong password. That is a username oracle. The alternative — hashing a dummy verifier so the two take the same time — hands an unauthenticated caller a CPU amplifier on an endpoint that runs before any session, and a management plane that stops answering is worse than one that confirms `admin` exists.
- **`docker/hypellm.conf` ships `admin`/`admin`.** That is a default credential, deliberately, so a fresh checkout is usable. The router logs `critical` `startup.default_password_in_use` on every start for any account whose password is its own username; that log line is the warning, not a formality.

## Anonymous inference access is a deviation

**Specification:** §9.2. **Implementation:** `RecordKind::AnonymousAccess` in `hypellm-store`, `RouterState::anonymous_access`, `Principal::anonymous`, `routes::authenticate`, `AdminApi::set_anonymous_access`, `web/views/credentials.js`.

Specification §9.2 requires every request to the inference listener to establish a principal from one of four credentials. This router can be switched into serving a request that presents **none** of them, as a configured principal. It is off in every fresh deployment and has to be switched on deliberately.

**The configuration document cannot switch it on.** `anonymous_enabled` is not a settings key — a document naming it fails to load as an unknown field, in either direction, so a key that silently did nothing when `false` cannot read as one that works. What the document declares is the *subject*: `anonymous_principal`, `anonymous_tenant`, `anonymous_scopes`. Those are inert on their own; they say who an uncredentialed caller would be served as, and declaring them is what makes the switch *available*. The switch itself is `POST /admin/v1/settings/anonymous`, which writes a MAC-protected `AnonymousAccess` frame and sets the `AtomicBool` the inference listener reads. Anyone able to write `hypellm.conf` can change routing; they cannot change whether authentication is required.

What it keeps:

- **It is not a bypass of credential checking.** The fallback is reachable only when neither `Authorization` nor `x-api-key` is present. A credential that is presented and fails — revoked, expired, unparseable, an unrecognised scheme, or an empty `Bearer ` — is refused with `unauthenticated`. A revoked key does not become an anonymous caller, so revocation keeps meaning what the Keys screen says it means.
- **The anonymous caller is a named subject**, not an identity the router invents. The document refuses a half-declared subject or one naming an undeclared tenant at load, and the endpoint refuses to switch on when no subject is declared at all.
- **It may not hold a management scope.** `management:read` and `management:write` in `anonymous_scopes` are a configuration error. Scopes default to `inference,models`; an unknown name is refused rather than dropped.
- **It is durable, and fails closed.** The last frame wins on replay; absent means off. A frame that does not parse, or carries no `enabled`, is treated as off rather than skipped — so a corrupt tail cannot resurrect a switch an operator turned off.
- **It is recorded as `anonymous`.** `AuthMethod::Anonymous` is distinct from `ApiKey`, and `key_id` is `None`. §22.3's investigation asks how a principal authenticated, and the answer here is "it did not" rather than a credential that was never issued.
- **It is said out loud.** `critical` `startup.anonymous_access_enabled` on every start while it is on, `critical` on both edges of every change, an audit entry with a mandatory reason, and an error-weight banner on the Credentials and Settings screens.
- **The permission is `manage_settings`**, not the `manage_credentials` that gates the screen the control is rendered on. `credential_manager` exists to rotate provider secrets; letting it disable authentication fleet-wide would make it the most powerful role in the model by accident.

What it does not:

- **There is nothing to revoke and nothing to attribute.** Every anonymous request is the same principal, so per-caller rate limiting, quota, and audit attribution are all at the granularity of "everyone who did not present a key". Usage for that principal is a single aggregate.
- **Reaching the listener is the entire authorization check.** On a listener bound to a network anyone else can reach, this is an open inference endpoint and the fleet's capacity is spendable by anyone who finds it. That is the intended behaviour of the switch, which is why it is off by default and why turning it on is a `critical` log line rather than an informational one.

## Security boundaries worth understanding

These are design boundaries rather than defects, but they affect deployment:

- Inbound TLS is supplied by a trusted edge; outbound TLS and OIDC signature verification are supplied by local platform helpers.
- The management session cookie is `__Host-` prefixed and `Secure`, so browsers store it only over HTTPS or on `localhost`/`127.0.0.1`. Management sign-in — including password sign-in — does not work over plain HTTP on any other address.
- Possession of the secrets directory defeats keyed store-integrity and authentication controls. Protect it separately from state.
- The TLS helper and OIDC verifier are part of the trusted computing base. The reference verifier in `verifier/` holds the OAuth client secret and decides which identity tokens are authentic; review it as such.
- Availability against an attacker capable of filling the configured connection cap is bounded, not guaranteed.
- API and module changes involving auth, parsers, credential handling, policy activation or storage integrity require two-person review.
