# HypeLLM Router — deployment

Specification 20 defines four deployment profiles and 20.1 defines process
hardening. This document maps them onto what the binary actually does today, and
says clearly which parts of 20.1 are **not** implemented in code and must be
supplied by the deployment image or the init system.

Contents: [The binary](#the-binary) · [Deployment
profiles](#deployment-profiles) · [The TLS boundary](#the-tls-boundary) ·
[Secrets directory](#secrets-directory) · [State
directory](#state-directory) · [Listener separation](#listener-separation) ·
[Configuration](#configuration) · [Startup](#startup) · [Shutdown](#shutdown) ·
[Process hardening](#process-hardening)

---

## The binary

```
hypellm-router --config <path> --secrets <dir> [--static <dir>] [--log <level>]
hypellm-router --check --config <path>
hypellm-router --generate-secrets <dir>
hypellm-router --version
```

| Flag | Meaning |
|---|---|
| `-c`, `--config <path>` | The configuration file. Required except for `--generate-secrets`. |
| `--secrets <dir>` | Directory holding the platform secret files. Required to serve. |
| `--static <dir>` | Serve the admin application from this directory. Omit and no SPA is served. |
| `--log <level>` | `debug`, `info`, `warn`, `error`, `critical`. Default `info`. |
| `--check` | Validate the configuration and exit. |
| `--generate-secrets <dir>` | Write a fresh secret bundle and exit. |
| `-V`, `--version` / `-h`, `--help` | Print and exit 0. |

Exit codes, so a supervisor can distinguish the failure
(`crates/hypellm-router/src/main.rs`):

| Code | Meaning |
|---|---|
| 0 | Clean shutdown |
| 2 | Configuration or arguments invalid |
| 3 | State directory unusable, or an integrity failure |
| 4 | A listener (including the control socket) could not be bound |
| 5 | A required secret was missing |

There is no environment-variable configuration and no implicit file discovery.
Secret *paths* are given on the command line so that secret *material* never
appears in `/proc/<pid>/cmdline` or in an inherited environment
(`crates/hypellm-router/src/startup.rs`, `Secrets`).

---

## Deployment profiles

Specification 20's four profiles, and what each requires of this build.

### Developer local

Router binds loopback; llama.cpp over loopback; file state with strict
permissions. This profile works end to end today.

```
settings inference_listen=127.0.0.1:8000 admin_listen=127.0.0.1:8001 \
         state_dir=/var/lib/hypellm control_socket=/run/hypellm/control.sock
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
```

The router listens on 8000/8001 because llama.cpp's own default is 8080. Both
examples used to put the inference listener on 8080 as well, which validates
happily and then makes the router its own only provider.

Cleartext `http` is permitted **only** to a loopback literal or the name
`localhost`; anything else is refused at load time
(`crates/hypellm-config/src/build.rs`, `validate_endpoint`). A remote provider in
this profile still needs the TLS helper.

### Single secure node

TLS edge on the same host, admin listener on a separate socket or network,
platform secrets, system service sandbox. This is the intended production
profile for a single node.

What the router supplies: two independent listeners with independent limits and
independent handlers, an authenticated control socket that stops admission and
drains within a deadline, a MAC-protected state directory, and 0600 credential
files written through the management API.

What the deployment must supply: the TLS edge in front of both listeners, the
TLS helper for outbound HTTPS, the identity verifier socket, the unprivileged
user, the filesystem layout, and the sandbox. See
[Process hardening](#process-hardening) — none of that last group is done in
code.

> **Unix-socket listeners are supported.** Specification 20's "Unix socket to
> router" is implemented: any listener address beginning with `unix:` or with
> `/` is bound as a `UnixListener` instead of a TCP socket, and the socket file
> is restricted to its owner. So `inference_listen=/run/hypellm/inference.sock`
> works, and the TLS edge can reach the router without a loopback port at all.
>
> One consequence worth knowing: a Unix peer has no IP address, so a key with a
> source restriction fails closed over a Unix socket rather than matching
> everything. Formerly recorded as `DI-028`, now resolved.

### HA stateless data plane

**Not supported.** `hypellm-store` is single-node by construction: a PID-file
process lock, no replication, no leader election, no distributed lock
(`crates/hypellm-store/src/durable.rs`, `ProcessLock`). Specification 11.2 defers
multi-node to an external consensus/config distributor and none is implemented.
Running two routers against one state directory is unsafe — the lock is advisory
and its stale-reclaim path is racy. Recorded as `DI-029`.

Multiple routers with *separate* state directories and a shared upstream is
possible, and the quota half of it is now addressed. Specification 12 requires
"an authoritative allocator **or** conservative node partitions" for
admission-critical quotas; there is no allocator, but `settings
quota_partitions=N` implements the partitions. Each router enforces `limit / N`,
so N nodes honour the configured figure between them rather than each enforcing
it alone. Set it to the number of routers you actually run — leaving it unset on
a four-node deployment quadruples every tenant limit, and setting it higher than
the node count under-admits.

What that does *not* give you: shared keys, a shared audit chain, shared
sessions, or shared decision traces. Each node has its own state directory and
its own view of everything in it. This is "several independent routers whose
quota arithmetic adds up", not a cluster.

### Air-gapped / local-only

Supported and the easiest profile to reason about: configure only `scheme=http`
loopback or `scheme=unix` providers, omit `tls_helper_socket` entirely, and omit
the OIDC settings. Outbound TLS then has no path at all — `Egress::acquire`
returns an error rather than falling back to a cleartext socket
(`crates/hypellm-net/src/egress.rs`).

Omitting the OIDC settings disables Google sign-in completely, which for an
air-gapped deployment is the point. Break-glass is the management plane there:
set `break_glass_principal`, `break_glass_tenant`, and a `role_binding`, keep the
token from `--generate-secrets`, and sign in through
`POST /admin/v1/auth/break-glass` (see
[`runbooks.md` 22.4](runbooks.md#break-glass-access)).

Two consequences worth planning for. Every session is time-limited to
`break_glass_ttl_secs`, so an air-gapped operator signs in per task rather than
staying signed in. And every sign-in emits a `critical` log event and an audit
record — correct for an emergency path, noisy as a daily one, so size the
retention accordingly.

---

## The TLS boundary

**The router does not implement TLS, in either direction.** This is a
specification requirement, not an omission: specification 4's "TLS reality" note
and 9.1's OIDC dependency boundary both forbid novel TLS or signature code, and
the no-dependency policy admits no TLS crate.

### Inbound

There is no inbound TLS. Both listeners speak cleartext HTTP/1.1
(`crates/wire-http1/`). **A TLS edge in front of the router is mandatory for any
non-loopback deployment**, and specifically for the management listener: the
session cookie is `__Host-hypellm_session` with the `Secure` attribute
(`crates/hypellm-auth/src/session.rs`), which browsers will not store over plain
HTTP. Management sign-in simply does not work without HTTPS.

The edge is also where specification 10.1's "edge normalization" for request
smuggling belongs. The router's own parser rejects TE/CL ambiguity and duplicate
framing headers and closes the connection on any framing error, but a
normalising edge is the specification's first line.

The router never trusts an inbound forwarding header unless the peer is a
configured trusted edge, and `TrustedEdge::none()` — trusting nothing — is what
`RouterState` is constructed with today (`crates/hypellm-router/src/startup.rs`).
`X-Forwarded-For` is therefore ignored, and the peer address used for API-key
source restrictions is the real socket peer.

### Outbound

Outbound HTTPS goes through a platform TLS helper over a Unix socket, named by
`settings tls_helper_socket`. The wire protocol is deliberately tiny
(`crates/hypellm-net/src/helper.rs`):

```text
→ CONNECT <host> <port> <sni>\n
← OK\n              then the socket carries the TLS session's plaintext
← ERR <code>\n      and the socket closes
```

The router sends only a host, a port, and an SNI name, all of which came from
configuration — never a URL, a path, or a header. The helper is inside the
trusted computing base: it validates certificates, selects ciphers, and should
enforce its own destination allowlist. Its error codes are sanitised to 64
characters of `[A-Za-z0-9_-]` before they reach a log or an error body.

**If `tls_helper_socket` is not configured and any provider declares
`scheme=https`, startup fails** with
`StartupError::Unreachable` (exit 2) listing each endpoint that "requires
outbound TLS, but no `tls_helper_socket` is configured". The router never
silently downgrades.

### Identity verification

JWT signature verification is delegated the same way, to a local verifier socket
at `settings oidc_verifier_socket`:

```text
→ VERIFY <length>\n<token bytes>
← OK <length>\n<claims JSON>
← ERR <code>\n
```

The verifier checks the signature; it must **not** validate `iss`, `aud`, `exp`,
or `nonce` — those are checked in exactly one place,
`hypellm_auth::oidc::validate_claims`, so that a check cannot be skipped on one of
two paths (`crates/hypellm-net/src/helper.rs`, `crates/hypellm-auth/src/oidc.rs`).

Both helper sockets are Unix sockets; their access control is filesystem
permission on the containing directory, which the router does not set.

---

## Secrets directory

Created by `hypellm-router --generate-secrets <dir>`, read by `--secrets <dir>`.

```text
<secrets>/
  store_mac.key       authenticates protected store frames and the audit chain
  key_verifier.key    derives API key verifiers
  session.key         derives session digests and CSRF tokens
  pseudonym.key       derives log pseudonyms
  oidc.key            derives OIDC transaction handles
  control.key         authenticates control-socket commands
  break_glass.verifier  verifies the break-glass token — the digest, not the token
  credentials/
    <credential-id>   one provider secret per declared `credential` record
```

Rules the code enforces (`crates/hypellm-router/src/startup.rs`):

- Each of the seven files must exist and be **at least 32 bytes**. A missing
  or short file is `StartupError::MissingSecret`, exit 5. A missing file is
  never silently replaced with a generated default: a router that invents its
  own store MAC key on first boot cannot detect tampering across a restart,
  because an attacker can delete the state and let it invent a new one.
- Provider credential files are read **only** for the credential ids the active
  configuration declares. A file nobody declared is never read — specification
  4.1 forbids implicit file discovery. The id is validated by `CredentialRef`,
  so it cannot contain a path separator or `..`.
- A declared credential whose file is missing or empty is a startup failure
  (`StartupError::CredentialUnreadable`), not a deferred surprise on the first
  request.
- Trailing `\n` and `\r` are trimmed, so `echo key > file` works.

- **`break_glass.verifier` is a digest, not a token.** The token itself is
  printed once by `--generate-secrets` and stored nowhere: specification 22.4
  requires it to be held offline, and a copy on the router would mean reading
  the secrets directory was itself a way in. Losing it means generating a new
  bundle; there is no recovery from the verifier.
- Every file is `chmod`ed to 0600 and the `credentials/` directory to 0700 by
  `--generate-secrets`, so a default `umask 022` no longer leaves the router's
  root of trust world-readable. Still own the directory as the router's user —
  the mode protects it from other accounts, not from a wrong owner.

Rotation of the router keys is an offline operation with consequences:
rotating `store_mac.key` invalidates every protected frame already on disk and
requires a rewritten state directory; rotating `key_verifier.key` invalidates
every API key; rotating `session.key` invalidates every session. There is no
runtime re-key path. Provider credentials rotate at runtime — see
[`runbooks.md` 22.2](runbooks.md#222-credential-rotation).

---

## State directory

> **A state directory written before the `hypellm` rename is not readable.** The
> log frame magic and the snapshot-metadata magic both changed, so `log.bin` and
> `snapshot.meta` from an older build are refused at startup with a message
> naming the file. That refusal is deliberate: the alternative was truncating
> the log and reporting the loss as a routine torn tail (`DI-055`). There is no
> migration path — start from an empty `state_dir`, and re-issue API keys.


`settings state_dir`. Opened with an advisory process lock and replayed at
startup (`crates/hypellm-store/src/lib.rs`).

```text
<state_dir>/
  lock              single-writer lock (a PID file, see below)
  snapshot.bin      the last compacted state
  snapshot.meta     sequence, audit head, audit count, payload digest, MAC
  log.bin           frames appended since the snapshot
```

Startup sequence:

1. Acquire the process lock, reclaiming it if the recorded process is gone.
2. Read the snapshot. `snapshot.meta` is MAC-verified against `store_mac.key`
   and cross-checked against a SHA-256 of `snapshot.bin`; either failing is
   `StoreError::SnapshotIntegrity` and startup aborts (exit 3).
3. Replay `log.bin`. A **torn tail** (incomplete frame, bad CRC) is truncated
   and the router starts, logging `store.tail_truncated`. A **protected-record
   integrity failure** (MAC mismatch, missing MAC, unexpected MAC) or a
   non-monotonic sequence aborts startup. That asymmetry is deliberate: a power
   loss must not become an outage, and an edited audit history must not become a
   boot.
4. Resume the audit chain from the snapshot's recorded head, and resume the last
   activated configuration.

Writes use temporary file → `fsync` → atomic rename → directory `fsync`
(`durable::write_atomic`). Compaction writes the new snapshot durably *before*
resetting the log, so a crash leaves either the old snapshot plus the full log
or the new snapshot plus an empty log.

Backup: `Store::backup_to` copies a validated snapshot plus a log boundary. It
is a library call with no CLI flag; copying a quiesced directory works equally
well. There is no automated backup and no retention policy in the router.

Operational notes that matter:

- **The lock is a PID file, not an OS lock.** `flock` would need `unsafe` FFI,
  which the workspace forbids. Liveness is `/proc/<pid>` existence, so PID reuse
  can cause a spurious refusal to start, and two starters that both observe a
  stale lock can both proceed. **On a shared or network volume it provides no
  protection at all.** Give each router its own local state directory.
- **Startup memory is roughly twice the log size.** `Log::replay` reads the
  whole file. Nothing triggers compaction automatically; size the volume and
  schedule compaction for the log growth your audit and key-change rate implies.
- **Sequence gaps are legal** — a failed append leaves a hole and replay
  requires strictly increasing, not contiguous, numbers. Gaps are not evidence
  of deletion; the audit chain is what covers that.
- **Audit checkpoints are produced, not exported.** `settings
  audit_checkpoint_interval` controls the cadence; shipping checkpoints to
  immutable storage (specification 11.2, 17) is the caller's job and there is no
  spool directory: `GET /admin/v1/audit/export` (permission `ExportAudit`)
  emits the chain with its checkpoints on request, but nothing ships them
  off-node on its own. Arrange a periodic export to immutable storage —
  otherwise the trust anchor lives in the same directory as the data it anchors
  (`DI-030`).

---

## Listener separation

Specification 3 requires the management path to be separated from the data path
"in code, scheduling, rate limits, authentication scopes, and listener
configuration". The separation as built:

| | Inference listener | Management listener |
|---|---|---|
| Address | `settings inference_listen` | `settings admin_listen` |
| Handler | `InferenceHandler` (`routes.rs`) | `AdminHandler` (`admin.rs`) → `AdminApi` |
| Authentication | Router API key (`Authorization: Bearer` or `x-api-key`) | Google OIDC session cookie + CSRF |
| Authorization | Key scopes | RBAC permissions |
| Max connections | 4096 | 256 |
| Requests per connection | 1000 | 200 |
| Read / write timeout | 30 s | 15 s |
| Keep-alive | 75 s | 30 s |
| Request head / target / headers | 32 KiB / 8 KiB / 100 | 16 KiB / 2 KiB / 64 |
| Request body | 16 MiB (from `settings max_body_bytes`) | 1 MiB |

Values from `crates/hypellm-router/src/server.rs` (`ServerConfig::inference` /
`::management`) and `crates/wire-http1/src/limits.rs`
(`Limits::DEFAULT` / `Limits::ADMIN`). `settings max_head_bytes`,
`max_body_bytes`, `slow_client_timeout_ms`, `default_deadline_ms`,
`max_connections`, `max_requests_per_connection`, `read_timeout_ms`,
`keepalive_timeout_ms`, and `connection_stack_kib` all reach the listeners
through
`startup::listener_config`. Zero keeps the profile default, so tune what you
mean to and inherit the rest; every value is clamped, so a configuration
mistake can move a bound but not remove one.

> **Running more than one router? Set `quota_partitions`.** Each router counts
> admissions alone, so N routers behind a load balancer enforce every quota N
> times over — a tenant limit of 100 becomes 400 across four nodes, silently.
> `settings quota_partitions=4` divides every quota limit by four so the four
> together honour the configured figure (specification 12's "conservative node
> partitions", `DI-029`). Division truncates, so the sum never exceeds the
> limit; a quota smaller than the partition count is a load error rather than a
> clamp, because zero encodes "unlimited" and clamping would invert the setting.
> This makes the quota arithmetic right for a fanned-out data plane. It does
> **not** make the router highly available, and two routers still must not share
> a state directory.

> **`max_connections` is not the real connection ceiling.** The router serves
> one thread per connection (`DI-001`), so the practical limit is address space
> divided by `connection_stack_kib`, whichever is lower. The default 512 KiB
> stack is what makes the inference profile's 4096 connections reachable at all
> — the platform default of 8 MiB would reserve 32 GiB for the same number. If
> you raise `max_connections`, check the product; if a handler needs deeper
> stacks, raise `connection_stack_kib` and expect a lower ceiling in exchange.
> The setting is clamped to 128 KiB–8 MiB: too small overflows a handler stack,
> which aborts the process rather than failing a request.

> **`keepalive_timeout_ms` is not `keepalive_interval_ms`.** The first is how
> long an idle connection waits for its next request. The second is
> specification 14's SSE comment cadence — how often the router writes into an
> *open stream* so an intermediary with an idle timeout does not drop a
> connection whose provider is still thinking. Tuning either must not move the
> other, which is why they are separate settings (`DI-031`).

Failed sign-ins on the two pre-session endpoints — the OIDC callback and
break-glass — are audited under a bound: the first ten in a sixty-second window
are recorded individually and the rest are summarised in one record per window.
Each path has its own budget, so a flood against one cannot suppress records
from the other. `hypellm_auth_failures_total` counts every attempt regardless, so
alert on the metric rather than on audit-row volume (`DI-052`).

`POST /admin/v1/targets` proposes a target rather than creating one: it returns
a policy draft carrying the new `target` record, which then follows the ordinary
validate → approve → activate path. Nothing routes to the proposed target until
that draft is activated, and the response says so (`target_created: false`).

`/admin/v1` is reachable **only** on the management listener. The inference
listener matches an exact, undecoded path set and answers anything else with
404 — there is no prefix matching and no normalisation step to walk.

The inference listener answers `GET /health/live` and `GET /health/ready`
**before** authentication, because health must answer when the configuration is
broken. Both return the verdict and nothing more: `/health/ready` is
`{"status":"ready"}` or `{"status":"not_ready"}`, with no configuration version,
digest, target, or address. It used to disclose the version and digest, which
together fingerprint the deployment and reveal its change cadence (`DI-032`).
The detailed form lives on the management listener, behind authentication.

The metrics exposition is served on the management listener at `GET /metrics`
and is deliberately **not** on the inference listener — it carries target
identifiers, breaker states, queue depths, and auth-failure counts, which is an
operational map of the deployment.

> **`settings metrics_listen` binds a third listener.** When it names an
> address, the router binds a separate server answering exactly two routes —
> `GET /metrics` and `GET /health/live` — and 404 for everything else, so a
> scraper and a supervisor can reach it without any path to the management
> plane. Leave it unset and the exposition stays on the management listener.
> Formerly recorded as `DI-011`, now resolved.
>
> The exposition is still an operational map (target identifiers, breaker
> states, queue depths), so restrict this listener to your monitoring network.

One series is worth knowing about when diagnosing a slow stream:
`hypellm_stream_backpressure_milliseconds` is how long a stream spent blocked
writing to its client. The router serves one thread per connection, so a client
that stops reading blocks that thread, which stops it reading from the provider
— backpressure without a knob to turn (`DI-037`). A high value here means the
*client* is slow; `hypellm_upstream_latency_milliseconds` on the same request
means the *provider* is. Without the first, the two were indistinguishable.

### The static admin application

`--static <dir>` serves the SPA from the management listener. Assets are served
from an explicit allowlist of relative filenames, never by joining a request
path onto a root (`crates/hypellm-router/src/admin.rs`, `serve_static`), and every
response carries:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none';
  frame-ancestors 'none'; form-action 'self'; object-src 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(),
  magnetometer=(), microphone=(), payment=(), usb=()
```

The absence of `'unsafe-inline'` is the load-bearing part: the application in
`web/` has no inline script and no inline event handlers, so a content injection
has nothing to execute. That property is enforced mechanically by
`depscan` (`crates/hypellm-devtools/src/web_scan.rs`), which also refuses
`vendor/`, remote origins, `eval`, `Function`, `innerHTML`, service workers, and
WebAssembly.

`settings cors_origins` must list the exact origin the SPA is served from.
Matching is exact string equality — no suffix matching, no scheme coercion, no
case folding, no trailing-slash tolerance, and no wildcard is ever emitted
(`crates/hypellm-admin-api/src/cors.rs`).

---

## Configuration

A line-oriented grammar, not YAML or TOML (specification 11.1). Records are
`type key=value …`; strings use JSON-style quoted escapes; `#` begins a comment
outside a string; a trailing `\` continues a line. **Unknown record types and
unknown fields are errors.** Includes, environment expansion, anchors,
expressions, and executable templates do not exist — `crates/hypellm-config/src/parse.rs`
has no evaluation step at all, so `${SECRET}` and `*anchor` are literal strings.

Record types (`crates/hypellm-config/src/schema.rs`, `SCHEMAS` — a closed set of
thirteen):

| Record | Required fields | Purpose |
|---|---|---|
| `settings` | — (singleton) | Listeners, limits, deadlines, OIDC, CORS, state dir, sockets |
| `tenant` | `id` | Tenant, residency, status |
| `provider` | `id`, `family`, `scheme`, `host` | Provider family, endpoint, credential reference, egress profile |
| `target` | `id`, `provider`, `model` | Native model, declared capabilities, limits, cost class, state |
| `alias` | `id`, `targets` | Client-visible name and its permitted target set |
| `binding` | `id`, `scope` | Per-principal/group/tenant priorities, denies, pins |
| `grant` | `scope` | Which aliases and operations a scope may use (default-deny) |
| `quota` | `scope` | Concurrency, queue, queue class, request rate, token rate |
| `role_binding` | `subject`, `role` | Management permissions |
| `group` | `id`, `tenant` | Group membership, used by `binding` and `grant` scopes |
| `identity` | `issuer`, `subject`, `principal`, `tenant` | Binds a Google account to a local principal — without one, that account cannot sign in |
| `credential` | `id` | Credential **metadata** only — never a secret value |
| `price` | `target` | Per-target token rates and the date they take effect, for usage estimates |

Two of these decide *who* rather than *what*, and both are explicit on purpose:

- **`identity`** maps the `(iss, sub)` pair of specification 9.1 to a principal
  and a tenant. The `subject` is the `sub` claim, never the email address —
  an email can be reassigned to a different person, a `sub` cannot. The tenant
  is named rather than inferred, because it decides whose data the operator
  sees.
- **`group`** declares membership rather than deriving it. Specification 25:
  "do not infer Google group membership from email domain."

A minimal working document:

```text
settings state_dir=/var/lib/hypellm inference_listen=127.0.0.1:8000 \
         admin_listen=127.0.0.1:8001 control_socket=/run/hypellm/control.sock
tenant id=acme
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:m provider=local model=m local=true operations=chat streaming=true \
       context=1000 max_output=100 concurrency=4
alias id=a targets=local:m
grant scope=tenant:acme model=* allow=true
binding id=b scope=tenant:acme model=* prefer=local:m
```

### Price schedules

A billing system is among the things the specification says this router is not,
and this is not one: no invoice, no ledger, no account. It is an *estimate*, so that an operator reading the
usage view can see which alias is expensive before the provider's own bill
arrives a month later. Specification 25 recommends exactly this — "a configured
price schedule with effective dates" — and the effective dates are the point:
provider prices change, and a figure computed with today's rate against last
month's tokens is worse than no figure.

```text
price target=openai:gpt-4o input_per_million=2500 output_per_million=10000 \
      cached_input_per_million=1250 currency=USD effective_from=1767225600000
price target=openai:gpt-4o input_per_million=2000 output_per_million=8000 \
      currency=USD effective_from=1780272000000
```

`effective_from` is **epoch milliseconds**, not an ISO date — the two values
above are 2026-01-01 and 2026-06-01 UTC. The grammar has no date parser: turning
`YYYY-MM-DD` into an instant is calendar arithmetic, and the workspace has no
date library and may not acquire one (specification 4). The same reasoning keeps
`budget_period` to fixed rolling windows rather than calendar months.

Rates are in **minor units per million tokens** — cents for `USD` — so the
arithmetic is integer throughout and never touches a float. The schedule entry
in effect is the latest one whose `effective_from` is on or before the usage
row's day; usage before the earliest entry is reported without a figure rather
than with a guessed one. A `price` naming a target that does not exist is an
`unknown_reference` error, so a renamed target cannot leave a stale rate
silently attached to nothing.

Two rounding decisions worth knowing when the number is compared against a real
invoice:

- Each term rounds **up** to the minor unit, so an estimate errs high rather
  than low. A number that undersells the bill is the one that causes trouble.
- `cached_input_per_million` defaults to `input_per_million` when omitted, not
  to zero — the same preference for over-reporting. Set it explicitly if the
  provider discounts cache reads and you want that reflected.

The figure appears as `estimated_cost` on usage rows from `GET
/admin/v1/usage`, alongside its currency, and is labelled an estimate there.
The tokenizer half of specification 25's cost question — pre-flight token
*counting* — is not implemented; see `DI-048`.

### Alias quotas

Specification 12's admission hierarchy has five layers. A `quota` may scope to
an alias, optionally for one operation:

```text
quota scope=alias:code concurrency=10
quota scope=alias:code operation=embeddings concurrency=2
```

The alias layer sits between the principal and the target, and that is the
reason to use it: an alias is what the caller asked for, a target is what the
router picked. A cap of two on each of three targets admits six requests for
that alias; a cap of two on the alias admits two.

An operation-specific quota replaces the alias-wide one for that operation
rather than combining with it, so the effective ceiling never depends on which
was evaluated first. Scopes available: `global`, `tenant:<id>`,
`principal:<id>`, `alias:<id>`, `target:<id>` (`DI-053`).

### Byte rates and spend budgets

Two more of specification 12's controls, both off unless configured.

```text
quota scope=global input_bytes_per_second=1048576 output_bytes_per_second=4194304
quota scope=tenant:acme budget=250000 budget_period=monthly
```

**Byte rates** belong on `global` and nowhere else — the grammar refuses them on
a narrower scope rather than ignoring them. They catch what the neighbouring
limits cannot: `max_body_bytes` bounds any one request and `rps` bounds how many
arrive, but nothing else bounds their product. Input is charged before
admission; output is charged after the response, so it throttles the *next*
request rather than truncating the current one.

**Budgets** are a spend ceiling per rolling period, in the same minor units as
the `price` schedule — cents for `USD`. Charged from provider-reported usage
rather than from the admission estimate, because the byte-based estimator
over-counts by roughly two and a budget on it would refuse a tenant at half
their allowance. The cost of that choice is a bounded overshoot: requests
already in flight when the budget is crossed still complete.

Periods are fixed rolling windows — `daily` is 24 hours, `monthly` is 30 days —
not calendar months. Exhaustion reports `budget_exhausted`, separately from the
rate limits, because it does not clear when load drops; it clears when the
period rolls. Both partition under `quota_partitions` (`DI-053`).

### Admission queueing

A `quota` with `queued=` non-zero lets a request wait for a concurrency slot
instead of being refused the moment the scope is full:

```text
quota scope=target:local:m concurrency=4 queued=16 class=interactive
```

- **Order** is specification 12's: weighted fair across tenants, by priority
  class, FIFO within a tenant and class. A tenant with sixteen queued requests
  delays another tenant's single request by one place, not sixteen.
- **`class`** is `interactive`, `standard` (the default), or `batch`. A
  principal's class wins over its tenant's.
- **The wait** is the smaller of `settings queue_timeout_ms` (default 5000) and
  what remains of the request deadline, so specification 12's "requests past
  deadline are removed without invoking the provider" holds for a queued request
  too. `queue_timeout_ms=0` disables queueing outright — there is no way to
  express an unbounded wait, because specification 3.2 makes the timeout
  mandatory.
- **Only concurrency queues.** A rate-limit rejection has nothing to wake on, so
  it is reported rather than waited out.
- Without `queued=`, behaviour is unchanged: the scope refuses immediately.

Queue depth and wait are published as `hypellm_queue_depth` and
`hypellm_queue_wait_milliseconds`.

Provider families: `llamacpp` (or `llama.cpp`), `openai`, `anthropic`,
`deepseek`, `moonshot` (or `kimi`), and `generic_openai`. The last requires
`settings allow_generic_adapter=true` — it is refused otherwise
(`crates/hypellm-config/src/build.rs`), per specification 25.

Schemes: `http` (loopback only), `https` (needs the TLS helper), `unix`
(absolute path only).

Validate before deploying:

```
hypellm-router --check --config /etc/hypellm/hypellm.conf
```

which prints provider/target/alias counts and the configuration digest, and
exits 2 with every accumulated error on failure. Validation collects all errors
rather than stopping at the first.

**Parsed but inert.** Two remain: `settings capture_bodies` (there is no
body-capture implementation at all, which is fail-safe but implies a feature
that does not exist) and `tenant retention_days` (no retention or expiry is
implemented for any stored data). Setting either has no effect (`DI-011`).

Three fields were on this list and are now honoured:

- `settings keepalive_interval_ms` — the SSE keepalive cadence. A stream whose
  provider is silent gets a comment at that interval (default 15 s; zero
  disables it).
- `settings metrics_listen` — binds a dedicated listener serving only
  `GET /metrics` and `GET /health/live`. Use it rather than scraping the
  management listener, which means admitting the collector to the control
  plane. Everything else on that address answers 404.
- `credential rotates_after_days` — `GET /admin/v1/credentials` reports
  `last_rotated` and `overdue` against the audit chain. The router does not
  force a rotation: cutting off a working credential on a timer would turn a
  policy into an outage.

---

## Startup

Order (`crates/hypellm-router/src/startup.rs`, `Router::assemble`):

1. Read and validate the configuration file. Invalid → exit 2.
2. Open the state directory, take the lock, replay the log. Integrity failure →
   exit 3.
3. Resume the last durably activated configuration if one exists, otherwise use
   the file. **If a policy has ever been published through the management API,
   the file on disk is ignored** — a reviewed policy must not vanish on a
   restart. To override it deliberately, start once with
   `--adopt-config "<reason>"`: the file becomes a new activation, the reason is
   recorded in the audit chain, and it persists across later restarts
   (`DI-027`).
4. Load the provider credentials the *resumed* configuration declares. Missing
   or empty → exit 5.
5. Check reachability: every `https` endpoint needs `tls_helper_socket`.
   Otherwise → exit 2 with the offending endpoints listed.
6. Build health registry, admission controller, credential store, key store
   (restoring keys and revocations from the log), session store.
7. Bind the inference listener, then the management listener. Failure → exit 4.
8. Bind the control socket. **Failure → exit 4**, deliberately: without it the
   router cannot be drained, and specification 20.1 requires graceful shutdown.
9. Append a `RouterStarted` audit record and serve.

The router logs `store.tail_truncated`, `store.key_records_unreadable`,
`config.activation_resumed` / `config.loaded_from_file`, and `router.started`
with the configuration digest. Alert on the first two.

---

## Shutdown

**The router has no signal handler.** `sigaction` would need `unsafe` FFI, which
specification 18.2 forbids workspace-wide. Shutdown is driven through the
control socket at `settings control_socket` (a Unix socket, path ≤ 100 bytes):

```
hypellm-router --shutdown --config /etc/hypellm/hypellm.conf --secrets /etc/hypellm/secrets
hypellm-router --ping     --config /etc/hypellm/hypellm.conf --secrets /etc/hypellm/secrets
```

**Commands are authenticated.** A control line is `<hex token> <command>`, where
the token is the contents of `<secrets>/control.key` — written by
`--generate-secrets` and narrowed to 0600 with the rest of the bundle. The
socket itself is `chmod`ed to 0600 immediately after bind, and a failure to do
so aborts startup rather than leaving it at the umask. Two controls rather than
one, because either alone is a single mistake from failing open.

Use the flags above rather than `socat`: they read the token from the secrets
directory and send it themselves, so it never enters the process list or shell
history. Sending the line by hand works, but an operator who has to assemble it
will eventually put the token in an argument.

Commands: `shutdown` and `drain` (identical — both set the shutdown flag on both
listeners), and `ping` → `pong`. An unauthenticated line gets `unauthenticated`
and a log entry; an authenticated but unknown one gets `unknown command`.

A bundle generated before `control.key` existed will not start: `--generate-secrets`
into a fresh directory and migrate the other five files, or add a `control.key`
of at least 32 random bytes. The router refuses rather than inventing one,
because a generated token would authenticate the socket with a value no operator
holds.

**Drain waits.** `Server::serve` returns only after the accept loop stops *and*
its connections have drained within `ServerConfig::drain_timeout`; the count
still running at the deadline is reported and logged as `router.drain_incomplete`.
Connections are not killed — each already carries a request deadline and a write
timeout, so they end on their own.

`SIGTERM` from a supervisor is **not** graceful: nothing handles it, so the
process dies immediately and in-flight streams are cut. Handling it needs
`sigaction` or `signalfd`, both `unsafe` FFI, which specification 18.2 forbids
workspace-wide — so the control socket is the router's shutdown mechanism and
`ExecStop=` is how a supervisor reaches it (`DI-033`).

**Use this unit rather than assembling one**, because the `ExecStop=` line is
the whole point and a unit without it drops streams on every restart:

```ini
[Unit]
Description=HypeLLM Router
After=network-online.target

[Service]
Type=simple
User=hypellm
Group=hypellm
ExecStart=/usr/local/bin/hypellm-router --config /etc/hypellm/hypellm.conf \
          --secrets /etc/hypellm/secrets --static /usr/share/hypellm/web
# Graceful shutdown. Without this, systemd sends SIGTERM, nothing handles it,
# and every in-flight stream is cut mid-response.
ExecStop=/usr/local/bin/hypellm-router --shutdown \
         --config /etc/hypellm/hypellm.conf --secrets /etc/hypellm/secrets
# Long enough for the drain to finish; the router bounds its own drain, so this
# only has to exceed it.
TimeoutStopSec=90
Restart=on-failure

# Specification 20.1's process hardening, none of which the router can do for
# itself (DI-003).
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/hypellm /run/hypellm
LimitCORE=0
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

The socket file is removed on clean exit and force-removed before bind, so a
crashed router does not block a restart.

---

## Process hardening

Specification 20.1, item by item, against what exists.

| Requirement (20.1) | Status |
|---|---|
| Dedicated unprivileged user | **Detected, not enforced.** The router cannot drop privilege — `setuid` is `unsafe` FFI — so run it as an unprivileged user from the start. It does check: an effective uid of 0 logs `startup.hardening_missing` at critical. `DI-003` |
| Read-only executable and configuration | Deployment concern. The router opens the configuration read-only and never writes to it. |
| Writable directories separated for state, audit spool, temporary files | Partly. State and secrets are separate directories, and the router writes temporary files only inside the directory it is replacing a file in. There is no audit *spool*: the chain and its checkpoints are exported on request through `GET /admin/v1/audit/export`, not pushed (`DI-030`). |
| No shell, compiler, package manager, or writable executable directory in the image | Deployment concern. The router spawns no subprocess and links no dynamic loader beyond libc. |
| System-call / filesystem / network sandbox | **Detected, not enforced.** No seccomp, no Landlock, no namespace work — all would need `unsafe` FFI. Supply it from systemd (`SystemCallFilter`, `ProtectSystem=strict`, `ReadWritePaths`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`) or the container runtime. The router reads `Seccomp:` and `NoNewPrivs:` from `/proc/self/status` at startup and logs `startup.hardening_missing` if either is absent, so a directive that silently failed to apply is visible. `DI-003` |
| Outbound connections restricted to resolved approved endpoints | Partly. In-process: destinations are administrator-configured tuples, addresses are classified and pinned, redirects are off, proxy environment variables are ignored (`crates/hypellm-net/src/egress.rs`). At the OS level: nothing. An egress firewall is still worth having. |
| Core dumps disabled or restricted | **Detected, not enforced.** Set `LimitCORE=0` / `RLIMIT_CORE=0` in the unit. The release profile uses `panic = "abort"` and `strip = "symbols"`, so a dump would be both likely on panic and full of key material. The router reads the *soft* core limit from `/proc/self/limits` at startup and logs `startup.hardening_missing` if it is non-zero. |
| Memory locking for secret pages | **Not implemented.** `mlock` needs `unsafe` FFI. `hypellm_crypto::Secret<N>` zeroes on drop as a best effort; Rust gives no guarantee against compiler copies. Disable swap, or use an encrypted swap device. |
| Environment scrubbed after startup | **Not implemented.** The router reads no configuration from the environment, so there is little to scrub, but nothing clears what it inherited. `DI-003` |
| Graceful shutdown: stop admission, drain within deadline, cancel remainder, flush audit/state, exit nonzero on integrity failure | **Done.** Admission stops, `Server::serve` drains within `drain_timeout` and reports what was still running at the deadline (`router.drain_incomplete`), the audit `RouterStopped` record and `Store::sync` run, and a failed flush exits nonzero. The remainder is not killed: each connection already carries a request deadline and a write timeout. |

> **Check the first few log lines after a deploy.** Every row above marked
> "detected" is read from `/proc/self` at startup and reported as
> `startup.hardening_missing` at critical, one line per missing property, each
> naming the systemd directive that supplies it. A clean start emits none. This
> is how you find out that a unit-file typo or a container runtime silently
> dropped a directive you believed was in force — the router cannot apply any of
> this, but it can tell you it is not there.

Two properties the build gives you for free, worth stating because they bound
the impact of everything above:

- `#![forbid(unsafe_code)]` at every crate root, verified by `depscan`, so the
  usual memory-safety classes are out of scope.
- No third-party code at all. `cargo tree` shows only workspace path
  dependencies, and the release build runs `--offline`. Verify with:

  ```
  cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .
  cargo run -q -p hypellm-devtools --bin depscan --offline -- --root . --manifest
  ```

  The second emits the content-addressed manifest of release inputs
  (specification 4.1).
