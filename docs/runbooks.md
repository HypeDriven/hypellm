# HypeLLM Router — operational runbooks

These runbooks cover the four operational incidents defined by the project:
provider outage, provider credential rotation, compromised router API key and
Google identity outage. Commands and response fields match the current
management API.

Contents: [Preconditions](#preconditions) · [22.1 Provider
outage](#221-provider-outage) · [22.2 Credential
rotation](#222-credential-rotation) · [22.3 Compromised router API
key](#223-compromised-router-api-key) · [22.4 Google identity
outage](#224-google-identity-outage)

---

## Preconditions

Every management step below assumes an authenticated session on the management
listener. Establish it once and reuse it.

**Where the listener is.** `settings admin_listen` in the configuration file
(`crates/hypellm-config/src/schema.rs`). The inference listener is
`settings inference_listen` and is a separate socket with a separate handler;
`/admin/v1` is not reachable on it at all
(`crates/hypellm-router/src/routes.rs`, exact-path matching).

**How to authenticate.** Sign in through Google OIDC:

1. `POST /admin/v1/auth/google/start` — returns the authorization URL and sets
   the transaction cookie.
2. Complete the Google flow; the browser lands on
   `GET /admin/v1/auth/google/callback`.
3. On success the router sets `__Host-hypellm_session`
   (`Secure; HttpOnly; SameSite=Lax; Path=/`) and returns `csrf_token` in the
   response body (`crates/hypellm-auth/src/session.rs`,
   `crates/hypellm-admin-api/src/handlers.rs`).

**What every request needs.**

| Requirement | Value |
|---|---|
| Session cookie | `__Host-hypellm_session=<token>` |
| CSRF header, on every non-GET/HEAD/OPTIONS request | `x-hypellm-csrf: <csrf_token>` |
| `Origin`, if sent at all, must be on the allowlist | `settings cors_origins` |
| `If-Match`, on mutating endpoints that expose an ETag | the ETag from the preceding GET |

Read the current token at any time with `GET /admin/v1/session`, which also
returns the principal, tenant, roles, and permissions. The CSRF token is
returned in the **body**, never in a cookie.

**The `__Host-` cookie prefix requires `Secure`, which requires HTTPS.** The
router does not terminate TLS (see [`deployment.md`](deployment.md)); the
management listener must sit behind a TLS edge or sign-in will not work in any
modern browser.

**Permissions used below** (`crates/hypellm-core/src/rbac.rs`):
`ReadSummary`, `OperateTargets`, `QuarantineTargets`, `EditPolicy`,
`SimulatePolicy`, `PublishPolicy`, `ManageKeys`, `ManageCredentials`,
`ReadAudit`, `ReadDecisionTraces`.

**Sensitive actions need a recent sign-in.** `ManageCredentials`, `ManageKeys`,
`PublishPolicy`, `ManagePrincipals`, `ManageSettings`, and `BreakGlass` require
an authentication within the last 5 minutes
(`crates/hypellm-core/src/rbac.rs`, `Permission::requires_reauthentication`;
`SessionPolicy::reauthentication_millis`). A session older than that is refused
with `reauthentication_required` — sign in again before starting 22.2 or 22.3,
and note the consequence for 22.4.

**Every mutation below writes a durable audit record before it is reported as
applied.** If the audit append fails, the action is refused with
`internal_fault` and is *not* applied
(`crates/hypellm-admin-api/src/handlers.rs`, `record_audit`).

---

## 22.1 Provider outage

Specification 22.1 steps 9–13. Read the whole runbook before acting: step 3 is
the only *runtime* override — steps 4 and 5 are policy changes, and they go
through the draft → validate → approve → activate path rather than taking effect
on the spot.

### 1. Confirm target health and breaker reason

```
GET /admin/v1/overview        # ReadSummary
GET /admin/v1/targets         # ReadSummary, paginated
GET /admin/v1/traffic         # ReadSummary
```

`overview` returns `targets_total`, `targets_healthy`, `targets_degraded`,
`config_version`, `config_digest`, `audit_head`, `audit_records`.

`targets` returns, per target: `state`, `breaker_state`
(`closed` / `open` / `half_open`), `in_flight`, `total_requests`,
`total_failures`, `quarantined`, plus declared capabilities and cost class
(`handlers.rs`, `render_target`).

`traffic` returns the figures the other two cannot: a rolling rate and latency
window, and the admission limits beside their occupancy. The counters on
`targets` are cumulative since the router started, so the ratio between them is
the average over the whole uptime — on a router that was busy yesterday and is
idle now, it reads as busy. Use `traffic` for "what is happening", `targets` for
"what has happened".

Two things about it are worth knowing before quoting a number from it:

- **Every window reports `covered_millis` as well as `window_millis`.** The rate
  is `requests / covered_millis`, never `requests / window_millis`: a router up
  for thirty seconds has not lived through a minute, and dividing by the nominal
  window would understate it by half.
- **Percentiles are bucket upper bounds.** `p99_millis: 25` means "at or below
  25 ms". A percentile that fell past the largest bucket is `null` with a
  non-zero `above_largest_bucket`, which is "longer than two minutes" rather
  than "two minutes". Specification 19.1's measured distributions come from
  `hypellm-bench`.

Rate and latency are scoped to the caller's own tenant (Appendix B). `attributed:
false` means this tenant's samples were not recorded — the router keeps a bounded
set of per-tenant windows and every one was in use — and is *not* the same as no
traffic. `capacity.available: false` means the deployment attached no admission
controller to the management API.

Neither response contains a provider credential, a provider error message, or
any prompt content. Provider error text is dropped at the adapter boundary;
only a sanitised `type`/`code` token ever survives
(`crates/hypellm-adapters/src/contract.rs`, `safe_detail_for`).

**Two caveats that will mislead you if you do not know them:**

- **`breaker_state` is the worst state across operations**, not the chat one.
  Health is tracked per `(target, operation)`; the summary answers "is anything
  about this target broken", and `breaker_state_by_operation` alongside it says
  which. `targets_healthy` in the overview counts on the same rule, so the two
  views cannot disagree .
- **There is no "breaker reason" field.** The specification asks for one; the
  API exposes counters and a state, not a cause. Use the decision traces and
  logs below to infer it.

For a specific failed request, retrieve its trace:

```
GET /admin/v1/decisions/{request_id}      # ReadDecisionTraces
```

The `request_id` is the `X-Request-Id` response header the client received
(`crates/hypellm-router/src/routes.rs`). The trace holds the policy digest, the
ranked candidates, integer score terms, and exclusion reason codes — and by
construction can hold no prompt, credential, or upstream URL. A trace belonging
to another tenant is reported as **not found**, not as forbidden.

Traces are an in-memory ring of 4 096 entries and are lost on restart
(`crates/hypellm-admin-api/src/decisions.rs`).

### 2. Automatic breaking is already running

Before you intervene, know what the router does on its own
(`crates/hypellm-core/src/health.rs`): a breaker opens on the configured failure
threshold, cools down with a doubling delay capped at `max_cooldown_millis`
(60 s by default), then admits `half_open_probes` (1) concurrent probes and
closes after `half_open_successes_to_close` (3) consecutive successes.

An upstream failure classified `Authentication` deliberately does **not** count
against health (`crates/hypellm-adapters/src/contract.rs`,
`UpstreamErrorClass::affects_health`) — a wrong router credential is a
configuration problem, not an upstream outage, and must not trip a breaker.
That is also why a hostile upstream can suppress breaker input by labelling its
failures `authentication_error`; see `crates/hypellm-adapters/MODULE.md`.

### 3. Quarantine, only when automatic breaking is insufficient

```
GET   /admin/v1/targets                    # capture the target's ETag
PATCH /admin/v1/targets/{id}               # OperateTargets + QuarantineTargets
      If-Match: <etag>
      x-hypellm-csrf: <token>
      {"state":"quarantined","reason":"INC-1234 provider 5xx storm","duration_seconds":3600}
```

`reason` is mandatory and must be non-empty; the request is refused without it.
`duration_seconds` defaults to 3 600. Quarantine expiry uses the **wall clock**
so it survives a restart, which also means a backwards clock step lengthens a
quarantine and a forwards step shortens it (`crates/hypellm-core/src/time.rs`).

Lift it with `{"state":"enabled"}` on the same endpoint; lifting also requires
`QuarantineTargets`, because un-quarantining is a quarantine-level action.

> **`draining`, `maintenance`, `disabled` and `quarantined` all take effect
> immediately.** The state is applied as a runtime override
> (`HealthRegistry::set_admin_state`) that routing prefers over the configured
> `target … state=` value, and the response reads the *effective* state back
> rather than echoing what you asked for — so if a live quarantine outranks a
> weaker state you requested, you will see that.
>
> **The override does not survive a restart.** It is held in memory, and a
> restart re-reads the configuration. The response says so explicitly
> (`persists_across_restart: false`). For a change meant to outlive a restart,
> publish a policy draft (step 4).
>
> `duration_seconds` is capped at 90 days and refused above it. For an
> indefinite removal use `{"state":"disabled"}`, which is what it means anyway —
> a quarantine has a review time by definition (specification 13).

### 4. Take a target out of rotation properly (policy change)

Draining, disabling, or re-ranking a target is a configuration change and goes
through the draft workflow:

```
POST /admin/v1/policies                    # EditPolicy
     {"configuration":"<the full configuration text>"}
POST /admin/v1/policies/{draft}:validate   # EditPolicy or SimulatePolicy
POST /admin/v1/policies/{draft}:simulate   # SimulatePolicy  (see the caveat below)
POST /admin/v1/policies/{draft}:publish    # PublishPolicy, If-Match on the active ETag
```

A draft is the **whole** configuration document, not a patch. Publication is a
durable `ConfigActivation` frame followed by an atomic pointer swap; requests
already in flight keep their prior snapshot.

**A publisher may not be the draft's author.** The refusal lives in
`DraftStore::prepare_publish` and is keyed on the draft, so no second code path
can bypass it. During a single-operator incident this will block you: plan for a
second authorised operator, or accept quarantine (step 3) as the only unilateral
lever.

**Undoing a publication does not need a second operator.**

```
POST /admin/v1/policies:rollback           # PublishPolicy, If-Match on the active ETag
     {"reason":"routing regression, incident 4711"}
```

The reason is required (8–256 characters) and is what a post-incident review
reads. Publication needs two people because it activates something nobody has
reviewed; rollback restores a configuration that was already published under
that rule, so the second signature has already been given — and requiring
another would put the recovery path out of reach exactly when one operator is
awake.

The restored configuration comes back under a **new** version number, not the
old one. `config_version` therefore goes up, never back: two different
configurations must never share a version, since `If-Match` ETags derive from
it. The response reports `restored_from_version` so you can see which one came
back. Eight versions are retained; a rollback with nothing to restore is a
refusal, not a silent no-op.

**Drafts survive a restart** (256 retained, oldest evicted), so one awaiting a
second approver is still there afterwards — during an incident that is the
difference between waiting for a colleague and re-authoring a configuration
under pressure.

> **A restored draft is unvalidated and must be validated again.** The verdict
> is not persisted on purpose: it depends on the configuration grammar the
> running binary implements, so a stored "valid" replayed across an upgrade
> would let a draft that no longer builds be published as though it had been
> checked. Re-run `:validate` after a restart; it costs one call .

### 5. Simulate critical aliases

```
POST /admin/v1/policies/active:simulate?live=true   # SimulatePolicy
POST /admin/v1/policies/{draft}:simulate            # SimulatePolicy
     {"alias":"code-premium","operation":"chat","input_tokens":120000,
      "principal":"user:42","groups":["eng"],"residency":"eu"}
```

The simulation runs the production routing function
(`PolicySnapshot::route`) so it cannot drift from what the router would decide,
and it takes a *size* rather than prompt text — `input_tokens`, never a prompt.
It returns the policy digest, whether the selection was pinned, the ranked
candidates, and the exclusion reasons.

**During an incident, use `active:simulate` with `live=true`.** That routes
against the real health registry — breakers, quarantines, operator overrides,
observed failure rates, remaining capacity — and answers "would this work right
now". Without `live=true` it evaluates against `IdealLiveState`, which answers
"does policy permit this" and is what you want when reviewing a *draft*: a
target that happens to be breaking should not make a policy look wrong.

The response carries `live_state`, so you can tell which question you asked. An
answer of "no eligible target" means something different in each mode
.

> **A simulation reserves nothing and calls no provider** (specification 15.4).
> A live one reads admission and health state without consuming any, so
> simulating cannot cause the rejection it is investigating.
>
> `input_tokens` is bounded ; keep it realistic anyway, since it is
> expanded into filler.

### 6. Do not broaden model families or residency during an incident

This is a procedural rule, and the code supports holding it: residency,
capability, and allowlist constraints are *eligibility filters*, never score
penalties (`crates/hypellm-core/src/policy.rs`, `PolicySnapshot::evaluate`
returns `Err(ExclusionReason)` and never constructs a `Candidate`). There is no
"soften the filter" knob to reach for under pressure, and adding one would be a
compliance bypass expressed as a tuning change.

A higher-precedence deny is sticky downward: no lower-precedence binding can
re-enable it, and an exact-specificity tie ORs the deny bits, failing closed
(`MergedBindings::is_denied`). Adding a permissive binding during an incident
will therefore *not* lift an existing deny.

### 7. After recovery

Half-open probing and closure are automatic (step 2); no operator action is
needed and none is available. Lift any quarantine you set with
`PATCH /admin/v1/targets/{id}` `{"state":"enabled"}`, then watch
`total_failures` and `breaker_state` on `GET /admin/v1/targets`.

**Weight restoration is automatic too.** For thirty seconds after a breaker
closes, the target's health score is ramped back rather than restored at once,
so it takes a growing share of traffic instead of all of it — two successful
probes make a target *probably* healthy, and the cost of "probably" being wrong
is the full load arriving at something still warming up and reopening the
breaker.

> The ramp is a **score** term, never a filter. A recovered target that is the
> only candidate is still chosen; it is merely less preferred than one that has
> been healthy throughout. Do not read a lower rank during that window as the
> target being excluded .

Close the incident against the audit record. `GET /admin/v1/audit` shows the
quarantine and any policy publication, tenant-scoped and cursor-paginated. It
reads a 2 048-entry in-memory ring by default; add `durable=true` to read the
authoritative chain in `<state_dir>/log.bin` instead, which is what an incident
needing evidence should use.

---

## 22.2 Credential rotation

Specification 22.2 steps 14–18.

### Where a provider credential actually lives

- On disk: `<secrets>/credentials/<credential-id>`, one file per `credential`
  record, mode 0600 when the router wrote it
  (`crates/hypellm-router/src/state.rs`, `CredentialStore::store`).
- Read at startup by `Secrets::load_provider_credentials`
  (`crates/hypellm-router/src/startup.rs`), which reads **only** the files the
  configuration declares — a file nobody declared is never read, and a declared
  file that is missing or empty is a startup failure (exit code 5). Trailing
  `\n`/`\r` are trimmed, so `echo key > file` works.
- In memory: `CredentialStore`, reachable only through a scoped borrow inside
  the adapter boundary. No management endpoint can read a secret back; there is
  no handler and no permission for it.
- **Never** in the append-only log, and never in configuration — the
  `credential` record carries `id`, `scope`, `description`, and
  `rotates_after_days`, never a value.

### 1. Write the new credential version

```
POST /admin/v1/credentials/{id}:rotate      # ManageCredentials
     x-hypellm-csrf: <token>
     {"secret":"<the new provider key>"}
```

The endpoint is write-only: the secret is accepted, never echoed, never logged.
The reference must already exist as a `credential` record in the active
configuration — rotating an unknown id returns 404 rather than silently creating
one, because a typo that created a new credential would leave you believing you
had rotated something you had not.

`store_credential` writes `<secrets>/credentials/<id>` atomically, `chmod`s it
to 0600, and only then updates the in-memory value — durable first, so a
rotation reported as applied is not undone by the next restart. If the router
was started without `--secrets` (no credential directory), the endpoint fails
closed with `internal_fault` and the message "this router has no credential
store configured, so the secret was not stored".

`POST /admin/v1/credentials` (same permission, body `{"id":…,"secret":…}`)
creates a new one. It writes the file but does **not** add the `credential`
record to the configuration — do that through a policy draft (22.1 step 4)
before the router will load it at the next start.

### 2. Validate with a low-cost probe

```
POST /admin/v1/credentials/{id}:probe
```

`ManageCredentials`, no body. It issues one request through the ordinary adapter
and dispatch path — the cheapest enabled target that uses the credential, one
output token, ten-second deadline — and answers:

```json
{"id":"provider-secret","ok":true,"target":"openai:gpt","elapsed_ms":412}
```

On failure, `ok` is false and `class` and `provider_code` say what the provider
returned. The provider's *message* is never included: an authentication error is
exactly where a provider echoes the key back.

**Probe immediately after every rotation.** Do not wait for traffic to tell you.
A probe that cannot run — no enabled target uses the credential — is reported as
a refusal, not as a pass; treat that as "unvalidated", because it is.

The probe does not reserve admission capacity, so it cannot be pushed out by
tenant load and cannot push tenant traffic out. It does cost one provider call.

An upstream authentication failure is deliberately reported to the client as
`internal_fault`, not as an auth error, so that a router credential problem is
never mistaken for the caller's key being wrong
(`crates/hypellm-router/src/dispatch.rs`). It also does not trip the breaker. A
bad rotation therefore presents as a quiet per-request 500 — watch the router's
own logs, not the breaker state.

### 3. Activation, and the overlap window

The new value is live the instant `store_credential` returns. There is no
staging step and nothing further to activate.

Specification 22.2 step 16's **bounded overlap** covers one specific mistake:
rotating before the provider has activated the new secret. For five minutes
after a rotation, a request that the provider refuses *on authentication* is
retried once with the superseded secret, so a premature rotation does not take
the target out of service.

> **The window is not a grace period, and it tells on itself.** Any use of the
> superseded secret sets `rotation_unaccepted: true` on the credential, emits a
> `critical` `credential.rotation_unaccepted` log event, and increments
> `hypellm_credential_fallbacks_total`. That flag means *the provider is refusing
> your new credential* — act on it now, because when the window closes every
> request fails at once.
>
> A rotation the provider has already accepted retires the old secret on its
> first success, so the healthy case lasts one request and emits nothing.
>
> **Still rotate in the right order**, because the window is five minutes and
> not a plan: create the new key at the provider, confirm it works, rotate here,
> probe (step 2), and only then revoke the old one at the provider .

### 4. Drain connections whose authentication is connection-bound

Provider authentication in this router is per-request (an `Authorization` or
`x-api-key` header built inside the adapter), so a pooled socket does not carry
a stale credential. The connection pool nonetheless keys on a credential
isolation class, and `ConnectionPool::drain_key` exists so that one rotation
closes only the affected sockets (`crates/hypellm-net/src/pool.rs`).

Rotation drains automatically: the response carries `connections_drained`, the
count of idle pooled sockets that were opened under that credential and have now
been closed. A connection currently serving a request is left alone — it was
authenticated under the old secret and its exchange is already in flight, so
killing it would turn a rotation into a client-visible failure.

> **`connections_drained: 0` is normal.** Provider authentication in this router
> is per-request, so a pooled socket carries no stale credential and there is
> usually nothing that needs dropping. The wiring exists so that a provider with
> connection-bound authentication works correctly without anyone having to
> notice this first .

If you want certainty, restart the router (see
[`deployment.md`](deployment.md#shutdown)); the credential is already durable, so
the restart picks up the new value.

### 5. Revoke the old credential and close the record

Revoke the old key **at the provider**. The router has no notion of a previous
version — the old value was overwritten in step 1 and is not recoverable from
the router.

Confirm no further use by watching the target's `total_failures` and the
router's logs for upstream authentication failures.

The rotation is already recorded: `rotate_credential` appends an
`AuditAction::CredentialRotated` record naming the actor, the credential
reference, and the tenant, and refuses the rotation outright if that record
cannot be written durably. It is in `log.bin`.

**Reading it back.** `GET /admin/v1/audit?action=credential_rotated&durable=true`
shows the rotation, read from the durable chain rather than from the in-memory
ring — so it is there however long ago it happened and across any restart since.

---

## 22.3 Compromised router API key

Specification 22.3 steps 19–22. This is about a *client* key — the
`hypellmk_…` credential a coding harness presents on the inference listener — not
about a provider credential.

### 1. Revoke the key id immediately

```
GET    /admin/v1/keys                # ManageKeys, tenant-scoped, no secret material
DELETE /admin/v1/keys/{key_id}       # ManageKeys
       x-hypellm-csrf: <token>
```

`revoke_key` appends a durable `ApiKeyRevocation` frame **before** revoking in
memory, and refuses the revocation if that append fails. A revocation that never
reached the log would be undone by the next restart, resurrecting the key that
was revoked precisely because it leaked
(`crates/hypellm-admin-api/src/handlers.rs`, `revoke_key`;
`crates/hypellm-router/src/startup.rs`, `restore_keys`).

Revocation is in-process and takes effect on the next verification. It does not
go through the policy draft workflow, so specification 22.3's "revocation
bypasses configuration publication delay" holds: there is no publication delay
in this path at all.

A key that belongs to another tenant returns 404, not 403.

**If a request is in flight when you revoke, it finishes.** Revocation is
checked at authentication, not per-attempt. Streaming responses can therefore
outlive the revocation by up to the request deadline
(`settings default_deadline_ms`, 120 s by default).

### 2. Search the audit and usage record

```
GET /admin/v1/audit?limit=500        # ReadAudit, cursor-paginated, tenant-scoped
GET /admin/v1/usage                  # ReadOwnUsage / ReadTenantUsage
```

> **The view is a window, not the record.** Every management mutation is
> durably audited — `record_audit` refuses the action outright if the append
> fails — and `GET /admin/v1/audit` shows those records for your tenant.
>
> **Pass `durable=true` for an investigation.** Without it the endpoint reads a
> bounded 2 048-entry in-memory ring that does not survive a restart. With it,
> and with any of `actor`, `action`, `since`, or `until`, it reads the
> authoritative chain in `<state_dir>/log.bin`. For anything that has to stand
> up as evidence, use `GET /admin/v1/audit/export`, which emits the chain
> together with the checkpoints that authenticate it.

Audit records carry `sequence`, `timestamp`, `actor`,
`action`, `outcome`, `object`, `tenant`, and where set a `reason` and `source`.
`GET /admin/v1/usage` is unaffected and returns per-(alias, target, operation,
status, cost class) totals for the caller's tenant, distinguishing
provider-reported from router-estimated numbers so an estimate cannot read as a
bill.

> **Searching "by key pseudonym" is not available.** Specification 22.3 step 20
> asks for it. `Pseudonymizer` produces deterministic tenant and principal
> pseudonyms for **log lines** (`crates/hypellm-telemetry/src/logs.rs`), and
> `GET /admin/v1/usage` still carries no key dimension, so "search *usage* by
> key pseudonym" is unmet. For the audit half, filter directly:
>
> ```
> GET /admin/v1/audit?actor=user:someone&action=key_revoked&since=<ms>&until=<ms>&durable=true
> ```
>
> Every parameter narrows and none widens: the tenant filter runs first, so no
> query string reaches another tenant's records. For usage, filter the router's
> structured logs by the principal pseudonym and correlate to the key through
> `GET /admin/v1/keys` .
>
> **`method` distinguishes how a caller authenticated:** `api_key`, `oidc`,
> `break_glass`, or `local_peer`.
>
> The in-memory audit index is a 2 048-record ring and is lost on restart; the
> durable chain in `log.bin` is authoritative. `durable=true` reads it, and
> `GET /admin/v1/audit/export` emits it with its checkpoints.

Also inspect decision traces for suspicious requests, if they are still in the
4 096-entry ring: `GET /admin/v1/decisions/{request_id}`.

### 3. Rotate downstream provider credentials only on evidence

A client key does **not** grant a read of any provider secret. There is no
endpoint, no permission, and no code path that returns one; adapters hold the
only access, through a scoped borrow. A leaked client key lets the holder *spend*
against your providers through the router, and does not disclose the provider
credential itself.

Rotate provider credentials (22.2) only if you have evidence of adapter or
credential exposure — for example filesystem access to `<secrets>/credentials/`,
or a process-memory compromise. Assess the blast radius from
`GET /admin/v1/usage` and the target-level counters.

### 4. Create a least-privilege replacement

```
POST /admin/v1/keys                  # ManageKeys
     x-hypellm-csrf: <token>
     {"principal":"svc:harness-a","scopes":["inference"],
      "expires_at":<unix-millis>,"description":"INC-1234 replacement"}
```

The secret is returned **exactly once**, in the creation response, and is never
retrievable again (`NewKey::into_secret`, and the type is not `Clone`).
`list_keys` returns no secret and no verifier material.

At least one scope is required. The scope vocabulary is closed —
`inference`, `embeddings`, `models`, `tokenize`, `management:read`,
`management:write` (`crates/hypellm-auth/src/apikey.rs`, `Scope::as_str`) — and an
unknown scope string is rejected. A browser session carries an **empty** scope
set by design (`Principal::from_session`), so a CSRF against the admin UI can
never spend a tenant's token budget.

The key is created in the **creating session's tenant**, not in a tenant named
in the request.

Pin the replacement to the network it will actually be used from — that is the
least-privilege step this runbook exists for:

```json
{"principal":"svc:worker","scopes":["inference"],
 "source_networks":["10.2.0.0/16"]}
```

Each entry is a CIDR block; a bare address is refused, so write `/32` if you
mean one host. Omitting `source_networks` gives an unrestricted key, and a
listing shows `null` for one. A restricted key whose peer address cannot be
determined **fails closed** — worth knowing if the key will be used from behind
a proxy that does not preserve the source address .

Document the incident in the audit trail by attaching a `description` to the
key; key creation and revocation both append audit records automatically.

---

## 22.4 Google identity outage

Specification 22.4. **Read this section before you need it, and preprovision the
break-glass token now** — it is minted once by `--generate-secrets`, printed
once, and cannot be recovered afterwards. See [Break-glass
access](#break-glass-access) below.

### Before an outage: bind the identities

Sign-in resolves a Google account to a local principal through an `identity`
record, and refuses any account that has none. A deployment with no `identity`
records has nobody who can sign in — which fails closed correctly, but is
discovered at the worst moment.

```text
identity issuer=https://accounts.google.com subject=<the sub claim> \
         principal=user:alice tenant=acme description="on-call"
role_binding subject=principal:user:alice role=operator
```

The `subject` is the `sub` claim, not the email address: specification 9.1
makes `(iss, sub)` the stable identity because an email can be reassigned to a
different person. The `tenant` is explicit for the same reason — it decides
whose data that operator sees.

`GET /admin/v1/access` lists the identities, service principals, groups and
live sessions of your tenant, which is the fastest way to check who can
currently reach the management plane. `GET /admin/v1/settings` reports whether
sign-in is configured at all (`oidc.configured`, `oidc.verifier_configured`)
without disclosing the verifier's socket path.

### What happens automatically

- **Existing sessions continue** until their configured lifetime expires:
  30 minutes idle, 12 hours absolute by default, overridable through
  `settings session_idle_secs` and `settings session_absolute_secs`
  (`crates/hypellm-auth/src/session.rs`, `SessionPolicy`;
  `crates/hypellm-router/src/startup.rs`).
- **New sign-ins fail closed.** `oidc_start` requires a configured
  `OidcConfig`; `oidc_callback` requires the verifier to return claims. An
  unreachable verifier maps to `OidcError::VerifierUnavailable` and a refusal to
  `OidcError::SignatureInvalid` — both are rejections. `parse_claims` returns
  nothing without `iss` and `sub`, and defaults `email_verified` to `false`, so
  an absent claim can never read as verified
  (`crates/hypellm-net/src/helper.rs`, `crates/hypellm-auth/src/oidc.rs`).
- **The inference data plane is unaffected.** It authenticates with router API
  keys and never consults the identity verifier
  (`crates/hypellm-router/src/routes.rs`, `authenticate`). A Google outage is a
  management-plane outage only.

### Do not do this

The specification is explicit and so is the code's shape: **the router MUST NOT
disable authentication or accept unverified identity claims to restore
convenience.** There is no configuration flag that skips verification, no
"trust the id_token without checking" path, and `validate_claims` is the single
place `iss`, `aud`, `exp`, and `nonce` are checked so a check cannot be skipped
on one of two paths. Removing `oidc_verifier_socket` from the configuration does
not weaken authentication — it disables sign-in entirely, which is the correct
failure.

### Break-glass access

Specification 22.4's preprovisioned local method. It does not touch the identity
provider, because the case it exists for is that provider being unreachable.

**Preparation, before you need it.** `--generate-secrets` prints the token once
and stores only a verifier; the token is yours to keep offline. Then declare who
it authenticates as:

```text
settings break_glass_principal=user:oncall break_glass_tenant=acme \
         break_glass_ttl_secs=900
role_binding subject=principal:user:oncall role=break_glass_admin
```

Both settings are required. Omit either and the endpoint returns 404 — a
deployment with no preprovisioned token should not advertise that the path is
live. The `role_binding` is required too: the token establishes *who* you are,
not *what* you may do, and a principal with no binding is refused rather than
handed a session that fails at every endpoint.

**Use.** The admin application offers it on the sign-in screen, under
**Use break-glass access** — and reveals it by itself when Google sign-in
answers `not_found`, which is what a deployment with no `oidc` record answers.
That is the path to prefer during an incident: it is the same endpoint, and it
keeps the token out of a shell history.

Directly, for automation and for a router serving no static assets:

```
curl -X POST https://admin.example/admin/v1/auth/break-glass \
     -H 'Content-Type: application/json' \
     -d '{"token":"<the offline token>","reason":"google oidc unreachable, incident 4711"}'
```

The reason is mandatory (8–256 characters) and is what a later review reads. It
is checked *before* the token, so the endpoint answers identically whether or
not the caller holds one.

The response sets the session cookie and returns `csrf_token` and
`expires_in_seconds`. The session's absolute lifetime is
`break_glass_ttl_secs`, independent of the ordinary twelve-hour ceiling and
clamped to it; when the window closes the session stops working, whether or not
it has been in continuous use.

**What it records.** `break_glass_opened` with the reason, `break_glass_closed`
on sign-out, and a `login_failed` record on every refusal — all in the durable
chain and all visible in `GET /admin/v1/audit`. Each also emits a `critical` log
event, which is what your alerting should key on:

```
event=auth.break_glass_opened
event=auth.break_glass_closed
event=auth.break_glass_refused
```

Alert on all three. A refusal means either an operator with a stale copy of the
token or someone probing the recovery path, and both are worth waking somebody
for.

**Sign out when done.** `POST /admin/v1/logout` writes the closing record, which
is what gives a review the window rather than only its start. An expiring
session leaves no closing record; the opening one carries the lifetime, so the
window is still bounded, but explicitly closing is better evidence.

> **The reauthentication rule still applies.** `Permission::requires_reauthentication`
> covers credential changes, key management, and policy publication, and it
> requires an authentication within the last 5 minutes. A break-glass session
> authenticates at issue, so those actions are available for the first five
> minutes of the window. Plan the sensitive step first.

### What you can actually do during an outage

1. **Use break-glass.** That is what it is for; see above. The remaining steps
   apply when no break-glass token was preprovisioned, or when it too has been
   lost.

2. **Keep an open session.** If an operator already has one, do not log out —
   `POST /admin/v1/logout` is irreversible until Google returns. Note the
   absolute lifetime: a 12-hour ceiling applies regardless of activity, and
   sensitive actions additionally require a re-authentication within the last
   5 minutes (`SessionPolicy::reauthentication_millis`), which a Google outage
   makes impossible. In practice a long outage locks out even an open session
   for privileged operations.

3. **Verify the outage is Google's, not yours.** The verifier is a local Unix
   socket at `settings oidc_verifier_socket`. Check the socket exists and the
   helper process is running before blaming the identity provider — an
   unreachable *local* verifier is indistinguishable from an unreachable Google
   from inside the router, and both surface as `VerifierUnavailable`. An
   oversized token is also reported as `VerifierUnavailable`, so this signal is
   not precise (`crates/hypellm-net/src/helper.rs`).

4. **The data plane needs nothing.** Inference continues on the existing
   configuration and existing API keys. Resist the temptation to restart the
   router "to clear it": a restart drops every management session and, with
   Google down, leaves the control plane unreachable. The router does resume the
   last durably activated configuration on restart
   (`startup::resume_activation`), so routing itself survives — but you will
   have no way back into `/admin/v1`.

5. **Emergency configuration changes go through the file, with a restart.** The
   configuration file named by `--config` is validated at startup and, if no
   activation is recorded in the state log, becomes the active configuration.
   Validate first without touching the running process:

   ```
   hypellm-router --check --config /etc/hypellm/hypellm.conf
   ```

   which prints the provider, target, and alias counts and the digest, and exits
   2 on any error.

   > **Editing the file is not enough on its own.** If a policy has ever been
   > published through the management API, startup resumes *that* configuration
   > from the durable log and ignores your edited file — which is correct, or a
   > reviewed policy would vanish on a restart.
   >
   > To override it, start once with the reason recorded:
   >
   > ```
   > hypellm-router --adopt-config "google outage, reverting to file, incident 4711" \
   >              --config /etc/hypellm/hypellm.conf --secrets /etc/hypellm/secrets
   > ```
   >
   > This writes the file as a new activation and appends a `config_adopted`
   > audit record, so the override is attributable afterwards and persists
   > across later restarts. It is **not** the old workaround of starting against
   > an empty state directory, which discarded the audit chain and every stored
   > API key .

6. **Review afterwards.** Every break-glass window is in `GET /admin/v1/audit`
   with its reason. Read them after the incident, not during it.

### Preparing before the next outage

- **Preprovision a break-glass token and store it offline**, and check that the
  principal it names still has its `role_binding`. A token whose principal lost
  its binding fails at exactly the moment you need it, and nothing tells you
  before then.
- Keep at least two operators with `PublishPolicy` (publication requires a
  distinct approver, so one operator alone cannot change policy even with a
  session).
- Keep the configuration file on disk in sync with the last published policy, so
  the file-adoption path in step 5 is a viable last resort rather than a rewrite.
- Take routine backups of the state directory (`Store::backup_to`, or a copy of
  a quiesced directory) so the destructive path in step 5 is recoverable.

## 22.5 Fleet incidents

The fleet is the set of accelerator hosts behind the aliases, and its failures
look different from a provider outage: the model an alias points at may be
correct, declared, and simply *not running*. Specification §26 and
[orchestration.md](orchestration.md) are the design; this is what to do at three
in the morning.

### Symptom: requests refused with "the requested capability is not available"

The data-plane error names nothing on purpose — host identifiers and residency
are management-plane data — so the diagnosis happens on the Fleet screen or:

```bash
curl -s --unix-socket /dev/null https://admin.example/admin/v1/fleet | jq .
```

Read `observation_age_ms` **first**. It gates every other decision:

| What you see | What it means | What to do |
|---|---|---|
| `null` | The router has never reached an agent. This is not "0 seconds"; it is "never". | Check the agent is running and the socket path in `fleet_agent` matches. |
| Larger than `observation_max_age_ms` | Belief has expired. Cold targets are ineligible and no plan will execute; warm ones keep serving. | Check the agent's process and the SSH path to each host. Nothing will start until an observation succeeds. |
| `digest_agreed: false` | The router and an agent disagree about what the identifiers mean. **No deployment will be started or stopped.** | Compare the digests (below) and reconcile the two files. Do not restart the agent hoping it clears — it will not. |

### Reconciling a digest mismatch

The two sides compute the digest independently, from two different files:

```bash
agent/fleet-agent --config /etc/hypellm/fleet.json --print-digest
hypellm-router --check --config /etc/hypellm/hypellm.conf   # prints "fleet digest ..."
```

They cover identifiers, placement, and architecture — not timings or governance,
so a dwell floor can be retuned without touching the agent. A mismatch means a
host, accelerator, deployment or artifact was added, removed, renamed or moved
on one side only. Fix the file that is wrong, then restart the agent (the router
picks the new digest up on its next configuration activation).

Fail closed is deliberate here. A router and an agent that disagree about what
`spark-music3` means must not act on that disagreement: the failure mode of
acting is stopping the wrong production model.

### Symptom: a model will not start

Ask the planner directly rather than guessing. It is a pure function, so this
changes nothing:

```bash
curl -X POST https://admin.example/admin/v1/fleet:simulate \
     -H 'content-type: application/json' \
     -d '{"target":"spark:minimax-music3","patience_ms":900000}'
```

The reply carries the class, the estimated time to ready, the steps it would
take, and — when it refuses — the reason code:

| Reason | Meaning | Response |
|---|---|---|
| `deployment_in_dwell` | Something that would have to be evicted has not been resident long enough, or the deployment itself is inside its reactivation cooldown. | Wait. The trace shows how long. This is the mechanism working. |
| `eviction_value_insufficient` | There *is* an admissible eviction set and it is large enough; the incoming demand simply does not beat its retention value by the configured margin. | Nothing is broken. Lower `eviction_margin_permille`, raise the deployment's `retention_weight`, or accept the answer. |
| `host_capacity_insufficient` | No admissible set frees enough memory — usually because everything else on the host is pinned, not evictable, or not router-owned. | Check `pinned` and `router_owned` on the Fleet screen. A deployment the router did not start is never evicted by it. |
| `activation_budget_exhausted` | The host has spent its hourly allowance. | Wait, or raise `max_activations_per_hour` deliberately. It is a hard ceiling on purpose: it is what bounds the worst case. |
| `activation_exceeds_deadline` | The model takes longer to load than the request has left. | Raise the alias's deadline. A three-minute model cannot serve a thirty-second request, and offering it would turn a fast failure into a slow one. |
| `artifact_unavailable` | The artifact is absent, on the wrong architecture, or fetching is not permitted. | Place it out of band, or grant `fleet.fetch` and set `allow_fetch=true` deliberately. |

### Symptom: the fleet is swapping constantly

Read `hypellm_fleet_thrash_ratio_permille`. It is activations per thousand
requests served from activated deployments. A healthy fleet trends toward zero
as batching amortises each swap; a value near 1,000 means every request costs a
swap and the configuration is wrong.

The usual causes, in the order they are worth checking:

1. **Two capabilities that cannot co-reside, both in demand.** Raise
   `min_resident_ms` on both. It costs responsiveness and buys throughput,
   because each swap costs minutes.
2. **`eviction_margin_permille` too low.** Two capabilities of near-identical
   value trade places on noise. Raise it.
3. **`activation_max_wait_ms` too short.** Batching is what turns ten requests
   into one swap; too short a window defeats it.
4. **A model that keeps failing to stay up.** Check the Activations screen for
   repeated `failed` outcomes on one deployment. The flap counter is already
   backing it off; the underlying problem is on the host.

### Stopping the fleet moving at all

Two levers, in increasing order of bluntness:

```text
# One deployment: the planner stops considering it for eviction.
PATCH /admin/v1/fleet/deployments/spark-qwen38  {"pinned": true}

# One deployment: routing demand can no longer start it, only an operator.
PATCH /admin/v1/fleet/deployments/spark-music3  {"autostart": false}
```

and, in the configuration, `fleet_enabled=false` — which leaves every record
declared and validated while the router opens no agent socket, takes no
observation, and routes exactly as it did before orchestration existed.

An operator action bypasses the *demand* threshold, because a person asking is
demand enough. It does not bypass the dwell floor, the cooldown, the
concurrency limit, or the activation budget. Those protect the fleet from every
caller, and an operator who could step over them would find the protections
absent at exactly the moment an incident makes them want to.

### After an incident

Every start and stop is in the audit chain — `fleet.activate`, `fleet.evict`,
`fleet.rollback`, `fleet.forced_stop` — and each names either the operator or
the decision identifier that caused it. The Activations screen links each row to
the decision trace, so "why did this model stop" resolves to a specific request.
