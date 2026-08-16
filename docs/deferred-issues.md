# Deferred issues register

Appendix C requires that "all normative requirements are traced to code, test,
or **explicit deferred issue**". This file is that third category: the honest
inventory of where the implementation departs from the specification, and where
a normative requirement has no implementation at all.

`crates/hypellm-router/src/server.rs` cites this file by name for its concurrency
deviation (`DI-001`).

**How to read an entry.** Each has: what the specification requires, what the
code does instead, why, and what would resolve it. An entry is not an excuse —
it is a commitment that the gap is known, bounded, and visible to whoever is
deciding whether to deploy.

**Where this register stands.** Of 55 entries: **49 resolved**, **3 partly
resolved** (each states which half remains and why), and **3 accepted
deviations** — decisions rather than backlog. Nothing is unclassified, and
nothing is merely waiting.

All three remaining deviations share one cause, stated once here and again in
each entry: specification 18.2 forbids `unsafe` workspace-wide, and an event
loop (`DI-001`), privilege drop and sandboxing (`DI-003`), and signal handling
(`DI-033`) each need FFI to implement. There is no code to write for any of
them, only a decision to record. Each carries whatever mitigation *was*
reachable in safe Rust — a tunable connection-stack ceiling, a startup report of
every specification 20.1 hardening property the operating system is not
enforcing, an authenticated control socket with a documented `ExecStop=` — and
none of those changes the classification. Reporting a missing sandbox is not a
sandbox.

They stop being deviations the day specification 4's exception profile admits
the corresponding dependency under a formal security decision record — not
before, and not by being reclassified.

`DI-047` used to sit in this group and no longer does. It recorded the absence of
`POST /admin/v1/targets`, on the grounds that creating a target through the API
would bypass the draft, review, and approval path specification 11 makes the only
way configuration changes. That reasoning was right about direct mutation and
wrong to stop there: the entry's own closing sentence named a shape that keeps
the control — a draft-generating convenience — and building that closed it.

The three partials each name what is left and what it waits on. `DI-029` has the
quota arithmetic for a fanned-out data plane — specification 12's "conservative
node partitions" — and still has no config distributor, no replication, and no
leader election; two routers must not share a state directory. `DI-037` has its
retention, accumulator, and observability halves done — backpressure is measured
even though it cannot be tuned — and its watermark needs the event loop that
`DI-001` defers, for a reason stated in the entry rather than by association: the
streaming path has no buffer between the upstream read and the client write, so
there is nothing for a watermark to be a threshold *of*. `DI-048` has its price
schedule implemented and its tokenizer still deferred to phase 4 by
specification 25. None is waiting on someone to get to it.

One thing this register does **not** claim: `DI-002` is closed, but its fuzz
engine is seeded rather than coverage-guided and does not shrink. Read its entry
before treating a green fuzz run as evidence of absence.

`DI-052` and `DI-053` are worth reading for how they were found rather than for
what they say.
Appendix C requires every normative requirement to trace to code, test, or an
entry here — and an audit *of that traceability*, rather than of the code, found
a specification 3.2 sentence with four clauses of which one had been
implemented and three had never been examined. Following the unexamined ones led
to a defect that made the router remotely and permanently unbootable by an
unauthenticated caller. A register can be complete about everything it lists and
still be missing an entry.

The audit that followed ran in two passes, and the second only happened because
the first was described as finished when it was not. Appendix C has **eight**
items and the first pass covered one of them — "all normative requirements are
traced" — which found the alias admission layer (`DI-053`) and the
`module-documentation` gate that enforced three of the six declarations its own
failure message quoted. Auditing the other seven items found two more: the
disk-full resilience scenario had never been demonstrated, and behind it two
defects (`DI-054`); and the definition of done claims the static application
passes accessibility tests, of which there were none. The application turned out
to be correct — `field` pairs a `<label for>` with every control — so
`web-labelled-controls` prevents a regression rather than fixing a defect, which
is worth stating plainly.

Both the MODULE.md gate and the first version of that accessibility rule shared
a defect worth naming, because it is invisible in review: an escape hatch broad
enough that the rule can never fail. The first checked `Limits` as a substring,
and the word appears in every `MODULE.md`'s prose. The second accepted any
`el('label')` anywhere in the file, so one correctly labelled control vouched for
every other one beside it. Both passed their own test suites. A rule is only
worth its line count if something can make it fail, and the only way to know is
to try.

**Audits run against this register, and what they found.** Three systematic
sweeps, in the order they happened, because the later ones only exist because
the earlier ones were described as finished before they were:

| Sweep | Scope | Outcome |
|---|---|---|
| Enumerated requirements | All 26 multi-clause normative sentences, element by element | 24 complete; the alias admission layer (`DI-053`) and the `module-documentation` gate were partial |
| Appendix C | All 8 definition-of-done items | 6 complete; disk-full recovery undemonstrated (`DI-054`), accessibility unenforced (`web-labelled-controls`) |
| Appendix B | All 10 invariants, plus every management endpoint for tenant isolation | Clean. Twenty-plus isolation tests across drafts, keys, sessions, traces, audit, and aliases; `/admin/v1/settings` is router-wide rather than tenant-scoped and sits behind `ManageSettings`, which only `BreakGlassAdmin` grants |

A clean sweep is worth recording so the next reader does not repeat it, and
worth dating so they know when it stops being evidence.

**Verification basis.** Every entry below was checked against the source at the
time of writing. Several `MODULE.md` threat notes describe defects that have
since been fixed — notably the `groups_for` group-membership bug, the derived
`Debug` implementations over key material in `hypellm-auth` / `hypellm-store` /
`hypellm-telemetry`, the unverified snapshot metadata MAC, the missing egress
profile in the connection pool key, the blocking-DNS path, the failure-open
`parse_model_selector`, the `u64::MAX` token-bucket freeze, the global audit
listing, and the metrics exposition on the inference listener. Those are **not**
listed here because they are closed. Where a `MODULE.md` and this register
disagree, check the code.

**Entries marked Resolved.** Forty-nine entries — DI-002, DI-004, DI-005,
DI-006, DI-007, DI-008, DI-009, DI-010, DI-012, DI-013, DI-014, DI-015, DI-016,
DI-017, DI-018, DI-019, DI-020, DI-022, DI-024, DI-025, DI-026, DI-027, DI-030,
DI-031, DI-032, DI-034, DI-035, DI-036, DI-038, DI-039, DI-040, DI-041, DI-042,
DI-011, DI-021, DI-023, DI-028, DI-043, DI-044, DI-045, DI-046, DI-047, DI-049,
DI-050, DI-051, DI-052, DI-053, DI-054, DI-055 — are closed, DI-055 most
recently. DI-029, DI-037, and
DI-048 are *partly* resolved and stay open for the remainder.

**Entries marked "accepted deviation"** — DI-001, DI-003, DI-033 — are
decisions, not backlog. Each names the condition
under which it would be revisited; most of them are specification 4's exception
profile admitting a dependency the workspace currently forbids.

The first six were written while the corresponding work was in progress and were
closed before this register was first read; the rest were closed afterwards, by
the work described in each entry. Each keeps its original description, with a
note saying what closed it. They are retained rather than deleted because the record of what was missing, and of how it was
found, is worth more than a shorter list. A register that only ever grows is
suspicious; one that quietly loses entries is worse.

**Keeping this honest.** An entry here is a commitment, so the failure mode to
guard against is the register drifting out of date in the *comfortable*
direction: a defect fixed and left listed makes the project look worse than it
is, but a defect introduced and never listed makes it look better. When you fix
something here, mark it Resolved and say what closed it. When you find something
new, add it before you decide what to do about it.

---

## Index

| ID | Summary | Specification | Severity |
|---|---|---|---|
| [DI-001](#di-001) | Thread-per-connection instead of an event loop | 3.2, 2.1 | Accepted deviation (stack now tunable) |
| [DI-002](#di-002) | No fuzz targets anywhere; test corpus is empty | 21, 18.2 |  **Resolved** |
| [DI-003](#di-003) | No privilege drop, sandbox, or environment scrub | 18.1, 20.1 | Accepted deviation (hardening is reported) |
| [DI-004](#di-004) | Control socket is unauthenticated | 20.1 |  **Resolved** |
| [DI-005](#di-005) | Break-glass authentication is not implemented | 22.4, 9.2 |  **Resolved** |
| [DI-006](#di-006) | OIDC principals all land in the first tenant | 9.1, App. B |  **Resolved** |
| [DI-007](#di-007) | `:simulate` accepts an unbounded `input_tokens` | 3.2 |  **Resolved** |
| [DI-008](#di-008) | Quarantine `duration_seconds` is unbounded and can overflow | 3.2 |  **Resolved** |
| [DI-009](#di-009) | Credential isolation class has an ambiguous delimiter | 19 |  **Resolved** |
| [DI-010](#di-010) | `PATCH /targets/{id}` cannot drain, disable, or set maintenance | 16, 22.1 |  **Resolved** |
| [DI-011](#di-011) | Configuration fields parsed but never read | 10, 17, 20 |  **Resolved** |
| [DI-012](#di-012) | `PinnedDestination` is a discipline, not a capability | 10 |  **Resolved** |
| [DI-013](#di-013) | Policy drafts are in-memory only | 15.3, 15.4 |  **Resolved** |
| [DI-014](#di-014) | Metric cardinality backstop blinds a metric permanently | 17 |  **Resolved** |
| [DI-015](#di-015) | Startup does not verify the audit chain | 11.2, 17 |  **Resolved** |
| [DI-016](#di-016) | Deployment-wide listings are not tenant-scoped | 15.4, App. B |  **Resolved** |
| [DI-017](#di-017) | Breaker state is reported for `Chat` only | 13, 22.1 |  **Resolved** |
| [DI-018](#di-018) | Simulation uses `IdealLiveState` and only runs on drafts | 15.4, 22.1 |  **Resolved** |
| [DI-019](#di-019) | No gradual weight restoration after recovery | 22.1 |  **Resolved** |
| [DI-020](#di-020) | No credential probe endpoint | 22.2 |  **Resolved** |
| [DI-021](#di-021) | No dual-accept credential overlap window | 22.2 |  **Resolved** |
| [DI-022](#di-022) | `drain_key` is not wired to credential rotation | 22.2 |  **Resolved** |
| [DI-023](#di-023) | No audit or usage search by key pseudonym | 22.3 |  **Resolved** |
| [DI-024](#di-024) | `AuthMethod` has no `ApiKey` variant | 17, 22.3 |  **Resolved** |
| [DI-025](#di-025) | Audit views read a 2 048-entry ring, not the durable chain | 17, 22.3 |  **Resolved** |
| [DI-026](#di-026) | API-key source restrictions cannot be set through the API | 9.2 |  **Resolved** |
| [DI-027](#di-027) | A published activation permanently shadows the config file | 11 |  **Resolved** |
| [DI-028](#di-028) | No Unix-socket listener | 20 |  **Resolved** |
| [DI-029](#di-029) | No HA or multi-node (quota partitioning done) | 11.2, 12, 20 | **Partly resolved** |
| [DI-030](#di-030) | Audit checkpoints are produced but never exported | 11.2, 17 |  **Resolved** |
| [DI-031](#di-031) | Listener caps and timeouts are compile-time constants | 3.2 |  **Resolved** |
| [DI-032](#di-032) | `/health/ready` discloses config version and digest pre-auth | 8 |  **Resolved** |
| [DI-033](#di-033) | No signal handling | 20.1 | Accepted deviation |
| [DI-034](#di-034) | Shutdown does not drain | 20.1 |  **Resolved** |
| [DI-035](#di-035) | `--generate-secrets` writes key files under the umask | 10, 20.1 |  **Resolved** |
| [DI-036](#di-036) | Provider `Retry-After` is never read | 6.5, 7.1 |  **Resolved** |
| [DI-037](#di-037) | No stream watermarks; decoded events retained per attempt | 14, 3.2 | **Partly resolved** |
| [DI-038](#di-038) | Entropy failure degrades request identity instead of failing | 17 |  **Resolved** |
| [DI-039](#di-039) | `testing` modules are ungated public API | 18.2, 4.1 |  **Resolved** |
| [DI-040](#di-040) | No benchmark suite | 19, 19.1 |  **Resolved** |
| [DI-041](#di-041) | No harness-compatibility profiles or golden-server corpus | 8.1, 21 |  **Resolved** |
| [DI-042](#di-042) | Mid-file log corruption silently discards everything after it | 11.2 |  **Resolved** |
| [DI-043](#di-043) | Audit field caps are asymmetric between write and read | 17 |  **Resolved** |
| [DI-044](#di-044) | `Log::replay` streams through a bounded window | 3.2 |  **Resolved** |
| [DI-045](#di-045) | Adapter `encode_headers` fails open on a non-UTF-8 credential | 7.1 |  **Resolved** |
| [DI-046](#di-046) | No rollback endpoint | 15.3, 16 |  **Resolved** |
| [DI-047](#di-047) | `POST /admin/v1/targets` proposes a draft | 16 |  **Resolved** |
| [DI-048](#di-048) | No tokenizer (price schedule implemented) | 12, 25 | **Partly resolved** |
| [DI-049](#di-049) | Log volume is unbounded per unit time; `StderrSink` blocks | 3.2, 17 |  **Resolved** |
| [DI-050](#di-050) | Manifests declare dependencies the source never uses | 4.1 |  **Resolved** |
| [DI-055](#di-055) | A foreign log was erased and reported as a torn tail | 11.2 |  **Resolved** |
| [DI-054](#di-054) | Disk-full recovery undemonstrated; audit chain and replay bound | 21, C |  **Resolved** |
| [DI-053](#di-053) | Specification 12's alias, byte-rate, and budget admission layers | 12, 11.1 |  **Resolved** |
| [DI-052](#di-052) | Unauthenticated sign-in failures could fill the durable log | 3.2, 22.4 |  **Resolved** |
| [DI-051](#di-051) | `GET /admin/v1/audit` returns nothing in production | 17, 22.2, 22.3 |  **Resolved** |

---

## Part 1 — Stated deviations

Places where the code deliberately does something other than what the
specification describes.

### DI-001
**Thread-per-connection instead of a fixed event loop.**

*Specification 3.2:* "Use a fixed set of event-loop workers. Each connection is
represented by an explicit state machine… No request may create an unbounded
thread, task, buffer, channel, retry loop, or log entry." Specification 2.1
targets 20 000 concurrent streams.

*What the code does:* `crates/hypellm-router/src/server.rs` spawns one thread per
connection with a 512 KiB stack, bounded at accept time by
`ServerConfig::max_connections` (4 096 inference, 256 management). Past the cap
the listener answers 429 and closes rather than queueing.

*Why:* an epoll-driven event loop needs either `unsafe` FFI to `epoll_create1`,
which specification 18.2 forbids workspace-wide, or an approved low-level crate
under specification 4's exception profile. Neither is in place, and a blocking
implementation that is *correct* and bounded is a better starting point than an
unreviewed unsafe one.

*What it costs:* the 20 000-stream target. Memory is `max_connections` ×
(stack + per-stream buffers), so the practical ceiling is far lower than
4 096 concurrent streams on a small node. Correctness is not affected: every
bound, deadline, and cancellation path in the specification is still enforced.

*Mitigated:* the stack is no longer a constant compiled into the binary.
`settings connection_stack_kib` moves it between 128 KiB and 8 MiB
(`startup::listener_config`), which is the one term of that product an operator
can actually trade. The default stays 512 KiB — small on purpose, because the
platform default of 8 MiB would make even the 4 096 the profile admits
unreachable. This does not resolve the entry: it makes the ceiling explicit and
tunable rather than raising it.

*Resolution:* an approved async runtime or `mio`-equivalent under specification
4's exception profile, or an in-repo epoll wrapper behind a formal security
decision record. `Handler` receives a parsed head and a writer, so replacing the
accept loop does not touch a handler.

### DI-021
**No dual-accept overlap window on credential rotation.**

*Specification 22.2 step 16:* "Activate new reference atomically with bounded
overlap."

*What the code does:* `CredentialStore` holds exactly one value per
`CredentialRef`. `POST /admin/v1/credentials/{id}:rotate` writes
`<secrets>/credentials/<id>` and replaces the in-memory value; the next request
uses the new secret. The handler reports this honestly, returning
`"overlap_seconds": 0` and a note saying the router does not run a dual-accept
window (`crates/hypellm-admin-api/src/handlers.rs`, `rotate_credential`).

*Why:* an overlap window means holding two live secrets per reference and
deciding per-request which to present, with a timer to retire the old one. That
doubles the credential surface in memory and adds a state machine to the one
place the specification is most emphatic about keeping narrow.

*Consequence for operators:* the new secret must be valid at the provider
*before* rotating. There is no fallback to the old value. Documented in
[`runbooks.md` 22.2](runbooks.md#222-credential-rotation).

**Resolved**, and the objection recorded above is answered rather than
overruled — it was right about the danger, and the design is shaped around it.

The concern was that holding two live secrets adds a state machine to the
narrowest part of the system. The sharper concern, which the original entry did
not name, is that **a fallback that quietly works is how a bad rotation stays
invisible** — until the window closes and every request fails at once,
uncorrelated with the change that caused it. That is worse than the hard cutover
it replaces.

So the window is not a grace period. It is a safety net that reports itself:

- **Only on an authentication failure, only before acceptance, only once.**
  Nothing has reached the client and no inference was billed, so falling back
  costs one extra exchange and cannot duplicate work.
- **A success with the *current* secret retires the old one immediately.** In a
  healthy rotation the overlap lasts one request and nothing is emitted — which
  is what keeps the alarm meaningful.
- **Every use is loud**: a `critical` log event, `hypellm_credential_fallbacks_total`,
  and `rotation_unaccepted` on the credential listing. That flag keys on the old
  secret having *actually served a request*, not on a window existing, so it
  says "the provider is refusing your new credential" rather than "a rotation
  happened recently".
- **Bounded** at `CREDENTIAL_OVERLAP_MILLIS` (5 minutes) regardless.

`CredentialStore::rotate` is separate from `set`, which *loads* a value at
startup: loading is not a rotation and must not open a window, or every restart
would look like one. And a first activation opens no window, because a creation
has nothing to fall back to.

Note the interaction with `DI-020`: the probe is still the right thing to run
after a rotation. The window keeps a premature rotation from becoming an outage;
the probe tells you it happened. Neither replaces the other.

*Resolution:* a two-slot `CredentialStore` entry with a retire-after timestamp,
plus adapter support for presenting a specific slot. Not planned; the
create-verify-rotate-revoke sequence at the provider achieves the same outcome
with no router state.

### DI-029
**No HA, no multi-node, no distributed quota authority.**

*Specification 20:* an "HA stateless data plane" profile. Specification 11.2:
multi-node "SHOULD use an external consensus/config distributor". Specification
12: "admission-critical quotas require an authoritative allocator or
conservative node partitions."

*What the code does:* `hypellm-store` is single-node by construction — a PID-file
`ProcessLock`, no replication, no leader election. `AdmissionController`
(`crates/hypellm-core/src/admission.rs`) counts per process, so running N routers
multiplies every tenant limit by N.

*Why:* specification 25's recommended default is "single-writer versioned
bundles; do not build consensus in v1", and consensus is outside what the
router sets out to be (line 54). This is a deferral the specification itself
sanctions.

*Resolution:* phase 4. A signed config distributor consumed by each node, plus
either an external quota allocator or conservative per-node partitions. Until
then, **do not run two routers against one state directory** — the lock is
advisory and its stale-reclaim path is racy.

**Partly resolved — the quota half.** Specification 12 offers a choice, "an
authoritative allocator **or** conservative node partitions", and the second
needs no consensus. `settings quota_partitions=N` divides every quota limit by
N, so N routers behind a load balancer honour the configured figure between them
instead of each enforcing it alone and multiplying every tenant's limit by N.

Division truncates, which is the conservative direction: the sum across nodes is
at or below what was configured, never above. `concurrency=10` over three nodes
admits nine. Rounding up, or spreading the remainder, would raise limits
deployment-wide to avoid losing one slot.

A limit smaller than `quota_partitions` is a **load error**, not a clamp. Zero
encodes "unlimited" in `ScopeLimits`, so `concurrency=2` split eight ways would
divide to zero and turn the tightest expressible configuration into the loosest.
Clamping to one instead would let eight nodes admit eight against a limit of
two — the guarantee the setting exists to provide, quietly broken. The error
names the scope and both numbers.

Applied when the configuration is built rather than at admission, so the router,
the management API's quota views, and policy simulation all see one set of
numbers, and an operator reading a quota back sees what this node actually
enforces.

*Still not done:* everything else. There is no config distributor, no
replication, no leader election, and the state directory is still single-writer.
`quota_partitions` makes the arithmetic correct for a fanned-out data plane; it
does not make the router highly available, and it must not be read as saying
two routers may now share a state directory. They may not.

### DI-047
**No `POST /admin/v1/targets`.**

*Specification 16* lists `GET/POST /admin/v1/targets`.

*What the code did:* only `GET`. Targets came into existence solely by
publishing a validated policy draft.

*Why:* deliberate. A second mutation path for a routing-relevant object would
sit outside the draft → validate → approve → atomic-activate discipline of
15.4, including outside the separation-of-duties check. Adding it would create a
way to change routing with one signature.

*Resolution:* none intended as a direct mutation. The entry closed itself by
naming the right shape — "a draft-generating convenience".

**Resolved.** `POST /admin/v1/targets` exists and returns a **draft**, not a
target. It renders the three required fields as one `target` record, appends it
to the active configuration text, and creates an ordinary policy draft; the
response carries `draft_id` and an explicit `target_created: false` so no client
can mistake what happened. Validation, the second approver, and atomic
activation are all unchanged, which is the whole point: the convenience is in
not hand-authoring a document to add one line, and the control the deviation
protected is untouched.

Three decisions the tests pin down:

- **`EditPolicy`, not `OperateTargets`.** The permission has to match what the
  call does — author a policy change. Accepting the target-operations permission
  would have made this a way into the policy workflow from outside it.
- **Only the required fields are rendered.** Capabilities, context window, and
  cost class are left for the operator to fill in on the draft. Guessing them
  would put a wrong number into routing policy with their name on it.
- **Values are refused, not escaped.** The grammar is line-oriented and
  space-separated (11.1), so an unchecked `provider` could add records rather
  than a field — and a draft is approved by a *second* person, who reads what
  they were shown. `is_configuration_token` rejects anything outside the
  identifier alphabet.

That last one was found by strengthening its own test rather than by writing it.
The first version injected only through `id`, which `TargetId::new` rejects
independently, so it passed with the guard disabled — proving nothing.
Extending it to `provider` and `model`, which have no second line of defence,
showed a `grant scope=tenant:acme model=* allow=true` reaching a draft with the
guard removed.

### DI-048
**No tokenizer, no price schedule.**

*Specification 12* mentions "selected target tokenizer when available";
specification 25 recommends "provider/local tokenize endpoint first;
conservative estimator fallback" and "configured price schedule with effective
dates".

*What the code does:* `estimated_input_tokens`
(`crates/hypellm-core/src/canonical.rs`) is `ceil(bytes / 2)` plus 8 per message,
computed with saturating arithmetic. It is deliberately pessimistic against a
real tokenizer's 3–4 bytes per token, because under-counting would admit a
request past a quota that should have held it. `POST /v1/tokenize` routes to a
provider. No cost schedule exists; `GET /admin/v1/usage` reports tokens, not
money, and distinguishes provider-reported from router-estimated counts.

*Why:* specification 25's recommended default. The billing non-goal is at line
54 — "not an agent framework, prompt marketplace, vector database, secrets
vault, **billing system**, or model host" — not in specification 2.2, which this
entry used to cite wrongly; specification 2.2's five non-goals are about browser
automation, scraping, semantic equivalence, reverse proxying, and dynamic code.
Specification 25 draws the line precisely: "configured price schedule with
effective dates; provider usage reconciliation; **not a billing ledger**". An
operator-facing estimate is on the permitted side of it.

*Price schedule: done.* A `price` record carries per-target rates in minor units
per million tokens plus an `effective_from` date, and `GET /admin/v1/usage`
reports `estimated_cost` with its currency, labelled an estimate. Effective
dates are the substance of it: provider prices change, and today's rate against
last month's tokens is worse than no figure. Arithmetic is integer throughout,
rounding up per term, and `cached_input_per_million` defaults to the uncached
rate — both so the estimate errs high, since a number that undersells the bill
is the one that causes trouble. Usage before the earliest schedule entry gets no
figure rather than a guessed one. A `price` naming an undefined target is an
`unknown_reference` error. See [`deployment.md`](deployment.md#price-schedules).

*Tokenizer: still deferred.* Wiring the tokenize operation into quota estimation
where a target declares one remains phase-4 scope, and the `ceil(bytes / 2)`
estimator stands until then. It is deliberately pessimistic, so the failure mode
is a request refused that could have been admitted — not a quota overrun.

---

## Part 2 — Unimplemented requirements

### DI-002
> **RESOLVED.** All seven areas specification 21 names now have a fuzz suite:
>
> | Area | Suite | Targets |
> |---|---|---|
> | JSON | `crates/wire-json/tests/fuzz.rs` | 6 |
> | HTTP | `crates/wire-http1/tests/fuzz.rs` | 7 |
> | SSE | `crates/wire-sse/tests/fuzz.rs` | 8 |
> | configuration | `crates/hypellm-config/tests/fuzz.rs` | 7 |
> | state recovery | `crates/hypellm-store/tests/fuzz.rs` | 7 |
> | provider events | `crates/hypellm-adapters/tests/fuzz.rs` | 9 |
> | management API | `crates/hypellm-admin-api/tests/fuzz.rs` | 9 |
>
> plus `crates/hypellm-router/tests/fuzz.rs` (9) over the client-facing protocol
> parsers, which specification 21 does not name separately but which read the
> same untrusted bytes.
>
> The engine is `hypellm_test_corpus::fuzz` — a seeded, reproducible mutation
> fuzzer, since the registry crates below remain forbidden. It is **not**
> coverage-guided and does not shrink; both limitations are stated in its module
> header, and they bound what this closure means: these suites find what their
> seeds and mutation strategies reach, not everything a coverage-guided fuzzer
> would.
>
> Two real defects found, one per new suite:
>
> - The configuration suite (earlier) found a fail-open: an explicitly empty
>   `model=` in a `grant` widened it from one alias to every alias.
> - The management-API suite found a leak: `unknown scope '{text}'` echoed an
>   unbounded caller-supplied string into the error, and a malformed management
>   body is very often a mis-pasted secret. Echoed values now go through `echo`,
>   which caps at 32 characters and narrows to an identifier alphabet — a typo
>   still comes back readable, a key does not.
>
> The provider-events suite also raised one finding that was **not** a defect:
> `provider_code` deliberately carries the provider's own error-type token, so
> the assertion there is that it is bounded and alphabet-narrowed, not that it
> is empty. Recorded because a reader should not assume every fuzz finding was
> a bug.
>
> Specification 21's *Property* row is separately met:
> `crates/hypellm-core/tests/properties.rs`, 14 properties over Appendix B across
> 400 seeded cases each.
>
> The description below is retained as the record of what was missing.

**No fuzz targets exist anywhere in the repository.**

*Specification 21* lists Fuzz as a required test layer: "HTTP, JSON, SSE,
configuration, provider events, management API, state recovery". Specification
18.2: "configuration and protocol parsers are fuzzed."

*What the code does:* nothing. There is no `fuzz/` directory, no fuzz harness,
and no seed corpus. `crates/hypellm-test-corpus` contains a single doc comment
saying so. Every crate's `MODULE.md` lists the targets it needs and marks all of
them "Required, not yet implemented" — roughly 45 targets across the workspace.

*Why:* `cargo-fuzz` and `libfuzzer-sys` are registry dependencies and
`arbitrary` is a proc macro, all three forbidden by specification 4. A
dependency-free structure-aware fuzzer has to be written in-repo.

*Consequence:* the parsers that face untrusted input — `wire-http1`,
`wire-json`, `wire-sse`, `hypellm-config`, the adapters' stream decoders, the
store's frame decoder — are covered by hand-written unit tests only. Those cover
the cases an author thought of. This is the largest single gap against
specification 21.

*Resolution:* an in-repo coverage-guided or at minimum random-input harness in
`hypellm-test-corpus`, plus a persistent seed corpus. A pragmatic first step is a
deterministic randomised test binary that runs a fixed budget in CI, which needs
no new dependency at all.

### DI-003
**No privilege drop, sandbox, or environment scrub.**

*Specification 18.1* assigns "privilege drop" to `hypellm-router`.
*Specification 20.1* requires a dedicated unprivileged user, a
system-call/filesystem/network sandbox, disabled core dumps, memory locking for
secret pages, and a scrubbed environment.

*What the code does:* `crates/hypellm-router/src/startup.rs` validates
configuration, opens the store, binds listeners, and serves. It never calls
`setuid`/`setgid`, never sets `RLIMIT_CORE`, never `mlock`s, and never clears
its environment.

*Why:* every one of those operations needs `unsafe` FFI, which the workspace
forbids at every crate root.

*Partly addressed — the router reports what it cannot enforce.* It still cannot
apply any of this, but it now reads what *was* applied and says what is missing.
`crates/hypellm-router/src/hardening.rs` parses `/proc/self/status` and
`/proc/self/limits` at startup and logs `startup.hardening_missing` at critical
for each of: running as uid 0, holding effective capabilities, core dumps
enabled, no seccomp filter, `no_new_privs` unset. Each message names the systemd
directive that supplies it, because a warning an operator cannot act on is
noise, and noise is how the actionable ones stop being read.

The gap this closes is not "the operator did not know". It is that a deployment
can *believe* it applied those directives and be wrong — a typo in a unit file, a
runtime that drops `SystemCallFilter`, a `LimitCORE` that never took — with
nothing to say so. Core dumps matter most of the five: the release profile uses
`panic = "abort"`, so a dump is likely rather than hypothetical, and this process
holds provider credentials, the store MAC key, and session material in memory.

Three properties the design turns on, each pinned by a test that fails without
it:

- **`Unknown` is not `Missing`.** `/proc` is Linux. On any other platform, or a
  kernel that does not publish a field, the reading is unknown and the router
  says nothing. Reporting "no sandbox" where the check does not work would train
  an operator to ignore the warning.
- **The *effective* uid and the *soft* core limit.** A setuid-root binary
  reports `Uid: 1000 0 0 0`, so reading the first field would call the one case
  worth warning about unprivileged. `LimitCORE=0` against an unlimited hard
  ceiling would likewise read as dumping cores.
- **Warnings, never refusals.** A container running as uid 0 with everything
  else locked down is a real deployment.

*Consequence:* all of specification 20.1's process isolation must still come from
the deployment. See [`deployment.md`](deployment.md#process-hardening) for the
systemd directives that substitute. Two items have no detection either: `mlock`
leaves no readable trace of *which* pages are locked, and the environment scrub
is about what was inherited rather than about a current state.

*Resolution:* either an approved minimal libc-binding crate under specification
4's exception profile, or accept the deployment-image responsibility and say so
in the release notes. The second is the current position; this entry exists so
it is a decision rather than an oversight.

**Reclassified from High to an accepted deviation**, to match what the last
sentence above already said. It was carrying a severity that implied unwritten
work, and there is none to write: every operation it names needs `unsafe` FFI,
which specification 18.2 forbids workspace-wide.

Confirmed while reclassifying: the *environment scrub* is blocked too. The
workspace is edition 2024, where `std::env::remove_var` is `unsafe` — so even
the one item on this list that looks like plain Rust is not.

`deployment.md` carries the systemd directives for every item, and now a
complete unit rather than a list to assemble one from (`DI-033`). This stops
being an accepted deviation the day specification 4's exception profile admits a
minimal libc binding, under a formal security decision record.

### DI-004
**The control socket is unauthenticated.**

*Specification 20.1* requires graceful shutdown to exist. It does not authorise
an unauthenticated trigger for it.

*What the code does:* `crates/hypellm-router/src/main.rs` binds a Unix socket at
`settings control_socket` and acts on a bare `shutdown` / `drain` / `ping` line.
It creates the socket under the process umask and does not `chmod` it. Its only
protection is filesystem permission on the containing directory.

*Consequence:* anything on the host that can open the socket can stop the
router. That is a full availability compromise from an unprivileged local
account if the directory is world-writable or world-executable.

*Resolution:* `SO_PEERCRED` peer-uid checking would need `unsafe` FFI; a shared
secret read from the secrets directory and required on the command line would
not, and is the cheapest fix. Until then, place the socket in a directory owned
by the router's user with mode 0700.

**Resolved**, by both controls rather than either alone.

*The mode.* The socket is `chmod`ed to 0600 immediately after bind, and a
failure to do so aborts startup rather than leaving it at the umask.

*The token.* `Secrets` gained `control`, written as `control.key` by
`--generate-secrets` alongside the other five keys and narrowed to 0600 with
them. A command line is `<hex token> <command>`; `authenticated_control_command`
compares without an early exit, so the socket cannot be used to recover the
token by timing, and a missing, malformed, and wrong token are one answer —
distinguishing them would tell an unauthenticated caller whether it had the
shape right. A refusal is logged.

Two controls because either alone is one mistake from failing open: a deployment
that gets the directory mode wrong is still safe from an account that has not
read the secrets directory, and an operator who leaks the token is still
protected by the mode.

*Usability, which is a security property here.* `hypellm-router --shutdown` and
`--ping` read the token from `--secrets` and send the command themselves, so it
never reaches the process list or shell history. An operator who has to
hand-assemble the line will eventually put the token in an argument.

A bundle written before this change has no `control.key` and startup refuses
with `MissingSecret("control.key")` rather than inventing one — a generated
token would authenticate the socket with a value no operator holds.

### DI-005
**Break-glass authentication is not implemented.**

*Specification 22.4:* "Authorized operators use a preprovisioned local
break-glass method stored offline. Break-glass access is time-limited,
reason-bound, alerting, and reviewed." Specification 9.2 lists break-glass as
one of four ways a principal is established.

*What the code does:* the vocabulary exists and the mechanism does not.
`session::AuthMethod::BreakGlass` has no producer — the only call to
`SessionStore::issue` outside tests is in `oidc_callback` and it passes
`AuthMethod::Oidc`. `rbac::Role::BreakGlassAdmin` and `Permission::BreakGlass`
exist and are assignable by `role_binding`, but a role is reachable only through
a session. `peer::TrustedEdge` / `peer::PeerMap` implement uid → principal
mapping, but `RouterState` is built with `TrustedEdge::none()` and no listener
binds a Unix socket for management.

*Consequence:* **during a Google outage there is no way into `/admin/v1` unless
a session is already open**, and even an open session cannot perform sensitive
actions after 5 minutes because `Permission::requires_reauthentication` covers
credential changes, key management, and policy publication. Runbook 22.4 is
therefore currently a procedural workaround rather than a recovery procedure.

*Resolution:* a management listener on a Unix socket, authenticated by peer uid
through the existing `PeerMap`, issuing a session with
`AuthMethod::BreakGlass`, a short absolute lifetime, a mandatory reason, and
`AuditAction::BreakGlassOpened` / `BreakGlassClosed` records — all of which
already exist in the audit vocabulary. Every piece but the wiring is present.

**Resolved**, though not by the Unix socket this entry proposed — that was this
register's suggestion, not the specification's requirement, and it needs
`SO_PEERCRED` (so `unsafe` FFI, `DI-003`) to authenticate anything. What
specification 22.4 actually calls for is "a preprovisioned local break-glass
method stored offline", and that is what exists:

`POST /admin/v1/auth/break-glass` on the management listener, ahead of the
session gate and with no dependence on the identity provider — the case it
exists for is that provider being unreachable. Against the specification's four
properties:

- **Preprovisioned, stored offline.** `--generate-secrets` mints a 256-bit token,
  prints it once, and stores only `break_glass.verifier`, a domain-separated
  SHA-256. Reading the secrets directory does not yield a way in.
- **Time-limited.** `SessionStore::issue_for` takes an explicit absolute
  lifetime — `settings break_glass_ttl_secs`, default 900 — clamped to the
  ordinary policy so a misconfiguration can only shorten it. The test advances
  the clock across the boundary and asserts the session stops working, not that
  the response claims it will.
- **Reason-bound.** 8–256 characters, required, recorded. Checked *before* the
  token, so the endpoint answers identically whether or not the caller holds
  one.
- **Alerting and reviewed.** `BreakGlassOpened` (with the reason) and
  `BreakGlassClosed` in the durable chain and in the audit view, plus a
  `critical` log event on success, on sign-out, and on every refusal.

Two things it deliberately does not do. Holding the token establishes *who* you
are, not *what* you may do: the principal still needs a `role_binding`, and one
with none is refused rather than handed a session that fails everywhere. And an
unconfigured deployment gets 404, not "wrong token" — an endpoint that exists
but cannot succeed is an oracle.

Found while wiring it: the break-glass and OIDC sign-in records were being
appended with `append_audit` rather than `record_audit`, so they reached the
durable chain and never the index the audit view reads — `DI-051` again, in the
record a reviewer looks for first. Both now go through `record_audit` and carry
their tenant.

### DI-006
> **RESOLVED.** A new `identity` configuration record binds `(issuer, subject)`
> to an explicit principal *and* tenant, and `resolve_identity` reads it. Two
> further defects on the same path were closed with it: the callback passed the
> raw authorization code to `TokenVerifier::verify` instead of exchanging it,
> and the PKCE `code_verifier` was generated but never transmitted. The trait
> gained `exchange_code`, the verifier client an `EXCHANGE` verb, and
> `crates/hypellm-admin-api/tests/oidc_sign_in.rs` asserts the verifier actually
> crosses the boundary — its fake verifier panics if `verify` is called, so a
> regression to the old path fails loudly rather than silently.
>
> Sign-in could not succeed at all before this; the description below is
> retained as the record of why.

**Every OIDC principal is assigned the first tenant by map order.**

*Specification 9.1* and Appendix B require management visibility never to exceed
the caller's tenant.

*What the code does:* `resolve_identity`
(`crates/hypellm-admin-api/src/handlers.rs`) correctly binds a principal by role
bindings — refusing to key on email, per 9.1 — and then takes
`config.tenants.keys().next()` as the tenant, with a comment-free
`.cloned()?`.

*Consequence:* in a multi-tenant deployment every human operator lands in
whichever tenant sorts first, regardless of who they are. Tenant-scoped
management views (`keys`, `usage`, `audit`, `decisions`) then scope to the wrong
tenant — which can be either over-permissive or uselessly restrictive, and is
non-obvious either way. This is the dominant cross-tenant risk on the management
plane.

*Resolution:* a `tenant` field on the `role_binding` record, or a
`principal id=… tenant=…` record. The identity → principal mapping already
exists; only the tenant edge is missing.

### DI-020
**No credential probe endpoint.**

*Specification 22.2 step 15:* "Validate with a low-cost target-safe probe."

*What the code does:* nothing. There is no `:probe`, `:verify`, or test-request
endpoint in `crates/hypellm-admin-api/src/handlers.rs`.

*Consequence:* a rotation cannot be validated from the control plane. Combined
with `DI-021` (no overlap window) and the fact that an upstream authentication
failure is reported to the client as `internal_fault` and does **not** trip a
breaker, a bad rotation presents as a quiet per-request 500 and is discovered by
users rather than by the operator who caused it.

*Resolution:* `POST /admin/v1/credentials/{id}:probe` issuing the cheapest
operation the credential's targets declare — a one-token completion or a
zero-length embedding — through the ordinary adapter path, reporting only
success/failure and a sanitised provider code. All the machinery exists; it
needs a handler and a `ManageCredentials`-gated route.

**Resolved** as described. Through the *ordinary* adapter and dispatch path,
which is the point: a probe with its own code path would validate its own code
path. It picks the cheapest enabled target using the credential, asks for one
output token, and carries a ten-second deadline — an operator is waiting on the
answer, and a probe that hangs tells them nothing either way.

Three decisions worth stating:

- **It does not reserve admission capacity.** A probe is an operator action on
  the management plane, not tenant traffic; charging it to the tenant's quota
  would let a rotation check push a real request out. It is bounded by what it
  sends instead: one target, one attempt, one token, no failover.
- **It reports the narrowed provider code and never the provider's message.**
  Specification 10 keeps that text out of any client-visible surface, and an
  authentication error is exactly where a provider echoes the key. There is a
  test that plants a secret in the provider's error body and asserts it does not
  survive.
- **"Cannot probe" is not "passed".** A credential no enabled target uses is a
  refusal, because reporting success there would be the single most misleading
  answer available.

Reached through `CredentialSink::probe`, the same boundary as `store` and
`drain_connections` — `hypellm-admin-api` has no network access and specification
3 keeps it that way.

### DI-023
**No audit or usage search by key pseudonym.**

*Specification 22.3 step 20:* "Search authorized audit/usage by key pseudonym,
source constraints, models, and time."

*What the code does:* `GET /admin/v1/audit` supports cursor pagination and a
limit, and nothing else — no actor filter, no action filter, no time range, no
pseudonym. `GET /admin/v1/usage` aggregates by (alias, target, operation,
status, cost class) and carries no key dimension. `Pseudonymizer`
(`crates/hypellm-telemetry/src/logs.rs`) produces tenant and principal pseudonyms
for log lines only; there is no key pseudonym anywhere.

*Consequence:* a compromised-key investigation runs on the structured logs, not
on the management API.

*Resolution:* query parameters on `/admin/v1/audit` (`actor`, `action`,
`since`, `until`) applied inside `AuditIndex`, and a key-id dimension on
`UsageAggregate` — noting that adding a dimension interacts with the
`MAX_SERIES` cap (`DI-014`).

**Partly resolved.** `/admin/v1/audit` takes `actor`, `action`, `since`, and
`until`, applied against the durable chain (`DI-025`). Every parameter narrows;
there is deliberately none that widens, and the tenant filter runs *before* any
of them — a search parameter that could reach another tenant's records would be
a cross-tenant read with a query string, and there is a test that tries exactly
that. A contradictory window (`since` after `until`) is refused rather than
returning empty, because an empty result and a refusal look identical to an
operator during an incident.

**Now closed**, and the cardinality question is decided rather than guessed.

A `key_id` dimension on `UsageKey` would have multiplied the main table by the
number of live keys, against a `MAX_SERIES` cap that already folds — so the
answer to "what did this key do" would have arrived by making every other usage
question less answerable. Instead there is a **separate** per-`(tenant, key)`
table of totals, bounded by `MAX_KEY_SERIES` and with no cross-product: one row
per key that has served a request.

That answers the question specification 22.3 step 20 actually asks — "what did
this key spend" — and for "on which alias", the principal dimension on the main
table is the tool, since a key belongs to exactly one principal.

No overflow row on the key table, deliberately: a folded row keyed by "some key"
answers nothing an investigation asks and would read as a real key's totals.
`by_key` appears on `GET /admin/v1/usage` only for a caller who may read the
whole tenant's usage — a per-key breakdown would otherwise let one service
account enumerate the others' keys.

### DI-024
**`AuthMethod` has no `ApiKey` variant.**

*Specification 17* requires audit records to identify how a principal
authenticated; specification 22.3's investigation workflow depends on it.

*What the code does:* `Principal::from_key` (`crates/hypellm-auth/src/lib.rs`)
sets `method: AuthMethod::LocalPeer` for every key-authenticated principal,
because `AuthMethod` (`crates/hypellm-auth/src/session.rs`) has only `Oidc`,
`BreakGlass`, and `LocalPeer`.

*Consequence:* not an authentication bypass — scopes, roles, tenant, and
`key_id` are all correct — but every key-authenticated caller is recorded and
exported as having used Unix socket peer credentials. The audit and metrics view
of *how* a principal authenticated is wrong.

*Resolution:* add `AuthMethod::ApiKey` with `as_str() == "api_key"` and use it in
`from_key`. Small change; it is listed here because it silently corrupts an
audit field and will not be noticed by any existing test.

**Resolved** exactly as described. The entry's last sentence was the important
one: nothing failed, because nothing asserted it. There is now a test that does.

### DI-030
**Audit checkpoints are produced but never exported.**

*Specification 11.2:* "Audit records form a hash/MAC chain with periodic signed
checkpoints exported to immutable storage." *Specification 17* lists Audit as an
integrity-bearing signal.

*What the code does:* `Store::checkpoint_audit` writes an
`AuditCheckpoint` frame at the cadence set by
`settings audit_checkpoint_interval`. Nothing ships one anywhere. There is no
export endpoint, no spool directory, and `AuditAction::AuditExported` has no
producer.

*Consequence:* the checkpoint — which is the trust anchor for the chain, since
`link_of` is unkeyed SHA-256 — lives in the same directory as the data it
anchors. An attacker with write access to the state directory cannot forge a
checkpoint without the MAC key, but can delete the whole directory. Immutable
off-node storage is what the specification asks for and it is absent.

*Resolution:* an export writer that appends checkpoints to an append-only spool
file for a collector to ship, plus `GET /admin/v1/audit/export` gated on
`ExportAudit` emitting the durable chain (not the ring — see `DI-025`) with an
`AuditExported` record.

**Resolved** by the endpoint half. `GET /admin/v1/audit/export` emits the
durable chain, oldest first, together with every checkpoint that verifies under
the store MAC key — and `Store::checkpoints` filters out any that does not,
because exporting a trust anchor that anchors nothing is worse than exporting
none.

The checkpoints are the point rather than a decoration: `AuditRecord::link` is
unkeyed SHA-256, so the records prove *ordering and continuity* and only a
checkpoint carries a MAC. An export of records alone is a document anyone could
produce.

Tenant-scoped like every other management read, and the envelope states its
scope — an export that silently omits records is worse evidence than one that
says what it covers. It states `truncated` for the same reason. And the export
is itself audited, which is what `AuditAction::AuditExported` was written for.

**Still open, in a narrower form:** there is no spool writer shipping
checkpoints off-node without an operator asking. The trust anchor still lives in
the same directory as the data it anchors, so an attacker with write access to
the state directory can delete both. What exists now is a supported way to get
them out; automatic export to immutable storage is a deployment integration this
router does not have. That half is folded into `DI-029` (no HA, no multi-node),
which is where off-node anything belongs.

### DI-040
> **RESOLVED.** `crates/hypellm-bench` is the specification 19.1 harness: it
> reports p50/p90/p99/p999 distributions rather than averages, runs offline
> against the in-process fake upstream, and asserts the targets in a test as a
> regression tripwire. The numbers it produces on a shared runner are not the
> specification's targets measured on production hardware, and it says so.
>
> The description below is retained as the record of what was missing.

**No benchmark suite.**

*Specification 19* sets p50 < 2 ms and p99 < 10 ms router overhead at 70 % rated
load, base memory < 100 MiB, per-idle-connection < 8 KiB, and reload pointer swap
< 1 ms. *Specification 19.1* requires a synthetic upstream with controllable
first-token delay, open- and closed-loop tests, direct-versus-routed comparison,
soak with reloads and rotations, and an adversarial parser corpus — "report
distributions, not averages".

*What the code does:* there is no `benches/` directory anywhere and no benchmark
harness. `crates/hypellm-router/src/testing.rs` provides `FakeUpstream` and
`TestRouter`, which `crates/hypellm-router/tests/end_to_end.rs` uses for
correctness. `[profile.bench]` exists in `Cargo.toml` and nothing uses it.

*Consequence:* **none of specification 19's numeric targets has been measured.**
Any claim about router overhead in this repository is unsubstantiated.
Specification 24 makes performance targets on the local provider a phase-1 exit
criterion, and Appendix C requires performance results in the definition of
done.

*Resolution:* a `benches` binary (Criterion is a registry dependency, so this
must be a hand-rolled harness reporting percentiles) driving `TestRouter`
against a `FakeUpstream` with a configurable token cadence. `hypellm_core::time`
already supplies the fixed-bucket histogram to report distributions with.

### DI-041
> **RESOLVED.** `crates/hypellm-test-corpus` now carries the protocol vectors,
> the golden provider responses and streams, and the versioned harness
> compatibility profiles of specification 8.1. Two honest limits remain, stated
> in that crate's module header: nothing was recorded from a live provider — the
> goldens are synthetic — and no named coding harness has been run against the
> router.
>
> The description below is retained as the record of what was missing.

**No harness-compatibility profiles and no golden-server corpus.**

*Specification 8.1* requires versioned coding-harness profiles; *specification
21* requires integration tests "against recorded golden servers" and a
Compatibility layer covering "versioned coding-harness profiles and
streaming/tool/error behavior".

*What the code does:* `crates/hypellm-test-corpus` is an empty placeholder whose
own module comment says so. Each parser crate carries its inline vectors —
`wire-http1` holds the smuggling corpus, `wire-json` the bounded-work cases —
and there is no recorded provider fixture, no profile definition, and no
version.

*Consequence:* adapter behaviour against each provider family is covered by
hand-written unit tests against hand-written JSON, not against recorded
responses. A provider changing its stream shape would not be caught.

*Resolution:* move the existing inline corpora into `hypellm-test-corpus`, add
recorded (sanitised) provider fixtures per family, and define profile records
with a version so "which harness versions does this build support" has an
answer.

---

## Part 3 — Known defects

Bugs and weaknesses in code that exists.

### DI-007
> **RESOLVED.** `build_scenario` now takes the draft's snapshot and refuses an
> `input_tokens` above twice the largest declared context window (floor 4096),
> so an approver can still reproduce a `context_window_too_small` exclusion
> without a ~60-byte body being able to drive a multi-gigabyte allocation.

**`POST /admin/v1/policies/{id}:simulate` accepts an unbounded `input_tokens`.**

*Specification 3.2* requires every request-originated buffer to be bounded.

*What the code does:* `build_scenario`
(`crates/hypellm-admin-api/src/handlers.rs`) reads `input_tokens` as any value
that fits `u32` and evaluates `"x".repeat(n * 2)`. A single request from a
caller holding `SimulatePolicy` can request roughly 8.6 GiB.

*Resolution:* clamp to the largest `max_context_tokens` declared by any target,
or a fixed ceiling such as 2 000 000.

### DI-008
> **RESOLVED.** `duration_seconds` is capped at 90 days and the arithmetic is
> saturating. The release profile sets `overflow-checks = true` with
> `panic = "abort"`, so the overflow was not a wrong expiry — it was a
> management request that killed the process. An indefinite removal is
> `state=disabled`, which is what it should have been spelled as anyway.

**Quarantine `duration_seconds` is unbounded and can overflow.**

*What the code does:* `patch_target` computes
`wall_millis() + duration_seconds * 1000` from an unbounded `i64` narrowed to
`u64`. Values above roughly 1.8 × 10¹⁶ overflow; with `overflow-checks = true`
and `panic = "abort"` in the release profile, that terminates the router. There
is also no maximum quarantine duration.

*Resolution:* clamp `duration_seconds` to a policy maximum (a week is generous)
and use `saturating_mul` / `saturating_add`.

### DI-009
**The credential isolation class has an ambiguous delimiter.**

*Specification 19:* "No cross-tenant reuse where auth binding is unsafe."

*What the code does:* `RouterState::credential_class`
(`crates/hypellm-router/src/state.rs`) builds `format!("{tenant}:{reference}")`,
and `:` is a legal identifier character (`hypellm_core::ids::validate`). Tenant
`a:b` with credential `c` produces the same class as tenant `a` with credential
`b:c`, so two tenants could share a pooled socket.

*Bounded by:* identifiers come from operator configuration, not from callers.

*Resolution:* length-prefix the components, or use a delimiter outside the
identifier alphabet.

**Resolved** by length-prefixing: `{len}:{tenant}:{len}:{reference}`. The byte
count is not drawn from the alphabet it counts, so exactly one split of the
string is consistent with it and no pair of (tenant, credential) can collide.

`credential_class` moved out of `RouterState` to a free function, because it
depends on nothing but its arguments and its test should not have to assemble a
router. That mattered: the existing test reconstructed the format inline and
compared two strings it had just built, so it passed whatever the function did.
It now calls the real function and asserts the collision case directly —
`("a:b", "c")` against `("a", "b:c")` — and fails if the delimiter form
returns.

### DI-010
> **RESOLVED.** `LiveState::admin_override` and
> `HealthRegistry::set_admin_state` give drain, maintenance, and disable runtime
> effect, and `PolicySnapshot::route` prefers the override over the configured
> state. The handler now reads the effective state back rather than echoing the
> request, and reports `persists_across_restart: false` — the override is
> in-memory, which is a smaller gap recorded separately below.
>
> The description below is retained as the record of what was missing.

**`PATCH /admin/v1/targets/{id}` cannot drain, disable, or set maintenance.**

*Specification 16:* "ETag-guarded update, drain, maintenance, quarantine."

*What the code does:* `patch_target` accepts `enabled`, `draining`,
`maintenance`, `quarantined`, and `disabled`. Only `quarantined` and the release
of a quarantine have any runtime effect, through
`HealthRegistry::quarantine` / `release_quarantine`. The other four states are
validated, audited, echoed back in the response body — and then dropped.
`Target::admin_state` is populated from the `target … state=` configuration
field (`crates/hypellm-config/src/build.rs`) and is never mutated at runtime.

*Consequence:* an operator following specification 22.1 who sets a target to
`draining` gets a 200, an audit record, and a `"state":"draining"` response, and
the target keeps taking traffic. This is a false assurance, which is worse than
a missing feature.

*Resolution:* either apply the state through a runtime override registry
alongside quarantine, or reject the four unimplemented states with
`invalid_request` until they are. The second is the honest interim.

### DI-011
> **PARTLY RESOLVED.** `capture_bodies`, `keepalive_interval_ms` and the
> tenant's `retention_days` are now read by `GET /admin/v1/settings`, so an
> operator can at least see what a deployment declared. `slow_client_timeout_ms`
> and `max_head_bytes`/`max_body_bytes` reach the listener via
> `listener_config`, and `max_failure_percent` reaches the routing filter.
>
> `keepalive_interval_ms` is now read: it is specification 14's SSE comment
> cadence, and `dispatch::stream_events` writes a comment into an open stream
> whenever that interval passes with nothing to read. It is the field this entry
> most deserved to have listed, because "parsed and ignored" understated it — a
> stream with a slow first token was silent for as long as the provider took,
> and an intermediary with an idle timeout turned a slow answer into a failed
> one. Zero disables it. Note the neighbouring trap recorded under `DI-031`:
> this is *not* the connection keep-alive timeout, which is now
> `keepalive_timeout_ms`.
>
> `quota queued` belongs in this entry's history and was missed when it was
> written: it was parsed into `ScopeLimits::max_queued`, stored on the scope,
> and consulted by nothing — a target at its concurrency limit was refused
> immediately no matter what an operator configured. It is now honoured by
> `AdmissionController::reserve_queued` under specification 12's weighted-fair
> order, with `settings queue_timeout_ms` as specification 3.2's mandatory
> queue timeout. Recorded here rather than quietly fixed, because a register
> that only lists the inert fields somebody happened to notice is the
> comfortable kind of incomplete.
>
> **Now closed.** The last two are read:
>
> `metrics_listen` binds a third listener serving *only* `GET /metrics` and
> `GET /health/live`. Serving only those is the point: the address is reachable
> by a scrape agent, and a scrape agent must not be one path away from
> `/admin/v1`. Everything else answers 404 rather than 403 — a 403 would
> confirm the management API is behind that address too. Previously the
> exposition lived on the management listener, so scraping meant admitting the
> collector to the control plane.
>
> `rotates_after_days` is reported against the audit chain: `last_rotated` and
> `overdue` on `GET /admin/v1/credentials`, derived from the newest
> `credential_rotated`/`credential_created` record rather than stored
> separately — a second copy could disagree with the chain, and the chain is the
> one with integrity protection. The router **reports** rather than enforces:
> cutting off a working credential on a timer would turn a policy into an
> outage. A credential with no recorded rotation is *not* overdue, because the
> chain is bounded and "never rotated" is indistinguishable from "rotated before
> the window this router can see" — marking everything overdue on first read
> would train an operator to ignore the field.

**Configuration fields are parsed, validated, and then never read.**

*What the code does:* the following are accepted by the grammar, typed, and
consumed by nothing:

| Field | Record | Consequence of setting it |
|---|---|---|
| `metrics_listen` | `settings` | No third listener is bound; the exposition is served only on the management listener at `GET /metrics` |
| `capture_bodies` | `settings` | There is no body-capture implementation at all (specification 10's optional per-tenant sampled capture). Fail-safe, but the field implies a feature that does not exist |
| ~~`keepalive_interval_ms`~~ | `settings` | **Now honoured** as specification 14's SSE keepalive cadence |
| `retention_days` | `tenant` | No retention or expiry is implemented for any stored data |
| `rotates_after_days` | `credential` | Displayed by `GET /admin/v1/credentials`; nothing enforces it and nothing alerts |

*Why it matters:* specification 11.1 makes unknown fields an error precisely so
that a misspelled setting fails loudly rather than doing nothing. A *known*
field that does nothing has the same failure mode the rule was written to
prevent.

*Resolution:* implement or remove. For `capture_bodies` in particular, removal
is safer than a half-implementation, since specification 10 requires any capture
to be per-tenant, sampled, encrypted, access-controlled, time-limited, and
visibly indicated.

### DI-012
**`PinnedDestination` is a discipline, not a capability.**

*Specification 10* requires the validated address to be pinned for the
connection.

*What the code does:* `Dialer::connect` (`crates/hypellm-net/src/egress.rs`)
accepts only a `PinnedDestination`, and the only production producer is
`Resolver::resolve`, which classifies every candidate before pinning. But
`PinnedDestination` has **public fields**, so a struct literal bypasses
classification entirely. Only tests do this today.

*Resolution:* make the fields private behind a constructor that only `resolve`
can reach, turning the discipline into an enforced invariant.

**Resolved** exactly so. The fields are private with read-only accessors, and
the two constructors — `unix` for a configured socket path, `validated` for an
address the classifier permitted — are module-private. Outside `egress`, the
only way to obtain a `PinnedDestination` is to call `resolve`, and `resolve`
cannot return one it has not classified.

Separate constructors rather than one with a "was this classified" parameter, so
there is no argument anybody can pass that skips classification by accident.

`for_tests` exists and is `#[cfg(test)]`, so it is not compiled into a router at
all: a test needs to reach a port it just bound without standing up a resolver,
but the value of the type is that production code cannot do the same, so the
escape hatch is compiled out rather than merely discouraged.

### DI-013
**Policy drafts are held in memory only.**

*Specification 15.3 / 15.4* describe drafts, validation, simulation, approval,
and rollback as a workflow.

*What the code does:* `DraftStore` (`crates/hypellm-admin-api/src/drafts.rs`) is a
`RwLock<BTreeMap<…>>` capped at 256 drafts with oldest-first eviction. Nothing
is written to the store. The published *activation* is durable; the draft is
not.

*Consequence:* a restart loses every draft under review, including one awaiting a
second approver. During an incident that means re-authoring under pressure.

*Resolution:* a `PolicyDraft` record kind in the framed log, replayed at startup
alongside key records.

**Resolved** as described, plus a `PolicyDraftClosed` record — without it,
replay would restore a draft that had already been published and present a
reviewed-and-activated configuration as though it were still awaiting approval.

Both kinds are **protected frames**. A draft is the text a publication will
activate, and publication is the most consequential management action there is:
an unprotected draft could be edited on disk between authoring and approval, so
the approver would review one document and publish another.

Two decisions worth stating:

- **The validation verdict is not persisted.** It is a function of the text and
  of the configuration grammar the running binary implements. Replaying a stored
  "valid" across an upgrade would let a draft that no longer builds be published
  as though it had been checked. A restored draft is unvalidated and must be
  validated again, which costs one call and cannot be wrong.
- **Creation fails closed; replay does not.** A draft reported as created but
  lost on restart is worse than one that visibly failed, because the operator
  walks away believing it exists — so a failed append refuses the creation. A
  record that does not *decode* at startup is skipped instead: a draft is
  proposed work, not authority, so losing one costs a retype while refusing to
  boot costs the deployment. That is the opposite trade from a key record or the
  audit chain, and the difference is deliberate.

The identifier allocator is advanced past every restored draft, or a create
after a restart would silently overwrite one awaiting approval.

### DI-014
**The metric cardinality backstop permanently blinds a metric.**

*Specification 17* forbids high-cardinality labels.

*What the code does:* `Registry::with_series`
(`crates/hypellm-telemetry/src/metrics.rs`) caps a metric at
`MAX_SERIES_PER_METRIC` (2 000) series and folds everything beyond it into one
`{outcome="overflow"}` series. There is no eviction, no decay, and no reset
short of a process restart.

*Consequence:* the memory attack becomes an observability attack. An attacker
who sprays 2 000 distinct label values permanently blinds that metric for the
life of the process. The overflow series is also indistinguishable in the
exposition from a legitimate `Outcome` value, and the fold is misleading for
gauges and meaningless for histograms.

*Bounded by:* no production call site uses `LabelName::Alias`, and target
identifiers come from the policy snapshot rather than the client string. That
must stay a deliberate decision.

*Resolution:* label only with resolved identifiers from the active snapshot
(already the practice), and add a decaying or LRU series table for the two
labels that can trace back to request content.

**Resolved.** `crates/hypellm-telemetry/src/metrics.rs` now does three things the
backstop was missing.

*Reclamation.* Each series records the metric access count at which it was last
touched, and a full table admits a new series by evicting the stalest one when
that series has gone `STALE_AFTER_ACCESSES` (8 × the cap) accesses untouched.
Staleness counted in accesses rather than milliseconds keeps the registry
clock-free and makes the threshold scale with load: on a busy router a series
that has missed eight sweeps of the table is idle, and on an idle router nothing
is evicted because nothing is competing. A table that is full of *live* series
still folds rather than evicting — that is a genuinely high-cardinality metric,
and evicting from it would only thrash. The scan that finds a victim is O(series)
under the write lock, so it runs once per `SCAN_INTERVAL` (256) attempts rather
than on every insert; otherwise the spray path would double as a lock-contention
lever.

*Distinguishability.* The overflow series carries `LabelName::Overflow`
(`hypellm_overflow="true"`), a reserved name no emit site uses, instead of
`{outcome="overflow"}` — which read in the exposition exactly like a router
outcome named "overflow".

*Meaning.* Only counters fold. Summing counters that could not be attributed
answers a question; summing unrelated gauges, or merging unrelated histograms,
produces a number that looks like data and describes nothing. Gauge and
histogram observations past the cap are dropped instead, and the registry
publishes `hypellm_metric_series_evicted_total` and
`hypellm_metric_series_overflowed_total` per metric so that a metric which has
stopped attributing says so rather than looking healthy. Those two are
synthesised at render time rather than emitted through `counter_add`, so the
registry cannot recurse into itself while holding its own lock.

Four tests cover it, including one asserting that a live series is never evicted
by a spray of new ones. The bounding note below still holds and is still a
deliberate decision.

### DI-015
**Startup does not verify the audit chain.**

*Specification 11.2* requires the audit chain to be integrity-checked;
specification 17 lists Audit as an integrity-bearing signal.

*What the code does:* `Store::open` (`crates/hypellm-store/src/lib.rs`) re-chains
post-snapshot audit frames by taking each record's own `link()`. It never calls
`verify_chain`, which is exported but referenced only from a unit test. A record
whose payload fails `AuditRecord::from_payload` is skipped silently — advancing
the count but not the head.

*Consequence:* chain continuity is not checked at startup, and a protected frame
that verifies its MAC yet does not parse (see `DI-043`) leaves the live head
diverged from the durable history with no error surfaced.

*Resolution:* call `verify_chain` during recovery and fail closed on a break, or
at minimum emit a `critical` log event and a metric.

**Resolved.** Recovery now compares each record's `previous_link` against the
running head instead of adopting the record's own `link()` unconditionally, and
reports the first break as `Recovery::audit_chain_broken_at`. A frame that
authenticates under the store MAC but does not decode as an audit record counts
as a break for the same reason a removed one does — the next record commits to a
link this reader cannot compute — rather than being skipped in silence.

`Router::assemble` refuses to start on `Some(_)` with a new
`StartupError::AuditChainBroken { sequence }`, which is specification 11.2's
"fails closed on protected-record integrity errors". Starting anyway would mean
vouching for an audit trail that does not verify, and a false assurance is worse
than a visible refusal.

The break is *reported* by the store and *acted on* by the router because what
to do about it is a policy question: an operator recovering a damaged volume
needs a way to read the log, and that path should not be gated on the same
decision the request path makes.

Four tests: an intact chain is not flagged, a removed middle record is, two
swapped records are, an undecodable frame is — plus a startup test that builds a
log with one audit record removed (every surviving frame still MAC-valid) and
asserts the router refuses to start.

### DI-016
**Deployment-wide management listings are not tenant-scoped.**

*Appendix B:* "Management visibility never exceeds the caller's tenant and
permissions."

*What the code does:* `list_targets`, `list_providers`, `list_aliases`, and
`overview` render the whole active configuration to any caller holding
`ReadSummary`, with no tenant filter. `list_keys`, `list_usage`, `list_audit`,
and `decision` **are** tenant-scoped.

*Open question rather than a defect:* targets and providers are deployment-wide
objects, and an operator who cannot see them cannot operate. Whether this
violates Appendix B depends on whether tenants in a given deployment are
mutually distrusting. It is recorded here so the decision is explicit.

*Resolution if scoping is required:* filter targets by the aliases the caller's
tenant is granted, and providers by the targets that survive.

**Resolved: scoping is required, and is now applied.** Appendix B is
unconditional — "never exceeds the caller's tenant and permissions" — and it
does not offer an exemption for objects that happen to be deployment-wide.

The entry was also partly stale: `list_targets` had already been scoped. What
had not been were `list_providers`, `list_aliases`, and `overview`. The provider
listing was the one that mattered: it carries endpoint hostnames and credential
*references*, so any tenant holding `ReadSummary` could read which providers the
deployment uses, where they live, and what their credentials are called.

All four now derive from `visible_targets` — the same authorization
`GET /v1/models` applies on the data plane — so a provider is visible when it
backs a target the caller's tenant can reach, and an alias when the tenant holds
a grant for it. `overview` counts over the same set, because an overview saying
four targets beside a listing showing none is both confusing and itself a
disclosure about the deployment's size.

The counter-argument in this entry — "an operator who cannot see them cannot
operate" — is answered by what the filter actually hides: an operator whose
tenant is granted the alias sees the target, the provider, and every field on
both. Only providers their tenant cannot reach at all disappear, and there is
nothing they could operate on those with.

A platform-scoped role that sees the whole deployment is a reasonable future
addition; it does not exist, and inventing one here would have been a larger
decision than this entry asked for.

### DI-017
**Breaker state is reported for `Operation::Chat` only.**

*What the code does:* health is tracked per `(target, operation)`
(`crates/hypellm-core/src/health.rs`), but `render_target` and `overview`
(`crates/hypellm-admin-api/src/handlers.rs`) both read
`health.entry(&target.id, Operation::Chat)`.

*Consequence:* a target failing only on embeddings or tokenize shows
`breaker_state: "closed"` and counts as healthy in `targets_healthy`. During an
outage this reads as "the target is fine" when it is not.

*Resolution:* render a per-operation map, or report the worst state across
operations, and say which in the field name.

**Resolved** by both. `breaker_state` is now the *worst* state across every
operation — `Open` over `HalfOpen` over `Closed` — and
`breaker_state_by_operation` carries the full map alongside it, so the summary
is never the only answer available.

Worst-of is the right summary because the question an operator asks is whether
*anything* about the target is broken, and the safe direction to be wrong in is
to say degraded. `targets_healthy` in the overview counts on the same rule, via
the same function, so the overview and the target list cannot disagree.

### DI-018
**Simulation runs against `IdealLiveState`, and only against a draft.**

*Specification 15.4* requires simulation "without provider invocation";
*specification 22.1 step 11* asks operators to "simulate critical aliases to
confirm permitted fallback **and capacity**".

*What the code does:* `simulate_draft` calls
`PolicySnapshot::route(…, &IdealLiveState)` — everything healthy, nothing
quarantined, no capacity consumed. It also requires a draft id; there is no
endpoint that simulates against the active configuration.

*Consequence:* simulation answers "does policy permit this" and cannot answer
"is there capacity right now" or "will the breaker allow it", which is exactly
what step 11 is for.

*Resolution:* an optional `live=true` parameter that routes against the real
`HealthRegistry` and `AdmissionController` (reserving nothing), and a
`POST /admin/v1/policies/active:simulate` alias.

**Resolved**, both halves. `live=true` routes against the real
`HealthRegistry` — breakers, quarantines, operator overrides, observed failure
rates, remaining capacity — and `POST /admin/v1/policies/active:simulate`
answers about what is running, which is what an operator needs during an
incident and could not previously ask without authoring a draft of the
configuration already live.

Both modes are kept, because they answer different questions and the difference
matters. Ideal answers "does policy permit this", which is what a draft review
wants: a target that happens to be breaking right now should not make a policy
look wrong. Live answers "would this work at this moment". The response states
which ran — an operator reading "no eligible target" has to know whether that
was policy or weather.

Neither reserves capacity or contacts a provider (specification 15.4, "without
provider invocation"); a live simulation *reads* admission and health state, so
simulating cannot cause the rejection it is investigating. There is a test that
simulates twenty-five times and asserts in-flight and request counts are
unchanged.

### DI-019
**No gradual weight restoration after recovery.**

*Specification 22.1 step 13:* "use half-open probes, gradual weight restoration,
and compare errors/latency."

*What the code does:* half-open probing and breaker closure are automatic and
correct (`crates/hypellm-core/src/health.rs`). Preference `weight` is a
configuration field on a `binding` record; there is no runtime weight ramp and
no scheduled restoration.

*Resolution:* a decaying weight multiplier in the health registry applied as a
score term after a breaker closes — noting that it must remain a *score* term,
never a filter, so it cannot exclude a target (specification 6.3).

**Resolved** exactly so, and the parenthesis is the important half.

`Breaker::restoration_permille` rises linearly over
`WEIGHT_RESTORATION_MILLIS` (30 s) from the moment a breaker closes, and
`HealthRegistry::health_penalty` folds it into the existing health term rather
than adding a new one — so it is clamped into `ScoreTerms::HEALTH_RANGE` with
everything else and cannot dominate the score or overflow it.

It **never returns zero**, and has a floor of a tenth. A ramp that reached zero
would be an exclusion wearing a score's clothes: a recovered target that is the
only candidate must still be chosen, or a recovery would present as an outage.
There is a test asserting precisely that — penalised, within range, and neither
`circuit_open` nor out of capacity.

Worst-of across operations, matching `worst_failure_percent`: a target whose
embeddings breaker just closed has not fully recovered whatever its chat breaker
says.

Why a ramp at all, given the probes already succeeded: two probes make a target
*probably* healthy, and the cost of "probably" being wrong is the full load
arriving at something still warming up — which reopens the breaker and makes the
outage longer than it needed to be.

### DI-022
**`ConnectionPool::drain_key` is not wired to credential rotation.**

*Specification 22.2 step 17:* "Drain/recycle connections whose authentication is
connection-bound."

*What the code does:* `drain_key` exists (`crates/hypellm-net/src/pool.rs`) and is
called only from its own unit test. `rotate_credential` does not call it.

*Bounded by:* provider authentication in this router is per-request, so a pooled
socket carries no stale credential, and idle sockets expire after 60 s anyway.

*Resolution:* call `drain_key` for the affected credential class on rotation.
Cheap, and it becomes load-bearing the moment a provider with connection-bound
authentication is added.

**Resolved**, though not through `drain_key` itself. A credential is one
*component* of the pool key, not a whole key, so draining "everything opened
under this credential" needs a predicate: `ConnectionPool::drain_where`.

The route from the handler to the pool is the interesting part.
`hypellm-admin-api` has no network access at all — specification 3 keeps the
management path out of the data path — so it cannot reach the pool directly.
`CredentialSink` gained `drain_connections`, which travels the same boundary the
secret already does, and `CredentialSinkAdapter` in the router implements it
against `Egress::pool`. The trait's default is a no-op, so a deployment with no
sink is unaffected.

Only *idle* connections close. One serving a request was authenticated under the
old credential and its exchange is already in flight; killing it mid-response
would turn a rotation into a client-visible failure.

The rotation response now reports `connections_drained`, which is also what
makes the behaviour testable: a test can distinguish "the handler asked and got
an answer" from "the handler never asked".

### DI-025
**Audit views read a 2 048-entry ring, not the durable chain.**

*What the code does:* `AuditIndex` (`crates/hypellm-admin-api/src/audit_index.rs`)
is an in-memory ring of 2 048 records, rebuilt from nothing on restart.
`GET /admin/v1/audit` reads it. The authoritative chain in `log.bin` has no read
path through any endpoint.

*Consequence:* an investigation cannot look further back than 2 048 management
actions, or across a restart, without reading the state directory offline.

*Resolution:* read the durable chain for paginated history, using the ring only
as a hot cache; add the export in `DI-030`.

**Resolved** as described. `Store::audit_records` pages backwards through the
durable chain, and `GET /admin/v1/audit` uses it whenever the caller asks for a
filter or passes `durable=true`; the default view stays on the ring, which is
the right shape for a screen showing recent activity.

Both paths render through one function, so a caller cannot tell which answered
and the two cannot drift into different shapes — asserted by a test that
compares the sequences from each.

The durable read is deliberately uncached: an investigation reading a stale
cache of the audit trail is worse than one that waits. It is bounded twice, at
`MAX_AUDIT_PAGE` (500) per page and `MAX_AUDIT_SCAN_PAGES` (20) per query, and a
query that exhausts the scan returns a cursor rather than pretending the history
ended.

### DI-026
**API-key source restrictions cannot be set through the management API.**

*Specification 9.2* describes source-constrained keys; specification 22.3 step 22
asks for a least-privilege replacement.

*What the code does:* `KeyStore` supports `SourceRestriction` with CIDR matching
and `verify` enforces it (`crates/hypellm-auth/src/apikey.rs`, `in_network`).
`create_key` (`crates/hypellm-admin-api/src/handlers.rs`) always passes
`SourceRestriction::Any`.

*Resolution:* accept an optional `source_networks` array in the create body,
parse to `SourceRestriction`, and render it (never the verifier) in `list_keys`.

**Resolved** as described, with three refusals worth stating because each one
could plausibly have been a silent widening instead:

- **Present but empty is an error**, not `Any`. An empty list reads as "restrict
  to nothing", and quietly turning that into "do not restrict" is the exact
  shape of the fail-open the configuration fuzzer already found once (`DI-002`:
  an explicitly empty `model=` widening a grant to every alias).
- **A bare address without a prefix is refused**, not assumed to be a /32. An
  operator who meant one host can write `/32`; one who forgot the prefix on a
  network gets an error rather than a restriction one address wide.
- **A prefix longer than the address family allows is refused.**

Absent means `Any`, which is what a key got before this existed, so no client
changes. A listing renders `null` for an unrestricted key rather than `[]`,
because a reader must be able to tell "usable from anywhere" from "restricted to
nothing". The verifier is still never returned.

### DI-027
**A published activation permanently shadows the configuration file.**

*What the code does:* `startup::resume_activation` prefers the last
`ConfigActivation` frame in the durable log over the file named by `--config`.
That is correct — a policy that was drafted, reviewed, approved, and durably
recorded must not disappear on the next restart — but it has a sharp
consequence: once *any* policy has been published through the management API,
editing the configuration file has no effect and there is no message saying so
beyond an `info` log line (`config.activation_resumed`).

*Consequence:* during a control-plane outage (`DI-005`) the file-edit path is
unavailable, and adopting the file requires starting against an empty state
directory — which discards the audit chain and every stored API key.
`StartupError::ActivationUnrecoverable` warns about this in one specific failure
case; the ordinary case is silent.

*Resolution:* a `--adopt-config` flag that records the file as a new activation
(with an audit record and a required reason), so adopting the file is a
first-class, audited operation rather than a destructive workaround.

**Resolved** as described. `hypellm-router --adopt-config "<reason>"` loads the
file, writes it as a new `ConfigActivation` frame, appends an
`AuditAction::ConfigAdopted` record carrying the reason, and emits a `critical`
log event — durable first, then audited, the same order a publication uses.

The reason is required and must be at least eight characters. This overrides a
policy that went through drafting, review, and approval; whoever reads the audit
record afterwards needs to know why, and asking for it is also asking the
operator to have one.

Adoption *persists*: it writes an activation rather than acting as a one-shot
override that silently reverts on the next restart, which would be the worst of
both designs. There is a test for exactly that.

The default is unchanged and remains correct — a published activation wins, or a
reviewed policy would vanish on the next restart. What changes is that
overriding it no longer requires starting against an empty state directory and
discarding the audit chain and every stored API key to edit a configuration
line.

### DI-028
**No Unix-socket listener.**

*Specification 20's* "single secure node" profile specifies "TLS edge on same
host, **Unix socket to router**".

*What the code does:* `Server::bind` (`crates/hypellm-router/src/server.rs`) calls
`TcpListener::bind`. Only TCP addresses are supported for both listeners. The
`unix` scheme is supported for *outbound* provider endpoints only.

*Resolution:* a `UnixListener` variant behind the same `Handler` interface.
`ClientWriter::peer()` returns an `Option<IpAddr>` and would need to become an
enum, which touches API-key source restrictions.

**Resolved** as described. `Server::bind` takes a filesystem path — recognised
by a leading `/` or a `unix:` prefix, neither of which can appear in a
`host:port`, so no setting is needed to disambiguate — and both listeners serve
the same `Handler` over the same connection state machine.

`ClientWriter::peer()` returns a `Peer` enum. The security question the entry
flagged resolves cleanly: `Peer::ip()` is `None` for a local socket, so an API
key carrying a source restriction **fails closed** over one — the restriction
cannot be evaluated, so it is not satisfied. A key pinned to a network must not
become unrestricted by arriving through a different transport. `Peer::Local` and
`Peer::Unknown` are distinct because they are different facts, and the audit
record says which.

Two things found while building it:

- **Filesystem permission is the only access control on a Unix listener.** There
  is no network to firewall, so the socket is `chmod`ed to 0600 at bind and a
  stale file is removed first — a router refusing to start because a socket file
  it created is still there would be an outage caused by tidiness.
- **`ShutdownHandle` would have hung.** It wakes a blocked `accept` by
  connecting to the listener's own endpoint, and a path is not a `SocketAddr`,
  so a Unix listener would have sat in `accept` forever while the router
  reported that it had stopped. The handle carries the path now, and a test
  fails — by hanging, then timing out — without it.

### DI-031
**Listener connection caps, keep-alive, and per-connection request limits are
compile-time constants.**

*What the code does:* `startup::listener_config` applies `max_head_bytes`,
`max_body_bytes`, `slow_client_timeout_ms`, and `default_deadline_ms` from the
configuration. `max_connections`, `read_timeout`, `keepalive_timeout`, and
`max_requests_per_connection` come from `ServerConfig::inference()` /
`::management()` and no settings field reaches them — including
`settings keepalive_interval_ms`, which is parsed and ignored (`DI-011`).

*Resolution:* extend `listener_config`, with clamping to the specification 3.2
ceilings as it already does for the head and body bounds.

**Resolved.** `max_connections`, `max_requests_per_connection`, `read_timeout_ms`
and a new `keepalive_timeout_ms` reach the listener, each clamped: zero keeps the
profile default, so an operator tunes what they mean to and inherits the rest,
and no configured value can *remove* a bound — only move it inside the allowed
range. The management listener keeps its own smaller profile, because
specification 3.1 separates the planes' limits and one number governing both
would let inference sizing decide how many operators can reach the control
plane.

**A trap found while doing it.** The obvious reading of this entry is to wire
`settings keepalive_interval_ms` to `ServerConfig::keepalive_timeout`, and the
first cut did exactly that. They are different things: `keepalive_interval_ms`
is specification 14's *SSE comment cadence* — how often the router writes into
an open stream — while `keepalive_timeout` is how long an idle socket waits for
its next request. Wiring one to the other would have meant an operator tuning
stream liveness silently changed connection reuse. They are now separate
settings, and `keepalive_interval_ms` is wired to the thing it names (see
`DI-011`).

### DI-032
**`/health/ready` discloses the configuration version and digest before
authentication.**

*Specification 8* requires health endpoints to expose "no sensitive provider
detail".

*What the code does:* `readiness` (`crates/hypellm-router/src/routes.rs`) returns
`{"status":…,"config_version":…,"config_digest":…}` to any unauthenticated
caller who can reach the inference port.

*Consequence:* an unauthenticated caller can fingerprint the active
configuration and detect when it changes. No target name, provider, or
credential is disclosed — the metrics exposition, which does carry those, was
correctly moved off this listener.

*Resolution:* return only `{"status":…}` on the inference listener and keep the
detailed form on the management listener.

**Resolved** as described. A load balancer needs the verdict; an unauthenticated
caller on the inference port does not need to fingerprint the active
configuration or watch for the moment it changes. The test asserts the absence
of both fields and of any target, provider, or address string.

### DI-033
**No signal handling.**

*Specification 20.1* requires graceful shutdown.

*What the code does:* nothing handles `SIGTERM` or `SIGINT`; `sigaction` needs
`unsafe` FFI. Shutdown is driven by writing `shutdown` to the control socket
(`crates/hypellm-router/src/main.rs`).

*Consequence:* a supervisor that only sends `SIGTERM` kills the process
immediately, cutting in-flight streams. systemd units must use `ExecStop=` to
write to the socket.

*Resolution:* an approved signal-handling binding, or `signalfd` read from a
thread — which still needs FFI. The control socket is the dependency-free
equivalent and works; this entry exists so the systemd requirement is not
discovered in production.

**Reclassified as an accepted deviation**, because that is what it is: every
route to handling a signal — `sigaction`, `signalfd`, `pthread_sigmask` — is
`unsafe` FFI, which specification 18.2 forbids workspace-wide. There is no
implementation to write, only a decision to record, and it belongs with
`DI-001` and `DI-003` rather than in a list of things somebody might get to.

What *has* changed is the thing this entry actually worried about — the
requirement being "discovered in production". `deployment.md` now carries a
complete systemd unit with the `ExecStop=` line, rather than a sentence saying
one should be written. The control socket is authenticated (`DI-004`) and
`--shutdown` drives it, so `ExecStop=` is one line and cannot be got subtly
wrong.

This stops being an accepted deviation the day specification 4's exception
profile admits a minimal signal binding — the same condition as `DI-003`, and
the same security decision record.

### DI-034
> **RESOLVED.** `Server::drain(timeout)` waits for in-flight exchanges and
> returns how many were still running at the deadline; `serve` calls it before
> returning, and `Router::serve` logs `router.drain_incomplete` and exits
> nonzero when the final state flush fails. `read_head` also polls in short
> slices while a request has not started arriving, so an idle keep-alive
> connection notices shutdown instead of holding it for the keep-alive timeout.
>
> The description below is retained as the record of what was missing.

**Shutdown does not drain.**

*Specification 20.1:* "Graceful shutdown stops admission, drains within
deadline, cancels remainder, flushes audit/state."

*What the code does:* setting the shutdown flag stops the accept loops, and
`serve_connection` checks the flag between requests on a keep-alive socket. But
connection threads are **detached and never joined**
(`crates/hypellm-router/src/server.rs`, `Server::serve`): `Router::serve` returns
as soon as both accept loops break, `main` returns, and the process exits. Any
response still streaming is cut. The audit `RouterStopped` record and
`Store::sync` do run first.

*Consequence:* "drain" is a misnomer for what the control socket does today. A
long-running streaming completion is terminated mid-response.

*Resolution:* track in-flight connections (`Server::active` already counts them)
and wait on it with a configurable deadline before returning, then force-close
the remainder. The counter exists; only the wait is missing.

### DI-035
> **RESOLVED.** `Secrets::write_to` narrows each key file to 0600 and the
> `credentials/` directory to 0700. These five keys authenticate the audit
> chain, forge any API key, mint any session, de-anonymize every log line, and
> complete anyone's sign-in; credentials written through the management API
> were already narrowed, and the router's own keys — the more serious of the
> two — were not.

**`--generate-secrets` writes key files under the process umask.**

*Specification 10* requires secrets at rest to use a platform secret facility,
or files protected by an operator-supplied key. *Specification 20.1* requires
separated, restricted writable directories.

*What the code does:* `Secrets::write_to`
(`crates/hypellm-router/src/startup.rs`) calls `hypellm_store::write_atomic`, which
uses `File::create` — mode 0666 masked by the umask. On a default `umask 022`
the five router key files land world-readable. By contrast, credentials written
through `CredentialStore::store` **are** `chmod`ed to 0600
(`crates/hypellm-router/src/state.rs`, `restrict_permissions`).

*Consequence:* `store_mac.key`, `key_verifier.key`, `session.key`,
`pseudonym.key`, and `oidc.key` are the router's entire root of trust, and
`--generate-secrets` can leave them readable by every account on the host.

*Resolution:* call `restrict_permissions` on each file in `Secrets::write_to`,
and `chmod 0700` the directory. Until then, `umask 077` before generating.

### DI-036
**The provider's `Retry-After` header is never read.**

*Specification 7.1* lists `decode_response(status, headers, body_stream)`;
*specification 6.5* requires "`Retry-After` is capped by the remaining
deadline".

*What the code does:* the plumbing is complete —
`RouterError::with_retry_after`, `dispatch::attempt` copying
`classification.retry_after_secs`, and `routes.rs` emitting the `Retry-After`
response header — but `Adapter::classify_error` receives only `(status, body)`,
so no adapter can see the header, and all eight construction sites in
`crates/hypellm-adapters/` set `retry_after_secs: None`.

*Consequence:* a provider's back-off hint is discarded. Retry timing falls back
to the router's own budget, which is safe but ignores the signal the provider
sent, and clients never receive a `Retry-After` on a 429 originating upstream.

*Resolution:* widen `Adapter::classify_error` to take the response headers, or
have `dispatch::attempt` read `Retry-After` itself and cap it against
`Deadline::remaining` (`hypellm_core::time` already implements the cap).

**Resolved** by the second, which keeps the adapter trait narrow: `Retry-After`
is standard HTTP with standard semantics rather than anything provider-specific,
so this is one implementation instead of eight, and the deadline it must be
capped against is already in scope at that point.

`dispatch::retry_after_secs` fills the hint only when the classification did not
already carry one, so an adapter that parses a back-off out of its provider's
*body* still wins — it knows that shape and this does not.

Only the delta-seconds form is honoured. The HTTP-date form would need a date
parser, and a wrong answer is worse than none: too large and the request sits
out its deadline for nothing, too small and the router hammers a provider that
asked for room. An unparsed value falls back to the router's own retry budget.

The cap is not politeness. An uncapped hint lets a provider hold a request past
its deadline — a client-visible stall the router promised would not happen — and
a misconfigured upstream can ask for a year.

### DI-037
**No stream watermarks; the full decoded event list is retained per attempt.**

*Specification 14* requires high/low watermarks that pause upstream reads;
*specification 3.2* sets a 256 KiB per-stream buffer budget.

*What the code does:* backpressure is emergent rather than explicit — the
per-connection thread blocks in `StreamSink::push`, which stops it calling
`connection.read_body`. Correct for the blocking model, but there is no
watermark to tune and none to assert on. Separately, `dispatch::attempt` pushes
every decoded `CanonicalEvent` into a `collected` vector so usage and native
model can be read after the stream ends; bytes still reach the client
incrementally, so specification 14's "MUST NOT buffer an entire completion"
holds for *latency*, but memory for one attempt is bounded only transitively by
the 64 MiB `Limits::UPSTREAM.max_body_bytes` cumulative cap.

*Also:* `hypellm_core::event::ResponseAccumulator` has no ceiling on `text`,
`reasoning`, `tool_calls`, or `embeddings`, and every `ToolCallDelta` linearly
scans `tool_calls`, so N distinct indices cost O(N²).

*Resolution:* explicit high/low watermarks in `StreamSink`, and retain only the
scalars (`usage`, native model) rather than the event list.

**Partly resolved.**

*Done — the retention half.* `retain_after_stream` keeps only `Start` and
`Usage`, and both are now capped at `MAX_RETAINED_EVENTS` (256): a provider
chooses how many of those it sends, so "only the scalars" was still unbounded
without a cap. The non-streaming path applies the same filter, so the two cannot
drift into disagreeing about what a later stage can read. `Usage` is kept in
full rather than reduced to the last one because the Anthropic adapter merges
across all of them — input tokens arrive in `message_start` and output tokens in
`message_delta`, so taking the last would report zero input.

*Done — the accumulator half.* `ResponseAccumulator` now bounds text, reasoning,
tool-call count, per-call arguments, and embeddings (`event::limits`), reports
`truncated()` so a shortened completion says so rather than reading as complete,
and truncates on a character boundary — a completion cut mid-character would
fail to serialise and turn a large response into an error. The O(N²)
`ToolCallDelta` scan is an index map now; a provider chose both N and the number
of deltas.

*Done — the observability half.* Backpressure is now measured even though it
cannot be tuned. `StreamSink::push` times the blocking write and the stream
reports the total as `hypellm_stream_backpressure_milliseconds`, labelled by
operation and nothing finer (specification 7.1). This is the quantity a high
watermark would have controlled, and without it "the client is slow" and "the
provider is slow" were indistinguishable from outside — which was the practical
cost of the missing watermark, separate from the missing knob.

*Not done — the watermark half.* Backpressure remains emergent: the
per-connection thread blocks in `StreamSink::push`, which stops it reading
upstream. That is correct for the blocking model and has no tunable, so
specification 14's explicit high/low watermarks are still absent.

Adding them means the event loop (`DI-001`), and it is worth being precise about
why rather than deferring by association. A watermark is a rule about how full a
buffer may get before reads pause. This path has no buffer: the same thread
reads upstream and writes to the client, so the pause is immediate and total.
Introducing a queue purely so there were a watermark to set would add latency and
memory to satisfy the letter of specification 14 while making the behaviour it
asks for worse. The knob only becomes meaningful once reads and writes are
separated, which is what `DI-001` describes.

*A note on the timing test that was deleted.* A wall-clock assertion for the
quadratic fix was written and removed: at any size that runs quickly the linear
version passes it too, so it would have been decoration. What is asserted
instead is that interleaved deltas land in the right slots, which is the failure
the optimisation could actually cause. The complexity claim rests on reading
`push`.

### DI-038
**Entropy failure degrades request identity instead of failing closed.**

*Specification 17* requires request ids for correlation; the decision trace,
audit record, and `X-Request-Id` all key on it.

*What the code does:* `crates/hypellm-router/src/routes.rs` and `admin.rs` use
`random::u128_value().unwrap_or(0)` and an equivalent fallback to a 32-zero
string. If `/dev/urandom` is unavailable, every request is assigned id `0` and
correlation collapses silently.

*Bounded by:* `hypellm_crypto::random::fill` returns an error rather than falling
back to a weaker source, so no *security* value is ever weak — session tokens,
key secrets, and OIDC state all fail closed. Only the request id degrades.

*Resolution:* return `503 internal_fault` on entropy failure, or at minimum emit
a `critical` log event and a metric so a silently uncorrelatable router is
visible.

**Resolved** by doing both, on both listeners. An entropy failure now answers
`internal_fault`, emits `router.entropy_unavailable` at `critical`, and
increments `hypellm_entropy_failures_total`.

Failing closed rather than degrading is the consistent choice, not the harsh
one: session tokens, API key secrets, and OIDC state already refuse rather than
weaken, so a router that cannot read entropy is already unable to authenticate
anyone. Serving inference with an unusable identity would have been the one path
that pretended otherwise — and an audit trail in which every entry shares an id
is worse than one missing entries, because it looks complete.

*Limit of the test.* Entropy failure has no injection seam, and adding one to
`hypellm-crypto` would mean a test-only failure path in the crate every other
secret depends on. What is tested is the property a reintroduced fallback would
break: identifiers are present, distinct across requests, and never the all-zero
value, on both the success and the error path.

### DI-039
**`testing` modules are ungated public API.**

*Specification 18.2* forbids `unwrap`/`expect` outside startup invariants and
tests; *specification 4.1* requires each module's public surface to be declared.

*What the code does:* `crates/hypellm-router/src/lib.rs` and
`crates/hypellm-adapters/src/lib.rs` both declare `pub mod testing;` with no `cfg`
or feature guard, so `FakeUpstream`, `TestRouter`, a fixed store MAC key of
`b"test-store-mac-key"`, and fixture builders using `.expect(…)` are part of the
released library's public API. `hypellm_store::tempdir::TempDir` and
`hypellm_telemetry::MemorySink` are likewise shipped in the library and both panic
or grow without bound.

*Bounded by:* nothing in the binary references any of them.

*Why they are public:* so the integration and compatibility suites build the
*same* fixtures the unit tests use — two suites with subtly different fixtures is
how a golden test passes against something the router never sends.

*Resolution:* a `test-harness` feature gating all four, enabled by the test
crates.

**Resolved.** `hypellm-router::testing`, `hypellm-adapters::testing`,
`hypellm-store::tempdir`, and `hypellm-telemetry::MemorySink` are behind
`#[cfg(any(test, feature = "test-harness"))]`. A crate's own integration tests
reach them through a self dev-dependency enabling the feature, which Cargo
unifies rather than duplicating; `hypellm-bench` now enables it in its ordinary
dependencies, because the benchmark harness genuinely needs the fixtures and
should have to say so.

The "Why they are public" paragraph above still holds and is why the feature
exists rather than the modules being deleted: two suites with subtly different
fixtures is how a golden test passes against something the router never sends.

Mechanically enforced, so it cannot quietly revert: `depscan` gained
`test-scaffolding-gated`. It skips crates reachable only through
`[dev-dependencies]` — those cannot reach a production build, so gating them
would be ceremony — and that exemption is *computed* rather than listed, because
an exemption list is a place for things to hide.

### DI-042
**Mid-file log corruption silently discards everything after it.**

*Specification 11.2:* "Startup replays only complete valid frames."

*What the code does:* `Log::replay` (`crates/hypellm-store/src/log.rs`) stops at
the first frame that does not decode and reports that offset as `valid_len`;
`Store::open` truncates there. Correct for a **tail**, which is the only case a
clean crash produces. It is not correct for a frame damaged mid-file — for
example after a partial write on ENOSPC, where `Log::append` returns an error
without advancing `self.len` and the next append lands past the partial bytes.
Every durable record after the damage is then dropped at the next startup,
silently.

*Consequence:* durably recorded key revocations, config activations, and audit
records can disappear on a restart following a disk-full event.

*Resolution:* scan past a damaged frame to look for a valid frame with a higher
sequence number, and refuse to start (rather than truncate) when one is found —
that distinguishes a torn tail from mid-file damage.

**Resolved** exactly so. `LogError::MidFileDamage` names the offset, the last
intact sequence, and the sequence that survives after the damage — so the
refusal tells an operator what would have been lost, not merely that something
was wrong.

The scan walks byte by byte looking for the frame magic, because the damage has
unknown length and the next frame can start anywhere. Every candidate is fully
decoded and MAC-checked before it counts, so the magic appearing inside a
payload cannot be mistaken for a frame, and a *lower* sequence number does not
count either — that is stale bytes from a compacted log, not a surviving record.

The distinction has to be made rather than simply refusing on any decode
failure: a torn tail is what a clean crash produces, it happens routinely, and
refusing over one would turn every unclean shutdown into an outage. Both halves
are tested, and the mid-file test replays 2 of 5 records without the fix.

### DI-043
**Audit field caps are asymmetric between the write and read paths.**

*Specification 17* requires capped audit fields.

*What the code does:* `AuditEvent::reason` is `Capped` at 512 bytes
(`crates/hypellm-store/src/audit.rs`), but `actor`, `tenant`, `object`,
`request_id`, and `source` are plain `String` with no cap on write — while the
read path parses under `wire_json::Limits::SMALL` (64 KiB per string, 1 MiB
total).

*Consequence:* a caller supplying an oversized actor or object writes a record
that cannot be parsed back. Combined with `DI-015` (recovery skips unparseable
records silently), the live chain head can diverge from the durable history with
no error.

*Bounded by:* every current call site passes identifiers already capped at
`MAX_ID_LEN` (128).

*Resolution:* `Capped` on all five fields at construction.

**Resolved.** `MAX_AUDIT_FIELD` (256) applies to `actor`, `tenant`, `object`,
`request_id`, and `source` at construction; `reason` keeps 512, because it is
prose an operator writes rather than an identifier. The longest a legal
identifier can be is `ids::MAX_ID_LEN` (128), so a value this cap truncates was
already malformed.

The consequence this entry paired with `DI-015` is now sharper, not softer:
recovery treats an undecodable audit frame as a broken chain and **refuses to
start**. So an uncapped field was not merely a record that could not be read
back — it was a way to make the router unbootable by writing one.

Two tests: the caps themselves, and the property they exist to preserve —
a record built from oversized input still round-trips through
`to_payload`/`from_payload` with its chain link intact.

### DI-044
**`Log::replay` buffers the whole log at startup.**

*Specification 3.2* requires bounded buffers.

*What the code does:* `Log::replay` reads the entire file with `read_to_end` and
then materialises every frame, so peak startup memory is roughly twice the log
size. `read_optional`, which loads `snapshot.bin`, is likewise unbounded.
Nothing in the crate caps the log or triggers compaction — that budget is set by
whoever calls `Store::compact`, and nothing calls it automatically.

*Bounded by:* the log is written only by this process, and management mutations
are rate-limited by human action.

*Resolution:* stream frames from a `BufReader` rather than materialising the
file, and schedule compaction from the router's own maintenance path.

**Resolved**, except that the second half of the resolution as originally
written turns out to be wrong — recording that is the more valuable part of this
entry.

*Done:* replay refuses a log larger than `log::MAX_LOG_BYTES` (256 MiB) before
reading it, and `read_optional` refuses a state file larger than
`MAX_STATE_FILE_BYTES`, checking the metadata first and bounding the read with
`take` so a file that grows during the read is caught too. That converts "the
router OOMs on every restart, and the state that would explain why is the state
it cannot read" into a message naming the file and the limit.

*Done since:* `Log::replay_retaining` lets a caller say which frames it wants
kept. Every frame is still decoded and every integrity check still runs — the
filter decides what is *materialised*, never what is *verified*, and there is a
test that tampers with a frame of an unasked-for kind and asserts the replay
still refuses. `Store::audit_records`, `checkpoints`, and `records_of_kinds` use
it, so an audit export no longer holds the whole log in memory to return a page
of it. That was where the memory actually grew once those endpoints existed.

*Done since:* replay streams. `Log::replay_retaining` reads through a bounded
`Window` — `WINDOW_START_BYTES` (64 KiB) initially, growing only when a frame
needs it and never past `MAX_FRAME_BYTES` — instead of `read_to_end` on the
whole file. Peak startup memory is now one frame plus the frames actually
retained, rather than the file plus the frames. For a log of ordinary records
the window never grows at all.

Two decisions carried the risk that had this deferred twice:

- **The window does not parse the length prefix.** It feeds `frame::decode`
  whatever it holds and grows on `FrameError::Incomplete`, so `decode` remains
  the single authority on how long a frame is. A second implementation of that
  question, disagreeing with the first, is precisely how a log gets silently
  truncated — which is the defect class `DI-042` was.
- **The rewrite is checked against the code it replaced.** The buffered replay
  is kept in `#[cfg(test)]` as a reference, and
  `streaming_replay_agrees_with_the_buffered_reference` compares the two across
  600 generated logs spanning intact, torn-tail, mid-file-damaged, tampered, and
  garbage-spliced shapes, including payloads large enough to force the window to
  grow. Outcomes must match exactly — frames, truncation offset, stop reason,
  and error.

That test earned its place on its first run: it caught the streaming lookahead
consuming one byte past a candidate frame it lacked the bytes to judge, which
made it miss the *first* surviving frame after mid-file damage and report a
later one. The failure was benign — both implementations still refused to start
— but the same off-by-one against a log whose only surviving frame was that
first one would have reported a torn tail and silently discarded every record
after the damage. `DI-042` again, reintroduced by the fix for `DI-044`. The
mid-file lookahead is bounded in memory but deliberately *not* in file extent,
for the same reason: capping how far it looks would misclassify damage followed
by enough garbage.

*Should not be done as written:* **do not schedule `Store::compact` from a
maintenance path.** Compaction resets the log, and the log is where API key
creations and revocations, the audit chain, and configuration activations live.
A payload that omits them compiles, succeeds, and destroys them — every issued
key stops authenticating after the next restart and the audit history is gone.
Automatic compaction needs a snapshot codec covering all three, which does not
exist. `Store::compact`'s doc comment now says so at the call site, because the
previous wording made it look like an ordinary maintenance operation.

### DI-045
> **RESOLVED.** `hypellm_adapters::is_usable_credential` is applied where a
> credential is *loaded* — both at startup and in `CredentialStore::store` — so
> a value that cannot appear in a header never reaches an adapter. This closed
> a second issue the original entry did not name: a credential containing CR or
> LF was header injection from a file in the state directory, which is precisely
> the position the threat model assumes an attacker may reach.

**Adapter `encode_headers` fails open on a non-UTF-8 credential.**

*Specification 7.1* makes credential handling the adapter's sole responsibility.

*What the code does:* both adapters write the authorization header only inside
`if let Some(secret) = credential.expose_str()`. A credential whose bytes are not
valid UTF-8 yields **no** header, and the request is dispatched
unauthenticated. The resulting 401 classifies as `Authentication`, which does not
affect health, so the misconfiguration presents as a quiet per-request failure
rather than as a target going down.

*Resolution:* return `ValidationFailure` from `encode_headers` when the
credential cannot be rendered, so the request fails closed with a diagnosable
error.

### DI-046
**No rollback endpoint.**

*Specification 15.3* requires the routing-policy screen to offer rollback;
*specification 17* lists rollback as an audited action and
`AuditAction::PolicyRolledBack` exists.

*What the code does:* `Activatable::rollback`
(`crates/hypellm-store/src/activation.rs`) is implemented and retains 8 versions
by default. No handler calls it; there is no route, and `PolicyRolledBack` has no
producer.

*Consequence:* recovering from a bad publication means re-publishing the
previous configuration as a new draft — which requires a second approver, and
therefore cannot be done unilaterally during an incident.

*Resolution:* `POST /admin/v1/policies:rollback` gated on `PublishPolicy`,
writing a `ConfigActivation` frame for the restored version and a
`PolicyRolledBack` audit record. Whether rollback should also require a second
approver is a policy question worth deciding explicitly.

**Resolved**, and the policy question is decided: **one operator, not two.**
Publication needs a second approver because it changes policy to something
nobody has reviewed. Rollback restores a configuration that was *already*
published under that rule, so the second signature has already been given —
and requiring another would make the recovery path unavailable precisely when an
incident has one operator awake, which is how a bad publication stays live. A
reason of 8–256 characters is required instead, and recorded.

Two implementation notes:

- **The previous configuration's text is re-loaded under a new version**, not
  swapped back in as an object. Two configurations must never share a version
  number: `If-Match` ETags derive from it, and an operator watching it through
  an incident needs the change to be visible. Reinstating the old object would
  make the counter go backwards.
- **`Activatable::rollback` is gone.** Re-loading is the real path, so a
  swap-back method would have been a second, subtly different activation path
  that nothing calls — the shape of dead code most likely to be picked up by
  mistake. `Activatable::previous` replaces it, which is what the durable-first
  ordering actually needs: the frame is written before the swap, so the caller
  has to know what the swap will produce without committing to it.

### DI-049
**Log volume is unbounded per unit time, and `StderrSink` blocks.**

*Specification 3.2:* "No request may create an unbounded thread, task, buffer,
channel, retry loop, or log entry."

*What the code does:* each log *entry* is bounded — 256 bytes per string field,
a closed 26-field vocabulary — but `crates/hypellm-telemetry/src/logs.rs`
rate-limits nothing, samples nothing, and deduplicates nothing. A flood of
rejected requests converts request rate directly into log-write rate.
`StderrSink::write_line` also takes the process-wide stderr lock and writes
synchronously with **no deadline**, so a stalled reader blocks every emitting
thread — a data-path stall introduced by observability.

*Resolution:* a bounded, drop-on-full queueing sink with a background writer,
plus per-event-code rate limiting. In the interim, redirect stderr to a local
file rather than a pipe.

**Resolved**, both halves, and the interim advice is no longer needed.

`QueueingSink` puts one fixed writer thread behind a bounded queue
(`MAX_QUEUED_LINES`, 4 096 — roughly 2 MiB). Callers append and return; a
stalled reader now stalls only the writer. When the queue is full the *oldest*
line is dropped, because during an incident the newest are the ones worth
keeping, and the drop count is emitted with the next line that gets through:
losing lines silently would be this same failure arriving by another route.
`Drop` joins the writer, so shutdown drains rather than discarding — the lines
most worth keeping are the ones written just before a process stopped.

Rate limiting is per event code, so a flood of one cannot starve another, and
`Critical` is never limited: it is the severity reserved for things an operator
must not miss, and no volume of them makes losing one acceptable.

One correction worth recording. The first cut set the limit at 100 lines per
code per second, and a test caught that this would throttle ordinary
per-request logging — blinding normal operation to protect against a flood that
admission control has already bounded. The limit is 2 000 and is explicitly the
*second* bound: the queue is what protects memory and the data path, and the
rate limit only stops one code monopolising the writer.

### DI-050
**Manifests declare dependencies the source never uses.**

*Specification 4.1* requires each module to declare its dependencies accurately.

*What the code does:* `hypellm-auth` declares `wire-json` and references it from no
source file. `hypellm-net` declares `wire-sse` (used only in an integration test)
and `hypellm-crypto` (unreferenced).

*Consequence:* not a supply-chain risk — all are workspace crates and `depscan`
is clean — but the manifests overstate the real coupling, which makes the
dependency graph a worse guide to what a change can affect.

*Resolution:* drop the unused declarations, or move the test-only one to
`[dev-dependencies]`.

**Resolved**, but the entry had gone stale in the comfortable direction and the
audit is worth recording. Two of the three claims were no longer true:
`hypellm-auth` does use `wire-json` (`apikey.rs`), and `hypellm-net` does use
`wire-sse` (`client.rs`). Only `hypellm-net`'s `hypellm-crypto` was genuinely
unused, and it is dropped.

More usefully, this is now mechanically enforced. `depscan` gained a
`dependencies-are-used` rule: every `[dependencies]` entry must be referenced
from that crate's `src`, or the scan fails. Only `[dependencies]` is checked —
a `[dev-dependencies]` entry is used by `tests/`, which the scan does not read,
and `[build-dependencies]` cannot exist at all. The reference test is textual
and can be fooled by a mention in a comment, which is the safe direction: it
under-reports rather than failing a build over a dependency used in a form it
does not recognise.

Enforcement is the point. This entry drifted because nothing checked it; a rule
cannot drift.

### DI-051
> **RESOLVED.** `AuditIndex::push_event` is now the only way into the index, and
> `record_audit` passes the event it actually appended. The reconstructing
> `record` method is gone. This was the most consequential finding of the
> documentation pass: the durable chain was always correct, but the screen an
> operator watches during an incident was blank, and the tests missed it because
> the harness exercised a code path the router never took.
>
> The description below is retained as the record of what was missing.

**`GET /admin/v1/audit` returns an empty list in production, and the tests do
not catch it.**

*Specification 17* requires an audit view; specification 22.2 step 18 and 22.3
step 20 both direct an operator to read it.

*What the code does:* three pieces interact badly.

1. `AdminApi::record_audit` (`crates/hypellm-admin-api/src/handlers.rs`) appends
   the real `AuditEvent` durably — that part is correct — and then calls
   `self.state.audit.record(sequence, link, session)`.
2. `AuditIndex::record` (`crates/hypellm-admin-api/src/audit_index.rs`)
   **discards the event it was given nothing of** and synthesises a fresh one:
   `AuditEvent::new(0, session.principal, AuditAction::SettingsChanged)`. The
   timestamp is `0`, the action is `SettingsChanged` regardless of what
   happened, and **no tenant is set**.
3. `AuditIndex::recent_for_tenant` — the tenant-isolation fix that
   `list_audit` correctly calls — filters on
   `entry.event.tenant.as_deref() == Some(tenant)`, which is never true for a
   record inserted by `record`.

*Consequence:* every management mutation is durably audited and **none of it is
visible through the API**. `GET /admin/v1/audit` returns an empty list for every
caller. Before the tenant filter was added it returned rows, but with the wrong
action and an epoch timestamp on every one — a wrong action label in an audit UI
being worse than a missing one. Both runbooks that tell an operator to read the
audit view are, today, telling them to read an empty page. Combined with
`DI-025` (no read path to the durable chain) there is currently **no working way
to review the audit trail without reading `log.bin` offline.**

*Why the tests pass:* `AuditIndex::push_event` exists and does the right thing,
and the integration harness
(`crates/hypellm-admin-api/tests/harness/mod.rs`, `TestHarness::record_audit`)
calls `push_event` with a fully-formed, tenant-bearing event. The production
path calls `record`. The suite therefore exercises a code path the router never
takes — which is the general hazard `crates/hypellm-adapters/MODULE.md` warns
about for fixtures, showing up here in a test harness.

*Resolution:* delete `AuditIndex::record` and have `record_audit` call
`push_event` with the `AuditEvent` it already constructed and appended. Then add
an integration test that drives a real mutating endpoint through `AdminApi` and
asserts the resulting row appears in `GET /admin/v1/audit` with the correct
action, tenant, and timestamp — the test that is missing is what let this
survive.

### DI-052
**Unauthenticated sign-in failures could fill the durable log and make the router unbootable.**

*Specification 3.2:* "No request may create an unbounded thread, task, buffer,
channel, retry loop, **or log entry**."

*What the code did:* `/admin/v1/auth/google/callback` and
`POST /admin/v1/auth/break-glass` run before any session — by definition, since
they are how a session is obtained. Every failure on either path appended a
durable `LoginFailed` audit record: a frame that never goes away, written with
an `fsync` held under the global store log mutex. Nothing rate-limited,
throttled, or locked out the attempt, so an unauthenticated caller who could
reach the management listener decided how many records were written.

*Why it matters more than the write cost:* `Log::replay` refuses a log larger
than `MAX_LOG_BYTES` (256 MiB), so a caller who filled it made the router
**unbootable** — and the operator's only remedy, `Store::compact`, discards API
keys, the audit chain, and configuration activations (`DI-044`). An
unauthenticated request flood therefore became a denial of service that survived
restart. Measured at 244 bytes per record, the ceiling is about 1.1 million
requests: under twenty minutes at 1 000 requests per second.

The break-glass path is the sharper case. Specification 22.4 calls it "the only
endpoint that must keep working when the identity provider does not", so filling
the log through it disables the emergency recovery path exactly when it is
needed.

**Resolved.** `AnonymousAuditBudget` bounds how many failures on each
pre-session path become durable records: the first ten in a sixty-second window
are written individually, the rest are counted, and the next window opens with
one record saying how many were suppressed. Worst case is eleven frames per
minute per path instead of one per attacker request.

Three decisions, each pinned by a test that fails without it:

- **The records are bounded; the signal is not.** Every failure still increments
  `hypellm_auth_failures_total`, which is O(1) memory. An operator sees a flood in
  the metric immediately and in the audit trail once per window. Suppressing the
  record must never suppress the evidence that an attack is happening.
- **Two budgets, not one.** A shared budget would let an attacker exhaust it
  with noise on the ordinary sign-in path and have their attempts against the
  *emergency* path suppressed along with it — hiding an attack on the more
  sensitive endpoint behind traffic on the less sensitive one.
- **A window with nothing suppressed writes no summary.** An audit trail padded
  with records saying nothing happened is one people stop reading.

*How it was found:* auditing Appendix C's traceability requirement rather than
the code. Specification 3.2 names four things that must run on bounded worker
pools — "blocking DNS, filesystem synchronization, configuration compaction, and
audit export" — and `hypellm-net/src/dns.rs` quotes that sentence in full while
implementing the first quarter of it. Following the other three led to the store
`fsync` under a global mutex, and from there to who can reach an appender
without authenticating.

The other three clauses turned out to be satisfied, and the reasoning is worth
recording since it was not obvious: the data plane never appends to the store —
usage aggregates are in memory and routing reads a snapshot — so no request can
be stalled behind a disk sync. `Store::compact` has no automatic caller at all
(`DI-044` records why it must not get one). Audit export runs on a management
connection thread, bounded at 256 by the management profile, and streams rather
than materialising (`DI-044`).

*The isolation test was wrong twice before it was right,* which is worth
recording because both failures looked like passes. The first version asserted
the log file grew after a break-glass failure — but a shared budget still writes
a suppression summary, so the file grows either way. The second added a premise
check for that summary, which fires only when a window *rolls*, and four hundred
requests finish inside a sixty-second window. Only the third — count the records
the flood wrote, assert the budget engaged, then assert the break-glass record
reached disk by name — fails when the budgets are shared.

### DI-053
**Specification 12's admission table has five layers; the implementation had four scopes.**

*Specification 12* defines admission as a hierarchy:

| Layer | Controls |
|---|---|
| Global | Connections, requests/s, **input bytes/s, output bytes/s**, total concurrency |
| Tenant | Requests, tokens, concurrent streams, **daily/monthly budget class** |
| Principal/key | Requests, token buckets, maximum queued requests, model permissions |
| **Alias/model** | **Operation-specific request/token and context limits** |
| Provider/target | Concurrency, connection pool, queue, breaker, adaptive load shed |

*Specification 11.1* separately lists a `quota` record as carrying
"hierarchical rate, token, concurrency, **and budget** limits".

*What the code did:* `QuotaScope` had `Global`, `Tenant`, `Principal`, and
`Target`. There was no alias layer, no byte-rate limit, and no spend budget.
None of the three was recorded anywhere.

**Resolved.** All three layers exist now: the alias scope, the global byte
rates, and the period budget.

*The alias layer.* `QuotaScope::Alias { alias, operation }`
exists, parses from `quota scope=alias:<id> [operation=<op>]`, and joins the
reservation chain between principal and target. That position is the point: an
alias is what the caller asked for and a target is what the router chose, so a
limit attached only to targets is spread across however many the alias resolves
to — an alias over three targets with a per-target cap of two admits six.

An operation-specific quota is preferred over the alias-wide one rather than
merged, because two limits that both applied would make the effective ceiling
depend on which was checked first. An unparseable `operation` is a load error,
not a silent widening to every operation.

The layer is inert unless configured, and that is checked rather than asserted:
`reserve` and `reserve_queued` keep their signatures and delegate to
`reserve_for` / `reserve_queued_for` with no alias, so every existing caller and
all 1795 pre-existing tests kept their exact behaviour through the change.

**Done — global byte-rate limits.** `quota scope=global
input_bytes_per_second=… output_bytes_per_second=…` (with optional bursts) puts
token buckets on the controller. They catch what neither neighbouring control
can: `max_body_bytes` bounds any single request and the request rate bounds how
many arrive, but nothing bounded their *product* — a modest number of very large
requests passed both.

The two directions have separate buckets, so a heavy download cannot consume the
allowance for reading requests. Input is charged before the reservation, so an
exhausted budget refuses with no narrower bookkeeping to unwind. Output is
charged *after* the response, from `ClientWriter::bytes_written`, and therefore
throttles subsequent requests rather than the current one — truncating a
response mid-stream to satisfy a rate limit would corrupt it.

Refused on any scope but `global`, because specification 12 places them only at
that layer and a value set on a narrower scope would be silently ignored — the
configuration mistake that is found months later, when the limit turns out never
to have applied.

**Done — daily/monthly budget.** `quota … budget=<minor units>
budget_period=daily|monthly` caps period spend, in the same minor units as the
price schedule (`DI-048`) so no conversion is needed.

Charged from **actual** provider-reported cost, not from the admission estimate.
That is the decision the design turns on: the byte-based estimator over-counts by
roughly a factor of two, and a budget enforced on it would refuse a tenant at
half their allowance while reporting that they had spent it all. The price is
that a scope can overshoot by the requests already in flight when it crosses the
line, which is bounded by its own concurrency limit — a bounded overshoot is a
better failure than a systematic false refusal.

`BudgetExhausted` is its own rejection rather than another rate error, because
it does not clear when load drops: it clears when the period rolls, which may be
hours away. An operator seeing it needs to raise the budget or wait, not add
capacity.

Periods are fixed rolling windows — 24 hours, 30 days — not calendar periods. A
calendar month needs date arithmetic across leap years, month lengths, and the
operator's timezone; the workspace has no date library and may not acquire one
(specification 4). The window is stated rather than implied, and it never
drifts. A misspelled `budget_period` is a load error, since defaulting it to
daily would silently apply a monthly budget every day — thirty times the spend
the operator authorised.

Budgets partition like every other limit (`DI-029`): N nodes each holding the
whole figure would let the deployment spend N times it.

Note that this is not the billing system the specification excludes as a
non-goal: the exclusion is at line 54 ("not an … billing system") and
specification 25 draws the line as "configured price schedule with effective
dates; provider usage reconciliation; **not a billing ledger**". A spend cap
that refuses admission is a quota, and specification 12 lists it as one.

*How it was found:* the Appendix C traceability audit, run after `DI-052` showed
a partial one was worth finishing. Eight of the enumerated
requirements checked out fully — OIDC claim validation (7 of 7), HTTP framing
rejections (6 of 6), breaker transitions, reauthentication actions, SSE framing,
passive health signals, SSRF controls, and quarantine fields. Two did not: this
entry, and the `module-documentation` gate, which required three of the six
declarations specification 4.1 names while its own failure message quoted all
six. That gate now checks all six, and by declaration rather than by substring —
it could not previously fail for `Limits`, because the word appears in the prose
of every `MODULE.md`.

### DI-054
**Disk-full recovery was never demonstrated, and two defects were hiding behind that.**

*Specification 21* requires a resilience layer covering "corrupt tail, disk
full, clock skew, slow client, reload race". *Appendix C* asks for recovery from
"corrupt tail, **disk full**, provider outage, identity outage, and killed
process" to be **demonstrated**.

*What the code did:* six of the seven resilience scenarios had tests. Disk full
had none — only a comment in `log.rs` reasoning about what a partial write on
`ENOSPC` leaves behind. The behaviour had been thought about and never executed.

**Resolved**, and writing the test found two defects that the reasoning had
missed.

*How it is tested:* `/dev/full` is a standard Linux device whose writes return
`ENOSPC`. It needs no privileges and no dependency, so the disk-full path is
exercised for real rather than by faking an error kind. The tests return early
where the device is absent, so no other platform fails the suite.

**Defect 1 — a full disk corrupted the audit chain.** `AuditChain::append`
advances the running head *before* the record is written, because the record's
payload contains the link. So an `ENOSPC` left the live head including a record
that never reached disk. Every later record then chained from that phantom head,
and on restart replay rebuilt the chain without it — so the links no longer
matched and `Recovery::audit_chain_broken_at` reported damage.

A full disk presenting as tampering is the wrong incident entirely: one is a
page to whoever owns the storage, the other is a security response. The head and
count are now captured before the append and restored if the write fails. A
failed *checkpoint* restores its interval counter instead, since a checkpoint
summarises the chain rather than linking into it — losing one costs a retry,
not correctness.

**Defect 2 — the streaming replay had no bound of its own,** introduced by
`DI-044`. The size guard reads `metadata().len()`, which is right for a regular
file and wrong for anything else: a character device reports zero and yields
bytes forever, and a file being appended to never reaches the length that was
measured. The buffered replay it replaced would have exhausted memory; the
streaming one looped without end, which is worse — a startup hang with no
diagnostic. Specification 3.2 bounds every loop, so the reader now counts what
it has actually read rather than trusting the filesystem.

The mutation that proved this test load-bearing is worth recording: with the
over-limit report removed, an endless log replays to
`Ok(Replay { frames: [], truncated_at: Some(0) })` — the entire log silently
discarded as a torn tail, reported as success. That is the `DI-042` failure
mode arriving by a third route.

*What is still not injectable:* a write failure inside an already-open `Store`.
The file descriptor is open, so permissions no longer apply, and a store cannot
be opened on `/dev/full` at all now that replay refuses it. The chain rollback is
therefore tested against `AuditChain` directly — that the restore is exact,
which is the part with logic in it — and the two-line wiring in `append_audit`
is verified by reading. Recorded rather than glossed, because a test that
appears to cover the wiring and does not is worse than one that says it does not.

### DI-055
**A log that was never this router's was discarded and reported as a torn tail.**

*Specification 11.2:* "Startup replays only complete valid frames."

*What the code did:* `Log::replay` treats any non-integrity decode failure as a
torn tail and truncates to the last valid offset. At offset zero there is no
last valid offset, so a file whose *first* frame does not decode was truncated
to nothing — every record it held destroyed — and the only signal was a warning
named `store.tail_truncated`, reading as a routine crash artifact.

This is reachable without malice: a `state_dir` pointed at the wrong directory,
a log written by a different build, or any file that is not this router's log.

*Found by:* the rename to `hypellm`, which changed the frame magic from `AEGS`
to `HYPE` and so made every pre-rename log a file whose first frame does not
decode. The rename did not create the defect — it made an existing one
reachable, which is the useful kind of accident.

**Resolved.** A non-recoverable failure at offset zero is now
`LogError::UnknownFormat`, and startup refuses. The rule is scoped by *error*
rather than by offset alone, because the two cases are genuinely different: a
crash during the very first append leaves a short frame, which decodes as
`Incomplete` or `ChecksumMismatch` — both `is_recoverable_tail()` — and must
still truncate, or a crash on a brand-new store would need manual intervention
to start. `BadMagic`, `UnsupportedVersion` and `PayloadTooLarge` at offset zero
mean the bytes are not this log, and are refused.

Both halves are tested and both mutations are caught by *different* tests:
deleting the rule fails `a_log_in_an_unrecognised_format_is_refused_rather_than_erased`,
and widening it to `offset == 0` alone fails `a_torn_first_append_still_truncates`.

*Also closed here:* the store was half-renamed. `META_MAGIC` was still `AGMT`
while the frame magic had become `HYPE`, so a pre-rename **snapshot** still
loaded while the **log** beside it was wiped — a router that came up restored to
the last compaction point with everything after it gone, looking healthy. The
metadata magic is now `HYMT`. That side already failed closed on a mismatch
(`CorruptSnapshotMetadata`), so it needed no separate guard; the defect was the
asymmetry, not the check.

**On-disk formats changed.** `log.bin` and `snapshot.meta` written by a
pre-rename build are not readable by this one, by design — and now say so
loudly instead of being discarded quietly. There is no migration path and none
is planned; start from an empty `state_dir`.
