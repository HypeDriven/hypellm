# HypeLLM Router — operator documentation

Specification 2.3 makes documentation a release-acceptance item and Appendix C
puts "threat model and abuse cases are current" and "operational owners accept
… runbooks" in the definition of done. These four documents are that material.
They describe the router **as built**, not as specified; where the two differ,
the difference is named and cross-referenced rather than smoothed over.

| Document | Read it when |
|---|---|
| [threat-model.md](threat-model.md) | Reviewing the design, or deciding whether a change weakens a control. Trust boundaries, assets, attacker capabilities, the specification 10.1 threat table with a file reference for every control, and five worked abuse cases. |
| [runbooks.md](runbooks.md) | Something is on fire. Specification 22's four runbooks — provider outage, credential rotation, compromised router API key, Google identity outage — as numbered steps against real endpoints, real config records, and real CLI flags. |
| [deployment.md](deployment.md) | Standing an instance up. Deployment profiles, the TLS boundary the router deliberately does not cross, secrets and state directory layouts, listener separation, and exactly which parts of specification 20.1's process hardening are the deployment's job rather than the code's. |
| [deferred-issues.md](deferred-issues.md) | Before trusting any claim in the other three, and before writing a release note. Fifty-five entries: every stated deviation from the specification, every unimplemented normative requirement, and every known defect, each with what the specification requires, what the code does, why, and what would resolve it. |

Per-module threat notes, limits, and fuzz obligations live next to the code they
describe, in each crate's `MODULE.md` (specification 4.1). The threat model
indexes them rather than duplicating them. Note that several `MODULE.md` threat
notes describe defects that have since been fixed; `deferred-issues.md` records
which, and is the more current of the two.

## Start here

- **New to the codebase?** `threat-model.md` §1–2, then the root `CLAUDE.md`.
- **Deploying?** `deployment.md` end to end, then `deferred-issues.md` entry
  `DI-003` (no privilege drop, no sandbox, no environment scrub) — that one is a
  deployment-time action and always will be, because every operation it names
  needs `unsafe` FFI. `DI-004`, `DI-034`, and `DI-035` were also on this list
  and are now closed in code: the control socket is authenticated and 0600,
  shutdown drains within a deadline, and generated secrets no longer inherit the
  umask. What remains a deployment-time action is preprovisioning the
  break-glass token (`DI-005`) — the code cannot do that for you, because the
  point is that the token lives somewhere the router does not.
- **On call?** `runbooks.md`. Check before you need it that a break-glass token
  has been preprovisioned and that the principal it names still holds a
  `role_binding` — without both, runbook 22.4 has nothing to offer during an
  identity-provider outage.

## Not yet written

Nothing is currently cited that does not exist. `main.rs` used to point at
`docs/operations.md`, which was never written; it now points at
[deployment.md](deployment.md#shutdown), where the content actually lives.
