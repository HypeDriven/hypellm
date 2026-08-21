# The HypeLLM fleet agent

This directory holds the reference **fleet agent**: the process that actually
starts and stops containers on slave machines.

It is deliberately outside the Rust workspace. It is not a workspace member, not
built by `cargo build --workspace`, and not scanned by `depscan` as router
source. That is not an oversight — it is the whole point.

## Why it is a separate process

Starting a container on `10.0.0.105` means running `ssh` and `docker`. The
router cannot do this and must not be changed so that it can: specification 4.1
forbids subprocess execution, `depscan`'s `forbidden-api` rule fails the build on
`process::Command`, and a router that can spawn a shell is a different security
proposition from one that cannot.

The specification already solves this shape twice — specification 4 delegates
outbound TLS to a platform helper with a narrow CONNECT-like API, and 9.1
delegates JWT verification to a local verifier over a narrow authenticated
interface. This is the third member of that family and follows the same rules.

**This is an honest cost, not a free win.** The agent holds SSH keys to every
slave and can stop production models on all of them. It is in the trusted
computing base and should be reviewed as such.

## What the router may tell it

Identifiers and bounded integers. The socket carries no image name, no host
address, no file path, no container name, no Docker flag, no shell fragment, and
no URL — only opaque `deployment-id`, `artifact-id`, `host-id`, and `lease-id`
tokens both sides hold from their own configuration.

The agent maintains **its own** allowlist (`fleet.example.json`) mapping each
identifier to a host, an SSH destination, and a command. The router cannot extend
it. The goal is specific: **a fully compromised router cannot cause arbitrary
code to run on a slave.** It can reorder declared deployments; it cannot
introduce one.

An unrecognised identifier is refused with `ERR unknown_deployment`.

## Obligations

These are normative. An agent that does not keep them is not this agent.

- **Runs as its own unprivileged user**, separate from the router.
- **Per-host SSH keys restricted by a forced `command=`** in the slave's
  `authorized_keys`, with `no-pty`, `no-port-forwarding`, `no-agent-forwarding`,
  and `no-X11-forwarding`. The agent's key must not grant an interactive shell.
- **Never interpolates a router-supplied value into a command line.** Router
  input selects a row in the agent's own table; the row's fields become the
  argument vector, and `subprocess` is called with `shell=False`.
- **Applies its own per-host activation rate limit.** A router bug must not be
  able to exhaust the fleet through the agent.
- **Verifies artifact digests before an artifact becomes activatable**, and
  refuses to activate an unverified one.
- **Reports memory as observed from the accelerator**, not as configured, so the
  router can detect drift between the declaration and the machine.
- **Bounds and truncates every reported field.**

## Setting it up

### 1. Write the allowlist

Copy `fleet.example.json` and edit it to match your machines. Every deployment
needs a host, an accelerator, a start command, a stop command, and a readiness
probe.

The probe matters more than it looks. A TCP connect is not readiness: a
llama.cpp server accepts connections long before it has finished mapping twenty
gigabytes of weights, and a router that believes otherwise sends the first
request into a timeout and opens a circuit breaker on a model that was working.
Probe something that only answers when the model is loaded.

### 2. Confirm both sides agree

```bash
agent/fleet-agent --config agent/fleet.example.json --print-digest
cargo run -q -p hypellm-router -- --check --config docs/examples/fleet.conf
```

The two digests are computed independently, from two different files, by two
different programs. **They must match.** When they do not, the router issues no
mutating verb, marks every orchestrated target ineligible with
`fleet_configuration_mismatch`, and audits it — a router and an agent that
disagree about what an identifier means must not act on that disagreement.

The digest deliberately covers only identifiers, placement, and architecture.
Retuning a dwell floor or an activation budget is the router's business and does
not force an agent restart; moving a deployment to a different accelerator is
not, and does.

### 3. Share the key

The router generates `fleet.key` alongside its other secrets:

```bash
cargo run -p hypellm-router -- --generate-secrets /var/lib/hypellm/secrets
```

Copy `<secrets>/fleet.key` to the agent's own directory, owner-readable only.
The handshake carries `HMAC-SHA-256(fleet.key, version ‖ nonce ‖ fleet-digest)`,
so it binds both the protocol version and the fleet each side claims, and the
agent rejects a nonce it has already accepted.

This is deliberately **stronger than the control socket's `control.key`**, and
does not reuse it. That one sends the hex-encoded key itself as a bearer line;
adequate for a local stop command and inadequate for verbs that stop production
models.

### 4. Run it

```bash
agent/fleet-agent \
    --config /etc/hypellm/fleet.json \
    --socket /run/hypellm/fleet.sock \
    --key /etc/hypellm/fleet.key \
    --agent-id local
```

The socket is created owner-only. Point the router at it with:

```text
fleet_agent id=local socket="/run/hypellm/fleet.sock" \
    observation_interval_ms=5000 observation_max_age_ms=30000
```

and set `fleet_enabled=true` in the `settings` record.

## What this reference implementation does not do

Stated so the gaps are not mistaken for controls:

- **No resumable fetches.** `FETCH` runs `docker pull` and verifies the digest
  afterwards. A 40 GB download that fails partway restarts. Specification-
  extension 12 requires resumability; this does not have it, and
  `docs/deferred-issues.md` records that.
- **No Windows-host support.** Four of the six machines are Windows hosts whose
  SSH lands in WSL, where `powershell.exe` interop reaches the Windows side.
  Driving that is entirely the agent's concern — the router must never learn
  that some hosts need it — but this reference agent does not implement it.
- **No forced `command=` enforcement.** It is documented above as an obligation
  and configured on the slave, not by this program. An agent deployed without it
  has a much larger blast radius than one with it.
- **Observation is serial.** Each host is probed in turn on the observing
  thread. With five hosts and a five-second interval this is comfortable; with
  fifty it would not be.

## Protocol

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

`ACTIVATE`, `DEACTIVATE`, and `FETCH` are asynchronous and **idempotent per
`lease-id`**: re-sending returns the same `activation-id` rather than starting a
second one. That is what makes the router's crash recovery tractable.

States are a closed vocabulary: `pending`, `draining`, `stopping`, `fetching`,
`starting`, `probing`, `ready`, `failed`, `stopped`, `cancelled`. An
unrecognised state fails the router's whole observation rather than being mapped
to something plausible.

The normative definition lives in `crates/hypellm-fleet/src/protocol.rs`, and
`crates/hypellm-net/src/fleet_sim.rs` is a conformant simulator used by the
integration suite — so `cargo test --workspace --offline` exercises the full
activation path with no SSH, no Docker, and no network.
