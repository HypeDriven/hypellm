# The reference init

`hypellm-init` runs `hypellm-router` as its child and turns `SIGTERM` into
`hypellm-router --shutdown`.

## Why this exists

The router cannot handle a signal. `sigaction` and `signalfd` are both `unsafe`
FFI, specification 18.2 forbids `unsafe` workspace-wide, and the Rust standard
library has no signal API. The router's answer is an authenticated control
socket, and `hypellm-router --shutdown` is how every documented stop path
reaches it.

That was enough for `systemd`, which has `ExecStop`. It was not enough for a
container. **A container's PID 1 receives no default signal actions from the
kernel**, so a router running as PID 1 does not merely fail to drain on
`SIGTERM` — it ignores the signal entirely. `docker stop`, `docker compose
down`, `kubectl delete pod` and any supervisor that sends only a signal all wait
out the grace period and then `SIGKILL`, cutting every in-flight stream. The
drain the control socket exists to provide was reachable only by an operator who
knew to run `just down`.

This process is PID 1 instead. The router still handles no signals, still
contains no `unsafe`, and still shuts down only when its authenticated control
socket says so — it simply now has something to say it on its behalf.

It is the fourth out-of-process component here, and it is the same pattern as
the other three: `hypellm-net::helper` is a client for a TLS terminator,
`verifier/` verifies OIDC signatures the router may not, `agent/` runs the `ssh`
and `docker` the router may not, and this handles the signals the router cannot.

## What it does

```text
hypellm-init --config <path> --secrets <dir> [router arguments...]
```

- Starts `hypellm-router` with every argument passed through verbatim.
- On `SIGTERM` or `SIGINT`, runs
  `hypellm-router --shutdown --config <path> --secrets <dir>`.
- Waits for the router to finish its own drain, up to `HYPELLM_DRAIN_DEADLINE`
  seconds (40 by default), then kills it.
- Exits with the router's status, or `70` if the shutdown was not graceful.

`--config` and `--secrets` are read twice: the router needs them to run, and
this needs them to address the control socket. Missing either is exit `71`,
refused before the router starts — a router running with no usable shutdown path
is the situation this exists to prevent.

**One-shot commands pass straight through.** `--generate-secrets`, `--check`,
`--hash-password`, `--adopt-config`, `--shutdown`, `--ping`, `--backup`,
`--version` and `--help` are `exec`ed directly: there is nothing to supervise
and no drain to arrange. This is not a convenience — `docker run
hypellm-router:local --generate-secrets /etc/hypellm/secrets` is how a fresh
checkout creates its secret bundle, and the image's contract is "append
arguments and they reach the router". Putting an init in front of it must not
change that.

## What it deliberately is not

**Not a supervisor.** One child, one shutdown, one exit status. It does not
restart the router: `compose.yaml` sets `restart: "no"` because a router that
exited cleanly after a drain must not be started again.

**Not a decision maker.** It reads nothing from the network, from a file, or
from the router. Its whole input is its own argv.

**Not silent about failure.** A refused shutdown, an undeliverable one, and a
router that outlives the deadline each print to stderr and exit `70`. A quiet
fallback to `SIGKILL` would be indistinguishable from having no init at all,
which is the state this replaced.

**Not escalating.** A second `SIGTERM` during a drain is logged and otherwise
ignored. Escalating would kill the drain the first signal started.

## Bash, not Python

`agent/` and `verifier/` are Python because they do real work — sockets, JSON,
HMAC, subprocess orchestration. This does not, and `docker/Dockerfile` installs
no packages in either stage: the runtime layer is a bare Debian plus one binary
and the static assets. Adding a Python runtime to the *router's* image to gain a
forty-line init would expand its attack surface for no security return. Bash is
already there.

## Two numbers that have to be ordered

1. The inference listener's `drain_timeout` — 30 s (`ServerConfig::inference`).
2. `HYPELLM_DRAIN_DEADLINE` — 40 s, longer than (1), or this kills the router
   part-way through the drain it just asked for.
3. The supervisor's grace period — `stop_grace_period: 45s` in `compose.yaml`,
   longer than (2), or the supervisor kills *this* part-way through.

Each has to exceed the one before it. Getting the order wrong reintroduces
exactly the dropped streams the whole chain exists to prevent, and it does so
silently.

## Tests

```bash
python3 supervisor/test_hypellm_init.py
```

Eight tests, no container and no real router: the router is replaced by a script
the test controls, connected to its own `--shutdown` invocation through a
sentinel file the way the real one is connected through the control socket. They
cover the signal becoming the right command with the right paths, a second
signal not cutting the drain, a router that ignores the drain being killed *and
reported*, a refused shutdown being reported rather than absorbed, and the exit
status being forwarded. Four of them fail if the signal traps are removed.

Not part of `cargo test --workspace`, because this component is deliberately
outside the Rust workspace.

## Using it outside a container

You probably do not need to. `systemd` has `ExecStop`, and
[deployment.md](../docs/deployment.md#shutdown) gives the unit. This is for
runtimes whose only stop mechanism is a signal.
