# HypeLLM Router

HypeLLM Router is a self-hosted gateway for routing LLM requests across local and hosted providers. It presents OpenAI- and Anthropic-compatible APIs to coding tools, applies tenant policy and capacity controls, selects an eligible target, and streams the provider response back to the client.

The project is a Rust workspace with a dependency-free static administration UI. It is designed for operators who need one controlled entry point for several model providers without allowing request content to choose destinations or credentials.

## What it provides

- **Compatible inference APIs** for OpenAI chat, responses, embeddings and Anthropic messages workflows.
- **Policy-based routing** through client-facing model aliases, grants, denies, preferences, hard pins, residency requirements and capability filters.
- **Capability-contract requests**: a caller states a verb, the modalities they are sending (including opaque documents), a reasoning tier and a quality floor, and each is an eligibility filter rather than a hint.
- **Fleet orchestration.** The router models the accelerator hosts behind its targets and starts and stops declared containers to serve demand — under dwell floors, hysteresis margins, per-host activation budgets and durable leases, through a separate out-of-process agent. It never executes a process itself.
- **Provider support** for llama.cpp, OpenAI, Anthropic, DeepSeek and Moonshot/Kimi, plus an explicitly enabled generic OpenAI-compatible adapter.
- **Bounded admission** with concurrency, queue, request-rate, token-rate, byte-rate and spend controls.
- **Streaming and failover** with backpressure, deadlines, circuit breakers and deterministic candidate ordering.
- **Separate management plane** with Google OIDC, RBAC, CSRF protection, policy drafts, two-person publication, audit export, usage views and emergency break-glass access.
- **Security-focused operation** including strict parsers, destination pinning, credential isolation, durable policy activation and an authenticated audit chain.
- **No third-party runtime or web dependencies.** The workspace builds offline and the admin UI uses first-party static assets only.

## Architecture at a glance

```text
Coding tools ──OpenAI/Anthropic API──▶ inference listener
                                           │
                                  authenticate and admit
                                           │
                                  policy and target ranking
                                           │
                         llama.cpp / OpenAI / Anthropic /
                           DeepSeek / Moonshot providers

Operators ─────────HTTPS edge────────▶ management listener
                                           │
                              admin API and static web UI

                     ┌──── owner-only Unix socket, identifiers only
                     ▼
              fleet agent ──ssh──▶ accelerator hosts
```

Inference and management use separate listeners, handlers, authentication methods and resource limits. Starting and stopping containers happens in a separate agent process, because the router must not execute a subprocess: the socket between them carries opaque identifiers and bounded integers, and the agent resolves each against its own allowlist. The router speaks HTTP/1.1 internally. Production deployments place a platform TLS edge in front of inbound listeners and use local platform helpers for outbound TLS and OIDC token verification; the router does not implement TLS or asymmetric signature verification itself. A reference identity verifier ships in `verifier/`, out of the workspace like the agent, and performs no cryptography of its own.

## Build and verify

Requirements: Rust 1.85 or newer on Linux. All commands run offline.

```bash
cargo build --workspace --offline
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline
cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .
```

`depscan` enforces the repository's supply-chain policy: no registry dependencies, build scripts, procedural macros, dynamic loading, unsafe Rust, remote web assets or vendored browser code.

## Quick start with llama.cpp

Create `hypellm.conf`:

```text
settings state_dir=./state inference_listen=127.0.0.1:8000 \
         admin_listen=127.0.0.1:8001 control_socket=./run/control.sock
tenant id=local
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:model provider=local model=model local=true operations=chat,embeddings \
       streaming=true context=32768 max_output=4096 concurrency=4
alias id=default targets=local:model
grant scope=tenant:local model=* allow=true
binding id=prefer-local scope=tenant:local model=* prefer=local:model
```

Then generate the secret bundle, validate the configuration and start the router:

```bash
mkdir -p ./run ./state
cargo run -p hypellm-router -- --generate-secrets ./secrets
cargo run -p hypellm-router -- --check --config ./hypellm.conf
cargo run -p hypellm-router -- \
  --config ./hypellm.conf --secrets ./secrets --static ./web
```

`--generate-secrets` prints the break-glass token once and stores only its verifier. Save it offline: it cannot be recovered, and with no OIDC configured it is the only way into the management plane — and therefore the only way to mint the API key inference requires.

Inference requests require a router API key created through the management API. [Using the router](docs/using-the-router.md) is the client-side guide — how to mint that key and point a project at the endpoint. See the [deployment guide](docs/deployment.md) for HTTPS/OIDC setup, credentials, configuration and service hardening.

## Run it in a container

A [`justfile`](justfile) and [`compose.yaml`](compose.yaml) build the router and start it locally. Requirements: Docker and [`just`](https://github.com/casey/just).

```bash
just bootstrap  # first run: secrets, router, and a key to call it with
just status     # is it running, and does it answer
just logs       # follow the structured log
just key        # mint another API key
just down       # drain over the control socket, then remove the container
```

`just bootstrap` is `just up` plus the two steps that otherwise happen by hand. It captures the break-glass token from `--generate-secrets` — printed once, stored nowhere — spends it minting the first API key, and prints the token at the end to be stored offline. Without a key the router answers `/health` and refuses everything else, and with no OIDC provider configured break-glass is the only credential the management plane accepts.

`just up` prints the inference, management and metrics endpoints when the router answers `/health/live`. The image build runs `depscan` and the release build offline; the router container gets no capabilities, a read-only root filesystem, and the invoking user's uid. Configuration is [`docker/hypellm.conf`](docker/hypellm.conf); state and secrets are bind-mounted under `run/`.

### Reaching it over Tailscale

The stack is two containers: a `tailscale/tailscale` node and the router running inside its network namespace. The router therefore *is* a tailnet node — `hypellm-router.<tailnet>.ts.net` — rather than a port published on the host, which also avoids Docker Desktop's inability to bind a host's Tailscale address.

Which planes the tailnet can reach is decided by bind address, in `docker/hypellm.conf`:

| Listener | Bound to | Tailnet | This host |
|---|---|---|---|
| Inference | `0.0.0.0:18000` | yes | yes |
| Management + SPA | `10.89.7.2:18001` | no | yes |
| Metrics | `10.89.7.2:18002` | no | yes |

`10.89.7.2` is the compose bridge address, pinned in `compose.yaml`. A listener bound to it is reachable through the published loopback ports and is not bound on `tailscale0`, so a tailnet peer finds nothing listening. This fails closed and does not depend on a Tailscale ACL or a firewall rule elsewhere. Tailnet reachability is not authentication — inference still requires a router API key.

First run needs the node authenticated: put a key in `run/secrets/tailscale.authkey`, or let `just up` print the login URL. `just tailnet` shows the node's address and its learned routes.

Slaves are reached by their **LAN address**, over a Tailscale subnet route advertised from their network — `--accept-routes` installs it and the RFC 1918 destination is preserved, so `egress=private_network` still describes the connection. Do not point a provider at a slave's `100.64.0.0/10` address: that classifies as `shared_address_space`, which `EgressProfile::permits` refuses under every profile, because carrier-grade NAT space is a well-known SSRF pivot.

## Documentation

- [Documentation index](docs/README.md)
- [Using the router](docs/using-the-router.md) — pointing a project at a running instance
- [Deployment and configuration](docs/deployment.md)
- [Operational runbooks](docs/runbooks.md)
- [Fleet orchestration](docs/orchestration.md) and the [fleet agent](agent/README.md)
- [The identity verifier](verifier/README.md) — Google sign-in, and enrolling the first administrator
- [Threat model](docs/threat-model.md)
- [Current limitations](docs/deferred-issues.md)
- [Detailed specification](secure_llm_router_specification.md)

The specification defines the intended security and protocol contract. The operator documentation describes the current implementation. Current limitations are kept separately and do not retain closed issue history.

## Current deployment scope

The supported production shape is a hardened single node, or several independent nodes with conservative quota partitioning and separate state directories. HypeLLM Router does not currently provide state replication, leader election or a distributed configuration service.

Fleet orchestration is single-router by design: one router manages a host, enforced agent-side. Four parts of the orchestration design are deliberately not built — a jobs API for long generations, predictive pre-warm, resumable artifact fetches and Windows-host actuation — and are listed rather than approximated.

Review [current limitations](docs/deferred-issues.md) before deployment.

## License

[MIT](LICENSE)
