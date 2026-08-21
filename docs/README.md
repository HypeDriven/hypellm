# HypeLLM Router documentation

HypeLLM Router is a self-hosted policy and routing gateway between coding tools and LLM providers. Start with the [project README](../README.md) for the feature overview and a local quick start.

## Guides

| Document | Audience | Contents |
|---|---|---|
| [Deployment](deployment.md) | Platform engineers | Runtime profiles, TLS boundaries, secrets, state, listeners, configuration, startup, shutdown and system hardening. |
| [Operational runbooks](runbooks.md) | On-call operators | Provider outages, provider credential rotation, compromised client API keys, identity-provider outages and fleet incidents. |
| [Fleet orchestration](orchestration.md) | Platform engineers, reviewers | How the router decides what a fleet of accelerator hosts must become to serve a request, and starts and stops containers to get there. The reasoning behind specification §26. |
| [Fleet agent](../agent/README.md) | Platform engineers | The out-of-process component that reaches the slaves: its obligations, its allowlist, and what it deliberately does not do. |
| [Example fleet configuration](examples/fleet.conf) | Platform engineers | A working five-host declaration, annotated. |
| [Threat model](threat-model.md) | Security and design reviewers | Trust boundaries, protected assets, attacker capabilities, controls and abuse cases. |
| [Current limitations](deferred-issues.md) | Evaluators and operators | Capabilities and deployment properties that are not currently provided, with their operational impact. |
| [Specification](../secure_llm_router_specification.md) | Implementers and reviewers | The complete normative design and protocol contract. |

## Recommended reading paths

- **Evaluating the project:** [README](../README.md) → [current limitations](deferred-issues.md) → [threat model](threat-model.md).
- **Deploying a node:** [deployment](deployment.md) → [current limitations](deferred-issues.md) → [runbooks](runbooks.md).
- **Deploying a fleet:** [fleet orchestration](orchestration.md) → [fleet agent](../agent/README.md) → [example configuration](examples/fleet.conf) → the fleet section of [current limitations](deferred-issues.md).
- **Joining on call:** read [runbooks](runbooks.md) and verify that break-glass access, audit export and graceful shutdown have been tested in your environment.
- **Changing security-sensitive code:** read the [specification](../secure_llm_router_specification.md), the relevant crate's `MODULE.md`, and the [threat model](threat-model.md).

## Source-level documentation

Each workspace crate has a `MODULE.md` describing ownership, public API, trust assumptions, resource limits and test obligations. These files are aimed at maintainers; the documents in this directory are the public operator-facing material.

Every document under **Guides** describes the current implementation. Where a described capability is partly built — fleet orchestration has four named exceptions — the document says so on its first page and [current limitations](deferred-issues.md) carries the detail. Closed defects and superseded implementation history are intentionally omitted; version control is the record for historical changes.
