# HypeLLM Router documentation

HypeLLM Router is a self-hosted policy and routing gateway between coding tools and LLM providers. Start with the [project README](../README.md) for the feature overview and a local quick start.

## Guides

| Document | Audience | Contents |
|---|---|---|
| [Deployment](deployment.md) | Platform engineers | Runtime profiles, TLS boundaries, secrets, state, listeners, configuration, startup, shutdown and system hardening. |
| [Operational runbooks](runbooks.md) | On-call operators | Provider outages, provider credential rotation, compromised client API keys and identity-provider outages. |
| [Threat model](threat-model.md) | Security and design reviewers | Trust boundaries, protected assets, attacker capabilities, controls and abuse cases. |
| [Current limitations](deferred-issues.md) | Evaluators and operators | Capabilities and deployment properties that are not currently provided, with their operational impact. |
| [Specification](../secure_llm_router_specification.md) | Implementers and reviewers | The complete normative design and protocol contract. |

## Recommended reading paths

- **Evaluating the project:** [README](../README.md) → [current limitations](deferred-issues.md) → [threat model](threat-model.md).
- **Deploying a node:** [deployment](deployment.md) → [current limitations](deferred-issues.md) → [runbooks](runbooks.md).
- **Joining on call:** read [runbooks](runbooks.md) and verify that break-glass access, audit export and graceful shutdown have been tested in your environment.
- **Changing security-sensitive code:** read the [specification](../secure_llm_router_specification.md), the relevant crate's `MODULE.md`, and the [threat model](threat-model.md).

## Source-level documentation

Each workspace crate has a `MODULE.md` describing ownership, public API, trust assumptions, resource limits and test obligations. These files are aimed at maintainers; the documents in this directory are the public operator-facing material.

Documentation describes the current implementation. Closed defects and superseded implementation history are intentionally omitted; version control is the record for historical changes.
