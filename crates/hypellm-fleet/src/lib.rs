//! Fleet orchestration: what the fleet must become to satisfy a request.
//!
//! HypeLLM routes a request to a target that is *already running*, chosen from
//! an alias's permitted set. This crate is what makes "already running" a
//! decision rather than an assumption.
//!
//! # What is here and what is not
//!
//! Like `hypellm-core`, this crate performs **no I/O**. It opens no socket,
//! reads no file, holds no secret, and has no clock of its own: callers pass
//! the time in. [`plan::plan`] is a pure function over an immutable
//! [`state::FleetSnapshot`], which is what lets
//! `POST /admin/v1/fleet:simulate` answer "what would you do, and why" without
//! touching the fleet.
//!
//! The socket that carries plans to a fleet agent lives in `hypellm-net`,
//! beside the TLS helper and the identity verifier — the two other places the
//! router delegates something it must not do itself. The router never executes
//! a process: specification 4.1 forbids it and `depscan`'s `forbidden-api`
//! rule fails the build on `process::Command`.
//!
//! # The identifiers that cross the socket
//!
//! Only `deployment-id`, `artifact-id`, `host-id`, `lease-id`, and bounded
//! integers. No image name, no host address, no file path, no container name,
//! no shell fragment, no URL. The agent holds its own allowlist mapping each
//! identifier to a machine and a Compose service, and the router cannot extend
//! it. **A fully compromised router cannot cause arbitrary code to run on a
//! slave**: it can reorder declared deployments; it cannot introduce one.
//!
//! # The invariants
//!
//! | Invariant | Where |
//! |---|---|
//! | A deployment inside its dwell window is never evicted | [`plan`] — `select_eviction_set` |
//! | A pinned or non-evictable deployment never appears in an eviction set | [`plan`] — `select_eviction_set` |
//! | No eviction without the configured hysteresis margin | [`plan`] — `EvictionValueInsufficient` |
//! | An eviction set frees at least the required memory, or the plan is refused | [`plan`] — `HostCapacityInsufficient` |
//! | Equal fleet, demand, and policy snapshots produce equal plans | [`plan`] — `BTreeMap` order, identifier tie-break |
//! | No plan executes on an observation older than its maximum age | [`plan`] — `FleetStateStale` |
//! | The activation budget is a hard ceiling | [`plan`] — `ActivationBudgetExhausted` |
//! | Every lease is released exactly once | [`activation`] — `ActivationLedger` |
//! | No identifier the configuration does not declare is ever adopted | [`state::parse_inventory`] |
//! | Prompts are inert | Nothing here takes a message, a document, or a tool argument |
//!
//! # Belief expires
//!
//! Acting on stale belief is how a scheduler stops a container something else
//! already restarted, or starts one twice. When the newest valid observation is
//! older than the configured maximum, cold orchestrated targets become
//! ineligible and no plan may execute — while warm targets already serving
//! traffic keep serving, because taking a working model out of rotation over a
//! late *observation* would turn an agent hiccup into an outage.

#![forbid(unsafe_code)]
// Specification 18.2 and 6.3, as in `hypellm-core`: this crate computes
// integer fixed-point values that feed eviction decisions, so an unchecked
// conversion or an unintended truncating divide fails the build rather than
// joining a list of warnings. The exemptions are named at their sites.
#![cfg_attr(
    not(test),
    deny(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

pub mod activation;
pub mod demand;
pub mod durable;
pub mod governance;
pub mod model;
pub mod plan;
pub mod protocol;
pub mod state;

pub use activation::{
    ActivationLedger, ActivationOutcome, ActivationRecord, ActivationState, LeaseRelease,
};
pub use demand::{DemandSnapshot, DemandTracker};
pub use durable::{ActivationSummary, FlapRecord};
pub use governance::{ActivationQueue, Budgets, FlapCounter, QueueAdmission};
pub use model::{
    Accelerator, AcceleratorKind, Arch, Artifact, ArtifactKind, Deployment, FleetAgent,
    FleetConfig, FleetPolicy, Host, HostState, Readiness,
};
pub use plan::{Plan, PlanContext, PlanOutcome, PlanStep, PlanTrace, plan, retention_value};
pub use protocol::{AgentReply, AgentRequest, ProtocolError, encode_request, parse_reply};
pub use state::{
    FleetSnapshot, Inventory, InventoryError, Lease, LeaseOperation, ObservedState, Timings,
    parse_inventory,
};
