//! Idle stop: which resident deployments the router should take down because
//! nothing is using them (specification 26.10).
//!
//! Pure, like the planner: the runtime gathers the inputs, this decides, and
//! the runtime acts. Keeping the predicate here is what lets the property suite
//! check it over thousands of generated fleets without a socket.
//!
//! # What "unused" means
//!
//! Every one of these must hold, and each is a separate reason the router keeps
//! a model up:
//!
//! - **The host's policy asks for it.** `idle_stop_ms` is non-zero.
//! - **It is serving**, observed on belief no older than the agents'
//!   `observation_max_age_ms`. Stopping a model on stale belief costs minutes of
//!   fleet time and can cascade (Appendix B), so stale belief stops nothing.
//! - **The operator has not anchored it.** Not pinned, and evictable.
//! - **The router started it.** A model an operator started by hand is used
//!   and never taken away, unless the host's policy says `adopt_unmanaged`.
//! - **No commitment is in flight.** No lease, and not already being evicted.
//! - **Nothing is using it.** Zero requests dispatched to it right now (the
//!   router's own count), zero the agent reports, and zero queued or parked for
//!   its capability.
//! - **It has been unused long enough.** No request dispatched to it for
//!   `idle_stop_ms`, *and* resident for at least `idle_stop_ms` and its dwell
//!   floor — a model that has just finished loading has served nothing yet, and
//!   that is not idleness.
//!
//! At most one per host per pass, so a host winding down stops its models one
//! drain at a time rather than all at once.

use crate::demand::DemandSnapshot;
use crate::state::FleetSnapshot;
use hypellm_core::ids::{DeploymentId, HostId};
use std::collections::BTreeMap;

/// Why a deployment is not being idle-stopped. For tests and traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleHold {
    /// The deployment is not declared.
    Unknown,
    /// The host's policy has idle stop switched off.
    Disabled,
    /// It is not serving.
    NotServing,
    /// Pinned or not evictable.
    Anchored,
    /// The router did not start it.
    Unmanaged,
    /// A lease or an eviction is in flight for it.
    Committed,
    /// Requests are dispatched to it, reported against it, or waiting for it.
    InUse,
    /// It has not been unused, or resident, for long enough.
    Recent,
}

/// Everything the predicate reads.
#[derive(Debug, Clone, Copy)]
pub struct IdleInputs<'a> {
    /// The newest belief, with commitments applied.
    pub snapshot: &'a FleetSnapshot,
    /// Live demand, including queued and parked requests.
    pub demand: &'a DemandSnapshot,
    /// Requests the router has dispatched to each deployment and not finished.
    pub in_flight: &'a BTreeMap<DeploymentId, u32>,
    /// Oldest belief the agents permit acting on.
    pub max_observation_age_ms: u64,
    /// The router's monotonic clock.
    pub now_ms: u64,
}

/// Whether `deployment` is idle enough to stop, or why not.
pub fn idle_hold(inputs: &IdleInputs<'_>, deployment: &DeploymentId) -> Result<(), IdleHold> {
    let snapshot = inputs.snapshot;
    let config = &snapshot.config;
    let record = config.deployments.get(deployment).ok_or(IdleHold::Unknown)?;
    let host = config
        .accelerator_of(record)
        .map(|a| a.host.clone())
        .ok_or(IdleHold::Unknown)?;
    let policy = config.policy_for(&host);
    if policy.idle_stop_ms == 0 {
        return Err(IdleHold::Disabled);
    }
    if !snapshot.state_of(deployment).is_serving() {
        return Err(IdleHold::NotServing);
    }
    if record.pinned || !record.evictable {
        return Err(IdleHold::Anchored);
    }
    if !snapshot.is_router_owned(deployment) && !policy.adopt_unmanaged {
        return Err(IdleHold::Unmanaged);
    }
    if snapshot.leases.contains_key(deployment) || snapshot.evicting.contains(deployment) {
        return Err(IdleHold::Committed);
    }
    let dispatched = inputs.in_flight.get(deployment).copied().unwrap_or(0);
    let waiting = snapshot
        .deployment_capabilities
        .get(deployment)
        .map_or(0, |capability| inputs.demand.queue_depth(*capability));
    if dispatched > 0 || snapshot.inflight(deployment) > 0 || waiting > 0 {
        return Err(IdleHold::InUse);
    }
    let resident = snapshot.resident_for_ms(deployment, inputs.now_ms);
    if inputs.demand.idle(deployment) < policy.idle_stop_ms
        || resident < policy.idle_stop_ms
        || resident < record.min_resident_ms
    {
        return Err(IdleHold::Recent);
    }
    Ok(())
}

/// The deployments to stop this pass: at most one per host, the longest idle
/// first, identifiers breaking ties so equal inputs give equal answers.
///
/// Empty when belief is stale.
#[must_use]
pub fn idle_stops(inputs: &IdleInputs<'_>) -> Vec<DeploymentId> {
    if !inputs
        .snapshot
        .belief_is_fresh(inputs.now_ms, inputs.max_observation_age_ms)
    {
        return Vec::new();
    }
    let config = &inputs.snapshot.config;
    let mut best: BTreeMap<HostId, (u64, DeploymentId)> = BTreeMap::new();
    for (id, record) in &config.deployments {
        if idle_hold(inputs, id).is_err() {
            continue;
        }
        let Some(host) = config.accelerator_of(record).map(|a| a.host.clone()) else {
            continue;
        };
        let idle = inputs.demand.idle(id);
        let replace = best
            .get(&host)
            .is_none_or(|(held, held_id)| idle > *held || (idle == *held && id < held_id));
        if replace {
            best.insert(host, (idle, id.clone()));
        }
    }
    best.into_values().map(|(_, id)| id).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test fixtures")]
mod tests {
    use super::*;
    use crate::model::{
        Accelerator, AcceleratorKind, Arch, Deployment, FleetConfig, FleetPolicy, Host, HostState,
        Readiness,
    };
    use crate::state::{DeploymentObservation, ObservedState};
    use hypellm_core::ids::{AcceleratorId, AgentId, PoolId, TargetId};
    use std::sync::Arc;

    fn fleet(idle_stop_ms: u64) -> FleetSnapshot {
        let mut config = FleetConfig::empty();
        let host = HostId::new("h1").unwrap();
        config.hosts.insert(
            host.clone(),
            Host {
                id: host.clone(),
                agent: AgentId::new("local").unwrap(),
                arch: Arch::X86_64,
                state: HostState::Enabled,
                reserved_memory_bytes: 0,
                max_concurrent_activations: 1,
            },
        );
        let accelerator = AcceleratorId::new("gpu0").unwrap();
        config.accelerators.insert(
            accelerator.clone(),
            Accelerator {
                id: accelerator.clone(),
                host,
                kind: AcceleratorKind::Cuda,
                memory_bytes: 1 << 34,
                pool: PoolId::new("gpu0").unwrap(),
            },
        );
        config.default_policy = FleetPolicy {
            idle_stop_ms,
            ..FleetPolicy::DEFAULT
        };
        let id = DeploymentId::new("d1").unwrap();
        config.deployments.insert(
            id.clone(),
            Deployment {
                id: id.clone(),
                target: TargetId::new("local:m").unwrap(),
                accelerator,
                artifact: None,
                memory_bytes: 1 << 30,
                start_ms: 1_000,
                stop_ms: 1_000,
                drain_ms: 1_000,
                probe_ms: 1_000,
                readiness: Readiness::HttpOk,
                min_resident_ms: 600_000,
                evictable: true,
                pinned: false,
                autostart: true,
                retention_weight: 0,
                max_drainable_inflight: 0,
                force_stop: false,
            },
        );
        let mut snapshot = FleetSnapshot::empty();
        snapshot.config = Arc::new(config);
        snapshot.observed = true;
        snapshot.observed_at_ms = 10_000_000;
        snapshot.inventory.deployments.insert(
            id.clone(),
            DeploymentObservation {
                deployment: id.clone(),
                state: ObservedState::Ready,
                observed_memory_bytes: 1 << 30,
                state_age_ms: 0,
                inflight: 0,
            },
        );
        snapshot.ready_since_ms.insert(id, 0);
        snapshot
    }

    fn idle_for(ms: u64) -> DemandSnapshot {
        let mut demand = DemandSnapshot::default();
        demand.idle_ms.insert(DeploymentId::new("d1").unwrap(), ms);
        demand
    }

    #[test]
    fn a_model_unused_past_its_window_is_stopped_and_one_used_recently_is_not() {
        let snapshot = fleet(900_000);
        let none = BTreeMap::new();
        let inputs = |demand| IdleInputs {
            snapshot: &snapshot,
            demand,
            in_flight: &none,
            max_observation_age_ms: 30_000,
            now_ms: 10_000_000,
        };
        let stale = idle_for(900_000);
        assert_eq!(idle_stops(&inputs(&stale)), vec![DeploymentId::new("d1").unwrap()]);
        let recent = idle_for(899_999);
        assert!(idle_stops(&inputs(&recent)).is_empty());
    }

    #[test]
    fn a_request_in_flight_keeps_the_model_up_however_long_since_the_last_one_began() {
        let snapshot = fleet(900_000);
        let demand = idle_for(u64::MAX);
        let mut busy = BTreeMap::new();
        busy.insert(DeploymentId::new("d1").unwrap(), 1);
        let inputs = IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &busy,
            max_observation_age_ms: 30_000,
            now_ms: 10_000_000,
        };
        assert_eq!(
            idle_hold(&inputs, &DeploymentId::new("d1").unwrap()),
            Err(IdleHold::InUse)
        );
    }

    #[test]
    fn stale_belief_stops_nothing() {
        let snapshot = fleet(900_000);
        let demand = idle_for(u64::MAX);
        let none = BTreeMap::new();
        let inputs = IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &none,
            max_observation_age_ms: 30_000,
            now_ms: 10_000_000 + 30_001,
        };
        assert!(idle_stops(&inputs).is_empty());
    }

    #[test]
    fn zero_disables_idle_stop() {
        let snapshot = fleet(0);
        let demand = idle_for(u64::MAX);
        let none = BTreeMap::new();
        let inputs = IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &none,
            max_observation_age_ms: 30_000,
            now_ms: 10_000_000,
        };
        assert_eq!(
            idle_hold(&inputs, &DeploymentId::new("d1").unwrap()),
            Err(IdleHold::Disabled)
        );
    }
}
