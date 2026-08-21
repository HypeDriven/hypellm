//! Property tests over the fleet planner and its governance.
//!
//! Specification-extension 16 names ten. Each is an invariant from extension
//! 23, stated as code and run over many generated fleets rather than one
//! arrangement — an example test shows that one fleet behaves, a property test
//! asserts that *no* fleet misbehaves.
//!
//! # Why these are hand-rolled
//!
//! Specification 4 forbids third-party packages, so there is no `proptest`
//! here. What matters from such a library is many inputs, reproducibility, and
//! shrinking. The first two are cheap: [`Rng`] is a seeded xorshift and every
//! case derives from a fixed seed, so a failure reproduces exactly from the
//! number in the message. Shrinking is what is missing, so every generator
//! keeps its fleets *small* — three or four deployments on one pool — and a
//! failing case is already close to minimal.
//!
//! # Making the fixtures adversarial
//!
//! A pin test where the pin is also the cheapest target proves nothing. The
//! generators below deliberately arrange the opposite in each case: the
//! protected deployment is the one the planner most wants to take, the
//! dwell-blocked one is idle and cheap to restore, and the incoming demand is
//! high enough that only the rule under test stands in the way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::decision::ExclusionReason;
use hypellm_core::ids::{AcceleratorId, AgentId, DeploymentId, HostId, PoolId, TargetId};
use hypellm_core::target::Capability;
use hypellm_fleet::demand::DemandSnapshot;
use hypellm_fleet::governance::{ActivationQueue, Budgets, FlapCounter, QueueAdmission};
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, FleetPolicy, Host,
    HostState, Readiness,
};
use hypellm_fleet::plan::{PlanContext, PlanOutcome, plan};
use hypellm_fleet::state::{DeploymentObservation, FleetSnapshot, ObservedState};
use std::sync::Arc;

/// How many cases each property runs.
const CASES: u32 = 400;

const GIB: u64 = 1024 * 1024 * 1024;

/// A seeded xorshift64* generator, as in `hypellm-core/tests/properties.rs`.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.next_u64() % bound }
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

fn did(s: &str) -> DeploymentId {
    DeploymentId::new(s).unwrap()
}
fn tid(s: &str) -> TargetId {
    TargetId::new(s).unwrap()
}

fn deployment(id: &str, memory: u64) -> Deployment {
    Deployment {
        id: did(id),
        target: tid(&format!("spark:{id}")),
        accelerator: AcceleratorId::new("gb10").unwrap(),
        artifact: None,
        memory_bytes: memory,
        start_ms: 180_000,
        stop_ms: 15_000,
        drain_ms: 30_000,
        probe_ms: 10_000,
        readiness: Readiness::HttpOk,
        min_resident_ms: 600_000,
        evictable: true,
        pinned: false,
        autostart: true,
        retention_weight: 0,
        max_drainable_inflight: 0,
        force_stop: false,
    }
}

/// One host, one unified pool, 114 GiB offered after the reservation.
fn fleet() -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = true;
    fleet.agents.insert(
        AgentId::new("local").unwrap(),
        FleetAgent {
            id: AgentId::new("local").unwrap(),
            socket: "/run/hypellm/fleet.sock".to_owned(),
            observation_interval_ms: 5_000,
            observation_max_age_ms: 30_000,
            request_timeout_ms: 5_000,
        },
    );
    fleet.hosts.insert(
        HostId::new("spark").unwrap(),
        Host {
            id: HostId::new("spark").unwrap(),
            agent: AgentId::new("local").unwrap(),
            arch: Arch::Aarch64,
            state: HostState::Enabled,
            reserved_memory_bytes: 16 * GIB,
            max_concurrent_activations: 1,
        },
    );
    fleet.accelerators.insert(
        AcceleratorId::new("gb10").unwrap(),
        Accelerator {
            id: AcceleratorId::new("gb10").unwrap(),
            host: HostId::new("spark").unwrap(),
            kind: AcceleratorKind::Unified,
            memory_bytes: 130 * GIB,
            pool: PoolId::new("spark-unified").unwrap(),
        },
    );
    fleet
}

fn snapshot_of(fleet: FleetConfig, now_ms: u64) -> FleetSnapshot {
    let mut snapshot = FleetSnapshot::empty();
    snapshot.config = Arc::new(fleet);
    snapshot.observed = true;
    snapshot.observed_at_ms = now_ms;
    snapshot
}

fn make_ready(snapshot: &mut FleetSnapshot, id: &str, since_ms: u64, memory: u64) {
    let deployment = did(id);
    snapshot.inventory.deployments.insert(
        deployment.clone(),
        DeploymentObservation {
            deployment: deployment.clone(),
            state: ObservedState::Ready,
            observed_memory_bytes: memory,
            state_age_ms: 0,
            inflight: 0,
        },
    );
    snapshot.ready_since_ms.insert(deployment, since_ms);
}

fn context(now_ms: u64) -> PlanContext {
    PlanContext {
        now_ms,
        deadline_remaining_ms: 3_600_000,
        effort_multiplier: 1,
        effort_headroom_ms: 5_000,
        may_activate: true,
        may_fetch: false,
        capability: Some(Capability::TextToMusic),
        priority_bonus: 0,
    }
}

/// Demand high enough that only the rule under test can refuse.
fn overwhelming_demand(idle: &[&str]) -> DemandSnapshot {
    let mut demand = DemandSnapshot::default();
    demand.rate_per_minute.insert(Capability::TextToMusic, 5_000);
    demand.queued.insert(Capability::TextToMusic, 64);
    for id in idle {
        demand.idle_ms.insert(did(id), u64::MAX);
    }
    demand
}

// -- The ten properties ------------------------------------------------------

#[test]
fn an_activation_never_evicts_a_deployment_inside_its_dwell_window() {
    let mut rng = Rng::new(0xF1EE_0001);
    for case in 0..CASES {
        let dwell = 60_000 + rng.below(600_000);
        let resident_for = rng.below(dwell);
        let now = 10_000_000;

        let mut fleet = fleet();
        let incoming = deployment("music3", 80 * GIB);
        let mut victim = deployment("h3", 80 * GIB);
        victim.min_resident_ms = dwell;
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());
        fleet.deployments.insert(victim.id.clone(), victim.clone());

        let mut snapshot = snapshot_of(fleet, now);
        make_ready(&mut snapshot, "h3", now - resident_for, 80 * GIB);

        let outcome = plan(
            &snapshot,
            &overwhelming_demand(&["h3"]),
            &incoming.target,
            &context(now),
        );
        if let PlanOutcome::Plan(plan) = &outcome {
            assert!(
                !plan.eviction_set().contains(&&victim.id),
                "case {case}: evicted a deployment {resident_for} ms into a {dwell} ms dwell \
                 floor"
            );
        }
    }
}

#[test]
fn a_pinned_or_unevictable_deployment_never_appears_in_an_eviction_set() {
    let mut rng = Rng::new(0xF1EE_0002);
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        let incoming = deployment("music3", 100 * GIB);
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());

        // Several residents; some protected, some not. The protected ones are
        // deliberately the *cheapest* to take: idle, small, and long resident.
        let mut protected = Vec::new();
        for n in 0..3u64 {
            let id = format!("resident{n}");
            let mut resident = deployment(&id, 20 * GIB);
            resident.min_resident_ms = 0;
            if rng.bool() {
                if rng.bool() {
                    resident.pinned = true;
                } else {
                    resident.evictable = false;
                }
                protected.push(did(&id));
            }
            fleet.deployments.insert(resident.id.clone(), resident);
        }

        let ids: Vec<String> = (0..3).map(|n| format!("resident{n}")).collect();
        let mut snapshot = snapshot_of(fleet, now);
        for id in &ids {
            make_ready(&mut snapshot, id, 0, 20 * GIB);
        }

        let idle: Vec<&str> = ids.iter().map(String::as_str).collect();
        let outcome = plan(
            &snapshot,
            &overwhelming_demand(&idle),
            &incoming.target,
            &context(now),
        );
        if let PlanOutcome::Plan(plan) = &outcome {
            for anchor in &protected {
                assert!(
                    !plan.eviction_set().contains(&anchor),
                    "case {case}: an operator anchor entered the eviction set"
                );
            }
        }
    }
}

#[test]
fn a_plan_that_evicts_frees_at_least_the_required_memory() {
    let mut rng = Rng::new(0xF1EE_0003);
    for case in 0..CASES {
        let now = 10_000_000;
        let want = 40 * GIB + rng.below(60) * GIB;
        let mut fleet = fleet();
        let incoming = deployment("music3", want);
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());

        let mut ids = Vec::new();
        for n in 0..3u64 {
            let id = format!("resident{n}");
            let mut resident = deployment(&id, 10 * GIB + rng.below(40) * GIB);
            resident.min_resident_ms = 0;
            fleet.deployments.insert(resident.id.clone(), resident);
            ids.push(id);
        }

        let pool = PoolId::new("spark-unified").unwrap();
        let mut snapshot = snapshot_of(fleet, now);
        for id in &ids {
            let memory = snapshot.config.deployments[&did(id)].memory_bytes;
            make_ready(&mut snapshot, id, 0, memory);
        }

        let free_before = snapshot.pool_free_bytes(&pool);
        let idle: Vec<&str> = ids.iter().map(String::as_str).collect();
        let outcome = plan(
            &snapshot,
            &overwhelming_demand(&idle),
            &incoming.target,
            &context(now),
        );
        if let PlanOutcome::Plan(plan) = &outcome {
            assert!(
                plan.trace.freed_bytes.saturating_add(free_before) >= want,
                "case {case}: a plan promised {want} bytes and freed {} on top of {free_before}",
                plan.trace.freed_bytes
            );
        }
    }
}

#[test]
fn equal_fleet_and_demand_snapshots_produce_equal_plans() {
    let mut rng = Rng::new(0xF1EE_0004);
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        let incoming = deployment("music3", 60 * GIB + rng.below(40) * GIB);
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());

        let mut ids = Vec::new();
        for n in 0..4u64 {
            let id = format!("resident{n}");
            let mut resident = deployment(&id, 10 * GIB + rng.below(30) * GIB);
            resident.min_resident_ms = 0;
            // Equal retention weights on purpose: the tie-break has to be the
            // identifier, not map iteration order.
            resident.retention_weight = 0;
            fleet.deployments.insert(resident.id.clone(), resident);
            ids.push(id);
        }

        let mut snapshot = snapshot_of(fleet, now);
        for id in &ids {
            let memory = snapshot.config.deployments[&did(id)].memory_bytes;
            make_ready(&mut snapshot, id, 0, memory);
        }

        let idle: Vec<&str> = ids.iter().map(String::as_str).collect();
        let demand = overwhelming_demand(&idle);
        let first = plan(&snapshot, &demand, &incoming.target, &context(now));
        for _ in 0..4 {
            assert_eq!(
                plan(&snapshot, &demand, &incoming.target, &context(now)),
                first,
                "case {case}: identical snapshots produced different plans"
            );
        }
    }
}

#[test]
fn no_eviction_occurs_without_the_configured_hysteresis_margin() {
    let mut rng = Rng::new(0xF1EE_0005);
    for case in 0..CASES {
        let now = 10_000_000;
        let margin = rng.below(900);
        let mut fleet = fleet();
        fleet.default_policy.eviction_margin_permille =
            u32::try_from(margin).unwrap_or(250);

        let incoming = deployment("music3", 80 * GIB);
        let mut victim = deployment("h3", 80 * GIB);
        victim.min_resident_ms = 0;
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());
        fleet.deployments.insert(victim.id.clone(), victim.clone());

        let mut snapshot = snapshot_of(fleet, now);
        snapshot
            .deployment_capabilities
            .insert(victim.id.clone(), Capability::AudioToVideo);
        make_ready(&mut snapshot, "h3", 0, 80 * GIB);

        let mut demand = DemandSnapshot::default();
        let incumbent = rng.below(500);
        let challenger = rng.below(500);
        demand
            .rate_per_minute
            .insert(Capability::AudioToVideo, incumbent);
        demand
            .rate_per_minute
            .insert(Capability::TextToMusic, challenger);
        demand.idle_ms.insert(victim.id.clone(), rng.below(600_000));

        let outcome = plan(&snapshot, &demand, &incoming.target, &context(now));
        if let PlanOutcome::Plan(plan) = &outcome {
            if plan.evicts() {
                assert!(
                    plan.trace.incoming_value > plan.trace.required_value,
                    "case {case}: evicted with incoming {} against a required {}",
                    plan.trace.incoming_value,
                    plan.trace.required_value
                );
            }
        }
    }
}

#[test]
fn the_planner_prefers_a_free_memory_host_over_an_eviction_host() {
    // Two accelerators in two pools: one with room, one that would need an
    // eviction. The cheapest swap is the one that does not happen.
    let mut rng = Rng::new(0xF1EE_0006);
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        fleet.hosts.insert(
            HostId::new("rtx5090").unwrap(),
            Host {
                id: HostId::new("rtx5090").unwrap(),
                agent: AgentId::new("local").unwrap(),
                arch: Arch::X86_64,
                state: HostState::Enabled,
                reserved_memory_bytes: 0,
                max_concurrent_activations: 1,
            },
        );
        fleet.accelerators.insert(
            AcceleratorId::new("rtx5090-0").unwrap(),
            Accelerator {
                id: AcceleratorId::new("rtx5090-0").unwrap(),
                host: HostId::new("rtx5090").unwrap(),
                kind: AcceleratorKind::Cuda,
                memory_bytes: 32 * GIB,
                pool: PoolId::new("rtx5090-pool").unwrap(),
            },
        );

        // The same model, two targets: one on the busy Spark, one on the free
        // RTX. Only the second fits without displacing anything.
        let mut spark_side = deployment("music3-spark", 80 * GIB);
        spark_side.target = tid("spark:music3");
        let mut rtx_side = deployment("music3-rtx", 16 * GIB);
        rtx_side.target = tid("rtx5090:music3");
        rtx_side.accelerator = AcceleratorId::new("rtx5090-0").unwrap();
        let mut resident = deployment("h3", 80 * GIB);
        resident.min_resident_ms = 0;

        fleet.deployments.insert(spark_side.id.clone(), spark_side.clone());
        fleet.deployments.insert(rtx_side.id.clone(), rtx_side.clone());
        fleet.deployments.insert(resident.id.clone(), resident.clone());

        let mut snapshot = snapshot_of(fleet, now);
        make_ready(&mut snapshot, "h3", 0, 80 * GIB);

        let demand = overwhelming_demand(&["h3"]);
        let on_spark = plan(&snapshot, &demand, &spark_side.target, &context(now));
        let on_rtx = plan(&snapshot, &demand, &rtx_side.target, &context(now));

        // Both must be *candidates*: a comparison between a candidate and an
        // exclusion would hold trivially and say nothing about preference.
        assert_eq!(
            on_rtx.residency_class(),
            hypellm_core::decision::ResidencyClass::ColdFits,
            "case {case}: the host with room must classify as fitting: {on_rtx:?}"
        );
        assert_eq!(
            on_spark.residency_class(),
            hypellm_core::decision::ResidencyClass::ColdRequiresEviction,
            "case {case}: the busy host must classify as needing an eviction: {on_spark:?}"
        );
        // Warmth is what expresses the preference to routing, and the ladder is
        // what routing ranks by.
        let free_rung = on_rtx.residency_class().warmth_bonus();
        let evict_rung = on_spark.residency_class().warmth_bonus();
        assert!(
            free_rung > evict_rung,
            "case {case}: a host with room did not outrank one needing an eviction \
             ({free_rung} against {evict_rung})"
        );
        let _ = rng.bool();
    }
}

#[test]
fn oscillating_demand_converges_below_the_activation_budget() {
    // The anti-thrash property, over adversarial alternating demand: a
    // low-privilege caller alternating two capabilities that cannot coexist.
    // Whatever they do, the trailing-hour count cannot exceed the ceiling.
    let mut rng = Rng::new(0xF1EE_0007);
    let policy = FleetPolicy::DEFAULT;
    for case in 0..16 {
        let budgets = Budgets::new();
        let flap = FlapCounter::new();
        let host = HostId::new("spark").unwrap();
        let mut spent: Vec<u64> = Vec::new();

        // Six hours of alternating demand, once a second.
        for second in 0..(6 * 3_600u64) {
            let now = second * 1_000;
            let which = if rng.bool() { "music3" } else { "h3" };
            let deployment = did(which);
            if flap.cooldown_until_ms(&deployment) > now {
                continue;
            }
            if budgets.try_spend(&host, &policy, now) {
                spent.push(now);
                flap.record_eviction(&deployment, &policy, now);
            }
        }

        for window_end in (0..(6 * 3_600_000u64)).step_by(300_000) {
            let count = spent
                .iter()
                .filter(|t| {
                    **t <= window_end
                        && t.saturating_add(hypellm_fleet::governance::BUDGET_PERIOD_MS)
                            > window_end
                })
                .count();
            assert!(
                u32::try_from(count).unwrap_or(u32::MAX) <= policy.max_activations_per_hour,
                "case {case}: {count} activations in the hour ending at {window_end}"
            );
        }
    }
}

#[test]
fn every_activation_lease_is_released_exactly_once() {
    use hypellm_fleet::activation::{
        ActivationLedger, ActivationOutcome, ActivationRecord, LeaseRelease,
    };
    use hypellm_fleet::plan::{Plan, PlanStep, PlanTrace};
    use hypellm_fleet::state::{Lease, LeaseOperation};
    use hypellm_core::ids::LeaseId;

    let mut rng = Rng::new(0xF1EE_0008);
    for case in 0..CASES {
        let ledger = ActivationLedger::new();
        let host = HostId::new("spark").unwrap();
        let mut live: Vec<LeaseId> = Vec::new();
        let mut double_releases = 0u32;

        for step in 0..32u64 {
            match rng.below(3) {
                0 => {
                    let id = LeaseId::new(format!("l-{case}-{step}")).unwrap();
                    let lease = Lease {
                        id: id.clone(),
                        deployment: did("music3"),
                        operation: LeaseOperation::Activate,
                        issued_ms: step,
                        expires_ms: step + 100_000,
                        decision_id: String::new(),
                    };
                    let plan = Plan {
                        deployment: did("music3"),
                        host: host.clone(),
                        steps: vec![PlanStep::Activate(did("music3"))],
                        eta_ms: 1_000,
                        trace: PlanTrace::default(),
                    };
                    if ledger.acquire(ActivationRecord::from_plan(&plan, lease, step), 4) {
                        live.push(id);
                    }
                }
                1 => {
                    if let Some(id) = live.pop() {
                        assert_eq!(
                            ledger.release(&id, ActivationOutcome::Succeeded, "ready", step),
                            LeaseRelease::Released
                        );
                    }
                }
                _ => {
                    // A double release, which must be refused rather than
                    // performed: it would return a slot a different activation
                    // now holds.
                    if let Some(id) = live.first() {
                        if rng.bool() {
                            continue;
                        }
                        let outcome =
                            ledger.release(id, ActivationOutcome::Failed, "failed", step);
                        if outcome == LeaseRelease::Released {
                            let repeat =
                                ledger.release(id, ActivationOutcome::Failed, "failed", step);
                            assert_eq!(repeat, LeaseRelease::AlreadyReleased);
                            double_releases += 1;
                            live.remove(0);
                        }
                    }
                }
            }
        }

        let (acquired, released) = ledger.accounting();
        assert_eq!(
            acquired,
            released.saturating_add(u64::try_from(live.len()).unwrap_or(0)),
            "case {case}: {acquired} acquired, {released} released, {} still live \
             ({double_releases} double releases refused)",
            live.len()
        );
        assert_eq!(
            ledger.slots_held(&host),
            u32::try_from(live.len()).unwrap_or(u32::MAX),
            "case {case}: slots held must equal live leases"
        );
    }
}

#[test]
fn a_cold_target_beyond_the_effort_adjusted_deadline_is_excluded_not_activated() {
    let mut rng = Rng::new(0xF1EE_0009);
    for case in 0..CASES {
        let now = 10_000_000;
        let start = 10_000 + rng.below(600_000);
        let multiplier = 1 + u32::try_from(rng.below(8)).unwrap_or(0);
        let headroom = rng.below(20_000);
        let deadline = rng.below(900_000);

        let mut fleet = fleet();
        let mut incoming = deployment("music3", 8 * GIB);
        incoming.start_ms = start;
        incoming.probe_ms = 0;
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());

        let snapshot = snapshot_of(fleet, now);
        let mut ctx = context(now);
        ctx.deadline_remaining_ms = deadline;
        ctx.effort_multiplier = multiplier;
        ctx.effort_headroom_ms = headroom;

        let required = start.saturating_add(headroom.saturating_mul(u64::from(multiplier)));
        let outcome = plan(&snapshot, &DemandSnapshot::default(), &incoming.target, &ctx);
        if required > deadline {
            assert_eq!(
                outcome,
                PlanOutcome::Infeasible(ExclusionReason::ActivationExceedsDeadline),
                "case {case}: {required} ms of work offered against a {deadline} ms deadline"
            );
        } else {
            assert!(
                matches!(outcome, PlanOutcome::Plan(_)),
                "case {case}: a feasible activation was refused: {outcome:?}"
            );
        }
    }
}

#[test]
fn an_unfetchable_artifact_never_produces_a_plan_that_evicts() {
    use hypellm_core::ids::ArtifactId;
    use hypellm_fleet::model::{Artifact, ArtifactKind};

    let mut rng = Rng::new(0xF1EE_000A);
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        // Half the cases put the artifact on the wrong architecture, half
        // simply forbid fetching. Neither may cost a running model.
        let arch = if rng.bool() { Arch::X86_64 } else { Arch::Aarch64 };
        fleet.default_policy.allow_fetch = rng.bool();
        fleet.artifacts.insert(
            ArtifactId::new("music3").unwrap(),
            Artifact {
                id: ArtifactId::new("music3").unwrap(),
                kind: ArtifactKind::Image,
                arch,
                size_bytes: 20 * GIB,
                digest: format!("sha256:{}", "0".repeat(64)),
                source: "mirror".to_owned(),
            },
        );

        let mut incoming = deployment("music3", 80 * GIB);
        incoming.artifact = Some(ArtifactId::new("music3").unwrap());
        let mut victim = deployment("h3", 80 * GIB);
        victim.min_resident_ms = 0;
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());
        fleet.deployments.insert(victim.id.clone(), victim.clone());

        let mut snapshot = snapshot_of(fleet, now);
        make_ready(&mut snapshot, "h3", 0, 80 * GIB);
        let mut ctx = context(now);
        ctx.may_fetch = true;

        // Nothing reports the artifact present anywhere.
        let outcome = plan(&snapshot, &overwhelming_demand(&["h3"]), &incoming.target, &ctx);
        assert_eq!(
            outcome,
            PlanOutcome::Infeasible(ExclusionReason::ArtifactUnavailable),
            "case {case}: an absent artifact must refuse before anything is stopped"
        );
        if let PlanOutcome::Plan(plan) = &outcome {
            assert!(
                !plan.evicts(),
                "case {case}: stopped a running model to make room for something that is \
                 not on the machine"
            );
        }

        // The same fleet with the artifact present and verified *does* reach
        // the eviction path — without which the assertion above would hold
        // for a fixture that could never have produced a plan at all.
        snapshot.inventory.artifacts.insert(
            (
                ArtifactId::new("music3").unwrap(),
                HostId::new("spark").unwrap(),
            ),
            hypellm_fleet::state::ArtifactPlacement {
                artifact: ArtifactId::new("music3").unwrap(),
                host: HostId::new("spark").unwrap(),
                present: true,
                verified: true,
                bytes_present: 20 * GIB,
            },
        );
        let with_artifact =
            plan(&snapshot, &overwhelming_demand(&["h3"]), &incoming.target, &ctx);
        assert!(
            matches!(&with_artifact, PlanOutcome::Plan(plan) if plan.evicts()),
            "case {case}: the fixture cannot reach the eviction path, so the assertion \
             above proves nothing: {with_artifact:?}"
        );
    }
}

// -- Supporting properties ---------------------------------------------------

#[test]
fn batching_never_lets_one_burst_pay_for_more_than_one_activation() {
    let mut rng = Rng::new(0xF1EE_000B);
    let policy = FleetPolicy::DEFAULT;
    for case in 0..CASES {
        let queue = ActivationQueue::new();
        let burst = 1 + rng.below(64);
        let mut activations = 0u32;
        for _ in 0..burst {
            if queue.admit(Capability::TextToMusic, &policy, 1_000) == QueueAdmission::Activate {
                activations += 1;
            }
        }
        assert!(
            activations <= 1,
            "case {case}: a burst of {burst} paid for {activations} activations"
        );
    }
}

#[test]
fn a_deployment_that_may_not_autostart_is_never_started_by_demand() {
    let mut rng = Rng::new(0xF1EE_000C);
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        let mut incoming = deployment("music3", 8 * GIB);
        incoming.autostart = false;
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());
        let snapshot = snapshot_of(fleet, now);

        let mut ctx = context(now);
        ctx.may_activate = rng.bool();
        assert_eq!(
            plan(&snapshot, &overwhelming_demand(&[]), &incoming.target, &ctx),
            PlanOutcome::Infeasible(ExclusionReason::ActivationNotPermitted),
            "case {case}: routing demand started an operator-only deployment"
        );
    }
}
