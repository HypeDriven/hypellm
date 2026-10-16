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
            ssh_public_key: None,
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
                image_id: None,
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
                image_id: None,
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

// -- Idle stop (specification 26.10) ------------------------------------------

/// A random one-host fleet of up to four ready deployments, each with a random
/// anchor, ownership, in-flight count, idle time and residency, under a random
/// idle window.
fn idle_case(rng: &mut Rng) -> (
    FleetSnapshot,
    DemandSnapshot,
    std::collections::BTreeMap<DeploymentId, u32>,
    u64,
) {
    let now = 50_000_000;
    let window = [0, 60_000, 900_000, 3_600_000][usize::try_from(rng.below(4)).unwrap()];
    let mut fleet = fleet();
    fleet.default_policy = FleetPolicy {
        idle_stop_ms: window,
        adopt_unmanaged: rng.bool(),
        ..FleetPolicy::DEFAULT
    };
    let count = 1 + rng.below(4);
    let mut ids = Vec::new();
    for i in 0..count {
        let id = format!("d{i}");
        let mut d = deployment(&id, 8 * GIB);
        d.pinned = rng.below(4) == 0;
        d.evictable = rng.below(4) != 0;
        d.min_resident_ms = rng.below(2_000_000);
        fleet.deployments.insert(d.id.clone(), d);
        ids.push(id);
    }
    let observed_at = now - rng.below(60_000);
    let mut snapshot = snapshot_of(fleet, observed_at);
    let mut demand = DemandSnapshot::default();
    let mut in_flight = std::collections::BTreeMap::new();
    for id in &ids {
        if rng.below(5) != 0 {
            make_ready(&mut snapshot, id, now - rng.below(5_000_000), 8 * GIB);
        }
        if rng.below(4) == 0 {
            snapshot.unmanaged.insert(did(id));
        }
        if rng.below(4) == 0 {
            in_flight.insert(did(id), 1 + u32::try_from(rng.below(3)).unwrap());
        }
        demand.idle_ms.insert(did(id), rng.below(5_000_000));
        if rng.bool() {
            snapshot
                .deployment_capabilities
                .insert(did(id), Capability::TextToMusic);
        }
    }
    if rng.below(4) == 0 {
        demand.queued.insert(Capability::TextToMusic, 1);
    }
    (snapshot, demand, in_flight, now)
}

#[test]
fn an_idle_stop_never_takes_a_model_that_is_in_use_anchored_recent_or_not_ours() {
    use hypellm_fleet::idle::{IdleInputs, idle_stops};
    let mut rng = Rng::new(0x1D1E_0001);
    let mut stopped_some = 0;
    for case in 0..CASES {
        let (snapshot, demand, in_flight, now) = idle_case(&mut rng);
        let inputs = IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &in_flight,
            max_observation_age_ms: 30_000,
            now_ms: now,
        };
        let stops = idle_stops(&inputs);
        assert!(stops.len() <= 1, "case {case}: more than one stop on one host");
        let policy = snapshot.config.default_policy;
        for id in &stops {
            let d = &snapshot.config.deployments[id];
            assert_ne!(policy.idle_stop_ms, 0, "case {case}: idle stop is switched off");
            assert!(!d.pinned && d.evictable, "case {case}: {id} is anchored");
            assert!(
                snapshot.is_router_owned(id) || policy.adopt_unmanaged,
                "case {case}: {id} is not the router's"
            );
            assert!(snapshot.state_of(id).is_serving(), "case {case}: {id} is not serving");
            assert_eq!(in_flight.get(id).copied().unwrap_or(0), 0, "case {case}: {id} in flight");
            let waiting = snapshot
                .deployment_capabilities
                .get(id)
                .map_or(0, |c| demand.queue_depth(*c));
            assert_eq!(waiting, 0, "case {case}: {id} has requests waiting");
            assert!(demand.idle(id) >= policy.idle_stop_ms, "case {case}: {id} used recently");
            let resident = snapshot.resident_for_ms(id, now);
            assert!(
                resident >= policy.idle_stop_ms && resident >= d.min_resident_ms,
                "case {case}: {id} not resident long enough"
            );
            assert!(
                snapshot.belief_is_fresh(now, 30_000),
                "case {case}: acted on stale belief"
            );
            stopped_some += 1;
        }
        // Determinism: equal inputs, equal answer.
        assert_eq!(stops, idle_stops(&inputs), "case {case}");
    }
    // The generator must reach the interesting branch, or the property above
    // is vacuous.
    assert!(stopped_some > CASES / 20, "only {stopped_some} cases stopped anything");
}

#[test]
fn an_idle_stop_picks_the_longest_idle_model_on_each_host() {
    use hypellm_fleet::idle::{IdleInputs, idle_hold, idle_stops};
    let mut rng = Rng::new(0x1D1E_0002);
    for case in 0..CASES {
        let (snapshot, demand, in_flight, now) = idle_case(&mut rng);
        let inputs = IdleInputs {
            snapshot: &snapshot,
            demand: &demand,
            in_flight: &in_flight,
            max_observation_age_ms: 30_000,
            now_ms: now,
        };
        let eligible: Vec<&DeploymentId> = snapshot
            .config
            .deployments
            .keys()
            .filter(|id| idle_hold(&inputs, id).is_ok())
            .collect();
        let stops = idle_stops(&inputs);
        if !snapshot.belief_is_fresh(now, 30_000) {
            assert!(stops.is_empty(), "case {case}");
            continue;
        }
        assert_eq!(stops.is_empty(), eligible.is_empty(), "case {case}");
        if let Some(chosen) = stops.first() {
            for other in &eligible {
                assert!(
                    demand.idle(chosen) >= demand.idle(other),
                    "case {case}: {chosen} chosen over the longer-idle {other}"
                );
            }
        }
    }
}

// -- Churn-aware scheduling (specification 26.11) ---------------------------

use hypellm_fleet::schedule::{
    Asking, Contender, JobClass, JobEntry, Proceed, Verdict, gate, pick_job, rank,
};

fn schedule_policy(rng: &mut Rng) -> FleetPolicy {
    FleetPolicy {
        activation_min_demand: 1 + u32::try_from(rng.below(3)).unwrap(),
        activation_max_wait_ms: rng.below(30_000),
        max_reorder_wait_ms: 5_000 + rng.below(200_000),
        ..FleetPolicy::DEFAULT
    }
}

/// Contenders with deliberately clustered ages and demand, so ties, the
/// starvation boundary and the readiness boundary are all hit often.
fn contenders(rng: &mut Rng, now: u64) -> Vec<Contender> {
    let count = 2 + rng.below(5);
    (0..count)
        .map(|i| Contender {
            deployment: did(&format!("d{i}")),
            waiting: 1 + u32::try_from(rng.below(4)).unwrap(),
            oldest_ms: now.saturating_sub(rng.below(4) * 60_000),
            restore_cost_ms: 10_000 * (1 + rng.below(3)),
        })
        .collect()
}

fn shuffled<T: Clone>(rng: &mut Rng, items: &[T]) -> Vec<T> {
    let mut out = items.to_vec();
    for i in (1..out.len()).rev() {
        let j = usize::try_from(rng.below(u64::try_from(i + 1).unwrap())).unwrap();
        out.swap(i, j);
    }
    out
}

#[test]
fn scheduling_decisions_do_not_depend_on_the_order_their_inputs_arrive_in() {
    // Appendix B: equal inputs give equal answers, never map or arrival order.
    // The contenders come from a queue the router iterates; a scheduler that
    // let that iteration order break a tie would hand the host to whichever
    // capability happened to sort first.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) + 7_001);
        let policy = schedule_policy(&mut rng);
        let now = 1_000_000;
        let all = contenders(&mut rng, now);
        let permuted = shuffled(&mut rng, &all);

        let order = |list: &[Contender]| -> Vec<DeploymentId> {
            rank(list, now, &policy).iter().map(|c| c.deployment.clone()).collect()
        };
        assert_eq!(order(&all), order(&permuted), "seed {seed}: ranking moved");

        for asking in &all {
            let evicts = rng.bool();
            let victims_busy = rng.bool();
            let question = Asking {
                deployment: &asking.deployment,
                evicts,
                victims_busy,
            };
            assert_eq!(
                gate(&question, &all, now, &policy),
                gate(&question, &permuted, now, &policy),
                "seed {seed}: the gate's answer for {} moved",
                asking.deployment
            );
        }

        let jobs: Vec<JobEntry> = (0..8_u64)
            .map(|seq| JobEntry {
                seq,
                submitted_ms: now.saturating_sub(rng.below(4) * 60_000),
                due: rng.below(5) != 0,
                class: match rng.below(4) {
                    0 => JobClass::Warm,
                    1 => JobClass::Activating,
                    2 => JobClass::Cold("a".to_owned()),
                    _ => JobClass::Cold("b".to_owned()),
                },
            })
            .collect();
        let shuffled_jobs = shuffled(&mut rng, &jobs);
        let seq_of = |list: &[JobEntry]| {
            pick_job(list, now, policy.max_reorder_wait_ms).map(|i| list[i].seq)
        };
        assert_eq!(seq_of(&jobs), seq_of(&shuffled_jobs), "seed {seed}: job pick moved");
    }
}

#[test]
fn nothing_waits_behind_reordering_past_the_bound() {
    // The bound is what makes reordering safe to ship: whatever the scores,
    // work that has waited `max_reorder_wait_ms` is first in line. Fixtures
    // put enormous demand on the young contenders, so only the bound can
    // explain the starving one going first.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) + 9_001);
        let policy = schedule_policy(&mut rng);
        let now = 10_000_000;
        let mut all = contenders(&mut rng, now);
        for contender in &mut all {
            contender.oldest_ms = now.saturating_sub(rng.below(policy.max_reorder_wait_ms));
            contender.waiting = 200;
        }
        let starving = rng.below(u64::try_from(all.len()).unwrap());
        let starving = usize::try_from(starving).unwrap();
        all[starving].waiting = 1;
        all[starving].restore_cost_ms = 600_000;
        all[starving].oldest_ms = now - policy.max_reorder_wait_ms - rng.below(10_000);

        let me = all[starving].clone();
        let busy = Asking {
            deployment: &me.deployment,
            evicts: true,
            victims_busy: true,
        };
        assert!(
            matches!(gate(&busy, &all, now, &policy), Verdict::Proceed(Proceed::Starving)),
            "seed {seed}: starving demand was held back"
        );
        for other in all.iter().filter(|c| c.deployment != me.deployment) {
            let asking = Asking {
                deployment: &other.deployment,
                evicts: false,
                victims_busy: false,
            };
            assert!(
                matches!(gate(&asking, &all, now, &policy), Verdict::Defer(_)),
                "seed {seed}: {} went ahead of starving demand",
                other.deployment
            );
        }

        // Jobs: a due job past the bound is always the one taken.
        let old = rng.below(8);
        let jobs: Vec<JobEntry> = (0..8_u64)
            .map(|seq| JobEntry {
                seq,
                submitted_ms: if seq == old {
                    now - policy.max_reorder_wait_ms
                } else {
                    now - rng.below(policy.max_reorder_wait_ms)
                },
                due: true,
                class: if seq == old {
                    JobClass::Cold("lonely".to_owned())
                } else {
                    JobClass::Warm
                },
            })
            .collect();
        let picked = pick_job(&jobs, now, policy.max_reorder_wait_ms).unwrap();
        assert_eq!(jobs[picked].seq, old, "seed {seed}: a starving job was passed over");
    }
}

/// One slot, two models, serial service: how many loads, and the longest wait.
///
/// `scheduled` asks [`gate`] on behalf of each waiting model, as parked
/// requests do, and keeps serving the loaded model when none may go; the
/// baseline serves strictly oldest-first.
fn simulate(arrivals: &[(u64, usize)], load_ms: u64, serve_ms: u64, policy: &FleetPolicy, scheduled: bool) -> (u32, u64) {
    let mut waiting: Vec<(u64, usize)> = Vec::new();
    let mut next = 0;
    let mut now = 0_u64;
    let mut loaded: Option<usize> = None;
    let mut loads = 0_u32;
    let mut longest = 0_u64;
    let mut served = 0;
    while served < arrivals.len() {
        while next < arrivals.len() && arrivals[next].0 <= now {
            waiting.push(arrivals[next]);
            next += 1;
        }
        if waiting.is_empty() {
            now = arrivals[next].0;
            continue;
        }
        let oldest_of = |model: usize| waiting.iter().filter(|w| w.1 == model).map(|w| w.0).min();
        let model = if scheduled {
            let contenders: Vec<Contender> = (0..2)
                .filter(|m| Some(*m) != loaded)
                .filter_map(|m| {
                    oldest_of(m).map(|oldest_ms| Contender {
                        deployment: did(&format!("m{m}")),
                        waiting: u32::try_from(waiting.iter().filter(|w| w.1 == m).count()).unwrap(),
                        oldest_ms,
                        restore_cost_ms: load_ms,
                    })
                })
                .collect();
            let warm_has_work = loaded.is_some_and(|l| oldest_of(l).is_some());
            // Each waiting model asks the gate, exactly as a parked request
            // does; the first allowed to go is loaded. If none is, the loaded
            // model keeps serving its own work.
            contenders
                .iter()
                .find(|c| {
                    let asking = Asking {
                        deployment: &c.deployment,
                        evicts: loaded.is_some(),
                        victims_busy: warm_has_work,
                    };
                    matches!(gate(&asking, &contenders, now, policy), Verdict::Proceed(_))
                })
                .map_or(loaded.unwrap_or(0), |c| {
                    usize::from(c.deployment.as_str() == "m1")
                })
        } else {
            waiting.iter().min_by_key(|w| w.0).unwrap().1
        };
        if loaded != Some(model) {
            loads += 1;
            now += load_ms;
            loaded = Some(model);
        }
        let position = waiting
            .iter()
            .enumerate()
            .filter(|(_, w)| w.1 == model)
            .min_by_key(|(_, w)| w.0)
            .map(|(i, _)| i)
            .unwrap();
        let (arrived, _) = waiting.remove(position);
        longest = longest.max(now - arrived);
        now += serve_ms;
        served += 1;
    }
    (loads, longest)
}

#[test]
fn interleaved_demand_for_two_models_costs_fewer_loads_than_arrival_order() {
    // The adversarial case for a one-slot host: requests for two models
    // arriving strictly alternately, faster than a load. Arrival order loads
    // on nearly every request. The scheduler must load measurably less, and
    // must still serve everyone within the bound plus the work already
    // committed when they started starving.
    let mut fifo_total = 0_u64;
    let mut scheduled_total = 0_u64;
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) + 11_001);
        let load_ms = 20_000 + rng.below(60_000);
        let serve_ms = 1_000 + rng.below(5_000);
        let gap_ms = 200 + rng.below(serve_ms);
        let count = 8 + rng.below(16);
        let arrivals: Vec<(u64, usize)> = (0..count)
            .map(|i| (i * gap_ms, usize::try_from(i % 2).unwrap()))
            .collect();
        // A bound shorter than a load makes everything starving the moment a
        // host frees, which is arrival order by design; the claim is about a
        // bound that leaves room to reorder.
        let policy = FleetPolicy {
            max_reorder_wait_ms: 2 * load_ms + rng.below(300_000),
            ..FleetPolicy::DEFAULT
        };

        let (fifo_loads, _) = simulate(&arrivals, load_ms, serve_ms, &policy, false);
        let (loads, longest) = simulate(&arrivals, load_ms, serve_ms, &policy, true);
        assert!(
            loads < fifo_loads,
            "seed {seed}: {loads} loads scheduled against {fifo_loads} in arrival order"
        );
        // Every request is served within the bound plus, at worst, a load and
        // a service for each request older than it: past the bound, work goes
        // in age order, and each older request may cost a swap.
        let ceiling = policy.max_reorder_wait_ms + count * (load_ms + serve_ms);
        assert!(longest <= ceiling, "seed {seed}: a request waited {longest} ms against {ceiling}");
        fifo_total += u64::from(fifo_loads);
        scheduled_total += u64::from(loads);
    }
    // The aggregate, so the report can quote a measured reduction.
    println!("interleaved two-model demand: {fifo_total} loads in arrival order, {scheduled_total} scheduled");
    assert!(scheduled_total * 2 <= fifo_total, "less than a halving: {scheduled_total} vs {fifo_total}");
}

#[test]
fn scheduling_priority_never_overflows() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) + 13_001);
        let contender = Contender {
            deployment: did("x"),
            waiting: u32::try_from(rng.next_u64() >> 32).unwrap(),
            oldest_ms: rng.next_u64(),
            restore_cost_ms: rng.next_u64(),
        };
        // Must not panic in debug builds, where overflow would.
        let now = rng.next_u64();
        let _ = contender.priority(now);
        let _ = contender.is_starving(now, &FleetPolicy::DEFAULT);
    }
}

// -- Specification 26.12: copies are only ever verified -----------------------

/// What one candidate source host holds, for the copy property.
#[derive(Debug, Clone, Copy)]
enum Holding {
    Nothing,
    Kept,
    Other,
    NoId,
    Unreachable,
}

#[test]
fn a_copy_is_planned_only_from_a_host_reporting_the_kept_checksum_and_preferred_to_a_fetch() {
    use hypellm_core::ids::ArtifactId;
    use hypellm_fleet::model::{Artifact, ArtifactKind, ImageId};
    use hypellm_fleet::plan::PlanStep;
    use hypellm_fleet::state::{ArtifactPlacement, HostObservation};

    let kept = ImageId::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
    let other = ImageId::parse(&format!("sha256:{}", "b".repeat(64))).unwrap();
    let mut rng = Rng::new(0xF1EE_C0B1);
    let mut copies = 0;
    let mut fetches = 0;
    for case in 0..CASES {
        let now = 10_000_000;
        let mut fleet = fleet();
        fleet.default_policy.allow_fetch = true;
        let artifact = ArtifactId::new("music3").unwrap();
        // Pinned in configuration, learned, or neither.
        let anchor = rng.below(3);
        fleet.artifacts.insert(
            artifact.clone(),
            Artifact {
                id: artifact.clone(),
                kind: ArtifactKind::Image,
                arch: Arch::Aarch64,
                size_bytes: GIB,
                digest: format!("sha256:{}", "0".repeat(64)),
                image_id: (anchor == 0).then(|| kept.clone()),
                source: "mirror".to_owned(),
            },
        );
        // Candidate sources, named so the honest one is often *not* first in
        // identifier order: the tampered hosts sort ahead of it.
        let count = 1 + rng.below(5);
        let mut holdings = Vec::new();
        for n in 0..count {
            let holding = match rng.below(5) {
                0 => Holding::Nothing,
                1 => Holding::Kept,
                2 => Holding::Other,
                3 => Holding::NoId,
                _ => Holding::Unreachable,
            };
            let id = HostId::new(&format!("peer-{n}")).unwrap();
            fleet.hosts.insert(
                id.clone(),
                Host {
                    id: id.clone(),
                    agent: AgentId::new("local").unwrap(),
                    arch: Arch::Aarch64,
                    state: HostState::Enabled,
                    reserved_memory_bytes: 0,
                    max_concurrent_activations: 1,
                },
            );
            holdings.push((id, holding));
        }
        let mut incoming = deployment("music3", 8 * GIB);
        incoming.artifact = Some(artifact.clone());
        fleet.deployments.insert(incoming.id.clone(), incoming.clone());

        let mut snapshot = snapshot_of(fleet, now);
        if anchor == 1 {
            snapshot.learned_checksums.insert(artifact.clone(), kept.clone());
        }
        let spark = HostId::new("spark").unwrap();
        for host in std::iter::once(&spark).chain(holdings.iter().map(|(h, _)| h)) {
            snapshot.inventory.hosts.insert(
                host.clone(),
                HostObservation {
                    host: host.clone(),
                    reachable: true,
                    free_disk_bytes: 100 * GIB,
                    arch: Some(Arch::Aarch64),
                },
            );
        }
        for (host, holding) in &holdings {
            let image_id = match holding {
                Holding::Nothing => continue,
                Holding::Kept | Holding::Unreachable => Some(kept.clone()),
                Holding::Other => Some(other.clone()),
                Holding::NoId => None,
            };
            if matches!(holding, Holding::Unreachable) {
                snapshot.inventory.hosts.get_mut(host).unwrap().reachable = false;
            }
            snapshot.inventory.artifacts.insert(
                (artifact.clone(), host.clone()),
                ArtifactPlacement {
                    artifact: artifact.clone(),
                    host: host.clone(),
                    present: true,
                    // The agent's registry check passes everywhere: the kept
                    // checksum, not this flag, is what must decide.
                    verified: true,
                    bytes_present: GIB,
                    image_id,
                },
            );
        }

        let mut ctx = context(now);
        ctx.may_fetch = true;
        let outcome = plan(&snapshot, &DemandSnapshot::default(), &incoming.target, &ctx);
        let PlanOutcome::Plan(planned) = &outcome else {
            panic!("case {case}: a fetchable artifact on an empty host refused: {outcome:?}");
        };
        let transfer = planned
            .steps
            .iter()
            .find(|s| matches!(s, PlanStep::Fetch { .. } | PlanStep::Copy { .. }))
            .expect("the artifact is absent on spark, so it must be acquired");

        let honest: Option<&HostId> = holdings
            .iter()
            .find(|(_, h)| matches!(h, Holding::Kept))
            .map(|(id, _)| id);
        match (anchor, honest, transfer) {
            // No checksum kept: there is nothing to verify a copy against.
            (2, _, PlanStep::Copy { .. }) => {
                panic!("case {case}: planned a copy with no kept checksum: {holdings:?}")
            }
            (_, Some(expected), PlanStep::Copy { from, to, .. }) if anchor != 2 => {
                assert_eq!(from, expected, "case {case}: {holdings:?}");
                assert_eq!(to, &spark);
                copies += 1;
            }
            (_, Some(_), PlanStep::Fetch { .. }) if anchor != 2 => {
                panic!("case {case}: fetched although a verified peer exists: {holdings:?}")
            }
            (_, None, PlanStep::Copy { from, .. }) => {
                panic!("case {case}: copied from unverified {from}: {holdings:?}")
            }
            _ => fetches += 1,
        }
    }
    // Both branches were reached, or the property proved half of itself.
    assert!(copies > 50 && fetches > 50, "copies {copies}, fetches {fetches}");
}
