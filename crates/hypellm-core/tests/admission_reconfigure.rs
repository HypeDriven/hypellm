//! A published quota applied to a running admission controller.
//!
//! `AdmissionController::apply` reconfigures scopes in place. What that must
//! never do is the failure a naïve "rebuild the controller" has: forget what
//! is in flight, hand back a spent budget, refill a drained rate bucket, or
//! strand a waiter. Each test names one of those.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use hypellm_core::admission::{
    AdmissionController, AdmissionPlan, BudgetPeriod, PriorityClass, Rejection, Reservation,
    ScopeLimits,
};
use hypellm_core::ids::{PrincipalId, TargetId, TenantId};
use hypellm_core::time::{Clock, TestClock};
use std::sync::Arc;
use std::time::Duration;

const CASES: u64 = 400;

fn tenant() -> TenantId {
    TenantId::new("local").unwrap()
}
fn principal(s: &str) -> PrincipalId {
    PrincipalId::new(s).unwrap()
}
fn target() -> TargetId {
    TargetId::new("spark:q").unwrap()
}

fn plan_with(principals: &[(&str, ScopeLimits)]) -> AdmissionPlan {
    let mut plan = AdmissionPlan::new(ScopeLimits::UNLIMITED);
    for (p, limits) in principals {
        plan.principals.insert(principal(p), *limits);
    }
    plan
}

fn controller(clock: &Arc<TestClock>, plan: &AdmissionPlan) -> AdmissionController {
    let clock: Arc<dyn Clock> = Arc::<TestClock>::clone(clock);
    AdmissionController::from_plan(clock, plan)
}

/// xorshift, seeded: a failure reproduces from its seed alone.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn random_limits(rng: &mut Rng) -> ScopeLimits {
    ScopeLimits {
        max_concurrency: u32::try_from(rng.below(4)).unwrap(),
        requests_per_second: [0, 0, 1, 5][usize::try_from(rng.below(4)).unwrap()],
        request_burst: u32::try_from(rng.below(3)).unwrap(),
        tokens_per_minute: [0, 0, 6_000, 60_000][usize::try_from(rng.below(4)).unwrap()],
        token_burst: rng.below(2_000),
        budget_minor_units: [0, 0, 50, 500][usize::try_from(rng.below(4)).unwrap()],
        budget_period: BudgetPeriod::Daily,
        ..ScopeLimits::UNLIMITED
    }
}

/// One run of interleaved admissions, releases, spend and reconfigurations.
/// Returns the trace of outcomes, so two runs of one seed can be compared.
fn run(seed: u64) -> Vec<String> {
    const SUBJECTS: [&str; 2] = ["mikiyas.mulugeta", "svc:other"];
    let mut rng = Rng::new(seed);
    let clock = Arc::new(TestClock::new());
    let mut limits = [random_limits(&mut rng), random_limits(&mut rng)];
    let mut configured = [true, true];
    let current_plan = |limits: &[ScopeLimits; 2], configured: &[bool; 2]| {
        let named: Vec<(&str, ScopeLimits)> = SUBJECTS
            .iter()
            .zip(limits.iter())
            .zip(configured.iter())
            .filter(|(_, on)| **on)
            .map(|((s, l), _)| (*s, *l))
            .collect();
        plan_with(&named)
    };
    let c = controller(&clock, &current_plan(&limits, &configured));
    let mut held: Vec<(usize, Reservation)> = Vec::new();
    let mut trace = Vec::new();

    for step in 0..60 {
        match rng.below(10) {
            // Reserve.
            0..=3 => {
                let who = usize::try_from(rng.below(2)).unwrap();
                let tokens = rng.below(3_000);
                match c.reserve(&tenant(), &principal(SUBJECTS[who]), &target(), tokens) {
                    Ok(reservation) => {
                        let scope = c.configured_principal_scope(&principal(SUBJECTS[who])).unwrap();
                        let in_force = if configured[who] { limits[who].max_concurrency } else { 0 };
                        assert!(
                            in_force == 0 || scope.in_flight() <= in_force,
                            "seed {seed} step {step}: admitted to {} in flight over a limit of {in_force}",
                            scope.in_flight()
                        );
                        trace.push(format!("{step} admit {who}"));
                        held.push((who, reservation));
                    }
                    Err((rejection, scope)) => trace.push(format!("{step} refuse {who} {rejection:?} {scope}")),
                }
            }
            // Release, three ways.
            4 | 5 => {
                if !held.is_empty() {
                    let index = usize::try_from(rng.below(u64::try_from(held.len()).unwrap())).unwrap();
                    let (_, reservation) = held.swap_remove(index);
                    match rng.below(3) {
                        0 => reservation.commit(rng.below(4_000)),
                        1 => reservation.release_unused(),
                        _ => drop(reservation),
                    }
                    trace.push(format!("{step} release"));
                }
            }
            // Spend.
            6 => {
                let who = usize::try_from(rng.below(2)).unwrap();
                c.record_spend(&tenant(), &principal(SUBJECTS[who]), None, None, rng.below(40), clock.now_millis());
            }
            // Reconfigure: raise, lower, remove or restore a principal's quota.
            7 | 8 => {
                let who = usize::try_from(rng.below(2)).unwrap();
                if rng.below(4) == 0 {
                    configured[who] = !configured[who];
                } else {
                    limits[who] = random_limits(&mut rng);
                    configured[who] = true;
                }
                let spent_before: Vec<u64> = SUBJECTS
                    .iter()
                    .map(|s| c.configured_principal_scope(&principal(s)).map_or(0, |sc| sc.observed_spend(clock.now_millis())))
                    .collect();
                let in_flight_before: Vec<u32> = SUBJECTS
                    .iter()
                    .map(|s| c.configured_principal_scope(&principal(s)).map_or(0, |sc| sc.in_flight()))
                    .collect();
                c.apply(&current_plan(&limits, &configured));
                for (i, s) in SUBJECTS.iter().enumerate() {
                    let scope = c.configured_principal_scope(&principal(s));
                    let spent = scope.as_ref().map_or(0, |sc| sc.observed_spend(clock.now_millis()));
                    let in_flight = scope.as_ref().map_or(0, |sc| sc.in_flight());
                    assert!(spent >= spent_before[i], "seed {seed} step {step}: a reconfiguration returned spent budget");
                    assert_eq!(in_flight, in_flight_before[i], "seed {seed} step {step}: a reconfiguration lost what was in flight");
                }
                trace.push(format!("{step} apply"));
            }
            // Time passes, well inside a budget period.
            _ => clock.advance(rng.below(1_500)),
        }

        // Conservation, after every step, in every scope a request can hold.
        for (i, s) in SUBJECTS.iter().enumerate() {
            if let Some(scope) = c.configured_principal_scope(&principal(s)) {
                let holding = u32::try_from(held.iter().filter(|(who, _)| *who == i).count()).unwrap();
                assert_eq!(scope.in_flight(), holding, "seed {seed} step {step}: in-flight drifted");
                let (acquired, released) = scope.conservation();
                assert_eq!(acquired - released, u64::from(holding), "seed {seed} step {step}: conservation broke");
            }
        }
    }

    held.clear();
    for s in SUBJECTS {
        if let Some(scope) = c.configured_principal_scope(&principal(s)) {
            assert_eq!(scope.in_flight(), 0, "seed {seed}: a reservation leaked");
            let (acquired, released) = scope.conservation();
            assert_eq!(acquired, released, "seed {seed}: released other than exactly once");
        }
    }
    let (acquired, released) = c.global().conservation();
    assert_eq!(acquired, released, "seed {seed}: the global scope leaked");
    trace
}

#[test]
fn reconfiguring_admission_never_loses_a_reservation_spend_or_a_limit_in_force() {
    for seed in 0..CASES {
        let first = run(seed);
        assert_eq!(first, run(seed), "seed {seed}: the same inputs admitted differently");
    }
}

#[test]
fn lowering_concurrency_below_what_is_in_flight_refuses_new_work_and_cancels_none() {
    let clock = Arc::new(TestClock::new());
    let p = principal("mikiyas.mulugeta");
    let wide = ScopeLimits { max_concurrency: 3, ..ScopeLimits::UNLIMITED };
    let c = controller(&clock, &plan_with(&[("mikiyas.mulugeta", wide)]));
    let held: Vec<Reservation> = (0..3).map(|_| c.reserve(&tenant(), &p, &target(), 1).unwrap()).collect();

    c.apply(&plan_with(&[("mikiyas.mulugeta", ScopeLimits { max_concurrency: 1, ..wide })]));
    let scope = c.configured_principal_scope(&p).unwrap();
    assert_eq!(scope.in_flight(), 3, "nothing in flight was cancelled");
    assert_eq!(
        c.reserve(&tenant(), &p, &target(), 1).err().map(|(r, _)| r),
        Some(Rejection::ConcurrencyExhausted)
    );
    drop(held);
    assert_eq!(scope.in_flight(), 0);
    let one = c.reserve(&tenant(), &p, &target(), 1).expect("under the new limit");
    assert!(c.reserve(&tenant(), &p, &target(), 1).is_err(), "the new limit of one holds");
    drop(one);
    let (acquired, released) = scope.conservation();
    assert_eq!(acquired, released);
}

#[test]
fn a_spent_budget_stays_spent_through_republication_and_removal() {
    let clock = Arc::new(TestClock::new());
    let p = principal("mikiyas.mulugeta");
    let budget = ScopeLimits { budget_minor_units: 100, ..ScopeLimits::UNLIMITED };
    let plan = plan_with(&[("mikiyas.mulugeta", budget)]);
    let c = controller(&clock, &plan);
    c.reserve(&tenant(), &p, &target(), 1).unwrap().commit(1);
    c.record_spend(&tenant(), &p, None, None, 100, clock.now_millis());
    let refused = || c.reserve(&tenant(), &p, &target(), 1).err().map(|(r, _)| r);
    assert_eq!(refused(), Some(Rejection::BudgetExhausted));

    // Re-publishing the same limit, or removing it and putting it back, must
    // not reset the ledger: that is the credit a rebuilt scope would return.
    c.apply(&plan);
    assert_eq!(refused(), Some(Rejection::BudgetExhausted));
    c.apply(&plan_with(&[]));
    assert!(c.reserve(&tenant(), &p, &target(), 1).is_ok(), "no budget, no refusal");
    c.apply(&plan);
    assert_eq!(refused(), Some(Rejection::BudgetExhausted), "restoring the budget restored the spend");
}

#[test]
fn republishing_a_rate_limit_does_not_refill_a_drained_bucket() {
    let clock = Arc::new(TestClock::new());
    let p = principal("mikiyas.mulugeta");
    let rate = ScopeLimits { requests_per_second: 1, request_burst: 1, ..ScopeLimits::UNLIMITED };
    let plan = plan_with(&[("mikiyas.mulugeta", rate)]);
    let c = controller(&clock, &plan);
    c.reserve(&tenant(), &p, &target(), 0).unwrap().commit(0);
    assert_eq!(
        c.reserve(&tenant(), &p, &target(), 0).err().map(|(r, _)| r),
        Some(Rejection::RequestRateExceeded)
    );
    c.apply(&plan);
    // A higher burst raises the ceiling, not the level.
    c.apply(&plan_with(&[("mikiyas.mulugeta", ScopeLimits { request_burst: 50, ..rate })]));
    assert_eq!(
        c.reserve(&tenant(), &p, &target(), 0).err().map(|(r, _)| r),
        Some(Rejection::RequestRateExceeded),
        "a publication handed out a fresh burst"
    );
    clock.advance(1_000);
    assert!(c.reserve(&tenant(), &p, &target(), 0).is_ok(), "refill continues at the rate");
}

#[test]
fn a_waiter_is_admitted_when_a_publication_raises_the_limit() {
    let clock = Arc::new(TestClock::new());
    let p = principal("mikiyas.mulugeta");
    let narrow = ScopeLimits { max_concurrency: 1, max_queued: 4, ..ScopeLimits::UNLIMITED };
    let c = Arc::new(controller(&clock, &plan_with(&[("mikiyas.mulugeta", narrow)])));
    let first = c.reserve(&tenant(), &p, &target(), 1).unwrap();

    let waiter = {
        let c = Arc::clone(&c);
        let p = p.clone();
        std::thread::spawn(move || {
            c.reserve_queued(&tenant(), &p, &target(), 1, PriorityClass::Standard, Duration::from_secs(5))
                .map(|(reservation, _)| reservation.commit(1))
                .map_err(|(r, _)| r)
        })
    };
    let scope = c.configured_principal_scope(&p).unwrap();
    let started = std::time::Instant::now();
    while scope.queued() == 0 && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(scope.queued(), 1, "the second request is waiting");

    // Nothing is released: only the publication can let it in, and it must
    // do so at once rather than when the waiter's own timeout runs out.
    let published = std::time::Instant::now();
    c.apply(&plan_with(&[("mikiyas.mulugeta", ScopeLimits { max_concurrency: 2, ..narrow })]));
    assert_eq!(waiter.join().unwrap(), Ok(()), "the raised limit admitted the waiter");
    assert!(published.elapsed() < Duration::from_secs(2), "the waiter sat out its timeout");
    drop(first);
    let (acquired, released) = scope.conservation();
    assert_eq!(acquired, released);
}

#[test]
fn a_removed_target_quota_still_releases_what_it_admitted() {
    let clock = Arc::new(TestClock::new());
    let mut plan = AdmissionPlan::new(ScopeLimits::UNLIMITED);
    plan.targets.insert(target(), ScopeLimits { max_concurrency: 1, ..ScopeLimits::UNLIMITED });
    let c = controller(&clock, &plan);
    let p = principal("svc:x");
    let held = c.reserve(&tenant(), &p, &target(), 1).unwrap();
    let scope = c.target_scope(&target()).unwrap();

    c.apply(&AdmissionPlan::new(ScopeLimits::UNLIMITED));
    assert!(c.target_scope(&target()).is_none(), "the target is no longer limited");
    let second = c.reserve(&tenant(), &p, &target(), 1).expect("no target limit now");
    drop(held);
    drop(second);
    assert_eq!(scope.in_flight(), 0, "the dropped scope was released against, exactly once");
    let (acquired, released) = scope.conservation();
    assert_eq!(acquired, released);
}
