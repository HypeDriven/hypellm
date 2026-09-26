//! Admission accounting across the scope hierarchy.
//!
//! Specification 12: "hierarchical token buckets and concurrency semaphores
//! with atomic reservation", reconciled "without granting negative-cost
//! abuse". Each test here names one way the arithmetic could let a caller
//! consume more than the configuration allows, or charge a scope for work it
//! never admitted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::admission::{
    AdmissionController, PriorityClass, Rejection, ScopeLimits, TokenBucket,
};
use hypellm_core::canonical::Operation;
use hypellm_core::ids::{AliasId, PrincipalId, TargetId, TenantId};
use hypellm_core::time::{Clock, TestClock};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tenant(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}
fn principal(s: &str) -> PrincipalId {
    PrincipalId::new(s).unwrap()
}
fn target(s: &str) -> TargetId {
    TargetId::new(s).unwrap()
}
fn alias(s: &str) -> AliasId {
    AliasId::new(s).unwrap()
}

fn controller(clock: &Arc<TestClock>) -> Arc<AdmissionController> {
    let clock: Arc<TestClock> = Arc::clone(clock);
    let clock: Arc<dyn Clock> = clock;
    Arc::new(AdmissionController::new(clock, ScopeLimits::UNLIMITED))
}

/// Wait, bounded, for `condition`; report whether it became true.
fn eventually(condition: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    condition()
}

#[test]
fn an_oversized_estimate_is_charged_in_full_and_not_refunded_past_actual_use() {
    // `tpm=60000` with no burst is a capacity of 1000 tokens. A request that
    // reserves a million and really uses 999_000 must cost 999_000: the charge
    // was once clamped to the capacity while reconciliation refunded against
    // the full estimate, so this request cost nothing and the bucket was full
    // again the moment it finished.
    let clock = Arc::new(TestClock::new());
    let c = controller(&clock);
    let t = tenant("acme");
    c.configure_tenant(
        &t,
        ScopeLimits {
            tokens_per_minute: 60_000,
            ..ScopeLimits::UNLIMITED
        },
    );
    let p = principal("svc:a");
    let tg = target("local:m");

    let big = c.reserve(&t, &p, &tg, 1_000_000).expect("a full bucket admits once");
    big.commit(999_000);

    assert_eq!(
        c.reserve(&t, &p, &tg, 1).err().map(|(r, _)| r),
        Some(Rejection::TokenRateExceeded),
        "usage far beyond the capacity must be paid for before anything else runs"
    );
    // At 1000 tokens a second, the 998_000 left owing takes 998 seconds.
    clock.advance(990_000);
    assert!(c.reserve(&t, &p, &tg, 1).is_err(), "still in debt");
    clock.advance(10_000);
    assert!(c.reserve(&t, &p, &tg, 1).is_ok(), "the debt is repaid by refill");
}

#[test]
fn an_oversized_request_that_used_nothing_is_refunded_exactly() {
    let b = TokenBucket::per_minute(60_000, 0, 0);
    assert!(b.try_take(5_000, 0));
    assert!(!b.try_take(1, 0), "in debt");
    b.refund(5_000);
    assert_eq!(b.level(), 1_000, "a full refund restores the bucket, no more");
    assert!(b.try_take(1_000, 0));
}

#[test]
fn a_rejection_at_a_narrow_scope_refunds_every_wider_scope_it_took_from() {
    // The tenant allows one request per second and 1000 tokens. A reservation
    // refused by the target's concurrency limit once kept the tenant's
    // request token and its token estimate, so each refusal drained budget
    // for work that never ran.
    let clock = Arc::new(TestClock::new());
    let c = controller(&clock);
    let busy = tenant("busy");
    let victim = tenant("victim");
    c.configure_tenant(
        &victim,
        ScopeLimits {
            requests_per_second: 1,
            request_burst: 1,
            tokens_per_minute: 60_000,
            ..ScopeLimits::UNLIMITED
        },
    );
    let tg = target("local:m");
    c.configure_target(
        &tg,
        ScopeLimits {
            max_concurrency: 1,
            ..ScopeLimits::UNLIMITED
        },
    );

    let holder = c.reserve(&busy, &principal("svc:busy"), &tg, 1).unwrap();
    for _ in 0..3 {
        let refused = c.reserve(&victim, &principal("svc:victim"), &tg, 1_000);
        assert_eq!(
            refused.err().map(|(r, _)| r),
            Some(Rejection::ConcurrencyExhausted)
        );
    }
    drop(holder);

    // No time has passed: the victim's buckets must be exactly as full as
    // before the refusals.
    let admitted = c.reserve(&victim, &principal("svc:victim"), &tg, 1_000);
    assert!(
        admitted.is_ok(),
        "refusals elsewhere drained the tenant: {:?}",
        admitted.err()
    );
}

#[test]
fn a_concurrency_limit_on_an_alias_queues_like_any_other() {
    let clock = Arc::new(TestClock::new());
    let c = controller(&clock);
    let a = alias("code");
    c.configure_alias(
        &a,
        None,
        ScopeLimits {
            max_concurrency: 1,
            max_queued: 1,
            ..ScopeLimits::UNLIMITED
        },
    );
    let t = tenant("acme");
    let p = principal("svc:a");
    let tg = target("local:m");

    let first = c
        .reserve_for(&t, &p, Some((&a, Operation::Chat)), &tg, 1)
        .unwrap();

    let waiter = {
        let c = Arc::clone(&c);
        let (t, p, a, tg) = (t.clone(), p.clone(), a.clone(), tg.clone());
        std::thread::spawn(move || {
            c.reserve_queued_for(
                &t,
                &p,
                Some((&a, Operation::Chat)),
                &tg,
                1,
                PriorityClass::Standard,
                Duration::from_secs(5),
            )
            .map(|(reservation, _)| reservation.commit(1))
            .map_err(|(rejection, _)| rejection)
        })
    };

    let alias_scope = c.alias_scope(&a, Operation::Chat).unwrap();
    let queued = eventually(|| alias_scope.queued() == 1);
    drop(first);
    let result = waiter.join().unwrap();
    assert!(queued, "the request never joined the alias's queue");
    assert_eq!(result, Ok(()));
}

#[test]
fn a_request_that_waited_in_line_is_still_held_to_the_alias_limits() {
    // The retry after a queue wait once rebuilt the scope chain without the
    // alias layer, so a request that queued on a target was admitted past its
    // alias's token budget.
    let clock = Arc::new(TestClock::new());
    let c = controller(&clock);
    let a = alias("code");
    c.configure_alias(
        &a,
        None,
        ScopeLimits {
            tokens_per_minute: 60_000, // 1000 tokens, no refill while the clock is still
            ..ScopeLimits::UNLIMITED
        },
    );
    let queued_target = target("local:queued");
    c.configure_target(
        &queued_target,
        ScopeLimits {
            max_concurrency: 1,
            max_queued: 1,
            ..ScopeLimits::UNLIMITED
        },
    );
    let other_target = target("local:other");
    let t = tenant("acme");
    let p = principal("svc:a");
    let via = Some((&a, Operation::Chat));

    let first = c.reserve_for(&t, &p, via, &queued_target, 100).unwrap();

    let waiter = {
        let c = Arc::clone(&c);
        let (t, p, a, tg) = (t.clone(), p.clone(), a.clone(), queued_target.clone());
        std::thread::spawn(move || {
            c.reserve_queued_for(
                &t,
                &p,
                Some((&a, Operation::Chat)),
                &tg,
                100,
                PriorityClass::Standard,
                Duration::from_secs(5),
            )
            .map(|(reservation, _)| reservation.commit(100))
            .map_err(|(rejection, _)| rejection)
        })
    };
    let target_scope = c.target_scope(&queued_target).unwrap();
    assert!(eventually(|| target_scope.queued() == 1), "never queued");

    // Another target spends the rest of the alias's budget while the first
    // request waits.
    let drain = c.reserve_for(&t, &p, via, &other_target, 900).unwrap();
    first.commit(100);

    let result = waiter.join().unwrap();
    assert_eq!(
        result,
        Err(Rejection::TokenRateExceeded),
        "the queued request bypassed the alias token budget"
    );
    drain.commit(900);
}
