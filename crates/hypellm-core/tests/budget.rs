//! Property tests over the per-key token budget ledger (specification 12.1,
//! 12.3; the "Key token budgets" row of specification 21).
//!
//! The unit tests beside the ledger show that particular arrangements behave.
//! These assert that no interleaving of reservations, settlements, limit
//! changes, credits, journal failures and crashes breaks the four things the
//! feature exists to guarantee:
//!
//! - nothing is admitted beyond a finite limit;
//! - a charge, once made, is never forgotten — by a later operation or by a
//!   restart;
//! - a credit is applied exactly once per operation identifier;
//! - a hold is finished exactly once, so reserved tokens return to zero.
//!
//! Hand-rolled for the reason `properties.rs` gives: specification 4 admits no
//! property-testing dependency. Every case derives from a printed seed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_core::budget::testing::MemoryJournal;
use hypellm_core::budget::{
    BudgetJournal, BudgetLedger, BudgetMutationError, BudgetRefusal, BudgetReservation,
};
use hypellm_core::ids::{KeyId, TenantId};
use std::collections::BTreeMap;
use std::sync::Arc;

const CASES: u64 = 400;
const STEPS: usize = 120;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn keys() -> [KeyId; 2] {
    [
        KeyId::new("00000000000000aa").unwrap(),
        KeyId::new("00000000000000bb").unwrap(),
    ]
}

/// What the test knows to be true, independently of the ledger.
#[derive(Default, Clone)]
struct Model {
    /// Tokens charged by settlements this test performed.
    charged: u64,
    /// The limit the last successful `set` or credit left.
    limit: Option<u64>,
    /// Operation identifiers whose credit was applied, with the amount.
    credits: BTreeMap<String, u64>,
}

struct World {
    journal: Arc<MemoryJournal>,
    ledger: Arc<BudgetLedger>,
    draw: u64,
    holds: Vec<(usize, BudgetReservation)>,
    models: [Model; 2],
}

impl World {
    fn new(draw: u64) -> Self {
        let journal = Arc::new(MemoryJournal::new());
        let ledger = Arc::new(BudgetLedger::new(
            Arc::clone(&journal) as Arc<dyn BudgetJournal>,
            draw,
        ));
        Self {
            journal,
            ledger,
            draw,
            holds: Vec::new(),
            models: [Model::default(), Model::default()],
        }
    }

    /// The mark on disk covers everything the key has spent or is holding.
    ///
    /// This is the property the whole durability argument rests on, checked
    /// directly rather than waiting for a crash to land in the window: at no
    /// moment is there a token in flight or consumed that a restart would not
    /// count.
    fn assert_covered(&self, key: &KeyId, seed: u64, step: usize) {
        let view = self.ledger.view(key);
        let held = view.consumed + view.reserved;
        if held == 0 {
            return;
        }
        let mark = self
            .journal
            .records()
            .iter()
            .rev()
            .find(|record| &record.key == key)
            .map(|record| record.drawn);
        assert!(
            mark.is_some_and(|mark| mark >= held),
            "seed {seed} step {step}: {held} tokens held against a durable mark of {mark:?}"
        );
    }

    /// Kill the process: holds are never finished, nothing is flushed, and a
    /// new ledger is built from what reached the journal.
    fn crash(&mut self, seed: u64) {
        let keys = keys();
        let before: Vec<_> = keys.iter().map(|key| self.ledger.view(key)).collect();
        // The old holds still point at the old ledger; finishing them there
        // changes nothing the new one can see.
        self.holds.clear();
        let reborn = Arc::new(BudgetLedger::new(
            Arc::clone(&self.journal) as Arc<dyn BudgetJournal>,
            self.draw,
        ));
        self.journal.replay_into(&reborn);
        for (index, key) in keys.iter().enumerate() {
            let after = reborn.view(key);
            let was = before.get(index).unwrap();
            assert!(
                after.consumed >= was.consumed.saturating_add(was.reserved),
                "seed {seed}: a restart returned credit to key {index}: {was:?} became {after:?}"
            );
            assert_eq!(after.limit, was.limit, "seed {seed}: a restart changed a limit");
            assert_eq!(after.revision, was.revision, "seed {seed}");
        }
        self.ledger = reborn;
    }
}

fn run(seed: u64) {
    let mut rng = Rng::new(seed);
    let draw = [0, 7, 500, 1_000_000][usize::try_from(rng.below(4)).unwrap()];
    let mut world = World::new(draw);
    let keys = keys();
    // Whether anything has been lost to a crash; exact equality with the
    // model holds only until then.
    let mut crashed = [false, false];

    for step in 0..STEPS {
        let index = usize::try_from(rng.below(2)).unwrap();
        let key = keys.get(index).unwrap();
        // The journal fails only around operations that must refuse when it
        // does. A settlement that cannot be written is a separate property,
        // covered beside the ledger.
        let failing = rng.below(8) == 0;
        match rng.below(10) {
            0 => {
                let limit = (rng.below(4) != 0).then(|| rng.below(5000));
                world.journal.fail(failing);
                let result = world.ledger.set(key, &tenant(), None, limit, None);
                world.journal.fail(false);
                match result {
                    Ok(view) => {
                        assert!(!failing, "seed {seed}: a limit was set without being written");
                        assert_eq!(view.limit, limit);
                        world.models.get_mut(index).unwrap().limit = limit;
                    }
                    Err(error) => {
                        assert_eq!(error, BudgetMutationError::Unavailable, "seed {seed}");
                        assert!(failing, "seed {seed}");
                    }
                }
            }
            1 => {
                let operation = format!("pay-{}", rng.below(6));
                let tokens = 1 + rng.below(900);
                let digest = format!("d{tokens}");
                world.journal.fail(failing);
                let result = world
                    .ledger
                    .credit(key, &tenant(), None, tokens, &operation, &digest, None, "svc", 0);
                world.journal.fail(false);
                let model = world.models.get_mut(index).unwrap();
                match (result, model.credits.get(&operation).copied()) {
                    (Ok(outcome), None) => {
                        assert!(!outcome.replayed && !failing, "seed {seed} step {step}");
                        let before = model.limit.expect("a credit to an unlimited budget succeeded");
                        model.limit = Some(before + tokens);
                        model.credits.insert(operation, tokens);
                    }
                    (Ok(outcome), Some(applied)) => {
                        assert!(outcome.replayed, "seed {seed}: a credit was applied twice");
                        assert_eq!(applied, tokens);
                        assert_eq!(outcome.receipt.tokens, applied);
                    }
                    (Err(BudgetMutationError::IdempotencyConflict), Some(applied)) => {
                        assert_ne!(applied, tokens, "seed {seed}: a faithful replay conflicted");
                    }
                    (Err(BudgetMutationError::Unlimited), None) => {
                        assert_eq!(model.limit, None, "seed {seed}");
                    }
                    (Err(BudgetMutationError::Unavailable), None) => {
                        assert!(failing, "seed {seed}");
                    }
                    (other, known) => panic!("seed {seed} step {step}: {other:?} with {known:?}"),
                }
                assert_eq!(world.ledger.view(key).limit, model.limit, "seed {seed} step {step}");
            }
            2..=5 => {
                let tokens = rng.below(700);
                let before = world.ledger.view(key);
                world.journal.fail(failing);
                let result = world.ledger.reserve(key, &tenant(), tokens);
                world.journal.fail(false);
                match result {
                    Ok(hold) => {
                        let after = world.ledger.view(key);
                        if let Some(limit) = after.limit {
                            assert!(
                                after.consumed + after.reserved <= limit,
                                "seed {seed} step {step}: admitted past the limit: {after:?}"
                            );
                        }
                        world.holds.push((index, hold));
                        world.assert_covered(key, seed, step);
                    }
                    Err(BudgetRefusal::Exhausted { .. }) => {
                        let limit = before.limit.expect("an unlimited key was refused");
                        let held = before.consumed + before.reserved;
                        assert!(
                            held >= limit || held + tokens > limit,
                            "seed {seed} step {step}: a request that fit was refused: \
                             {tokens} against {before:?}"
                        );
                        assert_eq!(world.ledger.view(key), before, "a refusal changed the ledger");
                    }
                    Err(BudgetRefusal::Unavailable) => {
                        assert!(failing, "seed {seed} step {step}");
                        assert_eq!(world.ledger.view(key).reserved, before.reserved);
                    }
                }
            }
            6..=8 if !world.holds.is_empty() => {
                let pick = usize::try_from(rng.below(world.holds.len() as u64)).unwrap();
                let (owner, hold) = world.holds.swap_remove(pick);
                let reserved = hold.tokens();
                let charged = match rng.below(4) {
                    0 => {
                        hold.release();
                        0
                    }
                    1 => hold.retain().charged,
                    // Sometimes above the reservation: an overrun.
                    _ => hold.settle(rng.below(reserved.saturating_mul(2) + 2)).charged,
                };
                let model = world.models.get_mut(owner).unwrap();
                model.charged += charged;
                let view = world.ledger.view(keys.get(owner).unwrap());
                assert!(
                    view.consumed >= model.charged,
                    "seed {seed} step {step}: a charge was forgotten"
                );
                if !*crashed.get(owner).unwrap() {
                    assert_eq!(view.consumed, model.charged, "seed {seed} step {step}");
                }
                world.assert_covered(keys.get(owner).unwrap(), seed, step);
            }
            9 if rng.below(3) == 0 => {
                // Everything in flight is lost with the process, and charged
                // as spent by the restart.
                for (owner, hold) in &world.holds {
                    world.models.get_mut(*owner).unwrap().charged += hold.tokens();
                }
                crashed = [true, true];
                world.crash(seed);
            }
            _ => {}
        }
    }

    // Finish everything still held: exactly once each, so nothing stays
    // reserved and nothing is charged twice.
    for (_, hold) in world.holds.drain(..) {
        hold.release();
    }
    for (index, key) in keys.iter().enumerate() {
        let view = world.ledger.view(key);
        assert_eq!(view.reserved, 0, "seed {seed}: key {index} leaked a reservation");
        assert!(view.consumed >= world.models.get(index).unwrap().charged, "seed {seed}");
    }
    // A clean stop, then a restart, loses nothing and forgives nothing.
    assert_eq!(world.ledger.flush(), 0);
    let before: Vec<_> = keys.iter().map(|key| world.ledger.view(key)).collect();
    world.crash(seed);
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            world.ledger.view(key).consumed,
            before.get(index).unwrap().consumed,
            "seed {seed}: a flushed ledger did not restart exactly"
        );
    }
}

#[test]
fn no_interleaving_admits_past_a_limit_forgets_a_charge_or_applies_a_credit_twice() {
    for seed in 1..=CASES {
        run(seed);
    }
}

#[test]
fn concurrent_callers_cannot_jointly_overspend_a_key() {
    // Specification 12.1: "Reservations are shared by every concurrent
    // request using the key." Eight threads race for a budget that funds
    // exactly twenty of their requests.
    let journal = Arc::new(MemoryJournal::new());
    let ledger = Arc::new(BudgetLedger::new(journal as Arc<dyn BudgetJournal>, 64));
    let key = keys().first().unwrap().clone();
    ledger.set(&key, &tenant(), None, Some(2000), None).unwrap();

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let ledger = Arc::clone(&ledger);
            let key = key.clone();
            std::thread::spawn(move || {
                let mut served = 0_u64;
                for _ in 0..50 {
                    if let Ok(hold) = ledger.reserve(&key, &tenant(), 100) {
                        std::thread::yield_now();
                        hold.settle(100);
                        served += 1;
                    }
                }
                served
            })
        })
        .collect();
    let served: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();

    let view = ledger.view(&key);
    assert_eq!(served, 20, "the budget funded {served} requests of 100 tokens");
    assert_eq!((view.consumed, view.reserved, view.remaining()), (2000, 0, Some(0)));
}
