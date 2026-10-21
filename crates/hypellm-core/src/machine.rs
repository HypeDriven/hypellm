//! Machine memory: work that shares one physical machine waits for memory.
//!
//! Concurrency scopes count requests, and a target's slot says nothing about
//! the other targets on the same box. A DGX Spark serving a resident Qwen, a
//! MiniMax-H3 and a YuE2 has one pool of unified memory between them: an H3
//! job needs ~70 GiB while it renders, a YuE2 job ~24 GiB, and starting both
//! beside Qwen fails in the driver (`NV_ERR_NO_MEMORY`) rather than in the
//! router. A [`MachineLedger`] is that pool: each target on the machine
//! declares what one request or job holds while it runs, and work starts only
//! when what is held plus what it needs fits.
//!
//! # Order
//!
//! Work that does not fit leaves a [`claim`](MachineLedger::claim), and a claim
//! ranks by `(class, arrival)`. A newcomer is refused while any claim outranks
//! it, even if it would fit, so a waiting YuE2 job (standard) is not starved by
//! a stream of H3 jobs (batch) each of which fits in what YuE2 is waiting for.
//! Work that needs no memory is never refused: a chat request to a resident
//! model holds nothing and delays nobody.
//!
//! # Claims are leases
//!
//! A job does not wait here — it waits in the job queue (specification 26.10)
//! and comes back on its next pass — so its claim must outlive the pass that
//! made it. Each refused pass renews it; a claim not renewed within
//! [`CLAIM_TTL_MS`] lapses. That makes a forgotten claim self-healing: a job
//! cancelled while waiting stops renewing, and the work it was blocking is
//! held up for one lease at most, never indefinitely. The arrival order is kept
//! across renewals, so a renewing claim keeps its place in line.
//!
//! # Accounting
//!
//! A [`MachineHold`] returns its memory exactly once, on
//! [`MachineHold::release`] or on `Drop`, like an admission reservation.
//! Reconfiguring a ledger's capacity keeps everything held: lowering it below
//! what is in use cancels nothing, it only refuses new work until enough ends.

use crate::admission::PriorityClass;
use crate::ids::TargetId;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// How long a claim lasts without being renewed.
///
/// A blocked job is retried every job-queue tick (250 ms) while a worker is
/// free; a minute is room for every worker being busy for a while without a
/// waiting job losing its place.
pub const CLAIM_TTL_MS: u64 = 60_000;

/// How often a waiting request renews its claim: well inside the lease.
const RENEW_EVERY_MS: u64 = 30_000;

/// Refused: the memory is not free, or work of a higher class waits for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// The most claims one machine keeps. A claim past it is not recorded — the
/// work is still refused and still retried, it just has no place in line.
pub const MAX_CLAIMS: usize = 256;

/// One piece of work waiting for memory.
#[derive(Debug, Clone)]
struct Claim {
    key: String,
    class: PriorityClass,
    seq: u64,
    bytes: u64,
    since_ms: u64,
    expires_ms: u64,
}

#[derive(Debug, Default)]
struct LedgerState {
    capacity_bytes: u64,
    held_bytes: u64,
    /// What each target holds now: (holds, bytes).
    holders: BTreeMap<TargetId, (u32, u64)>,
    claims: Vec<Claim>,
    next_seq: u64,
    acquired: u64,
    released: u64,
    /// Bumped on every change a waiter could be waiting for, so a waiter that
    /// was refused just before a release does not sleep through it.
    changes: u64,
}

impl LedgerState {
    fn expire(&mut self, now_ms: u64) -> bool {
        let before = self.claims.len();
        self.claims.retain(|c| c.expires_ms > now_ms);
        let expired = self.claims.len() != before;
        if expired {
            self.changed();
        }
        expired
    }

    fn changed(&mut self) {
        self.changes = self.changes.wrapping_add(1);
    }

    /// Whether a claim other than `key` outranks `(class, seq)`.
    ///
    /// A claim that cannot fit even on an empty machine — capacity was lowered
    /// under it — blocks nobody: it would hold the line until it lapsed.
    fn outranked(&self, class: PriorityClass, seq: u64, key: Option<&str>) -> bool {
        self.claims.iter().any(|c| {
            Some(c.key.as_str()) != key
                && c.bytes <= self.capacity_bytes
                && (c.class, c.seq) < (class, seq)
        })
    }
}

/// The memory of one machine, shared by every target on it.
#[derive(Debug)]
pub struct MachineLedger {
    /// `machine:<id>`, for traces and rejections.
    pub name: String,
    state: Mutex<LedgerState>,
    /// Signalled when memory is returned or a claim leaves.
    freed: Condvar,
}

/// What a ledger looks like right now, for the management API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineView {
    /// The configured capacity.
    pub capacity_bytes: u64,
    /// Held by running work.
    pub held_bytes: u64,
    /// Per target: how many holds and how many bytes.
    pub holders: Vec<(TargetId, u32, u64)>,
    /// Waiting work, in the order it will be admitted.
    pub waiting: Vec<WaitingView>,
}

/// One claim, as the management API shows it. The key is not shown: it is a
/// request or job identifier, which is the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingView {
    /// The class it waits in.
    pub class: PriorityClass,
    /// What it needs.
    pub bytes: u64,
    /// How long it has waited, in milliseconds.
    pub waited_ms: u64,
}

impl MachineLedger {
    /// A ledger for machine `id` with `capacity_bytes` to share.
    #[must_use]
    pub fn new(id: &str, capacity_bytes: u64) -> Self {
        Self {
            name: format!("machine:{id}"),
            state: Mutex::new(LedgerState {
                capacity_bytes,
                ..LedgerState::default()
            }),
            freed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, LedgerState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Change the capacity, keeping everything held and waiting.
    pub fn reconfigure(&self, capacity_bytes: u64) {
        let mut state = self.lock();
        state.capacity_bytes = capacity_bytes;
        state.changed();
        drop(state);
        self.freed.notify_all();
    }

    /// The configured capacity.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.lock().capacity_bytes
    }

    /// Bytes held by running work.
    #[must_use]
    pub fn held_bytes(&self) -> u64 {
        self.lock().held_bytes
    }

    /// Total holds taken and returned, which must be equal once idle.
    #[must_use]
    pub fn conservation(&self) -> (u64, u64) {
        let state = self.lock();
        (state.acquired, state.released)
    }

    /// Take `bytes` for `target`, as the holder of claim `key` if it has one.
    ///
    /// Refused when it does not fit, or when another claim outranks it. A
    /// successful hold consumes the caller's claim. Zero bytes always succeed.
    ///
    /// # Errors
    ///
    /// [`Refused`]; the caller reports which ledger refused it.
    pub fn try_hold(
        self: &Arc<Self>,
        target: &TargetId,
        bytes: u64,
        class: PriorityClass,
        key: Option<&str>,
        now_ms: u64,
    ) -> Result<MachineHold, Refused> {
        let mut state = self.lock();
        let expired = state.expire(now_ms);
        if bytes > 0 {
            let seq = key
                .and_then(|k| state.claims.iter().find(|c| c.key == k))
                .map_or(u64::MAX, |c| c.seq);
            let fits = state
                .held_bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= state.capacity_bytes);
            if !fits || state.outranked(class, seq, key) {
                drop(state);
                if expired {
                    self.freed.notify_all();
                }
                return Err(Refused);
            }
            state.held_bytes = state.held_bytes.saturating_add(bytes);
            let entry = state.holders.entry(target.clone()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(bytes);
        }
        let consumed = key.is_some_and(|k| {
            let before = state.claims.len();
            state.claims.retain(|c| c.key != k);
            state.claims.len() != before
        });
        if consumed {
            state.changed();
        }
        state.acquired = state.acquired.saturating_add(1);
        drop(state);
        if expired || consumed {
            self.freed.notify_all();
        }
        Ok(MachineHold {
            ledger: Arc::clone(self),
            target: target.clone(),
            bytes,
            released: AtomicBool::new(false),
        })
    }

    /// Record, or renew, `key`'s place in line for `bytes`.
    ///
    /// A renewal keeps the original arrival, and takes the class and size the
    /// caller has now. Returns whether the claim is held.
    pub fn claim(&self, key: &str, class: PriorityClass, bytes: u64, now_ms: u64) -> bool {
        if bytes == 0 {
            return false;
        }
        let mut state = self.lock();
        state.expire(now_ms);
        let expires_ms = now_ms.saturating_add(CLAIM_TTL_MS);
        if let Some(claim) = state.claims.iter_mut().find(|c| c.key == key) {
            claim.class = class;
            claim.bytes = bytes;
            claim.expires_ms = expires_ms;
            return true;
        }
        if state.claims.len() >= MAX_CLAIMS {
            return false;
        }
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        state.claims.push(Claim {
            key: key.to_owned(),
            class,
            seq,
            bytes,
            since_ms: now_ms,
            expires_ms,
        });
        true
    }

    /// Give up `key`'s place in line, if it has one.
    pub fn drop_claim(&self, key: &str) {
        let mut state = self.lock();
        let before = state.claims.len();
        state.claims.retain(|c| c.key != key);
        let changed = state.claims.len() != before;
        if changed {
            state.changed();
        }
        drop(state);
        if changed {
            self.freed.notify_all();
        }
    }

    /// Hold `bytes`, waiting up to `budget` in line as `key`.
    ///
    /// For a request that holds its connection. The claim is renewed while it
    /// waits and dropped on every exit, so a request that gives up leaves no
    /// place behind. `now` reads the monotonic clock.
    ///
    /// # Errors
    ///
    /// [`Refused`] when the budget ran out first.
    pub fn hold_waiting(
        self: &Arc<Self>,
        target: &TargetId,
        bytes: u64,
        class: PriorityClass,
        key: &str,
        budget: std::time::Duration,
        now: &dyn Fn() -> u64,
    ) -> Result<MachineHold, Refused> {
        let started = std::time::Instant::now();
        loop {
            let seen = self.lock().changes;
            if let Ok(hold) = self.try_hold(target, bytes, class, Some(key), now()) {
                return Ok(hold);
            }
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() || !self.claim(key, class, bytes, now()) {
                self.drop_claim(key);
                return Err(Refused);
            }
            // Bounded by the lease, so a long budget still renews the claim.
            let slice = remaining.min(std::time::Duration::from_millis(RENEW_EVERY_MS));
            let state = self.lock();
            if state.changes != seen {
                continue;
            }
            let _ = match self.freed.wait_timeout(state, slice) {
                Ok(pair) => pair,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    /// What the ledger holds and who is waiting, waiters in admission order.
    #[must_use]
    pub fn view(&self, now_ms: u64) -> MachineView {
        let mut state = self.lock();
        state.expire(now_ms);
        let mut claims = state.claims.clone();
        claims.sort_by_key(|c| (c.class, c.seq));
        MachineView {
            capacity_bytes: state.capacity_bytes,
            held_bytes: state.held_bytes,
            holders: state
                .holders
                .iter()
                .map(|(t, (n, b))| (t.clone(), *n, *b))
                .collect(),
            waiting: claims
                .iter()
                .map(|c| WaitingView {
                    class: c.class,
                    bytes: c.bytes,
                    waited_ms: now_ms.saturating_sub(c.since_ms),
                })
                .collect(),
        }
    }

    fn give_back(&self, target: &TargetId, bytes: u64) {
        let mut state = self.lock();
        state.held_bytes = state.held_bytes.saturating_sub(bytes);
        if bytes > 0 {
            let empty = state.holders.get_mut(target).is_some_and(|entry| {
                entry.0 = entry.0.saturating_sub(1);
                entry.1 = entry.1.saturating_sub(bytes);
                entry.0 == 0
            });
            if empty {
                state.holders.remove(target);
            }
        }
        state.released = state.released.saturating_add(1);
        state.changed();
        drop(state);
        self.freed.notify_all();
    }
}

/// Memory held on a machine, returned exactly once.
#[derive(Debug)]
pub struct MachineHold {
    ledger: Arc<MachineLedger>,
    target: TargetId,
    bytes: u64,
    released: AtomicBool,
}

impl MachineHold {
    /// What this hold took.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Return the memory. Idempotent; `Drop` calls it too.
    pub fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            self.ledger.give_back(&self.target, self.bytes);
        }
    }
}

impl Drop for MachineHold {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn target(name: &str) -> TargetId {
        TargetId::new(name).unwrap_or_else(|_| unreachable!())
    }

    fn spark() -> Arc<MachineLedger> {
        Arc::new(MachineLedger::new("spark", 64 * GIB))
    }

    #[test]
    fn work_that_does_not_fit_is_refused_until_memory_is_returned() {
        let ledger = spark();
        let h3 = ledger.try_hold(&target("h3"), 50 * GIB, PriorityClass::Batch, None, 0);
        assert!(h3.is_ok());
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, None, 0)
            .is_err());
        drop(h3);
        assert_eq!(ledger.held_bytes(), 0);
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, None, 0)
            .is_ok());
    }

    #[test]
    fn a_waiting_higher_class_claim_refuses_a_lower_newcomer_that_would_fit() {
        let ledger = spark();
        let running = ledger.try_hold(&target("h3"), 50 * GIB, PriorityClass::Batch, None, 0);
        assert!(running.is_ok());
        // YuE needs 24 and only 14 is free: it waits, with a claim.
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, Some("yue-1"), 0)
            .is_err());
        assert!(ledger.claim("yue-1", PriorityClass::Standard, 24 * GIB, 0));
        // A small batch job would fit in the 14 free, and is still refused.
        assert!(ledger
            .try_hold(&target("h3"), 10 * GIB, PriorityClass::Batch, Some("h3-2"), 0)
            .is_err());
        drop(running);
        // Memory is back: the batch job is still behind YuE, and YuE goes first.
        assert!(ledger
            .try_hold(&target("h3"), 10 * GIB, PriorityClass::Batch, Some("h3-2"), 1)
            .is_err());
        let yue = ledger.try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, Some("yue-1"), 1);
        assert!(yue.is_ok());
        // Its claim was consumed, so the batch job now fits behind it.
        assert!(ledger
            .try_hold(&target("h3"), 10 * GIB, PriorityClass::Batch, Some("h3-2"), 2)
            .is_ok());
    }

    #[test]
    fn a_lower_class_claim_does_not_hold_back_a_higher_newcomer() {
        let ledger = spark();
        assert!(ledger.claim("h3-1", PriorityClass::Batch, 60 * GIB, 0));
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, None, 0)
            .is_ok());
    }

    #[test]
    fn within_a_class_the_earlier_claim_goes_first() {
        let ledger = spark();
        assert!(ledger.claim("first", PriorityClass::Standard, 24 * GIB, 0));
        assert!(ledger.claim("second", PriorityClass::Standard, 24 * GIB, 0));
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, Some("second"), 0)
            .is_err());
        // Renewing does not move a claim to the back.
        assert!(ledger.claim("first", PriorityClass::Standard, 24 * GIB, 10));
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, Some("first"), 10)
            .is_ok());
    }

    #[test]
    fn work_that_needs_no_memory_is_never_refused() {
        let ledger = spark();
        let full = ledger.try_hold(&target("h3"), 64 * GIB, PriorityClass::Batch, None, 0);
        assert!(full.is_ok());
        assert!(ledger.claim("yue-1", PriorityClass::Interactive, 24 * GIB, 0));
        let chat = ledger.try_hold(&target("qwen"), 0, PriorityClass::Batch, None, 0);
        assert!(chat.is_ok());
        assert_eq!(ledger.held_bytes(), 64 * GIB);
    }

    #[test]
    fn an_unrenewed_claim_lapses_and_stops_blocking() {
        let ledger = spark();
        assert!(ledger.claim("cancelled", PriorityClass::Interactive, 24 * GIB, 0));
        assert!(ledger
            .try_hold(&target("h3"), 10 * GIB, PriorityClass::Batch, None, CLAIM_TTL_MS - 1)
            .is_err());
        assert!(ledger
            .try_hold(&target("h3"), 10 * GIB, PriorityClass::Batch, None, CLAIM_TTL_MS)
            .is_ok());
        assert!(ledger.view(CLAIM_TTL_MS).waiting.is_empty());
    }

    #[test]
    fn a_claim_that_can_no_longer_fit_blocks_nobody() {
        let ledger = spark();
        assert!(ledger.claim("big", PriorityClass::Interactive, 60 * GIB, 0));
        ledger.reconfigure(32 * GIB);
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Batch, None, 0)
            .is_ok());
    }

    #[test]
    fn every_hold_is_returned_exactly_once() {
        let ledger = spark();
        let hold = ledger.try_hold(&target("yue"), 24 * GIB, PriorityClass::Standard, None, 0);
        let Ok(hold) = hold else { unreachable!() };
        hold.release();
        hold.release();
        drop(hold);
        assert_eq!(ledger.held_bytes(), 0);
        assert_eq!(ledger.conservation(), (1, 1));
        assert!(ledger.view(0).holders.is_empty());
    }

    #[test]
    fn lowering_capacity_keeps_what_is_held_and_refuses_until_it_fits() {
        let ledger = spark();
        let hold = ledger.try_hold(&target("h3"), 50 * GIB, PriorityClass::Batch, None, 0);
        assert!(hold.is_ok());
        ledger.reconfigure(40 * GIB);
        assert_eq!(ledger.held_bytes(), 50 * GIB);
        assert!(ledger
            .try_hold(&target("yue"), GIB, PriorityClass::Interactive, None, 0)
            .is_err());
        drop(hold);
        assert!(ledger
            .try_hold(&target("yue"), 24 * GIB, PriorityClass::Interactive, None, 0)
            .is_ok());
    }

    #[test]
    fn a_waiting_request_is_admitted_when_memory_is_returned_and_leaves_no_claim() {
        let ledger = spark();
        let Ok(running) = ledger.try_hold(&target("h3"), 50 * GIB, PriorityClass::Batch, None, 0)
        else {
            unreachable!()
        };
        let waiter = {
            let ledger = Arc::clone(&ledger);
            std::thread::spawn(move || {
                ledger
                    .hold_waiting(
                        &target("yue"),
                        24 * GIB,
                        PriorityClass::Standard,
                        "req-1",
                        std::time::Duration::from_secs(10),
                        &|| 0,
                    )
                    .map(|hold| hold.bytes())
            })
        };
        while ledger.view(0).waiting.is_empty() {
            std::thread::yield_now();
        }
        running.release();
        assert_eq!(waiter.join().ok(), Some(Ok(24 * GIB)));
        assert!(ledger.view(0).waiting.is_empty());
        assert_eq!(ledger.held_bytes(), 0);
    }

    #[test]
    fn a_request_that_gives_up_leaves_no_claim_behind() {
        let ledger = spark();
        let held = ledger.try_hold(&target("h3"), 64 * GIB, PriorityClass::Batch, None, 0);
        assert!(held.is_ok());
        let outcome = ledger.hold_waiting(
            &target("yue"),
            24 * GIB,
            PriorityClass::Interactive,
            "req-1",
            std::time::Duration::from_millis(20),
            &|| 0,
        );
        assert!(outcome.is_err());
        assert!(ledger.view(0).waiting.is_empty());
    }
}
