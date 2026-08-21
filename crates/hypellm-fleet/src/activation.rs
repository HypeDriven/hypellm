//! The activation lifecycle, and the accounting that keeps it honest.
//!
//! ```text
//! Planned → LeaseHeld → Draining → Stopping → [Fetching] → Starting → Probing → Ready
//!                          ↓          ↓           ↓            ↓         ↓
//!                       Failed ←──────┴───────────┴────────────┴─────────┘
//!                          ↓
//!                   RollbackPending → RollbackDone | RollbackFailed
//! ```
//!
//! Every transition is deadline-bounded. Every terminal state releases the
//! lease exactly once.
//!
//! # Why `Drop` is not trusted
//!
//! Appendix B places this obligation on admission reservations — "every
//! reservation is released exactly once on success, error, timeout, and
//! cancellation; `Drop` alone is not trusted for accounting" — and a lease
//! carries the same one for a stronger reason. A leaked reservation costs a
//! slot until the process restarts; a leaked lease pins a host out of service
//! until the lease expires, which is a slow, confusing outage that looks like a
//! capacity problem. [`ActivationLedger`] therefore counts releases and refuses
//! a second one, and there is a conservation property test.

use crate::model::FleetPolicy;
use crate::plan::{Plan, PlanStep};
use crate::state::{Lease, LeaseOperation};
use core::fmt;
use hypellm_core::ids::{DeploymentId, HostId, LeaseId};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Where an activation has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActivationState {
    /// A plan exists; nothing has been asked of the agent.
    Planned,
    /// The durable lease is written and the host slot is held.
    LeaseHeld,
    /// Evicted deployments are finishing their in-flight work.
    Draining,
    /// Evicted deployments are stopping.
    Stopping,
    /// An artifact is being acquired.
    Fetching,
    /// The deployment is starting.
    Starting,
    /// The deployment is started; readiness is being confirmed.
    Probing,
    /// The deployment is serving.
    Ready,
    /// The activation failed.
    Failed,
    /// The eviction succeeded and the activation did not; the evicted set is
    /// being brought back.
    RollbackPending,
    /// The evicted set is back.
    RollbackDone,
    /// The evicted set could not be brought back.
    ///
    /// The fleet is now worse off than when the plan started: something was
    /// stopped and nothing was started. The deployment is quarantined for
    /// operator attention rather than retried, because a rollback storm can
    /// itself become the outage.
    RollbackFailed,
    /// The activation was cancelled before it completed.
    Cancelled,
}

impl ActivationState {
    /// Stable token for traces, audit records, and the activations view.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::LeaseHeld => "lease_held",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::Fetching => "fetching",
            Self::Starting => "starting",
            Self::Probing => "probing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::RollbackPending => "rollback_pending",
            Self::RollbackDone => "rollback_done",
            Self::RollbackFailed => "rollback_failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the activation has finished, however it finished.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Failed
                | Self::RollbackDone
                | Self::RollbackFailed
                | Self::Cancelled
        )
    }

    /// Whether `next` is a permitted successor.
    ///
    /// Exhaustive by construction. An invalid transition is an internal fault
    /// that closes safely rather than a state the machine quietly adopts —
    /// specification 18.2 forbids panicking on it, and adopting it would mean
    /// the router's belief about what it asked for had diverged from what it
    /// asked for.
    #[must_use]
    pub const fn may_transition_to(self, next: Self) -> bool {
        match (self, next) {
            // Any non-terminal state may fail or be cancelled.
            (s, Self::Failed | Self::Cancelled) if !s.is_terminal() => true,
            (Self::Planned, Self::LeaseHeld) => true,
            (
                Self::LeaseHeld,
                Self::Draining | Self::Stopping | Self::Fetching | Self::Starting,
            ) => true,
            (Self::Draining, Self::Stopping) => true,
            (Self::Stopping, Self::Fetching | Self::Starting) => true,
            (Self::Fetching, Self::Starting) => true,
            (Self::Starting, Self::Probing) => true,
            (Self::Probing, Self::Ready) => true,
            // Rollback is reachable only from a failure that already evicted.
            (Self::Failed, Self::RollbackPending) => true,
            (Self::RollbackPending, Self::RollbackDone | Self::RollbackFailed) => true,
            _ => false,
        }
    }

    /// Every state, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Planned,
            Self::LeaseHeld,
            Self::Draining,
            Self::Stopping,
            Self::Fetching,
            Self::Starting,
            Self::Probing,
            Self::Ready,
            Self::Failed,
            Self::RollbackPending,
            Self::RollbackDone,
            Self::RollbackFailed,
            Self::Cancelled,
        ]
    }
}

impl fmt::Display for ActivationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an activation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// The deployment became ready.
    Succeeded,
    /// It did not, and nothing had been evicted.
    Failed,
    /// It did not, and the evicted set was restored.
    FailedAndRolledBack,
    /// It did not, and the evicted set could not be restored.
    FailedAndQuarantined,
    /// It was cancelled.
    Cancelled,
}

impl ActivationOutcome {
    /// Stable token for the `outcome` metric label and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::FailedAndRolledBack => "rolled_back",
            Self::FailedAndQuarantined => "quarantined",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One activation, from plan to terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationRecord {
    /// The lease authorising it.
    pub lease: Lease,
    /// The host whose slot and budget it holds.
    pub host: HostId,
    /// Where it has got to.
    pub state: ActivationState,
    /// Deployments the plan evicted, in the order it evicted them.
    pub evicted: Vec<DeploymentId>,
    /// When it started, on the router's monotonic clock.
    pub started_ms: u64,
    /// When it reached a terminal state.
    pub finished_ms: Option<u64>,
    /// How it ended.
    pub outcome: Option<ActivationOutcome>,
    /// A bounded, router-authored explanation.
    ///
    /// Never agent-supplied text: the agent is trusted to actuate, not to
    /// author strings the router will store and echo into an operator's
    /// browser.
    pub detail: &'static str,
}

impl ActivationRecord {
    /// Begin an activation from a plan.
    #[must_use]
    pub fn from_plan(plan: &Plan, lease: Lease, now_ms: u64) -> Self {
        Self {
            lease,
            host: plan.host.clone(),
            state: ActivationState::Planned,
            evicted: plan
                .steps
                .iter()
                .filter_map(|s| match s {
                    PlanStep::Evict(d) => Some(d.clone()),
                    _ => None,
                })
                .collect(),
            started_ms: now_ms,
            finished_ms: None,
            outcome: None,
            detail: "",
        }
    }

    /// How long the activation took, or has taken so far.
    #[must_use]
    pub fn duration_ms(&self, now_ms: u64) -> u64 {
        self.finished_ms
            .unwrap_or(now_ms)
            .saturating_sub(self.started_ms)
    }

    /// Whether a rollback is owed: something was stopped and nothing started.
    #[must_use]
    pub fn owes_rollback(&self) -> bool {
        self.state == ActivationState::Failed && !self.evicted.is_empty()
    }
}

/// Why a lease release was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRelease {
    /// The lease was held and is now released.
    Released,
    /// The lease was already released. The caller must not act again.
    ///
    /// Returned rather than panicking, and rather than silently succeeding:
    /// releasing twice would return a host slot that a *different* activation
    /// now holds, which is how two plans come to run on one accelerator.
    AlreadyReleased,
    /// No such lease was ever held here.
    Unknown,
}

/// The router's in-memory record of what it holds.
///
/// The durable log is the authority across restarts; this is the authority
/// within one process, and the place the exactly-once obligation is enforced.
#[derive(Debug, Default)]
pub struct ActivationLedger {
    inner: RwLock<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    /// Active leases, by identifier.
    active: BTreeMap<LeaseId, ActivationRecord>,
    /// Leases already released, so a second release can be refused rather than
    /// mistaken for a first.
    released: BTreeMap<LeaseId, ActivationOutcome>,
    /// Host slots currently held.
    slots: BTreeMap<HostId, u32>,
    /// Bounded history, newest last, for the "why was this evicted" view.
    history: Vec<ActivationRecord>,
    /// Total acquisitions and releases, for the conservation property.
    acquired: u64,
    releases: u64,
}

/// How many finished activations are retained for the management view.
///
/// Bounded like every other request-influenced structure. Older entries are in
/// the durable log, which is where an operator looks for anything beyond the
/// recent past.
pub const MAX_HISTORY: usize = 256;

impl ActivationLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a host slot and record the activation.
    ///
    /// Returns `false` when the host is already at
    /// `max_concurrent_activations`, in which case nothing is recorded and the
    /// caller must not send a mutating verb.
    pub fn acquire(&self, record: ActivationRecord, max_concurrent: u32) -> bool {
        let Ok(mut state) = self.inner.write() else {
            return false;
        };
        let held = state.slots.get(&record.host).copied().unwrap_or(0);
        if held >= max_concurrent.max(1) {
            return false;
        }
        if state.active.contains_key(&record.lease.id)
            || state.released.contains_key(&record.lease.id)
        {
            // Idempotent per lease, in the ledger as at the agent. A repeat is
            // not an acquisition.
            return false;
        }
        state.slots.insert(record.host.clone(), held.saturating_add(1));
        state.acquired = state.acquired.saturating_add(1);
        state.active.insert(record.lease.id.clone(), record);
        true
    }

    /// Advance an activation, refusing an invalid transition.
    ///
    /// Returns `false` when the transition is not permitted; the caller closes
    /// the activation safely rather than adopting the state.
    pub fn transition(&self, lease: &LeaseId, next: ActivationState) -> bool {
        let Ok(mut state) = self.inner.write() else {
            return false;
        };
        let Some(record) = state.active.get_mut(lease) else {
            return false;
        };
        if !record.state.may_transition_to(next) {
            return false;
        }
        record.state = next;
        true
    }

    /// Release a lease exactly once.
    pub fn release(
        &self,
        lease: &LeaseId,
        outcome: ActivationOutcome,
        detail: &'static str,
        now_ms: u64,
    ) -> LeaseRelease {
        let Ok(mut state) = self.inner.write() else {
            return LeaseRelease::Unknown;
        };
        if state.released.contains_key(lease) {
            return LeaseRelease::AlreadyReleased;
        }
        let Some(mut record) = state.active.remove(lease) else {
            return LeaseRelease::Unknown;
        };
        let held = state.slots.get(&record.host).copied().unwrap_or(0);
        state
            .slots
            .insert(record.host.clone(), held.saturating_sub(1));

        record.finished_ms = Some(now_ms);
        record.outcome = Some(outcome);
        record.detail = detail;
        state.released.insert(lease.clone(), outcome);
        state.releases = state.releases.saturating_add(1);
        state.history.push(record);
        // Bounded: `MAX_HISTORY` entries, oldest dropped first.
        let overflow = state.history.len().saturating_sub(MAX_HISTORY);
        if overflow > 0 {
            state.history.drain(0..overflow);
        }
        LeaseRelease::Released
    }

    /// Whether a lease is currently held.
    #[must_use]
    pub fn is_active(&self, lease: &LeaseId) -> bool {
        self.inner
            .read()
            .is_ok_and(|s| s.active.contains_key(lease))
    }

    /// The state of a held lease.
    #[must_use]
    pub fn state_of(&self, lease: &LeaseId) -> Option<ActivationState> {
        self.inner
            .read()
            .ok()
            .and_then(|s| s.active.get(lease).map(|r| r.state))
    }

    /// Activations currently in flight.
    #[must_use]
    pub fn active(&self) -> Vec<ActivationRecord> {
        self.inner
            .read()
            .map(|s| s.active.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Slots held on a host.
    #[must_use]
    pub fn slots_held(&self, host: &HostId) -> u32 {
        self.inner
            .read()
            .ok()
            .and_then(|s| s.slots.get(host).copied())
            .unwrap_or(0)
    }

    /// Finished activations, newest last.
    #[must_use]
    pub fn history(&self) -> Vec<ActivationRecord> {
        self.inner
            .read()
            .map(|s| s.history.clone())
            .unwrap_or_default()
    }

    /// Leases the router holds, for the planner's snapshot.
    #[must_use]
    pub fn leases_by_deployment(&self) -> BTreeMap<DeploymentId, Lease> {
        self.inner
            .read()
            .map(|s| {
                s.active
                    .values()
                    .map(|r| (r.lease.deployment.clone(), r.lease.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Leases whose expiry has passed.
    ///
    /// A lease that outlives its expiry is not evidence that the work is still
    /// running; it is evidence that whatever was supposed to report back did
    /// not. The caller releases it, audits it, and re-plans from observation.
    #[must_use]
    pub fn expired(&self, now_ms: u64) -> Vec<LeaseId> {
        self.inner
            .read()
            .map(|s| {
                s.active
                    .values()
                    .filter(|r| now_ms >= r.lease.expires_ms)
                    .map(|r| r.lease.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Acquisitions and releases, for the conservation property.
    ///
    /// Exposed rather than inferred from `active`, because the property being
    /// asserted is that the two counts converge — which a test cannot check by
    /// looking at the same map the code maintains.
    #[must_use]
    pub fn accounting(&self) -> (u64, u64) {
        self.inner
            .read()
            .map(|s| (s.acquired, s.releases))
            .unwrap_or((0, 0))
    }
}

/// How long a lease lives before it is presumed lost.
///
/// The plan's own estimate, generously multiplied, and floored so that a
/// fast-starting deployment still gets a workable window. A lease that expires
/// while its activation is genuinely still running is recoverable — the router
/// re-queries `STATUS` and reconciles — while one that never expires is not.
#[must_use]
pub fn lease_expiry_ms(plan: &Plan, policy: &FleetPolicy, now_ms: u64) -> u64 {
    let _ = policy;
    /// Minimum lease lifetime.
    const FLOOR_MS: u64 = 120_000;
    /// Headroom over the plan's own estimate.
    const FACTOR: u64 = 3;
    now_ms.saturating_add(plan.eta_ms.saturating_mul(FACTOR).max(FLOOR_MS))
}

/// Build the durable lease record for a plan.
#[must_use]
pub fn lease_for(
    plan: &Plan,
    id: LeaseId,
    decision_id: String,
    policy: &FleetPolicy,
    now_ms: u64,
) -> Lease {
    Lease {
        id,
        deployment: plan.deployment.clone(),
        operation: LeaseOperation::Activate,
        issued_ms: now_ms,
        expires_ms: lease_expiry_ms(plan, policy, now_ms),
        decision_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{PlanTrace, PlanStep};

    fn lease(id: &str) -> Lease {
        Lease {
            id: LeaseId::new(id).expect("lease id"),
            deployment: DeploymentId::new("spark-music3").expect("deployment id"),
            operation: LeaseOperation::Activate,
            issued_ms: 0,
            expires_ms: 100_000,
            decision_id: String::new(),
        }
    }

    fn plan() -> Plan {
        Plan {
            deployment: DeploymentId::new("spark-music3").expect("id"),
            host: HostId::new("spark").expect("id"),
            steps: vec![
                PlanStep::Evict(DeploymentId::new("spark-h3").expect("id")),
                PlanStep::Activate(DeploymentId::new("spark-music3").expect("id")),
            ],
            eta_ms: 235_000,
            trace: PlanTrace::default(),
        }
    }

    fn record(id: &str) -> ActivationRecord {
        ActivationRecord::from_plan(&plan(), lease(id), 0)
    }

    #[test]
    fn a_lease_is_released_exactly_once() {
        let ledger = ActivationLedger::new();
        assert!(ledger.acquire(record("l1"), 1));
        assert_eq!(
            ledger.release(
                &LeaseId::new("l1").expect("id"),
                ActivationOutcome::Succeeded,
                "ready",
                1_000
            ),
            LeaseRelease::Released
        );
        assert_eq!(
            ledger.release(
                &LeaseId::new("l1").expect("id"),
                ActivationOutcome::Succeeded,
                "ready",
                1_000
            ),
            LeaseRelease::AlreadyReleased,
            "a second release would return a slot a different activation now holds"
        );
        let (acquired, released) = ledger.accounting();
        assert_eq!(acquired, 1);
        assert_eq!(released, 1);
    }

    #[test]
    fn a_released_lease_returns_its_host_slot_and_no_more() {
        let ledger = ActivationLedger::new();
        let host = HostId::new("spark").expect("id");
        assert!(ledger.acquire(record("l1"), 1));
        assert_eq!(ledger.slots_held(&host), 1);
        // The host is at its concurrency limit, so a second plan is refused.
        assert!(!ledger.acquire(record("l2"), 1));
        assert_eq!(ledger.slots_held(&host), 1);

        ledger.release(
            &LeaseId::new("l1").expect("id"),
            ActivationOutcome::Failed,
            "start failed",
            1,
        );
        assert_eq!(ledger.slots_held(&host), 0);
        ledger.release(
            &LeaseId::new("l1").expect("id"),
            ActivationOutcome::Failed,
            "start failed",
            2,
        );
        assert_eq!(
            ledger.slots_held(&host),
            0,
            "a double release must not drive the slot count below zero"
        );
    }

    #[test]
    fn re_issuing_the_same_lease_is_not_a_second_acquisition() {
        // Idempotency per lease is what makes crash recovery tractable: the
        // router re-sends a verb after a restart and must not thereby take a
        // second slot.
        let ledger = ActivationLedger::new();
        assert!(ledger.acquire(record("l1"), 4));
        assert!(!ledger.acquire(record("l1"), 4));
        assert_eq!(ledger.slots_held(&HostId::new("spark").expect("id")), 1);
    }

    #[test]
    fn an_invalid_transition_is_refused_rather_than_adopted() {
        let ledger = ActivationLedger::new();
        assert!(ledger.acquire(record("l1"), 1));
        let id = LeaseId::new("l1").expect("id");
        assert!(ledger.transition(&id, ActivationState::LeaseHeld));
        assert!(
            !ledger.transition(&id, ActivationState::Ready),
            "lease_held does not lead directly to ready"
        );
        assert_eq!(ledger.state_of(&id), Some(ActivationState::LeaseHeld));
    }

    #[test]
    fn every_non_terminal_state_can_fail_and_no_terminal_state_can() {
        for state in ActivationState::all() {
            if state.is_terminal() {
                assert!(
                    !state.may_transition_to(ActivationState::Failed),
                    "{state} is terminal and must not fail again"
                );
            } else {
                assert!(
                    state.may_transition_to(ActivationState::Failed),
                    "{state} must be able to fail"
                );
                assert!(
                    state.may_transition_to(ActivationState::Cancelled),
                    "{state} must be able to be cancelled"
                );
            }
        }
    }

    #[test]
    fn a_failure_after_eviction_owes_a_rollback_and_one_before_it_does_not() {
        // The distinction that matters: a plan that stopped something and then
        // failed has left the fleet worse than it found it.
        let mut with_eviction = record("l1");
        with_eviction.state = ActivationState::Failed;
        assert!(with_eviction.owes_rollback());

        let mut without = record("l2");
        without.evicted.clear();
        without.state = ActivationState::Failed;
        assert!(!without.owes_rollback());
    }

    #[test]
    fn history_is_bounded() {
        let ledger = ActivationLedger::new();
        for i in 0..(MAX_HISTORY + 50) {
            let id = format!("l{i}");
            let mut r = record(&id);
            r.lease.id = LeaseId::new(&id).expect("id");
            assert!(ledger.acquire(r, u32::MAX));
            ledger.release(
                &LeaseId::new(&id).expect("id"),
                ActivationOutcome::Succeeded,
                "ready",
                u64::try_from(i).unwrap_or(0),
            );
        }
        assert_eq!(ledger.history().len(), MAX_HISTORY);
    }

    #[test]
    fn an_expired_lease_is_reported_so_it_can_be_released() {
        let ledger = ActivationLedger::new();
        assert!(ledger.acquire(record("l1"), 1));
        assert!(ledger.expired(99_999).is_empty());
        assert_eq!(ledger.expired(100_000).len(), 1);
    }
}
