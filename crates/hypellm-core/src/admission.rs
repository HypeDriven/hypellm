//! Admission control: hierarchical token buckets and concurrency semaphores.
//!
//! Specification 12: "Admission uses hierarchical token buckets and concurrency
//! semaphores with atomic reservation."
//!
//! Appendix B states two invariants that this module exists to guarantee:
//!
//! > Every successful selection owns an admission reservation before outbound I/O.
//! >
//! > Every reservation is released exactly once on all success, error, timeout,
//! > and cancellation paths.
//!
//! The second is enforced structurally. [`Reservation`] releases on `Drop`, and
//! [`Reservation::commit`] releases early with reconciled usage; a flag makes
//! the second release a no-op. Specification 18.2 adds that "Drop alone is not
//! relied upon for accounting correctness" — so the accounting numbers come
//! from `commit`, and `Drop` is the safety net that keeps *capacity* correct
//! even on a path that forgot to commit.
//!
//! Acquisition across the scope hierarchy is all-or-nothing: if the tenant
//! admits a request but the target does not, the tenant's reservation is rolled
//! back before returning. A partial acquisition would leak capacity on every
//! rejection, and a busy router rejects a great deal.

use crate::decision::ExclusionReason;
use crate::canonical::Operation;
use crate::ids::{AliasId, PrincipalId, TargetId, TenantId};
use crate::machine::{MachineHold, MachineLedger, MachineView};
use crate::time::Clock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

/// Limits for one admission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeLimits {
    /// Maximum simultaneous in-flight requests. Zero means unlimited.
    pub max_concurrency: u32,
    /// Maximum requests waiting for capacity. Zero means no queue.
    pub max_queued: u32,
    /// Sustained request rate. Zero means unlimited.
    pub requests_per_second: u32,
    /// Burst allowance for the request bucket, in requests.
    pub request_burst: u32,
    /// Sustained token rate per minute. Zero means unlimited.
    pub tokens_per_minute: u64,
    /// Burst allowance for the token bucket, in tokens.
    pub token_burst: u64,
    /// Spend ceiling for one budget period, in minor currency units. Zero means
    /// no budget.
    ///
    /// Specification 12 gives the tenant layer a "daily/monthly budget class",
    /// and specification 11.1 lists "budget limits" among what a `quota`
    /// carries. The figure is in the same minor units as the price schedule
    /// (`DI-048`), because a budget expressed in anything else would need a
    /// conversion the router has no source for.
    pub budget_minor_units: u64,
    /// The period the budget resets over.
    pub budget_period: BudgetPeriod,
}

/// How often a spend budget resets.
///
/// Fixed-length rolling windows rather than calendar periods. A calendar month
/// needs date arithmetic — leap years, month lengths, the operator's timezone —
/// and the workspace has no date library and may not acquire one
/// (specification 4). A fixed window is the honest approximation: it is
/// predictable, it is stated here, and it never drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BudgetPeriod {
    /// Twenty-four hours.
    #[default]
    Daily,
    /// Thirty days.
    Monthly,
}

impl BudgetPeriod {
    /// The window length in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u64 {
        match self {
            Self::Daily => 24 * 60 * 60 * 1000,
            Self::Monthly => 30 * 24 * 60 * 60 * 1000,
        }
    }

    /// Parse from the configuration grammar.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "daily" => Some(Self::Daily),
            "monthly" => Some(Self::Monthly),
            _ => None,
        }
    }

    /// The configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Monthly => "monthly",
        }
    }
}

impl ScopeLimits {
    /// A scope that imposes no limit of its own.
    pub const UNLIMITED: Self = Self {
        max_concurrency: 0,
        max_queued: 0,
        requests_per_second: 0,
        request_burst: 0,
        tokens_per_minute: 0,
        token_burst: 0,
        budget_minor_units: 0,
        budget_period: BudgetPeriod::Daily,
    };

    /// Whether this scope constrains anything.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.max_concurrency == 0 && self.requests_per_second == 0 && self.tokens_per_minute == 0
    }

    /// This scope's share of the limit when the deployment runs `partitions`
    /// routers.
    ///
    /// Specification 12: "admission-critical quotas require an authoritative
    /// allocator **or conservative node partitions**." This is the second of
    /// those. Each router enforces `limit / partitions`, so the deployment as a
    /// whole honours the configured figure without any node having to ask
    /// another what it has admitted — no consensus, which specification 2.2
    /// makes a non-goal, and no shared state, which `DI-029` records as absent.
    ///
    /// Conservative in the precise sense that the sum across nodes never
    /// *exceeds* the configured limit: division truncates, so N nodes admit at
    /// most the whole. The cost is the remainder — `concurrency=10` over 3
    /// nodes admits 9 — and that under-admission is the deliberate direction to
    /// err, because the alternative rounds up and quietly raises every limit in
    /// the deployment.
    ///
    /// Zero stays zero: it means "unlimited" here, and a share of unlimited is
    /// still unlimited.
    ///
    /// A limit smaller than `partitions` divides to zero, which would mean
    /// "unlimited" rather than "almost nothing" — the exact inversion of what
    /// the operator asked for. [`Self::partition_underflows`] reports that so a
    /// configuration can be refused rather than silently opened up.
    #[must_use]
    // Not `const`: `u64::from` is not yet callable in a const function, and an
    // `as` cast here would be exactly the silent conversion this crate denies.
    pub fn partitioned(&self, partitions: u32) -> Self {
        if partitions <= 1 {
            return *self;
        }
        let n = u64::from(partitions);
        Self {
            max_concurrency: divide_u32(self.max_concurrency, partitions),
            // The queue is per-node working space rather than a limit the
            // deployment shares, but it is divided too: N nodes each holding
            // the full queue is N times the memory and N times the worst-case
            // wait, and the queue exists to bound both.
            max_queued: divide_u32(self.max_queued, partitions),
            requests_per_second: divide_u32(self.requests_per_second, partitions),
            request_burst: divide_u32(self.request_burst, partitions),
            tokens_per_minute: divide_u64(self.tokens_per_minute, n),
            token_burst: divide_u64(self.token_burst, n),
            // A budget is a limit like any other: N nodes each holding the
            // whole figure would let the deployment spend N times it.
            budget_minor_units: divide_u64(self.budget_minor_units, n),
            budget_period: self.budget_period,
        }
    }

    /// Whether partitioning would turn a real limit into "unlimited".
    ///
    /// A non-zero limit that divides to zero has inverted meaning: zero is the
    /// encoding for unlimited, so the tightest possible configuration would
    /// become the loosest. That must be refused at load rather than enforced.
    #[must_use]
    pub fn partition_underflows(&self, partitions: u32) -> bool {
        if partitions <= 1 {
            return false;
        }
        let n = u64::from(partitions);
        (self.max_concurrency != 0 && self.max_concurrency < partitions)
            || (self.requests_per_second != 0 && self.requests_per_second < partitions)
            || (self.tokens_per_minute != 0 && self.tokens_per_minute < n)
            || (self.budget_minor_units != 0 && self.budget_minor_units < n)
    }
}

/// Integer division that keeps zero meaning "unlimited".
///
/// Truncation is the point rather than a defect: rounding a node's share *down*
/// is what keeps the sum across nodes at or below the configured limit. Rounding
/// up, or using a float, would let N nodes admit more than was configured.
const fn divide_u32(value: u32, by: u32) -> u32 {
    match value.checked_div(by) {
        Some(quotient) => quotient,
        None => value,
    }
}

/// [`divide_u32`] for the token counters, which are 64-bit.
const fn divide_u64(value: u64, by: u64) -> u64 {
    match value.checked_div(by) {
        Some(quotient) => quotient,
        None => value,
    }
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

/// Why admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The concurrency semaphore is full.
    ConcurrencyExhausted,
    /// The queue is full.
    QueueFull,
    /// The request waited its full queue budget without reaching the head.
    ///
    /// Distinct from `QueueFull` because the two mean different things to an
    /// operator: a full queue is a sizing problem, and a timeout is a service
    /// rate problem. Reported as `capacity_exhausted` to the caller either way,
    /// since the difference is not theirs to act on.
    QueueTimeout,
    /// The request-rate bucket is empty.
    RequestRateExceeded,
    /// The global byte-rate limit is exhausted.
    ///
    /// Separate from `RequestRateExceeded` because the operator response
    /// differs: a request-rate rejection means too many calls, a byte-rate
    /// rejection means calls that are too large, and the fix for one is not the
    /// fix for the other.
    ByteRateExceeded,
    /// The scope has spent its budget for the current period.
    ///
    /// Distinct from the rate rejections because it does not clear when load
    /// drops: it clears when the period rolls, which may be hours away. An
    /// operator seeing this needs to raise the budget or wait, not add capacity.
    BudgetExhausted,
    /// The token bucket is empty.
    TokenRateExceeded,
    /// The target's machine has not the memory free, or work of a higher class
    /// is waiting for it ([`crate::machine`]).
    ///
    /// Capacity to the caller, like a full slot; separate for the operator,
    /// because the fix is the machine's memory, not the target's concurrency.
    MemoryExhausted,
}

impl Rejection {
    /// The exclusion reason this maps to in a decision trace.
    #[must_use]
    pub const fn exclusion_reason(self) -> ExclusionReason {
        match self {
            Self::ConcurrencyExhausted
            | Self::QueueFull
            | Self::QueueTimeout
            | Self::MemoryExhausted => ExclusionReason::CapacityExhausted,
            Self::RequestRateExceeded
            | Self::TokenRateExceeded
            | Self::ByteRateExceeded
            | Self::BudgetExhausted => ExclusionReason::BudgetExceeded,
        }
    }

    /// The client error code this maps to.
    #[must_use]
    pub const fn error_code(self) -> crate::error::ErrorCode {
        match self {
            Self::ConcurrencyExhausted
            | Self::QueueFull
            | Self::QueueTimeout
            | Self::MemoryExhausted => crate::error::ErrorCode::CapacityExhausted,
            Self::RequestRateExceeded
            | Self::TokenRateExceeded
            | Self::ByteRateExceeded
            | Self::BudgetExhausted => crate::error::ErrorCode::RateLimited,
        }
    }

    /// Stable name for traces and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConcurrencyExhausted => "concurrency_exhausted",
            Self::QueueFull => "queue_full",
            Self::QueueTimeout => "queue_timeout",
            Self::RequestRateExceeded => "request_rate_exceeded",
            Self::TokenRateExceeded => "token_rate_exceeded",
            Self::ByteRateExceeded => "byte_rate_exceeded",
            Self::BudgetExhausted => "budget_exhausted",
            Self::MemoryExhausted => "memory_exhausted",
        }
    }
}

/// A refilling token bucket over monotonic time.
///
/// Fixed-point in thousandths of a unit, so that a per-second rate refills
/// smoothly rather than in whole-unit steps.
///
/// # Resolution limit
///
/// The refill rate is held in thousandths of a unit per millisecond, so the
/// smallest representable non-zero rate is one unit per second. A per-minute
/// rate below 60 therefore truncates to a zero refill rate in
/// [`TokenBucket::per_minute`]: such a bucket serves its initial burst and
/// then never refills. Only `tokens_per_minute` reaches that constructor, and
/// token budgets sit far above 60 per minute, so no configuration in range
/// hits this today — but a per-minute *request* rate must not be routed here
/// without first widening the fixed-point unit or carrying the division
/// remainder in `BucketState`.
#[derive(Debug)]
pub struct TokenBucket {
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    /// Held under the same lock as the level, so a retune between a refill
    /// and a take cannot be observed half-applied.
    capacity_milli: u64,
    /// Refill in thousandths of a unit per millisecond.
    refill_milli_per_ms: u64,
    level_milli: u64,
    last_ms: u64,
    /// Units admitted beyond the bucket's capacity and not yet paid for.
    ///
    /// Refill and refunds pay this down before they raise the level, so while
    /// it is non-zero the level is zero and nothing else is admitted. See
    /// [`TokenBucket::try_take`] for why an oversized request creates debt
    /// rather than being clamped to the capacity.
    debt_milli: u64,
}

impl BucketState {
    /// Credit `amount` thousandths: pay down debt first, then raise the level.
    fn credit(&mut self, amount: u64) {
        let paid = amount.min(self.debt_milli);
        self.debt_milli -= paid;
        self.level_milli = self
            .level_milli
            .saturating_add(amount - paid)
            .min(self.capacity_milli);
    }
}

/// A bucket's shape: capacity and refill, in its fixed-point units.
struct BucketShape {
    capacity_milli: u64,
    refill_milli_per_ms: u64,
}

impl BucketShape {
    fn per_second(rate: u64, burst: u64) -> Self {
        let capacity = burst.max(rate).max(1);
        Self {
            capacity_milli: capacity.saturating_mul(1000),
            refill_milli_per_ms: rate, // rate/sec * 1000 milli / 1000 ms
        }
    }

    // The refill rate is fixed-point in thousandths of a unit per millisecond,
    // so converting a per-minute rate is an integer division by 60_000. It
    // truncates: rates below 60 units per minute floor to a zero refill rate.
    #[allow(clippy::integer_division)]
    fn per_minute(rate: u64, burst: u64) -> Self {
        let capacity = burst.max(rate.div_ceil(60)).max(1);
        Self {
            capacity_milli: capacity.saturating_mul(1000),
            // rate/min * 1000 milli / 60_000 ms
            refill_milli_per_ms: rate.saturating_mul(1000) / 60_000,
        }
    }
}

impl TokenBucket {
    fn full(shape: &BucketShape, now_ms: u64) -> Self {
        Self {
            state: Mutex::new(BucketState {
                capacity_milli: shape.capacity_milli,
                refill_milli_per_ms: shape.refill_milli_per_ms,
                level_milli: shape.capacity_milli,
                last_ms: now_ms,
                debt_milli: 0,
            }),
        }
    }

    /// Create a bucket with a per-second rate and a burst capacity.
    #[must_use]
    pub fn per_second(rate: u64, burst: u64, now_ms: u64) -> Self {
        Self::full(&BucketShape::per_second(rate, burst), now_ms)
    }

    /// Create a bucket with a per-minute rate and a burst capacity.
    #[must_use]
    pub fn per_minute(rate: u64, burst: u64, now_ms: u64) -> Self {
        Self::full(&BucketShape::per_minute(rate, burst), now_ms)
    }

    /// Change the rate and capacity, keeping what has been drawn.
    ///
    /// For a published quota change. Time up to `now_ms` is refilled at the
    /// *old* rate first, so the change is not applied retroactively. The level
    /// is then clamped to the new capacity and never raised: a retune is not a
    /// refill, and one that topped the bucket up would let an operator who
    /// re-published the same limits hand every caller a fresh burst. Debt is
    /// kept, so a request admitted beyond the old capacity is still paid for.
    fn retune(&self, shape: &BucketShape, now_ms: u64) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::refill_locked(&mut state, now_ms);
        state.capacity_milli = shape.capacity_milli;
        state.refill_milli_per_ms = shape.refill_milli_per_ms;
        state.level_milli = state.level_milli.min(shape.capacity_milli);
    }

    fn refill_locked(state: &mut BucketState, now_ms: u64) {
        // Monotonic clock: `now_ms` never goes backwards, so this cannot
        // credit time that did not pass.
        let elapsed = now_ms.saturating_sub(state.last_ms);
        if elapsed == 0 {
            return;
        }
        let credit = elapsed.saturating_mul(state.refill_milli_per_ms);
        state.credit(credit);
        state.last_ms = now_ms;
    }

    /// Try to take `amount` units.
    ///
    /// All or nothing, and when it succeeds the **whole** `amount` is charged.
    ///
    /// # Oversized requests
    ///
    /// A request larger than the bucket's capacity could never be admitted by
    /// a plain check, which with `token_burst=0` (capacity is one second of the
    /// rate) would refuse every realistic prompt. So it is admitted when the
    /// bucket is full — and charged in full, with the part beyond the capacity
    /// carried as debt that refill must pay off before anything else is
    /// admitted. The rate is therefore honoured over time: a request of ten
    /// minutes' tokens costs ten minutes of refill.
    ///
    /// The alternative this replaces clamped the charge to the capacity, so an
    /// arbitrarily large request cost at most one second of refill — and since
    /// reconciliation refunds `estimate - actual` against the full estimate, a
    /// request whose estimate was clamped could have almost all of its real
    /// usage refunded as well. Charging in full is the fail-closed choice that
    /// keeps both the admission charge and the later refund in the same units.
    pub fn try_take(&self, amount: u64, now_ms: u64) -> bool {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::refill_locked(&mut state, now_ms);
        let want = amount.saturating_mul(1000);
        if state.debt_milli > 0 {
            return false;
        }
        if want > state.capacity_milli {
            if state.level_milli < state.capacity_milli {
                return false;
            }
            state.debt_milli = want - state.level_milli;
            state.level_milli = 0;
            return true;
        }
        if state.level_milli >= want {
            state.level_milli -= want;
            true
        } else {
            false
        }
    }

    /// Return `amount` units, never exceeding capacity.
    ///
    /// Used for reconciliation when actual usage came in below the estimate,
    /// and to roll back a reservation that was refused elsewhere. Outstanding
    /// debt is paid first; capping at capacity is what stops a refund from
    /// becoming free burst.
    pub fn refund(&self, amount: u64) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.credit(amount.saturating_mul(1000));
    }

    /// Deduct `amount` units, draining to empty when the level is short.
    ///
    /// Reconciliation is not admission: by the time an overage is known the
    /// tokens are already spent, so the only question is whether the scope
    /// pays for them. [`TokenBucket::try_take`] is all-or-nothing and refuses
    /// when the level is insufficient, which would let a caller that
    /// systematically under-estimates never pay for the difference. This
    /// charges what it can and leaves the bucket empty, so the next request
    /// waits — the behaviour specification 12's reconciliation clause requires.
    pub fn charge(&self, amount: u64, now_ms: u64) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::refill_locked(&mut state, now_ms);
        state.level_milli = state.level_milli.saturating_sub(amount.saturating_mul(1000));
    }

    /// Current level in whole units, for metrics.
    // The level is held in thousandths; reporting whole units is a fixed-point
    // descale, and rounding down never overstates the capacity available.
    #[allow(clippy::integer_division)]
    #[must_use]
    pub fn level(&self) -> u64 {
        let state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.level_milli / 1000
    }
}

/// A request's priority class in the admission queue.
///
/// Specification 12: "Queue order is weighted fair by tenant and priority
/// class; FIFO is maintained within an equal class." Lower is served first.
///
/// A small closed set rather than an integer, because a class is a policy
/// decision expressed in configuration and an unbounded one would let a caller
/// or a careless binding invent a class that outranks everything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityClass {
    /// Served ahead of everything else.
    Interactive,
    /// The default.
    #[default]
    Standard,
    /// Yields to both of the above.
    Batch,
}

impl PriorityClass {
    /// Stable name for configuration, traces, and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Standard => "standard",
            Self::Batch => "batch",
        }
    }

    /// Parse a configured name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "interactive" => Some(Self::Interactive),
            "standard" => Some(Self::Standard),
            "batch" => Some(Self::Batch),
            _ => None,
        }
    }
}

/// One waiter in a scope's queue.
#[derive(Debug, Clone)]
struct Waiter {
    seq: u64,
    class: PriorityClass,
    tenant: TenantId,
    /// Which round of this tenant-and-class this waiter belongs to, stamped on
    /// arrival: the number of the tenant's own waiters already in line.
    round: usize,
}

/// The waiting line for one scope.
///
/// # Why the order is computed rather than stored
///
/// A plain FIFO starves a tenant that submits one request behind a tenant that
/// submitted a hundred, which is the failure specification 12's "weighted fair
/// by tenant" exists to prevent. A per-tenant round robin alone loses the
/// arrival order that the same sentence's "FIFO is maintained" requires.
///
/// Both hold if the sort key is `(class, round, arrival sequence)`, where the
/// round is the number of the tenant's own waiters already in line when this
/// one arrived. Every tenant's first waiter is served before any tenant's
/// second, so a hundred queued requests from one tenant cannot delay another
/// tenant's single request by more than one position; within a tenant and class
/// the arrival order is exact; and a higher class outranks both.
///
/// The round is stamped on arrival rather than recomputed, because recomputing
/// it re-ranks the survivors every time the head leaves: the tenant with the
/// backlog would find its second waiter promoted back to round zero the moment
/// its first was served, and the order would collapse to plain arrival order —
/// which is the starvation this exists to prevent. Rounds stay bounded by
/// `max_queued` because the count is of waiters *present*, not of requests
/// ever served, so a busy tenant cannot inflate its own numbers away.
#[derive(Debug, Default)]
struct QueueState {
    waiting: Vec<Waiter>,
    next_seq: u64,
}

impl QueueState {
    /// The sequence number of the waiter that should be admitted next.
    fn head(&self) -> Option<u64> {
        self.waiting
            .iter()
            .min_by_key(|w| (w.class, w.round, w.seq))
            .map(|w| w.seq)
    }

    /// The round to stamp on a new waiter of this tenant and class.
    fn next_round(&self, class: PriorityClass, tenant: &TenantId) -> usize {
        self.waiting
            .iter()
            .filter(|w| w.class == class && w.tenant == *tenant)
            .count()
    }
}

/// One level of the admission hierarchy.
#[derive(Debug)]
pub struct Scope {
    /// A stable name for metrics and rejection traces.
    pub name: String,
    /// What this scope enforces. Behind a lock because a published policy
    /// changes it in place ([`Scope::reconfigure`]): replacing the scope would
    /// forget what it has admitted and spent.
    limits: RwLock<ScopeLimits>,
    in_flight: AtomicU32,
    queued: AtomicU32,
    request_bucket: RwLock<Option<TokenBucket>>,
    token_bucket: RwLock<Option<TokenBucket>>,
    /// Cumulative counters, for the conservation invariant.
    acquired: AtomicU64,
    released: AtomicU64,
    /// The waiting line, and the signal that a slot came free.
    ///
    /// Only ever non-empty when `limits.max_queued > 0`, so a scope with no
    /// configured queue behaves exactly as it did before queueing existed.
    queue: Mutex<QueueState>,
    slot_freed: Condvar,
    /// Minor currency units spent in the current budget period.
    spent: AtomicU64,
    /// When the current budget period began, in monotonic milliseconds.
    period_start: AtomicU64,
}

impl Scope {
    /// Create a scope.
    #[must_use]
    pub fn new(name: impl Into<String>, limits: ScopeLimits, now_ms: u64) -> Self {
        Self {
            name: name.into(),
            limits: RwLock::new(limits),
            in_flight: AtomicU32::new(0),
            queued: AtomicU32::new(0),
            request_bucket: RwLock::new(
                request_shape(&limits).map(|shape| TokenBucket::full(&shape, now_ms)),
            ),
            token_bucket: RwLock::new(
                token_shape(&limits).map(|shape| TokenBucket::full(&shape, now_ms)),
            ),
            acquired: AtomicU64::new(0),
            released: AtomicU64::new(0),
            spent: AtomicU64::new(0),
            period_start: AtomicU64::new(now_ms),
            queue: Mutex::new(QueueState::default()),
            slot_freed: Condvar::new(),
        }
    }

    /// The limits this scope enforces.
    ///
    /// Exposed for reporting, not for decisions: nothing on the admission path
    /// reads this, because a caller that compared `in_flight()` against
    /// `limits().max_concurrency` itself would be re-implementing
    /// [`Scope::try_acquire`] without its atomicity. A management read is the
    /// one place where the pair is genuinely wanted — an operator looking at a
    /// utilisation figure needs the denominator, and the denominator is not
    /// otherwise reachable from outside this module.
    #[must_use]
    pub fn limits(&self) -> ScopeLimits {
        match self.limits.read() {
            Ok(limits) => *limits,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Change what this scope enforces, keeping everything it has counted.
    ///
    /// For a published or rolled-back policy. In-flight requests, queued
    /// waiters, the conservation counters, the budget ledger and its period
    /// start, and the level and debt of each rate bucket all carry over, so a
    /// reconfiguration neither returns spent credit nor briefly over-admits.
    /// It never cancels anything: lowering `max_concurrency` below what is in
    /// flight refuses new admissions until enough finish, and lowering
    /// `max_queued` below the waiters present refuses new arrivals while the
    /// ones already in line keep their places.
    ///
    /// A bucket that newly appears starts full, exactly as at startup; one that
    /// disappears is dropped. A reservation taken before a bucket appeared is
    /// still reconciled against it on release — a refund is capped at the
    /// capacity, so that can never grant burst, and an overage is charged,
    /// which is the conservative direction.
    pub fn reconfigure(&self, limits: ScopeLimits, now_ms: u64) {
        reshape(&self.request_bucket, request_shape(&limits), now_ms);
        reshape(&self.token_bucket, token_shape(&limits), now_ms);
        match self.limits.write() {
            Ok(mut current) => *current = limits,
            Err(poisoned) => *poisoned.into_inner() = limits,
        }
        // A raised concurrency limit, or a queue that went away, may let a
        // waiter proceed, and nothing else would wake it.
        self.slot_freed.notify_all();
    }

    /// Whether any waiter is in line or a queue is configured.
    fn wakes_waiters(&self) -> bool {
        self.limits().max_queued > 0 || self.queued() > 0
    }

    /// Requests currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Total reservations ever acquired in this scope.
    ///
    /// Appendix B requires that "every reservation is released exactly once on
    /// all success, error, timeout, and cancellation paths". That is a
    /// conservation law over these two counters, and it can only be asserted
    /// if both are observable — a leak is otherwise invisible until the scope
    /// stops admitting anything.
    #[must_use]
    pub fn acquired(&self) -> u64 {
        self.acquired.load(Ordering::SeqCst)
    }

    /// Total reservations ever released in this scope.
    ///
    /// Equal to [`Scope::acquired`] whenever nothing is in flight.
    #[must_use]
    pub fn released(&self) -> u64 {
        self.released.load(Ordering::SeqCst)
    }

    /// Requests currently queued.
    #[must_use]
    pub fn queued(&self) -> u32 {
        self.queued.load(Ordering::SeqCst)
    }

    /// Whether any concurrency slot remains.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        let max = self.limits().max_concurrency;
        max == 0 || self.in_flight() < max
    }

    /// Total acquisitions and releases, which must be equal once idle.
    #[must_use]
    pub fn conservation(&self) -> (u64, u64) {
        (
            self.acquired.load(Ordering::SeqCst),
            self.released.load(Ordering::SeqCst),
        )
    }

    /// Try to reserve one request slot and `tokens` of budget.
    #[cfg(test)]
    fn try_acquire(&self, tokens: u64, now_ms: u64) -> Result<(), Rejection> {
        self.try_acquire_as(tokens, now_ms, None)
    }

    /// Try to reserve, optionally as the holder of queue ticket `ticket`.
    ///
    /// A caller with no ticket yields to anyone already waiting. Without that,
    /// a queue is worse than none: arrivals take the slot the instant it frees
    /// and the waiters — who are, by construction, the requests that have
    /// already waited longest — are the last to be served.
    /// Roll the budget period if it has elapsed, and report the spend so far.
    ///
    /// Rolling on read rather than from a timer: there is no background task
    /// here, and a period that only advanced when something else ran would
    /// leave a scope refused indefinitely after traffic stopped.
    fn spend_in_period(&self, now_ms: u64) -> u64 {
        let period = self.limits().budget_period.millis();
        let start = self.period_start.load(Ordering::SeqCst);
        if now_ms.saturating_sub(start) >= period {
            // `compare_exchange` so concurrent callers roll the window once.
            // Two threads both resetting would be harmless here, but two
            // threads resetting to *different* starts would make the period
            // length depend on scheduling.
            if self
                .period_start
                .compare_exchange(start, now_ms, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.spent.store(0, Ordering::SeqCst);
                return 0;
            }
        }
        self.spent.load(Ordering::SeqCst)
    }

    /// Add actual spend to the current period.
    ///
    /// Called after a response, with the cost computed from provider-reported
    /// usage. Deliberately *not* an estimate taken at admission: the byte-based
    /// token estimator over-counts by roughly a factor of two (`DI-048`), and a
    /// budget enforced on it would refuse a tenant at half their allowance. The
    /// price of using actual cost is that a scope can overshoot by the requests
    /// already in flight when it crosses the line, which is bounded by its own
    /// concurrency limit.
    pub fn record_spend(&self, minor_units: u64, now_ms: u64) {
        let _ = self.spend_in_period(now_ms);
        let _ = self
            .spent
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(minor_units))
            });
    }

    /// Minor units spent in the current period.
    #[must_use]
    pub fn spent_this_period(&self, now_ms: u64) -> u64 {
        self.spend_in_period(now_ms)
    }

    /// Minor units spent in the current period, without rolling it.
    ///
    /// [`Self::spent_this_period`] resets the ledger when the period has
    /// elapsed, which is right on the admission path and wrong for a
    /// management read: a dashboard refresh would move the period boundary to
    /// whenever somebody happened to look, and two operators watching the same
    /// screen would each shorten the tenant's next budget period a little. This
    /// reports what the rolled value *would* be — zero once the period is up —
    /// and leaves the roll to the next request.
    #[must_use]
    pub fn observed_spend(&self, now_ms: u64) -> u64 {
        let period = self.limits().budget_period.millis();
        let start = self.period_start.load(Ordering::SeqCst);
        if now_ms.saturating_sub(start) >= period {
            return 0;
        }
        self.spent.load(Ordering::SeqCst)
    }

    fn try_acquire_as(
        &self,
        tokens: u64,
        now_ms: u64,
        ticket: Option<u64>,
    ) -> Result<(), Rejection> {
        // One read, so every check below judges against the same limits even
        // if a publication lands mid-acquisition.
        let limits = self.limits();
        // Before any bookkeeping: a scope past its budget is refused for the
        // rest of the period, and taking a slot first would mean releasing it
        // again on every request until the period rolls.
        if limits.budget_minor_units > 0
            && self.spend_in_period(now_ms) >= limits.budget_minor_units
        {
            return Err(Rejection::BudgetExhausted);
        }

        // Waiters keep their order even after a publication removes the
        // queue: an arrival must not barge past people already in line.
        if limits.max_queued > 0 || self.queued() > 0 {
            let head = match self.queue.lock() {
                Ok(q) => q.head(),
                Err(poisoned) => poisoned.into_inner().head(),
            };
            if let Some(head) = head {
                if ticket != Some(head) {
                    return Err(Rejection::ConcurrencyExhausted);
                }
            }
        }

        // Concurrency first: it is the cheapest check and the one most likely
        // to fail under load.
        if limits.max_concurrency > 0 {
            let mut current = self.in_flight.load(Ordering::SeqCst);
            loop {
                if current >= limits.max_concurrency {
                    return Err(Rejection::ConcurrencyExhausted);
                }
                match self.in_flight.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        } else {
            self.in_flight.fetch_add(1, Ordering::SeqCst);
        }

        if !with_bucket(&self.request_bucket, |bucket| bucket.try_take(1, now_ms)) {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return Err(Rejection::RequestRateExceeded);
        }

        if !with_bucket(&self.token_bucket, |bucket| bucket.try_take(tokens, now_ms)) {
            // Roll back both prior acquisitions.
            with_bucket(&self.request_bucket, |rb| {
                rb.refund(1);
                true
            });
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return Err(Rejection::TokenRateExceeded);
        }

        self.acquired.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Release one request slot, reconciling `reserved` against `actual`.
    /// Return a reservation, reconciling the estimate against actual usage.
    ///
    /// `now_ms` must be the real monotonic time. Passing a sentinel such as
    /// `u64::MAX` breaks the bucket twice over: the refill that precedes the
    /// charge credits an enormous elapsed interval, so the bucket is full and
    /// the overage costs nothing; and the bucket's `last_ms` is left at the
    /// sentinel, so every later refill computes an elapsed time of zero and the
    /// scope never refills again.
    fn release(&self, reserved: u64, actual: u64, now_ms: u64) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        with_bucket(&self.token_bucket, |bucket| {
            if actual < reserved {
                // Refund the unused estimate. The bucket caps at capacity, so
                // a refund can never grant more burst than the configuration
                // allows — this is the "without granting negative-cost abuse"
                // clause of specification 12.
                bucket.refund(reserved - actual);
            } else if actual > reserved {
                // Charge the overage. It may drive the bucket to empty, which
                // simply means the next request waits.
                bucket.charge(actual - reserved, now_ms);
            }
            true
        });
        self.released.fetch_add(1, Ordering::SeqCst);
        // A slot came free. Waking every waiter rather than one is deliberate:
        // which of them may proceed is decided by `QueueState::head`, not by
        // wake order, and a targeted wake would have to duplicate that decision
        // in a second place where it could disagree.
        if self.wakes_waiters() {
            self.slot_freed.notify_all();
        }
    }

    /// Undo a successful [`Scope::try_acquire_as`] whose reservation was
    /// refused at another scope.
    ///
    /// Not [`Scope::release`]: a release reconciles a request that *ran*, so it
    /// keeps the request-rate token and charges the tokens actually used. A
    /// rolled-back acquisition ran nothing, so everything it took — the slot,
    /// the request-rate token, and the whole token estimate — goes back. A
    /// rejection at a narrow scope must not drain the wider ones, or one
    /// saturated target would starve its tenant's budget for every other
    /// target.
    fn rollback(&self, tokens: u64) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        with_bucket(&self.request_bucket, |bucket| {
            bucket.refund(1);
            true
        });
        with_bucket(&self.token_bucket, |bucket| {
            bucket.refund(tokens);
            true
        });
        self.released.fetch_add(1, Ordering::SeqCst);
        if self.wakes_waiters() {
            self.slot_freed.notify_all();
        }
    }

    /// Join the waiting line, if there is room.
    ///
    /// Returns the ticket to pass to [`Scope::wait_for_turn`], or the rejection
    /// to report. A scope with `max_queued == 0` always rejects, which is what
    /// makes queueing opt-in per scope.
    fn join_queue(&self, class: PriorityClass, tenant: &TenantId) -> Result<u64, Rejection> {
        let max_queued = self.limits().max_queued;
        if max_queued == 0 {
            return Err(Rejection::ConcurrencyExhausted);
        }
        let mut state = match self.queue.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if u32::try_from(state.waiting.len()).unwrap_or(u32::MAX) >= max_queued {
            return Err(Rejection::QueueFull);
        }
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        let round = state.next_round(class, tenant);
        state.waiting.push(Waiter {
            seq,
            class,
            tenant: tenant.clone(),
            round,
        });
        self.queued.store(
            u32::try_from(state.waiting.len()).unwrap_or(u32::MAX),
            Ordering::SeqCst,
        );
        Ok(seq)
    }

    /// Leave the waiting line.
    fn leave_queue(&self, ticket: u64) {
        let mut state = match self.queue.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.waiting.retain(|w| w.seq != ticket);
        self.queued.store(
            u32::try_from(state.waiting.len()).unwrap_or(u32::MAX),
            Ordering::SeqCst,
        );
        drop(state);
        // Leaving can promote someone else to the head, and nothing else will
        // wake them: no slot was released, so `release` will not fire.
        self.slot_freed.notify_all();
    }

    /// Block until this ticket is at the head with capacity, or `timeout`.
    ///
    /// Returns whether the wait ended because it was this ticket's turn. The
    /// caller must still attempt the acquisition — being at the head means
    /// permission to try, not a held slot.
    fn wait_for_turn(&self, ticket: u64, timeout: std::time::Duration) -> bool {
        let mut state = match self.queue.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut remaining = timeout;
        loop {
            if state.head() == Some(ticket) && self.has_capacity() {
                return true;
            }
            if remaining.is_zero() {
                return false;
            }
            let started = std::time::Instant::now();
            let (next, result) = match self.slot_freed.wait_timeout(state, remaining) {
                Ok(pair) => pair,
                Err(poisoned) => {
                    let (guard, result) = poisoned.into_inner();
                    (guard, result)
                }
            };
            state = next;
            if result.timed_out() {
                // One last look: the slot may have freed between the timeout
                // firing and the lock being reacquired.
                return state.head() == Some(ticket) && self.has_capacity();
            }
            remaining = remaining.saturating_sub(started.elapsed());
        }
    }

}

/// The request-rate bucket shape `limits` asks for, if any.
fn request_shape(limits: &ScopeLimits) -> Option<BucketShape> {
    (limits.requests_per_second > 0).then(|| {
        BucketShape::per_second(
            u64::from(limits.requests_per_second),
            u64::from(limits.request_burst),
        )
    })
}

/// The token-rate bucket shape `limits` asks for, if any.
fn token_shape(limits: &ScopeLimits) -> Option<BucketShape> {
    (limits.tokens_per_minute > 0)
        .then(|| BucketShape::per_minute(limits.tokens_per_minute, limits.token_burst))
}

/// Retune, create or drop the bucket in `slot` to match `shape`.
fn reshape(slot: &RwLock<Option<TokenBucket>>, shape: Option<BucketShape>, now_ms: u64) {
    let mut slot = match slot.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    match (slot.as_ref(), shape) {
        (Some(bucket), Some(shape)) => bucket.retune(&shape, now_ms),
        (None, Some(shape)) => *slot = Some(TokenBucket::full(&shape, now_ms)),
        (_, None) => *slot = None,
    }
}

/// Run `f` on the bucket in `slot`; an absent bucket admits everything.
fn with_bucket(slot: &RwLock<Option<TokenBucket>>, f: impl FnOnce(&TokenBucket) -> bool) -> bool {
    let slot = match slot.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    slot.as_ref().is_none_or(f)
}

/// A held reservation across the whole scope hierarchy.
///
/// Released exactly once, whether by [`Reservation::commit`] or by `Drop`.
#[derive(Debug)]
pub struct Reservation {
    scopes: Vec<Arc<Scope>>,
    reserved_tokens: u64,
    released: AtomicBool,
    /// Needed at release time to charge an overage against the bucket as it
    /// stands *now*, rather than at some sentinel time.
    clock: Arc<dyn Clock>,
    /// The target this reservation admits a request to.
    pub target: TargetId,
    /// Memory held on the target's machine, returned with everything else.
    machine: Option<MachineHold>,
}

impl Reservation {
    /// Tokens reserved at admission.
    #[must_use]
    pub const fn reserved_tokens(&self) -> u64 {
        self.reserved_tokens
    }

    /// Whether the reservation has already been released.
    #[must_use]
    pub fn is_released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }

    /// Release with reconciled usage.
    ///
    /// Specification 12: "On completion, reconcile against provider usage
    /// without granting negative-cost abuse."
    pub fn commit(self, actual_tokens: u64) {
        self.finish(actual_tokens);
        // `self` drops here; `finish` is idempotent, so the Drop impl is a
        // no-op.
    }

    /// Release a reservation whose attempt consumed no tokens.
    ///
    /// For an attempt that never reached the provider, or that the provider
    /// refused before producing anything: the token estimate is refunded in
    /// full. The request-rate token is kept — the attempt was made — and the
    /// concurrency slot is returned as on every other path. `Drop`, by
    /// contrast, charges the whole estimate, which is the conservative answer
    /// for a path that does not know what happened.
    pub fn release_unused(self) {
        self.finish(0);
    }

    fn finish(&self, actual_tokens: u64) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        let now = self.clock.now_millis();
        // Release in reverse acquisition order so that the narrowest scope is
        // freed first, mirroring lock discipline.
        if let Some(hold) = &self.machine {
            hold.release();
        }
        for scope in self.scopes.iter().rev() {
            scope.release(self.reserved_tokens, actual_tokens, now);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // The safety net: an error, timeout, or cancellation path that never
        // reached `commit` still returns capacity. Accounting falls back to the
        // estimate, which is conservative.
        self.finish(self.reserved_tokens);
    }
}

/// Alias scopes, keyed by alias and optional operation qualifier.
type AliasScopes = BTreeMap<(AliasId, Option<Operation>), Arc<Scope>>;

/// Global byte-rate limits (specification 12's Global layer). Zero means
/// unlimited in that direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteRateLimits {
    /// Bytes per second read from clients.
    pub input_per_second: u64,
    /// Burst allowance for the input bucket, in bytes.
    pub input_burst: u64,
    /// Bytes per second written to clients.
    pub output_per_second: u64,
    /// Burst allowance for the output bucket, in bytes.
    pub output_burst: u64,
}

/// Every limit and class a configuration gives the admission controller.
///
/// One value, built from a configuration in one place
/// (`hypellm_config::ValidatedConfig::admission_plan`), so startup and a
/// publication cannot disagree about which quotas apply. Ordered maps, so
/// applying the same plan twice does the same thing in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPlan {
    /// The global scope's limits.
    pub global: ScopeLimits,
    /// The global byte rates.
    pub byte_rates: ByteRateLimits,
    /// Tenants with an explicit quota.
    pub tenants: BTreeMap<TenantId, ScopeLimits>,
    /// Principals with an explicit quota.
    pub principals: BTreeMap<PrincipalId, ScopeLimits>,
    /// Alias scopes, by alias and optional operation.
    pub aliases: BTreeMap<(AliasId, Option<Operation>), ScopeLimits>,
    /// Target scopes.
    pub targets: BTreeMap<TargetId, ScopeLimits>,
    /// Admission-queue classes by scope name.
    pub classes: BTreeMap<String, PriorityClass>,
    /// Machines, by id, with the memory their targets share.
    pub machines: BTreeMap<String, u64>,
    /// What a request or job to each target holds on its machine.
    pub target_memory: BTreeMap<TargetId, TargetMemory>,
}

/// What one request or job to a target holds while it runs, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetMemory {
    /// The machine, by id.
    pub machine: String,
    /// Bytes held while it runs. Zero for a model that is resident anyway.
    pub bytes: u64,
    /// The class its work waits in for the machine's memory; the caller's
    /// class when absent.
    pub class: Option<PriorityClass>,
}

impl AdmissionPlan {
    /// A plan with the given global limits and nothing else.
    #[must_use]
    pub const fn new(global: ScopeLimits) -> Self {
        Self {
            global,
            byte_rates: ByteRateLimits {
                input_per_second: 0,
                input_burst: 0,
                output_per_second: 0,
                output_burst: 0,
            },
            tenants: BTreeMap::new(),
            principals: BTreeMap::new(),
            aliases: BTreeMap::new(),
            targets: BTreeMap::new(),
            classes: BTreeMap::new(),
            machines: BTreeMap::new(),
            target_memory: BTreeMap::new(),
        }
    }
}

/// The hierarchical admission controller.
///
/// Layers follow specification 12: global, tenant, principal, alias, target.
/// The provider layer is expressed as target-scope limits.
#[derive(Debug)]
pub struct AdmissionController {
    clock: Arc<dyn Clock>,
    global: Arc<Scope>,
    tenants: RwLock<BTreeMap<TenantId, Arc<Scope>>>,
    principals: RwLock<BTreeMap<PrincipalId, Arc<Scope>>>,
    targets: RwLock<BTreeMap<TargetId, Arc<Scope>>>,
    /// Alias scopes, keyed by alias and optional operation qualifier.
    ///
    /// Specification 12's "Alias/model" admission layer. `None` covers every
    /// operation on that alias; a `Some` entry is preferred when it matches.
    aliases: RwLock<AliasScopes>,
    /// Global input/output byte-rate buckets (specification 12's Global layer).
    inbound_bytes: RwLock<Option<TokenBucket>>,
    outbound_bytes: RwLock<Option<TokenBucket>>,
    default_tenant_limits: ScopeLimits,
    default_principal_limits: ScopeLimits,
    /// Admission-queue class by scope name.
    ///
    /// Separate from the scopes themselves because a class is a property of the
    /// *requests* a scope covers, not of its capacity: two scopes can share
    /// limits and differ in class, and a scope that is reconfigured must not
    /// silently lose its class along with its old limits.
    classes: RwLock<BTreeMap<String, PriorityClass>>,
    /// Machine memory ledgers by machine id ([`crate::machine`]).
    machines: RwLock<BTreeMap<String, Arc<MachineLedger>>>,
    /// Which machine each target draws on, and how much.
    target_memory: RwLock<BTreeMap<TargetId, TargetMemory>>,
    /// Names the machine waits of requests without a key of their own.
    next_wait: AtomicU64,
}

/// How a reservation takes its target's machine memory.
enum MemoryAsk<'a> {
    /// Try now, in `class`, as the holder of claim `key` if any.
    Take {
        class: PriorityClass,
        key: Option<&'a str>,
    },
    /// Already held, by a request that waited on the machine for it.
    Held(MachineHold),
}

impl AdmissionController {
    /// Create a controller with the given global limits.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, global: ScopeLimits) -> Self {
        let now = clock.now_millis();
        Self {
            global: Arc::new(Scope::new("global", global, now)),
            clock,
            tenants: RwLock::new(BTreeMap::new()),
            principals: RwLock::new(BTreeMap::new()),
            targets: RwLock::new(BTreeMap::new()),
            aliases: RwLock::new(BTreeMap::new()),
            inbound_bytes: RwLock::new(None),
            outbound_bytes: RwLock::new(None),
            default_tenant_limits: ScopeLimits::UNLIMITED,
            default_principal_limits: ScopeLimits::UNLIMITED,
            classes: RwLock::new(BTreeMap::new()),
            machines: RwLock::new(BTreeMap::new()),
            target_memory: RwLock::new(BTreeMap::new()),
            next_wait: AtomicU64::new(0),
        }
    }

    /// A controller enforcing `plan`.
    #[must_use]
    pub fn from_plan(clock: Arc<dyn Clock>, plan: &AdmissionPlan) -> Self {
        let controller = Self::new(clock, plan.global);
        controller.apply(plan);
        controller
    }

    /// Make the controller enforce `plan`, in place.
    ///
    /// For startup and for every publication or rollback, so a published
    /// quota is enforced at once rather than at the next restart.
    ///
    /// Scopes are reconfigured, never replaced ([`Scope::reconfigure`]): what a
    /// scope has admitted, queued and spent survives, so a publication can
    /// neither return a spent budget nor open a window in which a limit is
    /// briefly not counted. A reservation holds its scopes by reference, so it
    /// is released against exactly the objects it reserved on whatever has
    /// happened to the configuration since.
    ///
    /// What the plan no longer mentions:
    ///
    /// - a **tenant or principal** falls back to the default limits but keeps
    ///   its scope, so its counters and ledger carry on — removing a budget and
    ///   restoring it does not hand back what was spent;
    /// - a **target or alias** scope is dropped from the lookup. Nothing new is
    ///   admitted through it; requests already holding it still release it.
    ///
    /// The maps therefore hold only what the active configuration names plus
    /// the tenants and principals that have made requests — the same bound as
    /// before, so repeated publications do not grow them.
    pub fn apply(&self, plan: &AdmissionPlan) {
        let now = self.clock.now_millis();
        self.global.reconfigure(plan.global, now);
        let rates = plan.byte_rates;
        reshape(
            &self.inbound_bytes,
            (rates.input_per_second > 0)
                .then(|| BucketShape::per_second(rates.input_per_second, rates.input_burst)),
            now,
        );
        reshape(
            &self.outbound_bytes,
            (rates.output_per_second > 0)
                .then(|| BucketShape::per_second(rates.output_per_second, rates.output_burst)),
            now,
        );
        apply_layer(
            &self.tenants,
            &plan.tenants,
            Some(self.default_tenant_limits),
            |t| format!("tenant:{t}"),
            now,
        );
        apply_layer(
            &self.principals,
            &plan.principals,
            Some(self.default_principal_limits),
            |p| format!("principal:{p}"),
            now,
        );
        apply_layer(&self.targets, &plan.targets, None, |t| format!("target:{t}"), now);
        apply_layer(
            &self.aliases,
            &plan.aliases,
            None,
            |(alias, operation)| {
                operation.map_or_else(
                    || format!("alias:{alias}"),
                    |op| format!("alias:{alias}:{}", op.as_str()),
                )
            },
            now,
        );
        self.replace_classes(plan.classes.clone());
        self.configure_machines(plan);
    }

    /// Bring the machine ledgers in line with `plan`, and nothing else.
    ///
    /// [`Self::apply`] calls it; it is separate for a caller that builds its
    /// scopes another way. A ledger is reconfigured, never replaced, so what it
    /// holds and who waits survive a publication. A machine the plan no longer
    /// names is dropped from the lookup; holds already taken on it are still
    /// returned to it.
    pub fn configure_machines(&self, plan: &AdmissionPlan) {
        if let Ok(mut machines) = self.machines.write() {
            machines.retain(|id, _| plan.machines.contains_key(id));
            for (id, capacity) in &plan.machines {
                match machines.get(id) {
                    Some(ledger) => ledger.reconfigure(*capacity),
                    None => {
                        machines.insert(id.clone(), Arc::new(MachineLedger::new(id, *capacity)));
                    }
                }
            }
        }
        if let Ok(mut memory) = self.target_memory.write() {
            memory.clone_from(&plan.target_memory);
        }
    }

    /// The ledger a target draws on, what one of its requests holds, and the
    /// class it waits in.
    fn machine_for(
        &self,
        target: &TargetId,
        caller: PriorityClass,
    ) -> Option<(Arc<MachineLedger>, u64, PriorityClass)> {
        let memory = self.target_memory.read().ok()?.get(target).cloned()?;
        let ledger = self.machines.read().ok()?.get(&memory.machine).cloned()?;
        Some((ledger, memory.bytes, memory.class.unwrap_or(caller)))
    }

    /// Every machine and what it holds, for the management API.
    #[must_use]
    pub fn machine_views(&self) -> Vec<(String, MachineView)> {
        let now = self.clock.now_millis();
        self.machines.read().map_or_else(
            |_| Vec::new(),
            |machines| {
                machines
                    .iter()
                    .map(|(id, ledger)| (id.clone(), ledger.view(now)))
                    .collect()
            },
        )
    }

    /// Give up `key`'s place in line on every machine.
    ///
    /// For a job whose pass ended other than waiting for memory: it is running,
    /// finished or gone, and a claim left behind would hold up lower-class
    /// work until its lease ran out.
    pub fn drop_machine_claims(&self, key: &str) {
        if let Ok(machines) = self.machines.read() {
            for ledger in machines.values() {
                ledger.drop_claim(key);
            }
        }
    }

    /// Record the admission-queue class of a named scope.
    pub fn set_class(&self, scope_name: &str, class: PriorityClass) {
        if let Ok(mut map) = self.classes.write() {
            map.insert(scope_name.to_owned(), class);
        }
    }

    /// Replace every recorded class with `classes`, at once.
    ///
    /// For a configuration activation: the classes come from the new
    /// configuration's quotas, and one that is no longer declared must stop
    /// applying rather than outlive its record. Scope limits are not touched;
    /// they are built once, at startup.
    pub fn replace_classes(&self, classes: BTreeMap<String, PriorityClass>) {
        if let Ok(mut map) = self.classes.write() {
            *map = classes;
        }
    }

    /// The queue class a request from this principal and tenant belongs to.
    ///
    /// The principal's own class wins over its tenant's: the narrower scope is
    /// the more specific statement, and it is the one an operator reaches for
    /// when a single service account needs to be held back from, or ahead of,
    /// the rest of its tenant.
    #[must_use]
    pub fn class_for(&self, tenant: &TenantId, principal: &PrincipalId) -> PriorityClass {
        let Ok(map) = self.classes.read() else {
            return PriorityClass::Standard;
        };
        map.get(&format!("principal:{principal}"))
            .or_else(|| map.get(&format!("tenant:{tenant}")))
            .copied()
            .unwrap_or(PriorityClass::Standard)
    }

    /// Set the limits applied to a tenant with no explicit configuration.
    pub fn set_default_tenant_limits(&mut self, limits: ScopeLimits) {
        self.default_tenant_limits = limits;
    }

    /// Set the limits applied to a principal with no explicit configuration.
    pub fn set_default_principal_limits(&mut self, limits: ScopeLimits) {
        self.default_principal_limits = limits;
    }

    /// Configure a tenant scope.
    pub fn configure_tenant(&self, tenant: &TenantId, limits: ScopeLimits) {
        let scope = Arc::new(Scope::new(
            format!("tenant:{tenant}"),
            limits,
            self.clock.now_millis(),
        ));
        if let Ok(mut map) = self.tenants.write() {
            map.insert(tenant.clone(), scope);
        }
    }

    /// Configure a principal scope.
    pub fn configure_principal(&self, principal: &PrincipalId, limits: ScopeLimits) {
        let scope = Arc::new(Scope::new(
            format!("principal:{principal}"),
            limits,
            self.clock.now_millis(),
        ));
        if let Ok(mut map) = self.principals.write() {
            map.insert(principal.clone(), scope);
        }
    }

    /// Configure an alias scope, optionally qualified by operation.
    ///
    /// Specification 12's admission table has five layers, and this is the
    /// "Alias/model" one: "operation-specific request/token and context
    /// limits". It sits between the principal and the target because an alias
    /// is what the caller asked for and a target is what they got — a limit on
    /// `code` should hold however the router resolves it.
    ///
    /// `operation` of `None` covers every operation on that alias. A quota that
    /// names one is preferred over one that does not, so an operator can cap
    /// embeddings separately from chat without repeating the rest.
    pub fn configure_alias(
        &self,
        alias: &AliasId,
        operation: Option<Operation>,
        limits: ScopeLimits,
    ) {
        let name = operation.map_or_else(
            || format!("alias:{alias}"),
            |op| format!("alias:{alias}:{}", op.as_str()),
        );
        let scope = Arc::new(Scope::new(name, limits, self.clock.now_millis()));
        if let Ok(mut map) = self.aliases.write() {
            map.insert((alias.clone(), operation), scope);
        }
    }

    /// An alias's scope for one operation, if configured.
    ///
    /// The operation-specific entry wins over the alias-wide one; there is no
    /// merging, because two limits that both applied would make the effective
    /// ceiling depend on which was checked first.
    #[must_use]
    pub fn alias_scope(&self, alias: &AliasId, operation: Operation) -> Option<Arc<Scope>> {
        let map = self.aliases.read().ok()?;
        map.get(&(alias.clone(), Some(operation)))
            .or_else(|| map.get(&(alias.clone(), None)))
            .cloned()
    }

    /// Configure a target scope.
    pub fn configure_target(&self, target: &TargetId, limits: ScopeLimits) {
        let scope = Arc::new(Scope::new(
            format!("target:{target}"),
            limits,
            self.clock.now_millis(),
        ));
        if let Ok(mut map) = self.targets.write() {
            map.insert(target.clone(), scope);
        }
    }

    /// Configure the global byte-rate limits.
    ///
    /// Specification 12 puts "input bytes/s, output bytes/s" at the **Global**
    /// layer and nowhere else, so this is a property of the controller rather
    /// than of every scope. Zero on either side leaves that direction
    /// unlimited.
    ///
    /// This is the limit that catches what a request-rate limit cannot: a
    /// modest number of very large requests. `max_body_bytes` bounds any single
    /// one, and the request rate bounds how many arrive, but neither bounds
    /// their product.
    pub fn configure_byte_rates(
        &self,
        input_per_second: u64,
        input_burst: u64,
        output_per_second: u64,
        output_burst: u64,
    ) {
        let now = self.clock.now_millis();
        if let Ok(mut slot) = self.inbound_bytes.write() {
            *slot = (input_per_second > 0)
                .then(|| TokenBucket::per_second(input_per_second, input_burst, now));
        }
        if let Ok(mut slot) = self.outbound_bytes.write() {
            *slot = (output_per_second > 0)
                .then(|| TokenBucket::per_second(output_per_second, output_burst, now));
        }
    }

    /// Charge `inbound` bytes against the global input-rate limit.
    ///
    /// Checked before a reservation is taken, so an overloaded byte budget
    /// refuses without any narrower bookkeeping to unwind.
    ///
    /// # Errors
    ///
    /// [`Rejection::ByteRateExceeded`] when the bucket is empty.
    pub fn try_admit_bytes(&self, inbound: u64, now_ms: u64) -> Result<(), Rejection> {
        let Ok(bucket) = self.inbound_bytes.read() else {
            return Ok(());
        };
        match bucket.as_ref() {
            Some(bucket) if !bucket.try_take(inbound, now_ms) => Err(Rejection::ByteRateExceeded),
            _ => Ok(()),
        }
    }

    /// Charge `outbound` bytes against the global output-rate limit.
    ///
    /// Charged after the response rather than checked before it: the size of a
    /// completion is not known until it has been produced. So this throttles
    /// *subsequent* requests rather than truncating the current one — which is
    /// the only correct direction, since cutting a response mid-stream to
    /// satisfy a rate limit would corrupt it.
    pub fn record_output_bytes(&self, outbound: u64, now_ms: u64) {
        if let Ok(bucket) = self.outbound_bytes.read() {
            if let Some(bucket) = bucket.as_ref() {
                let _ = bucket.try_take(outbound, now_ms);
            }
        }
    }

    /// Record actual spend against every scope a request passed through.
    ///
    /// Walks the same chain `reserve_for` builds, so a budget is charged at
    /// exactly the levels that admitted the request. Each level is an
    /// independent ceiling — a tenant budget and an alias budget both count
    /// what flowed through them — which is the same shape as the concurrency
    /// accounting one layer up.
    ///
    /// Called after the response, with cost derived from provider-reported
    /// usage rather than from the admission-time estimate: the byte-based
    /// estimator over-counts by roughly a factor of two (`DI-048`), and a
    /// budget enforced on it would refuse a tenant at half their allowance.
    pub fn record_spend(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: Option<&TargetId>,
        minor_units: u64,
        now_ms: u64,
    ) {
        if minor_units == 0 {
            return;
        }
        self.global.record_spend(minor_units, now_ms);
        self.tenant_scope(tenant).record_spend(minor_units, now_ms);
        self.principal_scope(principal)
            .record_spend(minor_units, now_ms);
        if let Some((id, operation)) = alias {
            if let Some(scope) = self.alias_scope(id, operation) {
                scope.record_spend(minor_units, now_ms);
            }
        }
        if let Some(scope) = target.and_then(|t| self.target_scope(t)) {
            scope.record_spend(minor_units, now_ms);
        }
    }

    /// The global scope.
    #[must_use]
    pub fn global(&self) -> &Arc<Scope> {
        &self.global
    }

    /// A target's scope, if configured.
    #[must_use]
    pub fn target_scope(&self, target: &TargetId) -> Option<Arc<Scope>> {
        self.targets.read().ok()?.get(target).cloned()
    }

    /// Whether a target has any concurrency left, for the routing filter.
    #[must_use]
    pub fn target_has_capacity(&self, target: &TargetId) -> bool {
        self.target_scope(target)
            .is_none_or(|s| s.has_capacity())
    }

    /// A tenant's scope, if one exists yet.
    ///
    /// Deliberately not the internal [`Self::tenant_scope`], which creates one
    /// on demand: a management read must not bring a scope into existence. A
    /// scope created by a reader would start its budget period at the moment
    /// somebody opened a dashboard rather than at the tenant's first request,
    /// which moves the reset of a spend limit to whoever looks at it.
    ///
    /// `None` therefore means "this tenant has not been admitted yet", and the
    /// limits that *would* apply are [`Self::default_tenant_limits`].
    #[must_use]
    pub fn configured_tenant_scope(&self, tenant: &TenantId) -> Option<Arc<Scope>> {
        self.tenants.read().ok()?.get(tenant).cloned()
    }

    /// A principal's scope, if one exists yet.
    ///
    /// Like [`Self::configured_tenant_scope`], a read that never creates one.
    #[must_use]
    pub fn configured_principal_scope(&self, principal: &PrincipalId) -> Option<Arc<Scope>> {
        self.principals.read().ok()?.get(principal).cloned()
    }

    /// The limits a tenant with no explicit configuration is admitted under.
    #[must_use]
    pub const fn default_tenant_limits(&self) -> ScopeLimits {
        self.default_tenant_limits
    }

    fn tenant_scope(&self, tenant: &TenantId) -> Arc<Scope> {
        if let Ok(map) = self.tenants.read() {
            if let Some(s) = map.get(tenant) {
                return Arc::clone(s);
            }
        }
        let scope = Arc::new(Scope::new(
            format!("tenant:{tenant}"),
            self.default_tenant_limits,
            self.clock.now_millis(),
        ));
        if let Ok(mut map) = self.tenants.write() {
            return Arc::clone(map.entry(tenant.clone()).or_insert(scope));
        }
        scope
    }

    fn principal_scope(&self, principal: &PrincipalId) -> Arc<Scope> {
        if let Ok(map) = self.principals.read() {
            if let Some(s) = map.get(principal) {
                return Arc::clone(s);
            }
        }
        let scope = Arc::new(Scope::new(
            format!("principal:{principal}"),
            self.default_principal_limits,
            self.clock.now_millis(),
        ));
        if let Ok(mut map) = self.principals.write() {
            return Arc::clone(map.entry(principal.clone()).or_insert(scope));
        }
        scope
    }

    /// Reserve capacity atomically across every applicable scope.
    ///
    /// Either every scope admits the request and a [`Reservation`] is returned,
    /// or none of them holds anything and the first rejection is reported.
    pub fn reserve(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        target: &TargetId,
        estimated_tokens: u64,
    ) -> Result<Reservation, (Rejection, String)> {
        self.reserve_for(tenant, principal, None, target, estimated_tokens)
    }

    /// `reserve`, including the alias layer of specification 12's table.
    ///
    /// Separate from [`Self::reserve`] rather than replacing it: an alias scope
    /// only participates when one is configured, so every existing caller and
    /// every existing test keeps its exact behaviour, and that is checkable
    /// rather than asserted.
    pub fn reserve_for(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
        estimated_tokens: u64,
    ) -> Result<Reservation, (Rejection, String)> {
        self.acquire_chain(
            tenant,
            principal,
            alias,
            target,
            estimated_tokens,
            None,
            MemoryAsk::Take {
                class: PriorityClass::Standard,
                key: None,
            },
        )
    }

    /// Every scope a request passes through, widest to narrowest.
    ///
    /// One function, used by the first attempt, by the queued retry, and by
    /// the lookup that decides which scope to queue on, so the three cannot
    /// disagree about which layers apply. They used to be three hand-written
    /// lists, and the queued retry's omitted the alias layer — a request that
    /// had waited in line was admitted past the alias's limits.
    fn chain(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
    ) -> Vec<Arc<Scope>> {
        // Widest to narrowest, so a global overload is rejected before any
        // narrower bookkeeping happens.
        let mut chain: Vec<Arc<Scope>> = vec![
            Arc::clone(&self.global),
            self.tenant_scope(tenant),
            self.principal_scope(principal),
        ];
        // Between principal and target: an alias is what the caller asked for,
        // a target is what the router chose.
        if let Some((id, operation)) = alias {
            if let Some(scope) = self.alias_scope(id, operation) {
                chain.push(scope);
            }
        }
        if let Some(t) = self.target_scope(target) {
            chain.push(t);
        }
        chain
    }

    /// Acquire across the whole chain, all or nothing.
    ///
    /// `holder` is a queue ticket and the scope it is honoured at, for a
    /// request that has waited its turn; `memory` is how the target's machine
    /// memory is taken.
    #[allow(
        clippy::too_many_arguments,
        reason = "the chain's layers plus how it is held; a struct would hide which one a caller forgot"
    )]
    fn acquire_chain(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
        estimated_tokens: u64,
        holder: Option<(&Arc<Scope>, u64)>,
        memory: MemoryAsk<'_>,
    ) -> Result<Reservation, (Rejection, String)> {
        let now = self.clock.now_millis();
        let chain = self.chain(tenant, principal, alias, target);

        let mut held: Vec<Arc<Scope>> = Vec::with_capacity(chain.len());
        for scope in chain {
            let ticket = holder
                .and_then(|(queued, ticket)| (queued.name == scope.name).then_some(ticket));
            match scope.try_acquire_as(estimated_tokens, now, ticket) {
                Ok(()) => held.push(scope),
                Err(rejection) => {
                    let name = scope.name.clone();
                    // Roll back everything acquired so far, in full. Without
                    // this, a rejection at the target layer would leak a slot
                    // — and request and token budget — in the global and
                    // tenant layers on every attempt.
                    for acquired in held.iter().rev() {
                        acquired.rollback(estimated_tokens);
                    }
                    return Err((rejection, name));
                }
            }
        }

        // Memory last: it is the scarcest thing, and the narrowest. A request
        // refused by its tenant's quota must not have held a machine's memory
        // even for the moment it took to find out.
        let machine = match memory {
            MemoryAsk::Held(hold) => Some(hold),
            MemoryAsk::Take { class, key } => match self.machine_for(target, class) {
                None => None,
                Some((ledger, bytes, class)) => {
                    match ledger.try_hold(target, bytes, class, key, now) {
                        Ok(hold) => Some(hold),
                        Err(crate::machine::Refused) => {
                            for acquired in held.iter().rev() {
                                acquired.rollback(estimated_tokens);
                            }
                            return Err((Rejection::MemoryExhausted, ledger.name.clone()));
                        }
                    }
                }
            },
        };

        Ok(Reservation {
            scopes: held,
            reserved_tokens: estimated_tokens,
            released: AtomicBool::new(false),
            clock: Arc::clone(&self.clock),
            target: target.clone(),
            machine,
        })
    }

    /// Reserve, waiting in a fair queue when a scope is at its concurrency
    /// limit.
    ///
    /// Specification 3.2 lists queued requests as a bounded resource "per
    /// target and principal; finite; queue timeout mandatory", and
    /// specification 12 sets the order. `budget` is that mandatory timeout; it
    /// must already be the smaller of the configured queue timeout and what
    /// remains of the request deadline, so that specification 12's "requests
    /// past deadline are removed without invoking the provider" holds.
    ///
    /// Only concurrency exhaustion queues. A rate-limit rejection has no event
    /// to wake on — nothing frees a token bucket except the passage of time —
    /// so waiting on one would be a sleep dressed up as admission control, and
    /// the caller is better told to retry.
    ///
    /// Returns the reservation and how long it waited, or the rejection and the
    /// name of the scope that produced it.
    pub fn reserve_queued(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        target: &TargetId,
        estimated_tokens: u64,
        class: PriorityClass,
        budget: std::time::Duration,
    ) -> Result<(Reservation, u64), (Rejection, String)> {
        self.reserve_queued_for(
            tenant,
            principal,
            None,
            target,
            estimated_tokens,
            class,
            budget,
        )
    }

    /// `reserve_queued`, including specification 12's alias layer.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is one admission layer or one queue parameter; \
                  bundling them into a struct would hide which layer a caller forgot"
    )]
    pub fn reserve_queued_for(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
        estimated_tokens: u64,
        class: PriorityClass,
        budget: std::time::Duration,
    ) -> Result<(Reservation, u64), (Rejection, String)> {
        self.reserve_queued_as(
            tenant,
            principal,
            alias,
            target,
            estimated_tokens,
            class,
            budget,
            None,
        )
    }

    /// `reserve_queued_for`, as the holder of machine claim `key`.
    ///
    /// A job passes its own stable identifier: with no budget to wait, a pass
    /// refused for memory leaves a claim under that key, and the job's next
    /// pass holds its place in line by presenting it again
    /// ([`crate::machine`]). A request that can wait waits on the machine
    /// itself, as `key` or under a name of its own.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is one admission layer or one queue parameter; \
                  bundling them into a struct would hide which layer a caller forgot"
    )]
    pub fn reserve_queued_as(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
        estimated_tokens: u64,
        class: PriorityClass,
        budget: std::time::Duration,
        key: Option<&str>,
    ) -> Result<(Reservation, u64), (Rejection, String)> {
        let take = MemoryAsk::Take { class, key };
        let first = self.acquire_chain(tenant, principal, alias, target, estimated_tokens, None, take);
        match first {
            Ok(reservation) => Ok((reservation, 0)),
            Err((Rejection::MemoryExhausted, name)) => {
                let Some((ledger, bytes, machine_class)) = self.machine_for(target, class) else {
                    return Err((Rejection::MemoryExhausted, name));
                };
                if budget.is_zero() {
                    if let Some(key) = key {
                        ledger.claim(key, machine_class, bytes, self.clock.now_millis());
                    }
                    return Err((Rejection::MemoryExhausted, name));
                }
                let own;
                let key = if let Some(key) = key {
                    key
                } else {
                    own = format!("wait-{}", self.next_wait.fetch_add(1, Ordering::SeqCst));
                    own.as_str()
                };
                let started = std::time::Instant::now();
                let clock = Arc::clone(&self.clock);
                let hold = ledger
                    .hold_waiting(target, bytes, machine_class, key, budget, &|| clock.now_millis())
                    .map_err(|crate::machine::Refused| (Rejection::QueueTimeout, name))?;
                let waited = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                self.acquire_chain(
                    tenant,
                    principal,
                    alias,
                    target,
                    estimated_tokens,
                    None,
                    MemoryAsk::Held(hold),
                )
                .map(|reservation| (reservation, waited))
            }
            Err((Rejection::ConcurrencyExhausted, name)) => {
                let Some(scope) = self.scope_named(&name, tenant, principal, alias, target) else {
                    return Err((Rejection::ConcurrencyExhausted, name));
                };
                if scope.limits().max_queued == 0 || budget.is_zero() {
                    return Err((Rejection::ConcurrencyExhausted, name));
                }
                let ticket = match scope.join_queue(class, tenant) {
                    Ok(ticket) => ticket,
                    Err(rejection) => return Err((rejection, name)),
                };
                // A guard rather than a bare call, because every exit below —
                // success, timeout, a rejection from a different scope — must
                // leave the line. A waiter left behind blocks the head
                // computation for everyone after it.
                let ticket = QueuedTicket {
                    scope: &scope,
                    ticket,
                };

                let started = std::time::Instant::now();
                let mut remaining = budget;
                loop {
                    if !ticket.scope.wait_for_turn(ticket.ticket, remaining) {
                        return Err((Rejection::QueueTimeout, name));
                    }
                    let waited = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    match self.acquire_chain(
                        tenant,
                        principal,
                        alias,
                        target,
                        estimated_tokens,
                        Some((&scope, ticket.ticket)),
                        MemoryAsk::Take { class, key },
                    ) {
                        Ok(reservation) => return Ok((reservation, waited)),
                        Err((Rejection::ConcurrencyExhausted, again)) if again == name => {
                            // Lost the slot between the wake and the acquire.
                            // Keep the place in line and wait out the rest of
                            // the budget rather than starting over at the back.
                            remaining = budget.saturating_sub(started.elapsed());
                            if remaining.is_zero() {
                                return Err((Rejection::QueueTimeout, name));
                            }
                        }
                        Err(other) => return Err(other),
                    }
                }
            }
            Err(other) => Err(other),
        }
    }

    /// The scope a rejection named, so the caller can queue on it.
    ///
    /// Searches the same chain the reservation walked, alias layer included,
    /// so a concurrency limit on an alias can queue like any other.
    fn scope_named(
        &self,
        name: &str,
        tenant: &TenantId,
        principal: &PrincipalId,
        alias: Option<(&AliasId, Operation)>,
        target: &TargetId,
    ) -> Option<Arc<Scope>> {
        self.chain(tenant, principal, alias, target)
            .into_iter()
            .find(|scope| scope.name == name)
    }
}

/// Bring one layer's scopes in line with `planned`.
///
/// `fallback` is what a scope the plan no longer names is reconfigured to;
/// `None` drops it from the lookup instead.
fn apply_layer<K: Ord + Clone>(
    layer: &RwLock<BTreeMap<K, Arc<Scope>>>,
    planned: &BTreeMap<K, ScopeLimits>,
    fallback: Option<ScopeLimits>,
    name: impl Fn(&K) -> String,
    now_ms: u64,
) {
    let mut map = match layer.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    match fallback {
        Some(limits) => {
            for (key, scope) in map.iter() {
                if !planned.contains_key(key) {
                    scope.reconfigure(limits, now_ms);
                }
            }
        }
        None => map.retain(|key, _| planned.contains_key(key)),
    }
    for (key, limits) in planned {
        match map.get(key) {
            Some(scope) => scope.reconfigure(*limits, now_ms),
            None => {
                map.insert(key.clone(), Arc::new(Scope::new(name(key), *limits, now_ms)));
            }
        }
    }
}

/// A held place in a scope's queue, given up on every exit path.
struct QueuedTicket<'a> {
    scope: &'a Arc<Scope>,
    ticket: u64,
}

impl Drop for QueuedTicket<'_> {
    fn drop(&mut self) {
        self.scope.leave_queue(self.ticket);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_global_byte_rate_bounds_what_a_request_rate_cannot() {
        // Specification 12's Global layer lists "input bytes/s, output bytes/s"
        // alongside requests/s (`DI-053`). They are not the same control: a
        // request-rate limit bounds how many calls arrive and `max_body_bytes`
        // bounds any one of them, but neither bounds their product — a modest
        // number of very large requests passes both.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        controller.configure_byte_rates(1_000, 1_000, 0, 0);

        assert!(controller.try_admit_bytes(600, clock.now_millis()).is_ok());
        assert!(controller.try_admit_bytes(400, clock.now_millis()).is_ok());
        assert_eq!(
            controller.try_admit_bytes(400, clock.now_millis()),
            Err(Rejection::ByteRateExceeded),
            "the byte bucket did not bound the total"
        );

        // It refills over time rather than latching.
        clock.advance(1_000);
        assert!(controller.try_admit_bytes(400, clock.now_millis()).is_ok());
    }

    #[test]
    fn byte_rates_are_unlimited_until_configured() {
        // Inert unless asked for, like every other limit here.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        for _ in 0..100 {
            assert!(
                controller
                    .try_admit_bytes(u64::MAX, clock.now_millis())
                    .is_ok(),
                "an unconfigured byte rate refused a request"
            );
        }
        // And recording output against an unconfigured bucket does nothing.
        controller.record_output_bytes(u64::MAX, clock.now_millis());
        assert!(controller.try_admit_bytes(1, clock.now_millis()).is_ok());
    }

    #[test]
    fn the_output_byte_rate_is_charged_separately_from_the_input_one() {
        // Two directions, two buckets: a large download must not consume the
        // allowance for reading requests, or one heavy streaming client would
        // stop the router accepting anything at all.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        controller.configure_byte_rates(1_000, 1_000, 1_000, 1_000);

        controller.record_output_bytes(5_000, clock.now_millis());
        assert!(
            controller.try_admit_bytes(500, clock.now_millis()).is_ok(),
            "output traffic consumed the input allowance"
        );
    }

    #[test]
    fn a_budget_refuses_once_the_period_spend_is_reached_and_clears_when_it_rolls() {
        // Specification 12 gives the tenant layer a "daily/monthly budget
        // class" and specification 11.1 lists "budget limits" on a `quota`
        // (`DI-053`). Charged from actual provider-reported cost, so the
        // ceiling means what it says.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = controller(
            Arc::clone(&clock),
            ScopeLimits {
                budget_minor_units: 1_000,
                budget_period: BudgetPeriod::Daily,
                ..ScopeLimits::UNLIMITED
            },
        );

        // Under budget: admitted.
        let first = controller
            .reserve(&tenant(), &principal(), &target(), 1)
            .expect("under budget");
        drop(first);

        // Spend up to the ceiling.
        controller.record_spend(
            &tenant(),
            &principal(),
            None,
            Some(&target()),
            1_000,
            clock.now_millis(),
        );

        let refused = controller.reserve(&tenant(), &principal(), &target(), 1);
        assert!(
            matches!(refused, Err((Rejection::BudgetExhausted, _))),
            "a scope past its budget was still admitted: {refused:?}"
        );

        // It does not clear when load drops — only when the period rolls. That
        // is the difference between this and the rate rejections, and it is why
        // it has its own variant: an operator seeing it needs to raise the
        // budget or wait, not add capacity.
        clock.advance(BudgetPeriod::Daily.millis() - 1);
        assert!(
            controller
                .reserve(&tenant(), &principal(), &target(), 1)
                .is_err(),
            "the budget cleared before its period elapsed"
        );

        clock.advance(2);
        assert!(
            controller
                .reserve(&tenant(), &principal(), &target(), 1)
                .is_ok(),
            "the budget did not clear when the period rolled"
        );
    }

    #[test]
    fn a_scope_with_no_budget_never_consults_the_ledger() {
        // The overwhelmingly common case. A budget of zero means "no budget",
        // consistent with every other limit here, and spend recorded against a
        // scope that has none must never refuse anything.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);

        controller.record_spend(
            &tenant(),
            &principal(),
            None,
            Some(&target()),
            u64::MAX,
            clock.now_millis(),
        );
        for _ in 0..20 {
            let reservation = controller
                .reserve(&tenant(), &principal(), &target(), 1)
                .expect("an unbudgeted scope must not refuse");
            drop(reservation);
        }
    }

    #[test]
    fn spend_saturates_rather_than_wrapping_back_under_budget() {
        // A wrapped total would put a scope that had spent an enormous amount
        // back under its ceiling — the budget silently resetting itself, which
        // is the one failure mode a spend cap must not have.
        let clock = Arc::new(crate::time::TestClock::new());
        let scope = Scope::new(
            "test",
            ScopeLimits {
                budget_minor_units: 100,
                ..ScopeLimits::UNLIMITED
            },
            clock.now_millis(),
        );
        scope.record_spend(u64::MAX, clock.now_millis());
        scope.record_spend(u64::MAX, clock.now_millis());
        assert_eq!(scope.spent_this_period(clock.now_millis()), u64::MAX);
        assert!(scope.try_acquire(1, clock.now_millis()).is_err());
    }

    #[test]
    fn an_alias_quota_limits_what_the_caller_asked_for_not_what_was_chosen() {
        // Specification 12's admission table has five layers and the
        // implementation had four scopes; this is the "Alias/model" one,
        // carrying "operation-specific request/token and context limits".
        //
        // It sits between principal and target because an alias is what the
        // caller controls and a target is what the router picks. A limit
        // attached only to targets is spread across however many the alias
        // resolves to, so an alias with three targets and a per-target cap of
        // two admits six.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = AdmissionController::new(clock, ScopeLimits::UNLIMITED);
        let alias = AliasId::new("code").expect("alias");
        controller.configure_alias(
            &alias,
            None,
            ScopeLimits {
                max_concurrency: 2,
                ..ScopeLimits::UNLIMITED
            },
        );

        let held: Vec<_> = ["a", "b"]
            .iter()
            .map(|name| {
                let target = TargetId::new(&format!("p:{name}")).expect("target");
                controller
                    .reserve_for(
                        &tenant(),
                        &principal(),
                        Some((&alias, Operation::Chat)),
                        &target,
                        1,
                    )
                    .expect("within the alias limit")
            })
            .collect();

        // A third request against a *different* target is still refused: the
        // limit is on the alias, which is the point.
        let third = TargetId::new("p:c").expect("target");
        let refused = controller.reserve_for(
            &tenant(),
            &principal(),
            Some((&alias, Operation::Chat)),
            &third,
            1,
        );
        assert!(
            matches!(refused, Err((Rejection::ConcurrencyExhausted, _))),
            "a third target evaded the alias limit"
        );

        drop(held);
        assert!(
            controller
                .reserve_for(
                    &tenant(),
                    &principal(),
                    Some((&alias, Operation::Chat)),
                    &third,
                    1
                )
                .is_ok(),
            "releasing the reservations did not free the alias scope"
        );
    }

    #[test]
    fn an_operation_specific_alias_quota_is_preferred_over_the_alias_wide_one() {
        // "Operation-specific" is the specification's word. An operator capping
        // embeddings separately from chat writes a second `quota` line, and the
        // narrower one must win — merging two limits would make the effective
        // ceiling depend on which was checked first.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = AdmissionController::new(clock, ScopeLimits::UNLIMITED);
        let alias = AliasId::new("code").expect("alias");
        controller.configure_alias(
            &alias,
            None,
            ScopeLimits {
                max_concurrency: 10,
                ..ScopeLimits::UNLIMITED
            },
        );
        controller.configure_alias(
            &alias,
            Some(Operation::Embeddings),
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );
        let target = TargetId::new("p:m").expect("target");

        let held = controller
            .reserve_for(
                &tenant(),
                &principal(),
                Some((&alias, Operation::Embeddings)),
                &target,
                1,
            )
            .expect("the first embedding");
        assert!(
            controller
                .reserve_for(
                    &tenant(),
                    &principal(),
                    Some((&alias, Operation::Embeddings)),
                    &target,
                    1
                )
                .is_err(),
            "the embeddings quota did not override the alias-wide one"
        );
        // Chat still gets the wider limit, unaffected.
        assert!(
            controller
                .reserve_for(
                    &tenant(),
                    &principal(),
                    Some((&alias, Operation::Chat)),
                    &target,
                    1
                )
                .is_ok(),
            "an embeddings limit constrained chat"
        );
        drop(held);
    }

    #[test]
    fn an_unconfigured_alias_changes_nothing() {
        // The layer must be inert unless an operator asks for it. This is what
        // makes the addition safe: every existing deployment, and every caller
        // that still uses `reserve`, behaves exactly as before.
        let clock = Arc::new(crate::time::TestClock::new());
        let controller = AdmissionController::new(clock, ScopeLimits::UNLIMITED);
        let alias = AliasId::new("code").expect("alias");
        let target = TargetId::new("p:m").expect("target");

        assert!(controller.alias_scope(&alias, Operation::Chat).is_none());
        for _ in 0..50 {
            let reservation = controller
                .reserve_for(
                    &tenant(),
                    &principal(),
                    Some((&alias, Operation::Chat)),
                    &target,
                    1,
                )
                .expect("an unconfigured alias must not constrain anything");
            drop(reservation);
        }
    }

    #[test]
    fn partitioning_never_lets_the_deployment_exceed_the_configured_limit() {
        // `DI-029`: specification 12 allows "an authoritative allocator **or**
        // conservative node partitions". The property that makes the second
        // one sound is that the *sum* across nodes never exceeds what was
        // configured — otherwise partitioning would quietly raise every limit
        // in the deployment, which is the failure it exists to prevent.
        let limits = ScopeLimits {
            max_concurrency: 10,
            max_queued: 20,
            requests_per_second: 100,
            request_burst: 200,
            tokens_per_minute: 1_000,
            token_burst: 2_000,
            budget_minor_units: 50_000,
            budget_period: BudgetPeriod::Daily,
        };

        for partitions in 1..=16u32 {
            let share = limits.partitioned(partitions);
            let n = u64::from(partitions);
            assert!(
                u64::from(share.max_concurrency) * n <= u64::from(limits.max_concurrency),
                "{partitions} nodes at {} each exceed a limit of {}",
                share.max_concurrency,
                limits.max_concurrency
            );
            assert!(
                u64::from(share.requests_per_second) * n <= u64::from(limits.requests_per_second)
            );
            assert!(share.tokens_per_minute * n <= limits.tokens_per_minute);
            assert!(u64::from(share.max_queued) * n <= u64::from(limits.max_queued));
            // A budget is a limit like any other: N nodes each holding the
            // whole figure would let the deployment spend N times it.
            assert!(
                share.budget_minor_units * n <= limits.budget_minor_units,
                "{partitions} nodes at {} each exceed a budget of {}",
                share.budget_minor_units,
                limits.budget_minor_units
            );
            // And the period is carried through unchanged: dividing a window
            // length would make each node reset on a different schedule.
            assert_eq!(share.budget_period, limits.budget_period);
        }

        // The remainder is the cost: 10 over 3 admits 9, not 12.
        assert_eq!(limits.partitioned(3).max_concurrency, 3);
    }

    #[test]
    fn a_single_partition_changes_nothing() {
        // The overwhelmingly common deployment. Zero and one must both mean
        // "one router", because zero is the "unset" encoding every other
        // setting uses and an operator who never touches this must not have
        // their quotas altered.
        let limits = ScopeLimits {
            max_concurrency: 7,
            max_queued: 3,
            requests_per_second: 11,
            request_burst: 13,
            tokens_per_minute: 17,
            token_burst: 19,
            budget_minor_units: 0,
            budget_period: BudgetPeriod::Daily,
        };
        assert_eq!(limits.partitioned(0), limits);
        assert_eq!(limits.partitioned(1), limits);
    }

    #[test]
    fn unlimited_stays_unlimited_when_partitioned() {
        // Zero encodes "no limit". A share of no limit is still no limit, and
        // dividing must not turn it into a limit of zero — which would admit
        // nothing at all.
        let share = ScopeLimits::UNLIMITED.partitioned(8);
        assert_eq!(share, ScopeLimits::UNLIMITED);
        assert!(share.is_unlimited());
    }

    #[test]
    fn a_limit_smaller_than_the_partition_count_is_reported_rather_than_enforced() {
        // The inversion this guard exists for: zero means unlimited, so a
        // `concurrency=2` split eight ways would divide to zero and become the
        // *loosest* configuration expressible from the tightest one.
        let tight = ScopeLimits {
            max_concurrency: 2,
            ..ScopeLimits::UNLIMITED
        };
        assert!(tight.partition_underflows(8));
        assert!(!tight.partition_underflows(2));
        assert!(!tight.partition_underflows(1));

        // Unlimited never underflows: there is no limit to lose.
        assert!(!ScopeLimits::UNLIMITED.partition_underflows(64));

        // And every limit that can underflow is checked, not just concurrency.
        let rate = ScopeLimits {
            requests_per_second: 3,
            ..ScopeLimits::UNLIMITED
        };
        assert!(rate.partition_underflows(4));
        let tokens = ScopeLimits {
            tokens_per_minute: 3,
            ..ScopeLimits::UNLIMITED
        };
        assert!(tokens.partition_underflows(4));
        let budget = ScopeLimits {
            budget_minor_units: 3,
            ..ScopeLimits::UNLIMITED
        };
        assert!(budget.partition_underflows(4));
        assert!(!budget.partition_underflows(3));
    }
    use super::*;
    use crate::time::TestClock;

    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }
    fn principal() -> PrincipalId {
        PrincipalId::new("user:42").unwrap()
    }
    fn target() -> TargetId {
        TargetId::new("local:qwen").unwrap()
    }

    fn controller(clock: Arc<TestClock>, global: ScopeLimits) -> AdmissionController {
        AdmissionController::new(clock, global)
    }

    // -- Fair queueing ------------------------------------------------------

    fn other_tenant() -> TenantId {
        TenantId::new("globex").unwrap()
    }

    /// The queue order for a set of arrivals, drained head-first.
    fn drain_order(arrivals: &[(PriorityClass, TenantId)]) -> Vec<u64> {
        let limits = ScopeLimits {
            max_concurrency: 1,
            max_queued: 64,
            ..ScopeLimits::UNLIMITED
        };
        let scope = Scope::new("t", limits, 0);
        let mut tickets = Vec::new();
        for (class, tenant) in arrivals {
            tickets.push(scope.join_queue(*class, tenant).expect("room"));
        }
        let mut order = Vec::new();
        while let Some(head) = {
            let guard = scope.queue.lock().expect("lock");
            guard.head()
        } {
            order.push(head);
            scope.leave_queue(head);
        }
        assert_eq!(order.len(), tickets.len());
        order
    }

    #[test]
    fn queue_order_is_fifo_within_one_tenant_and_class() {
        let acme = tenant();
        let order = drain_order(&[
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Standard, acme),
        ]);
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn one_tenants_backlog_does_not_starve_another() {
        // Specification 12: "Queue order is weighted fair by tenant". The
        // failure this prevents: a tenant that submits a hundred requests
        // pushing another tenant's single request a hundred places back.
        let acme = tenant();
        let globex = other_tenant();
        let order = drain_order(&[
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Standard, globex.clone()),
            (PriorityClass::Standard, acme),
            (PriorityClass::Standard, globex),
        ]);
        // acme's first, then globex's first, then acme's second, and so on:
        // the second tenant waits one place, not four.
        assert_eq!(order, vec![0, 3, 1, 5, 2, 4]);
    }

    #[test]
    fn a_higher_class_outranks_an_earlier_arrival() {
        let acme = tenant();
        let order = drain_order(&[
            (PriorityClass::Batch, acme.clone()),
            (PriorityClass::Standard, acme.clone()),
            (PriorityClass::Interactive, acme),
        ]);
        assert_eq!(order, vec![2, 1, 0]);
    }

    #[test]
    fn an_arrival_does_not_barge_past_a_waiting_request() {
        // A queue that lets new arrivals take the freed slot is worse than no
        // queue: the requests that have already waited longest are served last.
        let limits = ScopeLimits {
            max_concurrency: 1,
            max_queued: 4,
            ..ScopeLimits::UNLIMITED
        };
        let scope = Scope::new("t", limits, 0);
        scope.try_acquire(0, 0).expect("the one slot");

        let waiting = scope.join_queue(PriorityClass::Standard, &tenant()).unwrap();
        scope.release(0, 0, 0);

        // A ticketless caller is refused while someone is waiting...
        assert_eq!(
            scope.try_acquire(0, 0),
            Err(Rejection::ConcurrencyExhausted)
        );
        // ...and the waiter gets it.
        assert_eq!(scope.try_acquire_as(0, 0, Some(waiting)), Ok(()));
    }

    #[test]
    fn a_scope_without_a_queue_is_unchanged() {
        // Queueing is opt-in per scope. With `max_queued` at zero nothing
        // joins, nothing yields, and the behaviour is exactly what it was.
        let limits = ScopeLimits {
            max_concurrency: 1,
            max_queued: 0,
            ..ScopeLimits::UNLIMITED
        };
        let scope = Scope::new("t", limits, 0);
        assert_eq!(
            scope.join_queue(PriorityClass::Standard, &tenant()),
            Err(Rejection::ConcurrencyExhausted)
        );
        assert_eq!(scope.try_acquire(0, 0), Ok(()));
        assert_eq!(scope.try_acquire(0, 0), Err(Rejection::ConcurrencyExhausted));
    }

    #[test]
    fn the_queue_is_finite() {
        // Specification 3.2: queued requests are "finite".
        let limits = ScopeLimits {
            max_concurrency: 1,
            max_queued: 2,
            ..ScopeLimits::UNLIMITED
        };
        let scope = Scope::new("t", limits, 0);
        assert!(scope.join_queue(PriorityClass::Standard, &tenant()).is_ok());
        assert!(scope.join_queue(PriorityClass::Standard, &tenant()).is_ok());
        assert_eq!(
            scope.join_queue(PriorityClass::Standard, &tenant()),
            Err(Rejection::QueueFull)
        );
        assert_eq!(scope.queued(), 2);
    }

    #[test]
    fn leaving_the_queue_frees_the_place() {
        let limits = ScopeLimits {
            max_concurrency: 1,
            max_queued: 1,
            ..ScopeLimits::UNLIMITED
        };
        let scope = Scope::new("t", limits, 0);
        let ticket = scope.join_queue(PriorityClass::Standard, &tenant()).unwrap();
        assert_eq!(
            scope.join_queue(PriorityClass::Standard, &tenant()),
            Err(Rejection::QueueFull)
        );
        scope.leave_queue(ticket);
        assert_eq!(scope.queued(), 0);
        assert!(scope.join_queue(PriorityClass::Standard, &tenant()).is_ok());
    }

    #[test]
    fn a_queued_request_is_admitted_when_the_slot_frees() {
        // The end-to-end shape, across threads and with the real clock, since
        // that is the only way the condvar path is exercised.
        let clock = Arc::new(TestClock::new());
        let admission = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        admission.configure_target(
            &target(),
            ScopeLimits {
                max_concurrency: 1,
                max_queued: 4,
                ..ScopeLimits::UNLIMITED
            },
        );

        let held = admission
            .reserve(&tenant(), &principal(), &target(), 0)
            .expect("the one slot");

        let shared = Arc::new(admission);
        let waiter = {
            let admission = Arc::clone(&shared);
            std::thread::spawn(move || {
                admission.reserve_queued(
                    &tenant(),
                    &principal(),
                    &target(),
                    0,
                    PriorityClass::Standard,
                    std::time::Duration::from_secs(5),
                )
            })
        };

        // Give the waiter time to reach the queue, then free the slot.
        for _ in 0..200 {
            if shared
                .target_scope(&target())
                .is_some_and(|s| s.queued() > 0)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        drop(held);

        let (reservation, _waited) = waiter
            .join()
            .expect("thread")
            .expect("the queued request was admitted");
        drop(reservation);
        assert_eq!(
            shared.target_scope(&target()).map(|s| s.queued()),
            Some(0),
            "the waiter must leave the line"
        );
    }

    #[test]
    fn a_queued_request_gives_up_when_its_budget_expires() {
        // Specification 3.2: "queue timeout mandatory".
        let clock = Arc::new(TestClock::new());
        let admission = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        admission.configure_target(
            &target(),
            ScopeLimits {
                max_concurrency: 1,
                max_queued: 4,
                ..ScopeLimits::UNLIMITED
            },
        );
        let _held = admission
            .reserve(&tenant(), &principal(), &target(), 0)
            .expect("the one slot");

        match admission.reserve_queued(
            &tenant(),
            &principal(),
            &target(),
            0,
            PriorityClass::Standard,
            std::time::Duration::from_millis(50),
        ) {
            Err((Rejection::QueueTimeout, _)) => {}
            other => panic!("expected a queue timeout, got {other:?}"),
        }
        assert_eq!(
            admission.target_scope(&target()).map(|s| s.queued()),
            Some(0),
            "a timed-out waiter must still leave the line"
        );
    }

    #[test]
    fn a_zero_budget_does_not_queue_at_all() {
        // A request whose deadline has already passed must be refused without
        // waiting: specification 12's "requests past deadline are removed
        // without invoking the provider".
        let clock = Arc::new(TestClock::new());
        let admission = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        admission.configure_target(
            &target(),
            ScopeLimits {
                max_concurrency: 1,
                max_queued: 4,
                ..ScopeLimits::UNLIMITED
            },
        );
        let _held = admission
            .reserve(&tenant(), &principal(), &target(), 0)
            .expect("the one slot");

        let started = std::time::Instant::now();
        match admission.reserve_queued(
            &tenant(),
            &principal(),
            &target(),
            0,
            PriorityClass::Standard,
            std::time::Duration::ZERO,
        ) {
            Err((Rejection::ConcurrencyExhausted, _)) => {}
            other => panic!("expected an immediate refusal, got {other:?}"),
        }
        assert!(started.elapsed() < std::time::Duration::from_millis(200));
    }

    // -- Token bucket -------------------------------------------------------

    #[test]
    fn bucket_starts_full_and_drains() {
        let b = TokenBucket::per_second(10, 10, 0);
        assert_eq!(b.level(), 10);
        for _ in 0..10 {
            assert!(b.try_take(1, 0));
        }
        assert!(!b.try_take(1, 0), "an empty bucket must refuse");
    }

    #[test]
    fn bucket_refills_over_monotonic_time() {
        let b = TokenBucket::per_second(10, 10, 0);
        for _ in 0..10 {
            assert!(b.try_take(1, 0));
        }
        assert!(!b.try_take(1, 0));
        // Half a second at 10/s is 5 tokens.
        assert!(b.try_take(5, 500));
        assert!(!b.try_take(1, 500));
        // A full second more refills to capacity, not beyond.
        assert!(b.try_take(10, 2000));
        assert!(!b.try_take(1, 2000));
    }

    #[test]
    fn charging_more_than_the_level_drains_to_empty_rather_than_refusing() {
        // `try_take` refuses when short, which is right for admission and wrong
        // for reconciliation: the tokens are already spent by then.
        let b = TokenBucket::per_second(10, 10, 0);
        assert!(b.try_take(5, 0));
        assert_eq!(b.level(), 5);

        b.charge(100, 0);
        assert_eq!(b.level(), 0, "an overage larger than the level must still be charged");

        // And the bucket recovers normally afterwards.
        b.charge(0, 1000);
        assert_eq!(b.level(), 10);
    }

    #[test]
    fn bucket_never_exceeds_capacity() {
        let b = TokenBucket::per_second(10, 10, 0);
        // A very long idle period must not accumulate unbounded credit.
        assert!(b.try_take(10, 1_000_000));
        assert!(!b.try_take(1, 1_000_000));
    }

    #[test]
    fn per_minute_bucket_rate() {
        // 60000 tokens per minute is 1 token per millisecond.
        let b = TokenBucket::per_minute(60_000, 1_000, 0);
        assert!(b.try_take(1_000, 0));
        assert!(!b.try_take(1, 0));
        assert!(b.try_take(500, 500));
    }

    #[test]
    fn per_minute_rates_below_sixty_do_not_refill() {
        // Documents the fixed-point resolution limit on `TokenBucket`: the
        // refill rate is thousandths of a unit per millisecond, so a per-minute
        // rate below 60 truncates to zero and the bucket never refills after
        // its initial burst. This is a known sharp edge, not a desired
        // behaviour — it is pinned here so that widening the fixed-point unit
        // (the fix) breaks this test loudly rather than passing unnoticed, and
        // so that nobody routes a per-minute *request* rate through this
        // constructor believing it refills.
        let b = TokenBucket::per_minute(30, 30, 0);
        assert!(b.try_take(30, 0), "the initial burst is available");
        assert!(!b.try_take(1, 0));
        // A full hour later the bucket is still empty.
        assert!(
            !b.try_take(1, 3_600_000),
            "a sub-60 per-minute rate floors to a zero refill rate"
        );

        // At 60 per minute and above the refill works as intended.
        let ok = TokenBucket::per_minute(60, 60, 0);
        assert!(ok.try_take(60, 0));
        assert!(!ok.try_take(1, 0));
        assert!(ok.try_take(1, 1_000), "one unit per second refills");
    }

    #[test]
    fn refund_is_capped_at_capacity() {
        // The "no negative-cost abuse" property: a refund cannot mint burst.
        let b = TokenBucket::per_second(10, 10, 0);
        b.refund(1_000_000);
        assert_eq!(b.level(), 10);
        assert!(b.try_take(10, 0));
        assert!(!b.try_take(1, 0));
    }

    #[test]
    fn oversized_request_is_admissible_when_the_bucket_is_full() {
        // Otherwise a request larger than the burst could never be admitted and
        // would spin forever against a limit it cannot satisfy.
        let b = TokenBucket::per_second(10, 10, 0);
        assert!(b.try_take(1_000_000, 0));
        assert!(!b.try_take(1, 0));
    }

    // -- Reservation lifecycle ----------------------------------------------

    #[test]
    fn reservation_releases_on_drop() {
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );

        let r = c.reserve(&tenant(), &principal(), &target(), 10).unwrap();
        assert_eq!(c.global().in_flight(), 1);
        assert!(c.reserve(&tenant(), &principal(), &target(), 10).is_err());

        drop(r);
        assert_eq!(c.global().in_flight(), 0);
        assert!(c.reserve(&tenant(), &principal(), &target(), 10).is_ok());
    }

    #[test]
    fn reservation_releases_exactly_once() {
        // Appendix B: "Every reservation is released exactly once on all
        // success, error, timeout, and cancellation paths."
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 4,
                ..ScopeLimits::UNLIMITED
            },
        );

        let r = c.reserve(&tenant(), &principal(), &target(), 10).unwrap();
        assert!(!r.is_released());
        r.commit(8); // explicit release, then Drop runs
        assert_eq!(c.global().in_flight(), 0);

        let (acquired, released) = c.global().conservation();
        assert_eq!(acquired, 1);
        assert_eq!(released, 1, "commit followed by drop must release once");
    }

    #[test]
    fn conservation_holds_across_many_lifecycles() {
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 8,
                ..ScopeLimits::UNLIMITED
            },
        );

        for i in 0..200u64 {
            let r = c.reserve(&tenant(), &principal(), &target(), 10).unwrap();
            if i % 3 == 0 {
                r.commit(5); // success path
            } else if i % 3 == 1 {
                drop(r); // error or cancellation path
            } else {
                r.commit(20); // usage exceeded the estimate
            }
        }
        assert_eq!(c.global().in_flight(), 0);
        let (acquired, released) = c.global().conservation();
        assert_eq!(acquired, released);
        assert_eq!(acquired, 200);
    }

    #[test]
    fn rejection_rolls_back_wider_scopes() {
        // The leak this prevents: a target-layer rejection must not consume a
        // slot in the global and tenant layers.
        let clock = Arc::new(TestClock::new());
        let c = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        c.configure_target(
            &target(),
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );

        let held = c.reserve(&tenant(), &principal(), &target(), 1).unwrap();
        assert_eq!(c.global().in_flight(), 1);

        for _ in 0..50 {
            assert!(c.reserve(&tenant(), &principal(), &target(), 1).is_err());
        }
        assert_eq!(
            c.global().in_flight(),
            1,
            "rejected attempts must not accumulate in the global scope"
        );

        drop(held);
        assert_eq!(c.global().in_flight(), 0);
    }

    #[test]
    fn token_rate_rejection_rolls_back_the_request_bucket() {
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                requests_per_second: 100,
                request_burst: 100,
                tokens_per_minute: 60,
                token_burst: 1,
                max_concurrency: 0,
                max_queued: 0,
                budget_minor_units: 0,
                budget_period: BudgetPeriod::Daily,
            },
        );
        // First takes the single token of burst.
        let r = c.reserve(&tenant(), &principal(), &target(), 1).unwrap();
        // Second is refused for tokens, not requests.
        let (rejection, _) = c.reserve(&tenant(), &principal(), &target(), 1).unwrap_err();
        assert_eq!(rejection, Rejection::TokenRateExceeded);
        assert_eq!(c.global().in_flight(), 1, "only the held reservation counts");
        drop(r);
    }

    // -- Hierarchy ----------------------------------------------------------

    #[test]
    fn every_layer_can_reject_independently() {
        let clock = Arc::new(TestClock::new());

        // Tenant layer.
        let c = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        c.configure_tenant(
            &tenant(),
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );
        let _held = c.reserve(&tenant(), &principal(), &target(), 1).unwrap();
        let (rejection, scope) = c.reserve(&tenant(), &principal(), &target(), 1).unwrap_err();
        assert_eq!(rejection, Rejection::ConcurrencyExhausted);
        assert_eq!(scope, "tenant:acme");

        // Principal layer.
        let c = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        c.configure_principal(
            &principal(),
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );
        let _held = c.reserve(&tenant(), &principal(), &target(), 1).unwrap();
        let (_, scope) = c.reserve(&tenant(), &principal(), &target(), 1).unwrap_err();
        assert_eq!(scope, "principal:user:42");
    }

    #[test]
    fn one_tenant_cannot_exhaust_another() {
        // Specification 2.1: "Prevent one tenant, user, provider, or slow
        // client from exhausting global capacity."
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 100,
                ..ScopeLimits::UNLIMITED
            },
        );
        let noisy = TenantId::new("noisy").unwrap();
        let quiet = TenantId::new("quiet").unwrap();
        c.configure_tenant(
            &noisy,
            ScopeLimits {
                max_concurrency: 2,
                ..ScopeLimits::UNLIMITED
            },
        );
        c.configure_tenant(
            &quiet,
            ScopeLimits {
                max_concurrency: 2,
                ..ScopeLimits::UNLIMITED
            },
        );

        let _a = c.reserve(&noisy, &principal(), &target(), 1).unwrap();
        let _b = c.reserve(&noisy, &principal(), &target(), 1).unwrap();
        assert!(c.reserve(&noisy, &principal(), &target(), 1).is_err());

        // The quiet tenant is unaffected.
        assert!(c.reserve(&quiet, &principal(), &target(), 1).is_ok());
    }

    #[test]
    fn defaults_apply_to_unconfigured_scopes() {
        let clock = Arc::new(TestClock::new());
        let mut c = controller(Arc::clone(&clock), ScopeLimits::UNLIMITED);
        c.set_default_tenant_limits(ScopeLimits {
            max_concurrency: 1,
            ..ScopeLimits::UNLIMITED
        });

        let unknown = TenantId::new("brand-new").unwrap();
        let _held = c.reserve(&unknown, &principal(), &target(), 1).unwrap();
        assert!(c.reserve(&unknown, &principal(), &target(), 1).is_err());
    }

    // -- Reconciliation -----------------------------------------------------

    #[test]
    fn under_estimate_is_refunded() {
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                tokens_per_minute: 6_000,
                token_burst: 1_000,
                ..ScopeLimits::UNLIMITED
            },
        );

        // Reserve 1000, use 100: 900 come back.
        let r = c.reserve(&tenant(), &principal(), &target(), 1000).unwrap();
        r.commit(100);
        // The bucket should now hold roughly the refund.
        assert!(c.global().request_bucket.read().unwrap().is_none());
        // Another 900-token request fits immediately.
        assert!(c.reserve(&tenant(), &principal(), &target(), 900).is_ok());
    }

    #[test]
    fn over_estimate_is_charged() {
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                tokens_per_minute: 60,
                token_burst: 1_000,
                ..ScopeLimits::UNLIMITED
            },
        );
        let r = c.reserve(&tenant(), &principal(), &target(), 10).unwrap();
        // Actual usage of 1000 against a 10-token estimate must drain the
        // bucket rather than being ignored.
        r.commit(1000);
        let (rejection, _) = c
            .reserve(&tenant(), &principal(), &target(), 500)
            .unwrap_err();
        assert_eq!(rejection, Rejection::TokenRateExceeded);
    }

    #[test]
    fn charging_an_over_estimate_does_not_freeze_the_bucket() {
        // The overage charge used to pass `u64::MAX` as the current time. That
        // broke the bucket twice: the refill preceding the charge credited an
        // enormous interval, so the charge came out of a full bucket and cost
        // nothing real; and it left `last_ms` at the sentinel, so every later
        // refill saw zero elapsed time and the scope never recovered.
        //
        // `over_estimate_is_charged` did not catch it because refilling to
        // capacity and then draining happens to leave the same level as not
        // refilling at all when the clock reads zero.
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                tokens_per_minute: 6_000, // 100 per second
                token_burst: 1_000,
                ..ScopeLimits::UNLIMITED
            },
        );

        let r = c.reserve(&tenant(), &principal(), &target(), 100).unwrap();
        r.commit(1_100);

        // The overage drained the bucket, so a large request is refused now.
        assert_eq!(
            c.reserve(&tenant(), &principal(), &target(), 500).unwrap_err().0,
            Rejection::TokenRateExceeded
        );

        // Ten seconds at 100 tokens per second refills the bucket.
        clock.advance(10_000);
        assert!(
            c.reserve(&tenant(), &principal(), &target(), 500).is_ok(),
            "the bucket must still refill after an overage charge"
        );
    }

    #[test]
    fn an_overage_is_charged_against_the_bucket_as_it_stands() {
        // With a real clock the charge is taken from the level the scope
        // actually has, not from a bucket the charge itself refilled.
        let clock = Arc::new(TestClock::new());
        let c = controller(
            Arc::clone(&clock),
            ScopeLimits {
                tokens_per_minute: 60, // 1 per second
                token_burst: 1_000,
                ..ScopeLimits::UNLIMITED
            },
        );

        // Drain most of the burst, then overspend on top of it.
        let first = c.reserve(&tenant(), &principal(), &target(), 900).unwrap();
        first.commit(900);
        let second = c.reserve(&tenant(), &principal(), &target(), 50).unwrap();
        second.commit(150);

        // 900 + 150 = 1050 against a 1000 burst with no time elapsed, so
        // nothing further fits.
        assert!(c.reserve(&tenant(), &principal(), &target(), 100).is_err());
    }

    // -- Queue --------------------------------------------------------------

    #[test]
    fn a_scope_without_a_queue_refuses_to_enqueue() {
        let scope = Scope::new("q", ScopeLimits::UNLIMITED, 0);
        assert_eq!(
            scope.join_queue(PriorityClass::Standard, &tenant()),
            Err(Rejection::ConcurrencyExhausted)
        );
    }

    // -- Mapping ------------------------------------------------------------

    #[test]
    fn rejections_map_to_the_error_contract() {
        assert_eq!(
            Rejection::ConcurrencyExhausted.error_code(),
            crate::error::ErrorCode::CapacityExhausted
        );
        assert_eq!(
            Rejection::RequestRateExceeded.error_code(),
            crate::error::ErrorCode::RateLimited
        );
        assert_eq!(
            Rejection::QueueFull.exclusion_reason(),
            ExclusionReason::CapacityExhausted
        );
        assert_eq!(
            Rejection::TokenRateExceeded.exclusion_reason(),
            ExclusionReason::BudgetExceeded
        );
        // Both map to 429, per specification 8.2.
        assert_eq!(Rejection::ConcurrencyExhausted.error_code().status(), 429);
        assert_eq!(Rejection::RequestRateExceeded.error_code().status(), 429);
    }

    #[test]
    fn concurrent_reservations_do_not_oversubscribe() {
        use std::thread;

        let clock = Arc::new(TestClock::new());
        let c = Arc::new(controller(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 10,
                ..ScopeLimits::UNLIMITED
            },
        ));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..20 {
                    if let Ok(r) = c.reserve(&tenant(), &principal(), &target(), 1) {
                        held.push(r);
                    }
                }
                assert!(
                    c.global().in_flight() <= 10,
                    "concurrency limit was exceeded: {}",
                    c.global().in_flight()
                );
                drop(held);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(c.global().in_flight(), 0);
        let (acquired, released) = c.global().conservation();
        assert_eq!(acquired, released, "reservations leaked under contention");
    }

    // -- Machine memory ----------------------------------------------------

    const GIB: u64 = 1 << 30;

    fn spark_plan() -> (AdmissionPlan, TargetId, TargetId, TargetId) {
        let qwen = TargetId::new("spark:qwen").unwrap();
        let yue = TargetId::new("spark:yue2").unwrap();
        let h3 = TargetId::new("spark:h3").unwrap();
        let mut plan = AdmissionPlan::new(ScopeLimits::UNLIMITED);
        plan.machines.insert("spark".to_owned(), 80 * GIB);
        let on_spark = |bytes, class| TargetMemory {
            machine: "spark".to_owned(),
            bytes,
            class: Some(class),
        };
        plan.target_memory.insert(qwen.clone(), on_spark(0, PriorityClass::Interactive));
        plan.target_memory.insert(yue.clone(), on_spark(24 * GIB, PriorityClass::Standard));
        plan.target_memory.insert(h3.clone(), on_spark(70 * GIB, PriorityClass::Batch));
        plan.targets.insert(
            h3.clone(),
            ScopeLimits {
                max_concurrency: 4,
                ..ScopeLimits::UNLIMITED
            },
        );
        (plan, qwen, yue, h3)
    }

    #[test]
    fn a_memory_refusal_rolls_back_every_scope_it_passed() {
        let clock = Arc::new(TestClock::new());
        let (plan, _, _, h3) = spark_plan();
        let c = AdmissionController::from_plan(clock, &plan);
        let first = c.reserve(&tenant(), &principal(), &h3, 0);
        assert!(first.is_ok());
        let second = c.reserve(&tenant(), &principal(), &h3, 0);
        assert!(matches!(second, Err((Rejection::MemoryExhausted, ref name)) if name == "machine:spark"));
        // Only the running job holds the target's slot and the global one.
        assert_eq!(c.target_scope(&h3).map(|s| s.in_flight()), Some(1));
        assert_eq!(c.global().in_flight(), 1);
        drop(first);
        assert_eq!(c.global().in_flight(), 0);
        assert_eq!(c.machine_views()[0].1.held_bytes, 0);
    }

    #[test]
    fn a_waiting_job_keeps_its_place_across_passes_ahead_of_a_lower_class() {
        let clock = Arc::new(TestClock::new());
        let (plan, qwen, yue, h3) = spark_plan();
        let c = AdmissionController::from_plan(clock.clone(), &plan);
        let pass = |target: &TargetId, key: &str| {
            c.reserve_queued_as(
                &tenant(),
                &principal(),
                None,
                target,
                0,
                PriorityClass::Standard,
                std::time::Duration::ZERO,
                Some(key),
            )
        };
        let rendering = pass(&h3, "h3-1");
        assert!(rendering.is_ok());
        // YuE's pass is refused for memory and leaves a claim.
        assert!(matches!(pass(&yue, "yue-1"), Err((Rejection::MemoryExhausted, _))));
        assert_eq!(c.machine_views()[0].1.waiting.len(), 1);
        // Chat to the resident model is not held up by any of it.
        assert!(pass(&qwen, "chat-1").is_ok());
        drop(rendering);
        // The next H3 job fits on the empty machine, and is still refused:
        // YuE outranks it.
        assert!(matches!(pass(&h3, "h3-2"), Err((Rejection::MemoryExhausted, _))));
        assert_eq!(c.target_scope(&h3).map(|s| s.in_flight()), Some(0));
        let song = pass(&yue, "yue-1");
        assert!(song.is_ok());
        // YuE's claim went with its admission; H3 waits only for memory now.
        assert!(matches!(pass(&h3, "h3-2"), Err((Rejection::MemoryExhausted, _))));
        drop(song);
        assert!(pass(&h3, "h3-2").is_ok());
    }

    #[test]
    fn a_job_that_ends_another_way_gives_up_its_place() {
        let clock = Arc::new(TestClock::new());
        let (plan, _, yue, h3) = spark_plan();
        let c = AdmissionController::from_plan(clock, &plan);
        let held = c.reserve(&tenant(), &principal(), &h3, 0);
        assert!(held.is_ok());
        let refused = c.reserve_queued_as(
            &tenant(),
            &principal(),
            None,
            &yue,
            0,
            PriorityClass::Standard,
            std::time::Duration::ZERO,
            Some("yue-1"),
        );
        assert!(refused.is_err());
        c.drop_machine_claims("yue-1");
        assert!(c.machine_views()[0].1.waiting.is_empty());
    }

    #[test]
    fn a_publication_keeps_the_memory_already_held() {
        let clock = Arc::new(TestClock::new());
        let (mut plan, _, yue, h3) = spark_plan();
        let c = AdmissionController::from_plan(clock, &plan);
        let rendering = c.reserve(&tenant(), &principal(), &h3, 0);
        assert!(rendering.is_ok());
        plan.machines.insert("spark".to_owned(), 100 * GIB);
        c.apply(&plan);
        assert_eq!(c.machine_views()[0].1.held_bytes, 70 * GIB);
        assert!(c.reserve(&tenant(), &principal(), &yue, 0).is_ok());
        // A machine the plan drops admits nothing more, and the hold already
        // taken on it is still returned to it.
        plan.machines.clear();
        plan.target_memory.clear();
        c.apply(&plan);
        assert!(c.machine_views().is_empty());
        drop(rendering);
    }

    #[test]
    fn a_request_that_can_wait_is_admitted_when_the_memory_comes_back() {
        let clock = Arc::new(TestClock::new());
        let (plan, _, yue, h3) = spark_plan();
        let c = Arc::new(AdmissionController::from_plan(clock, &plan));
        let Ok(rendering) = c.reserve(&tenant(), &principal(), &h3, 0) else {
            unreachable!()
        };
        let waiter = {
            let c = Arc::clone(&c);
            let yue = yue.clone();
            std::thread::spawn(move || {
                c.reserve_queued_for(
                    &tenant(),
                    &principal(),
                    None,
                    &yue,
                    0,
                    PriorityClass::Standard,
                    std::time::Duration::from_secs(10),
                )
                .map(|(reservation, _)| reservation.target.clone())
            })
        };
        while c.machine_views()[0].1.waiting.is_empty() {
            std::thread::yield_now();
        }
        rendering.release_unused();
        assert_eq!(waiter.join().ok().and_then(Result::ok), Some(yue));
        assert_eq!(c.machine_views()[0].1.held_bytes, 0);
    }
}
