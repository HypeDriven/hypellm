//! Per-key cumulative token budgets (specification 12.1–12.3).
//!
//! A router API key may carry a finite allowance of tokens that does not
//! refill. This module is the ledger: what a key has been allowed, what it has
//! spent, what its in-flight requests hold, and the receipts of the credits an
//! external payment system has applied.
//!
//! It is unrelated to the refilling buckets in [`crate::admission`]. Those are
//! rate controls and admit an oversized request against future refill; a
//! budget is a balance, so nothing here extends credit and nothing here knows
//! what time it is.
//!
//! # Durability without a write per request
//!
//! Specification 12.1 requires that "restart cannot restore spent credit or
//! settle twice". The obvious implementation — one durable record when a
//! request reserves and another when it settles — puts two `fsync`s under the
//! store's global log mutex on every inference request, in a log that is never
//! compacted.
//!
//! The ledger keeps one durable number per key instead: `drawn`, a high-water
//! mark that the key's consumption plus its in-flight reservations never
//! exceed. A reservation that fits under the mark costs no I/O. One that does
//! not raises the mark first, durably, by more than it needs, and is refused
//! if that write fails. On restart `consumed` is taken to *be* `drawn`:
//!
//! - Spent credit cannot come back, because everything spent was under a mark
//!   that reached the disk before the request that spent it was dispatched.
//! - Nothing can settle twice, because individual settlements are never
//!   replayed — there is no settlement record to apply a second time.
//! - What a crash costs is the unused headroom, which is bounded by
//!   `draw_tokens` per key and, for a finite budget, by an eighth of what
//!   remained. A clean shutdown calls [`BudgetLedger::flush`] and loses
//!   nothing.
//!
//! This is conservative in exactly the direction the specification asks for,
//! and it is a deviation from a literal reading of "reservations [and]
//! settlement identifiers MUST be durable": they are durable in aggregate, not
//! one by one. `spec/deferred-issues.html` says so.
//!
//! # What is pure
//!
//! The ledger performs no I/O. It hands each record it needs committed to a
//! [`BudgetJournal`], and treats a journal failure as a refusal. The router
//! supplies a journal backed by the store; the tests here supply one that can
//! be made to fail and one that can be replayed, which is how "a crash cannot
//! restore credit" is checked rather than asserted.

use crate::ids::{KeyId, TenantId};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The largest token quantity the ledger represents.
///
/// `i64::MAX`, because the durable and management encodings are JSON and an
/// integer above it cannot be carried exactly. Limits and credits beyond it
/// are rejected; consumption saturates at it and never wraps.
pub const MAX_TOKENS: u64 = u64::MAX >> 1;

/// Default headroom drawn beyond what a reservation needs.
pub const DEFAULT_DRAW_TOKENS: u64 = 1_048_576;

/// Longest payment message, in bytes.
pub const MAX_PAYMENT_MESSAGE_BYTES: usize = 512;
/// Longest payment URL, in bytes.
pub const MAX_PAYMENT_URL_BYTES: usize = 512;
/// Longest idempotency key, in bytes.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Longest credit reason, in bytes.
pub const MAX_CREDIT_REASON_BYTES: usize = 256;

/// Operator-supplied directions to an external payment page (specification
/// 12.2).
///
/// Data, never markup and never a redirect: a bounded plain-text message and
/// an absolute HTTPS URL, each optional, at least one present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentInstructions {
    message: Option<String>,
    payment_url: Option<String>,
}

/// Why payment instructions were rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentError {
    /// The message is empty, too long, or contains a control character.
    Message,
    /// The URL is not an absolute `https://` URL of acceptable shape.
    Url,
}

impl PaymentError {
    /// A description safe to return to an administrator.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Message => {
                "the payment message must be 1 to 512 bytes of plain text without control characters"
            }
            Self::Url => {
                "the payment URL must be an absolute https:// URL of at most 512 bytes, with a host name and no credentials"
            }
        }
    }
}

impl PaymentInstructions {
    /// Validate and build. `Ok(None)` when neither part is supplied.
    pub fn new(message: Option<&str>, payment_url: Option<&str>) -> Result<Option<Self>, PaymentError> {
        if let Some(message) = message {
            if message.is_empty()
                || message.len() > MAX_PAYMENT_MESSAGE_BYTES
                || message.chars().any(char::is_control)
            {
                return Err(PaymentError::Message);
            }
        }
        if let Some(url) = payment_url {
            if !is_https_url(url) {
                return Err(PaymentError::Url);
            }
        }
        if message.is_none() && payment_url.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            message: message.map(str::to_owned),
            payment_url: payment_url.map(str::to_owned),
        }))
    }

    /// The plain-text message.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The absolute HTTPS URL.
    #[must_use]
    pub fn payment_url(&self) -> Option<&str> {
        self.payment_url.as_deref()
    }
}

/// Whether `url` is an absolute HTTPS URL the router is willing to repeat.
///
/// Deliberately narrower than a URL parser. The value is echoed to callers in
/// an error body, so the check is that it can only be read one way: printable
/// ASCII, an ordinary host name with an optional port, and no userinfo — a
/// `https://billing.example@evil.test/` would otherwise display one host and
/// name another, and `user:secret@` would be a credential in an error message.
fn is_https_url(url: &str) -> bool {
    if url.len() > MAX_PAYMENT_URL_BYTES {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if !rest
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'<' | b'>' | b'\\' | b'`'))
    {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && host.split('.').all(|label| !label.is_empty())
}

/// The receipt of one applied credit (specification 12.3).
///
/// Durable for as long as the key's budget is, so a replayed payment
/// notification is recognised however long it took to arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditReceipt {
    /// The caller's `Idempotency-Key`: the external payment or credit
    /// operation.
    pub idempotency_key: String,
    /// Digest of the normalized request body, so that a replay with different
    /// content is a conflict rather than a silent no-op.
    pub request_digest: String,
    /// Tokens added.
    pub tokens: u64,
    /// The limit after this credit.
    pub limit_after: u64,
    /// The budget revision this credit produced.
    pub revision_after: u64,
    /// Wall-clock time of the credit.
    pub at_millis: u64,
    /// The principal that applied it.
    pub actor: String,
    /// Optional bounded reason.
    pub reason: Option<String>,
}

/// One durable ledger record: a key's whole editable and high-water state,
/// plus the receipt of the credit that produced it, if a credit did.
///
/// A record replaces the previous one for its key, and a credit and its
/// receipt are a single record — specification 12.3's "credit and its receipt
/// commit atomically" is one frame rather than two that must agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRecord {
    /// The key.
    pub key: KeyId,
    /// The key's tenant.
    pub tenant: TenantId,
    /// Cumulative allowance, or `None` for unlimited.
    pub limit: Option<u64>,
    /// High-water mark: consumption plus reservations never exceed it.
    pub drawn: u64,
    /// Revision of the editable part: the limit and the payment override.
    pub revision: u64,
    /// Per-key payment override.
    pub payment: Option<PaymentInstructions>,
    /// The credit this record applies.
    pub receipt: Option<CreditReceipt>,
}

/// A journal refused or failed to commit a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalError;

/// Where the ledger's records become durable.
///
/// `commit` returns only after the record would survive a crash. The ledger
/// calls it with its own lock held, so a commit serializes budget work across
/// keys; draws are infrequent by design, and the store's log is a single
/// writer in any case.
pub trait BudgetJournal: Send + Sync + core::fmt::Debug {
    /// Commit one record durably.
    fn commit(&self, record: &BudgetRecord) -> Result<(), JournalError>;
}

/// A point-in-time view of one key's budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetView {
    /// Cumulative allowance, or `None` for unlimited.
    pub limit: Option<u64>,
    /// Tokens charged so far.
    pub consumed: u64,
    /// Tokens held by in-flight requests.
    pub reserved: u64,
    /// Revision of the editable part.
    pub revision: u64,
    /// Per-key payment override.
    pub payment: Option<PaymentInstructions>,
}

impl BudgetView {
    /// `max(0, limit - consumed - reserved)`, or `None` when unlimited.
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        self.limit
            .map(|limit| limit.saturating_sub(self.consumed).saturating_sub(self.reserved))
    }
}

/// Why a reservation was not granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The finite budget cannot fund the request (HTTP 402).
    Exhausted {
        /// The key's own payment override, if it has one.
        payment: Option<PaymentInstructions>,
    },
    /// The ledger could not record the reservation durably. Not a statement
    /// about the balance, and never reported as one.
    Unavailable,
}

/// Why a limit change or credit was not applied. Nothing was mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetMutationError {
    /// The editable state changed since the caller read it (412).
    RevisionChanged,
    /// A credit was addressed to an unlimited budget (validation error).
    Unlimited,
    /// A zero credit, or a quantity beyond [`MAX_TOKENS`].
    InvalidAmount,
    /// The credit would carry the limit past [`MAX_TOKENS`].
    Overflow,
    /// The idempotency key was already used with different content (409).
    IdempotencyConflict,
    /// The record could not be committed. Fails closed.
    Unavailable,
}

/// The result of [`BudgetLedger::credit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditOutcome {
    /// The receipt: the original one when `replayed`.
    pub receipt: CreditReceipt,
    /// The budget as it stands now.
    pub view: BudgetView,
    /// Whether this was a replay that added nothing.
    pub replayed: bool,
}

/// What settling a reservation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// Tokens charged to the key.
    pub charged: u64,
    /// Tokens by which the charge exceeded the reservation.
    pub overrun: u64,
    /// Whether the ledger's durable state covers the charge. `false` only
    /// when an overrun had to raise the high-water mark and the journal
    /// failed; the key admits nothing further until a commit succeeds.
    pub durable: bool,
}

#[derive(Debug)]
struct Entry {
    tenant: TenantId,
    limit: Option<u64>,
    drawn: u64,
    revision: u64,
    payment: Option<PaymentInstructions>,
    consumed: u64,
    reserved: u64,
    /// The in-memory mark is above the durable one.
    undurable: bool,
    receipts: BTreeMap<String, CreditReceipt>,
}

impl Entry {
    const fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            limit: None,
            drawn: 0,
            revision: 0,
            payment: None,
            consumed: 0,
            reserved: 0,
            undurable: false,
            receipts: BTreeMap::new(),
        }
    }

    fn held(&self) -> u64 {
        self.consumed.saturating_add(self.reserved).min(MAX_TOKENS)
    }

    fn view(&self) -> BudgetView {
        BudgetView {
            limit: self.limit,
            consumed: self.consumed,
            reserved: self.reserved,
            revision: self.revision,
            payment: self.payment.clone(),
        }
    }

    fn record(&self, key: &KeyId, drawn: u64) -> BudgetRecord {
        BudgetRecord {
            key: key.clone(),
            tenant: self.tenant.clone(),
            limit: self.limit,
            drawn,
            revision: self.revision,
            payment: self.payment.clone(),
            receipt: None,
        }
    }
}

/// The per-key token budget ledger.
#[derive(Debug)]
pub struct BudgetLedger {
    journal: Arc<dyn BudgetJournal>,
    draw_tokens: u64,
    entries: Mutex<BTreeMap<KeyId, Entry>>,
}

impl BudgetLedger {
    /// Create an empty ledger.
    ///
    /// `draw_tokens` is the headroom taken beyond what a reservation needs
    /// each time the high-water mark is raised. Zero makes every reservation
    /// that does not fit under the mark a durable write, and bounds what a
    /// crash can cost to the requests in flight.
    #[must_use]
    pub fn new(journal: Arc<dyn BudgetJournal>, draw_tokens: u64) -> Self {
        Self {
            journal,
            draw_tokens: draw_tokens.min(MAX_TOKENS),
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<KeyId, Entry>>, BudgetRefusal> {
        // A poisoned ledger cannot say what a key has left, so it authorises
        // nothing.
        self.entries.lock().map_err(|_| BudgetRefusal::Unavailable)
    }

    /// Apply a record read back from the journal at startup.
    ///
    /// Records must be applied in the order they were committed. Consumption
    /// is taken to be the high-water mark: whatever was drawn and not known to
    /// be unspent is spent.
    pub fn restore(&self, record: BudgetRecord) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .entry(record.key)
            .or_insert_with(|| Entry::new(record.tenant.clone()));
        entry.tenant = record.tenant;
        entry.limit = record.limit.map(|limit| limit.min(MAX_TOKENS));
        entry.drawn = record.drawn.min(MAX_TOKENS);
        entry.revision = record.revision;
        entry.payment = record.payment;
        entry.consumed = entry.drawn;
        entry.reserved = 0;
        entry.undurable = false;
        if let Some(receipt) = record.receipt {
            entry.receipts.insert(receipt.idempotency_key.clone(), receipt);
        }
    }

    /// Reserve `tokens` against `key` before an upstream attempt.
    ///
    /// Specification 12.1: the reservation is atomic with respect to every
    /// other request using the key, a request that does not fit is refused
    /// even when some credit remains, and nothing is admitted against future
    /// credit. An unlimited key always fits; its consumption is still counted.
    pub fn reserve(
        self: &Arc<Self>,
        key: &KeyId,
        tenant: &TenantId,
        tokens: u64,
    ) -> Result<BudgetReservation, BudgetRefusal> {
        let mut entries = self.lock()?;
        let entry = entries
            .entry(key.clone())
            .or_insert_with(|| Entry::new(tenant.clone()));
        let held = entry.held();
        let exhausted = || BudgetRefusal::Exhausted {
            payment: entry.payment.clone(),
        };
        let needed = match held.checked_add(tokens) {
            Some(needed) if needed <= MAX_TOKENS => needed,
            _ => return Err(exhausted()),
        };
        if let Some(limit) = entry.limit {
            // An exhausted budget funds nothing, including a request whose
            // estimate is zero.
            if held >= limit || needed > limit {
                return Err(exhausted());
            }
        }
        if needed > entry.drawn || entry.undurable {
            let headroom = match entry.limit {
                // An eighth of what would remain: a crash can then cost a
                // finite budget a bounded fraction of it, however large
                // `draw_tokens` is.
                Some(limit) => self.draw_tokens.min(limit.saturating_sub(needed) >> 3),
                None => self.draw_tokens,
            };
            let drawn = needed
                .saturating_add(headroom)
                .min(MAX_TOKENS)
                .max(entry.drawn);
            self.journal
                .commit(&entry.record(key, drawn))
                .map_err(|_| BudgetRefusal::Unavailable)?;
            entry.drawn = drawn;
            entry.undurable = false;
        }
        entry.reserved = entry.reserved.saturating_add(tokens);
        Ok(BudgetReservation {
            ledger: Arc::clone(self),
            key: key.clone(),
            tokens,
            finished: false,
        })
    }

    fn finish(&self, key: &KeyId, reserved: u64, charged: u64) -> Settlement {
        // Unlike `reserve`, this proceeds through a poisoned lock: declining
        // to record a charge would be the one outcome that favours the caller.
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let overrun = charged.saturating_sub(reserved);
        let Some(entry) = entries.get_mut(key) else {
            return Settlement {
                charged,
                overrun,
                durable: false,
            };
        };
        entry.reserved = entry.reserved.saturating_sub(reserved);
        entry.consumed = entry.consumed.saturating_add(charged).min(MAX_TOKENS);
        let held = entry.held();
        if held > entry.drawn {
            // Usage above the reservation. Specification 12.1: "recorded in
            // full and blocks further admission when the limit is reached".
            entry.drawn = held;
            entry.undurable = self.journal.commit(&entry.record(key, held)).is_err();
        }
        Settlement {
            charged,
            overrun,
            durable: !entry.undurable,
        }
    }

    /// The budget of `key`. A key the ledger has never seen is unlimited with
    /// nothing consumed, at revision zero.
    #[must_use]
    pub fn view(&self, key: &KeyId) -> BudgetView {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        entries.get(key).map_or(
            BudgetView {
                limit: None,
                consumed: 0,
                reserved: 0,
                revision: 0,
                payment: None,
            },
            Entry::view,
        )
    }

    /// Set the absolute limit and the payment override.
    ///
    /// `expected_revision` is the revision the caller read; `None` waives the
    /// check. Consumption and in-flight reservations are untouched, so a
    /// reduction below what is already held simply admits nothing further.
    pub fn set(
        &self,
        key: &KeyId,
        tenant: &TenantId,
        expected_revision: Option<u64>,
        limit: Option<u64>,
        payment: Option<PaymentInstructions>,
    ) -> Result<BudgetView, BudgetMutationError> {
        if limit.is_some_and(|limit| limit > MAX_TOKENS) {
            return Err(BudgetMutationError::InvalidAmount);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BudgetMutationError::Unavailable)?;
        let entry = entries
            .entry(key.clone())
            .or_insert_with(|| Entry::new(tenant.clone()));
        if expected_revision.is_some_and(|expected| expected != entry.revision) {
            return Err(BudgetMutationError::RevisionChanged);
        }
        let revision = entry
            .revision
            .checked_add(1)
            .ok_or(BudgetMutationError::Overflow)?;
        // A record is being written anyway, so it carries the exact mark.
        let drawn = entry.held();
        let record = BudgetRecord {
            key: key.clone(),
            tenant: entry.tenant.clone(),
            limit,
            drawn,
            revision,
            payment: payment.clone(),
            receipt: None,
        };
        self.journal
            .commit(&record)
            .map_err(|_| BudgetMutationError::Unavailable)?;
        entry.limit = limit;
        entry.payment = payment;
        entry.revision = revision;
        entry.drawn = drawn;
        entry.undurable = false;
        Ok(entry.view())
    }

    /// The receipt already recorded under `idempotency_key`, if any.
    #[must_use]
    pub fn receipt(&self, key: &KeyId, idempotency_key: &str) -> Option<CreditReceipt> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        entries.get(key)?.receipts.get(idempotency_key).cloned()
    }

    /// Add `tokens` to a finite limit, once per `idempotency_key`.
    ///
    /// A replay with the same digest returns the original receipt and adds
    /// nothing, whatever `expected_revision` says — the payment system that
    /// retries holds the ETag it had the first time. The same key with a
    /// different digest is a conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn credit(
        &self,
        key: &KeyId,
        tenant: &TenantId,
        expected_revision: Option<u64>,
        tokens: u64,
        idempotency_key: &str,
        request_digest: &str,
        reason: Option<&str>,
        actor: &str,
        at_millis: u64,
    ) -> Result<CreditOutcome, BudgetMutationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BudgetMutationError::Unavailable)?;
        let entry = entries
            .entry(key.clone())
            .or_insert_with(|| Entry::new(tenant.clone()));
        if let Some(receipt) = entry.receipts.get(idempotency_key) {
            if receipt.request_digest != request_digest {
                return Err(BudgetMutationError::IdempotencyConflict);
            }
            return Ok(CreditOutcome {
                receipt: receipt.clone(),
                view: entry.view(),
                replayed: true,
            });
        }
        if expected_revision.is_some_and(|expected| expected != entry.revision) {
            return Err(BudgetMutationError::RevisionChanged);
        }
        if tokens == 0 || tokens > MAX_TOKENS {
            return Err(BudgetMutationError::InvalidAmount);
        }
        let limit = entry.limit.ok_or(BudgetMutationError::Unlimited)?;
        let limit_after = limit
            .checked_add(tokens)
            .filter(|limit| *limit <= MAX_TOKENS)
            .ok_or(BudgetMutationError::Overflow)?;
        let revision = entry
            .revision
            .checked_add(1)
            .ok_or(BudgetMutationError::Overflow)?;
        let receipt = CreditReceipt {
            idempotency_key: idempotency_key.to_owned(),
            request_digest: request_digest.to_owned(),
            tokens,
            limit_after,
            revision_after: revision,
            at_millis,
            actor: actor.to_owned(),
            reason: reason.map(str::to_owned),
        };
        let drawn = entry.held();
        let record = BudgetRecord {
            key: key.clone(),
            tenant: entry.tenant.clone(),
            limit: Some(limit_after),
            drawn,
            revision,
            payment: entry.payment.clone(),
            receipt: Some(receipt.clone()),
        };
        self.journal
            .commit(&record)
            .map_err(|_| BudgetMutationError::Unavailable)?;
        entry.limit = Some(limit_after);
        entry.revision = revision;
        entry.drawn = drawn;
        entry.undurable = false;
        entry
            .receipts
            .insert(receipt.idempotency_key.clone(), receipt.clone());
        Ok(CreditOutcome {
            receipt,
            view: entry.view(),
            replayed: false,
        })
    }

    /// Commit the exact mark for every key whose durable mark is not exact.
    ///
    /// Called on a clean shutdown so that unused headroom is not charged.
    /// Returns how many keys could not be committed; those keep their higher
    /// durable mark, which is the conservative outcome.
    pub fn flush(&self) -> usize {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut failed = 0_usize;
        for (key, entry) in entries.iter_mut() {
            let held = entry.held();
            if entry.drawn == held && !entry.undurable {
                continue;
            }
            if self.journal.commit(&entry.record(key, held)).is_ok() {
                entry.drawn = held;
                entry.undurable = false;
            } else {
                failed = failed.saturating_add(1);
            }
        }
        failed
    }
}

/// Tokens held against a key for one upstream attempt.
///
/// Finished exactly once, by [`settle`](Self::settle),
/// [`retain`](Self::retain) or [`release`](Self::release). `Drop` is the net
/// under a path that reached none of them, and it retains: a path that does
/// not know what happened must not hand tokens back.
#[derive(Debug)]
pub struct BudgetReservation {
    ledger: Arc<BudgetLedger>,
    key: KeyId,
    tokens: u64,
    finished: bool,
}

impl BudgetReservation {
    /// Tokens reserved.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Settle against validated provider usage: charge `actual`, return the
    /// rest. Usage above the reservation is charged in full.
    pub fn settle(mut self, actual: u64) -> Settlement {
        self.finished = true;
        self.ledger.finish(&self.key, self.tokens, actual)
    }

    /// Keep the whole reservation as the charge.
    ///
    /// For an attempt the provider accepted whose final usage is unknown:
    /// specification 12.1 retains the reservation "rather than refunding
    /// uncertain consumption".
    pub fn retain(mut self) -> Settlement {
        self.finished = true;
        self.ledger.finish(&self.key, self.tokens, self.tokens)
    }

    /// Return the whole reservation: the attempt was refused before upstream
    /// acceptance and incurs no charge.
    pub fn release(mut self) {
        self.finished = true;
        self.ledger.finish(&self.key, self.tokens, 0);
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            self.ledger.finish(&self.key, self.tokens, self.tokens);
        }
    }
}

/// Journals for tests, in this crate and in the ones that build on it.
pub mod testing {
    use super::{BudgetJournal, BudgetLedger, BudgetRecord, JournalError};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, PoisonError};

    /// A journal that keeps its records in memory, can be told to fail, and
    /// can be replayed into a fresh ledger — a restart, without a disk.
    #[derive(Debug, Default)]
    pub struct MemoryJournal {
        records: Mutex<Vec<BudgetRecord>>,
        failing: AtomicBool,
    }

    impl MemoryJournal {
        /// An empty journal that accepts every record.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Make every later commit fail, or succeed again.
        pub fn fail(&self, failing: bool) {
            self.failing.store(failing, Ordering::SeqCst);
        }

        /// Every record committed so far, in order.
        #[must_use]
        pub fn records(&self) -> Vec<BudgetRecord> {
            self.records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Replay everything committed so far into `ledger`.
        pub fn replay_into(&self, ledger: &BudgetLedger) {
            for record in self.records() {
                ledger.restore(record);
            }
        }
    }

    impl BudgetJournal for MemoryJournal {
        fn commit(&self, record: &BudgetRecord) -> Result<(), JournalError> {
            if self.failing.load(Ordering::SeqCst) {
                return Err(JournalError);
            }
            self.records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MemoryJournal;
    use super::*;

    fn key() -> KeyId {
        KeyId::new("0123456789abcdef").unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    fn ledger(draw: u64) -> (Arc<BudgetLedger>, Arc<MemoryJournal>) {
        let journal = Arc::new(MemoryJournal::new());
        let ledger = Arc::new(BudgetLedger::new(
            Arc::clone(&journal) as Arc<dyn BudgetJournal>,
            draw,
        ));
        (ledger, journal)
    }

    fn restarted(journal: &Arc<MemoryJournal>, draw: u64) -> Arc<BudgetLedger> {
        let ledger = Arc::new(BudgetLedger::new(
            Arc::clone(journal) as Arc<dyn BudgetJournal>,
            draw,
        ));
        journal.replay_into(&ledger);
        ledger
    }

    fn exhausted(result: &Result<BudgetReservation, BudgetRefusal>) -> bool {
        matches!(result, Err(BudgetRefusal::Exhausted { .. }))
    }

    #[test]
    fn an_unseen_key_is_unlimited_and_its_consumption_is_still_counted() {
        let (ledger, _) = ledger(1000);
        let view = ledger.view(&key());
        assert_eq!((view.limit, view.consumed, view.remaining()), (None, 0, None));

        ledger.reserve(&key(), &tenant(), 500).unwrap().settle(120);
        let view = ledger.view(&key());
        assert_eq!((view.limit, view.consumed, view.reserved), (None, 120, 0));
    }

    #[test]
    fn a_zero_budget_permits_no_consumption() {
        let (ledger, _) = ledger(1000);
        ledger.set(&key(), &tenant(), None, Some(0), None).unwrap();
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 1)));
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 0)));
    }

    #[test]
    fn a_request_that_does_not_fit_is_refused_even_though_credit_remains() {
        // Specification 12.1: no oversized-request debt allowance.
        let (ledger, _) = ledger(1000);
        ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 101)));
        assert_eq!(ledger.view(&key()).remaining(), Some(100));
        // The refusal held nothing back.
        ledger.reserve(&key(), &tenant(), 100).unwrap().release();
        assert_eq!(ledger.view(&key()).remaining(), Some(100));
    }

    #[test]
    fn concurrent_reservations_share_one_balance() {
        let (ledger, _) = ledger(1000);
        ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        let first = ledger.reserve(&key(), &tenant(), 60).unwrap();
        // 40 remain while the first is in flight, whatever it ends up using.
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 41)));
        let second = ledger.reserve(&key(), &tenant(), 40).unwrap();
        assert_eq!(ledger.view(&key()).remaining(), Some(0));
        first.settle(10);
        second.settle(40);
        let view = ledger.view(&key());
        assert_eq!((view.consumed, view.reserved, view.remaining()), (50, 0, Some(50)));
    }

    #[test]
    fn each_way_of_finishing_charges_what_the_specification_says() {
        let (ledger, _) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(1000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 100).unwrap().release();
        assert_eq!(ledger.view(&key()).consumed, 0, "refused before acceptance");
        ledger.reserve(&key(), &tenant(), 100).unwrap().settle(30);
        assert_eq!(ledger.view(&key()).consumed, 30, "settled at provider usage");
        ledger.reserve(&key(), &tenant(), 100).unwrap().retain();
        assert_eq!(ledger.view(&key()).consumed, 130, "usage unknown: retained");
        drop(ledger.reserve(&key(), &tenant(), 100).unwrap());
        assert_eq!(ledger.view(&key()).consumed, 230, "dropped: retained");
        assert_eq!(ledger.view(&key()).reserved, 0);
    }

    #[test]
    fn usage_above_the_reservation_is_charged_in_full_and_blocks_admission() {
        let (ledger, journal) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        let settlement = ledger.reserve(&key(), &tenant(), 50).unwrap().settle(180);
        assert_eq!((settlement.charged, settlement.overrun), (180, 130));
        assert!(settlement.durable);
        let view = ledger.view(&key());
        assert_eq!((view.consumed, view.remaining()), (180, Some(0)));
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 1)));
        // And a restart does not forgive it.
        assert_eq!(restarted(&journal, 0).view(&key()).consumed, 180);
    }

    #[test]
    fn consumption_saturates_instead_of_wrapping() {
        let (ledger, _) = ledger(0);
        ledger.reserve(&key(), &tenant(), 10).unwrap().settle(u64::MAX);
        ledger.reserve(&key(), &tenant(), 0).unwrap().settle(u64::MAX);
        assert_eq!(ledger.view(&key()).consumed, MAX_TOKENS);
        ledger.set(&key(), &tenant(), None, Some(MAX_TOKENS), None).unwrap();
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 1)));
    }

    #[test]
    fn a_reservation_is_refused_when_it_cannot_be_recorded() {
        let (ledger, journal) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        journal.fail(true);
        assert_eq!(
            ledger.reserve(&key(), &tenant(), 10).unwrap_err(),
            BudgetRefusal::Unavailable
        );
        assert_eq!(ledger.view(&key()).reserved, 0);
        journal.fail(false);
        ledger.reserve(&key(), &tenant(), 10).unwrap().settle(10);
    }

    #[test]
    fn a_crash_never_restores_spent_credit() {
        let (ledger, journal) = ledger(64);
        ledger.set(&key(), &tenant(), None, Some(10_000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 300).unwrap().settle(250);
        let in_flight = ledger.reserve(&key(), &tenant(), 400).unwrap();
        let before = ledger.view(&key());
        // The process dies here: nothing is flushed, `in_flight` never settles.
        let after = restarted(&journal, 64).view(&key());
        assert!(
            after.consumed >= before.consumed + before.reserved,
            "restart forgave tokens: {before:?} became {after:?}"
        );
        assert!(after.consumed <= 10_000);
        drop(in_flight);
    }

    #[test]
    fn a_clean_shutdown_charges_only_what_was_used() {
        let (ledger, journal) = ledger(5000);
        ledger.set(&key(), &tenant(), None, Some(100_000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 300).unwrap().settle(250);
        assert_eq!(ledger.flush(), 0);
        assert_eq!(restarted(&journal, 5000).view(&key()).consumed, 250);
    }

    #[test]
    fn headroom_spares_the_journal_and_never_exceeds_the_limit() {
        let (ledger, journal) = ledger(10_000);
        ledger.set(&key(), &tenant(), None, Some(1_000_000), None).unwrap();
        let written = journal.records().len();
        for _ in 0..20 {
            ledger.reserve(&key(), &tenant(), 100).unwrap().settle(100);
        }
        assert_eq!(journal.records().len(), written + 1, "one draw covers them all");
        for record in journal.records() {
            assert!(record.drawn <= 1_000_000);
        }
    }

    #[test]
    fn a_crash_costs_a_finite_budget_at_most_an_eighth_of_what_remained() {
        let (ledger, journal) = ledger(u64::MAX);
        ledger.set(&key(), &tenant(), None, Some(8000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 80).unwrap().settle(80);
        let after = restarted(&journal, u64::MAX).view(&key());
        assert!(after.consumed <= 80 + (8000 - 80) / 8, "{after:?}");
    }

    #[test]
    fn changing_the_limit_keeps_consumption_and_in_flight_reservations() {
        let (ledger, _) = ledger(1000);
        ledger.set(&key(), &tenant(), None, Some(1000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 200).unwrap().settle(200);
        let in_flight = ledger.reserve(&key(), &tenant(), 300).unwrap();

        // A reduction below what is held: nothing new, but the work in flight
        // finishes within its reservation.
        let view = ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        assert_eq!((view.consumed, view.reserved, view.remaining()), (200, 300, Some(0)));
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 1)));
        in_flight.settle(300);

        // Removing the limit does not reset the counter either.
        let view = ledger.set(&key(), &tenant(), None, None, None).unwrap();
        assert_eq!((view.limit, view.consumed), (None, 500));
    }

    #[test]
    fn a_stale_revision_changes_nothing() {
        let (ledger, journal) = ledger(0);
        let view = ledger.set(&key(), &tenant(), Some(0), Some(100), None).unwrap();
        assert_eq!(view.revision, 1);
        let written = journal.records().len();
        assert_eq!(
            ledger.set(&key(), &tenant(), Some(0), Some(999), None),
            Err(BudgetMutationError::RevisionChanged)
        );
        assert_eq!(
            ledger.credit(&key(), &tenant(), Some(0), 5, "pay-1", "d", None, "svc", 1),
            Err(BudgetMutationError::RevisionChanged)
        );
        assert_eq!(ledger.view(&key()).limit, Some(100));
        assert_eq!(journal.records().len(), written);
    }

    #[test]
    fn consumption_does_not_move_the_revision() {
        // Specification 12.3: "ordinary consumption does not invalidate an
        // operator's update".
        let (ledger, _) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(100), None).unwrap();
        let before = ledger.view(&key()).revision;
        ledger.reserve(&key(), &tenant(), 10).unwrap().settle(10);
        assert_eq!(ledger.view(&key()).revision, before);
    }

    #[test]
    fn a_credit_is_applied_once_however_often_it_is_replayed() {
        let (ledger, journal) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(1_000_000), None).unwrap();
        ledger.reserve(&key(), &tenant(), 1_000_000).unwrap().settle(1_000_000);
        assert!(exhausted(&ledger.reserve(&key(), &tenant(), 1)));

        let first = ledger
            .credit(&key(), &tenant(), Some(1), 500_000, "pay-7", "digest", Some("invoice 7"), "svc:pay", 42)
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.view.limit, Some(1_500_000));
        assert_eq!(first.view.remaining(), Some(500_000));

        // The replay carries the ETag it had the first time, now stale.
        let replay = ledger
            .credit(&key(), &tenant(), Some(1), 500_000, "pay-7", "digest", Some("invoice 7"), "svc:pay", 99)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.receipt, first.receipt);
        assert_eq!(replay.view.limit, Some(1_500_000));

        // And it is still recognised after a restart.
        let reborn = restarted(&journal, 0);
        let replay = reborn
            .credit(&key(), &tenant(), None, 500_000, "pay-7", "digest", None, "svc:pay", 100)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(reborn.view(&key()).limit, Some(1_500_000));
    }

    #[test]
    fn an_idempotency_key_reused_with_different_content_is_a_conflict() {
        let (ledger, _) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(10), None).unwrap();
        ledger
            .credit(&key(), &tenant(), None, 5, "pay-1", "digest-a", None, "svc", 1)
            .unwrap();
        assert_eq!(
            ledger.credit(&key(), &tenant(), None, 50, "pay-1", "digest-b", None, "svc", 2),
            Err(BudgetMutationError::IdempotencyConflict)
        );
        assert_eq!(ledger.view(&key()).limit, Some(15));
    }

    #[test]
    fn a_credit_to_an_unlimited_budget_is_an_error_not_a_conversion() {
        let (ledger, _) = ledger(0);
        assert_eq!(
            ledger.credit(&key(), &tenant(), None, 5, "pay-1", "d", None, "svc", 1),
            Err(BudgetMutationError::Unlimited)
        );
        assert_eq!(ledger.view(&key()).limit, None);
        assert_eq!(ledger.receipt(&key(), "pay-1"), None);
    }

    #[test]
    fn invalid_and_overflowing_amounts_are_rejected() {
        let (ledger, _) = ledger(0);
        assert_eq!(
            ledger.set(&key(), &tenant(), None, Some(MAX_TOKENS + 1), None),
            Err(BudgetMutationError::InvalidAmount)
        );
        ledger.set(&key(), &tenant(), None, Some(MAX_TOKENS - 1), None).unwrap();
        assert_eq!(
            ledger.credit(&key(), &tenant(), None, 0, "a", "d", None, "svc", 1),
            Err(BudgetMutationError::InvalidAmount)
        );
        assert_eq!(
            ledger.credit(&key(), &tenant(), None, 2, "b", "d", None, "svc", 1),
            Err(BudgetMutationError::Overflow)
        );
        assert_eq!(ledger.view(&key()).limit, Some(MAX_TOKENS - 1));
    }

    #[test]
    fn a_credit_that_cannot_be_persisted_is_not_applied() {
        let (ledger, journal) = ledger(0);
        ledger.set(&key(), &tenant(), None, Some(10), None).unwrap();
        journal.fail(true);
        assert_eq!(
            ledger.credit(&key(), &tenant(), None, 5, "pay-1", "d", None, "svc", 1),
            Err(BudgetMutationError::Unavailable)
        );
        assert_eq!(
            ledger.set(&key(), &tenant(), None, Some(99), None),
            Err(BudgetMutationError::Unavailable)
        );
        journal.fail(false);
        assert_eq!(ledger.view(&key()).limit, Some(10));
        // No receipt was kept, so the retry is a first application.
        let outcome = ledger
            .credit(&key(), &tenant(), None, 5, "pay-1", "d", None, "svc", 1)
            .unwrap();
        assert!(!outcome.replayed);
    }

    #[test]
    fn an_overrun_that_could_not_be_recorded_blocks_until_it_is() {
        let (ledger, journal) = ledger(0);
        ledger.reserve(&key(), &tenant(), 10).unwrap();
        let held = ledger.reserve(&key(), &tenant(), 10).unwrap();
        journal.fail(true);
        assert!(!held.settle(500).durable);
        // Even a reservation that fits under the in-memory mark is refused:
        // the disk does not know about the overrun yet.
        assert_eq!(
            ledger.reserve(&key(), &tenant(), 0).unwrap_err(),
            BudgetRefusal::Unavailable
        );
        journal.fail(false);
        ledger.reserve(&key(), &tenant(), 0).unwrap().release();
        assert!(restarted(&journal, 0).view(&key()).consumed >= 510);
    }

    #[test]
    fn payment_instructions_are_plain_bounded_data() {
        let ok = PaymentInstructions::new(
            Some("Purchase more tokens in the customer portal."),
            Some("https://billing.example/tokens?plan=a#top"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok.payment_url(), Some("https://billing.example/tokens?plan=a#top"));
        assert_eq!(PaymentInstructions::new(None, None), Ok(None));
        assert!(PaymentInstructions::new(None, Some("https://pay.example:8443")).is_ok());

        for url in [
            "http://billing.example/",
            "//billing.example/",
            "/tokens",
            "https://",
            "https:///tokens",
            "https://user:secret@billing.example/",
            "https://billing.example@evil.test/",
            "https://billing.example/a b",
            "https://billing.example/\"><script>",
            "https://billing..example/",
            "https://billing.example:port/",
            "javascript:alert(1)",
            "https://billing.example/\u{202e}",
        ] {
            assert_eq!(
                PaymentInstructions::new(None, Some(url)),
                Err(PaymentError::Url),
                "{url} was accepted"
            );
        }
        let long = format!("https://billing.example/{}", "a".repeat(MAX_PAYMENT_URL_BYTES));
        assert_eq!(PaymentInstructions::new(None, Some(&long)), Err(PaymentError::Url));

        for message in ["", "line one\nline two", "bell\u{7}"] {
            assert_eq!(
                PaymentInstructions::new(Some(message), None),
                Err(PaymentError::Message)
            );
        }
        let long = "m".repeat(MAX_PAYMENT_MESSAGE_BYTES + 1);
        assert_eq!(PaymentInstructions::new(Some(&long), None), Err(PaymentError::Message));
    }
}
