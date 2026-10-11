//! Per-key token budgets: the durable codec, the store-backed journal, and
//! the management representation (specification 12.1–12.3).
//!
//! The ledger itself is `hypellm_core::budget` and does no I/O. This module is
//! where it meets the store, and it lives in this crate because both planes
//! need it: the router restores the ledger from here at startup and reserves
//! against it on the data path, and the handlers in this crate are the only
//! thing that changes a limit.

use hypellm_core::budget::{
    BudgetJournal, BudgetLedger, BudgetRecord, BudgetView, CreditReceipt, JournalError,
    MAX_CREDIT_REASON_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_TOKENS, PaymentInstructions,
};
use hypellm_core::ids::{KeyId, TenantId};
use hypellm_store::{RecordKind, Recovery, Store};
use std::sync::Arc;
use wire_json::{Limits, Object, Value, parse, to_string};

use crate::response::etag_for;

/// Commits ledger records to the store's log as [`RecordKind::KeyBudget`].
///
/// One protected, `fsync`ed frame per record, in the same log as the key it
/// describes — so a backup that has the key has its budget, and a state
/// directory cannot be given a balance the router did not write.
#[derive(Debug)]
pub struct StoreJournal {
    store: Arc<Store>,
}

impl StoreJournal {
    /// A journal over `store`.
    #[must_use]
    pub const fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl BudgetJournal for StoreJournal {
    fn commit(&self, record: &BudgetRecord) -> Result<(), JournalError> {
        self.store
            .append(RecordKind::KeyBudget, &encode_record(record))
            .map(|_| ())
            .map_err(|_| JournalError)
    }
}

/// A ledger backed by `store`, with every budget record in `recovery` applied.
///
/// Returns the ledger and how many budget frames could not be read. An
/// unreadable frame is skipped rather than fatal — it has already passed the
/// store's MAC, so it is a record this build does not understand, not
/// tampering — and it is counted so startup can say so.
#[must_use]
pub fn restore(
    store: &Arc<Store>,
    recovery: &Recovery,
    draw_tokens: u64,
) -> (Arc<BudgetLedger>, usize) {
    let ledger = Arc::new(BudgetLedger::new(
        Arc::new(StoreJournal::new(Arc::clone(store))),
        draw_tokens,
    ));
    let mut unreadable = 0_usize;
    for frame in &recovery.frames {
        if frame.kind != RecordKind::KeyBudget {
            continue;
        }
        match decode_record(&frame.payload) {
            Some(record) => ledger.restore(record),
            None => unreadable = unreadable.saturating_add(1),
        }
    }
    (ledger, unreadable)
}

/// Encode a ledger record for the log.
#[must_use]
pub fn encode_record(record: &BudgetRecord) -> Vec<u8> {
    let mut object = Object::new();
    object.push("key", Value::from(record.key.as_str()));
    object.push("tenant", Value::from(record.tenant.as_str()));
    object.push_opt("limit", record.limit.map(Value::from));
    object.push("drawn", Value::from(record.drawn));
    object.push("revision", Value::from(record.revision));
    if let Some(payment) = &record.payment {
        object.push_opt("payment_message", payment.message().map(Value::from));
        object.push_opt("payment_url", payment.payment_url().map(Value::from));
    }
    if let Some(receipt) = &record.receipt {
        let mut inner = Object::new();
        inner.push("idempotency_key", Value::from(receipt.idempotency_key.as_str()));
        inner.push("request_digest", Value::from(receipt.request_digest.as_str()));
        inner.push("tokens", Value::from(receipt.tokens));
        inner.push("limit_after", Value::from(receipt.limit_after));
        inner.push("revision_after", Value::from(receipt.revision_after));
        inner.push("at_millis", Value::from(receipt.at_millis));
        inner.push("actor", Value::from(receipt.actor.as_str()));
        inner.push_opt("reason", receipt.reason.as_deref().map(Value::from));
        object.push("receipt", Value::Object(inner));
    }
    to_string(&Value::Object(object)).into_bytes()
}

fn tokens_field(value: &Value, name: &str) -> Option<u64> {
    value.get(name)?.as_u64().filter(|tokens| *tokens <= MAX_TOKENS)
}

fn optional_str<'a>(value: &'a Value, name: &str) -> Option<Option<&'a str>> {
    match value.get(name) {
        None | Some(Value::Null) => Some(None),
        Some(present) => present.as_str().map(Some),
    }
}

/// Decode a ledger record. `None` for anything that is not exactly one.
///
/// Strict in the direction that matters: a record whose limit, mark or receipt
/// is present but malformed is rejected whole, never read as "unlimited" or
/// "nothing consumed".
#[must_use]
pub fn decode_record(payload: &[u8]) -> Option<BudgetRecord> {
    let value = parse(payload, &Limits::SMALL).ok()?;
    value.as_object()?;
    let limit = match value.get("limit") {
        None | Some(Value::Null) => None,
        Some(present) => Some(present.as_u64().filter(|limit| *limit <= MAX_TOKENS)?),
    };
    let payment = PaymentInstructions::new(
        optional_str(&value, "payment_message")?,
        optional_str(&value, "payment_url")?,
    )
    .ok()?;
    let receipt = match value.get("receipt") {
        None | Some(Value::Null) => None,
        Some(inner) => {
            inner.as_object()?;
            let idempotency_key = inner.get("idempotency_key")?.as_str()?;
            if !valid_idempotency_key(idempotency_key) {
                return None;
            }
            Some(CreditReceipt {
                idempotency_key: idempotency_key.to_owned(),
                request_digest: inner.get("request_digest")?.as_str()?.to_owned(),
                tokens: tokens_field(inner, "tokens")?,
                limit_after: tokens_field(inner, "limit_after")?,
                revision_after: inner.get("revision_after")?.as_u64()?,
                at_millis: inner.get("at_millis")?.as_u64()?,
                actor: inner.get("actor")?.as_str()?.to_owned(),
                reason: optional_str(inner, "reason")?.map(str::to_owned),
            })
        }
    };
    Some(BudgetRecord {
        key: KeyId::new(value.get("key")?.as_str()?).ok()?,
        tenant: TenantId::new(value.get("tenant")?.as_str()?).ok()?,
        limit,
        drawn: tokens_field(&value, "drawn")?,
        revision: value.get("revision")?.as_u64()?,
        payment,
        receipt,
    })
}

/// Whether `key` is an acceptable `Idempotency-Key`: 1 to 128 printable ASCII
/// bytes. It names an operation in somebody else's system and is written to
/// the log and the audit trail verbatim, so it is bounded and unambiguous.
#[must_use]
pub fn valid_idempotency_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES
        && key.bytes().all(|b| b.is_ascii_graphic())
}

/// Whether `reason` is an acceptable credit reason.
#[must_use]
pub fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_CREDIT_REASON_BYTES
        && !reason.chars().any(char::is_control)
}

/// Payment instructions as the JSON object of specification 12.2.
#[must_use]
pub fn payment_value(payment: &PaymentInstructions) -> Value {
    let mut object = Object::new();
    object.push_opt("message", payment.message().map(Value::from));
    object.push_opt("payment_url", payment.payment_url().map(Value::from));
    Value::Object(object)
}

/// The entity tag for a budget's editable state.
///
/// Specification 12.3: "ETags/revisions cover the editable limit and payment
/// override, so ordinary consumption does not invalidate an operator's
/// update." The tenant default is deliberately outside it — that changes with
/// a configuration publication, and a payment system holding an ETag across
/// one should not have its credit refused for it.
#[must_use]
pub fn budget_etag(key: &KeyId, view: &BudgetView) -> String {
    let mut object = Object::new();
    object.push("key", Value::from(key.as_str()));
    object.push("revision", Value::from(view.revision));
    object.push("token_limit", view.limit.map_or(Value::Null, Value::from));
    object.push(
        "payment_required",
        view.payment.as_ref().map_or(Value::Null, payment_value),
    );
    etag_for(&Value::Object(object))
}

/// The budget snapshot of specification 12.3.
///
/// `payment_required` is the *effective* value — the key's override, else the
/// tenant default — and `payment_override` says which of the two it is, so an
/// operator editing the override can tell an inherited value from a set one.
#[must_use]
pub fn budget_value(
    key: &KeyId,
    view: &BudgetView,
    tenant_default: Option<&PaymentInstructions>,
) -> Value {
    let mut object = Object::new();
    object.push("key_id", Value::from(key.as_str()));
    object.push("token_limit", view.limit.map_or(Value::Null, Value::from));
    object.push("consumed_tokens", Value::from(view.consumed));
    object.push("reserved_tokens", Value::from(view.reserved));
    object.push(
        "remaining_tokens",
        view.remaining().map_or(Value::Null, Value::from),
    );
    object.push(
        "payment_required",
        view.payment
            .as_ref()
            .or(tenant_default)
            .map_or(Value::Null, payment_value),
    );
    object.push("payment_override", Value::from(view.payment.is_some()));
    object.push("revision", Value::from(view.revision));
    object.push("etag", Value::from(budget_etag(key, view)));
    Value::Object(object)
}

/// A credit receipt as returned by `budget:credit`.
#[must_use]
pub fn receipt_value(receipt: &CreditReceipt) -> Value {
    let mut object = Object::new();
    object.push("idempotency_key", Value::from(receipt.idempotency_key.as_str()));
    object.push("tokens", Value::from(receipt.tokens));
    object.push("token_limit", Value::from(receipt.limit_after));
    object.push("revision", Value::from(receipt.revision_after));
    object.push("credited_at", Value::from(receipt.at_millis));
    object.push("credited_by", Value::from(receipt.actor.as_str()));
    object.push_opt("reason", receipt.reason.as_deref().map(Value::from));
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> BudgetRecord {
        BudgetRecord {
            key: KeyId::new("0123456789abcdef").unwrap(),
            tenant: TenantId::new("acme").unwrap(),
            limit: Some(1_500_000),
            drawn: 1_000_000,
            revision: 3,
            payment: PaymentInstructions::new(
                Some("Purchase more tokens in the customer portal."),
                Some("https://billing.example/tokens"),
            )
            .unwrap(),
            receipt: Some(CreditReceipt {
                idempotency_key: "pay-7".to_owned(),
                request_digest: "abc".to_owned(),
                tokens: 500_000,
                limit_after: 1_500_000,
                revision_after: 3,
                at_millis: 42,
                actor: "svc:pay".to_owned(),
                reason: Some("invoice 7".to_owned()),
            }),
        }
    }

    #[test]
    fn a_record_survives_the_log_exactly() {
        let full = record();
        assert_eq!(decode_record(&encode_record(&full)), Some(full.clone()));

        let bare = BudgetRecord {
            limit: None,
            payment: None,
            receipt: None,
            ..full
        };
        assert_eq!(decode_record(&encode_record(&bare)), Some(bare));
    }

    #[test]
    fn a_malformed_limit_is_never_read_as_unlimited() {
        for (from, to) in [
            (r#""limit":1500000"#, r#""limit":"1500000""#),
            (r#""limit":1500000"#, r#""limit":-1"#),
            (r#""limit":1500000"#, r#""limit":1.5e6"#),
            (r#""drawn":1000000"#, r#""drawn":null"#),
            (r#""drawn":1000000"#, r#""drawn":-5"#),
        ] {
            let text = String::from_utf8(encode_record(&record())).unwrap();
            assert!(text.contains(from), "fixture drifted: {text}");
            let tampered = text.replace(from, to);
            assert_eq!(decode_record(tampered.as_bytes()), None, "{tampered}");
        }
    }

    #[test]
    fn the_etag_ignores_consumption_and_follows_the_editable_state() {
        let key = KeyId::new("0123456789abcdef").unwrap();
        let view = BudgetView {
            limit: Some(100),
            consumed: 0,
            reserved: 0,
            revision: 1,
            payment: None,
        };
        let spent = BudgetView {
            consumed: 60,
            reserved: 20,
            ..view.clone()
        };
        assert_eq!(budget_etag(&key, &view), budget_etag(&key, &spent));
        let raised = BudgetView {
            limit: Some(200),
            revision: 2,
            ..view.clone()
        };
        assert_ne!(budget_etag(&key, &view), budget_etag(&key, &raised));
    }
}
