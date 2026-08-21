//! The durable form of fleet state.
//!
//! Three record types join the `hypellm-store` append-only framed log and are
//! replayed at startup under the existing integrity rules.
//!
//! | Record | Why it is durable |
//! |---|---|
//! | **Lease** | Written *before* the mutating verb. On restart the router replays leases, queries each activation's status, and reconciles. Because agent verbs are idempotent per lease, re-issuing is safe. |
//! | **Activation outcome** | Feeds the observed-timing cost model and the "why was this evicted" view. |
//! | **Flap counter** | A router bounce that reset accrued backoff would permit a fresh burst of exactly the thrash the backoff exists to stop. |
//!
//! Demand averages are **not** persisted. They rebuild from traffic.
//! Persisting an advisory statistic so it survives a restart is how a scheduler
//! ends up acting confidently on data from before an outage — the moment when
//! it is least likely to still be true.
//!
//! # The encoding
//!
//! JSON through `wire-json`, parsed under `Limits::SMALL`. Every field is
//! range-checked on the way back in, and a record that fails any check is
//! **skipped rather than adopted**: a corrupt lease that the router acted on
//! would send a verb nobody asked for, while a skipped one expires and is
//! audited.

use crate::activation::{ActivationOutcome, ActivationRecord};
use crate::state::{Lease, LeaseOperation};
use hypellm_core::ids::{DeploymentId, HostId, LeaseId};
use wire_json::{Limits, Object, Value};

/// Maximum bytes any one durable fleet record may occupy.
pub const MAX_RECORD_BYTES: usize = 4 * 1024;

/// Limits applied when replaying a fleet record.
#[must_use]
fn record_limits() -> Limits {
    Limits::SMALL.with_max_input_bytes(MAX_RECORD_BYTES)
}

/// Encode a lease for the durable log.
#[must_use]
pub fn encode_lease(lease: &Lease) -> Vec<u8> {
    let mut object = Object::new();
    object.push("lease", Value::from(lease.id.as_str()));
    object.push("deployment", Value::from(lease.deployment.as_str()));
    object.push("operation", Value::from(lease.operation.as_str()));
    object.push("issued_ms", Value::from(i64_of(lease.issued_ms)));
    object.push("expires_ms", Value::from(i64_of(lease.expires_ms)));
    object.push("decision", Value::from(lease.decision_id.as_str()));
    wire_json::to_vec(&Value::Object(object))
}

/// Decode a lease, or `None` if the record cannot be trusted.
#[must_use]
pub fn decode_lease(payload: &[u8]) -> Option<Lease> {
    let value = wire_json::parse(payload, &record_limits()).ok()?;
    let id = LeaseId::new(value.get("lease")?.as_str()?).ok()?;
    let deployment = DeploymentId::new(value.get("deployment")?.as_str()?).ok()?;
    let operation = LeaseOperation::parse(value.get("operation")?.as_str()?)?;
    let issued_ms = value.get("issued_ms")?.as_u64()?;
    let expires_ms = value.get("expires_ms")?.as_u64()?;
    if expires_ms < issued_ms {
        // A lease that expired before it was issued is either a corrupt record
        // or a clock that moved backwards across a restart. Either way it is
        // not something to reconcile against.
        return None;
    }
    let decision_id = value
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(32)
        .filter(char::is_ascii_alphanumeric)
        .collect();
    Some(Lease {
        id,
        deployment,
        operation,
        issued_ms,
        expires_ms,
        decision_id,
    })
}

/// What an activation cost and how it ended.
///
/// A flattened form of [`ActivationRecord`]: the durable log keeps the numbers
/// the cost model and the operator view need, not the whole in-memory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSummary {
    /// Which deployment.
    pub deployment: DeploymentId,
    /// Which host.
    pub host: HostId,
    /// How it ended.
    pub outcome: ActivationOutcome,
    /// How long it took, in milliseconds.
    pub duration_ms: u64,
    /// What it displaced.
    pub evicted: Vec<DeploymentId>,
    /// The decision that caused it, or empty for an operator action.
    pub decision_id: String,
    /// When it finished, on the router's monotonic clock.
    pub finished_ms: u64,
}

impl ActivationSummary {
    /// Flatten an in-memory record.
    #[must_use]
    pub fn from_record(record: &ActivationRecord, now_ms: u64) -> Self {
        Self {
            deployment: record.lease.deployment.clone(),
            host: record.host.clone(),
            outcome: record.outcome.unwrap_or(ActivationOutcome::Failed),
            duration_ms: record.duration_ms(now_ms),
            evicted: record.evicted.clone(),
            decision_id: record.lease.decision_id.clone(),
            finished_ms: record.finished_ms.unwrap_or(now_ms),
        }
    }
}

/// Encode an activation outcome for the durable log.
#[must_use]
pub fn encode_activation(summary: &ActivationSummary) -> Vec<u8> {
    let mut object = Object::new();
    object.push("deployment", Value::from(summary.deployment.as_str()));
    object.push("host", Value::from(summary.host.as_str()));
    object.push("outcome", Value::from(summary.outcome.as_str()));
    object.push("duration_ms", Value::from(i64_of(summary.duration_ms)));
    object.push("finished_ms", Value::from(i64_of(summary.finished_ms)));
    object.push("decision", Value::from(summary.decision_id.as_str()));
    object.push(
        "evicted",
        Value::Array(
            summary
                .evicted
                .iter()
                .take(8)
                .map(|d| Value::from(d.as_str()))
                .collect(),
        ),
    );
    wire_json::to_vec(&Value::Object(object))
}

/// Decode an activation outcome, or `None` if it cannot be trusted.
#[must_use]
pub fn decode_activation(payload: &[u8]) -> Option<ActivationSummary> {
    let value = wire_json::parse(payload, &record_limits()).ok()?;
    let deployment = DeploymentId::new(value.get("deployment")?.as_str()?).ok()?;
    let host = HostId::new(value.get("host")?.as_str()?).ok()?;
    let outcome = match value.get("outcome")?.as_str()? {
        "succeeded" => ActivationOutcome::Succeeded,
        "failed" => ActivationOutcome::Failed,
        "rolled_back" => ActivationOutcome::FailedAndRolledBack,
        "quarantined" => ActivationOutcome::FailedAndQuarantined,
        "cancelled" => ActivationOutcome::Cancelled,
        _ => return None,
    };
    let evicted = match value.get("evicted") {
        Some(Value::Array(items)) => items
            .iter()
            .take(8)
            .filter_map(|v| v.as_str().and_then(|s| DeploymentId::new(s).ok()))
            .collect(),
        _ => Vec::new(),
    };
    Some(ActivationSummary {
        deployment,
        host,
        outcome,
        duration_ms: value.get("duration_ms")?.as_u64()?,
        evicted,
        decision_id: value
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(32)
            .filter(char::is_ascii_alphanumeric)
            .collect(),
        finished_ms: value.get("finished_ms")?.as_u64()?,
    })
}

/// A deployment's accrued flap backoff, in durable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlapRecord {
    /// Which deployment.
    pub deployment: DeploymentId,
    /// Consecutive activate/evict cycles inside the window.
    pub cycles: u32,
    /// When the most recent cycle completed.
    pub last_cycle_ms: u64,
    /// When re-activation becomes permitted.
    pub until_ms: u64,
}

/// Encode a flap counter.
#[must_use]
pub fn encode_flap(record: &FlapRecord) -> Vec<u8> {
    let mut object = Object::new();
    object.push("deployment", Value::from(record.deployment.as_str()));
    object.push("cycles", Value::from(i64::from(record.cycles)));
    object.push("last_cycle_ms", Value::from(i64_of(record.last_cycle_ms)));
    object.push("until_ms", Value::from(i64_of(record.until_ms)));
    wire_json::to_vec(&Value::Object(object))
}

/// Decode a flap counter, or `None` if it cannot be trusted.
#[must_use]
pub fn decode_flap(payload: &[u8]) -> Option<FlapRecord> {
    let value = wire_json::parse(payload, &record_limits()).ok()?;
    let deployment = DeploymentId::new(value.get("deployment")?.as_str()?).ok()?;
    let cycles = u32::try_from(value.get("cycles")?.as_u64()?).ok()?;
    Some(FlapRecord {
        deployment,
        // Bounded on the way in. A corrupt count of four billion would produce
        // a cooldown that never elapses, which is an outage expressed as a
        // number rather than as a failure.
        cycles: cycles.min(64),
        last_cycle_ms: value.get("last_cycle_ms")?.as_u64()?,
        until_ms: value.get("until_ms")?.as_u64()?,
    })
}

/// Widen a monotonic millisecond value for JSON.
///
/// `wire-json` numbers are `i64`. A monotonic clock reaching `i64::MAX`
/// milliseconds is 292 million years of uptime; saturating is the honest
/// treatment for a value that cannot occur but must not wrap if it did.
fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease {
            id: LeaseId::new("lease-1").expect("id"),
            deployment: DeploymentId::new("spark-music3").expect("id"),
            operation: LeaseOperation::Activate,
            issued_ms: 1_000,
            expires_ms: 301_000,
            decision_id: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    }

    #[test]
    fn a_lease_survives_a_round_trip() {
        assert_eq!(decode_lease(&encode_lease(&lease())), Some(lease()));
    }

    #[test]
    fn a_lease_that_expired_before_it_was_issued_is_skipped_not_adopted() {
        // Either a corrupt record or a clock that moved backwards. Acting on
        // it would mean re-issuing a verb nobody asked for.
        let mut bad = lease();
        bad.expires_ms = 0;
        assert_eq!(decode_lease(&encode_lease(&bad)), None);
    }

    #[test]
    fn a_truncated_or_foreign_record_is_skipped_rather_than_half_read() {
        assert_eq!(decode_lease(b"{\"lease\":\"l1\""), None);
        assert_eq!(decode_lease(b"{}"), None);
        assert_eq!(decode_lease(b"[]"), None);
        assert_eq!(decode_activation(b"{\"deployment\":\"d\"}"), None);
        assert_eq!(decode_flap(b"null"), None);
    }

    #[test]
    fn a_decision_identifier_is_narrowed_on_the_way_back_in() {
        // The identifier reaches an audit view and an operator's browser. A
        // record edited on disk must not be able to put anything else there.
        let mut hostile = lease();
        hostile.decision_id = "<script>alert(1)</script>".to_owned();
        let decoded = decode_lease(&encode_lease(&hostile)).expect("decodes");
        assert_eq!(decoded.decision_id, "scriptalert1script");
    }

    #[test]
    fn a_corrupt_flap_count_cannot_produce_a_cooldown_that_never_elapses() {
        let record = FlapRecord {
            deployment: DeploymentId::new("spark-h3").expect("id"),
            cycles: u32::MAX,
            last_cycle_ms: 0,
            until_ms: 0,
        };
        let decoded = decode_flap(&encode_flap(&record)).expect("decodes");
        assert_eq!(decoded.cycles, 64);
    }

    #[test]
    fn an_activation_summary_survives_a_round_trip_with_its_eviction_set() {
        let summary = ActivationSummary {
            deployment: DeploymentId::new("spark-music3").expect("id"),
            host: HostId::new("spark").expect("id"),
            outcome: ActivationOutcome::Succeeded,
            duration_ms: 174_000,
            evicted: vec![DeploymentId::new("spark-h3").expect("id")],
            decision_id: "abc".to_owned(),
            finished_ms: 500_000,
        };
        assert_eq!(decode_activation(&encode_activation(&summary)), Some(summary));
    }
}
