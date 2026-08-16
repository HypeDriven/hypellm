//! The audit hash chain.
//!
//! Specification 11.2: "Audit records form a hash/MAC chain with periodic
//! signed checkpoints exported to immutable storage."
//! Specification 17 lists what must be recorded: "Login, role/key/credential/
//! config changes, policy approval, break-glass, export, quarantine, rollback."
//!
//! Each record commits to its predecessor:
//!
//! ```text
//! link[n] = SHA-256( link[n-1] || canonical_json(event[n]) )
//! ```
//!
//! Removing, reordering, or editing any record breaks every link after it. A
//! checkpoint MACs the current head with a key the router holds, so an offline
//! copy of the chain can be verified against a checkpoint without replaying it
//! against a live router.
//!
//! Audit records carry **no request content**. Specification 10 makes prompts
//! and tool arguments sensitive by default, and specification 17 caps log
//! fields; the audit trail records who did what to which object with what
//! result, not what was said to a model.

use hypellm_core::sensitive::Capped;
use hypellm_crypto::{Digest, hmac_sha256_parts, sha256_parts};
use wire_json::{Object, Value, to_canonical_vec};

/// The genesis link: the value `link[-1]` takes.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// What happened.
///
/// The set is closed rather than free-text so that the audit view can filter on
/// it and an operator cannot accidentally write an unqueryable action name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditAction {
    /// A human signed in.
    Login,
    /// A human signed out.
    Logout,
    /// A sign-in attempt failed.
    LoginFailed,
    /// A router API key was created.
    KeyCreated,
    /// A router API key was revoked.
    KeyRevoked,
    /// A provider credential reference was created.
    CredentialCreated,
    /// A provider credential was rotated.
    CredentialRotated,
    /// A credential was validated with a low-cost upstream probe.
    CredentialProbed,
    /// The configuration file was adopted over a published activation.
    ConfigAdopted,
    /// A provider credential reference was revoked.
    CredentialRevoked,
    /// A policy draft was created or edited.
    PolicyDrafted,
    /// A policy draft was validated.
    PolicyValidated,
    /// A policy was published and activated.
    PolicyPublished,
    /// A configuration was rolled back.
    PolicyRolledBack,
    /// A role binding changed.
    RoleChanged,
    /// A target was drained, put into maintenance, or restored.
    TargetStateChanged,
    /// A target was quarantined.
    TargetQuarantined,
    /// A quarantine was lifted.
    TargetQuarantineLifted,
    /// A break-glass session was opened.
    BreakGlassOpened,
    /// A break-glass session was closed.
    BreakGlassClosed,
    /// Audit records were exported.
    AuditExported,
    /// The router started.
    RouterStarted,
    /// The router shut down.
    RouterStopped,
    /// Settings were changed.
    SettingsChanged,
}

impl AuditAction {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::LoginFailed => "login_failed",
            Self::KeyCreated => "key_created",
            Self::KeyRevoked => "key_revoked",
            Self::CredentialCreated => "credential_created",
            Self::CredentialRotated => "credential_rotated",
            Self::CredentialProbed => "credential_probed",
            Self::ConfigAdopted => "config_adopted",
            Self::CredentialRevoked => "credential_revoked",
            Self::PolicyDrafted => "policy_drafted",
            Self::PolicyValidated => "policy_validated",
            Self::PolicyPublished => "policy_published",
            Self::PolicyRolledBack => "policy_rolled_back",
            Self::RoleChanged => "role_changed",
            Self::TargetStateChanged => "target_state_changed",
            Self::TargetQuarantined => "target_quarantined",
            Self::TargetQuarantineLifted => "target_quarantine_lifted",
            Self::BreakGlassOpened => "break_glass_opened",
            Self::BreakGlassClosed => "break_glass_closed",
            Self::AuditExported => "audit_exported",
            Self::RouterStarted => "router_started",
            Self::RouterStopped => "router_stopped",
            Self::SettingsChanged => "settings_changed",
        }
    }

    /// Parse from a stored record.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|a| a.as_str() == s)
    }

    /// Whether this action requires a stated reason.
    ///
    /// Specification 13 requires a reason for quarantine; specification 9.3
    /// requires one for break-glass.
    #[must_use]
    pub const fn requires_reason(self) -> bool {
        matches!(
            self,
            Self::TargetQuarantined | Self::BreakGlassOpened | Self::PolicyRolledBack
        )
    }

    /// Every action.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Login,
            Self::Logout,
            Self::LoginFailed,
            Self::KeyCreated,
            Self::KeyRevoked,
            Self::CredentialCreated,
            Self::CredentialRotated,
            Self::CredentialProbed,
            Self::ConfigAdopted,
            Self::CredentialRevoked,
            Self::PolicyDrafted,
            Self::PolicyValidated,
            Self::PolicyPublished,
            Self::PolicyRolledBack,
            Self::RoleChanged,
            Self::TargetStateChanged,
            Self::TargetQuarantined,
            Self::TargetQuarantineLifted,
            Self::BreakGlassOpened,
            Self::BreakGlassClosed,
            Self::AuditExported,
            Self::RouterStarted,
            Self::RouterStopped,
            Self::SettingsChanged,
        ]
    }
}

/// Whether the action succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// It succeeded.
    Success,
    /// It was denied by authorization.
    Denied,
    /// It failed.
    Failed,
}

impl AuditOutcome {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// One audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Wall-clock milliseconds since the epoch.
    pub timestamp_millis: u64,
    /// Who performed the action.
    pub actor: String,
    /// The tenant the action applies to.
    pub tenant: Option<String>,
    /// What happened.
    pub action: AuditAction,
    /// The object acted upon, such as a target or key identifier.
    pub object: Option<String>,
    /// The outcome.
    pub outcome: AuditOutcome,
    /// A stated reason, required for some actions.
    pub reason: Option<Capped>,
    /// The correlating request identifier, when there is one.
    pub request_id: Option<String>,
    /// The source address, when known.
    pub source: Option<String>,
}

/// The cap applied to every free-text audit field except `reason`.
///
/// Specification 17 requires audit fields to be capped, and specification 3.2
/// bounds every input. `reason` gets 512 because it is prose written by an
/// operator; the rest are identifiers, and 256 is generous for one — the
/// longest an identifier can legally be is `ids::MAX_ID_LEN` (128), so a value
/// this cap actually truncates is already malformed.
///
/// Uncapped, these were the asymmetry that made a record unwritable-then-
/// unreadable: they were written without a bound and read back under
/// `wire_json::Limits::SMALL`, so a long enough value produced a record that
/// authenticates and does not parse. Recovery treats that as a broken chain
/// (`Recovery::audit_chain_broken_at`), which is correct and also a refusal to
/// start — so an uncapped field was a way to make the router unbootable.
pub const MAX_AUDIT_FIELD: usize = 256;

impl AuditEvent {
    /// A successful event.
    #[must_use]
    pub fn new(timestamp_millis: u64, actor: impl Into<String>, action: AuditAction) -> Self {
        Self {
            timestamp_millis,
            actor: Capped::new(&actor.into(), MAX_AUDIT_FIELD).as_str().to_owned(),
            tenant: None,
            action,
            object: None,
            outcome: AuditOutcome::Success,
            reason: None,
            request_id: None,
            source: None,
        }
    }

    /// Set the object.
    #[must_use]
    pub fn with_object(mut self, object: impl Into<String>) -> Self {
        self.object = Some(Capped::new(&object.into(), MAX_AUDIT_FIELD).as_str().to_owned());
        self
    }

    /// Set the tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(Capped::new(&tenant.into(), MAX_AUDIT_FIELD).as_str().to_owned());
        self
    }

    /// Set the outcome.
    #[must_use]
    pub const fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Set the reason, capped.
    #[must_use]
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(Capped::new(reason, 512));
        self
    }

    /// Set the correlating request identifier.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(Capped::new(&request_id.into(), MAX_AUDIT_FIELD).as_str().to_owned());
        self
    }

    /// Set the source address.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(Capped::new(&source.into(), MAX_AUDIT_FIELD).as_str().to_owned());
        self
    }

    /// Whether the event satisfies the reason requirement for its action.
    #[must_use]
    pub fn has_required_reason(&self) -> bool {
        !self.action.requires_reason()
            || self.reason.as_ref().is_some_and(|r| !r.as_str().is_empty())
    }

    /// The canonical JSON encoding that the chain commits to.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut o = Object::new();
        o.push("action", Value::from(self.action.as_str()));
        o.push("actor", Value::from(self.actor.as_str()));
        o.push("outcome", Value::from(self.outcome.as_str()));
        o.push("timestamp_millis", Value::from(self.timestamp_millis));
        o.push_opt("object", self.object.as_deref().map(Value::from));
        o.push_opt("tenant", self.tenant.as_deref().map(Value::from));
        o.push_opt(
            "reason",
            self.reason.as_ref().map(|r| Value::from(r.as_str())),
        );
        o.push_opt("request_id", self.request_id.as_deref().map(Value::from));
        o.push_opt("source", self.source.as_deref().map(Value::from));
        to_canonical_vec(&Value::Object(o))
    }

    /// Parse from canonical JSON.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            timestamp_millis: value.get("timestamp_millis")?.as_u64()?,
            actor: value.get("actor")?.as_str()?.to_owned(),
            tenant: value.get("tenant").and_then(|v| v.as_str()).map(str::to_owned),
            action: AuditAction::parse(value.get("action")?.as_str()?)?,
            object: value.get("object").and_then(|v| v.as_str()).map(str::to_owned),
            outcome: match value.get("outcome")?.as_str()? {
                "success" => AuditOutcome::Success,
                "denied" => AuditOutcome::Denied,
                "failed" => AuditOutcome::Failed,
                _ => return None,
            },
            reason: value
                .get("reason")
                .and_then(|v| v.as_str())
                .map(|s| Capped::new(s, 512)),
            request_id: value
                .get("request_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            source: value.get("source").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }
}

/// A chained audit record: the previous link plus the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The link value of the preceding record.
    pub previous_link: [u8; 32],
    /// The event.
    pub event: AuditEvent,
}

impl AuditRecord {
    /// The stored payload: 32 bytes of previous link, then canonical JSON.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let json = self.event.to_canonical_bytes();
        let mut out = Vec::with_capacity(32 + json.len());
        out.extend_from_slice(&self.previous_link);
        out.extend_from_slice(&json);
        out
    }

    /// Parse a stored payload.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        // Splitting off the link as a fixed-size chunk is the length check: a
        // payload shorter than the link is rejected without indexing it.
        let (previous_link, json) = payload.split_first_chunk::<32>()?;
        let value = wire_json::parse(json, &wire_json::Limits::SMALL).ok()?;
        Some(Self {
            previous_link: *previous_link,
            event: AuditEvent::from_json(&value)?,
        })
    }

    /// This record's link value.
    #[must_use]
    pub fn link(&self) -> [u8; 32] {
        link_of(&self.previous_link, &self.event.to_canonical_bytes())
    }
}

/// Compute a chain link.
#[must_use]
pub fn link_of(previous: &[u8; 32], event_bytes: &[u8]) -> [u8; 32] {
    // Domain-separated so that a link value can never be confused with any
    // other digest the router computes.
    sha256_parts(&[b"hypellm.audit.v1", previous, event_bytes])
}

/// A signed checkpoint over the chain head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheckpoint {
    /// The sequence number of the last record covered.
    pub sequence: u64,
    /// The chain head at that point.
    pub link: [u8; 32],
    /// When the checkpoint was taken.
    pub timestamp_millis: u64,
    /// The MAC over the above.
    pub mac: [u8; 32],
}

impl AuditCheckpoint {
    /// Create a checkpoint over `link`.
    #[must_use]
    pub fn create(sequence: u64, link: [u8; 32], timestamp_millis: u64, key: &[u8]) -> Self {
        Self {
            sequence,
            link,
            timestamp_millis,
            mac: checkpoint_mac(sequence, &link, timestamp_millis, key),
        }
    }

    /// Verify the checkpoint's MAC.
    #[must_use]
    pub fn verify(&self, key: &[u8]) -> bool {
        let expected = checkpoint_mac(self.sequence, &self.link, self.timestamp_millis, key);
        hypellm_crypto::ct::eq(&expected, &self.mac)
    }

    /// The stored payload.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 8 + 32);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.link);
        out.extend_from_slice(&self.timestamp_millis.to_le_bytes());
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parse a stored payload.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        // Four fixed-size fields and nothing after them: the chain of splits
        // accepts exactly the 80-byte payload `to_payload` writes, and rejects
        // anything shorter or longer without indexing.
        let (sequence, rest) = payload.split_first_chunk::<8>()?;
        let (link, rest) = rest.split_first_chunk::<32>()?;
        let (timestamp, rest) = rest.split_first_chunk::<8>()?;
        let (mac, rest) = rest.split_first_chunk::<32>()?;
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            sequence: u64::from_le_bytes(*sequence),
            link: *link,
            timestamp_millis: u64::from_le_bytes(*timestamp),
            mac: *mac,
        })
    }
}

fn checkpoint_mac(sequence: u64, link: &[u8; 32], timestamp_millis: u64, key: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(
        key,
        &[
            b"hypellm.audit.checkpoint.v1",
            &sequence.to_le_bytes(),
            link,
            &timestamp_millis.to_le_bytes(),
        ],
    )
}

/// The result of verifying a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerification {
    /// Every link matched.
    Intact {
        /// The final link value.
        head: [u8; 32],
        /// How many records were verified.
        count: usize,
    },
    /// A link did not match its predecessor.
    Broken {
        /// Index of the first record whose link did not match.
        index: usize,
    },
}

impl ChainVerification {
    /// Whether the chain verified.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        matches!(self, Self::Intact { .. })
    }
}

/// Verify a sequence of records forms an unbroken chain from genesis.
#[must_use]
pub fn verify_chain(records: &[AuditRecord]) -> ChainVerification {
    let mut expected = GENESIS;
    for (index, record) in records.iter().enumerate() {
        if record.previous_link != expected {
            return ChainVerification::Broken { index };
        }
        expected = record.link();
    }
    ChainVerification::Intact {
        head: expected,
        count: records.len(),
    }
}

/// The running head of an audit chain.
#[derive(Debug)]
pub struct AuditChain {
    head: [u8; 32],
    count: u64,
}

impl AuditChain {
    /// Start a fresh chain at genesis.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: GENESIS,
            count: 0,
        }
    }

    /// Resume a chain from a known head.
    #[must_use]
    pub const fn resume(head: [u8; 32], count: u64) -> Self {
        Self { head, count }
    }

    /// The current head.
    #[must_use]
    pub const fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The current head as a displayable digest.
    #[must_use]
    pub const fn head_digest(&self) -> Digest {
        Digest::from_bytes(self.head)
    }

    /// How many records the chain covers.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Chain an event, returning the record to store.
    pub fn append(&mut self, event: AuditEvent) -> AuditRecord {
        let record = AuditRecord {
            previous_link: self.head,
            event,
        };
        self.head = record.link();
        self.count += 1;
        record
    }

    /// Take a checkpoint over the current head.
    #[must_use]
    pub fn checkpoint(&self, sequence: u64, timestamp_millis: u64, key: &[u8]) -> AuditCheckpoint {
        AuditCheckpoint::create(sequence, self.head, timestamp_millis, key)
    }
}

impl Default for AuditChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_audit_field_is_capped_on_write() {
        // The asymmetry this closes: `reason` was capped at write, the other
        // five were not, and the read path parses under
        // `wire_json::Limits::SMALL`. A long enough actor or object therefore
        // produced a record that authenticates under the store MAC and does not
        // parse back — and since recovery treats an undecodable audit frame as
        // a broken chain and refuses to start, an uncapped field was a way to
        // make the router unbootable.
        let long = "x".repeat(4096);
        let event = AuditEvent::new(0, long.clone(), AuditAction::KeyCreated)
            .with_object(long.clone())
            .with_tenant(long.clone())
            .with_request_id(long.clone())
            .with_source(long.clone())
            .with_reason(&long);

        assert_eq!(event.actor.len(), MAX_AUDIT_FIELD);
        assert_eq!(event.object.as_deref().map(str::len), Some(MAX_AUDIT_FIELD));
        assert_eq!(event.tenant.as_deref().map(str::len), Some(MAX_AUDIT_FIELD));
        assert_eq!(
            event.request_id.as_deref().map(str::len),
            Some(MAX_AUDIT_FIELD)
        );
        assert_eq!(event.source.as_deref().map(str::len), Some(MAX_AUDIT_FIELD));
        assert_eq!(event.reason.as_ref().map(|r| r.as_str().len()), Some(512));
    }

    #[test]
    fn a_capped_record_still_round_trips_through_the_chain() {
        // The property the caps exist to preserve: whatever is written can be
        // read back. Asserted against the encoder and decoder rather than
        // against the lengths, because the lengths are only a means to it.
        let long = "y".repeat(4096);
        let event = AuditEvent::new(7, long.clone(), AuditAction::KeyRevoked)
            .with_object(long.clone())
            .with_tenant(long.clone())
            .with_request_id(long.clone())
            .with_source(long)
            .with_reason("an operator note");

        let mut chain = AuditChain::new();
        let record = chain.append(event.clone());
        let payload = record.to_payload();
        let decoded = AuditRecord::from_payload(&payload)
            .expect("a record written by this crate must parse back");
        assert_eq!(decoded.event.actor, event.actor);
        assert_eq!(decoded.event.object, event.object);
        assert_eq!(decoded.link(), record.link());
    }

    use super::*;

    const KEY: &[u8] = b"audit-checkpoint-key";

    fn event(n: u64, action: AuditAction) -> AuditEvent {
        AuditEvent::new(1_767_225_600_000 + n, format!("user:{n}"), action)
            .with_object(format!("object-{n}"))
            .with_tenant("acme")
    }

    #[test]
    fn a_chain_of_events_verifies() {
        let mut chain = AuditChain::new();
        let records: Vec<AuditRecord> = (0..10)
            .map(|n| chain.append(event(n, AuditAction::Login)))
            .collect();

        assert_eq!(chain.count(), 10);
        match verify_chain(&records) {
            ChainVerification::Intact { head, count } => {
                assert_eq!(head, chain.head());
                assert_eq!(count, 10);
            }
            other => panic!("expected intact chain, got {other:?}"),
        }
    }

    #[test]
    fn the_first_record_links_to_genesis() {
        let mut chain = AuditChain::new();
        let record = chain.append(event(0, AuditAction::RouterStarted));
        assert_eq!(record.previous_link, GENESIS);
        assert_ne!(chain.head(), GENESIS);
    }

    #[test]
    fn editing_a_record_breaks_the_chain() {
        // The property the chain exists for.
        let mut chain = AuditChain::new();
        let mut records: Vec<AuditRecord> = (0..5)
            .map(|n| chain.append(event(n, AuditAction::PolicyPublished)))
            .collect();
        assert!(verify_chain(&records).is_intact());

        records[2].event.actor = "user:attacker".to_owned();
        match verify_chain(&records) {
            // Record 2's own link changes, so record 3's stored previous_link
            // no longer matches.
            ChainVerification::Broken { index } => assert_eq!(index, 3),
            other => panic!("editing must break the chain, got {other:?}"),
        }
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let mut chain = AuditChain::new();
        let mut records: Vec<AuditRecord> = (0..5)
            .map(|n| chain.append(event(n, AuditAction::KeyCreated)))
            .collect();
        records.remove(2);
        match verify_chain(&records) {
            ChainVerification::Broken { index } => assert_eq!(index, 2),
            other => panic!("deletion must break the chain, got {other:?}"),
        }
    }

    #[test]
    fn reordering_records_breaks_the_chain() {
        let mut chain = AuditChain::new();
        let mut records: Vec<AuditRecord> = (0..5)
            .map(|n| chain.append(event(n, AuditAction::RoleChanged)))
            .collect();
        records.swap(1, 3);
        assert!(!verify_chain(&records).is_intact());
    }

    #[test]
    fn appending_a_forged_record_at_the_end_breaks_the_chain() {
        let mut chain = AuditChain::new();
        let mut records: Vec<AuditRecord> = (0..3)
            .map(|n| chain.append(event(n, AuditAction::Login)))
            .collect();
        records.push(AuditRecord {
            previous_link: GENESIS,
            event: event(99, AuditAction::BreakGlassOpened),
        });
        match verify_chain(&records) {
            ChainVerification::Broken { index } => assert_eq!(index, 3),
            other => panic!("expected break at 3, got {other:?}"),
        }
    }

    #[test]
    fn records_round_trip_through_their_payload() {
        let mut chain = AuditChain::new();
        let record = chain.append(
            event(1, AuditAction::TargetQuarantined)
                .with_reason("provider outage, incident INC-42")
                .with_request_id("0123456789abcdef0123456789abcdef")
                .with_source("10.0.0.5")
                .with_outcome(AuditOutcome::Success),
        );
        let payload = record.to_payload();
        let parsed = AuditRecord::from_payload(&payload).expect("parses");
        assert_eq!(parsed, record);
        assert_eq!(parsed.link(), record.link());
    }

    #[test]
    fn a_malformed_payload_does_not_parse() {
        assert_eq!(AuditRecord::from_payload(b"short"), None);
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(b"not json");
        assert_eq!(AuditRecord::from_payload(&payload), None);
    }

    #[test]
    fn canonical_encoding_is_field_order_independent() {
        // The chain commits to canonical JSON, so two structurally identical
        // events must hash the same however they were built.
        let a = AuditEvent::new(1, "actor", AuditAction::Login)
            .with_tenant("acme")
            .with_object("obj");
        let b = AuditEvent::new(1, "actor", AuditAction::Login)
            .with_object("obj")
            .with_tenant("acme");
        assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    }

    #[test]
    fn checkpoints_verify_and_detect_edits() {
        let mut chain = AuditChain::new();
        for n in 0..5 {
            chain.append(event(n, AuditAction::Login));
        }
        let checkpoint = chain.checkpoint(5, 1_767_225_600_000, KEY);
        assert!(checkpoint.verify(KEY));
        assert!(!checkpoint.verify(b"wrong-key"));

        let mut tampered = checkpoint.clone();
        tampered.link[0] ^= 0x01;
        assert!(!tampered.verify(KEY), "an edited head must not verify");

        let mut renumbered = checkpoint.clone();
        renumbered.sequence += 1;
        assert!(!renumbered.verify(KEY), "an edited sequence must not verify");

        let mut retimed = checkpoint.clone();
        retimed.timestamp_millis += 1;
        assert!(!retimed.verify(KEY));
    }

    #[test]
    fn checkpoints_round_trip_through_their_payload() {
        let checkpoint = AuditCheckpoint::create(7, [0xab; 32], 1_767_225_600_000, KEY);
        let payload = checkpoint.to_payload();
        assert_eq!(payload.len(), 80);
        let parsed = AuditCheckpoint::from_payload(&payload).expect("parses");
        assert_eq!(parsed, checkpoint);
        assert!(parsed.verify(KEY));

        assert_eq!(AuditCheckpoint::from_payload(b"short"), None);
        assert_eq!(AuditCheckpoint::from_payload(&[0u8; 81]), None);
    }

    #[test]
    fn a_resumed_chain_continues_correctly() {
        let mut chain = AuditChain::new();
        let mut records: Vec<AuditRecord> =
            (0..3).map(|n| chain.append(event(n, AuditAction::Login))).collect();

        // Restart: resume from the stored head.
        let mut resumed = AuditChain::resume(chain.head(), chain.count());
        records.push(resumed.append(event(3, AuditAction::Logout)));

        assert!(verify_chain(&records).is_intact());
        assert_eq!(resumed.count(), 4);
    }

    #[test]
    fn actions_requiring_a_reason_are_enforceable() {
        // Specification 13 requires a reason for quarantine.
        let without = event(1, AuditAction::TargetQuarantined);
        assert!(!without.has_required_reason());
        let with = without.clone().with_reason("provider outage");
        assert!(with.has_required_reason());

        // Actions that do not require one are always satisfied.
        assert!(event(1, AuditAction::Login).has_required_reason());

        for action in AuditAction::all() {
            if action.requires_reason() {
                assert!(!event(1, *action).has_required_reason(), "{action:?}");
            }
        }
    }

    #[test]
    fn specification_17_actions_all_exist() {
        // "Login, role/key/credential/config changes, policy approval,
        // break-glass, export, quarantine, rollback."
        for action in [
            AuditAction::Login,
            AuditAction::RoleChanged,
            AuditAction::KeyCreated,
            AuditAction::CredentialRotated,
            AuditAction::SettingsChanged,
            AuditAction::PolicyPublished,
            AuditAction::BreakGlassOpened,
            AuditAction::AuditExported,
            AuditAction::TargetQuarantined,
            AuditAction::PolicyRolledBack,
        ] {
            assert!(AuditAction::parse(action.as_str()).is_some());
        }
    }

    #[test]
    fn action_names_are_distinct_and_round_trip() {
        let mut names: Vec<&str> = AuditAction::all().iter().map(|a| a.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        for a in AuditAction::all() {
            assert_eq!(AuditAction::parse(a.as_str()), Some(*a));
        }
        assert_eq!(AuditAction::parse("nonexistent"), None);
    }

    #[test]
    fn reasons_are_capped() {
        let e = event(1, AuditAction::TargetQuarantined).with_reason(&"x".repeat(10_000));
        let reason = e.reason.as_ref().expect("reason");
        assert_eq!(reason.as_str().len(), 512);
        assert!(reason.is_truncated());
    }

    #[test]
    fn an_empty_chain_verifies_as_intact() {
        match verify_chain(&[]) {
            ChainVerification::Intact { head, count } => {
                assert_eq!(head, GENESIS);
                assert_eq!(count, 0);
            }
            other => panic!("expected intact, got {other:?}"),
        }
    }
}
