//! A bounded in-memory index over recent audit records.
//!
//! Specification 15.3's audit screen shows "Actor/action/object/result,
//! filters, export, integrity checkpoint status". The durable chain lives in
//! the store; this index is what the screen reads, so a page load does not
//! replay the log.
//!
//! It is a *view*, not the record. The chain in `hypellm-store` is authoritative,
//! and export reads from there. Losing this index on restart is harmless.

use hypellm_crypto::Digest;
use hypellm_store::AuditEvent;
use std::collections::VecDeque;
use std::sync::RwLock;

/// One indexed record.
#[derive(Debug, Clone)]
pub struct IndexedAudit {
    /// The store sequence number.
    pub sequence: u64,
    /// The event.
    pub event: AuditEvent,
    /// The chain link at this record, truncated for display.
    pub link_short: String,
}

/// A bounded ring of recent audit records.
#[derive(Debug)]
pub struct AuditIndex {
    capacity: usize,
    entries: RwLock<VecDeque<IndexedAudit>>,
}

impl AuditIndex {
    /// Create an index holding at most `capacity` records.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: RwLock::new(VecDeque::new()),
        }
    }

    /// Record a fully-formed event.
    ///
    /// The only way in. An earlier `record` took the appended record's metadata
    /// and *reconstructed* an event from the session — which meant it indexed a
    /// `settings_changed` with timestamp 0, no object and no tenant, whatever
    /// had really happened. The chain stayed correct and the operator's audit
    /// screen went blank, because [`Self::recent_for_tenant`] filters on the
    /// tenant the reconstruction never had.
    pub fn push_event(&self, sequence: u64, event: AuditEvent, link: [u8; 32]) {
        self.push(IndexedAudit {
            sequence,
            event,
            link_short: Digest::from_bytes(link).short(),
        });
    }

    fn push(&self, entry: IndexedAudit) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// The most recent records, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<IndexedAudit> {
        self.entries
            .read()
            .map(|entries| entries.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// The most recent records belonging to `tenant`, newest first.
    ///
    /// Appendix B: "Management visibility never exceeds the caller's tenant and
    /// permissions." Filtering happens *before* the limit is applied, so a
    /// tenant with few records still sees up to `limit` of its own rather than
    /// whatever survives a global truncation.
    ///
    /// Records carrying no tenant are router-wide administrative events. They
    /// are excluded: a session is always scoped to one tenant, and there is no
    /// platform-wide role to grant broader sight. That is deliberately
    /// conservative — it means router-wide events are not visible through this
    /// endpoint at all, and a platform-scope role is the right way to expose
    /// them when one exists.
    pub fn recent_for_tenant(&self, tenant: &str, limit: usize) -> Vec<IndexedAudit> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .rev()
                    .filter(|entry| entry.event.tenant.as_deref() == Some(tenant))
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many records are indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AuditIndex {
    fn default() -> Self {
        Self::new(2048)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_store::{AuditAction, AuditOutcome};

    fn event(n: u64) -> AuditEvent {
        AuditEvent::new(1_767_225_600_000 + n, format!("user:{n}"), AuditAction::Login)
            .with_object(format!("object-{n}"))
            .with_outcome(AuditOutcome::Success)
    }

    #[test]
    fn records_are_returned_newest_first() {
        let index = AuditIndex::new(16);
        for n in 0..5 {
            index.push_event(n, event(n), [n as u8; 32]);
        }
        let recent = index.recent(10);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].sequence, 4);
        assert_eq!(recent[4].sequence, 0);
    }

    #[test]
    fn a_tenant_query_returns_only_that_tenants_records() {
        // Appendix B: management visibility never exceeds the caller's tenant.
        let index = AuditIndex::new(64);
        for n in 0..6 {
            let tenant = if n % 2 == 0 { "acme" } else { "other" };
            index.push_event(n, event(n).with_tenant(tenant), [n as u8; 32]);
        }
        // A router-wide record, carrying no tenant.
        index.push_event(6, event(6), [6u8; 32]);

        let acme = index.recent_for_tenant("acme", 10);
        assert_eq!(acme.len(), 3);
        assert!(acme.iter().all(|r| r.event.tenant.as_deref() == Some("acme")));

        let other = index.recent_for_tenant("other", 10);
        assert_eq!(other.len(), 3);
        assert!(other.iter().all(|r| r.event.tenant.as_deref() == Some("other")));

        // The unscoped query still sees everything; only the tenant-scoped
        // path is narrowed.
        assert_eq!(index.recent(10).len(), 7);
    }

    #[test]
    fn the_tenant_filter_is_applied_before_the_limit() {
        // Filtering after truncation would show a small tenant nothing at all
        // once a noisy neighbour filled the window.
        let index = AuditIndex::new(64);
        for n in 0..20 {
            index.push_event(n, event(n).with_tenant("loud"), [0u8; 32]);
        }
        for n in 20..23 {
            index.push_event(n, event(n).with_tenant("quiet"), [0u8; 32]);
        }
        for n in 23..40 {
            index.push_event(n, event(n).with_tenant("loud"), [0u8; 32]);
        }

        assert_eq!(index.recent_for_tenant("quiet", 5).len(), 3);
    }

    #[test]
    fn an_unknown_tenant_sees_nothing() {
        let index = AuditIndex::new(16);
        index.push_event(0, event(0).with_tenant("acme"), [0u8; 32]);
        assert!(index.recent_for_tenant("nosuch", 10).is_empty());
    }

    #[test]
    fn the_index_is_bounded() {
        let index = AuditIndex::new(4);
        for n in 0..20 {
            index.push_event(n, event(n), [0; 32]);
        }
        assert_eq!(index.len(), 4);
        let recent = index.recent(100);
        assert_eq!(recent[0].sequence, 19);
        assert_eq!(recent[3].sequence, 16);
    }

    #[test]
    fn the_limit_is_respected() {
        let index = AuditIndex::new(16);
        for n in 0..10 {
            index.push_event(n, event(n), [0; 32]);
        }
        assert_eq!(index.recent(3).len(), 3);
        assert_eq!(index.recent(0).len(), 0);
    }

    #[test]
    fn an_empty_index_returns_nothing() {
        let index = AuditIndex::new(16);
        assert!(index.is_empty());
        assert!(index.recent(10).is_empty());
    }

    #[test]
    fn the_chain_link_is_truncated_for_display() {
        let index = AuditIndex::new(4);
        index.push_event(1, event(1), [0xab; 32]);
        let recent = index.recent(1);
        assert_eq!(recent[0].link_short.len(), 12);
        assert!(recent[0].link_short.starts_with("abab"));
    }
}
