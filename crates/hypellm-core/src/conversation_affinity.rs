//! Bounded, tenant-scoped conversation-to-target affinity observations.
//!
//! The router owns this state; clients must not be allowed to select an
//! upstream target by inventing an affinity record. The table never stores
//! prompt content, token sequences or credentials. It is a soft routing
//! preference only: eligibility, residency, rank and capacity still win.
//!
//! A successful upstream completion can refresh an observation. Callers must
//! invalidate an observation after a model restart or cache eviction if known.
//! Time is supplied by the caller to keep this component deterministic.
use std::collections::BTreeMap;

use crate::ids::{AliasId, PrincipalId, TargetId, TenantId};

/// An opaque, validated conversation identifier from the caller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConversationKey {
    pub tenant: TenantId,
    pub principal: PrincipalId,
    pub alias: AliasId,
    pub conversation_id: String,
}

impl ConversationKey {
    /// Empty or oversized IDs are rejected to bound retained metadata.
    pub fn new(
        tenant: TenantId,
        principal: PrincipalId,
        alias: AliasId,
        conversation_id: &str,
    ) -> Option<Self> {
        if conversation_id.is_empty()
            || conversation_id.len() > 128
            || !conversation_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
        {
            return None;
        }
        Some(Self {
            tenant,
            principal,
            alias,
            conversation_id: conversation_id.to_owned(),
        })
    }
}

#[derive(Debug, Clone)]
struct Observation {
    target: TargetId,
    expires_at_ms: u64,
}

/// In-memory bounded affinity state; not a distributed cache-residency oracle.
#[derive(Debug)]
pub struct ConversationAffinity {
    entries: BTreeMap<ConversationKey, Observation>,
    ttl_ms: u64,
    max_entries: usize,
}

impl ConversationAffinity {
    #[must_use]
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            ttl_ms,
            max_entries,
        }
    }

    /// Return a target only while the observation remains fresh.
    #[must_use]
    pub fn preferred(&self, key: &ConversationKey, now_ms: u64) -> Option<&TargetId> {
        self.entries.get(key).and_then(|entry| {
            (now_ms < entry.expires_at_ms).then_some(&entry.target)
        })
    }

    /// Record a successfully served request; failed attempts do not warm caches.
    pub fn observe(&mut self, key: ConversationKey, target: TargetId, now_ms: u64) {
        if self.ttl_ms == 0 || self.max_entries == 0 {
            return;
        }
        self.entries.retain(|_, v| now_ms < v.expires_at_ms);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            // Evict the soonest-expiring record, breaking ties by key.
            if let Some(oldest) = self.entries.iter()
                .min_by_key(|(k, v)| (v.expires_at_ms, *k))
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, Observation {
            target,
            expires_at_ms: now_ms.saturating_add(self.ttl_ms),
        });
    }

    /// Drop all observations for a target after a restart or known KV eviction.
    pub fn invalidate_target(&mut self, target: &TargetId) {
        self.entries.retain(|_, entry| &entry.target != target);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(principal: &str) -> ConversationKey {
        ConversationKey::new(
            TenantId::new("acme").unwrap(),
            PrincipalId::new(principal).unwrap(),
            AliasId::new("chat").unwrap(),
            "conversation-1",
        ).unwrap()
    }

    #[test]
    fn expires_and_refreshes() {
        let mut affinity = ConversationAffinity::new(100, 10);
        let target = TargetId::new("spark-a:qwen").unwrap();
        affinity.observe(key("user:1"), target.clone(), 10);
        assert_eq!(affinity.preferred(&key("user:1"), 109), Some(&target));
        assert_eq!(affinity.preferred(&key("user:1"), 110), None);
        affinity.observe(key("user:1"), target.clone(), 110);
        assert_eq!(affinity.preferred(&key("user:1"), 150), Some(&target));
        affinity.invalidate_target(&target);
        assert!(affinity.preferred(&key("user:1"), 150).is_none());
    }

    #[test]
    fn isolates_principals_and_bounds_memory() {
        let mut affinity = ConversationAffinity::new(100, 1);
        let target = TargetId::new("spark-a:qwen").unwrap();
        affinity.observe(key("user:1"), target.clone(), 0);
        assert!(affinity.preferred(&key("user:2"), 1).is_none());
        affinity.observe(key("user:2"), target, 1);
        assert_eq!(affinity.len(), 1);
        assert!(affinity.preferred(&key("user:1"), 2).is_none());
    }

    #[test]
    fn rejects_unbounded_or_unsafe_identifiers() {
        assert!(ConversationKey::new(
            TenantId::new("acme").unwrap(),
            PrincipalId::new("user:1").unwrap(),
            AliasId::new("chat").unwrap(),
            &"x".repeat(129),
        ).is_none());
    }
}
