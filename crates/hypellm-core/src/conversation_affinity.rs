//! Bounded, tenant-scoped conversation-to-target affinity observations.
//!
//! A conversation whose earlier turns were served by one target is likely to
//! find its prompt prefix still in that target's KV cache, so routing the next
//! turn there saves a prefill. This table remembers which target last served a
//! conversation, and nothing else: no prompt content, token sequences or
//! credentials.
//!
//! It is a soft preference only. The router feeds it into the score through
//! [`crate::policy::LiveState::affinity_bonus`], which policy clamps to
//! [`crate::decision::ScoreTerms::CONVERSATION_SLICE`] and reads only after
//! every eligibility filter has passed. It cannot create eligibility, outrank a
//! binding, or promote a colder target over a warmer one. The client supplies
//! only an opaque identifier; the target is always one the router observed
//! serving that tenant's principal successfully.
//!
//! Every operation is `O(log n)` except [`ConversationAffinity::invalidate_target`],
//! which is `O(n)` and runs only on a target restart or outage. Time and limits
//! are supplied by the caller, so the component stays deterministic and a
//! configuration reload applies on the next observation.

use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{AliasId, PrincipalId, TargetId, TenantId};

/// The longest conversation identifier accepted, in bytes.
pub const MAX_CONVERSATION_ID_BYTES: usize = 128;

/// Whether `id` is an acceptable conversation identifier.
///
/// One to [`MAX_CONVERSATION_ID_BYTES`] bytes of ASCII alphanumerics and
/// `-_:.`. The protocol layer and the table share this one definition.
#[must_use]
pub fn valid_conversation_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CONVERSATION_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

/// A conversation, scoped to the tenant, principal and alias that own it.
///
/// Two principals choosing the same identifier never share an entry, so one
/// caller cannot steer another's routing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConversationKey {
    tenant: TenantId,
    principal: PrincipalId,
    alias: AliasId,
    conversation_id: String,
}

impl ConversationKey {
    /// Build a key; `None` when the identifier fails [`valid_conversation_id`].
    #[must_use]
    pub fn new(
        tenant: TenantId,
        principal: PrincipalId,
        alias: AliasId,
        conversation_id: &str,
    ) -> Option<Self> {
        valid_conversation_id(conversation_id).then(|| Self {
            tenant,
            principal,
            alias,
            conversation_id: conversation_id.to_owned(),
        })
    }
}

/// The table's limits, read from configuration at each observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinityLimits {
    /// How long an observation stays usable. Zero disables affinity.
    pub ttl_ms: u64,
    /// The most conversations held at once. Zero disables affinity.
    pub max_entries: usize,
}

impl AffinityLimits {
    /// Whether these limits switch affinity off.
    #[must_use]
    pub const fn disabled(self) -> bool {
        self.ttl_ms == 0 || self.max_entries == 0
    }
}

/// Where a conversation was last served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The target that served it.
    pub target: TargetId,
    /// The target's activation epoch at the time, so a restart since — which
    /// emptied its cache — can be recognised.
    pub epoch: u64,
    expires_at_ms: u64,
    seq: u64,
}

/// In-memory bounded affinity state; not a distributed cache-residency oracle.
#[derive(Debug, Default)]
pub struct ConversationAffinity {
    entries: BTreeMap<ConversationKey, Observation>,
    /// `(expires_at_ms, seq)` → key: soonest-expiring first, for purge and
    /// eviction without a scan. `seq` makes every index key unique.
    by_expiry: BTreeMap<(u64, u64), ConversationKey>,
    next_seq: u64,
}

impl ConversationAffinity {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The observation for `key`, while it is still fresh.
    #[must_use]
    pub fn preferred(&self, key: &ConversationKey, now_ms: u64) -> Option<&Observation> {
        self.entries
            .get(key)
            .filter(|entry| now_ms < entry.expires_at_ms)
    }

    /// Record a successfully served request; failed attempts do not warm caches.
    pub fn observe(
        &mut self,
        key: ConversationKey,
        target: TargetId,
        epoch: u64,
        now_ms: u64,
        limits: AffinityLimits,
    ) {
        self.purge_expired(now_ms);
        if limits.disabled() {
            self.entries.clear();
            self.by_expiry.clear();
            return;
        }
        self.forget(&key);
        // A reload may have lowered the cap, so evict until there is room.
        while self.entries.len() >= limits.max_entries {
            let Some((_, oldest)) = self.by_expiry.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let expires_at_ms = now_ms.saturating_add(limits.ttl_ms);
        self.by_expiry.insert((expires_at_ms, seq), key.clone());
        self.entries.insert(
            key,
            Observation {
                target,
                epoch,
                expires_at_ms,
                seq,
            },
        );
    }

    /// Drop one conversation's observation.
    pub fn forget(&mut self, key: &ConversationKey) {
        if let Some(old) = self.entries.remove(key) {
            self.by_expiry.remove(&(old.expires_at_ms, old.seq));
        }
    }

    /// Drop every observation of a target after a restart or outage.
    pub fn invalidate_target(&mut self, target: &TargetId) {
        let stale: BTreeSet<(u64, u64)> = self
            .entries
            .values()
            .filter(|entry| &entry.target == target)
            .map(|entry| (entry.expires_at_ms, entry.seq))
            .collect();
        self.entries.retain(|_, entry| &entry.target != target);
        self.by_expiry.retain(|index, _| !stale.contains(index));
    }

    fn purge_expired(&mut self, now_ms: u64) {
        while let Some(entry) = self.by_expiry.first_entry() {
            if entry.key().0 > now_ms {
                break;
            }
            let key = entry.remove();
            self.entries.remove(&key);
        }
    }

    /// How many conversations are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: AffinityLimits = AffinityLimits {
        ttl_ms: 100,
        max_entries: 10,
    };

    fn key(principal: &str, id: &str) -> ConversationKey {
        ConversationKey::new(
            TenantId::new("acme").unwrap(),
            PrincipalId::new(principal).unwrap(),
            AliasId::new("chat").unwrap(),
            id,
        )
        .unwrap()
    }

    fn target(id: &str) -> TargetId {
        TargetId::new(id).unwrap()
    }

    /// The two indexes describe the same set; a leak in either would grow
    /// memory past the cap or evict a live entry.
    fn consistent(table: &ConversationAffinity) {
        assert_eq!(table.entries.len(), table.by_expiry.len());
        for (index, key) in &table.by_expiry {
            let entry = table.entries.get(key).unwrap();
            assert_eq!((entry.expires_at_ms, entry.seq), *index);
        }
    }

    #[test]
    fn an_observation_expires_and_a_new_success_refreshes_it() {
        let mut table = ConversationAffinity::new();
        let a = target("spark-a:qwen");
        table.observe(key("user:1", "c"), a.clone(), 0, 10, LIMITS);
        assert_eq!(table.preferred(&key("user:1", "c"), 109).unwrap().target, a);
        assert!(table.preferred(&key("user:1", "c"), 110).is_none());
        table.observe(key("user:1", "c"), a.clone(), 0, 110, LIMITS);
        assert_eq!(table.preferred(&key("user:1", "c"), 150).unwrap().target, a);
        assert_eq!(table.len(), 1);
        consistent(&table);
    }

    #[test]
    fn one_principal_cannot_read_or_steer_another_principals_conversation() {
        let mut table = ConversationAffinity::new();
        table.observe(key("user:1", "c"), target("a:m"), 0, 0, LIMITS);
        assert!(table.preferred(&key("user:2", "c"), 1).is_none());
    }

    #[test]
    fn a_full_table_evicts_the_soonest_expiring_entry_and_never_exceeds_its_cap() {
        let mut table = ConversationAffinity::new();
        let limits = AffinityLimits {
            ttl_ms: 1_000,
            max_entries: 3,
        };
        for (i, id) in ["c0", "c1", "c2", "c3", "c4"].iter().enumerate() {
            table.observe(
                key("u", id),
                target("a:m"),
                0,
                u64::try_from(i).unwrap(),
                limits,
            );
            assert!(table.len() <= 3);
            consistent(&table);
        }
        assert!(table.preferred(&key("u", "c0"), 5).is_none());
        assert!(table.preferred(&key("u", "c1"), 5).is_none());
        assert!(table.preferred(&key("u", "c4"), 5).is_some());
    }

    #[test]
    fn refreshing_a_conversation_moves_it_to_the_back_of_the_eviction_order() {
        let mut table = ConversationAffinity::new();
        let limits = AffinityLimits {
            ttl_ms: 1_000,
            max_entries: 2,
        };
        table.observe(key("u", "old"), target("a:m"), 0, 0, limits);
        table.observe(key("u", "new"), target("a:m"), 0, 1, limits);
        table.observe(key("u", "old"), target("a:m"), 0, 2, limits);
        table.observe(key("u", "third"), target("a:m"), 0, 3, limits);
        assert!(table.preferred(&key("u", "old"), 4).is_some());
        assert!(table.preferred(&key("u", "new"), 4).is_none());
        consistent(&table);
    }

    #[test]
    fn a_lowered_cap_takes_effect_on_the_next_observation() {
        let mut table = ConversationAffinity::new();
        for id in ["a", "b", "c", "d"] {
            table.observe(key("u", id), target("a:m"), 0, 0, LIMITS);
        }
        table.observe(
            key("u", "e"),
            target("a:m"),
            0,
            1,
            AffinityLimits {
                ttl_ms: 100,
                max_entries: 2,
            },
        );
        assert_eq!(table.len(), 2);
        consistent(&table);
    }

    #[test]
    fn disabling_affinity_empties_the_table() {
        let mut table = ConversationAffinity::new();
        table.observe(key("u", "a"), target("a:m"), 0, 0, LIMITS);
        table.observe(
            key("u", "b"),
            target("a:m"),
            0,
            1,
            AffinityLimits {
                ttl_ms: 0,
                max_entries: 10,
            },
        );
        assert!(table.is_empty());
        consistent(&table);
    }

    #[test]
    fn invalidating_a_target_drops_only_its_conversations() {
        let mut table = ConversationAffinity::new();
        table.observe(key("u", "on-a"), target("a:m"), 0, 0, LIMITS);
        table.observe(key("u", "on-b"), target("b:m"), 0, 0, LIMITS);
        table.invalidate_target(&target("a:m"));
        assert!(table.preferred(&key("u", "on-a"), 1).is_none());
        assert!(table.preferred(&key("u", "on-b"), 1).is_some());
        consistent(&table);
    }

    #[test]
    fn expired_entries_are_purged_rather_than_held_until_eviction() {
        let mut table = ConversationAffinity::new();
        for id in ["a", "b", "c"] {
            table.observe(key("u", id), target("a:m"), 0, 0, LIMITS);
        }
        table.observe(key("u", "d"), target("a:m"), 0, 100, LIMITS);
        assert_eq!(table.len(), 1);
        consistent(&table);
    }

    #[test]
    fn identifiers_are_bounded_and_restricted_to_a_safe_alphabet() {
        assert!(valid_conversation_id("conv-1_a:b.c"));
        assert!(valid_conversation_id(&"x".repeat(128)));
        assert!(!valid_conversation_id(&"x".repeat(129)));
        assert!(!valid_conversation_id(""));
        assert!(!valid_conversation_id("has space"));
        assert!(!valid_conversation_id("slash/"));
        assert!(!valid_conversation_id("é"));
    }
}
