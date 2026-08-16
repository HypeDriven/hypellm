//! The bounded decision-trace cache.
//!
//! Specification 15.3 requires a decision explorer showing the "redacted
//! candidate/exclusion/score/failover trace by request id", and 16 exposes it
//! at `GET /admin/v1/decisions/{request_id}`.
//!
//! The cache is **bounded and in memory**. Traces are diagnostic, not
//! accounting: losing the oldest under load is correct, and persisting every
//! trace would be a per-request write on the hot path plus an unbounded store
//! of routing metadata about every request the router ever served.

use hypellm_core::decision::DecisionTrace;
use hypellm_core::ids::{RequestId, TenantId};
use std::collections::VecDeque;
use std::sync::RwLock;

/// A trace plus the tenant it belongs to.
///
/// The tenant is stored alongside so that a read can be authorized without
/// re-deriving it: specification 15.4 requires that "management visibility
/// never exceeds the caller's tenant and permissions".
#[derive(Debug, Clone)]
pub struct StoredTrace {
    /// The tenant whose request this was.
    pub tenant: TenantId,
    /// The trace.
    pub trace: DecisionTrace,
    /// When it was recorded, in wall-clock milliseconds.
    pub recorded_at_millis: u64,
}

/// A bounded ring of recent decision traces.
#[derive(Debug)]
pub struct DecisionCache {
    capacity: usize,
    entries: RwLock<VecDeque<StoredTrace>>,
}

impl DecisionCache {
    /// Create a cache holding at most `capacity` traces.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: RwLock::new(VecDeque::with_capacity(capacity.min(4096))),
        }
    }

    /// Record a trace, evicting the oldest if the cache is full.
    pub fn record(&self, tenant: TenantId, trace: DecisionTrace, recorded_at_millis: u64) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(StoredTrace {
            tenant,
            trace,
            recorded_at_millis,
        });
    }

    /// Look up a trace, but only for a caller in the same tenant.
    ///
    /// A trace for another tenant reads as absent rather than forbidden: the
    /// distinction would confirm that a request with that identifier exists.
    #[must_use]
    pub fn get(&self, request_id: RequestId, tenant: &TenantId) -> Option<StoredTrace> {
        let entries = self.entries.read().ok()?;
        entries
            .iter()
            .find(|entry| entry.trace.request_id == request_id && entry.tenant == *tenant)
            .cloned()
    }

    /// Recent traces for a tenant, newest first.
    #[must_use]
    pub fn recent(&self, tenant: &TenantId, limit: usize) -> Vec<StoredTrace> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .rev()
                    .filter(|entry| entry.tenant == *tenant)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many traces are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_crypto::Digest;

    fn trace(id: u128) -> DecisionTrace {
        DecisionTrace {
            request_id: RequestId::from_u128(id),
            policy_digest: Digest::from_bytes([0xab; 32]),
            candidates: Vec::new(),
            exclusions: Vec::new(),
            chosen: None,
            attempts: Vec::new(),
            routing_micros: 42,
            pinned: false,
        }
    }

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("valid identifier")
    }

    #[test]
    fn a_recorded_trace_is_retrievable_by_its_tenant() {
        let cache = DecisionCache::new(16);
        cache.record(tenant("acme"), trace(1), 1000);

        let found = cache
            .get(RequestId::from_u128(1), &tenant("acme"))
            .expect("present");
        assert_eq!(found.trace.routing_micros, 42);
        assert_eq!(found.recorded_at_millis, 1000);
    }

    #[test]
    fn another_tenants_trace_reads_as_absent() {
        // Specification 15.4: management visibility never exceeds the caller's
        // tenant. Reporting "forbidden" would confirm the request exists.
        let cache = DecisionCache::new(16);
        cache.record(tenant("acme"), trace(1), 0);
        assert!(cache.get(RequestId::from_u128(1), &tenant("other")).is_none());
        assert!(cache.get(RequestId::from_u128(1), &tenant("acme")).is_some());
    }

    #[test]
    fn an_unknown_request_reads_as_absent() {
        let cache = DecisionCache::new(16);
        assert!(cache.get(RequestId::from_u128(99), &tenant("acme")).is_none());
    }

    #[test]
    fn the_cache_is_bounded_and_evicts_oldest_first() {
        let cache = DecisionCache::new(4);
        for id in 0..10u128 {
            cache.record(tenant("acme"), trace(id), id as u64);
        }
        assert_eq!(cache.len(), 4);
        // The oldest are gone.
        assert!(cache.get(RequestId::from_u128(0), &tenant("acme")).is_none());
        assert!(cache.get(RequestId::from_u128(5), &tenant("acme")).is_none());
        // The newest survive.
        assert!(cache.get(RequestId::from_u128(9), &tenant("acme")).is_some());
        assert!(cache.get(RequestId::from_u128(6), &tenant("acme")).is_some());
    }

    #[test]
    fn recent_returns_newest_first_and_filters_by_tenant() {
        let cache = DecisionCache::new(16);
        cache.record(tenant("acme"), trace(1), 1);
        cache.record(tenant("other"), trace(2), 2);
        cache.record(tenant("acme"), trace(3), 3);

        let recent = cache.recent(&tenant("acme"), 10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].trace.request_id, RequestId::from_u128(3));
        assert_eq!(recent[1].trace.request_id, RequestId::from_u128(1));

        assert_eq!(cache.recent(&tenant("acme"), 1).len(), 1);
        assert!(cache.recent(&tenant("nobody"), 10).is_empty());
    }

    #[test]
    fn a_zero_capacity_still_holds_one() {
        let cache = DecisionCache::new(0);
        cache.record(tenant("acme"), trace(1), 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn concurrent_recording_does_not_exceed_the_bound() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(DecisionCache::new(64));
        let mut handles = Vec::new();
        for t in 0..8u128 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..200u128 {
                    cache.record(tenant("acme"), trace(t * 1000 + i), 0);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        assert!(cache.len() <= 64, "cache grew to {}", cache.len());
    }
}
