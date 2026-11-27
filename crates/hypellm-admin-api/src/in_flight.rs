//! Live metadata for keyed requests that are using an upstream slot.

use hypellm_core::canonical::{CanonicalRequest, DEFAULT_BYTES_PER_TOKEN_HUNDREDTHS};
use hypellm_core::ids::{KeyId, PrincipalId, RequestId, TargetId, TenantId};
use hypellm_core::target::Target;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const BUCKETS: usize = 4;
const BUCKET_MILLIS: u32 = 1_000;

/// Tracks active keyed exchanges for the traffic view.
#[derive(Debug, Default)]
pub struct InFlightRequests {
    next: AtomicU64,
    active: RwLock<BTreeMap<u64, Arc<Request>>>,
}

#[derive(Debug)]
struct Request {
    id: RequestId,
    key: KeyId,
    tenant: TenantId,
    principal: PrincipalId,
    target: TargetId,
    model: String,
    bytes_per_token: f64,
    output: Mutex<RecentOutput>,
}

#[derive(Debug, Default)]
struct RecentOutput {
    first_millis: Option<u64>,
    buckets: [(u64, u64); BUCKETS],
}

impl RecentOutput {
    fn observe(&mut self, now: u64, bytes: u64) {
        let second = now.div_euclid(u64::from(BUCKET_MILLIS));
        let index = usize::try_from(second)
            .ok()
            .map(|second| second.rem_euclid(BUCKETS));
        if let Some(bucket) = index.and_then(|index| self.buckets.get_mut(index)) {
            if bucket.0 != second {
                *bucket = (second, 0);
            }
            bucket.1 = bucket.1.saturating_add(bytes);
            self.first_millis.get_or_insert(now);
        }
    }

    fn bytes_per_second(&self, now: u64) -> Option<f64> {
        let first = self.first_millis?;
        let second = now.div_euclid(u64::from(BUCKET_MILLIS));
        let oldest = second.saturating_sub(u64::try_from(BUCKETS - 1).ok()?);
        let span = now.checked_sub(first.max(oldest * u64::from(BUCKET_MILLIS)))?;
        let bytes = self
            .buckets
            .iter()
            .filter(|(bucket, _)| (oldest..=second).contains(bucket))
            .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes));
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        let span = u32::try_from(span).ok()?.max(BUCKET_MILLIS);
        Some(f64::from(bytes) * 1_000.0 / f64::from(span))
    }
}

/// One live request as seen by a reader of the traffic API.
pub(crate) struct RequestSnapshot {
    pub id: RequestId,
    pub key: KeyId,
    pub target: TargetId,
    pub model: String,
    pub output_tokens_per_second: Option<f64>,
}

impl InFlightRequests {
    /// Register an upstream exchange. The internal sequence keeps concurrent
    /// requests distinct even when clients reuse their correlation ID.
    pub fn start(
        &self,
        request: &CanonicalRequest,
        key: &KeyId,
        target: &Target,
    ) -> Option<InFlightRequest<'_>> {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Request {
            id: request.request_id,
            key: key.clone(),
            tenant: request.tenant.clone(),
            principal: request.principal.clone(),
            target: target.id.clone(),
            model: target.native_model.clone(),
            bytes_per_token: f64::from(
                target
                    .bytes_per_token_hundredths
                    .unwrap_or(DEFAULT_BYTES_PER_TOKEN_HUNDREDTHS)
                    .max(1),
            ) / 100.0,
            output: Mutex::default(),
        });
        self.active
            .write()
            .ok()?
            .insert(sequence, Arc::clone(&entry));
        Some(InFlightRequest {
            owner: self,
            sequence,
            entry,
        })
    }

    pub(crate) fn snapshot(
        &self,
        tenant: &TenantId,
        principal: Option<&PrincipalId>,
        now: u64,
    ) -> Vec<RequestSnapshot> {
        let Ok(active) = self.active.read() else {
            return Vec::new();
        };
        active
            .values()
            .filter(|entry| {
                &entry.tenant == tenant
                    && principal.is_none_or(|principal| &entry.principal == principal)
            })
            .map(|entry| RequestSnapshot {
                id: entry.id,
                key: entry.key.clone(),
                target: entry.target.clone(),
                model: entry.model.clone(),
                output_tokens_per_second: entry
                    .output
                    .lock()
                    .ok()
                    .and_then(|output| output.bytes_per_second(now))
                    .map(|bytes| bytes / entry.bytes_per_token),
            })
            .collect()
    }
}

/// Removes its row on every exit from dispatch, including cancellation and retry.
#[derive(Debug)]
pub struct InFlightRequest<'a> {
    owner: &'a InFlightRequests,
    sequence: u64,
    entry: Arc<Request>,
}

impl InFlightRequest<'_> {
    /// Estimate live output tokens from streamed bytes. Most providers report
    /// exact usage only at completion. No content is retained here.
    pub fn observe_output(&self, now: u64, bytes: u64) {
        if bytes > 0
            && let Ok(mut output) = self.entry.output.lock()
        {
            output.observe(now, bytes);
        }
    }
}

impl Drop for InFlightRequest<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.owner.active.write() {
            active.remove(&self.sequence);
        }
    }
}
