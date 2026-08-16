//! Bounded usage aggregation.
//!
//! Specification 15.3 requires a usage screen showing totals "per authorized
//! scope, model/alias, operation, status, cost class; **no prompt bodies by
//! default**", and specification 5 lists "usage aggregates" among the things
//! the state store holds.
//!
//! Three decisions shape this module.
//!
//! **It aggregates, it does not log.** A per-request usage record would be a
//! second unbounded history of every request the router ever served, and it
//! would carry the same re-identification risk as the request log. What is kept
//! is a counter per distinct (tenant, principal, alias, target, operation,
//! status, cost class) tuple: enough to answer "who spent what on which model",
//! nothing that describes an individual exchange.
//!
//! **The series count is bounded.** Principals and aliases are operator-chosen
//! identifiers, but a compromised or careless client can still ask for a
//! thousand distinct aliases. Past [`MAX_SERIES`] distinct tuples, samples fold
//! into a per-tenant overflow row rather than growing the map, so the totals
//! stay correct even when the breakdown stops being complete — the same
//! discipline specification 17 imposes on metric label cardinality.
//!
//! **Provenance is preserved.** Specification 14 requires usage to be marked
//! provider-reported or router-estimated, and a usage screen that silently adds
//! the two would let an estimate be mistaken for a bill. Both are counted, and
//! the estimated share of each row is reported alongside the total.

use hypellm_core::canonical::{CostClass, Operation};
use hypellm_core::event::CanonicalUsage;
use hypellm_core::ids::{AliasId, PrincipalId, TargetId, TenantId};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// The largest number of distinct usage rows held.
///
/// Sized so that a deployment with a few hundred principals and a handful of
/// aliases keeps a complete breakdown, while a pathological caller cannot make
/// the map grow without limit.
pub const MAX_SERIES: usize = 4096;

/// The outcome class of a request, as a closed vocabulary.
///
/// A free-form error string would make this a high-cardinality dimension, which
/// is exactly what specification 17 forbids for metric labels; the same
/// reasoning applies to a stored aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsageStatus {
    /// The request completed and produced output.
    Success,
    /// The request was refused because of the caller or the policy.
    ClientError,
    /// The request was refused because of capacity or a quota.
    Throttled,
    /// The router or a provider failed.
    ServerError,
}

impl UsageStatus {
    /// The stable name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ClientError => "client_error",
            Self::Throttled => "throttled",
            Self::ServerError => "server_error",
        }
    }

    /// Classify an HTTP status into the vocabulary above.
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Success,
            429 => Self::Throttled,
            400..=499 => Self::ClientError,
            _ => Self::ServerError,
        }
    }
}

/// The dimensions a usage row is broken down by.
///
/// Ordered, so `BTreeMap` iteration is stable and two routers replaying the
/// same samples produce byte-identical output (specification 6's determinism
/// requirement applied to reporting).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsageKey {
    /// The tenant the request belonged to.
    pub tenant: TenantId,
    /// The principal that made it, or `None` for an overflow row.
    pub principal: Option<PrincipalId>,
    /// The client-visible alias, or `None` for an overflow row.
    pub alias: Option<AliasId>,
    /// The target that served it, if one was chosen.
    pub target: Option<TargetId>,
    /// The operation.
    pub operation: Operation,
    /// The outcome class.
    pub status: UsageStatus,
    /// The cost class of the target that served it.
    pub cost_class: u8,
}

impl UsageKey {
    /// Whether this row is the folded remainder rather than a real breakdown.
    #[must_use]
    pub const fn is_overflow(&self) -> bool {
        self.principal.is_none()
    }
}

/// The counters held for one [`UsageKey`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageTotals {
    /// How many requests fell into this row.
    pub requests: u64,
    /// Input tokens, from both provenances.
    pub input_tokens: u64,
    /// Output tokens, from both provenances.
    pub output_tokens: u64,
    /// Input tokens served from a provider prompt cache.
    pub cached_input_tokens: u64,
    /// Reasoning tokens, where the provider reports them separately.
    pub reasoning_tokens: u64,
    /// How many of the requests carried router-estimated rather than
    /// provider-reported numbers.
    pub estimated_requests: u64,
}

impl UsageTotals {
    fn add(&mut self, usage: &CanonicalUsage) {
        self.requests = self.requests.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
        self.cached_input_tokens = self
            .cached_input_tokens
            .saturating_add(usage.cached_input_tokens);
        self.reasoning_tokens = self
            .reasoning_tokens
            .saturating_add(usage.reasoning_tokens);
        if !usage.is_reported() {
            self.estimated_requests = self.estimated_requests.saturating_add(1);
        }
    }

    /// Total tokens.
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// One sample: what a completed request contributes.
#[derive(Debug, Clone)]
pub struct UsageSample {
    /// The tenant.
    pub tenant: TenantId,
    /// The principal.
    pub principal: PrincipalId,
    /// The requested alias.
    pub alias: AliasId,
    /// The chosen target, if routing got that far.
    pub target: Option<TargetId>,
    /// The operation.
    pub operation: Operation,
    /// The outcome class.
    pub status: UsageStatus,
    /// The cost class of the chosen target.
    pub cost_class: CostClass,
    /// Token accounting, if any was produced.
    pub usage: CanonicalUsage,
    /// The API key the request authenticated with, when it used one.
    ///
    /// `None` for a management-plane or peer-authenticated principal.
    pub key_id: Option<hypellm_core::ids::KeyId>,
}

/// A usage row, ready to render.
#[derive(Debug, Clone)]
pub struct UsageRow {
    /// The dimensions.
    pub key: UsageKey,
    /// The counters.
    pub totals: UsageTotals,
}

/// The aggregate.
#[derive(Debug)]
pub struct UsageAggregate {
    max_series: usize,
    rows: RwLock<BTreeMap<UsageKey, UsageTotals>>,
    /// Totals per (tenant, key), for specification 22.3 step 20's
    /// "search authorized audit/usage by key pseudonym".
    ///
    /// A **separate** table rather than a `key_id` dimension on `UsageKey`, and
    /// that is the whole design decision. Adding a seventh dimension would
    /// multiply the main table's cardinality by the number of live keys —
    /// against a `MAX_SERIES` cap that already folds — so the answer to "what
    /// did this key do" would have arrived by making every other usage question
    /// less answerable.
    ///
    /// Totals only, no cross-product: this answers "what did this key spend",
    /// which is the question an investigation asks. For "what did it spend on
    /// which alias", the principal dimension on the main table is the tool, and
    /// a key belongs to exactly one principal.
    ///
    /// Bounded by [`MAX_KEY_SERIES`], and separately by reality: a row can only
    /// exist for a key that authenticated a request.
    by_key: RwLock<BTreeMap<(TenantId, hypellm_core::ids::KeyId), UsageTotals>>,
    /// When aggregation started or was last reset, in wall-clock milliseconds.
    since_millis: RwLock<u64>,
}

/// Distinct (tenant, key) rows retained.
///
/// Smaller than [`MAX_SERIES`] because this table has no cross-product: one row
/// per key that has served a request. A deployment with more live keys than
/// this has a key-management problem before it has a metrics problem.
pub const MAX_KEY_SERIES: usize = 4096;

impl UsageAggregate {
    /// An aggregate holding at most `max_series` distinct rows.
    #[must_use]
    pub fn new(max_series: usize) -> Self {
        Self {
            max_series: max_series.max(1),
            rows: RwLock::new(BTreeMap::new()),
            by_key: RwLock::new(BTreeMap::new()),
            since_millis: RwLock::new(0),
        }
    }

    /// Record a completed request.
    ///
    /// Never fails and never blocks on anything but the map: this runs on the
    /// completion path of every request, and a usage counter is not worth
    /// failing a response over.
    pub fn record(&self, sample: &UsageSample, now_millis: u64) {
        // The per-key table first, and under its own lock: it is bounded
        // separately and must not be skipped because the main table is
        // contended or poisoned.
        if let Some(key_id) = &sample.key_id {
            if let Ok(mut by_key) = self.by_key.write() {
                let entry = (sample.tenant.clone(), key_id.clone());
                if let Some(totals) = by_key.get_mut(&entry) {
                    totals.add(&sample.usage);
                } else if by_key.len() < MAX_KEY_SERIES {
                    let mut totals = UsageTotals::default();
                    totals.add(&sample.usage);
                    by_key.insert(entry, totals);
                }
                // Past the bound a new key is not recorded. There is no
                // overflow row here on purpose: a folded row keyed by "some
                // key" answers nothing an investigation asks, and would read as
                // a real key's totals.
            }
        }

        let Ok(mut rows) = self.rows.write() else {
            return;
        };
        if let Ok(mut since) = self.since_millis.write() {
            if *since == 0 {
                *since = now_millis;
            }
        }

        let key = UsageKey {
            tenant: sample.tenant.clone(),
            principal: Some(sample.principal.clone()),
            alias: Some(sample.alias.clone()),
            target: sample.target.clone(),
            operation: sample.operation,
            status: sample.status,
            cost_class: sample.cost_class.0,
        };

        // A row that already exists is always updated, whatever the bound: the
        // cap limits how many *distinct* rows exist, not how much traffic an
        // existing row can account for.
        if let Some(totals) = rows.get_mut(&key) {
            totals.add(&sample.usage);
            return;
        }

        if rows.len() >= self.max_series {
            let overflow = UsageKey {
                tenant: sample.tenant.clone(),
                principal: None,
                alias: None,
                target: None,
                operation: sample.operation,
                status: sample.status,
                cost_class: sample.cost_class.0,
            };
            rows.entry(overflow).or_default().add(&sample.usage);
            return;
        }

        rows.entry(key).or_default().add(&sample.usage);
    }

    /// Rows visible to a caller.
    ///
    /// `principal` restricts the result to one principal's own usage, which is
    /// what [`ReadOwnUsage`] grants; passing `None` returns the whole tenant,
    /// which requires `ReadTenantUsage`. The authorization decision itself is
    /// the caller's — this function only enforces the filter it is given, and
    /// never crosses a tenant boundary regardless.
    ///
    /// [`ReadOwnUsage`]: hypellm_core::rbac::Permission::ReadOwnUsage
    #[must_use]
    pub fn rows(&self, tenant: &TenantId, principal: Option<&PrincipalId>) -> Vec<UsageRow> {
        let Ok(rows) = self.rows.read() else {
            return Vec::new();
        };
        rows.iter()
            .filter(|(key, _)| key.tenant == *tenant)
            .filter(|(key, _)| match principal {
                // An overflow row is not attributed to anyone, so a caller
                // restricted to their own usage does not see it: it would
                // otherwise report another principal's tokens as theirs.
                Some(wanted) => key.principal.as_ref() == Some(wanted),
                None => true,
            })
            .map(|(key, totals)| UsageRow {
                key: key.clone(),
                totals: *totals,
            })
            .collect()
    }

    /// The totals across every visible row.
    /// Totals for one key, or `None` if it has served nothing.
    ///
    /// Tenant-scoped like every other management read: a key identifier from
    /// another tenant reads as absent rather than forbidden, because a 403
    /// would confirm the key exists somewhere.
    #[must_use]
    pub fn for_key(
        &self,
        tenant: &TenantId,
        key: &hypellm_core::ids::KeyId,
    ) -> Option<UsageTotals> {
        self.by_key
            .read()
            .ok()?
            .get(&(tenant.clone(), key.clone()))
            .copied()
    }

    /// Every key that has served a request in this tenant, with its totals.
    #[must_use]
    pub fn keys(&self, tenant: &TenantId) -> Vec<(hypellm_core::ids::KeyId, UsageTotals)> {
        self.by_key
            .read()
            .map(|rows| {
                rows.iter()
                    .filter(|((t, _), _)| t == tenant)
                    .map(|((_, key), totals)| (key.clone(), *totals))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn summary(&self, tenant: &TenantId, principal: Option<&PrincipalId>) -> UsageTotals {
        let mut summary = UsageTotals::default();
        for row in self.rows(tenant, principal) {
            summary.requests = summary.requests.saturating_add(row.totals.requests);
            summary.input_tokens = summary.input_tokens.saturating_add(row.totals.input_tokens);
            summary.output_tokens = summary
                .output_tokens
                .saturating_add(row.totals.output_tokens);
            summary.cached_input_tokens = summary
                .cached_input_tokens
                .saturating_add(row.totals.cached_input_tokens);
            summary.reasoning_tokens = summary
                .reasoning_tokens
                .saturating_add(row.totals.reasoning_tokens);
            summary.estimated_requests = summary
                .estimated_requests
                .saturating_add(row.totals.estimated_requests);
        }
        summary
    }

    /// When aggregation started, in wall-clock milliseconds; zero if nothing
    /// has been recorded.
    #[must_use]
    pub fn since_millis(&self) -> u64 {
        self.since_millis.read().map_or(0, |v| *v)
    }

    /// How many distinct rows are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.read().map_or(0, |rows| rows.len())
    }

    /// Whether anything has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the series bound has been reached, so some rows are folded.
    #[must_use]
    pub fn is_saturated(&self) -> bool {
        self.len() >= self.max_series
    }
}

impl Default for UsageAggregate {
    fn default() -> Self {
        Self::new(MAX_SERIES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("valid identifier")
    }

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid identifier")
    }

    fn alias(name: &str) -> AliasId {
        AliasId::new(name).expect("valid identifier")
    }

    fn sample(who: &str, which: &str, usage: CanonicalUsage) -> UsageSample {
        UsageSample {
            tenant: tenant("acme"),
            principal: principal(who),
            alias: alias(which),
            target: Some(TargetId::new("openai-gpt").expect("valid identifier")),
            operation: Operation::Chat,
            status: UsageStatus::Success,
            cost_class: CostClass::new(3),
            usage,
            key_id: None,
        }
    }

    /// The same sample, attributed to an API key.
    fn keyed(who: &str, which: &str, key: &str, usage: CanonicalUsage) -> UsageSample {
        UsageSample {
            key_id: Some(hypellm_core::ids::KeyId::new(key).expect("valid identifier")),
            ..sample(who, which, usage)
        }
    }

    #[test]
    fn usage_is_attributable_to_the_key_that_produced_it() {
        // Specification 22.3 step 20: "Search authorized audit/usage by key
        // pseudonym". `UsageKey` carries a *principal*, and one principal can
        // hold several keys — so a compromised-key investigation could not ask
        // what that key had spent.
        let aggregate = UsageAggregate::default();
        let acme = tenant("acme");
        let one = hypellm_core::ids::KeyId::new("key_one").expect("id");
        let two = hypellm_core::ids::KeyId::new("key_two").expect("id");

        aggregate.record(&keyed("svc:a", "code", "key_one", CanonicalUsage::reported(10, 5)), 1);
        aggregate.record(&keyed("svc:a", "chat", "key_one", CanonicalUsage::reported(1, 1)), 2);
        aggregate.record(&keyed("svc:a", "code", "key_two", CanonicalUsage::reported(7, 3)), 3);

        // Totals per key, across every alias that key used.
        let first = aggregate.for_key(&acme, &one).expect("key one served requests");
        assert_eq!(first.requests, 2);
        assert_eq!(first.input_tokens, 11);
        let second = aggregate.for_key(&acme, &two).expect("key two served requests");
        assert_eq!(second.requests, 1);
        assert_eq!(second.input_tokens, 7);

        // Tenant-scoped: another tenant's read finds nothing rather than being
        // told the key exists somewhere.
        assert!(aggregate.for_key(&tenant("globex"), &one).is_none());

        // And a key that served nothing has no row, rather than a zeroed one
        // that would read as "used and produced nothing".
        let unused = hypellm_core::ids::KeyId::new("key_unused").expect("id");
        assert!(aggregate.for_key(&acme, &unused).is_none());

        let listed = aggregate.keys(&acme);
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn unkeyed_usage_does_not_create_a_key_row() {
        // A management-plane or peer-authenticated principal has no key, and
        // inventing a row for it would attribute traffic to a key that does not
        // exist.
        let aggregate = UsageAggregate::default();
        aggregate.record(&sample("user:admin", "code", CanonicalUsage::reported(1, 1)), 1);
        assert!(aggregate.keys(&tenant("acme")).is_empty());
    }

    #[test]
    fn the_key_table_is_bounded_and_does_not_fold() {
        // Bounded like every other buffer (specification 3.2). No overflow row
        // on purpose: a folded row keyed by "some key" answers nothing an
        // investigation asks, and would read as a real key's totals.
        let aggregate = UsageAggregate::default();
        let acme = tenant("acme");
        for n in 0..(super::MAX_KEY_SERIES + 50) {
            aggregate.record(
                &keyed("svc:a", "code", &format!("key_{n}"), CanonicalUsage::reported(1, 1)),
                1,
            );
        }
        assert_eq!(aggregate.keys(&acme).len(), super::MAX_KEY_SERIES);
    }

    #[test]
    fn identical_dimensions_accumulate_into_one_row() {
        let aggregate = UsageAggregate::default();
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(10, 5)), 1);
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(20, 7)), 2);

        let rows = aggregate.rows(&tenant("acme"), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].totals.requests, 2);
        assert_eq!(rows[0].totals.input_tokens, 30);
        assert_eq!(rows[0].totals.output_tokens, 12);
        assert_eq!(rows[0].totals.total_tokens(), 42);
    }

    #[test]
    fn differing_dimensions_stay_separate() {
        let aggregate = UsageAggregate::default();
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(1, 1)), 0);
        aggregate.record(&sample("bob", "code", CanonicalUsage::reported(1, 1)), 0);
        aggregate.record(&sample("alice", "chat", CanonicalUsage::reported(1, 1)), 0);
        assert_eq!(aggregate.rows(&tenant("acme"), None).len(), 3);
    }

    #[test]
    fn estimated_and_reported_usage_are_counted_separately() {
        // Specification 14: usage must be marked provider-reported or
        // router-estimated. A screen that added them without saying so would
        // let an estimate be read as a bill.
        let aggregate = UsageAggregate::default();
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(10, 0)), 0);
        aggregate.record(&sample("alice", "code", CanonicalUsage::estimated(90, 0)), 0);

        let rows = aggregate.rows(&tenant("acme"), None);
        assert_eq!(rows[0].totals.requests, 2);
        assert_eq!(rows[0].totals.estimated_requests, 1);
        assert_eq!(rows[0].totals.input_tokens, 100);
    }

    #[test]
    fn cached_and_reasoning_tokens_are_kept() {
        let aggregate = UsageAggregate::default();
        let usage = CanonicalUsage {
            input_tokens: 100,
            output_tokens: 20,
            cached_input_tokens: 80,
            reasoning_tokens: 15,
            source: hypellm_core::event::UsageSource::ProviderReported,
        };
        aggregate.record(&sample("alice", "code", usage), 0);
        let rows = aggregate.rows(&tenant("acme"), None);
        assert_eq!(rows[0].totals.cached_input_tokens, 80);
        assert_eq!(rows[0].totals.reasoning_tokens, 15);
    }

    #[test]
    fn another_tenants_usage_is_never_visible() {
        let aggregate = UsageAggregate::default();
        let mut other = sample("alice", "code", CanonicalUsage::reported(1, 1));
        other.tenant = tenant("other");
        aggregate.record(&other, 0);
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(2, 2)), 0);

        let rows = aggregate.rows(&tenant("acme"), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].totals.input_tokens, 2);
    }

    #[test]
    fn own_usage_sees_only_its_own_principal() {
        let aggregate = UsageAggregate::default();
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(1, 0)), 0);
        aggregate.record(&sample("bob", "code", CanonicalUsage::reported(9, 0)), 0);

        let rows = aggregate.rows(&tenant("acme"), Some(&principal("alice")));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].totals.input_tokens, 1);

        let summary = aggregate.summary(&tenant("acme"), Some(&principal("alice")));
        assert_eq!(summary.input_tokens, 1);
        assert_eq!(aggregate.summary(&tenant("acme"), None).input_tokens, 10);
    }

    #[test]
    fn the_series_count_is_bounded_and_overflow_keeps_the_totals() {
        let aggregate = UsageAggregate::new(8);
        for i in 0..200u32 {
            let who = format!("user{i}");
            aggregate.record(&sample(&who, "code", CanonicalUsage::reported(1, 1)), 0);
        }

        // The map never grew past the bound plus the overflow rows it folds
        // into, and those share one key per (operation, status, cost class).
        assert!(aggregate.len() <= 9, "grew to {}", aggregate.len());
        assert!(aggregate.is_saturated());

        // Every request is still accounted for.
        let summary = aggregate.summary(&tenant("acme"), None);
        assert_eq!(summary.requests, 200);
        assert_eq!(summary.input_tokens, 200);

        let overflow: Vec<UsageRow> = aggregate
            .rows(&tenant("acme"), None)
            .into_iter()
            .filter(|row| row.key.is_overflow())
            .collect();
        assert_eq!(overflow.len(), 1);
        assert_eq!(overflow[0].totals.requests, 200 - 8);
    }

    #[test]
    fn an_overflow_row_is_not_attributed_to_a_principal() {
        // Otherwise "your own usage" would include other people's tokens.
        let aggregate = UsageAggregate::new(2);
        for i in 0..10u32 {
            let who = format!("user{i}");
            aggregate.record(&sample(&who, "code", CanonicalUsage::reported(1, 1)), 0);
        }
        let own = aggregate.rows(&tenant("acme"), Some(&principal("user9")));
        assert!(own.is_empty(), "a folded sample must not surface as own usage");
        assert_eq!(aggregate.rows(&tenant("acme"), None).len(), 3);
    }

    #[test]
    fn an_existing_row_still_accumulates_after_saturation() {
        let aggregate = UsageAggregate::new(2);
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(1, 0)), 0);
        aggregate.record(&sample("bob", "code", CanonicalUsage::reported(1, 0)), 0);
        assert!(aggregate.is_saturated());

        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(5, 0)), 0);
        let alice = aggregate.rows(&tenant("acme"), Some(&principal("alice")));
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].totals.input_tokens, 6, "an existing row keeps counting");
    }

    #[test]
    fn status_classification_follows_the_http_status() {
        assert_eq!(UsageStatus::from_status(200), UsageStatus::Success);
        assert_eq!(UsageStatus::from_status(204), UsageStatus::Success);
        assert_eq!(UsageStatus::from_status(400), UsageStatus::ClientError);
        assert_eq!(UsageStatus::from_status(403), UsageStatus::ClientError);
        assert_eq!(UsageStatus::from_status(429), UsageStatus::Throttled);
        assert_eq!(UsageStatus::from_status(500), UsageStatus::ServerError);
        assert_eq!(UsageStatus::from_status(503), UsageStatus::ServerError);
    }

    #[test]
    fn the_window_start_is_the_first_sample() {
        let aggregate = UsageAggregate::default();
        assert_eq!(aggregate.since_millis(), 0);
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(1, 0)), 5_000);
        aggregate.record(&sample("alice", "code", CanonicalUsage::reported(1, 0)), 9_000);
        assert_eq!(aggregate.since_millis(), 5_000);
    }

    #[test]
    fn rows_are_ordered_deterministically() {
        let first = UsageAggregate::default();
        let second = UsageAggregate::default();
        let names = ["carol", "alice", "bob"];
        for name in names {
            first.record(&sample(name, "code", CanonicalUsage::reported(1, 0)), 0);
        }
        for name in names.iter().rev() {
            second.record(&sample(name, "code", CanonicalUsage::reported(1, 0)), 0);
        }

        let left: Vec<_> = first
            .rows(&tenant("acme"), None)
            .into_iter()
            .map(|row| row.key)
            .collect();
        let right: Vec<_> = second
            .rows(&tenant("acme"), None)
            .into_iter()
            .map(|row| row.key)
            .collect();
        assert_eq!(left, right, "insertion order must not affect output order");
    }

    #[test]
    fn concurrent_recording_keeps_the_totals_exact() {
        use std::sync::Arc;
        use std::thread;

        let aggregate = Arc::new(UsageAggregate::default());
        let mut handles = Vec::new();
        for t in 0..8u32 {
            let aggregate = Arc::clone(&aggregate);
            handles.push(thread::spawn(move || {
                let who = format!("user{t}");
                for _ in 0..250 {
                    aggregate.record(&sample(&who, "code", CanonicalUsage::reported(2, 3)), 0);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }

        let summary = aggregate.summary(&tenant("acme"), None);
        assert_eq!(summary.requests, 2_000);
        assert_eq!(summary.input_tokens, 4_000);
        assert_eq!(summary.output_tokens, 6_000);
    }
}
