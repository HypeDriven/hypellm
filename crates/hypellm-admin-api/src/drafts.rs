//! Policy drafts and the approval separation.
//!
//! Specification 15.3: the routing-policy screen offers "draft diff,
//! validation, simulation, approval, rollback". Specification 15.4: "Publishing
//! requires validation and, where configured, a distinct approver."
//! Specification 9.3: a policy editor "cannot publish own draft by default".
//!
//! The separation is enforced here rather than in the handler, because it is a
//! property of the draft — who wrote it — not of the request.

use hypellm_config::{ConfigError, ValidatedConfig};
use hypellm_core::ids::{PrincipalId, TenantId};
use hypellm_crypto::Digest;
use std::collections::BTreeMap;
use wire_json::{Object, Value};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// A policy draft.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The draft identifier.
    pub id: String,
    /// The configuration text.
    pub text: String,
    /// Who wrote it.
    pub author: PrincipalId,
    /// The tenant the author's session was scoped to.
    ///
    /// A draft is a whole-router configuration change, so it has no tenant of
    /// its own in any deep sense. It records the tenant it was *proposed* in
    /// because Appendix B keeps management visibility inside the caller's
    /// tenant: without this, one tenant's approver could publish a change
    /// another tenant drafted and nobody in the publishing tenant reviewed.
    pub tenant: TenantId,
    /// When it was created, in wall-clock milliseconds.
    pub created_at_millis: u64,
    /// The digest of the canonical form, once validated.
    pub digest: Option<Digest>,
    /// Validation errors, empty once it validates.
    pub errors: Vec<ConfigError>,
    /// Whether the draft has been validated at all.
    pub validated: bool,
}

impl Draft {
    /// Encode for the durable log.
    ///
    /// Specification 15.3 and 15.4 describe drafting, validation, simulation,
    /// approval, and publication as a *workflow*. A workflow that loses its
    /// state on restart is not one: a draft awaiting a second approver
    /// disappeared, and during an incident that means re-authoring under
    /// pressure — exactly when nobody should be retyping a configuration.
    ///
    /// Only the authored facts are recorded: identifier, text, author, tenant,
    /// and creation time. The validation result is *not*, because it is a
    /// function of the text and the configuration grammar the running binary
    /// implements. Replaying a stored "valid" verdict across an upgrade would
    /// let a draft that no longer builds be published as though it had been
    /// checked. A restored draft is unvalidated and must be validated again,
    /// which costs one call and cannot be wrong.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut object = Object::new();
        object.push("id", Value::from(self.id.as_str()));
        object.push("text", Value::from(self.text.as_str()));
        object.push("author", Value::from(self.author.as_str()));
        object.push("tenant", Value::from(self.tenant.as_str()));
        object.push("created_at", Value::from(self.created_at_millis));
        wire_json::to_string(&Value::Object(object)).into_bytes()
    }

    /// Decode a record written by [`Draft::to_payload`].
    ///
    /// Returns `None` for anything that does not decode, so a record from a
    /// newer writer — or a damaged one — is skipped rather than panicking a
    /// startup path.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let value = wire_json::parse(payload, &wire_json::Limits::DEFAULT).ok()?;
        Some(Self {
            id: value.field_str("id").ok()?.to_owned(),
            text: value.field_str("text").ok()?.to_owned(),
            author: PrincipalId::new(value.field_str("author").ok()?).ok()?,
            tenant: TenantId::new(value.field_str("tenant").ok()?).ok()?,
            created_at_millis: value
                .opt_field_i64("created_at")
                .ok()
                .flatten()
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0),
            // Deliberately not restored: see `to_payload`.
            digest: None,
            errors: Vec::new(),
            validated: false,
        })
    }

    /// Whether the draft is publishable.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validated && self.errors.is_empty()
    }
}

/// Why a publish was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishRefusal {
    /// The draft does not exist.
    NoSuchDraft,
    /// The draft has not been validated.
    NotValidated,
    /// The draft failed validation.
    Invalid,
    /// The publisher wrote the draft and self-approval is not permitted.
    SelfApproval,
}

impl PublishRefusal {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoSuchDraft => "no_such_draft",
            Self::NotValidated => "draft_not_validated",
            Self::Invalid => "draft_invalid",
            Self::SelfApproval => "self_approval_not_permitted",
        }
    }

    /// A message for an operator.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NoSuchDraft => "no such draft",
            Self::NotValidated => "the draft must be validated before it can be published",
            Self::Invalid => "the draft did not validate",
            Self::SelfApproval => {
                "a draft must be published by someone other than its author; \
                 ask an approver to review it"
            }
        }
    }
}

/// Draft storage and the approval rule.
#[derive(Debug)]
pub struct DraftStore {
    drafts: RwLock<BTreeMap<String, Draft>>,
    next_id: AtomicU64,
    /// Whether an author may publish their own draft.
    ///
    /// Specification 9.3 makes this false by default; a single-operator
    /// deployment can enable it deliberately.
    allow_self_approval: bool,
    /// Maximum drafts retained.
    capacity: usize,
}

impl DraftStore {
    /// Create a store with the default separation of duties.
    #[must_use]
    pub fn new() -> Self {
        Self {
            drafts: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            allow_self_approval: false,
            capacity: 256,
        }
    }

    /// Create a store permitting self-approval.
    #[must_use]
    pub fn with_self_approval() -> Self {
        Self {
            allow_self_approval: true,
            ..Self::new()
        }
    }

    /// Whether self-approval is permitted.
    #[must_use]
    pub const fn allows_self_approval(&self) -> bool {
        self.allow_self_approval
    }

    /// Create a draft.
    pub fn create(
        &self,
        text: String,
        author: PrincipalId,
        tenant: TenantId,
        now_millis: u64,
    ) -> Draft {
        let id = format!("draft_{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let draft = Draft {
            id: id.clone(),
            text,
            author,
            tenant,
            created_at_millis: now_millis,
            digest: None,
            errors: Vec::new(),
            validated: false,
        };
        if let Ok(mut drafts) = self.drafts.write() {
            if drafts.len() >= self.capacity {
                // Evict the oldest by creation time.
                if let Some(oldest) = drafts
                    .values()
                    .min_by_key(|d| d.created_at_millis)
                    .map(|d| d.id.clone())
                {
                    drafts.remove(&oldest);
                }
            }
            drafts.insert(id, draft.clone());
        }
        draft
    }

    /// Insert a draft restored from the durable log.
    ///
    /// Bypasses identifier allocation — the identifier is part of the record —
    /// and advances the allocator past it, so a draft created after a restart
    /// cannot collide with one restored from before it.
    pub fn restore(&self, draft: Draft) {
        if let Some(number) = draft
            .id
            .strip_prefix("draft_")
            .and_then(|n| n.parse::<u64>().ok())
        {
            // `fetch_max` rather than a store: several records replay in
            // sequence and the allocator must end above all of them.
            self.next_id.fetch_max(number.saturating_add(1), Ordering::SeqCst);
        }
        if let Ok(mut drafts) = self.drafts.write() {
            if drafts.len() >= self.capacity {
                if let Some(oldest) = drafts
                    .values()
                    .min_by_key(|d| d.created_at_millis)
                    .map(|d| d.id.clone())
                {
                    drafts.remove(&oldest);
                }
            }
            drafts.insert(draft.id.clone(), draft);
        }
    }

    /// Remove a draft that was published or discarded.
    pub fn close(&self, id: &str) {
        if let Ok(mut drafts) = self.drafts.write() {
            drafts.remove(id);
        }
    }

    /// Fetch a draft proposed in `tenant`.
    ///
    /// A draft belonging to another tenant reads as absent rather than
    /// forbidden: a 403 would confirm that the identifier names a real draft
    /// somewhere, which is itself the disclosure.
    #[must_use]
    pub fn get(&self, id: &str, tenant: &TenantId) -> Option<Draft> {
        self.get_unscoped(id).filter(|draft| draft.tenant == *tenant)
    }

    fn get_unscoped(&self, id: &str) -> Option<Draft> {
        self.drafts.read().ok()?.get(id).cloned()
    }

    /// Every draft proposed in `tenant`, oldest first.
    #[must_use]
    pub fn list(&self, tenant: &TenantId) -> Vec<Draft> {
        self.drafts
            .read()
            .map(|drafts| {
                let mut all: Vec<Draft> = drafts
                    .values()
                    .filter(|draft| draft.tenant == *tenant)
                    .cloned()
                    .collect();
                all.sort_by_key(|d| d.created_at_millis);
                all
            })
            .unwrap_or_default()
    }

    /// Validate a draft, recording the outcome.
    pub fn validate(&self, id: &str, tenant: &TenantId, version: u64) -> Option<Draft> {
        let text = self.get(id, tenant)?.text;
        let (digest, errors) = match hypellm_config::load(&text, version) {
            Ok(config) => (Some(config.digest), Vec::new()),
            Err(errors) => (None, errors),
        };

        let mut drafts = self.drafts.write().ok()?;
        let draft = drafts.get_mut(id)?;
        draft.validated = true;
        draft.digest = digest;
        draft.errors = errors;
        Some(draft.clone())
    }

    /// Build the validated configuration for a draft, if it is publishable by
    /// `publisher`.
    pub fn prepare_publish(
        &self,
        id: &str,
        publisher: &PrincipalId,
        tenant: &TenantId,
        version: u64,
    ) -> Result<ValidatedConfig, PublishRefusal> {
        let draft = self.get(id, tenant).ok_or(PublishRefusal::NoSuchDraft)?;
        if !draft.validated {
            return Err(PublishRefusal::NotValidated);
        }
        if !draft.errors.is_empty() {
            return Err(PublishRefusal::Invalid);
        }
        if !self.allow_self_approval && draft.author == *publisher {
            return Err(PublishRefusal::SelfApproval);
        }
        hypellm_config::load(&draft.text, version).map_err(|_| PublishRefusal::Invalid)
    }

    /// Remove a draft.
    pub fn remove(&self, id: &str) -> bool {
        self.drafts
            .write()
            .map(|mut drafts| drafts.remove(id).is_some())
            .unwrap_or(false)
    }

    /// How many drafts are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.drafts.read().map_or(0, |drafts| drafts.len())
    }

    /// Whether no drafts are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DraftStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "\
tenant id=acme
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:m provider=local model=m local=true operations=chat streaming=true \
       context=1000 max_output=100
alias id=a targets=local:m
grant scope=tenant:acme model=* allow=true
binding id=b scope=tenant:acme model=* prefer=local:m
";

    const INVALID: &str = "alias id=a targets=does-not-exist\n";

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid identifier")
    }

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("valid identifier")
    }

    const ACME: &str = "acme";

    #[test]
    fn a_draft_is_created_unvalidated() {
        let store = DraftStore::new();
        let draft = store.create(VALID.to_owned(), principal("user:alice"), tenant(ACME), 1000);
        assert!(!draft.validated);
        assert!(!draft.is_valid());
        assert_eq!(draft.author.as_str(), "user:alice");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn validation_records_the_digest_for_a_good_draft() {
        let store = DraftStore::new();
        let draft = store.create(VALID.to_owned(), principal("user:alice"), tenant(ACME), 0);
        let validated = store.validate(&draft.id, &tenant(ACME), 2).expect("validates");
        assert!(validated.validated);
        assert!(validated.errors.is_empty());
        assert!(validated.digest.is_some());
        assert!(validated.is_valid());
    }

    #[test]
    fn validation_records_errors_for_a_bad_draft() {
        let store = DraftStore::new();
        let draft = store.create(INVALID.to_owned(), principal("user:alice"), tenant(ACME), 0);
        let validated = store.validate(&draft.id, &tenant(ACME), 2).expect("validates");
        assert!(validated.validated);
        assert!(!validated.errors.is_empty());
        assert!(validated.digest.is_none());
        assert!(!validated.is_valid());
    }

    #[test]
    fn an_author_cannot_publish_their_own_draft() {
        // Specification 9.3: a policy editor "cannot publish own draft by
        // default". This is the separation that makes the approver role mean
        // something.
        let store = DraftStore::new();
        let alice = principal("user:alice");
        let draft = store.create(VALID.to_owned(), alice.clone(), tenant(ACME), 0);
        store.validate(&draft.id, &tenant(ACME), 2);

        assert_eq!(
            store.prepare_publish(&draft.id, &alice, &tenant(ACME), 2).unwrap_err(),
            PublishRefusal::SelfApproval
        );

        // Somebody else can.
        let config = store
            .prepare_publish(&draft.id, &principal("user:bob"), &tenant(ACME), 2)
            .expect("an approver may publish");
        assert_eq!(config.snapshot.version, 2);
    }

    #[test]
    fn self_approval_can_be_enabled_deliberately() {
        let store = DraftStore::with_self_approval();
        assert!(store.allows_self_approval());
        let alice = principal("user:alice");
        let draft = store.create(VALID.to_owned(), alice.clone(), tenant(ACME), 0);
        store.validate(&draft.id, &tenant(ACME), 2);
        assert!(store.prepare_publish(&draft.id, &alice, &tenant(ACME), 2).is_ok());
    }

    #[test]
    fn an_unvalidated_draft_cannot_be_published() {
        // Specification 15.4: "Publishing requires validation".
        let store = DraftStore::new();
        let draft = store.create(VALID.to_owned(), principal("user:alice"), tenant(ACME), 0);
        assert_eq!(
            store
                .prepare_publish(&draft.id, &principal("user:bob"), &tenant(ACME), 2)
                .unwrap_err(),
            PublishRefusal::NotValidated
        );
    }

    #[test]
    fn an_invalid_draft_cannot_be_published() {
        let store = DraftStore::new();
        let draft = store.create(INVALID.to_owned(), principal("user:alice"), tenant(ACME), 0);
        store.validate(&draft.id, &tenant(ACME), 2);
        assert_eq!(
            store
                .prepare_publish(&draft.id, &principal("user:bob"), &tenant(ACME), 2)
                .unwrap_err(),
            PublishRefusal::Invalid
        );
    }

    #[test]
    fn an_unknown_draft_is_reported_as_such() {
        let store = DraftStore::new();
        assert_eq!(
            store
                .prepare_publish("draft_999", &principal("user:bob"), &tenant(ACME), 2)
                .unwrap_err(),
            PublishRefusal::NoSuchDraft
        );
        assert!(store.validate("draft_999", &tenant(ACME), 2).is_none());
        assert!(!store.remove("draft_999"));
    }

    #[test]
    fn drafts_list_oldest_first_and_can_be_removed() {
        let store = DraftStore::new();
        let first = store.create(VALID.to_owned(), principal("user:a"), tenant(ACME), 100);
        let second = store.create(VALID.to_owned(), principal("user:a"), tenant(ACME), 200);

        let listed = store.list(&tenant(ACME));
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, first.id);
        assert_eq!(listed[1].id, second.id);

        assert!(store.remove(&first.id));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn draft_identifiers_are_unique() {
        let store = DraftStore::new();
        let a = store.create(VALID.to_owned(), principal("user:a"), tenant(ACME), 0);
        let b = store.create(VALID.to_owned(), principal("user:a"), tenant(ACME), 0);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn a_draft_is_reachable_only_from_the_tenant_it_was_proposed_in() {
        // Appendix B: management visibility never exceeds the caller's tenant.
        // The store is one global map, so the scoping has to be in every lookup
        // — a publish that skipped it would activate a whole-router change
        // nobody in the publishing tenant reviewed.
        let store = DraftStore::new();
        let theirs = store.create(
            VALID.to_owned(),
            principal("user:editor-globex"),
            tenant("globex"),
            0,
        );
        let mine = store.create(VALID.to_owned(), principal("user:editor-acme"), tenant(ACME), 0);

        let listed = store.list(&tenant(ACME));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, mine.id);

        assert!(store.get(&theirs.id, &tenant(ACME)).is_none());
        assert!(store.validate(&theirs.id, &tenant(ACME), 2).is_none());
        assert_eq!(
            store
                .prepare_publish(&theirs.id, &principal("user:approver-acme"), &tenant(ACME), 2)
                .unwrap_err(),
            PublishRefusal::NoSuchDraft,
            "another tenant's draft must read as absent, not as forbidden"
        );

        // And their own tenant is unaffected.
        assert!(store.validate(&theirs.id, &tenant("globex"), 2).is_some());
    }

    #[test]
    fn refusal_codes_are_distinct() {
        let all = [
            PublishRefusal::NoSuchDraft,
            PublishRefusal::NotValidated,
            PublishRefusal::Invalid,
            PublishRefusal::SelfApproval,
        ];
        let mut codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);
        for refusal in all {
            assert!(!refusal.message().is_empty());
        }
    }
}
