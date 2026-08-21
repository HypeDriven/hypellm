//! Routing policy: precedence, eligibility, scoring, selection.
//!
//! Specification 6: "Routing is a pure function over an immutable policy
//! snapshot plus bounded live state. It MUST be deterministic for equal inputs
//! except for an explicitly configured weighted tie-breaker seeded by
//! `request_id`. Administrative ordering is never inferred from map iteration
//! order."
//!
//! Three structural choices follow from that sentence:
//!
//! - [`PolicySnapshot::route`] does no I/O and takes `&self`. Live state
//!   arrives through the [`LiveState`] trait, which returns already-sampled
//!   values, so a routing decision cannot block or observe a moving target
//!   mid-evaluation.
//! - Every collection that affects ordering is a `BTreeMap`/`Vec`, never a hash
//!   map. Iteration order is part of the contract.
//! - Ties are broken by target identifier, which is total and stable, after the
//!   optional request-id-seeded jitter.

use crate::canonical::{CanonicalRequest, Operation, ResponseFormat};
use crate::decision::{Candidate, Exclusion, ExclusionReason, ResidencyClass, ScoreTerms};
use crate::ids::{AliasId, BindingId, GroupId, PrincipalId, ProviderId, RequestId, TargetId, TenantId};
use crate::target::{Alias, AdminState, Provider, Target};
use hypellm_crypto::Digest;
use std::collections::{BTreeMap, BTreeSet};

/// Which principals a binding or grant applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingScope {
    /// One principal.
    Principal(PrincipalId),
    /// Every member of a group.
    Group(GroupId),
    /// Every principal in a tenant.
    Tenant(TenantId),
    /// Every principal, in every tenant that permits inheritance.
    Global,
}

/// Which requested models a binding or grant applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelSelector {
    /// One alias, matched exactly.
    Exact(AliasId),
    /// Any alias beginning with this prefix, written `prefix*` in configuration.
    Prefix(String),
    /// Any alias.
    Any,
}

impl ModelSelector {
    /// Whether this selector matches an alias.
    #[must_use]
    pub fn matches(&self, alias: &AliasId) -> bool {
        match self {
            Self::Exact(a) => a == alias,
            Self::Prefix(p) => alias.as_str().starts_with(p.as_str()),
            Self::Any => true,
        }
    }

    /// Whether this selector names one alias exactly.
    ///
    /// Specification 6.1 separates "exact requested model/alias" from
    /// "model class/wildcard" at different precedence levels.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

/// Which targets a preference, deny, or allow applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelector {
    /// One target, matched exactly.
    Exact(TargetId),
    /// Every target of one provider, written `provider:*` in configuration.
    Provider(ProviderId),
    /// Every target.
    Any,
}

impl TargetSelector {
    /// Whether this selector matches a target.
    #[must_use]
    pub fn matches(&self, target: &Target) -> bool {
        match self {
            Self::Exact(id) => *id == target.id,
            Self::Provider(p) => *p == target.provider_id,
            Self::Any => true,
        }
    }

    /// Specificity, higher being more specific. Used to resolve two selectors
    /// within one binding that both match the same target.
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Exact(_) => 3,
            Self::Provider(_) => 2,
            Self::Any => 1,
        }
    }
}

/// An ordered preference for a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPreference {
    /// Which targets this applies to.
    pub selector: TargetSelector,
    /// Rank, zero being most preferred.
    pub rank: u16,
    /// Administrator weight, within [`ScoreTerms::POLICY_WEIGHT_RANGE`].
    pub weight: i64,
}

/// A priority binding (specification 5, "Priority binding").
#[derive(Debug, Clone)]
pub struct Binding {
    /// Identifier, used as the final deterministic tie-break.
    pub id: BindingId,
    /// Who it applies to.
    pub scope: BindingScope,
    /// Which requested models it applies to.
    pub model: ModelSelector,
    /// Ordered target preferences.
    pub preferences: Vec<TargetPreference>,
    /// Targets this binding denies.
    pub denies: Vec<TargetSelector>,
    /// Targets this binding explicitly allows.
    ///
    /// An allow can only overturn a deny from a *lower*-precedence binding.
    /// Specification 6.1: "a lower-precedence binding cannot re-enable a target
    /// denied by a higher-precedence security or compliance rule."
    pub allows: Vec<TargetSelector>,
    /// A hard pin. When set, only this target — and any declared emergency
    /// fallback — may be selected.
    pub pin: Option<TargetId>,
    /// Targets this binding permits when its pin is unavailable.
    ///
    /// Specification 6.1: a hard pin "fails closed if unavailable unless the
    /// same binding defines an allowed emergency fallback".
    pub emergency_fallback: Vec<TargetId>,
    /// Tie-break among bindings at the same precedence level, higher first.
    pub priority: i32,
}

impl Binding {
    /// The precedence level of this binding for a given request context.
    ///
    /// Returns `None` when the binding does not apply. Levels follow
    /// specification 6.1; group and tenant wildcards occupy the slots
    /// immediately below their exact counterparts, which preserves the
    /// specification's ordering for every case it names.
    #[must_use]
    pub fn precedence(&self, ctx: &RoutingContext<'_>, alias: &AliasId) -> Option<u8> {
        if !self.model.matches(alias) {
            return None;
        }
        let exact = self.model.is_exact();
        match &self.scope {
            BindingScope::Principal(p) if p == ctx.principal => {
                Some(if exact { 1 } else { 2 })
            }
            BindingScope::Group(g) if ctx.groups.contains(g) => Some(if exact { 3 } else { 4 }),
            BindingScope::Tenant(t) if t == ctx.tenant => Some(if exact { 5 } else { 6 }),
            BindingScope::Global => Some(7),
            _ => None,
        }
    }
}

/// An authorization grant for an alias.
///
/// Specification 6.2's first filter is "Principal is authorized for requested
/// alias and operation". Authorization is default-deny: an alias with no
/// matching grant is invisible, which is what makes specification 8's rule that
/// `/v1/models` "returns only aliases/models authorized for the principal"
/// hold without a second mechanism.
#[derive(Debug, Clone)]
pub struct AliasGrant {
    /// Who it applies to.
    pub scope: BindingScope,
    /// Which aliases.
    pub model: ModelSelector,
    /// Which operations. Empty means every operation.
    pub operations: Vec<Operation>,
    /// Whether this grant permits or forbids.
    pub allow: bool,
}

impl AliasGrant {
    fn precedence(&self, ctx: &RoutingContext<'_>, alias: &AliasId) -> Option<u8> {
        if !self.model.matches(alias) {
            return None;
        }
        let exact = self.model.is_exact();
        match &self.scope {
            BindingScope::Principal(p) if p == ctx.principal => Some(if exact { 1 } else { 2 }),
            BindingScope::Group(g) if ctx.groups.contains(g) => Some(if exact { 3 } else { 4 }),
            BindingScope::Tenant(t) if t == ctx.tenant => Some(if exact { 5 } else { 6 }),
            BindingScope::Global => Some(7),
            _ => None,
        }
    }

    fn covers(&self, op: Operation) -> bool {
        self.operations.is_empty() || self.operations.contains(&op)
    }
}

/// Bounded live state consulted during scoring.
///
/// Every method returns an already-sampled value. The trait exists so that
/// routing is testable without a running health subsystem, and so that
/// specification 15.4's draft simulation — "returning exclusions and scores
/// without provider invocation" — uses exactly the same code path as
/// production.
pub trait LiveState {
    /// Whether the target's circuit breaker is open.
    fn circuit_open(&self, target: &TargetId) -> bool;
    /// Health penalty, within [`ScoreTerms::HEALTH_RANGE`].
    fn health_penalty(&self, target: &TargetId) -> i64;
    /// Latency penalty, within [`ScoreTerms::LATENCY_RANGE`].
    fn latency_penalty(&self, target: &TargetId) -> i64;
    /// Queue penalty, within [`ScoreTerms::QUEUE_RANGE`].
    fn queue_penalty(&self, target: &TargetId) -> i64;
    /// Affinity bonus, within [`ScoreTerms::AFFINITY_RANGE`].
    fn affinity_bonus(&self, target: &TargetId) -> i64;
    /// Whether the target has any admission capacity left at all.
    fn has_capacity(&self, target: &TargetId) -> bool;

    /// An operator-set administrative state that overrides the configured one.
    ///
    /// Specification 13 makes drain, maintenance, and quarantine operational
    /// actions: an operator takes a target out of rotation *now*, without
    /// waiting for a policy draft to be written, reviewed, approved, and
    /// published. The configured [`Target::admin_state`] is the deployment's
    /// declared intent; this is the live override on top of it.
    ///
    /// Returning `None` — the default — means "no override", and the
    /// configured state applies. Implementations that have no notion of
    /// operator overrides need not implement this.
    fn admin_override(&self, target: &TargetId) -> Option<AdminState> {
        let _ = target;
        None
    }

    /// The observed failure percentage for a target, 0 to 100.
    ///
    /// Used by the failure-policy filter of specification 6.2. Distinct from
    /// [`LiveState::health_penalty`], which expresses the same observation as a
    /// score term; a filter and a penalty answer different questions.
    fn failure_percent(&self, target: &TargetId) -> u32 {
        let _ = target;
        0
    }

    /// How the fleet stands in relation to this target right now.
    ///
    /// [`ResidencyClass::Unmanaged`] — the default — means the target has no
    /// deployment record, so nothing about the fleet applies to it and routing
    /// behaves exactly as it did before orchestration existed. Every current
    /// implementor therefore compiles unchanged, which is the same reason
    /// [`LiveState::admin_override`] and [`LiveState::failure_percent`] are
    /// defaulted.
    ///
    /// Only [`ResidencyClass::Infeasible`] excludes. The other classes remain
    /// candidates and are ordered by warmth — this is the central decision of
    /// the design and the easiest one to get wrong: **if "not currently
    /// running" excluded a target, no target would ever start.**
    fn residency_class(&self, target: &TargetId) -> ResidencyClass {
        let _ = target;
        ResidencyClass::Unmanaged
    }

    /// Estimated milliseconds until the target can serve, from now.
    ///
    /// Zero for anything already resident. For a cold target this is the sum
    /// of the drain, stop, fetch, start, and probe costs the planner computed,
    /// and it is what the deadline check of specification-extension 7.3
    /// compares against: a 90-second model load cannot serve a 30-second
    /// deadline, and pretending otherwise converts a fast failure into a slow
    /// one.
    fn activation_eta_ms(&self, target: &TargetId) -> u64 {
        let _ = target;
        0
    }

    /// Age of the newest valid fleet observation, in milliseconds.
    ///
    /// `None` means no fleet is configured. A router acting on stale belief
    /// stops a container something else already restarted, or starts one
    /// twice — so the classifier fails closed on age rather than guessing.
    fn fleet_observation_age_ms(&self) -> Option<u64> {
        None
    }
}

/// Live state that reports every target as healthy, idle, and available.
///
/// Used by policy simulation and by tests that are exercising precedence rather
/// than health.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdealLiveState;

impl LiveState for IdealLiveState {
    fn circuit_open(&self, _target: &TargetId) -> bool {
        false
    }
    fn health_penalty(&self, _target: &TargetId) -> i64 {
        0
    }
    fn latency_penalty(&self, _target: &TargetId) -> i64 {
        0
    }
    fn queue_penalty(&self, _target: &TargetId) -> i64 {
        0
    }
    fn affinity_bonus(&self, _target: &TargetId) -> i64 {
        0
    }
    fn has_capacity(&self, _target: &TargetId) -> bool {
        true
    }
}

/// The request context routing evaluates against.
#[derive(Debug, Clone)]
pub struct RoutingContext<'a> {
    /// The authenticated principal.
    pub principal: &'a PrincipalId,
    /// Groups the principal belongs to.
    ///
    /// Specification 25: group membership comes from local role bindings or a
    /// provisioned directory sync — never inferred from an email domain.
    pub groups: &'a [GroupId],
    /// The principal's tenant.
    pub tenant: &'a TenantId,
    /// Targets already tried in this request's retry chain.
    pub attempted: &'a [TargetId],
    /// The caller's monotonic clock reading, in milliseconds.
    ///
    /// Sampled once by the caller and passed in, because this crate performs
    /// no I/O and holds no clock (specification 18.3). It exists so that
    /// deadline-versus-time-to-ready can be decided during eligibility rather
    /// than discovered after a container has been started: a 90-second model
    /// load cannot serve a 30-second deadline.
    ///
    /// Routing stays deterministic in the sense Appendix B requires — equal
    /// inputs, including this one, produce equal ordered candidates.
    pub now_millis: u64,
}

impl RoutingContext<'_> {
    /// Milliseconds left before `deadline`, saturating at zero.
    #[must_use]
    pub const fn remaining_ms(&self, deadline: crate::time::Deadline) -> u64 {
        deadline.as_millis().saturating_sub(self.now_millis)
    }
}

/// The result of routing.
#[derive(Debug, Clone)]
pub struct RouteOutcome {
    /// Eligible targets, best first.
    pub candidates: Vec<Candidate>,
    /// Excluded targets with reasons, sorted by target id for determinism.
    pub exclusions: Vec<Exclusion>,
    /// Whether a hard pin governed the selection.
    pub pinned: bool,
}

impl RouteOutcome {
    /// The best candidate, if any.
    #[must_use]
    pub fn best(&self) -> Option<&Candidate> {
        self.candidates.first()
    }
}

/// An immutable, validated policy snapshot.
///
/// Specification 11: "The runtime parses into a validated typed snapshot,
/// resolves all references, verifies invariants, computes a digest, and swaps a
/// single shared pointer. Requests already in flight retain the prior snapshot."
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// Monotonic version number.
    pub version: u64,
    /// Digest of the canonical configuration this was built from.
    pub digest: Digest,
    /// Providers by identifier.
    pub providers: BTreeMap<ProviderId, Provider>,
    /// Targets by identifier.
    pub targets: BTreeMap<TargetId, Target>,
    /// Aliases by identifier.
    pub aliases: BTreeMap<AliasId, Alias>,
    /// Priority bindings.
    pub bindings: Vec<Binding>,
    /// Alias authorization grants.
    pub grants: Vec<AliasGrant>,
    /// Tenants that permit inheriting global defaults.
    ///
    /// Specification 6.1, level 6: "Only when tenant permits inheritance."
    pub global_inheritance: BTreeSet<TenantId>,
    /// Endpoints that passed the static destination allowlist at load time.
    pub allowlisted_targets: BTreeSet<TargetId>,
    /// Whether the deterministic weighted tie-breaker is enabled.
    pub weighted_tie_break: bool,
    /// The observed failure percentage above which a target is refused outright.
    ///
    /// Specification 6.2 requires a target to be "healthy enough for the
    /// requested failure policy" — a filter, distinct from the health *score*
    /// term of specification 6.3. The score expresses a preference between
    /// working targets; this is the floor below which a target is not a
    /// candidate at all, however attractive its other terms.
    ///
    /// 100 means no floor, which is the default: a router that starts refusing
    /// targets on an operator's first day, because of a threshold nobody chose,
    /// is worse than one that relies on the circuit breaker alone.
    pub max_failure_percent: u32,
    /// Tokens charged per document part when a target declares no figure.
    pub default_document_token_estimate: u32,
    /// Milliseconds of generation time, per unit of effort multiplier, that a
    /// cold target must leave inside the deadline after it becomes ready.
    ///
    /// Time-to-ready alone is not the whole cost of choosing a cold target: a
    /// request that finishes loading a model with two seconds of deadline left
    /// has not been served. This is the operator's statement of how much of
    /// the deadline generation itself needs, scaled by the reasoning tier's
    /// multiplier, and it is why a high-effort request behind a three-minute
    /// load is a different proposition from a minimal-effort one.
    ///
    /// Zero disables the headroom and compares time-to-ready against the
    /// deadline alone.
    pub activation_effort_headroom_ms: u64,
}

impl PolicySnapshot {
    /// An empty snapshot, used before the first configuration is activated.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: 0,
            digest: Digest::from_bytes([0; 32]),
            providers: BTreeMap::new(),
            targets: BTreeMap::new(),
            aliases: BTreeMap::new(),
            bindings: Vec::new(),
            grants: Vec::new(),
            global_inheritance: BTreeSet::new(),
            allowlisted_targets: BTreeSet::new(),
            weighted_tie_break: false,
            max_failure_percent: 100,
            default_document_token_estimate: crate::canonical::DEFAULT_DOCUMENT_TOKEN_ESTIMATE,
            activation_effort_headroom_ms: 5_000,
        }
    }

    /// Whether the principal may use this alias for this operation.
    ///
    /// Default deny. The highest-precedence matching grant wins; ties within a
    /// level are resolved deny-first, so a deny and an allow at the same
    /// specificity fail closed.
    #[must_use]
    pub fn authorizes(
        &self,
        ctx: &RoutingContext<'_>,
        alias: &AliasId,
        operation: Operation,
    ) -> bool {
        let mut best: Option<(u8, bool)> = None;
        for grant in &self.grants {
            if !grant.covers(operation) {
                continue;
            }
            if matches!(grant.scope, BindingScope::Global)
                && !self.global_inheritance.contains(ctx.tenant)
            {
                continue;
            }
            let Some(level) = grant.precedence(ctx, alias) else {
                continue;
            };
            best = Some(match best {
                None => (level, grant.allow),
                Some((best_level, best_allow)) => {
                    if level < best_level {
                        (level, grant.allow)
                    } else if level == best_level {
                        // Deny wins a tie.
                        (best_level, best_allow && grant.allow)
                    } else {
                        (best_level, best_allow)
                    }
                }
            });
        }
        best.is_some_and(|(_, allow)| allow)
    }

    /// Aliases this principal may see, for `GET /v1/models`.
    ///
    /// Specification 8: "returns only aliases/models authorized for the
    /// principal", and Appendix B: "The models endpoint reveals only authorized
    /// aliases."
    #[must_use]
    pub fn visible_aliases(&self, ctx: &RoutingContext<'_>, operation: Operation) -> Vec<&Alias> {
        self.aliases
            .values()
            .filter(|a| self.authorizes(ctx, &a.id, operation))
            .collect()
    }

    /// Route a request: returns ranked eligible candidates plus exclusion
    /// reasons. Performs no I/O (specification 18.3).
    #[must_use]
    pub fn route(
        &self,
        ctx: &RoutingContext<'_>,
        req: &CanonicalRequest,
        live: &dyn LiveState,
    ) -> RouteOutcome {
        let alias_id = &req.requested_model;

        let Some(alias) = self.aliases.get(alias_id) else {
            return RouteOutcome {
                candidates: Vec::new(),
                exclusions: Vec::new(),
                pinned: false,
            };
        };

        if !self.authorizes(ctx, alias_id, req.operation) {
            // Every target the alias could have used is reported as excluded
            // for the same reason, so the trace explains the outcome without
            // disclosing which targets exist.
            let exclusions = alias
                .permitted_targets
                .iter()
                .map(|t| Exclusion {
                    target: t.clone(),
                    reason: ExclusionReason::NotAuthorizedForAlias,
                })
                .collect();
            return RouteOutcome {
                candidates: Vec::new(),
                exclusions,
                pinned: false,
            };
        }

        let merged = self.merge_bindings(ctx, alias_id);

        let mut candidates = Vec::new();
        let mut exclusions = Vec::new();

        for target_id in &alias.permitted_targets {
            let Some(target) = self.targets.get(target_id) else {
                // A dangling reference cannot occur in a validated snapshot;
                // if one does, exclude rather than panic (specification 18.2:
                // no panics on data-plane input).
                exclusions.push(Exclusion {
                    target: target_id.clone(),
                    reason: ExclusionReason::NotPermittedForAlias,
                });
                continue;
            };

            match self.evaluate(ctx, req, alias, target, &merged, live) {
                Err(reason) => exclusions.push(Exclusion {
                    target: target_id.clone(),
                    reason,
                }),
                Ok(candidate) => candidates.push(candidate),
            }
        }

        // Sort by pin standing, then score descending, then target id
        // ascending. The last key makes the order total and independent of the
        // input order, which is what Appendix B's "equal request, policy
        // snapshot, and live-state snapshot produce equal ordered candidates"
        // requires.
        //
        // Pin standing leads because specification 6.1 makes an emergency
        // fallback a fallback rather than a peer: without this key a local,
        // cheap fallback outscores a healthy remote pin on the locality and
        // cost terms, and the pin is never tried at all.
        candidates.sort_by(|a, b| a.ordering_key().cmp(&b.ordering_key()));
        exclusions.sort_by(|a, b| a.target.cmp(&b.target).then_with(|| a.reason.cmp(&b.reason)));

        RouteOutcome {
            candidates,
            exclusions,
            pinned: merged.pin.is_some(),
        }
    }

    /// Collapse every applicable binding into one merged view.
    fn merge_bindings(&self, ctx: &RoutingContext<'_>, alias: &AliasId) -> MergedBindings {
        // Order bindings by (precedence level, descending priority, id) so that
        // "highest precedence wins" is a single forward pass and never depends
        // on the order bindings appear in configuration.
        let mut applicable: Vec<(u8, &Binding)> = self
            .bindings
            .iter()
            .filter(|b| {
                !matches!(b.scope, BindingScope::Global)
                    || self.global_inheritance.contains(ctx.tenant)
            })
            .filter_map(|b| b.precedence(ctx, alias).map(|level| (level, b)))
            .collect();
        applicable.sort_by(|(la, a), (lb, b)| {
            la.cmp(lb)
                .then_with(|| b.priority.cmp(&a.priority))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut merged = MergedBindings::default();

        for (level, binding) in applicable {
            for deny in &binding.denies {
                merged.record_rule(level, deny.clone(), true, binding.id.clone());
            }
            for allow in &binding.allows {
                merged.record_rule(level, allow.clone(), false, binding.id.clone());
            }
            for pref in &binding.preferences {
                merged.record_preference(level, pref, binding.priority, binding.id.clone());
            }
            if let Some(pin) = &binding.pin {
                if merged.pin.is_none() {
                    merged.pin = Some(pin.clone());
                    merged.pin_fallback.clone_from(&binding.emergency_fallback);
                }
            }
            if merged.top_level.is_none() {
                merged.top_level = Some(level);
            }
        }

        merged
    }

    /// Run every eligibility filter, then score. Filters come first and are
    /// never expressible as penalties (specification 6.3).
    fn evaluate(
        &self,
        ctx: &RoutingContext<'_>,
        req: &CanonicalRequest,
        alias: &Alias,
        target: &Target,
        merged: &MergedBindings,
        live: &dyn LiveState,
    ) -> Result<Candidate, ExclusionReason> {
        // -- Security and compliance filters -------------------------------

        if merged.is_denied(target) {
            return Err(ExclusionReason::DeniedByPolicy);
        }

        if let Some(pin) = &merged.pin {
            if *pin != target.id && !merged.pin_fallback.contains(&target.id) {
                return Err(ExclusionReason::NotPinnedTarget);
            }
        }

        if !self.allowlisted_targets.contains(&target.id) {
            return Err(ExclusionReason::EndpointNotAllowlisted);
        }

        let Some(provider) = self.providers.get(&target.provider_id) else {
            return Err(ExclusionReason::ProviderDisabled);
        };
        if !provider.enabled {
            return Err(ExclusionReason::ProviderDisabled);
        }
        if provider.credential_ref.is_none() && !target.is_local {
            // A remote target with no credential reference cannot be reached
            // under any tenant's scope.
            return Err(ExclusionReason::CredentialScopeMismatch);
        }

        if !target.satisfies_residency(req.limits.residency.as_ref()) {
            return Err(ExclusionReason::ResidencyMismatch);
        }

        if req.hints.require_local && !target.is_local {
            return Err(ExclusionReason::LocalRequired);
        }

        if !alias.allow_family_failover
            && !ctx.attempted.is_empty()
            && !ctx.attempted.contains(&target.id)
        {
            // Only relevant once an attempt has been made: switching to a
            // target whose provider family differs requires explicit
            // permission (specification 6.5).
            let already_family: Option<&ProviderId> = ctx
                .attempted
                .first()
                .and_then(|t| self.targets.get(t))
                .map(|t| &t.provider_id);
            if let Some(family) = already_family {
                let attempted_family = self.providers.get(family).map(|p| p.family);
                let this_family = provider.family;
                if attempted_family.is_some_and(|f| f != this_family) {
                    return Err(ExclusionReason::FamilyFailoverNotAllowed);
                }
            }
        }

        // -- Administrative state -------------------------------------------

        // An operator override wins over the configured state. Both are
        // eligibility filters, never score penalties (specification 6.3).
        match live
            .admin_override(&target.id)
            .unwrap_or(target.admin_state)
        {
            AdminState::Enabled => {}
            AdminState::Draining => return Err(ExclusionReason::TargetDraining),
            AdminState::Maintenance => return Err(ExclusionReason::TargetMaintenance),
            AdminState::Quarantined => return Err(ExclusionReason::TargetQuarantined),
            AdminState::Disabled => return Err(ExclusionReason::TargetDisabled),
        }

        if ctx.attempted.contains(&target.id) {
            return Err(ExclusionReason::AlreadyAttempted);
        }

        // -- Capability filters ---------------------------------------------

        let caps = &target.capabilities;

        if !caps.supports_operation(req.operation) {
            return Err(ExclusionReason::OperationUnsupported);
        }
        // The capability verb, when the alias declares one. `Operation` is the
        // wire shape the client used; `Capability` is the work the model does,
        // and no combination of operation and modality distinguishes a music
        // model from a speech model.
        if let Some(verb) = alias.capability {
            if !caps.supports_capability(verb) {
                return Err(ExclusionReason::CapabilityUnsupported);
            }
        }
        if !caps.supports_modalities(&req.required_modalities()) {
            return Err(ExclusionReason::ModalityUnsupported);
        }
        // Excluded rather than downgraded. A target that quietly serves a
        // `high` request at whatever it does support returns a cheaper answer
        // than the caller asked for and tells nobody.
        if !caps.supports_effort(req.reasoning_effort) {
            return Err(ExclusionReason::ReasoningEffortUnsupported);
        }
        if req.stream.enabled && !caps.streaming {
            return Err(ExclusionReason::StreamingUnsupported);
        }
        if req.requires_tools() && !caps.tools {
            return Err(ExclusionReason::ToolsUnsupported);
        }
        match &req.response_format {
            Some(ResponseFormat::JsonObject) if !caps.json_mode => {
                return Err(ExclusionReason::StructuredOutputUnsupported);
            }
            Some(ResponseFormat::JsonSchema { .. }) if !caps.structured_output => {
                return Err(ExclusionReason::StructuredOutputUnsupported);
            }
            _ => {}
        }

        // The document constant this target declares, not the byte-derived
        // figure: a scanned PDF is megabytes and few tokens, and a dense text
        // one is the reverse.
        let estimate =
            target.token_estimate(req.reasoning_effort, self.default_document_token_estimate);
        let estimated_input = req.estimated_input_tokens_with(estimate.document_token_estimate);
        if estimated_input > u64::from(caps.max_context_tokens) {
            return Err(ExclusionReason::ContextWindowTooSmall);
        }
        if let Some(want) = req.limits.max_output_tokens {
            if u64::from(want) > u64::from(caps.max_output_tokens) {
                return Err(ExclusionReason::OutputLimitTooSmall);
            }
        }

        // -- Cost, quality, and capacity -------------------------------------

        if !target.within_cost_ceiling(req.limits.max_cost_class) {
            return Err(ExclusionReason::CostCeilingExceeded);
        }
        // A floor, and independent of the ceiling above. A local Q5 may be
        // cheaper *and* better than a remote Q4, so neither bound is derivable
        // from the other.
        if !target.meets_quality_floor(req.limits.min_quality_class) {
            return Err(ExclusionReason::QualityFloorNotMet);
        }
        if live.circuit_open(&target.id) {
            return Err(ExclusionReason::CircuitOpen);
        }
        // Specification 6.2: the target must be "healthy enough for the
        // requested failure policy". A filter, not a penalty — a target failing
        // most of its requests should not be reachable merely because it is
        // cheap and local.
        if self.max_failure_percent < 100
            && live.failure_percent(&target.id) > self.max_failure_percent
        {
            return Err(ExclusionReason::Unhealthy);
        }
        if !live.has_capacity(&target.id) {
            return Err(ExclusionReason::CapacityExhausted);
        }

        // -- Fleet residency --------------------------------------------------

        // Sampled once, here, and reused for scoring below. Re-reading it
        // mid-decision would let a target be filtered under one belief and
        // ranked under another.
        let residency = live.residency_class(&target.id);
        if let Some(reason) = residency.exclusion() {
            return Err(reason);
        }
        if residency.requires_activation() {
            // Time-to-ready plus the generation headroom the tier implies,
            // against what is left of the deadline. Offering a cold target
            // that cannot finish converts a fast, explained failure into a
            // slow, expensive one — and on this path the expense is minutes of
            // fleet time, not milliseconds of router time.
            let required = live.activation_eta_ms(&target.id).saturating_add(
                self.activation_effort_headroom_ms
                    .saturating_mul(u64::from(estimate.output_multiplier)),
            );
            if required > ctx.remaining_ms(req.limits.deadline) {
                return Err(ExclusionReason::ActivationExceedsDeadline);
            }
        }

        // -- Reachability by preference --------------------------------------

        // Standing relative to an active pin. With no pin every candidate is
        // `PIN_TARGET`, so the ordering key is unaffected.
        let pin_rank = match &merged.pin {
            Some(pin) if *pin != target.id => Candidate::PIN_FALLBACK,
            _ => Candidate::PIN_TARGET,
        };

        let Some(pref) = merged.preference_for(target) else {
            // A pin makes its own target reachable even with no preference
            // entry, so an operator does not have to write both.
            if merged.pin.as_ref() == Some(&target.id)
                || merged.pin_fallback.contains(&target.id)
            {
                return Ok(self.score(req, target, 0, 0, pin_rank, residency, live));
            }
            return Err(ExclusionReason::NotSelectedByAnyBinding);
        };

        Ok(self.score(
            req,
            target,
            pref.rank,
            pref.weight,
            pin_rank,
            residency,
            live,
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every argument is a distinct, already-computed input to one \
                  formula; bundling them into a struct would move the same \
                  values behind a name that adds nothing"
    )]
    fn score(
        &self,
        req: &CanonicalRequest,
        target: &Target,
        rank: u16,
        weight: i64,
        pin_rank: u8,
        residency: ResidencyClass,
        live: &dyn LiveState,
    ) -> Candidate {
        let cost_penalty = -(i64::from(target.cost_class.0) * 5_000);
        let locality_bonus = if target.is_local { 25_000 } else { 0 };
        let jitter = if self.weighted_tie_break {
            deterministic_jitter(req.request_id, &target.id)
        } else {
            0
        };

        // The affinity term carries three contributors in disjoint slices
        // (specification-extension 7.2). Splitting rather than contending is
        // what keeps the guarantee readable: warmth occupies a ladder whose
        // step exceeds the whole hint slice, so a hint can break a tie between
        // two equally-warm targets and can never promote a colder one.
        //
        // The hint is permission-gated *before* it reaches this crate: the
        // protocol layer drops `prefer_target` unless the principal may supply
        // one, so a hint present here is one policy already admitted. It still
        // cannot create eligibility — it is read only after every filter above
        // has passed — and it cannot outrank a binding, because rank is a
        // separate term two orders of magnitude larger.
        let warmth = residency.warmth_bonus();
        let hint_bonus = if req.hints.prefer_target.as_ref() == Some(&target.id) {
            ScoreTerms::HINT_SLICE
        } else {
            0
        };
        let affinity = live
            .affinity_bonus(&target.id)
            .clamp(0, ScoreTerms::CONVERSATION_SLICE)
            .saturating_add(warmth)
            .saturating_add(hint_bonus);

        let terms = ScoreTerms {
            priority_rank: ScoreTerms::rank_term(rank),
            policy_weight: weight,
            health: live.health_penalty(&target.id),
            latency: live.latency_penalty(&target.id),
            queue: live.queue_penalty(&target.id),
            cost: cost_penalty,
            locality: locality_bonus,
            affinity,
            jitter,
        }
        .clamped();

        Candidate {
            target: target.id.clone(),
            terms,
            binding_precedence: 0,
            rank,
            pin_rank,
            residency,
        }
    }
}

/// A merged view of every applicable binding.
#[derive(Debug, Default)]
struct MergedBindings {
    /// Best (numerically lowest) precedence at which each rule applies, and
    /// whether that rule denies. Keyed by an opaque rule key so that a
    /// provider-wide deny and an exact allow can be compared.
    rules: Vec<MergedRule>,
    /// Preferences by target selector, highest precedence first.
    preferences: Vec<MergedPreference>,
    /// The hard pin from the highest-precedence binding that declares one.
    pin: Option<TargetId>,
    /// Emergency fallback targets from that same binding.
    pin_fallback: Vec<TargetId>,
    /// The highest precedence level seen.
    top_level: Option<u8>,
}

#[derive(Debug)]
struct MergedRule {
    level: u8,
    selector: TargetSelector,
    deny: bool,
    #[allow(dead_code, reason = "retained for decision-trace attribution")]
    binding: BindingId,
}

#[derive(Debug)]
struct MergedPreference {
    level: u8,
    selector: TargetSelector,
    rank: u16,
    weight: i64,
    priority: i32,
    binding: BindingId,
}

impl MergedBindings {
    fn record_rule(&mut self, level: u8, selector: TargetSelector, deny: bool, binding: BindingId) {
        self.rules.push(MergedRule {
            level,
            selector,
            deny,
            binding,
        });
    }

    fn record_preference(
        &mut self,
        level: u8,
        pref: &TargetPreference,
        priority: i32,
        binding: BindingId,
    ) {
        self.preferences.push(MergedPreference {
            level,
            selector: pref.selector.clone(),
            rank: pref.rank,
            weight: pref.weight,
            priority,
            binding,
        });
    }

    /// Whether a target is denied.
    ///
    /// Implements specification 6.1's sticky deny: the best-precedence matching
    /// rule wins, and a deny wins a tie at equal precedence and specificity. A
    /// lower-precedence allow can therefore never re-enable a higher-precedence
    /// deny.
    fn is_denied(&self, target: &Target) -> bool {
        let mut best: Option<(u8, u8, bool)> = None; // (level, specificity, deny)
        for rule in &self.rules {
            if !rule.selector.matches(target) {
                continue;
            }
            let key = (rule.level, rule.selector.specificity());
            best = Some(match best {
                None => (key.0, key.1, rule.deny),
                Some((level, spec, deny)) => {
                    // Lower level number is higher precedence. Within a level,
                    // a more specific selector wins.
                    if key.0 < level || (key.0 == level && key.1 > spec) {
                        (key.0, key.1, rule.deny)
                    } else if key.0 == level && key.1 == spec {
                        (level, spec, deny || rule.deny)
                    } else {
                        (level, spec, deny)
                    }
                }
            });
        }
        best.is_some_and(|(_, _, deny)| deny)
    }

    /// The winning preference for a target, if any.
    ///
    /// Highest precedence wins; within a level, the more specific selector
    /// wins; then higher binding priority; then lower binding id.
    fn preference_for(&self, target: &Target) -> Option<&MergedPreference> {
        let mut best: Option<&MergedPreference> = None;
        for pref in &self.preferences {
            if !pref.selector.matches(target) {
                continue;
            }
            best = Some(match best {
                None => pref,
                Some(current) => {
                    let better = pref.level < current.level
                        || (pref.level == current.level
                            && pref.selector.specificity() > current.selector.specificity())
                        || (pref.level == current.level
                            && pref.selector.specificity() == current.selector.specificity()
                            && pref.priority > current.priority)
                        || (pref.level == current.level
                            && pref.selector.specificity() == current.selector.specificity()
                            && pref.priority == current.priority
                            && pref.binding < current.binding);
                    if better { pref } else { current }
                }
            });
        }
        best
    }
}

/// A small, deterministic, request-scoped value in `0..1000`.
///
/// Specification 6.3: "Optional small request-id-derived value for weighted
/// distribution without global RNG contention." Deterministic in the
/// request id and the target id, so replaying a request reproduces the
/// decision exactly — which is what makes the decision explorer meaningful.
///
/// Deliberately not `DefaultHasher`: that is randomly seeded per process, so
/// two routers would disagree and a replay would not reproduce.
#[must_use]
pub fn deterministic_jitter(request_id: RequestId, target: &TargetId) -> i64 {
    // FNV-1a over the target id, mixed with the request id by SplitMix64.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in target.as_str().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Split the 128-bit id into its two 64-bit halves. Both conversions are
    // infallible — the mask and the shift each leave 64 bits — so the fallback
    // is unreachable and only there to keep the conversion checked.
    let low = u64::try_from(request_id.as_u128() & u128::from(u64::MAX)).unwrap_or(0);
    let high = u64::try_from(request_id.as_u128() >> 64).unwrap_or(0);
    let mut z = h ^ low ^ high.rotate_left(32);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    i64::try_from(z % 1000).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        ClientProtocol, CostClass, Message, RequestLimits, Residency, Role, Sampling, StreamOptions,
    };
    use crate::ids::RequestId;
    use crate::target::{Capabilities, Endpoint, EndpointScheme, ProviderFamily};
    use crate::time::{Deadline, TestClock};
    use std::time::Duration;

    fn tid(s: &str) -> TargetId {
        TargetId::new(s).unwrap()
    }
    fn pid(s: &str) -> ProviderId {
        ProviderId::new(s).unwrap()
    }
    fn aid(s: &str) -> AliasId {
        AliasId::new(s).unwrap()
    }
    fn bid(s: &str) -> BindingId {
        BindingId::new(s).unwrap()
    }

    fn provider(id: &str, family: ProviderFamily, local: bool) -> Provider {
        Provider {
            id: pid(id),
            family,
            endpoints: vec![Endpoint {
                scheme: if local {
                    EndpointScheme::Http
                } else {
                    EndpointScheme::Https
                },
                host: if local { "127.0.0.1" } else { "api.example" }.to_owned(),
                port: if local { 8080 } else { 443 },
                base_path: "/v1".to_owned(),
            }],
            credential_ref: if local {
                None
            } else {
                Some(crate::ids::CredentialRef::new("cred").unwrap())
            },
            enabled: true,
            egress_profile: "default".to_owned(),
        }
    }

    fn target(id: &str, provider: &str, local: bool, context: u32, cost: u8) -> Target {
        Target {
            id: tid(id),
            provider_id: pid(provider),
            native_model: id.to_owned(),
            aliases: vec![aid("code-premium")],
            capabilities: Capabilities {
                operations: vec![Operation::Chat],
                streaming: true,
                tools: true,
                max_context_tokens: context,
                max_output_tokens: 8192,
                ..Capabilities::default()
            },
            cost_class: CostClass::new(cost),
            quality_class: Default::default(),
            document_token_estimate: None,
            residency: Some(Residency::new("eu")),
            is_local: local,
            admin_state: AdminState::Enabled,
            endpoint_index: 0,
            max_concurrency: 16,
            max_requests_per_second: 100,
        }
    }

    /// The Appendix A scenario, as a reusable fixture.
    fn snapshot() -> PolicySnapshot {
        let mut s = PolicySnapshot::empty();
        s.providers.insert(pid("local"), provider("local", ProviderFamily::LlamaCpp, true));
        s.providers.insert(
            pid("anthropic"),
            provider("anthropic", ProviderFamily::Anthropic, false),
        );
        s.providers
            .insert(pid("openai"), provider("openai", ProviderFamily::OpenAi, false));
        s.providers.insert(
            pid("deepseek"),
            provider("deepseek", ProviderFamily::DeepSeek, false),
        );

        for (id, prov, local, ctx, cost) in [
            ("local:qwen", "local", true, 65_536u32, 0u8),
            ("anthropic:claude", "anthropic", false, 200_000, 5),
            ("openai:gpt", "openai", false, 128_000, 4),
            ("deepseek:coder", "deepseek", false, 128_000, 1),
        ] {
            s.targets.insert(tid(id), target(id, prov, local, ctx, cost));
            s.allowlisted_targets.insert(tid(id));
        }

        s.aliases.insert(
            aid("code-premium"),
            Alias {
                id: aid("code-premium"),
                capability: None,
                permitted_targets: vec![
                    tid("local:qwen"),
                    tid("anthropic:claude"),
                    tid("openai:gpt"),
                    tid("deepseek:coder"),
                ],
                allow_family_failover: true,
                description: None,
            },
        );

        s.grants.push(AliasGrant {
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            operations: Vec::new(),
            allow: true,
        });

        s.digest = Digest::from_bytes([0x8f; 32]);
        s.version = 1;
        s
    }

    fn request(alias: &str) -> CanonicalRequest {
        let clock = TestClock::new();
        CanonicalRequest {
            request_id: RequestId::from_u128(42),
            tenant: TenantId::new("acme").unwrap(),
            principal: PrincipalId::new("user:42").unwrap(),
            protocol: ClientProtocol::OpenAiChat,
            operation: Operation::Chat,
            requested_model: aid(alias),
            messages: vec![Message::text(Role::User, "hello")],
            inputs: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            response_format: None,
            sampling: Sampling::default(),
            reasoning_effort: Default::default(),
            limits: RequestLimits {
                max_output_tokens: Some(512),
                deadline: Deadline::after(&clock, Duration::from_secs(60)),
                max_cost_class: None,
                min_quality_class: None,
                residency: None,
            },
            stream: StreamOptions {
                enabled: true,
                include_usage: false,
            },
            hints: crate::canonical::RoutingHints::default(),
        }
    }

    fn ctx<'a>(
        principal: &'a PrincipalId,
        groups: &'a [GroupId],
        tenant: &'a TenantId,
        attempted: &'a [TargetId],
    ) -> RoutingContext<'a> {
        RoutingContext {
            principal,
            groups,
            tenant,
            attempted,
            now_millis: 0,
        }
    }

    /// Route against a caller-supplied live state.
    fn route_with(s: &PolicySnapshot, req: &CanonicalRequest, live: &dyn LiveState) -> RouteOutcome {
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);
        s.route(&c, req, live)
    }

    fn route(s: &PolicySnapshot, req: &CanonicalRequest) -> RouteOutcome {
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);
        s.route(&c, req, &IdealLiveState)
    }

    fn chosen(outcome: &RouteOutcome) -> Option<&str> {
        outcome.candidates.first().map(|c| c.target.as_str())
    }

    fn excluded_for(outcome: &RouteOutcome, target: &str) -> Option<ExclusionReason> {
        outcome
            .exclusions
            .iter()
            .find(|e| e.target.as_str() == target)
            .map(|e| e.reason)
    }

    // -- Precedence ---------------------------------------------------------

    #[test]
    fn principal_exact_beats_tenant_default() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("tenant-default"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Exact(tid("openai:gpt")),
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        s.bindings.push(Binding {
            id: bid("user-specific"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: vec![TargetPreference {
                selector: TargetSelector::Exact(tid("local:qwen")),
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert_eq!(chosen(&outcome), Some("local:qwen"));
    }

    #[test]
    fn precedence_levels_follow_specification_6_1() {
        let principal = PrincipalId::new("user:42").unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let groups = vec![GroupId::new("engineering").unwrap()];
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);
        let alias = aid("code-premium");

        let make = |scope: BindingScope, model: ModelSelector| Binding {
            id: bid("b"),
            scope,
            model,
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        };

        assert_eq!(
            make(
                BindingScope::Principal(principal.clone()),
                ModelSelector::Exact(alias.clone())
            )
            .precedence(&c, &alias),
            Some(1)
        );
        assert_eq!(
            make(BindingScope::Principal(principal.clone()), ModelSelector::Any)
                .precedence(&c, &alias),
            Some(2)
        );
        assert_eq!(
            make(
                BindingScope::Group(GroupId::new("engineering").unwrap()),
                ModelSelector::Exact(alias.clone())
            )
            .precedence(&c, &alias),
            Some(3)
        );
        assert_eq!(
            make(
                BindingScope::Tenant(tenant.clone()),
                ModelSelector::Exact(alias.clone())
            )
            .precedence(&c, &alias),
            Some(5)
        );
        assert_eq!(
            make(BindingScope::Tenant(tenant.clone()), ModelSelector::Any).precedence(&c, &alias),
            Some(6)
        );
        assert_eq!(
            make(BindingScope::Global, ModelSelector::Any).precedence(&c, &alias),
            Some(7)
        );

        // Non-matching scopes do not apply at all.
        assert_eq!(
            make(
                BindingScope::Principal(PrincipalId::new("other").unwrap()),
                ModelSelector::Any
            )
            .precedence(&c, &alias),
            None
        );
        assert_eq!(
            make(
                BindingScope::Group(GroupId::new("sales").unwrap()),
                ModelSelector::Any
            )
            .precedence(&c, &alias),
            None
        );
    }

    #[test]
    fn global_defaults_apply_only_with_tenant_inheritance() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("global"),
            scope: BindingScope::Global,
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        // Without inheritance, no binding reaches any target.
        let outcome = route(&s, &request("code-premium"));
        assert!(outcome.candidates.is_empty());
        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::NotSelectedByAnyBinding)
        );

        s.global_inheritance.insert(TenantId::new("acme").unwrap());
        let outcome = route(&s, &request("code-premium"));
        assert!(!outcome.candidates.is_empty());
    }

    // -- Deny semantics -----------------------------------------------------

    #[test]
    fn deny_is_sticky_downward() {
        // Appendix B: "A target denied by an applicable higher-precedence rule
        // is never selected."
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("principal-deny"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: Vec::new(),
            denies: vec![TargetSelector::Provider(pid("deepseek"))],
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        s.bindings.push(Binding {
            id: bid("tenant-allow"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            // A lower-precedence binding explicitly tries to re-enable it.
            allows: vec![TargetSelector::Exact(tid("deepseek:coder"))],
            denies: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert_eq!(
            excluded_for(&outcome, "deepseek:coder"),
            Some(ExclusionReason::DeniedByPolicy),
            "a lower-precedence allow must not re-enable a denied target"
        );
        assert!(
            outcome
                .candidates
                .iter()
                .all(|c| c.target.as_str() != "deepseek:coder")
        );
    }

    #[test]
    fn higher_precedence_allow_overrides_lower_precedence_deny() {
        // The converse direction is permitted: precedence flows one way only.
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("principal-allow"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: vec![TargetPreference {
                selector: TargetSelector::Exact(tid("deepseek:coder")),
                rank: 0,
                weight: 0,
            }],
            allows: vec![TargetSelector::Exact(tid("deepseek:coder"))],
            denies: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        s.bindings.push(Binding {
            id: bid("tenant-deny"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: Vec::new(),
            denies: vec![TargetSelector::Provider(pid("deepseek"))],
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert_eq!(chosen(&outcome), Some("deepseek:coder"));
    }

    #[test]
    fn deny_wins_a_tie_at_equal_precedence_and_specificity() {
        let mut s = snapshot();
        for (id, deny) in [("a", true), ("b", false)] {
            s.bindings.push(Binding {
                id: bid(id),
                scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
                model: ModelSelector::Any,
                preferences: vec![TargetPreference {
                    selector: TargetSelector::Any,
                    rank: 0,
                    weight: 0,
                }],
                denies: if deny {
                    vec![TargetSelector::Exact(tid("openai:gpt"))]
                } else {
                    Vec::new()
                },
                allows: if deny {
                    Vec::new()
                } else {
                    vec![TargetSelector::Exact(tid("openai:gpt"))]
                },
                pin: None,
                emergency_fallback: Vec::new(),
                priority: 0,
            });
        }
        let outcome = route(&s, &request("code-premium"));
        assert_eq!(
            excluded_for(&outcome, "openai:gpt"),
            Some(ExclusionReason::DeniedByPolicy),
            "an ambiguous allow/deny pair must fail closed"
        );
    }

    #[test]
    fn exact_deny_beats_provider_wide_allow_at_the_same_level() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("mixed"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: vec![TargetSelector::Exact(tid("openai:gpt"))],
            allows: vec![TargetSelector::Provider(pid("openai"))],
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        let outcome = route(&s, &request("code-premium"));
        assert_eq!(
            excluded_for(&outcome, "openai:gpt"),
            Some(ExclusionReason::DeniedByPolicy)
        );
    }

    // -- Operator overrides -------------------------------------------------

    /// Live state that reports one target under an operator override.
    #[derive(Debug)]
    struct OverriddenState {
        target: TargetId,
        state: AdminState,
    }

    impl LiveState for OverriddenState {
        fn circuit_open(&self, _target: &TargetId) -> bool {
            false
        }
        fn health_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn latency_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn queue_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn affinity_bonus(&self, _target: &TargetId) -> i64 {
            0
        }
        fn has_capacity(&self, _target: &TargetId) -> bool {
            true
        }
        fn admin_override(&self, target: &TargetId) -> Option<AdminState> {
            (*target == self.target).then_some(self.state)
        }
    }

    /// The base fixture with a binding that makes every target reachable, so a
    /// target missing from the candidates is missing because of the override
    /// under test and not because nothing selected it.
    fn snapshot_with_open_binding() -> PolicySnapshot {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("open"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        s
    }

    #[test]
    fn an_operator_override_takes_a_target_out_of_rotation() {
        // Specification 13 makes drain and maintenance operational actions that
        // take effect immediately. Before this existed the management API
        // reported a successful drain and traffic kept arriving, because the
        // administrative state lived only in the immutable policy snapshot.
        let s = snapshot_with_open_binding();

        for (state, expected) in [
            (AdminState::Draining, ExclusionReason::TargetDraining),
            (AdminState::Maintenance, ExclusionReason::TargetMaintenance),
            (AdminState::Disabled, ExclusionReason::TargetDisabled),
            (AdminState::Quarantined, ExclusionReason::TargetQuarantined),
        ] {
            let live = OverriddenState {
                target: tid("local:qwen"),
                state,
            };
            let outcome = route_with(&s, &request("code-premium"), &live);

            assert_eq!(
                excluded_for(&outcome, "local:qwen"),
                Some(expected),
                "override {state:?} did not exclude the target"
            );
            assert!(
                outcome.candidates.iter().all(|c| c.target.as_str() != "local:qwen"),
                "an overridden target must not be a candidate"
            );
            // The others are unaffected.
            assert!(outcome.candidates.iter().any(|c| c.target.as_str() == "anthropic:claude"));
        }
    }

    /// Live state reporting a fixed failure percentage for one target.
    #[derive(Debug)]
    struct FailingState {
        target: TargetId,
        percent: u32,
    }

    impl LiveState for FailingState {
        fn circuit_open(&self, _target: &TargetId) -> bool {
            false
        }
        fn health_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn latency_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn queue_penalty(&self, _target: &TargetId) -> i64 {
            0
        }
        fn affinity_bonus(&self, _target: &TargetId) -> i64 {
            0
        }
        fn has_capacity(&self, _target: &TargetId) -> bool {
            true
        }
        fn failure_percent(&self, target: &TargetId) -> u32 {
            if *target == self.target { self.percent } else { 0 }
        }
    }

    #[test]
    fn a_target_above_the_failure_ceiling_is_excluded_not_merely_penalised() {
        // Specification 6.2 requires a target to be "healthy enough for the
        // requested failure policy". Before this, `ExclusionReason::Unhealthy`
        // was never produced by the engine at all: a target failing 90% of its
        // requests stayed a candidate, held back only by a score penalty that a
        // locality bonus could outweigh.
        let mut s = snapshot_with_open_binding();
        s.max_failure_percent = 25;

        let live = FailingState {
            // local:qwen is local and free, so on score alone it wins.
            target: tid("local:qwen"),
            percent: 90,
        };
        let outcome = route_with(&s, &request("code-premium"), &live);

        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::Unhealthy)
        );
        assert!(outcome.candidates.iter().all(|c| c.target.as_str() != "local:qwen"));
        assert!(!outcome.candidates.is_empty(), "healthy targets remain eligible");
    }

    #[test]
    fn a_target_within_the_failure_ceiling_stays_eligible() {
        let mut s = snapshot_with_open_binding();
        s.max_failure_percent = 25;
        let live = FailingState {
            target: tid("local:qwen"),
            percent: 10,
        };
        let outcome = route_with(&s, &request("code-premium"), &live);
        assert!(outcome.candidates.iter().any(|c| c.target.as_str() == "local:qwen"));
    }

    #[test]
    fn the_failure_ceiling_is_disabled_by_default() {
        // A router that starts refusing targets because of a threshold nobody
        // chose is worse than one that relies on the circuit breaker alone.
        let s = snapshot_with_open_binding();
        assert_eq!(s.max_failure_percent, 100);

        let live = FailingState {
            target: tid("local:qwen"),
            percent: 100,
        };
        let outcome = route_with(&s, &request("code-premium"), &live);
        assert!(outcome.candidates.iter().any(|c| c.target.as_str() == "local:qwen"));
    }

    #[test]
    fn an_enabled_override_leaves_the_target_in_rotation() {
        let s = snapshot_with_open_binding();
        let live = OverriddenState {
            target: tid("local:qwen"),
            state: AdminState::Enabled,
        };
        let outcome = route_with(&s, &request("code-premium"), &live);
        assert!(outcome.candidates.iter().any(|c| c.target.as_str() == "local:qwen"));
    }

    // -- Pin semantics ------------------------------------------------------

    #[test]
    fn hard_pin_selects_only_the_pinned_target() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("pin"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid("anthropic:claude")),
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert!(outcome.pinned);
        assert_eq!(outcome.candidates.len(), 1);
        assert_eq!(chosen(&outcome), Some("anthropic:claude"));
        for other in ["local:qwen", "openai:gpt", "deepseek:coder"] {
            assert_eq!(
                excluded_for(&outcome, other),
                Some(ExclusionReason::NotPinnedTarget),
                "{other}"
            );
        }
    }

    #[test]
    fn hard_pin_fails_closed_when_unavailable() {
        // Appendix B: "A hard pin never falls back unless its own binding
        // declares fallback."
        let mut s = snapshot();
        if let Some(t) = s.targets.get_mut(&tid("anthropic:claude")) {
            t.admin_state = AdminState::Quarantined;
        }
        s.bindings.push(Binding {
            id: bid("pin"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 1,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid("anthropic:claude")),
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert!(
            outcome.candidates.is_empty(),
            "a pinned target that is unavailable must not fall back: {:?}",
            outcome.candidates
        );
        assert_eq!(
            excluded_for(&outcome, "anthropic:claude"),
            Some(ExclusionReason::TargetQuarantined)
        );
    }

    #[test]
    fn declared_emergency_fallback_is_permitted() {
        let mut s = snapshot();
        if let Some(t) = s.targets.get_mut(&tid("anthropic:claude")) {
            t.admin_state = AdminState::Disabled;
        }
        s.bindings.push(Binding {
            id: bid("pin"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid("anthropic:claude")),
            emergency_fallback: vec![tid("openai:gpt")],
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        assert_eq!(chosen(&outcome), Some("openai:gpt"));
        assert_eq!(outcome.candidates.len(), 1);
    }

    #[test]
    fn a_healthy_pin_outranks_its_own_emergency_fallback() {
        // Specification 6.1: a hard pin "selects only the pinned target and
        // fails closed if unavailable unless the same binding defines an
        // allowed emergency fallback". The fallback is reached only when the
        // pin cannot be — it is not a peer that competes on score.
        //
        // The fixture makes this maximally adversarial: the pin is remote and
        // the most expensive target (cost class 5, no locality bonus), while
        // the fallback is local and free. On score alone the fallback leads by
        // 50,000 points, which is exactly how this defect went unnoticed —
        // `declared_emergency_fallback_is_permitted` disables the pin, so the
        // both-healthy case was never exercised.
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("pin"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid("anthropic:claude")),
            emergency_fallback: vec![tid("local:qwen")],
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));

        assert_eq!(
            chosen(&outcome),
            Some("anthropic:claude"),
            "a healthy pin must be selected before its emergency fallback: {:?}",
            outcome.candidates.iter().map(|c| (c.target.as_str(), c.score())).collect::<Vec<_>>()
        );

        // The fallback stays eligible — it is reachable if the pin fails at
        // dispatch — but it must rank second.
        let order: Vec<&str> = outcome.candidates.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(order, vec!["anthropic:claude", "local:qwen"]);

        // And it must rank second because of pin standing, not because of
        // score, which still favours the fallback.
        let by_score = outcome.candidates.iter().map(Candidate::score).collect::<Vec<_>>();
        assert!(
            by_score.first() < by_score.get(1),
            "the fixture no longer exercises the defect: the pin now outscores \
             the fallback on ordinary terms, so the ordering key is untested"
        );
    }

    #[test]
    fn among_several_emergency_fallbacks_ordinary_scoring_still_applies() {
        // Pin standing separates the pin from its fallbacks; it must not
        // flatten the ordering *within* the fallback set.
        let mut s = snapshot();
        if let Some(t) = s.targets.get_mut(&tid("anthropic:claude")) {
            t.admin_state = AdminState::Disabled;
        }
        s.bindings.push(Binding {
            id: bid("pin"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid("anthropic:claude")),
            emergency_fallback: vec![tid("openai:gpt"), tid("local:qwen")],
            priority: 0,
        });

        let outcome = route(&s, &request("code-premium"));
        let order: Vec<&str> = outcome.candidates.iter().map(|c| c.target.as_str()).collect();
        // local:qwen is local and free; openai:gpt is remote at cost class 4.
        assert_eq!(order, vec!["local:qwen", "openai:gpt"]);
    }

    // -- Eligibility filters ------------------------------------------------

    #[test]
    fn appendix_a_scenario() {
        // Request: alias code-premium, streaming tools, 120k input context, EU
        // residency. Local excluded for 64k context, OpenAI for residency,
        // DeepSeek by sticky deny; Claude is chosen.
        let mut s = snapshot();
        if let Some(t) = s.targets.get_mut(&tid("openai:gpt")) {
            t.residency = Some(Residency::new("us"));
        }
        s.bindings.push(Binding {
            id: bid("user-42"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: vec![
                TargetPreference {
                    selector: TargetSelector::Exact(tid("local:qwen")),
                    rank: 0,
                    weight: 0,
                },
                TargetPreference {
                    selector: TargetSelector::Exact(tid("anthropic:claude")),
                    rank: 1,
                    weight: 0,
                },
                TargetPreference {
                    selector: TargetSelector::Exact(tid("openai:gpt")),
                    rank: 2,
                    weight: 0,
                },
            ],
            denies: vec![TargetSelector::Provider(pid("deepseek"))],
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let mut req = request("code-premium");
        // 120k tokens of input: two bytes per token in the estimator.
        req.messages = vec![Message::text(Role::User, &"x".repeat(240_000))];
        req.limits.residency = Some(Residency::new("eu"));
        req.tools.push(crate::canonical::ToolDef {
            name: "lookup".to_owned(),
            description: None,
            parameters_json: "{}".to_owned(),
            strict: false,
        });

        let outcome = route(&s, &req);
        assert_eq!(chosen(&outcome), Some("anthropic:claude"));
        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::ContextWindowTooSmall)
        );
        assert_eq!(
            excluded_for(&outcome, "openai:gpt"),
            Some(ExclusionReason::ResidencyMismatch)
        );
        assert_eq!(
            excluded_for(&outcome, "deepseek:coder"),
            Some(ExclusionReason::DeniedByPolicy)
        );
    }

    #[test]
    fn capability_filters_exclude_with_specific_reasons() {
        // Each case names the target whose exclusion reason is asserted, so
        // that a case can use a genuinely remote target where that matters.
        let cases: Vec<(
            &str,
            &str,
            Box<dyn Fn(&mut PolicySnapshot, &mut CanonicalRequest)>,
            ExclusionReason,
        )> = vec![
            (
                "streaming",
                "local:qwen",
                Box::new(|s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.stream.enabled = true;
                    if let Some(t) = s.targets.get_mut(&tid("local:qwen")) {
                        t.capabilities.streaming = false;
                    }
                }),
                ExclusionReason::StreamingUnsupported,
            ),
            (
                "tools",
                "local:qwen",
                Box::new(|s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.tools.push(crate::canonical::ToolDef {
                        name: "t".to_owned(),
                        description: None,
                        parameters_json: "{}".to_owned(),
                        strict: false,
                    });
                    if let Some(t) = s.targets.get_mut(&tid("local:qwen")) {
                        t.capabilities.tools = false;
                    }
                }),
                ExclusionReason::ToolsUnsupported,
            ),
            (
                "json mode",
                "local:qwen",
                Box::new(|_s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.response_format = Some(ResponseFormat::JsonObject);
                }),
                ExclusionReason::StructuredOutputUnsupported,
            ),
            (
                "operation",
                "local:qwen",
                Box::new(|_s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.operation = Operation::Embeddings;
                }),
                ExclusionReason::OperationUnsupported,
            ),
            (
                "output limit",
                "local:qwen",
                Box::new(|_s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.limits.max_output_tokens = Some(100_000);
                }),
                ExclusionReason::OutputLimitTooSmall,
            ),
            (
                "cost ceiling",
                "local:qwen",
                Box::new(|s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.limits.max_cost_class = Some(CostClass::new(0));
                    if let Some(t) = s.targets.get_mut(&tid("local:qwen")) {
                        t.cost_class = CostClass::new(5);
                    }
                }),
                ExclusionReason::CostCeilingExceeded,
            ),
            (
                "local required",
                "openai:gpt",
                Box::new(|_s: &mut PolicySnapshot, r: &mut CanonicalRequest| {
                    r.hints.require_local = true;
                }),
                ExclusionReason::LocalRequired,
            ),
        ];

        for (name, subject, mutate, expected) in cases {
            let mut s = snapshot();
            s.bindings.push(Binding {
                id: bid("all"),
                scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
                model: ModelSelector::Any,
                preferences: vec![TargetPreference {
                    selector: TargetSelector::Any,
                    rank: 0,
                    weight: 0,
                }],
                denies: Vec::new(),
                allows: Vec::new(),
                pin: None,
                emergency_fallback: Vec::new(),
                priority: 0,
            });
            let mut req = request("code-premium");
            mutate(&mut s, &mut req);
            let outcome = route(&s, &req);
            assert_eq!(
                excluded_for(&outcome, subject),
                Some(expected),
                "case: {name}"
            );
        }
    }

    #[test]
    fn non_allowlisted_endpoint_is_excluded() {
        let mut s = snapshot();
        s.allowlisted_targets.remove(&tid("local:qwen"));
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        let outcome = route(&s, &request("code-premium"));
        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::EndpointNotAllowlisted)
        );
    }

    // -- Authorization ------------------------------------------------------

    #[test]
    fn authorization_is_default_deny() {
        let mut s = snapshot();
        s.grants.clear();
        let outcome = route(&s, &request("code-premium"));
        assert!(outcome.candidates.is_empty());
        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::NotAuthorizedForAlias)
        );
    }

    #[test]
    fn a_principal_deny_grant_overrides_a_tenant_allow() {
        let mut s = snapshot();
        s.grants.push(AliasGrant {
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            operations: Vec::new(),
            allow: false,
        });
        let outcome = route(&s, &request("code-premium"));
        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::NotAuthorizedForAlias)
        );
    }

    #[test]
    fn grants_are_operation_scoped() {
        let mut s = snapshot();
        s.grants.clear();
        s.grants.push(AliasGrant {
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            operations: vec![Operation::Embeddings],
            allow: true,
        });
        let principal = PrincipalId::new("user:42").unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);

        assert!(!s.authorizes(&c, &aid("code-premium"), Operation::Chat));
        assert!(s.authorizes(&c, &aid("code-premium"), Operation::Embeddings));
    }

    #[test]
    fn visible_aliases_respect_authorization() {
        let mut s = snapshot();
        s.aliases.insert(
            aid("secret-model"),
            Alias {
                id: aid("secret-model"),
                permitted_targets: vec![tid("local:qwen")],
                capability: None,
                allow_family_failover: false,
                description: None,
            },
        );
        s.grants.clear();
        s.grants.push(AliasGrant {
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            operations: Vec::new(),
            allow: true,
        });

        let principal = PrincipalId::new("user:42").unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);

        let visible: Vec<&str> = s
            .visible_aliases(&c, Operation::Chat)
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(visible, vec!["code-premium"]);
        assert!(!visible.contains(&"secret-model"));
    }

    // -- Determinism --------------------------------------------------------

    #[test]
    fn equal_inputs_produce_equal_ordered_candidates() {
        // Appendix B: "Equal request, policy snapshot, and live-state snapshot
        // produce equal ordered candidates."
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        let req = request("code-premium");

        let first = route(&s, &req);
        for _ in 0..64 {
            let again = route(&s, &req);
            assert_eq!(
                first.candidates.iter().map(|c| c.target.as_str()).collect::<Vec<_>>(),
                again.candidates.iter().map(|c| c.target.as_str()).collect::<Vec<_>>()
            );
            assert_eq!(
                first.candidates.iter().map(Candidate::score).collect::<Vec<_>>(),
                again.candidates.iter().map(Candidate::score).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn binding_declaration_order_does_not_affect_the_outcome() {
        let build = |reverse: bool| {
            let mut s = snapshot();
            let mut bindings = vec![
                Binding {
                    id: bid("a"),
                    scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
                    model: ModelSelector::Any,
                    preferences: vec![TargetPreference {
                        selector: TargetSelector::Exact(tid("openai:gpt")),
                        rank: 1,
                        weight: 0,
                    }],
                    denies: Vec::new(),
                    allows: Vec::new(),
                    pin: None,
                    emergency_fallback: Vec::new(),
                    priority: 0,
                },
                Binding {
                    id: bid("b"),
                    scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
                    model: ModelSelector::Exact(aid("code-premium")),
                    preferences: vec![TargetPreference {
                        selector: TargetSelector::Exact(tid("local:qwen")),
                        rank: 0,
                        weight: 0,
                    }],
                    denies: Vec::new(),
                    allows: Vec::new(),
                    pin: None,
                    emergency_fallback: Vec::new(),
                    priority: 0,
                },
            ];
            if reverse {
                bindings.reverse();
            }
            s.bindings = bindings;
            s
        };

        let forward = route(&build(false), &request("code-premium"));
        let backward = route(&build(true), &request("code-premium"));
        assert_eq!(chosen(&forward), chosen(&backward));
        assert_eq!(
            forward.candidates.iter().map(|c| c.target.as_str()).collect::<Vec<_>>(),
            backward.candidates.iter().map(|c| c.target.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn jitter_is_deterministic_in_request_and_target() {
        let a = deterministic_jitter(RequestId::from_u128(1), &tid("x"));
        let b = deterministic_jitter(RequestId::from_u128(1), &tid("x"));
        assert_eq!(a, b, "same inputs must give the same jitter");
        assert!((0..1000).contains(&a));

        let c = deterministic_jitter(RequestId::from_u128(2), &tid("x"));
        let d = deterministic_jitter(RequestId::from_u128(1), &tid("y"));
        // Different seeds should generally differ; assert the distribution is
        // not degenerate rather than that any specific pair differs.
        let values: BTreeSet<i64> = (0..200u128)
            .map(|i| deterministic_jitter(RequestId::from_u128(i), &tid("x")))
            .collect();
        assert!(values.len() > 100, "jitter is not spread: {} distinct", values.len());
        let _ = (c, d);
    }

    #[test]
    fn jitter_is_off_unless_enabled() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        let outcome = route(&s, &request("code-premium"));
        assert!(outcome.candidates.iter().all(|c| c.terms.jitter == 0));

        s.weighted_tie_break = true;
        let outcome = route(&s, &request("code-premium"));
        assert!(outcome.candidates.iter().any(|c| c.terms.jitter != 0));
    }

    #[test]
    fn rank_beats_every_optimization_term_end_to_end() {
        // A rank-0 remote, expensive target must still be selected over a
        // rank-1 local, free one.
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("ranked"),
            scope: BindingScope::Principal(PrincipalId::new("user:42").unwrap()),
            model: ModelSelector::Exact(aid("code-premium")),
            preferences: vec![
                TargetPreference {
                    selector: TargetSelector::Exact(tid("anthropic:claude")),
                    rank: 0,
                    weight: 0,
                },
                TargetPreference {
                    selector: TargetSelector::Exact(tid("local:qwen")),
                    rank: 1,
                    weight: ScoreTerms::POLICY_WEIGHT_RANGE.1,
                },
            ],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });
        let outcome = route(&s, &request("code-premium"));
        assert_eq!(chosen(&outcome), Some("anthropic:claude"));
    }

    #[test]
    fn attempted_targets_are_excluded_from_retry() {
        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let req = request("code-premium");
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted = vec![tid("local:qwen")];
        let c = ctx(&principal, &groups, &tenant, &attempted);
        let outcome = s.route(&c, &req, &IdealLiveState);

        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::AlreadyAttempted)
        );
        assert!(outcome.candidates.iter().all(|x| x.target.as_str() != "local:qwen"));
    }

    #[test]
    fn unknown_alias_yields_no_candidates() {
        let s = snapshot();
        let outcome = route(&s, &request("does-not-exist"));
        assert!(outcome.candidates.is_empty());
        assert!(outcome.exclusions.is_empty());
    }

    #[test]
    fn live_state_penalties_order_equal_ranks() {
        #[derive(Debug)]
        struct SlowLocal;
        impl LiveState for SlowLocal {
            fn circuit_open(&self, _t: &TargetId) -> bool {
                false
            }
            fn health_penalty(&self, t: &TargetId) -> i64 {
                if t.as_str() == "local:qwen" { -40_000 } else { 0 }
            }
            fn latency_penalty(&self, _t: &TargetId) -> i64 {
                0
            }
            fn queue_penalty(&self, _t: &TargetId) -> i64 {
                0
            }
            fn affinity_bonus(&self, _t: &TargetId) -> i64 {
                0
            }
            fn has_capacity(&self, _t: &TargetId) -> bool {
                true
            }
        }

        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let req = request("code-premium");
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);

        // Healthy: local wins on the locality and cost bonuses.
        let healthy = s.route(&c, &req, &IdealLiveState);
        assert_eq!(chosen(&healthy), Some("local:qwen"));

        // Unhealthy: the penalty is enough to demote it, but only because the
        // ranks are equal.
        let degraded = s.route(&c, &req, &SlowLocal);
        assert_ne!(chosen(&degraded), Some("local:qwen"));
    }

    #[test]
    fn circuit_open_and_no_capacity_are_filters_not_penalties() {
        #[derive(Debug)]
        struct Broken;
        impl LiveState for Broken {
            fn circuit_open(&self, t: &TargetId) -> bool {
                t.as_str() == "local:qwen"
            }
            fn health_penalty(&self, _t: &TargetId) -> i64 {
                0
            }
            fn latency_penalty(&self, _t: &TargetId) -> i64 {
                0
            }
            fn queue_penalty(&self, _t: &TargetId) -> i64 {
                0
            }
            fn affinity_bonus(&self, _t: &TargetId) -> i64 {
                0
            }
            fn has_capacity(&self, t: &TargetId) -> bool {
                t.as_str() != "openai:gpt"
            }
        }

        let mut s = snapshot();
        s.bindings.push(Binding {
            id: bid("all"),
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let req = request("code-premium");
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let c = ctx(&principal, &groups, &tenant, &attempted);
        let outcome = s.route(&c, &req, &Broken);

        assert_eq!(
            excluded_for(&outcome, "local:qwen"),
            Some(ExclusionReason::CircuitOpen)
        );
        assert_eq!(
            excluded_for(&outcome, "openai:gpt"),
            Some(ExclusionReason::CapacityExhausted)
        );
    }

    #[test]
    fn selector_matching() {
        let t = target("openai:gpt", "openai", false, 1000, 1);
        assert!(TargetSelector::Exact(tid("openai:gpt")).matches(&t));
        assert!(!TargetSelector::Exact(tid("openai:other")).matches(&t));
        assert!(TargetSelector::Provider(pid("openai")).matches(&t));
        assert!(!TargetSelector::Provider(pid("anthropic")).matches(&t));
        assert!(TargetSelector::Any.matches(&t));

        assert!(ModelSelector::Exact(aid("a")).matches(&aid("a")));
        assert!(!ModelSelector::Exact(aid("a")).matches(&aid("ab")));
        assert!(ModelSelector::Prefix("code-".to_owned()).matches(&aid("code-fast")));
        assert!(!ModelSelector::Prefix("code-".to_owned()).matches(&aid("chat-fast")));
        assert!(ModelSelector::Any.matches(&aid("anything")));
        assert!(ModelSelector::Exact(aid("a")).is_exact());
        assert!(!ModelSelector::Prefix("a".to_owned()).is_exact());
    }
}
