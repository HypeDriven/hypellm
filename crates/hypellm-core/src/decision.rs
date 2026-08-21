//! Decision traces: candidates, exclusions, scores, and the chosen target.
//!
//! Specification 2.1: "Make every routing outcome reconstructable from
//! versioned policy, health snapshots, and a redacted decision trace."
//! Specification 17 requires the trace to carry "policy digest, candidates,
//! exclusion reason codes, integer score terms, reservations, attempts" — and
//! nothing else. There is no prompt, no credential, and no upstream URL in any
//! type here.

use crate::ids::{RequestId, TargetId};
use hypellm_crypto::Digest;
use core::fmt;

/// Why a target was excluded from consideration.
///
/// Every filter in specification 6.2 has a code. Operators read these in the
/// decision explorer to answer "why did this not go where I expected", so the
/// set is deliberately fine-grained: "not eligible" is not an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExclusionReason {
    /// The principal is not authorized for the requested alias.
    NotAuthorizedForAlias,
    /// The target does not serve the requested operation.
    OperationUnsupported,
    /// The alias does not permit this target.
    NotPermittedForAlias,
    /// The provider is disabled.
    ProviderDisabled,
    /// The target is disabled.
    TargetDisabled,
    /// The target is draining.
    TargetDraining,
    /// The target is in a maintenance window.
    TargetMaintenance,
    /// The target is quarantined by an operator.
    TargetQuarantined,
    /// The target's circuit breaker is open.
    CircuitOpen,
    /// The target is too unhealthy for the request's failure policy.
    Unhealthy,
    /// The target does not accept a required input modality.
    ModalityUnsupported,
    /// The target does not support tool calling.
    ToolsUnsupported,
    /// The target does not support the requested response format.
    StructuredOutputUnsupported,
    /// The target does not support streaming.
    StreamingUnsupported,
    /// The request's input exceeds the target's context window.
    ContextWindowTooSmall,
    /// The requested output length exceeds the target's limit.
    OutputLimitTooSmall,
    /// The target's data region does not satisfy the residency requirement.
    ResidencyMismatch,
    /// The provider endpoint is not on the static destination allowlist.
    EndpointNotAllowlisted,
    /// The credential's scope does not cover this tenant or target.
    CredentialScopeMismatch,
    /// The target's cost class exceeds the request's ceiling.
    CostCeilingExceeded,
    /// A hierarchical budget or quota would be exceeded.
    BudgetExceeded,
    /// Concurrency or queue capacity is exhausted.
    CapacityExhausted,
    /// A higher-precedence binding denies this target.
    DeniedByPolicy,
    /// A hard pin selected a different target.
    NotPinnedTarget,
    /// The request required local inference and this target is remote.
    LocalRequired,
    /// Selecting this target would change model family without permission.
    FamilyFailoverNotAllowed,
    /// The target was already attempted in this request's retry chain.
    AlreadyAttempted,
    /// No preference or default made this target reachable.
    NotSelectedByAnyBinding,

    // -- Capability contract, independent of the fleet --------------------
    /// The target does not declare the alias's capability verb.
    CapabilityUnsupported,
    /// The target does not support the requested reasoning tier.
    ReasoningEffortUnsupported,
    /// The target's quality class is below the request's floor.
    QualityFloorNotMet,

    // -- Fleet -------------------------------------------------------------
    /// Effort-adjusted time-to-ready exceeds what remains of the deadline.
    ActivationExceedsDeadline,
    /// The host's activation budget for this period is exhausted.
    ActivationBudgetExhausted,
    /// The principal may not cause activation, or the deployment is not
    /// `autostart`.
    ActivationNotPermitted,
    /// The artifact is absent and acquisition is not permitted, budgeted, or
    /// feasible.
    ArtifactUnavailable,
    /// No admissible eviction set frees enough memory on the host.
    HostCapacityInsufficient,
    /// Fleet belief is older than `observation_max_age_ms`.
    FleetStateStale,
    /// The fleet agent socket is unreachable.
    FleetAgentUnavailable,
    /// Router and agent disagree about the fleet configuration digest.
    FleetConfigurationMismatch,
    /// Serving would require evicting a deployment inside its dwell window.
    DeploymentInDwell,
    /// An admissible eviction set exists, but incoming demand does not exceed
    /// its retention value by the configured margin.
    EvictionValueInsufficient,
}

impl ExclusionReason {
    /// Stable code for traces, metrics, and the decision explorer.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotAuthorizedForAlias => "not_authorized_for_alias",
            Self::OperationUnsupported => "operation_unsupported",
            Self::NotPermittedForAlias => "not_permitted_for_alias",
            Self::ProviderDisabled => "provider_disabled",
            Self::TargetDisabled => "target_disabled",
            Self::TargetDraining => "target_draining",
            Self::TargetMaintenance => "target_maintenance",
            Self::TargetQuarantined => "target_quarantined",
            Self::CircuitOpen => "circuit_open",
            Self::Unhealthy => "unhealthy",
            Self::ModalityUnsupported => "modality_unsupported",
            Self::ToolsUnsupported => "tools_unsupported",
            Self::StructuredOutputUnsupported => "structured_output_unsupported",
            Self::StreamingUnsupported => "streaming_unsupported",
            Self::ContextWindowTooSmall => "context_window_too_small",
            Self::OutputLimitTooSmall => "output_limit_too_small",
            Self::ResidencyMismatch => "residency_mismatch",
            Self::EndpointNotAllowlisted => "endpoint_not_allowlisted",
            Self::CredentialScopeMismatch => "credential_scope_mismatch",
            Self::CostCeilingExceeded => "cost_ceiling_exceeded",
            Self::BudgetExceeded => "budget_exceeded",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::DeniedByPolicy => "denied_by_policy",
            Self::NotPinnedTarget => "not_pinned_target",
            Self::LocalRequired => "local_required",
            Self::FamilyFailoverNotAllowed => "family_failover_not_allowed",
            Self::AlreadyAttempted => "already_attempted",
            Self::NotSelectedByAnyBinding => "not_selected_by_any_binding",
            Self::CapabilityUnsupported => "capability_unsupported",
            Self::ReasoningEffortUnsupported => "reasoning_effort_unsupported",
            Self::QualityFloorNotMet => "quality_floor_not_met",
            Self::ActivationExceedsDeadline => "activation_exceeds_deadline",
            Self::ActivationBudgetExhausted => "activation_budget_exhausted",
            Self::ActivationNotPermitted => "activation_not_permitted",
            Self::ArtifactUnavailable => "artifact_unavailable",
            Self::HostCapacityInsufficient => "host_capacity_insufficient",
            Self::FleetStateStale => "fleet_state_stale",
            Self::FleetAgentUnavailable => "fleet_agent_unavailable",
            Self::FleetConfigurationMismatch => "fleet_configuration_mismatch",
            Self::DeploymentInDwell => "deployment_in_dwell",
            Self::EvictionValueInsufficient => "eviction_value_insufficient",
        }
    }

    /// Whether this exclusion is a fleet-orchestration outcome.
    ///
    /// Data-plane errors derived from these must say "capability unavailable"
    /// and never name a host, an accelerator, or what else is loaded:
    /// specification 10 makes fleet topology management-plane data, and an
    /// unauthenticated caller learning which models are resident is a
    /// cross-tenant disclosure by another name.
    #[must_use]
    pub const fn is_fleet_constraint(self) -> bool {
        matches!(
            self,
            Self::ActivationExceedsDeadline
                | Self::ActivationBudgetExhausted
                | Self::ActivationNotPermitted
                | Self::ArtifactUnavailable
                | Self::HostCapacityInsufficient
                | Self::FleetStateStale
                | Self::FleetAgentUnavailable
                | Self::FleetConfigurationMismatch
                | Self::DeploymentInDwell
                | Self::EvictionValueInsufficient
        )
    }

    /// Whether this exclusion is a security or compliance decision.
    ///
    /// Specification 6.3: "Security constraints never appear as score
    /// penalties — they are eligibility filters." This predicate exists so
    /// tests can assert that no security reason is ever downgraded to a score
    /// adjustment.
    #[must_use]
    pub const fn is_security_constraint(self) -> bool {
        matches!(
            self,
            Self::NotAuthorizedForAlias
                | Self::DeniedByPolicy
                | Self::ResidencyMismatch
                | Self::EndpointNotAllowlisted
                | Self::CredentialScopeMismatch
                | Self::TargetQuarantined
                | Self::FamilyFailoverNotAllowed
                | Self::LocalRequired
                // An activation the principal may not cause is an
                // authorization decision, not a capacity one. It has to be a
                // filter for the same reason every other one is: a permission
                // expressed as a penalty is a permission that a cheap enough
                // target overcomes.
                | Self::ActivationNotPermitted
        )
    }

    /// Every reason, for exhaustiveness tests and documentation.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::NotAuthorizedForAlias,
            Self::OperationUnsupported,
            Self::NotPermittedForAlias,
            Self::ProviderDisabled,
            Self::TargetDisabled,
            Self::TargetDraining,
            Self::TargetMaintenance,
            Self::TargetQuarantined,
            Self::CircuitOpen,
            Self::Unhealthy,
            Self::ModalityUnsupported,
            Self::ToolsUnsupported,
            Self::StructuredOutputUnsupported,
            Self::StreamingUnsupported,
            Self::ContextWindowTooSmall,
            Self::OutputLimitTooSmall,
            Self::ResidencyMismatch,
            Self::EndpointNotAllowlisted,
            Self::CredentialScopeMismatch,
            Self::CostCeilingExceeded,
            Self::BudgetExceeded,
            Self::CapacityExhausted,
            Self::DeniedByPolicy,
            Self::NotPinnedTarget,
            Self::LocalRequired,
            Self::FamilyFailoverNotAllowed,
            Self::AlreadyAttempted,
            Self::NotSelectedByAnyBinding,
            Self::CapabilityUnsupported,
            Self::ReasoningEffortUnsupported,
            Self::QualityFloorNotMet,
            Self::ActivationExceedsDeadline,
            Self::ActivationBudgetExhausted,
            Self::ActivationNotPermitted,
            Self::ArtifactUnavailable,
            Self::HostCapacityInsufficient,
            Self::FleetStateStale,
            Self::FleetAgentUnavailable,
            Self::FleetConfigurationMismatch,
            Self::DeploymentInDwell,
            Self::EvictionValueInsufficient,
        ]
    }
}

impl fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Where a target stands in relation to the fleet.
///
/// Exactly one class per target per decision, sampled once from an immutable
/// snapshot and never re-read mid-scoring, so that equal (request, policy
/// snapshot, live state) still produce equal ordered candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResidencyClass {
    /// The target has no deployment record. The fleet has nothing to say.
    #[default]
    Unmanaged,
    /// Ready to serve now, and idle.
    Resident,
    /// Ready to serve now, and already carrying work.
    ///
    /// One rung below [`ResidencyClass::Resident`] so that, given two warm
    /// copies of a model, the idle one is preferred. The queue penalty
    /// expresses the same observation with more precision; this rung exists so
    /// that the ladder's spacing is uniform, which is what the hint-cannot-beat-
    /// warmth property depends on.
    ResidentBusy,
    /// Coming up under an existing lease; the ETA is known.
    Activating,
    /// Not resident, and free pool memory suffices.
    ColdFits,
    /// Not resident, and starting it requires stopping a computed set.
    ColdRequiresEviction,
    /// Not resident, and its artifact is absent from the host.
    ColdRequiresFetch,
    /// Cannot be made ready, for the stated reason.
    Infeasible(ExclusionReason),
}

impl ResidencyClass {
    /// Stable token for traces and the decision explorer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unmanaged => "unmanaged",
            Self::Resident => "resident",
            Self::ResidentBusy => "resident_busy",
            Self::Activating => "activating",
            Self::ColdFits => "cold_fits",
            Self::ColdRequiresEviction => "cold_requires_eviction",
            Self::ColdRequiresFetch => "cold_requires_fetch",
            Self::Infeasible(_) => "infeasible",
        }
    }

    /// The reason this class excludes the target, if it does.
    #[must_use]
    pub const fn exclusion(self) -> Option<ExclusionReason> {
        match self {
            Self::Infeasible(reason) => Some(reason),
            _ => None,
        }
    }

    /// Whether serving this target requires starting something first.
    #[must_use]
    pub const fn requires_activation(self) -> bool {
        matches!(
            self,
            Self::ColdFits | Self::ColdRequiresEviction | Self::ColdRequiresFetch
        )
    }

    /// The warmness contribution to `affinity_term`.
    ///
    /// A ladder whose adjacent gap is [`ScoreTerms::WARMTH_LADDER_STEP`],
    /// spaced so that no permitted client hint can move a target between
    /// rungs (specification-extension 7.2). `Unmanaged` sits at the top with
    /// `Resident`: a target with no deployment record is running because an
    /// operator runs it, and demoting it below an orchestrated one would make
    /// adding a deployment record to a neighbour change where unrelated
    /// traffic goes.
    #[must_use]
    pub const fn warmth_bonus(self) -> i64 {
        let rung = match self {
            Self::Unmanaged | Self::Resident => 5,
            Self::ResidentBusy => 4,
            Self::Activating => 3,
            Self::ColdFits => 2,
            Self::ColdRequiresEviction => 1,
            Self::ColdRequiresFetch | Self::Infeasible(_) => 0,
        };
        ScoreTerms::WARMTH_LADDER_STEP.saturating_mul(rung)
    }

    /// The classes that make a target a candidate, coldest last.
    ///
    /// Ordered, so a test can walk adjacent pairs and assert the ladder's
    /// spacing rather than restating the constants it is checking.
    #[must_use]
    pub const fn all_ready_classes() -> &'static [Self] {
        &[
            Self::Resident,
            Self::ResidentBusy,
            Self::Activating,
            Self::ColdFits,
            Self::ColdRequiresEviction,
            Self::ColdRequiresFetch,
        ]
    }
}


/// The integer score terms of specification 6.3.
///
/// All arithmetic is integer fixed-point with saturation. Floating point would
/// make the ordering of two equally-ranked targets depend on accumulated
/// rounding, and specification 6 requires that equal inputs produce equal
/// ordered candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScoreTerms {
    /// User/model ordered preference. Dominates every other term.
    pub priority_rank: i64,
    /// Administrator weight from the winning binding.
    pub policy_weight: i64,
    /// Penalty for elevated error rate, recent timeouts, half-open circuits.
    pub health: i64,
    /// Penalty derived from observed latency.
    pub latency: i64,
    /// Penalty derived from reserved concurrency and predicted wait.
    pub queue: i64,
    /// Penalty derived from the configured cost class.
    pub cost: i64,
    /// Bonus for local inference.
    pub locality: i64,
    /// Bonus for cache or conversation affinity.
    pub affinity: i64,
    /// Small request-id-derived value for weighted distribution.
    pub jitter: i64,
}

impl ScoreTerms {
    /// One rank step. Chosen so that a better rank beats any combination of the
    /// other terms: see [`ScoreTerms::MAX_NON_RANK_MAGNITUDE`].
    pub const RANK_UNIT: i64 = 1_000_000;

    /// The highest rank index a preference list may use.
    pub const MAX_RANK: i64 = 64;

    /// Bounds on each non-rank term, as (minimum, maximum).
    pub const POLICY_WEIGHT_RANGE: (i64, i64) = (-100_000, 100_000);
    /// Health penalty range.
    pub const HEALTH_RANGE: (i64, i64) = (-50_000, 0);
    /// Latency penalty range.
    pub const LATENCY_RANGE: (i64, i64) = (-50_000, 0);
    /// Queue penalty range.
    pub const QUEUE_RANGE: (i64, i64) = (-50_000, 0);
    /// Cost penalty range.
    pub const COST_RANGE: (i64, i64) = (-50_000, 0);
    /// Locality bonus range.
    pub const LOCALITY_RANGE: (i64, i64) = (0, 50_000);
    /// Affinity bonus range.
    pub const AFFINITY_RANGE: (i64, i64) = (0, 50_000);

    // The affinity term has more than one contributor, so its range is
    // **split** into disjoint slices rather than contended for. Specification
    // 6.3 defines the term as "short-lived cache/model warmness or conversation
    // affinity", which is exactly what fleet warmness needs — so no new score
    // term is introduced and the proven rank-dominance bound is untouched.
    //
    // The slices sum to the term's range, and there is a test.

    /// The slice of `affinity` that model warmness may occupy.
    pub const WARMTH_SLICE: i64 = 40_000;
    /// The slice a permitted client hint may occupy.
    pub const HINT_SLICE: i64 = 6_000;
    /// The slice reserved for conversation affinity. Not implemented.
    pub const CONVERSATION_SLICE: i64 = 4_000;

    /// The gap between adjacent rungs of the warmth ladder.
    ///
    /// Chosen to exceed [`ScoreTerms::HINT_SLICE`], which is what makes "a
    /// client hint can break a tie between equally-warm targets but can never
    /// promote a colder one over a warmer one" arithmetic rather than
    /// aspiration. A property test asserts the relationship, because changing
    /// either number in isolation silently converts a preference into a
    /// destination control.
    pub const WARMTH_LADDER_STEP: i64 = 8_000;
    /// Jitter range.
    pub const JITTER_RANGE: (i64, i64) = (0, 999);

    /// The largest magnitude the non-rank terms can sum to.
    ///
    /// Must stay strictly below [`ScoreTerms::RANK_UNIT`] so that rank ordering
    /// is never overturned by optimization terms. There is a test.
    pub const MAX_NON_RANK_MAGNITUDE: i64 = 100_000 + 50_000 * 6 + 999;

    /// Build the rank term from a preference rank, clamped into range.
    #[must_use]
    pub const fn rank_term(rank: u16) -> i64 {
        // Widening a `u16` into an `i64` is lossless — every `u16` value is
        // representable, so no truncation or sign change is possible. The
        // checked form (`i64::from`/`i64::try_from`) is not callable here
        // because `From` is not yet const-stable, and this must stay `const`.
        #[allow(clippy::as_conversions)]
        let r = rank as i64;
        let r = if r > Self::MAX_RANK { Self::MAX_RANK } else { r };
        (Self::MAX_RANK - r) * Self::RANK_UNIT
    }

    /// The total score. Higher is better.
    #[must_use]
    pub const fn total(&self) -> i64 {
        self.priority_rank
            .saturating_add(self.policy_weight)
            .saturating_add(self.health)
            .saturating_add(self.latency)
            .saturating_add(self.queue)
            .saturating_add(self.cost)
            .saturating_add(self.locality)
            .saturating_add(self.affinity)
            .saturating_add(self.jitter)
    }

    /// Sum of everything except the rank term.
    #[must_use]
    pub const fn non_rank_total(&self) -> i64 {
        self.total().saturating_sub(self.priority_rank)
    }

    /// Clamp every term into its documented range.
    ///
    /// Applied before scoring so that a misconfigured weight cannot invert the
    /// precedence order.
    #[must_use]
    pub fn clamped(mut self) -> Self {
        fn clamp(v: i64, range: (i64, i64)) -> i64 {
            v.clamp(range.0, range.1)
        }
        self.policy_weight = clamp(self.policy_weight, Self::POLICY_WEIGHT_RANGE);
        self.health = clamp(self.health, Self::HEALTH_RANGE);
        self.latency = clamp(self.latency, Self::LATENCY_RANGE);
        self.queue = clamp(self.queue, Self::QUEUE_RANGE);
        self.cost = clamp(self.cost, Self::COST_RANGE);
        self.locality = clamp(self.locality, Self::LOCALITY_RANGE);
        self.affinity = clamp(self.affinity, Self::AFFINITY_RANGE);
        self.jitter = clamp(self.jitter, Self::JITTER_RANGE);
        self.priority_rank = self.priority_rank.clamp(0, Self::MAX_RANK * Self::RANK_UNIT);
        self
    }
}

/// A target that survived eligibility filtering, with its score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The target.
    pub target: TargetId,
    /// Its score terms.
    pub terms: ScoreTerms,
    /// The precedence level of the binding that placed it.
    pub binding_precedence: u8,
    /// Its preference rank within that binding.
    pub rank: u16,
    /// Standing relative to an active hard pin: [`Candidate::PIN_TARGET`] for
    /// the pinned target, [`Candidate::PIN_FALLBACK`] for a target the pinning
    /// binding named as emergency fallback, and [`Candidate::PIN_TARGET`] for
    /// every candidate when no pin is active.
    ///
    /// This is an ordering key, not a score term. Specification 6.1 says a hard
    /// pin "selects only the pinned target and fails closed if unavailable
    /// unless the same binding defines an allowed emergency fallback" — the
    /// fallback is reached only when the pin cannot be, which is a structural
    /// relationship. Expressing it as a score bonus would make it a penalty on
    /// the fallback, and specification 6.3 reserves scoring for ordinary
    /// optimization terms: an emergency fallback that happened to be local and
    /// cheap would still outrank the pin once the bonus was outweighed.
    pub pin_rank: u8,
    /// Where the fleet stood in relation to this target at decision time.
    ///
    /// Carried on the candidate rather than recomputed, for two reasons. The
    /// dispatcher has to know whether the target it picked needs starting
    /// before it can be used, and re-asking would consult a snapshot that may
    /// have moved. And an operator reading the decision explorer needs to see
    /// *why* a colder target was passed over, which is not reconstructable
    /// from the affinity total alone.
    pub residency: ResidencyClass,
}

impl Candidate {
    /// The pinned target, or any candidate when no pin is active.
    pub const PIN_TARGET: u8 = 0;
    /// A target named as emergency fallback by the pinning binding.
    pub const PIN_FALLBACK: u8 = 1;

    /// Total score.
    #[must_use]
    pub const fn score(&self) -> i64 {
        self.terms.total()
    }

    /// The total ordering key: pin standing first, then score, then target id.
    ///
    /// Appendix B requires that equal request, policy snapshot, and live state
    /// produce equal ordered candidates, so the key must be total and must not
    /// depend on input order.
    #[must_use]
    pub fn ordering_key(&self) -> (u8, core::cmp::Reverse<i64>, &TargetId) {
        (self.pin_rank, core::cmp::Reverse(self.score()), &self.target)
    }
}

/// A target that was excluded, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    /// The target.
    pub target: TargetId,
    /// Why it was excluded.
    pub reason: ExclusionReason,
}

/// One attempt against a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The target tried.
    pub target: TargetId,
    /// Attempt ordinal, starting at zero.
    pub sequence: u16,
    /// Milliseconds from decision to first byte, when one arrived.
    pub first_byte_millis: Option<u64>,
    /// Milliseconds the whole attempt took.
    pub total_millis: u64,
    /// The outcome.
    pub outcome: AttemptOutcome,
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Completed successfully.
    Success,
    /// Failed before the upstream accepted the request. Failover is unrestricted.
    FailedBeforeAcceptance(crate::event::UpstreamErrorClass),
    /// Failed after acceptance but before any response bytes.
    ///
    /// Specification 6.5 permits failover only for an idempotent request or one
    /// carrying a provider-supported idempotency key.
    FailedAfterAcceptance(crate::event::UpstreamErrorClass),
    /// Failed after semantic output reached the client. Failover is forbidden.
    FailedAfterOutput(crate::event::UpstreamErrorClass),
    /// Cancelled by the client.
    Cancelled,
    /// Abandoned because the deadline expired.
    DeadlineExceeded,
}

impl AttemptOutcome {
    /// Stable name for traces.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::FailedBeforeAcceptance(_) => "failed_before_acceptance",
            Self::FailedAfterAcceptance(_) => "failed_after_acceptance",
            Self::FailedAfterOutput(_) => "failed_after_output",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }

    /// The upstream error class, when there was one.
    #[must_use]
    pub const fn error_class(self) -> Option<crate::event::UpstreamErrorClass> {
        match self {
            Self::FailedBeforeAcceptance(c)
            | Self::FailedAfterAcceptance(c)
            | Self::FailedAfterOutput(c) => Some(c),
            Self::Success | Self::Cancelled | Self::DeadlineExceeded => None,
        }
    }
}

/// A complete, redacted record of how a request was routed.
#[derive(Debug, Clone)]
pub struct DecisionTrace {
    /// The request.
    pub request_id: RequestId,
    /// The digest of the policy snapshot in force.
    pub policy_digest: Digest,
    /// Ranked candidates, best first.
    pub candidates: Vec<Candidate>,
    /// Targets that were filtered out, with reasons.
    pub exclusions: Vec<Exclusion>,
    /// The target finally chosen, if any.
    pub chosen: Option<TargetId>,
    /// The chain of attempts.
    pub attempts: Vec<Attempt>,
    /// Microseconds spent in routing itself, excluding upstream time.
    ///
    /// Microseconds, not milliseconds: specification 19 puts the whole router
    /// overhead budget at 2 ms (p50), so a millisecond-resolution value would
    /// be almost entirely quantisation. Read from
    /// [`crate::time::Clock::now_micros`].
    pub routing_micros: u64,
    /// Whether the selection was forced by a hard pin.
    pub pinned: bool,
}

impl DecisionTrace {
    /// A short, human-readable explanation of the outcome.
    ///
    /// Contains only identifiers, reason codes, and integers. Safe to return
    /// through the management API to a caller authorized for the tenant.
    #[must_use]
    pub fn explain(&self) -> String {
        let mut s = String::new();
        s.push_str("policy ");
        s.push_str(&self.policy_digest.short());
        s.push_str("; candidates=");
        s.push_str(&self.candidates.len().to_string());
        s.push_str("; excluded=");
        s.push_str(&self.exclusions.len().to_string());
        if self.pinned {
            s.push_str("; pinned");
        }
        match &self.chosen {
            Some(t) => {
                s.push_str("; chosen=");
                s.push_str(t.as_str());
            }
            None => s.push_str("; chosen=none"),
        }
        if !self.attempts.is_empty() {
            s.push_str("; attempts=");
            s.push_str(&self.attempts.len().to_string());
        }
        s
    }

    /// Count of exclusions by reason, for the decision explorer.
    #[must_use]
    pub fn exclusion_summary(&self) -> Vec<(ExclusionReason, usize)> {
        let mut reasons: Vec<ExclusionReason> =
            self.exclusions.iter().map(|e| e.reason).collect();
        reasons.sort_unstable();
        let mut out: Vec<(ExclusionReason, usize)> = Vec::new();
        for r in reasons {
            match out.last_mut() {
                Some((last, count)) if *last == r => *count += 1,
                _ => out.push((r, 1)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_codes_are_distinct() {
        let mut codes: Vec<&str> = ExclusionReason::all().iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);
    }

    #[test]
    fn security_constraints_are_marked() {
        for r in [
            ExclusionReason::NotAuthorizedForAlias,
            ExclusionReason::DeniedByPolicy,
            ExclusionReason::ResidencyMismatch,
            ExclusionReason::EndpointNotAllowlisted,
            ExclusionReason::CredentialScopeMismatch,
            ExclusionReason::TargetQuarantined,
        ] {
            assert!(r.is_security_constraint(), "{r} should be a security filter");
        }
        // Optimization-adjacent reasons are not security constraints, but they
        // are still filters — none of them is expressible as a score penalty.
        for r in [
            ExclusionReason::Unhealthy,
            ExclusionReason::CapacityExhausted,
            ExclusionReason::CostCeilingExceeded,
        ] {
            assert!(!r.is_security_constraint());
        }
    }

    #[test]
    fn rank_zero_dominates_every_other_term() {
        // The central invariant of specification 6.3: "rank 0 dominates all
        // ordinary optimization terms". A rank-0 target with the worst possible
        // score on every other axis must still beat a rank-1 target with the
        // best possible score on every axis.
        let best_rank_worst_everything = ScoreTerms {
            priority_rank: ScoreTerms::rank_term(0),
            policy_weight: ScoreTerms::POLICY_WEIGHT_RANGE.0,
            health: ScoreTerms::HEALTH_RANGE.0,
            latency: ScoreTerms::LATENCY_RANGE.0,
            queue: ScoreTerms::QUEUE_RANGE.0,
            cost: ScoreTerms::COST_RANGE.0,
            locality: ScoreTerms::LOCALITY_RANGE.0,
            affinity: ScoreTerms::AFFINITY_RANGE.0,
            jitter: ScoreTerms::JITTER_RANGE.0,
        };
        let worse_rank_best_everything = ScoreTerms {
            priority_rank: ScoreTerms::rank_term(1),
            policy_weight: ScoreTerms::POLICY_WEIGHT_RANGE.1,
            health: ScoreTerms::HEALTH_RANGE.1,
            latency: ScoreTerms::LATENCY_RANGE.1,
            queue: ScoreTerms::QUEUE_RANGE.1,
            cost: ScoreTerms::COST_RANGE.1,
            locality: ScoreTerms::LOCALITY_RANGE.1,
            affinity: ScoreTerms::AFFINITY_RANGE.1,
            jitter: ScoreTerms::JITTER_RANGE.1,
        };
        assert!(
            best_rank_worst_everything.total() > worse_rank_best_everything.total(),
            "{} !> {}",
            best_rank_worst_everything.total(),
            worse_rank_best_everything.total()
        );
    }

    #[test]
    fn non_rank_terms_cannot_span_a_rank_step() {
        // The structural reason the invariant above holds.
        let span = ScoreTerms::POLICY_WEIGHT_RANGE.1 - ScoreTerms::POLICY_WEIGHT_RANGE.0
            + (ScoreTerms::HEALTH_RANGE.1 - ScoreTerms::HEALTH_RANGE.0)
            + (ScoreTerms::LATENCY_RANGE.1 - ScoreTerms::LATENCY_RANGE.0)
            + (ScoreTerms::QUEUE_RANGE.1 - ScoreTerms::QUEUE_RANGE.0)
            + (ScoreTerms::COST_RANGE.1 - ScoreTerms::COST_RANGE.0)
            + (ScoreTerms::LOCALITY_RANGE.1 - ScoreTerms::LOCALITY_RANGE.0)
            + (ScoreTerms::AFFINITY_RANGE.1 - ScoreTerms::AFFINITY_RANGE.0)
            + (ScoreTerms::JITTER_RANGE.1 - ScoreTerms::JITTER_RANGE.0);
        assert!(
            span < ScoreTerms::RANK_UNIT,
            "non-rank terms span {span}, which is not below the rank unit {}",
            ScoreTerms::RANK_UNIT
        );
    }

    #[test]
    fn rank_ordering_is_monotonic() {
        let mut last = i64::MAX;
        for rank in 0..=64u16 {
            let t = ScoreTerms::rank_term(rank);
            assert!(t < last, "rank {rank} did not decrease the term");
            last = t;
        }
        // Out-of-range ranks clamp rather than wrapping negative.
        assert_eq!(ScoreTerms::rank_term(1000), ScoreTerms::rank_term(64));
        assert_eq!(ScoreTerms::rank_term(64), 0);
    }

    #[test]
    fn score_arithmetic_saturates() {
        let extreme = ScoreTerms {
            priority_rank: i64::MAX,
            policy_weight: i64::MAX,
            health: i64::MAX,
            latency: i64::MAX,
            queue: i64::MAX,
            cost: i64::MAX,
            locality: i64::MAX,
            affinity: i64::MAX,
            jitter: i64::MAX,
        };
        // Must not panic under overflow checks, and must not wrap negative.
        assert_eq!(extreme.total(), i64::MAX);

        let negative = ScoreTerms {
            priority_rank: i64::MIN,
            policy_weight: i64::MIN,
            ..ScoreTerms::default()
        };
        assert_eq!(negative.total(), i64::MIN);
    }

    #[test]
    fn clamping_restores_documented_ranges() {
        let wild = ScoreTerms {
            priority_rank: i64::MAX,
            policy_weight: 999_999_999,
            health: 999_999,
            latency: -999_999_999,
            queue: 5,
            cost: 5,
            locality: -5,
            affinity: 999_999,
            jitter: 100_000,
        };
        let c = wild.clamped();
        assert_eq!(c.policy_weight, ScoreTerms::POLICY_WEIGHT_RANGE.1);
        assert_eq!(c.health, ScoreTerms::HEALTH_RANGE.1);
        assert_eq!(c.latency, ScoreTerms::LATENCY_RANGE.0);
        assert_eq!(c.queue, 0);
        assert_eq!(c.locality, 0);
        assert_eq!(c.affinity, ScoreTerms::AFFINITY_RANGE.1);
        assert_eq!(c.jitter, ScoreTerms::JITTER_RANGE.1);
        assert_eq!(c.priority_rank, ScoreTerms::MAX_RANK * ScoreTerms::RANK_UNIT);
        // A clamped set can never overturn a rank step.
        assert!(c.non_rank_total().abs() < ScoreTerms::RANK_UNIT);
    }

    #[test]
    fn attempt_outcomes_carry_their_error_class() {
        use crate::event::UpstreamErrorClass;
        let o = AttemptOutcome::FailedBeforeAcceptance(UpstreamErrorClass::Timeout);
        assert_eq!(o.error_class(), Some(UpstreamErrorClass::Timeout));
        assert_eq!(o.code(), "failed_before_acceptance");
        assert_eq!(AttemptOutcome::Success.error_class(), None);
        assert_eq!(AttemptOutcome::Cancelled.code(), "cancelled");
    }

    #[test]
    fn trace_explanation_contains_only_safe_fields() {
        let trace = DecisionTrace {
            request_id: RequestId::from_u128(7),
            policy_digest: Digest::from_bytes([0xab; 32]),
            candidates: vec![Candidate {
                target: TargetId::new("local:qwen").unwrap(),
                terms: ScoreTerms::default(),
                binding_precedence: 1,
                rank: 0,
                pin_rank: Candidate::PIN_TARGET,
                residency: ResidencyClass::Unmanaged,
            }],
            exclusions: vec![
                Exclusion {
                    target: TargetId::new("openai:gpt").unwrap(),
                    reason: ExclusionReason::ResidencyMismatch,
                },
                Exclusion {
                    target: TargetId::new("deepseek:coder").unwrap(),
                    reason: ExclusionReason::DeniedByPolicy,
                },
            ],
            chosen: Some(TargetId::new("local:qwen").unwrap()),
            attempts: Vec::new(),
            routing_micros: 42,
            pinned: false,
        };
        let text = trace.explain();
        assert!(text.contains("policy abababab"));
        assert!(text.contains("candidates=1"));
        assert!(text.contains("excluded=2"));
        assert!(text.contains("chosen=local:qwen"));
        // No prompt, no credential, no URL can appear: none of the fields hold
        // one. This assertion documents the intent for future editors.
        assert!(!text.contains("http"));
    }

    #[test]
    fn exclusion_summary_groups_by_reason() {
        let trace = DecisionTrace {
            request_id: RequestId::from_u128(1),
            policy_digest: Digest::from_bytes([0; 32]),
            candidates: Vec::new(),
            exclusions: vec![
                Exclusion {
                    target: TargetId::new("a").unwrap(),
                    reason: ExclusionReason::Unhealthy,
                },
                Exclusion {
                    target: TargetId::new("b").unwrap(),
                    reason: ExclusionReason::Unhealthy,
                },
                Exclusion {
                    target: TargetId::new("c").unwrap(),
                    reason: ExclusionReason::DeniedByPolicy,
                },
            ],
            chosen: None,
            attempts: Vec::new(),
            routing_micros: 0,
            pinned: false,
        };
        let summary = trace.exclusion_summary();
        assert_eq!(summary.len(), 2);
        assert!(summary.contains(&(ExclusionReason::Unhealthy, 2)));
        assert!(summary.contains(&(ExclusionReason::DeniedByPolicy, 1)));
    }
}
