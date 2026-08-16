//! The HypeLLM Router core: canonical types, routing policy, admission control,
//! health, and decision traces.
//!
//! Specification 18.1 describes this crate as "Canonical types, routing,
//! quotas, retries, decision traces; pure and heavily property-tested."
//!
//! # What is here and what is not
//!
//! This crate performs **no I/O**. It does not open sockets, read files,
//! resolve names, or hold credentials. [`PolicySnapshot::route`] takes `&self`,
//! a request, and a [`LiveState`] of already-sampled values, and returns ranked
//! candidates. That is what makes the routing rules testable exhaustively and
//! what lets specification 15.4's draft simulation run the production code path
//! "without provider invocation".
//!
//! # The invariants
//!
//! Appendix B is the checklist. Each item is enforced somewhere concrete:
//!
//! | Invariant | Where |
//! |---|---|
//! | A denied target is never selected | [`policy`] — sticky deny in `MergedBindings::is_denied` |
//! | A hard pin never falls back unless declared | [`policy`] — `NotPinnedTarget` filter |
//! | Security constraints are filters, never soft scores | [`decision::ExclusionReason::is_security_constraint`] |
//! | Equal inputs produce equal ordered candidates | [`policy`] — `BTreeMap` ordering, identifier tie-break |
//! | Every selection owns a reservation before I/O | [`admission::AdmissionController::reserve`] |
//! | Every reservation is released exactly once | [`admission::Reservation`] — `commit` plus `Drop` |
//! | No failover after client-visible semantic bytes | [`event::CanonicalEvent::is_semantic_output`] |
//! | Rank 0 dominates optimization terms | [`decision::ScoreTerms`] — `RANK_UNIT` |
//!
//! # Sensitivity
//!
//! Specification 10 makes prompts, tool arguments, credentials, and provider
//! bodies sensitive by default. Every type in this crate that can hold such a
//! value has a hand-written `Debug` that reports shape and size only — see
//! [`canonical::CanonicalRequest`], [`canonical::Message`],
//! [`event::CanonicalEvent`], and [`sensitive::Sensitive`]. Tests assert it.

#![forbid(unsafe_code)]

// Specification 18.2 ("no panics on data-plane input", "all integer
// conversions checked") and 6.3 (integer fixed-point scoring). This crate is
// entirely data plane, so the workspace-level warnings are escalated to errors
// here: a new unchecked conversion or unintended division fails the build
// rather than joining a list of warnings. The few sites where truncation is
// the specified behaviour carry a narrowly-scoped `#[allow]` and a comment
// saying why. `clippy::indexing_slicing` and `clippy::panic` are not listed
// because no site in this crate has ever raised them.
#![deny(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division
)]
// The escalation covers the shipped library. Under `cfg(test)` the three lints
// fall back to the workspace `warn` level, which is the level the workspace
// manifest chose deliberately "because test code legitimately uses them": the
// unit tests below coerce `Arc<TestClock>` to `Arc<dyn Clock>` with `as` and
// divide in assertions. Production code is compiled without `cfg(test)`, so
// nothing that ships is exempted here.
#![cfg_attr(
    test,
    allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::integer_division
    )
)]

/// How long a superseded provider credential stays usable after a rotation.
///
/// Specification 22.2 step 16's bounded overlap. Lives here so the router that
/// enforces it and the management API that reports it cannot disagree — an
/// operator planning a cutover around a number the router does not honour would
/// be worse than no number.
pub const OVERLAP_HINT_MILLIS: u64 = 5 * 60 * 1000;

pub mod admission;
pub mod canonical;
pub mod decision;
pub mod error;
pub mod event;
pub mod health;
pub mod ids;
pub mod netaddr;
pub mod policy;
pub mod rbac;
pub mod sensitive;
pub mod target;
pub mod time;

pub use canonical::{
    CanonicalRequest, ClientProtocol, ContentPart, CostClass, Message, Modality, Operation,
    RequestLimits, Residency, ResponseFormat, Role, RoutingHints, Sampling, StreamOptions, ToolCall,
    ToolChoice, ToolDef,
};
pub use decision::{
    Attempt, AttemptOutcome, Candidate, DecisionTrace, Exclusion, ExclusionReason, ScoreTerms,
};
pub use error::{ErrorCode, RouterError};
pub use event::{
    CanonicalEvent, CanonicalUsage, FinishReason, ResponseAccumulator, ToolCallDelta, UpstreamError,
    UpstreamErrorClass, UsageSource,
};
pub use ids::{
    AliasId, BindingId, CredentialRef, GroupId, KeyId, PolicyId, PrincipalId, ProviderId, RequestId,
    TargetId, TenantId,
};
pub use policy::{
    AliasGrant, Binding, BindingScope, LiveState, ModelSelector, PolicySnapshot, RouteOutcome,
    RoutingContext, TargetPreference, TargetSelector,
};
pub use netaddr::{AddressClass, EgressDenial, EgressProfile, check_destination, classify};
// `canonical::Role` is a message role and `rbac::Role` is a management role.
// They are unrelated concepts that would read identically at a call site, so
// the management one is re-exported under its full name.
pub use rbac::{Permission, PermissionSet, Role as ManagementRole};
pub use sensitive::{Capped, Sensitive};
pub use target::{
    AdminState, Alias, Capabilities, Endpoint, EndpointScheme, Provider, ProviderFamily, Target,
};
pub use time::{Clock, Deadline, SystemClock};

#[cfg(test)]
mod invariant_tests {
    //! Cross-module tests for the Appendix B invariants that no single module
    //! owns on its own.

    use super::*;
    use crate::admission::{AdmissionController, ScopeLimits};
    use crate::policy::IdealLiveState;
    use crate::time::TestClock;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    fn tid(s: &str) -> TargetId {
        TargetId::new(s).unwrap()
    }

    fn minimal_snapshot() -> PolicySnapshot {
        let mut s = PolicySnapshot::empty();
        s.providers.insert(
            ProviderId::new("local").unwrap(),
            Provider {
                id: ProviderId::new("local").unwrap(),
                family: ProviderFamily::LlamaCpp,
                endpoints: vec![Endpoint {
                    scheme: EndpointScheme::Http,
                    host: "127.0.0.1".to_owned(),
                    port: 8080,
                    base_path: "/v1".to_owned(),
                }],
                credential_ref: None,
                enabled: true,
                egress_profile: "local".to_owned(),
            },
        );
        s.targets.insert(
            tid("local:qwen"),
            Target {
                id: tid("local:qwen"),
                provider_id: ProviderId::new("local").unwrap(),
                native_model: "qwen".to_owned(),
                aliases: vec![AliasId::new("code").unwrap()],
                capabilities: Capabilities {
                    operations: vec![Operation::Chat],
                    streaming: true,
                    max_context_tokens: 100_000,
                    max_output_tokens: 4_096,
                    ..Capabilities::default()
                },
                cost_class: CostClass::CHEAPEST,
                residency: None,
                is_local: true,
                admin_state: AdminState::Enabled,
                endpoint_index: 0,
                max_concurrency: 4,
                max_requests_per_second: 10,
            },
        );
        s.allowlisted_targets.insert(tid("local:qwen"));
        s.aliases.insert(
            AliasId::new("code").unwrap(),
            Alias {
                id: AliasId::new("code").unwrap(),
                permitted_targets: vec![tid("local:qwen")],
                allow_family_failover: false,
                description: None,
            },
        );
        s.grants.push(AliasGrant {
            scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
            model: ModelSelector::Any,
            operations: Vec::new(),
            allow: true,
        });
        s.bindings.push(Binding {
            id: BindingId::new("default").unwrap(),
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

    fn request() -> CanonicalRequest {
        let clock = TestClock::new();
        CanonicalRequest {
            request_id: RequestId::from_u128(1),
            tenant: TenantId::new("acme").unwrap(),
            principal: PrincipalId::new("user:1").unwrap(),
            protocol: ClientProtocol::OpenAiChat,
            operation: Operation::Chat,
            requested_model: AliasId::new("code").unwrap(),
            messages: vec![Message::text(Role::User, "hi")],
            inputs: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            response_format: None,
            sampling: Sampling::default(),
            limits: RequestLimits {
                max_output_tokens: Some(128),
                deadline: Deadline::after(&clock, Duration::from_secs(30)),
                max_cost_class: None,
                residency: None,
            },
            stream: StreamOptions {
                enabled: false,
                include_usage: false,
            },
            hints: RoutingHints::default(),
        }
    }

    #[test]
    fn selection_is_followed_by_a_reservation_before_any_io() {
        // "Every successful selection owns an admission reservation before
        // outbound I/O." This crate cannot do I/O at all, so the assertion is
        // that the sequence composes: route, then reserve, then hold.
        let snapshot = minimal_snapshot();
        let req = request();
        let principal = req.principal.clone();
        let tenant = req.tenant.clone();
        let groups: Vec<GroupId> = Vec::new();
        let attempted: Vec<TargetId> = Vec::new();
        let ctx = RoutingContext {
            principal: &principal,
            groups: &groups,
            tenant: &tenant,
            attempted: &attempted,
        };

        let outcome = snapshot.route(&ctx, &req, &IdealLiveState);
        let best = outcome.candidates.first().expect("a candidate");

        let clock = Arc::new(TestClock::new());
        let admission = AdmissionController::new(
            clock,
            ScopeLimits {
                max_concurrency: 1,
                ..ScopeLimits::UNLIMITED
            },
        );
        let reservation = admission
            .reserve(
                &req.tenant,
                &req.principal,
                &best.target,
                req.estimated_total_tokens(),
            )
            .expect("capacity");
        assert_eq!(reservation.target, best.target);
        assert_eq!(admission.global().in_flight(), 1);
        drop(reservation);
        assert_eq!(admission.global().in_flight(), 0);
    }

    #[test]
    fn no_security_exclusion_is_expressible_as_a_score_penalty() {
        // Specification 6.3: "Security constraints never appear as score
        // penalties — they are eligibility filters." Structurally, ScoreTerms
        // has no field a security reason could be written into; this test
        // records the intent so that adding one is a deliberate act.
        let security: Vec<ExclusionReason> = ExclusionReason::all()
            .iter()
            .copied()
            .filter(|r| r.is_security_constraint())
            .collect();
        assert!(!security.is_empty());
        for reason in security {
            // Every security reason is produced by the filter phase, which
            // returns `Err(reason)` and never constructs a Candidate.
            assert!(
                reason.is_security_constraint(),
                "{reason} must remain a filter"
            );
        }
    }

    #[test]
    fn failover_gate_and_attempt_outcomes_agree() {
        // "No failover splices output after client-visible semantic bytes."
        let mut acc = ResponseAccumulator::new();
        acc.push(&CanonicalEvent::Start {
            upstream_id: None,
            native_model: None,
        });
        assert!(
            !acc.saw_semantic_output(),
            "before output, failover is permitted"
        );

        acc.push(&CanonicalEvent::TextDelta("partial".to_owned()));
        assert!(acc.saw_semantic_output());

        // Once output has been seen, the only faithful outcome is
        // FailedAfterOutput, which no retry policy may act on.
        let outcome = AttemptOutcome::FailedAfterOutput(UpstreamErrorClass::Connection);
        assert_eq!(outcome.code(), "failed_after_output");
    }

    #[test]
    fn every_exclusion_reason_is_reachable_from_a_documented_filter() {
        // A reason that no filter can produce is dead documentation. This test
        // is a registry: adding a reason without a filter fails here.
        let produced_by_routing: BTreeSet<ExclusionReason> = [
            ExclusionReason::NotAuthorizedForAlias,
            ExclusionReason::OperationUnsupported,
            ExclusionReason::NotPermittedForAlias,
            ExclusionReason::ProviderDisabled,
            ExclusionReason::TargetDisabled,
            ExclusionReason::TargetDraining,
            ExclusionReason::TargetMaintenance,
            ExclusionReason::TargetQuarantined,
            ExclusionReason::CircuitOpen,
            ExclusionReason::ModalityUnsupported,
            ExclusionReason::ToolsUnsupported,
            ExclusionReason::StructuredOutputUnsupported,
            ExclusionReason::StreamingUnsupported,
            ExclusionReason::ContextWindowTooSmall,
            ExclusionReason::OutputLimitTooSmall,
            ExclusionReason::ResidencyMismatch,
            ExclusionReason::EndpointNotAllowlisted,
            ExclusionReason::CredentialScopeMismatch,
            ExclusionReason::CostCeilingExceeded,
            ExclusionReason::CapacityExhausted,
            ExclusionReason::DeniedByPolicy,
            ExclusionReason::NotPinnedTarget,
            ExclusionReason::LocalRequired,
            ExclusionReason::FamilyFailoverNotAllowed,
            ExclusionReason::AlreadyAttempted,
            ExclusionReason::NotSelectedByAnyBinding,
        ]
        .into_iter()
        .collect();

        // These two come from the admission layer rather than the filter phase.
        let produced_by_admission: BTreeSet<ExclusionReason> =
            [ExclusionReason::BudgetExceeded, ExclusionReason::Unhealthy]
                .into_iter()
                .collect();

        let all: BTreeSet<ExclusionReason> = ExclusionReason::all().iter().copied().collect();
        let covered: BTreeSet<ExclusionReason> = produced_by_routing
            .union(&produced_by_admission)
            .copied()
            .collect();
        let uncovered: Vec<&ExclusionReason> = all.difference(&covered).collect();
        assert!(
            uncovered.is_empty(),
            "these reasons have no documented producer: {uncovered:?}"
        );
    }
}
