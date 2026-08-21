//! Property tests over the capability contract.
//!
//! Specification-extension 3 adds four axes to eligibility — verb, modality,
//! feature, tier — and extension 7.2 splits the affinity term between model
//! warmness and a permitted client hint. Every one of those is an eligibility
//! filter or a bounded preference, never a way for a caller to reach something
//! policy did not already permit, and this file is where that is asserted.
//!
//! The nine properties extension 16 names are here, plus the arithmetic the
//! hint-versus-warmth guarantee rests on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, ContentPart, CostClass, DocumentSource, DocumentType,
    Message, Modality, Operation, QualityClass, ReasoningEffort, RequestLimits, Role,
    RoutingHints, Sampling, StreamOptions, TokenEstimate,
};
use hypellm_core::decision::{ExclusionReason, ResidencyClass, ScoreTerms};
use hypellm_core::ids::{
    AliasId, BindingId, GroupId, PrincipalId, ProviderId, RequestId, TargetId, TenantId,
};
use hypellm_core::policy::{
    AliasGrant, Binding, BindingScope, LiveState, ModelSelector, PolicySnapshot, RouteOutcome,
    RoutingContext, TargetPreference, TargetSelector,
};
use hypellm_core::target::{
    AdminState, Alias, Capabilities, Capability, EffortMultipliers, Endpoint, EndpointScheme,
    Provider, ProviderFamily, Target,
};
use hypellm_core::time::Deadline;

fn tid(s: &str) -> TargetId {
    TargetId::new(s).unwrap()
}
fn aid(s: &str) -> AliasId {
    AliasId::new(s).unwrap()
}

/// Live state that reports a chosen residency class for every target.
#[derive(Debug)]
struct Warmth(Vec<(TargetId, ResidencyClass)>);

impl LiveState for Warmth {
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
    fn residency_class(&self, target: &TargetId) -> ResidencyClass {
        self.0
            .iter()
            .find(|(id, _)| id == target)
            .map_or(ResidencyClass::Unmanaged, |(_, class)| *class)
    }
    fn activation_eta_ms(&self, _target: &TargetId) -> u64 {
        0
    }
}

fn provider() -> Provider {
    Provider {
        id: ProviderId::new("local").unwrap(),
        family: ProviderFamily::LlamaCpp,
        endpoints: vec![Endpoint {
            scheme: EndpointScheme::Http,
            host: "127.0.0.1".to_owned(),
            port: 8080,
            base_path: "/v1".to_owned(),
        }],
        // Declared so that a target marked remote is not excluded for a
        // missing credential before the axis under test is reached — several
        // fixtures below are deliberately remote *and* expensive, because a
        // filter expressed as a score would lose to a local cheap alternative.
        credential_ref: Some(hypellm_core::ids::CredentialRef::new("cred").unwrap()),
        enabled: true,
        egress_profile: "local".to_owned(),
    }
}

fn target(id: &str) -> Target {
    Target {
        id: tid(id),
        provider_id: ProviderId::new("local").unwrap(),
        native_model: id.to_owned(),
        aliases: vec![aid("code")],
        capabilities: Capabilities {
            operations: vec![Operation::Chat],
            verbs: vec![Capability::Chat],
            modalities: vec![Modality::Text],
            reasoning_efforts: ReasoningEffort::declarable().to_vec(),
            effort_multipliers: EffortMultipliers::DEFAULT,
            streaming: true,
            max_context_tokens: 1_000_000,
            max_output_tokens: 100_000,
            ..Capabilities::default()
        },
        cost_class: CostClass::CHEAPEST,
        quality_class: QualityClass::LOWEST,
        document_token_estimate: None,
        residency: None,
        is_local: true,
        admin_state: AdminState::Enabled,
        endpoint_index: 0,
        max_concurrency: 8,
        max_requests_per_second: 100,
    }
}

fn snapshot(targets: Vec<Target>) -> PolicySnapshot {
    let mut snapshot = PolicySnapshot::empty();
    snapshot
        .providers
        .insert(ProviderId::new("local").unwrap(), provider());
    let ids: Vec<TargetId> = targets.iter().map(|t| t.id.clone()).collect();
    for target in targets {
        snapshot.allowlisted_targets.insert(target.id.clone());
        snapshot.targets.insert(target.id.clone(), target);
    }
    snapshot.aliases.insert(
        aid("code"),
        Alias {
            id: aid("code"),
            capability: Some(Capability::Chat),
            permitted_targets: ids.clone(),
            allow_family_failover: true,
            description: None,
        },
    );
    snapshot.grants.push(AliasGrant {
        scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
        model: ModelSelector::Any,
        operations: Vec::new(),
        allow: true,
    });
    snapshot.bindings.push(Binding {
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
    snapshot
}

fn request(content: Vec<ContentPart>) -> CanonicalRequest {
    CanonicalRequest {
        request_id: RequestId::from_u128(1),
        tenant: TenantId::new("acme").unwrap(),
        principal: PrincipalId::new("user:1").unwrap(),
        protocol: ClientProtocol::OpenAiChat,
        operation: Operation::Chat,
        requested_model: aid("code"),
        messages: vec![Message {
            role: Role::User,
            content,
            tool_calls: Vec::new(),
            name: None,
        }],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: ReasoningEffort::Unset,
        limits: RequestLimits {
            max_output_tokens: Some(1_000),
            deadline: Deadline::at(u64::MAX),
            max_cost_class: None,
            min_quality_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: RoutingHints::default(),
    }
}

fn route(snapshot: &PolicySnapshot, request: &CanonicalRequest, live: &dyn LiveState) -> RouteOutcome {
    let groups: Vec<GroupId> = Vec::new();
    let attempted: Vec<TargetId> = Vec::new();
    let context = RoutingContext {
        principal: &request.principal,
        groups: &groups,
        tenant: &request.tenant,
        attempted: &attempted,
        now_millis: 0,
    };
    snapshot.route(&context, request, live)
}

fn excluded_for(outcome: &RouteOutcome, target: &str) -> Option<ExclusionReason> {
    outcome
        .exclusions
        .iter()
        .find(|e| e.target.as_str() == target)
        .map(|e| e.reason)
}

fn document(url: &str) -> ContentPart {
    ContentPart::Document {
        media_type: DocumentType::Pdf,
        source: DocumentSource::Url(url.to_owned()),
    }
}

// -- Modality ---------------------------------------------------------------

#[test]
fn a_document_request_is_excluded_from_a_target_without_the_document_modality() {
    // The fleet case exactly: the Spark's Qwen3.8 runs without the vision
    // projector deliberately, so it cannot serve a document however much
    // unified memory is free — and the request must be refused *before* a
    // container is started, not discovered at the provider afterwards.
    let mut projectorless = target("spark:qwen38");
    projectorless.capabilities.modalities = vec![Modality::Text];
    let mut vision = target("node0:qwen35-vision");
    vision.capabilities.modalities =
        vec![Modality::Text, Modality::Image, Modality::Document];
    // Adversarial: the target that *can* serve the document is the expensive,
    // remote one, so anything that ranked rather than filtered would pick the
    // other.
    vision.cost_class = CostClass::MOST_EXPENSIVE;
    vision.is_local = false;

    let snapshot = snapshot(vec![projectorless, vision]);
    let request = request(vec![
        ContentPart::Text("summarise this".to_owned()),
        document("https://example.invalid/report.pdf"),
    ]);
    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));

    assert_eq!(
        excluded_for(&outcome, "spark:qwen38"),
        Some(ExclusionReason::ModalityUnsupported)
    );
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("node0:qwen35-vision"),
        "the document goes to the target that declared the modality"
    );
}

#[test]
fn a_document_url_is_never_dereferenced_and_never_influences_routing() {
    // The router holds no fetcher, so the structural assertion available here
    // is the one that matters for routing: the URL is opaque. Two requests
    // differing only in the document's URL must produce identical decisions,
    // which is false the moment anything reads it.
    let mut vision = target("node0:vision");
    vision.capabilities.modalities = vec![Modality::Text, Modality::Document];
    let snapshot = snapshot(vec![vision]);

    let mut first = request(vec![document("https://example.invalid/a.pdf")]);
    let mut second = request(vec![document(
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
    )]);
    // Same identifier, so the tie-break is identical too.
    first.request_id = RequestId::from_u128(7);
    second.request_id = RequestId::from_u128(7);

    let a = route(&snapshot, &first, &Warmth(Vec::new()));
    let b = route(&snapshot, &second, &Warmth(Vec::new()));
    assert_eq!(
        a.candidates.iter().map(|c| c.score()).collect::<Vec<_>>(),
        b.candidates.iter().map(|c| c.score()).collect::<Vec<_>>(),
        "a document URL changed a routing score, so something read it"
    );
    assert_eq!(
        a.candidates.iter().map(|c| c.target.clone()).collect::<Vec<_>>(),
        b.candidates.iter().map(|c| c.target.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn a_document_costs_a_configured_constant_rather_than_its_byte_length() {
    // A scanned PDF is megabytes and few tokens; a dense text PDF is the
    // reverse. Byte-derived estimation is meaningless for both, and the
    // constant must dominate — otherwise a large document silently exceeds a
    // context window it would have fitted, or slips past a quota it should not.
    let small = request(vec![ContentPart::Document {
        media_type: DocumentType::Pdf,
        source: DocumentSource::Inline {
            base64_data: "AAAA".to_owned(),
        },
    }]);
    let large = request(vec![ContentPart::Document {
        media_type: DocumentType::Pdf,
        source: DocumentSource::Inline {
            base64_data: "A".repeat(4_000_000),
        },
    }]);
    assert_eq!(
        small.estimated_input_tokens_with(4_096),
        large.estimated_input_tokens_with(4_096),
        "the estimate must not depend on the document's size"
    );
    // And the constant is what it charges.
    assert!(small.estimated_input_tokens_with(4_096) >= 4_096);
    assert_eq!(small.document_parts(), 1);
}

// -- Reasoning effort -------------------------------------------------------

#[test]
fn a_reasoning_effort_reserves_its_multiplied_output_budget() {
    // Applied at reservation, not after. Reserving unmultiplied would let a
    // high-effort request consume several times what it was held to — a quota
    // bypass that needs no malformed input, just a JSON field.
    let mut request = request(vec![ContentPart::Text("hi".to_owned())]);
    request.limits.max_output_tokens = Some(1_000);

    let base = request.estimated_output_tokens_with(1);
    for (effort, expected) in [
        (ReasoningEffort::Unset, 1),
        (ReasoningEffort::Minimal, 1),
        (ReasoningEffort::Low, 2),
        (ReasoningEffort::Medium, 4),
        (ReasoningEffort::High, 8),
    ] {
        request.reasoning_effort = effort;
        let estimate = TokenEstimate::for_effort(effort);
        let reserved = request.estimated_output_tokens_with(estimate.output_multiplier);
        assert_eq!(
            reserved,
            base.saturating_mul(expected),
            "{effort} reserved {reserved} against a base of {base}"
        );
        assert!(
            request.estimated_total_tokens() >= reserved,
            "the total must include the multiplied output"
        );
    }
}

#[test]
fn an_unsupported_effort_tier_excludes_rather_than_downgrades() {
    // A target that quietly served a `high` request at whatever it supports
    // returns a cheaper answer than the caller asked for and tells nobody.
    let mut limited = target("local:limited");
    limited.capabilities.reasoning_efforts =
        vec![ReasoningEffort::Minimal, ReasoningEffort::Low];
    let snapshot = snapshot(vec![limited]);

    let mut request = request(vec![ContentPart::Text("think".to_owned())]);
    request.reasoning_effort = ReasoningEffort::High;
    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
    assert!(outcome.candidates.is_empty());
    assert_eq!(
        excluded_for(&outcome, "local:limited"),
        Some(ExclusionReason::ReasoningEffortUnsupported)
    );

    // A tier it does declare still routes.
    request.reasoning_effort = ReasoningEffort::Low;
    assert_eq!(
        route(&snapshot, &request, &Warmth(Vec::new()))
            .candidates
            .len(),
        1
    );
}

#[test]
fn an_unset_effort_is_never_refused_by_a_target_that_declares_tiers() {
    // `Unset` is the absence of a request, not a tier. A target that refused it
    // would refuse every ordinary chat request the moment its operator declared
    // which reasoning levels it supports.
    let mut declared = target("local:declared");
    declared.capabilities.reasoning_efforts = vec![ReasoningEffort::High];
    let snapshot = snapshot(vec![declared]);
    let request = request(vec![ContentPart::Text("hi".to_owned())]);
    assert_eq!(
        route(&snapshot, &request, &Warmth(Vec::new()))
            .candidates
            .len(),
        1
    );
}

// -- Quality ----------------------------------------------------------------

#[test]
fn a_quality_floor_excludes_a_lower_tier_target_even_when_it_is_cheaper() {
    // Adversarial by construction: the high-quality target is the *expensive*
    // one, so a floor expressed as a score would lose to the cheap one.
    let mut cheap = target("local:q4");
    cheap.quality_class = QualityClass::new(3);
    cheap.cost_class = CostClass::CHEAPEST;
    let mut good = target("local:q5");
    good.quality_class = QualityClass::new(7);
    good.cost_class = CostClass::MOST_EXPENSIVE;

    let snapshot = snapshot(vec![cheap, good]);
    let mut request = request(vec![ContentPart::Text("hi".to_owned())]);
    request.limits.min_quality_class = Some(QualityClass::new(5));

    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
    assert_eq!(
        excluded_for(&outcome, "local:q4"),
        Some(ExclusionReason::QualityFloorNotMet)
    );
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("local:q5")
    );
}

#[test]
fn a_quality_floor_and_a_cost_ceiling_are_independent() {
    // Neither is derived from the other: a local high-quality target may also
    // be the cheapest, and a configuration that conflated them would make that
    // target unreachable or mispriced.
    let mut local_best = target("local:q5");
    local_best.quality_class = QualityClass::new(9);
    local_best.cost_class = CostClass::CHEAPEST;
    let mut remote_worse = target("openai:q4");
    remote_worse.quality_class = QualityClass::new(2);
    remote_worse.cost_class = CostClass::MOST_EXPENSIVE;

    let snapshot = snapshot(vec![local_best, remote_worse]);
    let mut request = request(vec![ContentPart::Text("hi".to_owned())]);
    request.limits.min_quality_class = Some(QualityClass::new(9));
    request.limits.max_cost_class = Some(CostClass::new(0));

    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("local:q5"),
        "the best and cheapest target satisfies both bounds at once"
    );
}

// -- Capability verb --------------------------------------------------------

#[test]
fn a_target_that_does_not_declare_the_aliases_verb_is_excluded() {
    // A music model and a speech model both take text and emit audio, and no
    // combination of operation and modality distinguishes them.
    let mut speech = target("spark:tts");
    speech.capabilities.verbs = vec![Capability::TextToSpeech];
    let mut music = target("spark:music3");
    music.capabilities.verbs = vec![Capability::TextToMusic];

    let mut snapshot = snapshot(vec![speech, music]);
    if let Some(alias) = snapshot.aliases.get_mut(&aid("code")) {
        alias.capability = Some(Capability::TextToMusic);
    }

    let request = request(vec![ContentPart::Text("a jingle".to_owned())]);
    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
    assert_eq!(
        excluded_for(&outcome, "spark:tts"),
        Some(ExclusionReason::CapabilityUnsupported)
    );
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("spark:music3")
    );
}

#[test]
fn an_alias_that_declares_no_verb_routes_exactly_as_it_did_before() {
    // The compatibility promise: a configuration written before the capability
    // axis existed must behave identically, which means an alias with no verb
    // consults no verb.
    let mut verbless = target("local:old");
    verbless.capabilities.verbs = Vec::new();
    let mut snapshot = snapshot(vec![verbless]);
    if let Some(alias) = snapshot.aliases.get_mut(&aid("code")) {
        alias.capability = None;
    }
    let request = request(vec![ContentPart::Text("hi".to_owned())]);
    assert_eq!(
        route(&snapshot, &request, &Warmth(Vec::new()))
            .candidates
            .len(),
        1
    );
}

// -- Warmth and hints -------------------------------------------------------

#[test]
fn the_warmth_ladder_spacing_exceeds_the_maximum_hint_bonus() {
    // The arithmetic every hint guarantee depends on. Changing either constant
    // in isolation silently converts a preference into a destination control.
    let ladder = ResidencyClass::all_ready_classes();
    for pair in ladder.windows(2) {
        let gap = pair[0].warmth_bonus() - pair[1].warmth_bonus();
        assert!(
            gap > ScoreTerms::HINT_SLICE,
            "adjacent rungs {:?} and {:?} are {gap} apart, which a {} hint can cross",
            pair[0],
            pair[1],
            ScoreTerms::HINT_SLICE
        );
    }
    // And the slices fit inside the term they share.
    assert!(
        ScoreTerms::WARMTH_SLICE + ScoreTerms::HINT_SLICE + ScoreTerms::CONVERSATION_SLICE
            <= ScoreTerms::AFFINITY_RANGE.1,
        "the affinity slices overflow the term's range"
    );
}

#[test]
fn a_client_hint_never_makes_an_ineligible_target_eligible() {
    // The hint is read only after every filter has passed. A hint that could
    // create eligibility would be a client-controlled destination by a longer
    // route, which Appendix B forbids outright.
    let mut denied = target("local:denied");
    denied.admin_state = AdminState::Disabled;
    let mut wrong_modality = target("local:text-only");
    wrong_modality.capabilities.modalities = vec![Modality::Text];
    let mut vision = target("local:vision");
    vision.capabilities.modalities = vec![Modality::Text, Modality::Document];

    let snapshot = snapshot(vec![denied, wrong_modality, vision]);
    for hinted in ["local:denied", "local:text-only"] {
        let mut request = request(vec![document("https://example.invalid/a.pdf")]);
        request.hints.prefer_target = Some(tid(hinted));
        let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
        assert!(
            outcome.candidates.iter().all(|c| c.target.as_str() != hinted),
            "a hint made {hinted} eligible"
        );
    }
}

#[test]
fn a_client_hint_never_outranks_a_warmer_target() {
    // A caller asking for a cold target when a warm equivalent exists gets the
    // warm one. The hint may break a tie; it may not move a target between
    // rungs.
    let warm = target("spark:warm");
    let cold = target("spark:cold");
    let snapshot = snapshot(vec![warm, cold]);

    let live = Warmth(vec![
        (tid("spark:warm"), ResidencyClass::Resident),
        (tid("spark:cold"), ResidencyClass::ColdRequiresEviction),
    ]);

    let mut request = request(vec![ContentPart::Text("hi".to_owned())]);
    request.hints.prefer_target = Some(tid("spark:cold"));
    let outcome = route(&snapshot, &request, &live);
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("spark:warm"),
        "a hint promoted a colder target over a warmer one"
    );

    // With both equally warm, the hint decides — which is its entire
    // legitimate purpose, and without this the assertion above would hold for
    // a hint that did nothing at all.
    let equal = Warmth(vec![
        (tid("spark:warm"), ResidencyClass::Resident),
        (tid("spark:cold"), ResidencyClass::Resident),
    ]);
    let outcome = route(&snapshot, &request, &equal);
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("spark:cold"),
        "a hint must break a tie between equally warm targets"
    );
}

#[test]
fn a_client_hint_never_outranks_a_priority_binding() {
    // Rank dominates every optimization term, hint included. An operator's
    // explicit ordering is not overturned by a JSON field.
    let preferred = target("local:rank0");
    let other = target("local:rank1");
    let mut snapshot = snapshot(vec![preferred, other]);
    snapshot.bindings.clear();
    snapshot.bindings.push(Binding {
        id: BindingId::new("ranked").unwrap(),
        scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
        model: ModelSelector::Any,
        preferences: vec![
            TargetPreference {
                selector: TargetSelector::Exact(tid("local:rank0")),
                rank: 0,
                weight: 0,
            },
            TargetPreference {
                selector: TargetSelector::Exact(tid("local:rank1")),
                rank: 1,
                weight: 0,
            },
        ],
        denies: Vec::new(),
        allows: Vec::new(),
        pin: None,
        emergency_fallback: Vec::new(),
        priority: 0,
    });

    let mut request = request(vec![ContentPart::Text("hi".to_owned())]);
    request.hints.prefer_target = Some(tid("local:rank1"));
    let outcome = route(&snapshot, &request, &Warmth(Vec::new()));
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("local:rank0")
    );
}

#[test]
fn a_cold_rank_zero_target_still_outranks_a_warm_rank_one_target() {
    // Warmness is a preference, not a filter, and it must not silently
    // overturn an operator's ordering: the swap happens, and that is intended.
    let cold = target("spark:pinned-choice");
    let warm = target("spark:convenient");
    let mut snapshot = snapshot(vec![cold, warm]);
    snapshot.bindings.clear();
    snapshot.bindings.push(Binding {
        id: BindingId::new("ranked").unwrap(),
        scope: BindingScope::Tenant(TenantId::new("acme").unwrap()),
        model: ModelSelector::Any,
        preferences: vec![
            TargetPreference {
                selector: TargetSelector::Exact(tid("spark:pinned-choice")),
                rank: 0,
                weight: 0,
            },
            TargetPreference {
                selector: TargetSelector::Exact(tid("spark:convenient")),
                rank: 1,
                weight: 0,
            },
        ],
        denies: Vec::new(),
        allows: Vec::new(),
        pin: None,
        emergency_fallback: Vec::new(),
        priority: 0,
    });

    let live = Warmth(vec![
        (tid("spark:pinned-choice"), ResidencyClass::ColdRequiresFetch),
        (tid("spark:convenient"), ResidencyClass::Resident),
    ]);
    let request = request(vec![ContentPart::Text("hi".to_owned())]);
    let outcome = route(&snapshot, &request, &live);
    assert_eq!(
        outcome.candidates.first().map(|c| c.target.as_str()),
        Some("spark:pinned-choice"),
        "rank must dominate warmth"
    );
}

#[test]
fn an_infeasible_residency_class_excludes_and_every_other_class_does_not() {
    // The central decision of the design: if "not currently running" excluded a
    // target, no target would ever start.
    let subject = target("spark:subject");
    let snapshot = snapshot(vec![subject]);
    let request = request(vec![ContentPart::Text("hi".to_owned())]);

    for class in ResidencyClass::all_ready_classes() {
        let live = Warmth(vec![(tid("spark:subject"), *class)]);
        let outcome = route(&snapshot, &request, &live);
        assert_eq!(
            outcome.candidates.len(),
            1,
            "{class:?} excluded a target that could still be made ready"
        );
    }

    let live = Warmth(vec![(
        tid("spark:subject"),
        ResidencyClass::Infeasible(ExclusionReason::HostCapacityInsufficient),
    )]);
    let outcome = route(&snapshot, &request, &live);
    assert!(outcome.candidates.is_empty());
    assert_eq!(
        excluded_for(&outcome, "spark:subject"),
        Some(ExclusionReason::HostCapacityInsufficient)
    );
}
