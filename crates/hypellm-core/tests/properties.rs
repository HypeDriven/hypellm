//! Property tests over the routing engine and the admission controller.
//!
//! Specification 21 lists a Property layer covering "routing determinism, deny
//! monotonicity, pin semantics, reservation conservation", and specification
//! 18.1 calls `core` "heavily property-tested". This file is that layer.
//!
//! # Why these are hand-rolled
//!
//! Specification 4 forbids third-party packages, so there is no `proptest` or
//! `quickcheck` here. What a property-testing library provides that matters is
//! (a) many generated inputs, (b) reproducibility, and (c) shrinking. The first
//! two are cheap to build: [`Rng`] is a seeded xorshift, and every case is
//! derived from a fixed seed, so a failure reproduces exactly.
//!
//! Shrinking is what is missing. Rather than pretend otherwise, each generator
//! keeps its inputs *small* — a handful of targets, a handful of bindings — so
//! that a failing case is already close to minimal and can be read directly
//! from the seed printed in the assertion message.
//!
//! # What a property test is for here
//!
//! Every property below is an invariant from Appendix B, stated as code. They
//! are not examples: an example test shows that one arrangement behaves, a
//! property test asserts that *no* arrangement misbehaves. When one fails, the
//! seed in the message reproduces it.

use hypellm_core::admission::{AdmissionController, ScopeLimits};
use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, CostClass, Message, Modality, Operation, RequestLimits,
    Role, RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::decision::{Candidate, ExclusionReason};
use hypellm_core::key_restriction::KeyRestriction;
use hypellm_core::ids::{
    AliasId, GroupId, HostId, PrincipalId, ProviderId, RequestId, TargetId, TenantId,
};
use hypellm_core::policy::{
    Binding, BindingScope, IdealLiveState, ModelSelector, PolicySnapshot, RouteOutcome,
    RoutingContext, TargetPreference, TargetSelector,
};
use hypellm_core::target::{
    AdminState, Alias, Capabilities, Endpoint, EndpointScheme, Provider, ProviderFamily, Target,
};
use hypellm_core::time::{Clock, TestClock};
use std::sync::Arc;

/// How many cases each property runs.
///
/// Large enough to explore the small input space thoroughly, small enough that
/// the whole file stays well inside a second — a property layer nobody runs
/// because it is slow protects nothing.
const CASES: u32 = 400;

/// A seeded xorshift64* generator.
///
/// Deterministic by construction: the same seed yields the same sequence on
/// every machine and every run, so a failure is reproducible from the seed
/// alone. `std` offers no PRNG and specification 4 forbids pulling one in.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift; fold it away.
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..bound`. `bound` must be non-zero.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Fisher-Yates, so that "the same set in a different order" is expressible.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

// -- Generators --------------------------------------------------------------

const TARGET_NAMES: &[&str] = &[
    "local:qwen",
    "openai:gpt",
    "anthropic:claude",
    "deepseek:coder",
    "kimi:k2",
];

fn tid(name: &str) -> TargetId {
    TargetId::new(name).expect("target id")
}

fn provider_of(target: &str) -> ProviderId {
    ProviderId::new(target.split(':').next().unwrap_or("local")).expect("provider id")
}

fn alias() -> AliasId {
    AliasId::new("code").expect("alias id")
}

fn tenant() -> TenantId {
    TenantId::new("acme").expect("tenant id")
}

fn principal() -> PrincipalId {
    PrincipalId::new("user:42").expect("principal id")
}

fn capabilities() -> Capabilities {
    Capabilities {
        operations: vec![Operation::Chat],
        modalities: vec![Modality::Text],
        verbs: Vec::new(),
        reasoning_efforts: Vec::new(),
        effort_multipliers: Default::default(),
        streaming: true,
        tools: true,
        parallel_tool_calls: true,
        json_mode: true,
        structured_output: true,
        reasoning: false,
        prompt_caching: false,
        max_context_tokens: 200_000,
        max_output_tokens: 16_384,
        embedding_dimensions: None,
        native_tokenizer: false,
    }
}

/// A snapshot whose targets differ in the dimensions scoring cares about, so
/// that ordering is a real question rather than a formality.
fn snapshot(rng: &mut Rng) -> PolicySnapshot {
    let mut s = PolicySnapshot::empty();

    for name in TARGET_NAMES {
        let provider = provider_of(name);
        s.providers.insert(
            provider.clone(),
            Provider {
                id: provider.clone(),
                family: ProviderFamily::OpenAi,
                endpoints: vec![Endpoint {
                    scheme: EndpointScheme::Https,
                    host: "api.example".to_owned(),
                    port: 443,
                    base_path: "/v1".to_owned(),
                }],
                // A remote target whose provider has no credential is refused
                // with `CredentialScopeMismatch`, which is correct but would
                // make these generators produce empty candidate sets for
                // reasons unrelated to the property under test.
                credential_ref: Some(
                    hypellm_core::ids::CredentialRef::new("cred").expect("credential ref"),
                ),
                enabled: true,
                egress_profile: "remote".to_owned(),
                recovery_wait_ms: 0,
            },
        );

        s.targets.insert(
            tid(name),
            Target {
                id: tid(name),
                provider_id: provider,
                native_model: (*name).to_owned(),
                aliases: vec![alias()],
                capabilities: capabilities(),
                cost_class: CostClass(u8::try_from(rng.below(10)).unwrap_or(0)),
                quality_class: Default::default(),
                document_token_estimate: None,
            bytes_per_token: None,
                residency: None,
                // A local target earns a large locality bonus, which is what
                // makes pin ordering and deny handling non-trivial.
                is_local: rng.bool(),
                admin_state: AdminState::Enabled,
                endpoint_index: 0,
                max_concurrency: 8,
                max_requests_per_second: 100,
            },
        );
        s.allowlisted_targets.insert(tid(name));
    }

    s.aliases.insert(
        alias(),
        Alias {
            id: alias(),
            permitted_targets: TARGET_NAMES.iter().map(|n| tid(n)).collect(),
            capability: None,
            allow_family_failover: true,
            llamacpp_sampling: Default::default(),
            description: None,
        },
    );

    s.grants.push(hypellm_core::policy::AliasGrant {
        scope: BindingScope::Tenant(tenant()),
        model: ModelSelector::Any,
        operations: Vec::new(),
        allow: true,
    });

    // A binding that makes every target reachable, so a target absent from the
    // candidates is absent for a reason under test.
    s.bindings.push(Binding {
        id: hypellm_core::ids::BindingId::new("open").expect("binding id"),
        scope: BindingScope::Tenant(tenant()),
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

    s.weighted_tie_break = rng.bool();
    s
}

fn request(rng: &mut Rng) -> CanonicalRequest {
    let clock = TestClock::new();
    CanonicalRequest {
        request_id: RequestId::from_u128(u128::from(rng.next_u64())),
        tenant: tenant(),
        principal: principal(),
        protocol: ClientProtocol::OpenAiChat,
        operation: Operation::Chat,
        requested_model: alias(),
        messages: vec![Message::text(Role::User, "hello")],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: Default::default(),
        limits: RequestLimits {
            max_output_tokens: None,
            deadline: hypellm_core::time::Deadline::after(&clock, std::time::Duration::from_secs(30)),
            max_cost_class: None,
            min_quality_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: RoutingHints::default(),
    }
}

fn route(s: &PolicySnapshot, req: &CanonicalRequest) -> RouteOutcome {
    let groups: Vec<GroupId> = Vec::new();
    let attempted: Vec<TargetId> = Vec::new();
    let ctx = RoutingContext {
        principal: &req.principal,
        groups: &groups,
        tenant: &req.tenant,
        attempted: &attempted,
        now_millis: 0,
        key: None,
    };
    s.route(&ctx, req, &IdealLiveState)
}

fn order(outcome: &RouteOutcome) -> Vec<String> {
    outcome
        .candidates
        .iter()
        .map(|c| c.target.as_str().to_owned())
        .collect()
}

// -- Determinism -------------------------------------------------------------

#[test]
fn equal_inputs_produce_equal_ordered_candidates() {
    // Appendix B: "Equal request, policy snapshot, and live-state snapshot
    // produce equal ordered candidates."
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed));
        let s = snapshot(&mut rng);
        let req = request(&mut rng);

        let first = route(&s, &req);
        let second = route(&s, &req);

        assert_eq!(order(&first), order(&second), "seed {seed}");
        assert_eq!(
            first.candidates.iter().map(Candidate::score).collect::<Vec<_>>(),
            second.candidates.iter().map(Candidate::score).collect::<Vec<_>>(),
            "seed {seed}"
        );
    }
}

#[test]
fn candidate_order_does_not_depend_on_the_order_bindings_were_written() {
    // Specification 6: "Administrative ordering is never inferred from map
    // iteration order." Bindings are a `Vec`, so their written order is an
    // input the result must not depend on.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xa11c_e00d);
        let mut s = snapshot(&mut rng);

        // Several bindings at the same precedence, differing in priority.
        for n in 0..3u32 {
            s.bindings.push(Binding {
                id: hypellm_core::ids::BindingId::new(format!("b{n}")).expect("binding id"),
                scope: BindingScope::Tenant(tenant()),
                model: ModelSelector::Any,
                preferences: vec![TargetPreference {
                    selector: TargetSelector::Exact(tid(TARGET_NAMES[rng.below(TARGET_NAMES.len())])),
                    rank: u16::try_from(rng.below(4)).unwrap_or(0),
                    weight: 0,
                }],
                denies: Vec::new(),
                allows: Vec::new(),
                pin: None,
                emergency_fallback: Vec::new(),
                priority: i32::try_from(rng.below(5)).unwrap_or(0),
            });
        }

        let req = request(&mut rng);
        let expected = order(&route(&s, &req));

        let mut shuffled = s.clone();
        rng.shuffle(&mut shuffled.bindings);
        assert_eq!(order(&route(&shuffled, &req)), expected, "seed {seed}");
    }
}

#[test]
fn the_tie_break_is_seeded_by_request_id_and_nothing_else() {
    // Specification 6 permits exactly one source of nondeterminism: "an
    // explicitly configured weighted tie-breaker seeded by request_id". Two
    // requests differing only in their identifier may order differently; the
    // same identifier must always order the same way.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x7113_b4ea);
        let mut s = snapshot(&mut rng);
        s.weighted_tie_break = true;

        let req = request(&mut rng);
        let repeated = CanonicalRequest { ..req.clone() };
        assert_eq!(order(&route(&s, &req)), order(&route(&s, &repeated)), "seed {seed}");
    }
}

// -- Deny monotonicity -------------------------------------------------------

#[test]
fn adding_a_deny_never_adds_a_candidate() {
    // A deny can only remove. If adding one ever grew the candidate set, some
    // deny would be acting as a preference.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xdeed_0001);
        let s = snapshot(&mut rng);
        let req = request(&mut rng);

        let before: Vec<String> = order(&route(&s, &req));

        let victim = TARGET_NAMES[rng.below(TARGET_NAMES.len())];
        let mut denied = s.clone();
        denied.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("deny").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: Vec::new(),
            denies: vec![TargetSelector::Exact(tid(victim))],
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let after = order(&route(&denied, &req));

        assert!(
            after.iter().all(|t| before.contains(t)),
            "seed {seed}: a deny introduced a candidate: before={before:?} after={after:?}"
        );
        assert!(
            !after.iter().any(|t| t == victim),
            "seed {seed}: the denied target survived"
        );
    }
}

#[test]
fn a_lower_precedence_allow_cannot_re_enable_a_higher_precedence_deny() {
    // Specification 6.1: "A deny is sticky downward: a lower-precedence binding
    // cannot re-enable a target denied by a higher-precedence security or
    // compliance rule."
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x5713_c4b1);
        let mut s = snapshot(&mut rng);
        let victim = TARGET_NAMES[rng.below(TARGET_NAMES.len())];

        // Precedence 1: principal + exact alias.
        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("high-deny").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: Vec::new(),
            denies: vec![TargetSelector::Exact(tid(victim))],
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        // Precedence 5/6: tenant. Lower, and tries to allow the same target.
        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("low-allow").expect("binding id"),
            scope: BindingScope::Tenant(tenant()),
            model: ModelSelector::Any,
            preferences: vec![TargetPreference {
                selector: TargetSelector::Exact(tid(victim)),
                rank: 0,
                weight: 0,
            }],
            denies: Vec::new(),
            allows: vec![TargetSelector::Exact(tid(victim))],
            pin: None,
            emergency_fallback: Vec::new(),
            priority: 100,
        });

        let req = request(&mut rng);
        assert!(
            !order(&route(&s, &req)).iter().any(|t| t == victim),
            "seed {seed}: a lower-precedence allow re-enabled a denied target"
        );
    }
}

// -- Pin semantics -----------------------------------------------------------

#[test]
fn a_pin_without_fallback_admits_only_the_pinned_target() {
    // Specification 6.1: "An explicit hard pin selects only the pinned target
    // and fails closed if unavailable unless the same binding defines an
    // allowed emergency fallback."
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x9111_0000);
        let mut s = snapshot(&mut rng);
        let pinned = TARGET_NAMES[rng.below(TARGET_NAMES.len())];

        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("pin").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid(pinned)),
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let req = request(&mut rng);
        let outcome = route(&s, &req);

        assert!(outcome.pinned, "seed {seed}");
        assert!(
            outcome.candidates.iter().all(|c| c.target.as_str() == pinned),
            "seed {seed}: a pin admitted something else: {:?}",
            order(&outcome)
        );
    }
}

#[test]
fn a_healthy_pin_always_outranks_its_own_fallbacks() {
    // The fallback is a fallback, not a peer. Scoring alone gets this wrong
    // whenever a fallback is local and cheap and the pin is neither.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x9111_fa11);
        let mut s = snapshot(&mut rng);

        let index = rng.below(TARGET_NAMES.len());
        let pinned = TARGET_NAMES[index];
        let fallbacks: Vec<TargetId> = TARGET_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, n)| tid(n))
            .collect();

        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("pin").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid(pinned)),
            emergency_fallback: fallbacks,
            priority: 0,
        });

        let req = request(&mut rng);
        let outcome = route(&s, &req);

        assert_eq!(
            outcome.candidates.first().map(|c| c.target.as_str()),
            Some(pinned),
            "seed {seed}: a fallback outranked a healthy pin: {:?}",
            order(&outcome)
        );
    }
}

#[test]
fn an_unavailable_pin_without_fallback_fails_closed() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x9111_dead);
        let mut s = snapshot(&mut rng);
        let pinned = TARGET_NAMES[rng.below(TARGET_NAMES.len())];

        if let Some(target) = s.targets.get_mut(&tid(pinned)) {
            target.admin_state = AdminState::Quarantined;
        }
        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("pin").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: Vec::new(),
            denies: Vec::new(),
            allows: Vec::new(),
            pin: Some(tid(pinned)),
            emergency_fallback: Vec::new(),
            priority: 0,
        });

        let req = request(&mut rng);
        assert!(
            route(&s, &req).candidates.is_empty(),
            "seed {seed}: an unavailable pin fell back without permission"
        );
    }
}

// -- Scoring -----------------------------------------------------------------

#[test]
fn scores_never_overflow_however_extreme_the_weights() {
    // Specification 6.3: "saturation arithmetic prevents overflow". A panic
    // here on a release build with overflow checks is a data-plane crash.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x0f10_0000);
        let mut s = snapshot(&mut rng);

        s.bindings.push(Binding {
            id: hypellm_core::ids::BindingId::new("extreme").expect("binding id"),
            scope: BindingScope::Principal(principal()),
            model: ModelSelector::Exact(alias()),
            preferences: vec![TargetPreference {
                selector: TargetSelector::Any,
                rank: u16::MAX,
                // Beyond the documented range in both directions.
                weight: if rng.bool() { i64::MAX } else { i64::MIN },
            }],
            denies: Vec::new(),
            allows: Vec::new(),
            pin: None,
            emergency_fallback: Vec::new(),
            priority: i32::MAX,
        });

        let req = request(&mut rng);
        let outcome = route(&s, &req);
        for candidate in &outcome.candidates {
            // Merely calling `score` exercises the saturating sum.
            let _ = candidate.score();
        }
    }
}

#[test]
fn the_candidate_order_is_a_total_order() {
    // Sorting is only well defined if the key is total. A partial key makes the
    // result depend on the sort implementation, which is exactly the
    // nondeterminism Appendix B forbids.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x7074_0000);
        let s = snapshot(&mut rng);
        let req = request(&mut rng);
        let outcome = route(&s, &req);

        let names = order(&outcome);
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "seed {seed}: a target appeared twice");
    }
}

#[test]
fn every_permitted_target_is_either_a_candidate_or_carries_an_exclusion() {
    // An operator reading the decision explorer must be able to account for
    // every target. One that is neither chosen nor explained is a hole in the
    // trace.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xacc0_0000);
        let s = snapshot(&mut rng);
        let req = request(&mut rng);
        let outcome = route(&s, &req);

        for name in TARGET_NAMES {
            let is_candidate = outcome.candidates.iter().any(|c| c.target.as_str() == *name);
            let is_excluded = outcome.exclusions.iter().any(|e| e.target.as_str() == *name);
            assert!(
                is_candidate ^ is_excluded,
                "seed {seed}: {name} is {}accounted for",
                if is_candidate && is_excluded { "doubly " } else { "un" }
            );
        }
    }
}

// -- Key restrictions --------------------------------------------------------

/// Route as a caller holding a key with `restriction`.
fn route_with_key(
    s: &PolicySnapshot,
    req: &CanonicalRequest,
    restriction: &KeyRestriction,
) -> RouteOutcome {
    let groups: Vec<GroupId> = Vec::new();
    let attempted: Vec<TargetId> = Vec::new();
    let ctx = RoutingContext {
        principal: &req.principal,
        groups: &groups,
        tenant: &req.tenant,
        attempted: &attempted,
        now_millis: 0,
        key: Some(restriction),
    };
    s.route(&ctx, req, &IdealLiveState)
}

const HOST_NAMES: &[&str] = &["spark-a", "spark-b"];

/// A random restriction over the generator's alias, targets and slaves, with
/// some targets placed on slaves so the host half is exercised too.
fn restriction(rng: &mut Rng, s: &mut PolicySnapshot) -> KeyRestriction {
    for name in TARGET_NAMES {
        if rng.bool() {
            let host = HOST_NAMES[rng.below(HOST_NAMES.len())];
            s.fleet_placement
                .insert(tid(name), HostId::new(host).expect("host id"));
        }
    }
    let subset = |rng: &mut Rng, names: &[&str]| -> Vec<String> {
        names
            .iter()
            .filter(|_| rng.bool())
            .map(|n| (*n).to_owned())
            .collect()
    };
    KeyRestriction {
        models: rng.bool().then(|| {
            let mut models = std::collections::BTreeSet::new();
            models.insert(if rng.bool() {
                alias()
            } else {
                AliasId::new("other").expect("alias id")
            });
            models
        }),
        targets: rng
            .bool()
            .then(|| subset(rng, TARGET_NAMES).iter().map(|n| tid(n)).collect()),
        hosts: rng.bool().then(|| {
            subset(rng, HOST_NAMES)
                .iter()
                .map(|h| HostId::new(h).expect("host id"))
                .collect()
        }),
        priority: None,
    }
}

#[test]
fn a_key_restriction_removes_exactly_what_it_names_and_adds_nothing() {
    // The principal's policy is the ceiling and a key may only narrow it. So
    // with a restriction the candidates must be the unrestricted candidates
    // less those it names, in the same order: never one more, never one
    // fewer, never reordered. A restriction that shifted a score would show
    // up here as a reordering.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x6b65_7900);
        let mut s = snapshot(&mut rng);
        let restriction = restriction(&mut rng, &mut s);
        let req = request(&mut rng);

        let before = route(&s, &req);
        let after = route_with_key(&s, &req, &restriction);

        let permitted = |target: &TargetId| {
            restriction.permits_alias(&req.requested_model)
                && restriction.permits_target(target)
                && s.fleet_placement
                    .get(target)
                    .is_none_or(|host| restriction.permits_host(host))
        };
        let expected: Vec<String> = before
            .candidates
            .iter()
            .filter(|c| permitted(&c.target))
            .map(|c| c.target.as_str().to_owned())
            .collect();
        assert_eq!(order(&after), expected, "seed {seed}: {restriction:?}");
        assert_eq!(
            after.candidates.iter().map(Candidate::score).collect::<Vec<_>>(),
            before
                .candidates
                .iter()
                .filter(|c| permitted(&c.target))
                .map(Candidate::score)
                .collect::<Vec<_>>(),
            "seed {seed}: a restriction changed a surviving score"
        );

        // Whatever it removed, it says why, and the reason is its own (or the
        // alias refusal, which is how a restricted alias must look).
        for c in &before.candidates {
            if !permitted(&c.target) {
                let reason = after
                    .exclusions
                    .iter()
                    .find(|e| e.target == c.target)
                    .map(|e| e.reason);
                assert!(
                    matches!(
                        reason,
                        Some(ExclusionReason::KeyRestricted | ExclusionReason::NotAuthorizedForAlias)
                    ),
                    "seed {seed}: {} was removed as {reason:?}",
                    c.target
                );
            }
        }

        // Deterministic, like every other routing input.
        assert_eq!(order(&route_with_key(&s, &req, &restriction)), order(&after), "seed {seed}");

        // And the models list only ever shrinks.
        let groups: Vec<GroupId> = Vec::new();
        let open = RoutingContext {
            principal: &req.principal,
            groups: &groups,
            tenant: &req.tenant,
            attempted: &[],
            now_millis: 0,
            key: None,
        };
        let keyed = RoutingContext { key: Some(&restriction), ..open };
        let visible_open: Vec<&AliasId> =
            s.servable_aliases(&open, Operation::Chat).iter().map(|a| &a.id).collect();
        for alias in s.servable_aliases(&keyed, Operation::Chat) {
            assert!(visible_open.contains(&&alias.id), "seed {seed}: a restriction revealed {}", alias.id);
        }
    }
}

#[test]
fn a_key_never_raises_its_principals_priority() {
    use hypellm_core::admission::PriorityClass::{Batch, Interactive, Standard};
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x7072_696f);
        let classes = [Interactive, Standard, Batch];
        let principal_class = classes[rng.below(3)];
        let restriction = KeyRestriction {
            priority: rng.bool().then(|| classes[rng.below(3)]),
            ..KeyRestriction::default()
        };
        let effective = restriction.cap_priority(principal_class);
        // `PriorityClass` orders interactive first; served first means smaller.
        assert!(effective >= principal_class, "seed {seed}: {restriction:?} raised {principal_class:?}");
        assert_eq!(
            effective,
            restriction.priority.map_or(principal_class, |key| key.max(principal_class)),
            "seed {seed}"
        );
    }
}

// -- Reservation conservation ------------------------------------------------

#[test]
fn every_reservation_is_released_exactly_once() {
    // Appendix B: "Every reservation is released exactly once on all success,
    // error, timeout, and cancellation paths." A leak here exhausts a scope's
    // concurrency and the router stops admitting anything.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x2e5e_0000);
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new());
        let controller = AdmissionController::new(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 32,
                ..ScopeLimits::UNLIMITED
            },
        );

        let target = tid(TARGET_NAMES[rng.below(TARGET_NAMES.len())]);

        for _ in 0..16 {
            let estimate = rng.below(500) as u64;
            let Ok(reservation) = controller.reserve(&tenant(), &principal(), &target, estimate)
            else {
                continue;
            };

            // Exercise every release path the specification names.
            match rng.below(3) {
                // Success: reconciled against reported usage.
                0 => reservation.commit(estimate.saturating_add(rng.below(100) as u64)),
                // Success with usage below the estimate.
                1 => reservation.commit(estimate / 2),
                // Error, timeout, or cancellation: dropped without commit.
                _ => drop(reservation),
            }
        }

        // Whatever path each took, nothing is still held.
        assert_eq!(
            controller.global().in_flight(),
            0,
            "seed {seed}: a reservation leaked"
        );
        assert_eq!(
            controller.global().acquired(),
            controller.global().released(),
            "seed {seed}: acquire and release counts diverged"
        );
    }
}

#[test]
fn committing_and_dropping_the_same_reservation_releases_it_once() {
    // `commit` consumes the value and `Drop` also runs. Appendix B says
    // *exactly* once, so the second path must be a no-op — a double release
    // would return capacity that was never held.
    for seed in 0..64 {
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new());
        let controller = AdmissionController::new(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: 4,
                ..ScopeLimits::UNLIMITED
            },
        );
        let target = tid("local:qwen");

        let reservation = controller
            .reserve(&tenant(), &principal(), &target, 10)
            .expect("reserve");
        reservation.commit(10);

        assert_eq!(controller.global().in_flight(), 0, "seed {seed}");
        assert_eq!(
            controller.global().acquired(),
            controller.global().released(),
            "seed {seed}"
        );
    }
}

#[test]
fn concurrency_is_never_exceeded_under_interleaved_reservations() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x600d_0000);
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new());
        const LIMIT: u32 = 4;
        let controller = AdmissionController::new(
            Arc::clone(&clock),
            ScopeLimits {
                max_concurrency: LIMIT,
                ..ScopeLimits::UNLIMITED
            },
        );
        let target = tid("local:qwen");

        let mut held = Vec::new();
        for _ in 0..24 {
            if rng.bool() && !held.is_empty() {
                let index = rng.below(held.len());
                let reservation = held.swap_remove(index);
                drop(reservation);
            } else if let Ok(reservation) =
                controller.reserve(&tenant(), &principal(), &target, 1)
            {
                held.push(reservation);
            }

            assert!(
                controller.global().in_flight() <= LIMIT,
                "seed {seed}: concurrency limit exceeded"
            );
        }
    }
}
