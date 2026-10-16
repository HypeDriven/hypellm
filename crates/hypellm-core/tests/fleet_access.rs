//! Property tests over fleet grants: who may use which slave, and which model
//! on it.
//!
//! The rule lives in `hypellm_core::fleet_access::permits`; routing applies it
//! as an eligibility filter and `/v1/models` hides an alias it puts entirely
//! out of reach. Each property is a sentence from the module contract stated
//! over many generated arrangements, seeded so a failure reproduces from the
//! number in its message.
//!
//! The fixtures are adversarial where it matters: the slave a caller is kept
//! off is frequently the local, cheap one, which is the target scoring would
//! otherwise choose first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, CostClass, Message, Modality, Operation, RequestLimits,
    Role, RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::decision::ExclusionReason;
use hypellm_core::fleet_access::{FleetAccessDefault, FleetGrant, FleetModelSelector, HostSelector, permits};
use hypellm_core::ids::{
    AliasId, BindingId, GroupId, HostId, PrincipalId, ProviderId, RequestId, TargetId, TenantId,
};
use hypellm_core::policy::{
    Binding, BindingScope, IdealLiveState, ModelSelector, PolicySnapshot, RouteOutcome,
    RoutingContext, TargetPreference, TargetSelector,
};
use hypellm_core::target::{
    AdminState, Alias, Capabilities, Endpoint, EndpointScheme, Provider, ProviderFamily, Target,
};
use hypellm_core::time::TestClock;

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

// -- Fleet generators --------------------------------------------------------

const HOSTS: &[&str] = &["spark", "gpu2", "gpu3"];
const PRINCIPALS: &[&str] = &["user:42", "user:7", "svc:ci"];
const GROUPS: &[&str] = &["devs", "ops"];
const TENANTS: &[&str] = &["acme", "globex"];

fn hid(name: &str) -> HostId {
    HostId::new(name).expect("host id")
}

/// A caller: one principal, some groups, one tenant.
struct Caller {
    principal: PrincipalId,
    groups: Vec<GroupId>,
    tenant: TenantId,
}

impl Caller {
    fn ctx(&self) -> RoutingContext<'_> {
        RoutingContext {
            principal: &self.principal,
            groups: &self.groups,
            tenant: &self.tenant,
            attempted: &[],
            now_millis: 0,
            key: None,
        }
    }
}

fn caller(rng: &mut Rng) -> Caller {
    Caller {
        principal: PrincipalId::new(PRINCIPALS[rng.below(PRINCIPALS.len())]).expect("principal"),
        groups: GROUPS
            .iter()
            .filter(|_| rng.bool())
            .map(|g| GroupId::new(*g).expect("group"))
            .collect(),
        tenant: TenantId::new(TENANTS[rng.below(TENANTS.len())]).expect("tenant"),
    }
}

fn the_caller() -> Caller {
    Caller {
        principal: principal(),
        groups: vec![GroupId::new("devs").expect("group")],
        tenant: tenant(),
    }
}

fn scope(rng: &mut Rng) -> BindingScope {
    match rng.below(4) {
        0 => BindingScope::Principal(PrincipalId::new(PRINCIPALS[rng.below(PRINCIPALS.len())]).expect("p")),
        1 => BindingScope::Group(GroupId::new(GROUPS[rng.below(GROUPS.len())]).expect("g")),
        2 => BindingScope::Tenant(TenantId::new(TENANTS[rng.below(TENANTS.len())]).expect("t")),
        _ => BindingScope::Global,
    }
}

fn host_selector(rng: &mut Rng) -> HostSelector {
    if rng.below(3) == 0 {
        HostSelector::Any
    } else {
        HostSelector::Exact(hid(HOSTS[rng.below(HOSTS.len())]))
    }
}

fn model_selector(rng: &mut Rng) -> FleetModelSelector {
    match rng.below(4) {
        0 => FleetModelSelector::Alias(ModelSelector::Any),
        1 => FleetModelSelector::Alias(ModelSelector::Exact(alias())),
        2 => FleetModelSelector::Alias(ModelSelector::Prefix("co".to_owned())),
        _ => FleetModelSelector::Target(tid(TARGET_NAMES[rng.below(TARGET_NAMES.len())])),
    }
}

fn fleet_grant(rng: &mut Rng, n: usize, allow: Option<bool>) -> FleetGrant {
    FleetGrant {
        id: BindingId::new(format!("fg{n}")).expect("id"),
        scope: scope(rng),
        host: host_selector(rng),
        model: model_selector(rng),
        allow: allow.unwrap_or_else(|| rng.bool()),
    }
}

fn grants(rng: &mut Rng) -> Vec<FleetGrant> {
    let count = rng.below(8);
    (0..count).map(|n| fleet_grant(rng, n, None)).collect()
}

fn default(rng: &mut Rng) -> FleetAccessDefault {
    if rng.bool() { FleetAccessDefault::Allow } else { FleetAccessDefault::Deny }
}

/// Every (target, host) pair a target could be placed on.
fn placements() -> Vec<(TargetId, HostId)> {
    TARGET_NAMES
        .iter()
        .flat_map(|t| HOSTS.iter().map(move |h| (tid(t), hid(h))))
        .collect()
}

/// The routing snapshot with some targets placed on slaves and some not.
///
/// The first target is always placed, and it is the local one with the lowest
/// cost class: the target scoring would choose first is exactly the one a
/// fleet deny has to keep the caller off.
fn fleet_snapshot(rng: &mut Rng) -> PolicySnapshot {
    let mut s = snapshot(rng);
    for (n, name) in TARGET_NAMES.iter().enumerate() {
        if n == 0 {
            if let Some(t) = s.targets.get_mut(&tid(name)) {
                t.is_local = true;
                t.cost_class = CostClass(0);
            }
        }
        if n == 0 || rng.bool() {
            s.fleet_placement.insert(tid(name), hid(HOSTS[rng.below(HOSTS.len())]));
        }
    }
    s.fleet_grants = grants(rng);
    s.fleet_access_default = default(rng);
    s
}

fn route_as(s: &PolicySnapshot, caller: &Caller, req: &CanonicalRequest) -> RouteOutcome {
    s.route(&caller.ctx(), req, &IdealLiveState)
}

// -- Monotonicity ------------------------------------------------------------

#[test]
fn adding_a_fleet_deny_never_widens_access() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xf1ee_7001);
        let base = grants(&mut rng);
        let default = default(&mut rng);
        let mut with_deny = base.clone();
        with_deny.push(fleet_grant(&mut rng, 99, Some(false)));
        let who = caller(&mut rng);
        for (target, host) in placements() {
            let after = permits(&with_deny, default, &who.ctx(), &alias(), &target, &host);
            let before = permits(&base, default, &who.ctx(), &alias(), &target, &host);
            assert!(!after || before, "seed {seed}: a deny opened {target} on {host}");
        }
    }
}

#[test]
fn adding_a_fleet_allow_never_narrows_access() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xa110_7001);
        let base = grants(&mut rng);
        let default = default(&mut rng);
        let mut with_allow = base.clone();
        with_allow.push(fleet_grant(&mut rng, 99, Some(true)));
        let who = caller(&mut rng);
        for (target, host) in placements() {
            let before = permits(&base, default, &who.ctx(), &alias(), &target, &host);
            let after = permits(&with_allow, default, &who.ctx(), &alias(), &target, &host);
            assert!(!before || after, "seed {seed}: an allow closed {target} on {host}");
        }
    }
}

#[test]
fn a_principal_wide_deny_is_not_reopened_by_any_group_tenant_or_global_grant() {
    // Specification 6.1's sticky deny, for machines: lower-precedence scopes
    // cannot re-enable what a higher one closed, however specific they are.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x5717_c4d1);
        let who = the_caller();
        let mut set: Vec<FleetGrant> = (0..8)
            .map(|n| {
                let mut g = fleet_grant(&mut rng, n, Some(true));
                if matches!(g.scope, BindingScope::Principal(_)) {
                    g.scope = BindingScope::Global;
                }
                g
            })
            .collect();
        set.push(FleetGrant {
            id: BindingId::new("closed").expect("id"),
            scope: BindingScope::Principal(principal()),
            host: HostSelector::Any,
            model: FleetModelSelector::Alias(ModelSelector::Any),
            allow: false,
        });
        rng.shuffle(&mut set);
        for (target, host) in placements() {
            assert!(
                !permits(&set, FleetAccessDefault::Allow, &who.ctx(), &alias(), &target, &host),
                "seed {seed}: {target} on {host} reopened below a principal deny"
            );
        }
    }
}

#[test]
fn the_answer_does_not_depend_on_the_order_grants_were_written() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x0dde_0dde);
        let set = grants(&mut rng);
        let default = default(&mut rng);
        let mut shuffled = set.clone();
        rng.shuffle(&mut shuffled);
        let who = caller(&mut rng);
        for (target, host) in placements() {
            assert_eq!(
                permits(&set, default, &who.ctx(), &alias(), &target, &host),
                permits(&shuffled, default, &who.ctx(), &alias(), &target, &host),
                "seed {seed}: {target} on {host}"
            );
        }
    }
}

#[test]
fn a_caller_no_grant_mentions_gets_the_default_in_both_directions() {
    // "Existing credentials can use any slave and any model" is the `allow`
    // default; `deny` must be exactly as total in the other direction.
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0xdefa_0017);
        // Grants for everyone except the caller: other principals, a group
        // the caller is not in, a tenant that is not theirs. No global.
        let others: Vec<FleetGrant> = (0..6)
            .map(|n| {
                let mut g = fleet_grant(&mut rng, n, None);
                g.scope = match rng.below(3) {
                    0 => BindingScope::Principal(PrincipalId::new("user:7").expect("p")),
                    1 => BindingScope::Group(GroupId::new("ops").expect("g")),
                    _ => BindingScope::Tenant(TenantId::new("globex").expect("t")),
                };
                g
            })
            .collect();
        let who = the_caller();
        for default in [FleetAccessDefault::Allow, FleetAccessDefault::Deny] {
            for (target, host) in placements() {
                assert_eq!(
                    permits(&others, default, &who.ctx(), &alias(), &target, &host),
                    default == FleetAccessDefault::Allow,
                    "seed {seed}: {target} on {host} under default {default}"
                );
            }
        }
    }
}

// -- Routing -----------------------------------------------------------------

#[test]
fn routing_keeps_a_denied_caller_off_the_slave_as_a_filter_not_a_penalty() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x0001_7e57);
        let s = fleet_snapshot(&mut rng);
        let req = request(&mut rng);
        let who = the_caller();
        let outcome = route_as(&s, &who, &req);

        let mut open = s.clone();
        open.fleet_grants.clear();
        open.fleet_access_default = FleetAccessDefault::Allow;
        let unrestricted = route_as(&open, &who, &req);

        for candidate in &outcome.candidates {
            assert!(
                s.fleet_access_permits(&who.ctx(), &alias(), &candidate.target),
                "seed {seed}: {} was offered on a slave the caller is denied",
                candidate.target
            );
        }
        for exclusion in &outcome.exclusions {
            if exclusion.reason == ExclusionReason::FleetAccessDenied {
                assert!(!s.fleet_access_permits(&who.ctx(), &alias(), &exclusion.target));
            }
        }
        // A filter removes; it does not reorder. The survivors keep exactly
        // the order and scores they had with no fleet grant at all.
        let kept: Vec<(String, i64)> = unrestricted
            .candidates
            .iter()
            .filter(|c| s.fleet_access_permits(&who.ctx(), &alias(), &c.target))
            .map(|c| (c.target.as_str().to_owned(), c.score()))
            .collect();
        let got: Vec<(String, i64)> = outcome
            .candidates
            .iter()
            .map(|c| (c.target.as_str().to_owned(), c.score()))
            .collect();
        assert_eq!(got, kept, "seed {seed}");
    }
}

#[test]
fn targets_that_run_on_no_slave_are_untouched_by_fleet_grants() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x0000_f1ee);
        let mut s = fleet_snapshot(&mut rng);
        // The harshest setting: deny by default and a global deny of
        // everything. Unplaced targets must not notice.
        s.fleet_access_default = FleetAccessDefault::Deny;
        s.fleet_grants.clear();
        s.fleet_grants.push(FleetGrant {
            id: BindingId::new("all-off").expect("id"),
            scope: BindingScope::Global,
            host: HostSelector::Any,
            model: FleetModelSelector::Alias(ModelSelector::Any),
            allow: false,
        });
        let req = request(&mut rng);
        let who = caller(&mut rng);

        let mut unmanaged = s.clone();
        unmanaged.fleet_grants.clear();
        unmanaged.fleet_access_default = FleetAccessDefault::Allow;

        let restricted = route_as(&s, &who, &req);
        let reference = route_as(&unmanaged, &who, &req);
        let unplaced = |o: &RouteOutcome| -> Vec<(String, i64)> {
            o.candidates
                .iter()
                .filter(|c| !s.fleet_placement.contains_key(&c.target))
                .map(|c| (c.target.as_str().to_owned(), c.score()))
                .collect()
        };
        assert_eq!(unplaced(&restricted), unplaced(&reference), "seed {seed}");
        assert!(
            restricted
                .candidates
                .iter()
                .all(|c| !s.fleet_placement.contains_key(&c.target)),
            "seed {seed}: a placed target survived a global deny"
        );
    }
}

#[test]
fn the_models_list_hides_an_alias_only_when_every_target_is_out_of_reach() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x30de_1500);
        let s = fleet_snapshot(&mut rng);
        let who = the_caller();
        let listed = s
            .servable_aliases(&who.ctx(), Operation::Chat)
            .iter()
            .any(|a| a.id == alias());
        let reachable = s.aliases[&alias()]
            .permitted_targets
            .iter()
            .any(|t| s.fleet_access_permits(&who.ctx(), &alias(), t));
        assert_eq!(listed, reachable, "seed {seed}");
        // The management view of what a tenant can reach is not shrunk by one
        // caller's fleet grants.
        assert!(s.visible_aliases(&who.ctx(), Operation::Chat).iter().any(|a| a.id == alias()));
    }
}

#[test]
fn fleet_access_denied_is_a_security_filter() {
    assert!(ExclusionReason::FleetAccessDenied.is_security_constraint());
    assert!(!ExclusionReason::FleetAccessDenied.is_fleet_constraint());
}

#[test]
fn an_allow_and_a_deny_at_the_same_level_resolve_to_deny() {
    for seed in 0..CASES {
        let mut rng = Rng::new(u64::from(seed) ^ 0x7e1e_d0e5);
        let allow = fleet_grant(&mut rng, 1, Some(true));
        let deny = FleetGrant {
            id: BindingId::new("twin").expect("id"),
            allow: false,
            ..allow.clone()
        };
        let mut pair = vec![allow.clone(), deny];
        rng.shuffle(&mut pair);
        let who = caller(&mut rng);
        for (target, host) in placements() {
            // Whether the grant applies at all: alone, under a deny default,
            // it opens exactly what it covers.
            let applies = permits(
                std::slice::from_ref(&allow),
                FleetAccessDefault::Deny,
                &who.ctx(),
                &alias(),
                &target,
                &host,
            );
            let got = permits(&pair, FleetAccessDefault::Allow, &who.ctx(), &alias(), &target, &host);
            assert_eq!(got, !applies, "seed {seed}: {target} on {host}");
        }
    }
}
