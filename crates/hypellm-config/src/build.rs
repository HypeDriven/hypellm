//! Building a validated, activatable configuration from a parsed document.
//!
//! Specification 11: "The runtime parses into a validated typed snapshot,
//! resolves all references, verifies invariants, computes a digest, and swaps a
//! single shared pointer."
//!
//! Reference resolution and invariant checking happen **here**, at load time,
//! not at first use. A target naming a provider that does not exist, an alias
//! naming a target that does not exist, a cleartext endpoint pointing at the
//! public internet, or a generic adapter used without the opt-in are all
//! rejected before the snapshot can be activated. The alternative — discovering
//! them on the request path — means the failure appears as a 503 to a caller
//! rather than as a refused deployment.

use crate::parse::{Document, Position};
use crate::schema::{ConfigError, Fields, validate_record};
use hypellm_core::canonical::{CostClass, Modality, Operation, Residency};
use hypellm_core::ids::{
    AliasId, BindingId, CredentialRef, GroupId, PrincipalId, ProviderId, TargetId, TenantId,
};
use hypellm_core::netaddr::{self, EgressProfile};
use hypellm_core::policy::{
    AliasGrant, Binding, BindingScope, ModelSelector, PolicySnapshot, TargetPreference,
    TargetSelector,
};
use hypellm_core::rbac::Role;
use hypellm_core::target::{
    AdminState, Alias, Capabilities, Endpoint, EndpointScheme, Provider, ProviderFamily, Target,
};
use hypellm_crypto::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Router-wide settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Address the inference listener binds.
    pub inference_listen: String,
    /// Address the management listener binds.
    pub admin_listen: String,
    /// Address the metrics listener binds, when separate.
    pub metrics_listen: Option<String>,
    /// Maximum inbound body size.
    pub max_body_bytes: u64,
    /// Maximum inbound head size.
    pub max_head_bytes: u32,
    /// Whether the generic OpenAI-compatible adapter may be configured.
    ///
    /// Specification 25: "Disabled by default; fixed endpoint and explicit
    /// capabilities required."
    pub allow_generic_adapter: bool,
    /// Whether the deterministic weighted tie-breaker is enabled.
    pub weighted_tie_break: bool,
    /// Observed failure percentage above which a target is refused outright
    /// (specification 6.2). 100 disables the filter.
    pub max_failure_percent: u32,
    /// Default end-to-end deadline.
    pub default_deadline_ms: u64,
    /// Maximum attempts in one retry chain.
    pub max_attempts: u32,
    /// Total elapsed retry budget.
    pub retry_budget_ms: u64,
    /// OIDC issuer, when Google sign-in is configured.
    pub oidc_issuer: Option<String>,
    /// OIDC client identifier.
    pub oidc_client_id: Option<String>,
    /// The fixed authorization endpoint.
    pub oidc_authorization_endpoint: Option<String>,
    /// The fixed token endpoint.
    pub oidc_token_endpoint: Option<String>,
    /// The fixed redirect URI the router owns.
    pub oidc_redirect_uri: Option<String>,
    /// Permitted hosted domains.
    pub oidc_hosted_domains: Vec<String>,
    /// Unix socket of the identity verifier that checks token signatures.
    ///
    /// Specification 9.1: "Strict profile delegates them to an approved local
    /// identity/TLS verifier service over a narrow authenticated local
    /// interface."
    pub oidc_verifier_socket: Option<String>,
    /// Exact origins permitted to call the management API cross-origin.
    pub cors_origins: Vec<String>,
    /// Session idle lifetime.
    pub session_idle_secs: u64,
    /// Session absolute lifetime.
    pub session_absolute_secs: u64,
    /// Unix socket of the outbound TLS helper.
    pub tls_helper_socket: Option<String>,
    /// Directory holding durable state.
    pub state_dir: String,
    /// Audit records between signed checkpoints.
    pub audit_checkpoint_interval: u64,
    /// Whether prompt and completion capture is enabled at all.
    ///
    /// Specification 10: "Prompt and completion bodies are not logged by
    /// default."
    pub capture_bodies: bool,
    /// Interval between SSE keepalive comments.
    pub keepalive_interval_ms: u64,
    /// How long a client may stall before its upstream is cancelled.
    pub slow_client_timeout_ms: u64,
    /// How long a request may wait in the admission queue for a concurrency
    /// slot before it is refused.
    ///
    /// Specification 3.2 lists queued requests as a bounded resource and makes
    /// the "queue timeout mandatory", so there is no way to express an
    /// unbounded wait: zero disables queueing outright rather than meaning
    /// "forever". The effective wait is always the smaller of this and what
    /// remains of the request deadline, which is what makes specification 12's
    /// "requests past deadline are removed without invoking the provider" hold
    /// for a queued request as well as a dispatched one.
    pub queue_timeout_ms: u64,
    /// The principal a break-glass sign-in authenticates as.
    ///
    /// Specification 22.4 requires a preprovisioned local break-glass method.
    /// Both this and `break_glass_tenant` must be set for it to be available at
    /// all: an unset pair means the endpoint does not exist, rather than the
    /// router inventing an identity with administrative permissions. The
    /// principal still needs a `role_binding` — holding the token proves who
    /// you are, not what you may do.
    pub break_glass_principal: Option<String>,
    /// The tenant a break-glass session belongs to.
    pub break_glass_tenant: Option<String>,
    /// How long a break-glass session lives, in seconds.
    ///
    /// Specification 22.4: break-glass access is "time-limited". Short on
    /// purpose and independent of the ordinary session lifetime, because this
    /// one is for the duration of an incident.
    pub break_glass_ttl_secs: u64,
    /// Maximum simultaneous client connections on the inference listener.
    ///
    /// Zero keeps the compiled-in profile default. Clamped to a hard ceiling
    /// rather than trusted: this is the bound that keeps a connection flood
    /// from becoming a memory exhaustion, so a configuration mistake must not
    /// be able to remove it.
    ///
    /// The management listener keeps its own, much smaller, profile default:
    /// specification 3.1 separates the two planes' limits, and one number that
    /// governed both would let inference sizing decide how many operators can
    /// reach the control plane.
    pub max_connections: u64,
    /// Maximum requests one keep-alive connection may serve. Zero keeps the
    /// profile default.
    pub max_requests_per_connection: u32,
    /// Per-read socket timeout in milliseconds. Zero keeps the profile default.
    pub read_timeout_ms: u64,
    /// How many routers share this deployment's quotas.
    ///
    /// Specification 12 allows "an authoritative allocator **or conservative
    /// node partitions**" for admission-critical quotas, and this is the
    /// second. Every quota limit is divided by this number, so N routers each
    /// enforcing their share honour the configured figure between them without
    /// consensus — which specification 2.2 makes a non-goal (`DI-029`).
    ///
    /// Zero or one means a single router and leaves every limit as written.
    ///
    /// Setting it does **not** make the router highly available: state, keys,
    /// and the audit chain remain single-node, and two routers must still not
    /// share a state directory. It makes the *quota arithmetic* correct for a
    /// deployment that fans out behind a load balancer, which is otherwise the
    /// part that silently multiplies every tenant's limit by the node count.
    pub quota_partitions: u32,
    /// Stack size for each connection thread, in KiB. Zero keeps the profile
    /// default.
    ///
    /// One thread per connection means the practical connection ceiling is
    /// address space divided by this number, not [`Settings::max_connections`]
    /// (`DI-001`). The default is deliberately small so that a high
    /// `max_connections` is actually reachable; an operator whose handlers need
    /// deeper stacks — a deeply nested tool-call schema, say — can trade
    /// ceiling for headroom here rather than editing the binary.
    pub connection_stack_kib: u64,
    /// How long an idle keep-alive connection may wait for its next request,
    /// in milliseconds. Zero keeps the profile default.
    ///
    /// Not to be confused with [`Settings::keepalive_interval_ms`], which is
    /// how often the router writes a comment into an *open SSE stream*
    /// (specification 14). One governs connection reuse, the other stream
    /// liveness, and tuning either must not move the other.
    pub keepalive_timeout_ms: u64,
    /// Path of the control socket used to request a graceful shutdown.
    ///
    /// Defaults to `control.sock` inside the state directory. A Unix socket
    /// path is limited to about 108 bytes by the kernel, so a deep state
    /// directory needs this set explicitly to somewhere short.
    pub control_socket: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            inference_listen: "127.0.0.1:8080".to_owned(),
            admin_listen: "127.0.0.1:8081".to_owned(),
            metrics_listen: None,
            max_body_bytes: 16 * 1024 * 1024,
            max_head_bytes: 32 * 1024,
            allow_generic_adapter: false,
            weighted_tie_break: false,
            max_failure_percent: 100,
            default_deadline_ms: 120_000,
            max_attempts: 3,
            retry_budget_ms: 30_000,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_authorization_endpoint: None,
            oidc_token_endpoint: None,
            oidc_redirect_uri: None,
            oidc_hosted_domains: Vec::new(),
            oidc_verifier_socket: None,
            cors_origins: Vec::new(),
            session_idle_secs: 1_800,
            session_absolute_secs: 43_200,
            tls_helper_socket: None,
            state_dir: "./state".to_owned(),
            audit_checkpoint_interval: 1_000,
            capture_bodies: false,
            keepalive_interval_ms: 15_000,
            slow_client_timeout_ms: 30_000,
            // Long enough for a slot to free on a busy router, short enough
            // that a caller learns the router is saturated rather than sitting
            // through most of its deadline to find out.
            queue_timeout_ms: 5_000,
            max_connections: 0,
            quota_partitions: 0,
            connection_stack_kib: 0,
            max_requests_per_connection: 0,
            read_timeout_ms: 0,
            keepalive_timeout_ms: 0,
            break_glass_principal: None,
            break_glass_tenant: None,
            break_glass_ttl_secs: 900,
            control_socket: None,
        }
    }
}

/// A tenant's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantConfig {
    /// Identifier.
    pub id: TenantId,
    /// Whether global defaults are inherited.
    pub inherit_global: bool,
    /// Whether the tenant is active.
    pub active: bool,
    /// Default data region.
    pub residency: Option<Residency>,
    /// Retention window for captured data.
    pub retention_days: u32,
    /// The most expensive class this tenant's requests may select.
    ///
    /// Specification 6.2: "Estimated cost class and actual policy ceiling
    /// permit selection." The ceiling is policy, so it lives here rather than
    /// in a request field a caller could raise.
    pub max_cost_class: Option<CostClass>,
}

/// A quota scope selector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QuotaScope {
    /// Router-wide.
    Global,
    /// One tenant.
    Tenant(TenantId),
    /// One principal.
    Principal(PrincipalId),
    /// One target.
    Target(TargetId),
    /// One alias, optionally for a single operation.
    ///
    /// Specification 12's admission table has an "Alias/model" layer carrying
    /// "operation-specific request/token and context limits". The operation is
    /// part of the scope rather than a separate field because two quotas on the
    /// same alias for different operations are different scopes, and giving
    /// them one identity would make the effective limit depend on record order.
    Alias {
        /// The alias the quota applies to.
        alias: AliasId,
        /// The operation it is restricted to, or every operation.
        operation: Option<Operation>,
    },
}

/// How a quota scope is written in the configuration grammar.
///
/// Used in errors so the message names the record the operator has to edit,
/// spelled the way they spelled it.
fn quota_scope_label(scope: &QuotaScope) -> String {
    match scope {
        QuotaScope::Global => "global".to_owned(),
        QuotaScope::Tenant(id) => format!("tenant:{id}"),
        QuotaScope::Principal(id) => format!("principal:{id}"),
        QuotaScope::Target(id) => format!("target:{id}"),
        QuotaScope::Alias { alias, operation } => operation.map_or_else(
            || format!("alias:{alias}"),
            |op| format!("alias:{alias} operation={}", op.as_str()),
        ),
    }
}

/// Global byte-rate limits, from the `global` quota record.
///
/// Specification 12 places "input bytes/s, output bytes/s" at the Global layer
/// and nowhere else, so these ride on the global quota rather than on
/// `ScopeLimits` — a per-scope field that only ever applied to one scope would
/// invite an operator to set it somewhere it does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ByteRates {
    /// Bytes per second read from clients. Zero means unlimited.
    pub input_per_second: u64,
    /// Burst allowance for the input bucket, in bytes.
    pub input_burst: u64,
    /// Bytes per second written to clients. Zero means unlimited.
    pub output_per_second: u64,
    /// Burst allowance for the output bucket, in bytes.
    pub output_burst: u64,
}

/// A configured quota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    /// What it applies to.
    pub scope: QuotaScope,
    /// The limits.
    pub limits: hypellm_core::admission::ScopeLimits,
    /// Global byte-rate limits. Only meaningful on the `global` scope.
    pub byte_rates: ByteRates,
    /// The admission-queue class of requests in this scope.
    ///
    /// Specification 12 orders the queue by "tenant and priority class". The
    /// class lives on the quota record because that is where the rest of a
    /// scope's admission policy already lives: an operator setting a tenant's
    /// concurrency and its service class edits one record, and the two cannot
    /// end up describing different scopes.
    pub class: hypellm_core::admission::PriorityClass,
}

/// One target's price, from a stated date.
///
/// Amounts are **minor currency units per million tokens** — integers, not
/// floats. Money in binary floating point is wrong in a way that compounds, and
/// Appendix B's determinism requirement means two routers must compute the same
/// figure from the same inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceSchedule {
    /// The target this price applies to.
    pub target: TargetId,
    /// Minor units per million input tokens.
    pub input_per_million: u64,
    /// Minor units per million output tokens.
    pub output_per_million: u64,
    /// Minor units per million cached input tokens, which most providers
    /// discount.
    pub cached_input_per_million: u64,
    /// The currency, as a display token. The router does no conversion: two
    /// prices in different currencies are two numbers, never one sum.
    pub currency: String,
    /// Wall-clock milliseconds from which this price applies.
    ///
    /// The newest schedule whose date has passed wins, so a future-dated price
    /// can be published ahead of time without taking effect early.
    pub effective_from_millis: u64,
}

impl PriceSchedule {
    /// The cost of `tokens` at this price, in minor currency units.
    ///
    /// Integer arithmetic throughout, rounding **up**: an estimate that is too
    /// low is the one an operator acts on and regrets. Saturating, so no token
    /// count can overflow the figure into a small number.
    #[must_use]
    pub const fn cost_minor_units(&self, input: u64, output: u64, cached_input: u64) -> u64 {
        charge(input, self.input_per_million)
            .saturating_add(charge(output, self.output_per_million))
            .saturating_add(charge(cached_input, self.cached_input_per_million))
    }
}

/// `tokens` at `rate` per million, in minor units, rounded up.
const fn charge(tokens: u64, rate: u64) -> u64 {
    const PER: u64 = 1_000_000;
    tokens
        .saturating_mul(rate)
        .saturating_add(PER - 1)
        .saturating_div(PER)
}

/// The price in effect for `target` at `now_millis`, if one is configured.
///
/// The newest schedule whose date has passed wins, so a future-dated price can
/// be published ahead of time without taking effect early — which is what makes
/// "effective dates" useful rather than a field that has to be edited at
/// midnight.
#[must_use]
pub fn price_in_effect<'a>(
    prices: &'a [PriceSchedule],
    target: &TargetId,
    now_millis: u64,
) -> Option<&'a PriceSchedule> {
    prices
        .iter()
        .filter(|price| price.target == *target)
        .filter(|price| price.effective_from_millis <= now_millis)
        .max_by_key(|price| price.effective_from_millis)
}

/// A role binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBinding {
    /// The subject.
    pub subject: RoleSubject,
    /// The role granted.
    pub role: Role,
}

/// Who a role binding applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleSubject {
    /// One principal.
    Principal(PrincipalId),
    /// Every member of a group.
    Group(GroupId),
}

/// A binding from an external identity to a local principal.
///
/// Specification 9.1 makes the stable identity the `(iss, sub)` pair and says
/// authorization is "by local role binding, never by email domain".
/// Specification 25 adds: "do not infer Google group membership from email
/// domain."
///
/// This record is what makes a Google sign-in resolve to *someone*. Without it
/// there is no honest answer to "which principal is this, and in which
/// tenant": the identity key is not a valid identifier, and picking a tenant by
/// map order would put every signed-in operator into whichever tenant happened
/// to sort first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBinding {
    /// The `iss` claim, exactly as the provider issues it.
    ///
    /// Free-form rather than an identifier: it is a URL, and the router does
    /// not get to choose its shape.
    pub issuer: String,
    /// The `sub` claim: immutable within the issuer, and the only field that
    /// identifies the human. Email is an attribute and may be reassigned.
    pub subject: String,
    /// The local principal this identity signs in as.
    pub principal: PrincipalId,
    /// The tenant that principal belongs to.
    pub tenant: TenantId,
    /// A description for the management API.
    pub description: Option<String>,
}

/// A named set of principals, declared by an administrator.
///
/// Specification 25 settles where membership comes from: "Local role bindings
/// or separately provisioned directory sync; do not infer Google group
/// membership from email domain." Membership is therefore configuration, never
/// a token claim and never derived from an identifier's shape.
///
/// Groups are tenant-scoped. Specification 6.1 places group bindings at
/// precedence 3 and 4, above tenant defaults, so a group name shared across
/// tenants would let one tenant's binding take precedence over another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group identifier.
    pub id: GroupId,
    /// The tenant that owns it.
    pub tenant: TenantId,
    /// The principals that belong to it.
    pub members: BTreeSet<PrincipalId>,
    /// A description for the management API.
    pub description: Option<String>,
}

/// Metadata about a credential. Never the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMeta {
    /// The opaque reference.
    pub id: CredentialRef,
    /// Which providers or tenants it covers.
    pub scope: Vec<String>,
    /// A description.
    pub description: Option<String>,
    /// Rotation interval.
    pub rotates_after_days: u32,
}

/// A fully validated configuration, ready to activate.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The routing snapshot.
    pub snapshot: PolicySnapshot,
    /// Router-wide settings.
    pub settings: Settings,
    /// Tenants.
    pub tenants: BTreeMap<TenantId, TenantConfig>,
    /// Quotas.
    pub quotas: Vec<Quota>,
    /// Role bindings.
    pub roles: Vec<RoleBinding>,
    /// Group membership, keyed by group.
    pub groups: Vec<Group>,
    /// External identities bound to local principals.
    pub identities: Vec<IdentityBinding>,
    /// Credential metadata.
    pub credentials: Vec<CredentialMeta>,
    /// Price schedule, for cost *reporting*.
    ///
    /// Specification 25 recommends "configured price schedule with effective
    /// dates"; a billing *system* is among the things the specification says
    /// this router is not, and this is not one. It produces an operator-facing
    /// estimate of spend from token counts that are themselves sometimes
    /// estimates — see
    /// `UsageTotals::estimated_requests`, which is why the figure is reported
    /// as an estimate and never as an amount owed.
    pub prices: Vec<PriceSchedule>,
    /// Egress profile per provider.
    pub egress_profiles: BTreeMap<ProviderId, EgressProfile>,
    /// The canonical text this was built from.
    pub canonical: String,
    /// Digest of the canonical text.
    pub digest: Digest,
}

impl ValidatedConfig {
    /// Short digest, for logs and the session response.
    #[must_use]
    pub fn digest_short(&self) -> String {
        self.digest.short()
    }
}

/// Read a field and construct a validated identifier from it.
///
/// A macro rather than a function because the identifier constructors are
/// generic over `impl Into<String>`, which cannot be passed as a
/// higher-ranked function value.
macro_rules! id_field {
    ($fields:expr, $key:expr, $ty:ty) => {{
        let raw = $fields.str_field($key)?;
        <$ty>::new(raw).map_err(|e| {
            $fields.error(
                "invalid_identifier",
                format!("field '{}' value '{}' is invalid: {}", $key, raw, e),
            )
        })
    }};
}

/// Build and validate a configuration.
pub fn build(document: &Document, version: u64) -> Result<ValidatedConfig, Vec<ConfigError>> {
    let mut errors: Vec<ConfigError> = Vec::new();

    for record in &document.records {
        if let Err(e) = validate_record(record) {
            errors.push(e);
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // Singleton enforcement.
    for schema in crate::schema::SCHEMAS.iter().filter(|s| s.singleton) {
        let count = document.of_kind(schema.kind).count();
        if count > 1 {
            errors.push(ConfigError::new(
                "duplicate_singleton",
                format!("at most one '{}' record is permitted", schema.kind),
                document
                    .of_kind(schema.kind)
                    .nth(1)
                    .map_or(Position { line: 1, column: 1 }, |r| r.position),
            ));
        }
    }

    let settings = match build_settings(document) {
        Ok(s) => s,
        Err(e) => {
            errors.push(e);
            Settings::default()
        }
    };

    let tenants = collect(document, "tenant", &mut errors, build_tenant);
    let mut tenant_map: BTreeMap<TenantId, TenantConfig> = BTreeMap::new();
    for t in tenants {
        if tenant_map.insert(t.id.clone(), t.clone()).is_some() {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate tenant '{}'", t.id),
                Position { line: 0, column: 0 },
            ));
        }
    }

    let providers_and_profiles = collect(document, "provider", &mut errors, |f| {
        build_provider(f, &settings)
    });
    let mut providers: BTreeMap<ProviderId, Provider> = BTreeMap::new();
    let mut egress_profiles: BTreeMap<ProviderId, EgressProfile> = BTreeMap::new();
    for (provider, profile, position) in providers_and_profiles {
        if providers.contains_key(&provider.id) {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate provider '{}'", provider.id),
                position,
            ));
            continue;
        }
        egress_profiles.insert(provider.id.clone(), profile);
        providers.insert(provider.id.clone(), provider);
    }

    let targets_list = collect(document, "target", &mut errors, build_target);
    let mut targets: BTreeMap<TargetId, Target> = BTreeMap::new();
    for (target, position) in targets_list {
        if targets.contains_key(&target.id) {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate target '{}'", target.id),
                position,
            ));
            continue;
        }
        if !providers.contains_key(&target.provider_id) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "target '{}' names provider '{}', which is not defined",
                    target.id, target.provider_id
                ),
                position,
            ));
            continue;
        }
        if let Some(provider) = providers.get(&target.provider_id) {
            if target.endpoint_index >= provider.endpoints.len() {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!(
                        "target '{}' names endpoint {} of provider '{}', which has {}",
                        target.id,
                        target.endpoint_index,
                        provider.id,
                        provider.endpoints.len()
                    ),
                    position,
                ));
                continue;
            }
        }
        targets.insert(target.id.clone(), target);
    }

    let aliases_list = collect(document, "alias", &mut errors, build_alias);
    let mut aliases: BTreeMap<AliasId, Alias> = BTreeMap::new();
    for (alias, position) in aliases_list {
        if aliases.contains_key(&alias.id) {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate alias '{}'", alias.id),
                position,
            ));
            continue;
        }
        for target_id in &alias.permitted_targets {
            if !targets.contains_key(target_id) {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!(
                        "alias '{}' names target '{target_id}', which is not defined",
                        alias.id
                    ),
                    position,
                ));
            }
        }
        aliases.insert(alias.id.clone(), alias);
    }

    let bindings_list = collect(document, "binding", &mut errors, build_binding);
    let mut bindings: Vec<Binding> = Vec::new();
    let mut binding_ids: BTreeSet<BindingId> = BTreeSet::new();
    for (binding, position) in bindings_list {
        if !binding_ids.insert(binding.id.clone()) {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate binding '{}'", binding.id),
                position,
            ));
            continue;
        }
        check_selectors(&binding, &targets, &providers, position, &mut errors);
        bindings.push(binding);
    }

    let grants = collect(document, "grant", &mut errors, build_grant);
    let quotas = collect(document, "quota", &mut errors, build_quota);

    // Specification 12's "conservative node partitions". Applied here rather
    // than at admission so that everything downstream — the router, the
    // management API's quota views, simulation — sees one set of numbers, and
    // an operator reading a quota back gets the figure this node actually
    // enforces (`DI-029`).
    let partitions = settings.quota_partitions;
    let quotas: Vec<Quota> = quotas
        .into_iter()
        .map(|quota| {
            // Zero encodes "unlimited", so a real limit that divides to zero
            // would become the loosest configuration expressible instead of the
            // tightest. Refused rather than clamped: clamping to 1 would let N
            // nodes admit N against a limit of 2, which is the guarantee this
            // setting exists to provide, quietly broken.
            if quota.limits.partition_underflows(partitions) {
                errors.push(ConfigError::new(
                    "quota_partition_underflow",
                    format!(
                        "quota scope '{}' has a limit smaller than quota_partitions ({partitions}), \
                         so its share would round down to zero — which encodes 'unlimited'. \
                         Raise the limit to at least {partitions}, or lower quota_partitions",
                        quota_scope_label(&quota.scope)
                    ),
                    Position { line: 1, column: 1 },
                ));
            }
            Quota {
                limits: quota.limits.partitioned(partitions),
                ..quota
            }
        })
        .collect();
    let roles = collect(document, "role_binding", &mut errors, build_role_binding);
    let groups = collect(document, "group", &mut errors, build_group);
    let identities = collect(document, "identity", &mut errors, build_identity);

    // An identity naming a tenant that does not exist would sign its holder
    // into nothing; a duplicate (issuer, subject) would make which principal
    // they become depend on record order.
    let mut seen_identities: BTreeSet<(&str, &str)> = BTreeSet::new();
    for identity in &identities {
        if !seen_identities.insert((identity.issuer.as_str(), identity.subject.as_str())) {
            errors.push(ConfigError::new(
                "duplicate_record",
                format!(
                    "identity '{}' at issuer '{}' is bound more than once",
                    identity.subject, identity.issuer
                ),
                Position { line: 0, column: 0 },
            ));
        }
        if !tenant_map.contains_key(&identity.tenant) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "identity '{}' names tenant '{}', which is not defined",
                    identity.subject, identity.tenant
                ),
                Position { line: 0, column: 0 },
            ));
        }
    }
    let credentials = collect(document, "credential", &mut errors, build_credential);

    // A price naming a target that does not exist is almost always a typo in
    // the target id, and silently ignoring it would report a spend of zero for
    // a target that is costing money — the one direction a cost estimate must
    // not be wrong in.
    let prices = collect(document, "price", &mut errors, build_price);
    for price in &prices {
        if !targets.contains_key(&price.target) {
            errors.push(ConfigError::new(
                "unknown_reference",
                format!(
                    "price names target '{}', which is not defined",
                    price.target
                ),
                Position { line: 0, column: 0 },
            ));
        }
    }

    // Group identifiers are unique, and every group names a tenant that exists.
    // Both are checked here rather than at first use: a group that silently
    // resolves to nothing would grant a principal fewer privileges than the
    // operator intended, and a duplicate would make membership depend on
    // record order.
    let mut seen_groups: BTreeSet<&GroupId> = BTreeSet::new();
    for group in &groups {
        if !seen_groups.insert(&group.id) {
            errors.push(ConfigError::new(
                "duplicate_record",
                format!("group '{}' is defined more than once", group.id),
                Position { line: 0, column: 0 },
            ));
        }
        if !tenant_map.contains_key(&group.tenant) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "group '{}' names tenant '{}', which is not defined",
                    group.id, group.tenant
                ),
                Position { line: 0, column: 0 },
            ));
        }
    }

    // A binding or role binding that names a group with no definition would
    // never match, which reads as a silently ineffective policy.
    for binding in &bindings {
        if let BindingScope::Group(g) = &binding.scope {
            if !seen_groups.contains(g) {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!("binding '{}' names group '{g}', which is not defined", binding.id),
                    Position { line: 0, column: 0 },
                ));
            }
        }
    }
    for role in &roles {
        if let RoleSubject::Group(g) = &role.subject {
            if !seen_groups.contains(g) {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!("role binding names group '{g}', which is not defined"),
                    Position { line: 0, column: 0 },
                ));
            }
        }
    }

    // Credential references on providers must resolve.
    let credential_ids: BTreeSet<&CredentialRef> = credentials.iter().map(|c| &c.id).collect();
    for provider in providers.values() {
        if let Some(cred) = &provider.credential_ref {
            if !credential_ids.contains(cred) {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!(
                        "provider '{}' names credential '{cred}', which is not defined",
                        provider.id
                    ),
                    Position { line: 0, column: 0 },
                ));
            }
        }
    }

    // Quota target scopes must resolve.
    for quota in &quotas {
        match &quota.scope {
            QuotaScope::Target(t) if !targets.contains_key(t) => {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!("quota names target '{t}', which is not defined"),
                    Position { line: 0, column: 0 },
                ));
            }
            QuotaScope::Tenant(t) if !tenant_map.contains_key(t) => {
                errors.push(ConfigError::new(
                    "unresolved_reference",
                    format!("quota names tenant '{t}', which is not defined"),
                    Position { line: 0, column: 0 },
                ));
            }
            _ => {}
        }
    }

    // A target must be reachable through at least one alias, otherwise it is
    // configured but unusable — almost always a mistake rather than an intent.
    for target_id in targets.keys() {
        let reachable = aliases
            .values()
            .any(|a| a.permitted_targets.contains(target_id));
        if !reachable {
            errors.push(ConfigError::new(
                "unreachable_target",
                format!("target '{target_id}' is not listed by any alias"),
                Position { line: 0, column: 0 },
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let global_inheritance: BTreeSet<TenantId> = tenant_map
        .values()
        .filter(|t| t.inherit_global)
        .map(|t| t.id.clone())
        .collect();

    // Every target that survived validation is on the allowlist: endpoint
    // classification already happened in `build_provider`.
    let allowlisted_targets: BTreeSet<TargetId> = targets.keys().cloned().collect();

    let canonical = document.to_canonical_string();
    let digest = hypellm_crypto::digest(canonical.as_bytes());

    let snapshot = PolicySnapshot {
        version,
        digest,
        providers,
        targets,
        aliases,
        bindings,
        grants,
        global_inheritance,
        allowlisted_targets,
        weighted_tie_break: settings.weighted_tie_break,
        max_failure_percent: settings.max_failure_percent,
    };

    Ok(ValidatedConfig {
        snapshot,
        settings,
        tenants: tenant_map,
        quotas,
        roles,
        groups,
        identities,
        credentials,
        prices,
        egress_profiles,
        canonical,
        digest,
    })
}

fn collect<T>(
    document: &Document,
    kind: &str,
    errors: &mut Vec<ConfigError>,
    builder: impl Fn(&Fields<'_>) -> Result<T, ConfigError>,
) -> Vec<T> {
    let mut out = Vec::new();
    for record in document.of_kind(kind) {
        let fields = Fields::new(record);
        match builder(&fields) {
            Ok(v) => out.push(v),
            Err(e) => errors.push(e),
        }
    }
    out
}

fn build_settings(document: &Document) -> Result<Settings, ConfigError> {
    let Some(record) = document.of_kind("settings").next() else {
        return Ok(Settings::default());
    };
    let f = Fields::new(record);
    let d = Settings::default();

    Ok(Settings {
        inference_listen: f
            .opt_str("inference_listen")
            .unwrap_or(&d.inference_listen)
            .to_owned(),
        admin_listen: f.opt_str("admin_listen").unwrap_or(&d.admin_listen).to_owned(),
        metrics_listen: f.opt_str("metrics_listen").map(str::to_owned),
        max_body_bytes: f.u64_field("max_body_bytes", d.max_body_bytes)?,
        max_head_bytes: f.u32_field("max_head_bytes", d.max_head_bytes)?,
        allow_generic_adapter: f.bool_field("allow_generic_adapter", false)?,
        weighted_tie_break: f.bool_field("weighted_tie_break", false)?,
        max_failure_percent: f.u32_field("max_failure_percent", 100)?.min(100),
        default_deadline_ms: f.u64_field("default_deadline_ms", d.default_deadline_ms)?,
        max_attempts: f.u32_field("max_attempts", d.max_attempts)?,
        retry_budget_ms: f.u64_field("retry_budget_ms", d.retry_budget_ms)?,
        oidc_issuer: f.opt_str("oidc_issuer").map(str::to_owned),
        oidc_client_id: f.opt_str("oidc_client_id").map(str::to_owned),
        oidc_authorization_endpoint: f.opt_str("oidc_authorization_endpoint").map(str::to_owned),
        oidc_token_endpoint: f.opt_str("oidc_token_endpoint").map(str::to_owned),
        oidc_redirect_uri: f.opt_str("oidc_redirect_uri").map(str::to_owned),
        oidc_hosted_domains: f
            .list_field("oidc_hosted_domains")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        oidc_verifier_socket: f.opt_str("oidc_verifier_socket").map(str::to_owned),
        cors_origins: f
            .list_field("cors_origins")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        session_idle_secs: f.u64_field("session_idle_secs", d.session_idle_secs)?,
        session_absolute_secs: f.u64_field("session_absolute_secs", d.session_absolute_secs)?,
        tls_helper_socket: f.opt_str("tls_helper_socket").map(str::to_owned),
        state_dir: f.opt_str("state_dir").unwrap_or(&d.state_dir).to_owned(),
        audit_checkpoint_interval: f
            .u64_field("audit_checkpoint_interval", d.audit_checkpoint_interval)?,
        capture_bodies: f.bool_field("capture_bodies", false)?,
        keepalive_interval_ms: f.u64_field("keepalive_interval_ms", d.keepalive_interval_ms)?,
        slow_client_timeout_ms: f.u64_field("slow_client_timeout_ms", d.slow_client_timeout_ms)?,
        queue_timeout_ms: f.u64_field("queue_timeout_ms", d.queue_timeout_ms)?,
        max_connections: f.u64_field("max_connections", d.max_connections)?,
        quota_partitions: f.u32_field("quota_partitions", d.quota_partitions)?,
        connection_stack_kib: f.u64_field("connection_stack_kib", d.connection_stack_kib)?,
        max_requests_per_connection: f
            .u32_field("max_requests_per_connection", d.max_requests_per_connection)?,
        read_timeout_ms: f.u64_field("read_timeout_ms", d.read_timeout_ms)?,
        keepalive_timeout_ms: f.u64_field("keepalive_timeout_ms", d.keepalive_timeout_ms)?,
        break_glass_principal: f.opt_str("break_glass_principal").map(ToOwned::to_owned),
        break_glass_tenant: f.opt_str("break_glass_tenant").map(ToOwned::to_owned),
        break_glass_ttl_secs: f.u64_field("break_glass_ttl_secs", d.break_glass_ttl_secs)?,
        control_socket: f.opt_str("control_socket").map(str::to_owned),
    })
}

fn build_tenant(f: &Fields<'_>) -> Result<TenantConfig, ConfigError> {
    Ok(TenantConfig {
        id: id_field!(f, "id", TenantId)?,
        inherit_global: f.bool_field("inherit_global", true)?,
        active: match f.opt_str("status") {
            None | Some("active") => true,
            Some("suspended") => false,
            Some(other) => {
                return Err(f.error(
                    "invalid_status",
                    format!("tenant status must be active or suspended, found '{other}'"),
                ));
            }
        },
        residency: f.opt_str("residency").map(Residency::new),
        retention_days: f.u32_field("retention_days", 30)?,
        max_cost_class: match f.opt_str("max_cost") {
            None => None,
            Some(_) => {
                let raw = f.u32_field("max_cost", 0)?;
                if raw > 9 {
                    return Err(f.error(
                        "invalid_cost_class",
                        format!("max_cost must be between 0 and 9, found {raw}"),
                    ));
                }
                Some(CostClass(u8::try_from(raw).unwrap_or(9)))
            }
        },
    })
}

fn build_provider(
    f: &Fields<'_>,
    settings: &Settings,
) -> Result<(Provider, EgressProfile, Position), ConfigError> {
    let id = id_field!(f, "id", ProviderId)?;
    let family = f.parsed("family", "invalid_family", ProviderFamily::parse)?;

    if family.requires_explicit_opt_in() && !settings.allow_generic_adapter {
        return Err(f.error(
            "generic_adapter_not_enabled",
            format!(
                "provider '{id}' uses the generic adapter, which requires \
                 settings allow_generic_adapter=true"
            ),
        ));
    }

    let scheme = f.parsed("scheme", "invalid_scheme", EndpointScheme::parse)?;
    let host = f.str_field("host")?.to_owned();
    let default_port = match scheme {
        EndpointScheme::Https => 443,
        EndpointScheme::Http => 80,
        EndpointScheme::Unix => 0,
    };
    let port = f.u32_field("port", default_port)?;
    let port = u16::try_from(port)
        .map_err(|_| f.error("invalid_port", format!("port {port} is out of range")))?;

    let profile_name = f.opt_str("egress").unwrap_or(match scheme {
        EndpointScheme::Unix => "local",
        EndpointScheme::Http => "local",
        EndpointScheme::Https => "remote",
    });
    let profile = EgressProfile::parse(profile_name).ok_or_else(|| {
        f.error(
            "invalid_egress_profile",
            format!("unknown egress profile '{profile_name}'"),
        )
    })?;

    validate_endpoint(f, scheme, &host, port, profile)?;

    let endpoint = Endpoint {
        scheme,
        host,
        port,
        base_path: f.opt_str("base_path").unwrap_or("").to_owned(),
    };

    let credential_ref = match f.opt_str("credential") {
        None => None,
        Some(c) => Some(CredentialRef::new(c).map_err(|e| {
            f.error(
                "invalid_identifier",
                format!("credential reference '{c}' is invalid: {e}"),
            )
        })?),
    };

    Ok((
        Provider {
            id,
            family,
            endpoints: vec![endpoint],
            credential_ref,
            enabled: f.bool_field("enabled", true)?,
            egress_profile: profile_name.to_owned(),
        },
        profile,
        f.position(),
    ))
}

/// Reject an endpoint that cannot be safely reached under its profile.
///
/// Two rules matter here:
///
/// - **Cleartext is loopback-only.** Specification 8.1: "Loopback listener
///   defaults to local-only; remote cleartext forbidden." A credential sent
///   over plaintext HTTP to a non-loopback host is disclosed to the network.
/// - **An IP literal is classified now.** A DNS name cannot be, so it is
///   validated for syntax here and classified at connect time by the egress
///   guard, which pins the address it validated.
fn validate_endpoint(
    f: &Fields<'_>,
    scheme: EndpointScheme,
    host: &str,
    port: u16,
    profile: EgressProfile,
) -> Result<(), ConfigError> {
    if scheme == EndpointScheme::Unix {
        if !host.starts_with('/') {
            return Err(f.error(
                "invalid_endpoint",
                format!("unix endpoint path '{host}' must be absolute"),
            ));
        }
        return Ok(());
    }

    if !netaddr::is_valid_host(host) {
        return Err(f.error(
            "invalid_endpoint",
            format!("host '{host}' is not a valid DNS name or IP literal"),
        ));
    }

    let literal: Option<IpAddr> = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok();

    if let Some(addr) = literal {
        let class = netaddr::classify(addr);
        if !profile.permits(class) {
            return Err(f.error(
                "endpoint_not_permitted",
                format!(
                    "endpoint {host}:{port} resolves to address class '{class}', \
                     which the '{}' egress profile does not permit",
                    if profile == EgressProfile::LOCAL {
                        "local"
                    } else if profile == EgressProfile::REMOTE {
                        "remote"
                    } else if profile == EgressProfile::PRIVATE_NETWORK {
                        "private_network"
                    } else {
                        "none"
                    }
                ),
            ));
        }
        if scheme == EndpointScheme::Http && !matches!(class, netaddr::AddressClass::Loopback) {
            return Err(f.error(
                "cleartext_not_permitted",
                format!(
                    "endpoint {host}:{port} uses cleartext http to a non-loopback \
                     address; remote cleartext is forbidden"
                ),
            ));
        }
    } else if scheme == EndpointScheme::Http && host != "localhost" {
        return Err(f.error(
            "cleartext_not_permitted",
            format!(
                "endpoint {host}:{port} uses cleartext http to a named host; \
                 remote cleartext is forbidden"
            ),
        ));
    }

    Ok(())
}

fn build_target(f: &Fields<'_>) -> Result<(Target, Position), ConfigError> {
    let id = id_field!(f, "id", TargetId)?;
    let provider_id = id_field!(f, "provider", ProviderId)?;

    let mut operations = Vec::new();
    for op in f.list_field("operations") {
        operations.push(Operation::parse(op).ok_or_else(|| {
            f.error("invalid_operation", format!("unknown operation '{op}'"))
        })?);
    }
    if operations.is_empty() {
        operations.push(Operation::Chat);
    }

    let mut modalities = Vec::new();
    for m in f.list_field("modalities") {
        modalities.push(Modality::parse(m).ok_or_else(|| {
            f.error("invalid_modality", format!("unknown modality '{m}'"))
        })?);
    }
    if modalities.is_empty() {
        modalities.push(Modality::Text);
    }

    let mut aliases = Vec::new();
    for a in f.list_field("aliases") {
        aliases.push(AliasId::new(a).map_err(|e| {
            f.error("invalid_identifier", format!("alias '{a}' is invalid: {e}"))
        })?);
    }

    let capabilities = Capabilities {
        operations,
        modalities,
        streaming: f.bool_field("streaming", false)?,
        tools: f.bool_field("tools", false)?,
        parallel_tool_calls: f.bool_field("parallel_tools", false)?,
        json_mode: f.bool_field("json_mode", false)?,
        structured_output: f.bool_field("structured_output", false)?,
        reasoning: f.bool_field("reasoning", false)?,
        prompt_caching: f.bool_field("prompt_caching", false)?,
        max_context_tokens: f.u32_field("context", 0)?,
        max_output_tokens: f.u32_field("max_output", 0)?,
        embedding_dimensions: match f.opt_str("embedding_dims") {
            None => None,
            Some(_) => Some(f.u32_field("embedding_dims", 0)?),
        },
        native_tokenizer: f.bool_field("tokenizer", false)?,
    };

    let admin_state = match f.opt_str("state") {
        None | Some("enabled") => AdminState::Enabled,
        Some("draining") => AdminState::Draining,
        Some("maintenance") => AdminState::Maintenance,
        Some("quarantined") => AdminState::Quarantined,
        Some("disabled") => AdminState::Disabled,
        Some(other) => {
            return Err(f.error(
                "invalid_state",
                format!("unknown target state '{other}'"),
            ));
        }
    };

    let cost = f.u32_field("cost", 0)?;
    let cost = u8::try_from(cost.min(9)).unwrap_or(9);

    Ok((
        Target {
            id,
            provider_id,
            native_model: f.str_field("model")?.to_owned(),
            aliases,
            capabilities,
            cost_class: CostClass::new(cost),
            residency: f.opt_str("residency").map(Residency::new),
            is_local: f.bool_field("local", false)?,
            admin_state,
            endpoint_index: usize::try_from(f.u32_field("endpoint", 0)?).unwrap_or(0),
            max_concurrency: f.u32_field("concurrency", 0)?,
            max_requests_per_second: f.u32_field("rps", 0)?,
        },
        f.position(),
    ))
}

fn build_alias(f: &Fields<'_>) -> Result<(Alias, Position), ConfigError> {
    let id = id_field!(f, "id", AliasId)?;
    let mut permitted_targets = Vec::new();
    for t in f.list_field("targets") {
        permitted_targets.push(TargetId::new(t).map_err(|e| {
            f.error("invalid_identifier", format!("target '{t}' is invalid: {e}"))
        })?);
    }
    if permitted_targets.is_empty() {
        return Err(f.error(
            "empty_alias",
            format!("alias '{id}' lists no targets"),
        ));
    }
    Ok((
        Alias {
            id,
            permitted_targets,
            allow_family_failover: f.bool_field("family_failover", false)?,
            description: f.opt_str("description").map(str::to_owned),
        },
        f.position(),
    ))
}

fn build_binding(f: &Fields<'_>) -> Result<(Binding, Position), ConfigError> {
    let id = id_field!(f, "id", BindingId)?;
    let scope = parse_binding_scope(f, f.str_field("scope")?)?;
    let model = parse_model_selector(f, f.opt_str("model"))?;

    let weight = f.i64_field("weight", 0)?;
    let mut preferences = Vec::new();
    for (rank, entry) in f.list_field("prefer").into_iter().enumerate() {
        let rank = u16::try_from(rank).unwrap_or(u16::MAX);
        preferences.push(TargetPreference {
            selector: parse_target_selector(f, entry)?,
            rank,
            weight,
        });
    }

    let mut denies = Vec::new();
    for entry in f.list_field("deny") {
        denies.push(parse_target_selector(f, entry)?);
    }
    let mut allows = Vec::new();
    for entry in f.list_field("allow") {
        allows.push(parse_target_selector(f, entry)?);
    }

    let pin = match f.opt_str("pin") {
        None => None,
        Some(p) => Some(TargetId::new(p).map_err(|e| {
            f.error("invalid_identifier", format!("pin '{p}' is invalid: {e}"))
        })?),
    };
    let mut emergency_fallback = Vec::new();
    for entry in f.list_field("fallback") {
        emergency_fallback.push(TargetId::new(entry).map_err(|e| {
            f.error(
                "invalid_identifier",
                format!("fallback '{entry}' is invalid: {e}"),
            )
        })?);
    }
    if pin.is_none() && !emergency_fallback.is_empty() {
        return Err(f.error(
            "fallback_without_pin",
            format!("binding '{id}' declares a fallback but no pin"),
        ));
    }

    Ok((
        Binding {
            id,
            scope,
            model,
            preferences,
            denies,
            allows,
            pin,
            emergency_fallback,
            priority: f.i32_field("priority", 0)?,
        },
        f.position(),
    ))
}

fn build_grant(f: &Fields<'_>) -> Result<AliasGrant, ConfigError> {
    let scope = parse_binding_scope(f, f.str_field("scope")?)?;
    let mut operations = Vec::new();
    for op in f.list_field("operations") {
        operations.push(Operation::parse(op).ok_or_else(|| {
            f.error("invalid_operation", format!("unknown operation '{op}'"))
        })?);
    }
    Ok(AliasGrant {
        scope,
        model: parse_model_selector(f, f.opt_str("model"))?,
        operations,
        allow: f.bool_field("allow", true)?,
    })
}

fn build_quota(f: &Fields<'_>) -> Result<Quota, ConfigError> {
    let raw = f.str_field("scope")?;
    let scope = if raw == "global" {
        QuotaScope::Global
    } else if let Some(rest) = raw.strip_prefix("tenant:") {
        QuotaScope::Tenant(TenantId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("tenant '{rest}': {e}"))
        })?)
    } else if let Some(rest) = raw.strip_prefix("principal:") {
        QuotaScope::Principal(PrincipalId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("principal '{rest}': {e}"))
        })?)
    } else if let Some(rest) = raw.strip_prefix("target:") {
        QuotaScope::Target(TargetId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("target '{rest}': {e}"))
        })?)
    } else if let Some(rest) = raw.strip_prefix("alias:") {
        // The operation qualifier is optional and rides on the same record, so
        // an operator capping embeddings separately from chat writes two
        // `quota` lines rather than a second record type.
        let operation = match f.opt_str("operation") {
            Some(text) => Some(Operation::parse(text).ok_or_else(|| {
                f.error(
                    "invalid_operation",
                    format!("quota operation '{text}' is not a known operation"),
                )
            })?),
            None => None,
        };
        QuotaScope::Alias {
            alias: AliasId::new(rest).map_err(|e| {
                f.error("invalid_identifier", format!("alias '{rest}': {e}"))
            })?,
            operation,
        }
    } else {
        return Err(f.error(
            "invalid_scope",
            format!(
                "quota scope '{raw}' must be global, tenant:, principal:, alias:, or target:"
            ),
        ));
    };

    let class = match f.opt_str("class") {
        Some(text) => hypellm_core::admission::PriorityClass::parse(text).ok_or_else(|| {
            f.error(
                "invalid_value",
                format!(
                    "priority class '{text}' must be interactive, standard, or batch"
                ),
            )
        })?,
        None => hypellm_core::admission::PriorityClass::Standard,
    };

    let byte_rates = ByteRates {
        input_per_second: f.u64_field("input_bytes_per_second", 0)?,
        input_burst: f.u64_field("input_bytes_burst", 0)?,
        output_per_second: f.u64_field("output_bytes_per_second", 0)?,
        output_burst: f.u64_field("output_bytes_burst", 0)?,
    };
    // Specification 12 lists byte rates only at the Global layer. A value set
    // on a narrower scope would be silently ignored, which is the shape of
    // configuration mistake that is found months later when the limit turns out
    // never to have applied.
    if byte_rates != ByteRates::default() && scope != QuotaScope::Global {
        return Err(f.error(
            "byte_rates_not_global",
            "input_bytes_per_second and output_bytes_per_second apply only to \
             `quota scope=global` (specification 12's Global layer)"
                .to_owned(),
        ));
    }

    Ok(Quota {
        scope,
        class,
        byte_rates,
        limits: hypellm_core::admission::ScopeLimits {
            max_concurrency: f.u32_field("concurrency", 0)?,
            max_queued: f.u32_field("queued", 0)?,
            requests_per_second: f.u32_field("rps", 0)?,
            request_burst: f.u32_field("burst", 0)?,
            tokens_per_minute: f.u64_field("tpm", 0)?,
            token_burst: f.u64_field("token_burst", 0)?,
            budget_minor_units: f.u64_field("budget", 0)?,
            budget_period: match f.opt_str("budget_period") {
                Some(text) => hypellm_core::admission::BudgetPeriod::parse(text).ok_or_else(|| {
                    f.error(
                        "invalid_budget_period",
                        format!("budget_period '{text}' must be daily or monthly"),
                    )
                })?,
                None => hypellm_core::admission::BudgetPeriod::Daily,
            },
        },
    })
}

fn build_role_binding(f: &Fields<'_>) -> Result<RoleBinding, ConfigError> {
    let raw = f.str_field("subject")?;
    let subject = if let Some(rest) = raw.strip_prefix("principal:") {
        RoleSubject::Principal(PrincipalId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("principal '{rest}': {e}"))
        })?)
    } else if let Some(rest) = raw.strip_prefix("group:") {
        RoleSubject::Group(GroupId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("group '{rest}': {e}"))
        })?)
    } else {
        return Err(f.error(
            "invalid_subject",
            format!("role binding subject '{raw}' must be principal: or group:"),
        ));
    };
    Ok(RoleBinding {
        subject,
        role: f.parsed("role", "invalid_role", Role::parse)?,
    })
}

fn build_identity(f: &Fields<'_>) -> Result<IdentityBinding, ConfigError> {
    let issuer = f.str_field("issuer")?.to_owned();
    let subject = f.str_field("subject")?.to_owned();

    if issuer.is_empty() || subject.is_empty() {
        return Err(f.error(
            "empty_field",
            "an identity binding needs a non-empty issuer and subject",
        ));
    }

    Ok(IdentityBinding {
        issuer,
        subject,
        principal: id_field!(f, "principal", PrincipalId)?,
        tenant: id_field!(f, "tenant", TenantId)?,
        description: f.opt_str("description").map(str::to_owned),
    })
}

fn build_group(f: &Fields<'_>) -> Result<Group, ConfigError> {
    let id = id_field!(f, "id", GroupId)?;
    let tenant = id_field!(f, "tenant", TenantId)?;

    let mut members = BTreeSet::new();
    for raw in f.list_field("members") {
        let principal = PrincipalId::new(raw)
            .map_err(|e| f.error("invalid_identifier", format!("principal '{raw}': {e}")))?;
        if !members.insert(principal) {
            return Err(f.error(
                "duplicate_member",
                format!("group '{id}' lists principal '{raw}' more than once"),
            ));
        }
    }

    Ok(Group {
        id,
        tenant,
        members,
        description: f.opt_str("description").map(str::to_owned),
    })
}

/// Specification 25's "configured price schedule with effective dates".
fn build_price(f: &Fields<'_>) -> Result<PriceSchedule, ConfigError> {
    let raw = f.str_field("target")?;
    let target = TargetId::new(raw)
        .map_err(|e| f.error("invalid_identifier", format!("target '{raw}': {e}")))?;

    let input_per_million = f.u64_field("input_per_million", 0)?;
    Ok(PriceSchedule {
        target,
        input_per_million,
        output_per_million: f.u64_field("output_per_million", 0)?,
        // Defaults to the *input* price, not to zero. A provider that discounts
        // cached input still charges for it, so an omitted field must
        // over-report rather than under-report: an estimate that is too low is
        // the one an operator acts on and regrets.
        cached_input_per_million: f
            .u64_field("cached_input_per_million", input_per_million)?,
        currency: f.opt_str("currency").unwrap_or("USD").to_owned(),
        effective_from_millis: f.u64_field("effective_from", 0)?,
    })
}

fn build_credential(f: &Fields<'_>) -> Result<CredentialMeta, ConfigError> {
    Ok(CredentialMeta {
        id: id_field!(f, "id", CredentialRef)?,
        scope: f.list_field("scope").into_iter().map(str::to_owned).collect(),
        description: f.opt_str("description").map(str::to_owned),
        rotates_after_days: f.u32_field("rotates_after_days", 90)?,
    })
}

fn parse_binding_scope(f: &Fields<'_>, raw: &str) -> Result<BindingScope, ConfigError> {
    if raw == "global" {
        return Ok(BindingScope::Global);
    }
    if let Some(rest) = raw.strip_prefix("principal:") {
        return Ok(BindingScope::Principal(PrincipalId::new(rest).map_err(
            |e| f.error("invalid_identifier", format!("principal '{rest}': {e}")),
        )?));
    }
    if let Some(rest) = raw.strip_prefix("group:") {
        return Ok(BindingScope::Group(GroupId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("group '{rest}': {e}"))
        })?));
    }
    if let Some(rest) = raw.strip_prefix("tenant:") {
        return Ok(BindingScope::Tenant(TenantId::new(rest).map_err(|e| {
            f.error("invalid_identifier", format!("tenant '{rest}': {e}"))
        })?));
    }
    Err(f.error(
        "invalid_scope",
        format!("scope '{raw}' must be global, principal:, group:, or tenant:"),
    ))
}

/// Parse a model selector. `*` and an absent value both mean "any"; a trailing
/// `*` is a class prefix.
/// Parse a model selector. `*` is every alias, `prefix*` is a prefix match,
/// and anything else is an exact alias identifier.
///
/// An invalid identifier is an error, not a fallback. This previously read
/// `AliasId::new(v).map_or(ModelSelector::Any, ModelSelector::Exact)`, so a
/// typo in `grant scope=tenant:acme model=<invalid> allow=true` silently
/// widened the grant from one alias to *every* alias — a fail-open in the
/// filter specification 6.2 lists first ("Principal is authorized for requested
/// alias and operation"). `parse_target_selector` below has always rejected
/// invalid identifiers; this now matches it.
fn parse_model_selector(f: &Fields<'_>, raw: Option<&str>) -> Result<ModelSelector, ConfigError> {
    // An omitted `model` legitimately means "every alias". An explicitly empty
    // one does not: nobody writes `model=` on purpose, and reading it as a
    // wildcard turns a truncated line — or a substitution that produced
    // nothing — into a grant over every model. The two cases look identical to
    // `opt_str`, which treats an empty value as absence, so presence is checked
    // separately here.
    if raw.is_none() && f.present("model") {
        return Err(f.error(
            "empty_field",
            "'model' is present but empty; omit it to mean every alias, or name one",
        ));
    }

    match raw {
        None | Some("*") | Some("") => Ok(ModelSelector::Any),
        Some(v) => match v.strip_suffix('*') {
            Some(prefix) => Ok(ModelSelector::Prefix(prefix.to_owned())),
            None => AliasId::new(v)
                .map(ModelSelector::Exact)
                .map_err(|e| f.error("invalid_identifier", format!("alias '{v}': {e}"))),
        },
    }
}

/// Parse a target selector. `*` is every target; `provider:*` is a provider's
/// targets; anything else is an exact target identifier.
fn parse_target_selector(f: &Fields<'_>, raw: &str) -> Result<TargetSelector, ConfigError> {
    if raw == "*" {
        return Ok(TargetSelector::Any);
    }
    if let Some(provider) = raw.strip_suffix(":*") {
        return Ok(TargetSelector::Provider(ProviderId::new(provider).map_err(
            |e| f.error("invalid_identifier", format!("provider '{provider}': {e}")),
        )?));
    }
    Ok(TargetSelector::Exact(TargetId::new(raw).map_err(|e| {
        f.error("invalid_identifier", format!("target '{raw}': {e}"))
    })?))
}

fn check_selectors(
    binding: &Binding,
    targets: &BTreeMap<TargetId, Target>,
    providers: &BTreeMap<ProviderId, Provider>,
    position: Position,
    errors: &mut Vec<ConfigError>,
) {
    let mut check = |selector: &TargetSelector, what: &str| match selector {
        TargetSelector::Exact(t) if !targets.contains_key(t) => {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "binding '{}' {what} names target '{t}', which is not defined",
                    binding.id
                ),
                position,
            ));
        }
        TargetSelector::Provider(p) if !providers.contains_key(p) => {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "binding '{}' {what} names provider '{p}', which is not defined",
                    binding.id
                ),
                position,
            ));
        }
        _ => {}
    };

    for p in &binding.preferences {
        check(&p.selector, "preference");
    }
    for d in &binding.denies {
        check(d, "deny");
    }
    for a in &binding.allows {
        check(a, "allow");
    }
    if let Some(pin) = &binding.pin {
        if !targets.contains_key(pin) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "binding '{}' pins target '{pin}', which is not defined",
                    binding.id
                ),
                position,
            ));
        }
    }
    for fallback in &binding.emergency_fallback {
        if !targets.contains_key(fallback) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "binding '{}' names fallback target '{fallback}', which is not defined",
                    binding.id
                ),
                position,
            ));
        }
    }
}

