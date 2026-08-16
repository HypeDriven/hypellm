//! Providers, targets, and capability declarations (specification 5).
//!
//! Specification 23 is explicit that capabilities are **declared, not
//! inferred**: "Create provider targets and aliases with explicit capabilities;
//! do not infer capabilities solely from names." A model called
//! `something-vision` may not accept images, and a routing decision made on a
//! guess fails at the provider after the request has already been admitted,
//! metered, and possibly streamed.

use crate::canonical::{CostClass, Modality, Operation, Residency};
use crate::ids::{AliasId, CredentialRef, ProviderId, TargetId};
use core::fmt;

/// The provider family an adapter is compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderFamily {
    /// A llama.cpp server speaking the OpenAI-compatible surface.
    LlamaCpp,
    /// OpenAI.
    OpenAi,
    /// Anthropic.
    Anthropic,
    /// DeepSeek.
    DeepSeek,
    /// Moonshot / Kimi.
    Moonshot,
    /// A generic OpenAI-compatible endpoint.
    ///
    /// Specification 25: "Disabled by default; fixed endpoint and explicit
    /// capabilities required."
    GenericOpenAi,
}

impl ProviderFamily {
    /// Stable configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlamaCpp => "llamacpp",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::DeepSeek => "deepseek",
            Self::Moonshot => "moonshot",
            Self::GenericOpenAi => "generic_openai",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "llamacpp" | "llama.cpp" => Self::LlamaCpp,
            "openai" => Self::OpenAi,
            "anthropic" => Self::Anthropic,
            "deepseek" => Self::DeepSeek,
            "moonshot" | "kimi" => Self::Moonshot,
            "generic_openai" => Self::GenericOpenAi,
            _ => return None,
        })
    }

    /// Whether this family must be explicitly enabled before use.
    #[must_use]
    pub const fn requires_explicit_opt_in(self) -> bool {
        matches!(self, Self::GenericOpenAi)
    }

    /// Every family, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::LlamaCpp,
            Self::OpenAi,
            Self::Anthropic,
            Self::DeepSeek,
            Self::Moonshot,
            Self::GenericOpenAi,
        ]
    }
}

impl fmt::Display for ProviderFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An administrator-declared upstream endpoint.
///
/// Specification 10: "Upstream destinations are administrator-defined
/// scheme/host/port tuples." There is no URL string here that a request could
/// influence — the parts are separate fields, fixed at configuration time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `https`, `http`, or `unix`.
    pub scheme: EndpointScheme,
    /// Host name, IP literal, or Unix socket path.
    pub host: String,
    /// TCP port. Zero for a Unix socket.
    pub port: u16,
    /// Path prefix prepended to every adapter path.
    pub base_path: String,
}

/// The transport an endpoint uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScheme {
    /// Cleartext HTTP. Permitted only for loopback and Unix transports.
    Http,
    /// HTTPS through the platform TLS boundary.
    Https,
    /// A Unix domain socket.
    Unix,
}

impl EndpointScheme {
    /// Stable configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Unix => "unix",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http" => Self::Http,
            "https" => Self::Https,
            "unix" => Self::Unix,
            _ => return None,
        })
    }

    /// Whether this scheme goes through the TLS helper boundary.
    #[must_use]
    pub const fn needs_tls(self) -> bool {
        matches!(self, Self::Https)
    }
}

impl Endpoint {
    /// The authority used in the `Host` header.
    #[must_use]
    pub fn authority(&self) -> String {
        match self.scheme {
            EndpointScheme::Unix => "localhost".to_owned(),
            EndpointScheme::Http if self.port == 80 => self.host.clone(),
            EndpointScheme::Https if self.port == 443 => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        }
    }

    /// Join the base path with an adapter-supplied path.
    #[must_use]
    pub fn path(&self, suffix: &str) -> String {
        let base = self.base_path.trim_end_matches('/');
        if suffix.starts_with('/') {
            format!("{base}{suffix}")
        } else {
            format!("{base}/{suffix}")
        }
    }

    /// A key identifying the connection pool this endpoint uses.
    ///
    /// Specification 19: "Pools keyed by exact endpoint, TLS identity/profile,
    /// credential isolation class, and protocol."
    #[must_use]
    pub fn pool_key(&self, credential_class: &str) -> String {
        format!(
            "{}|{}|{}|{}",
            self.scheme.as_str(),
            self.host,
            self.port,
            credential_class
        )
    }
}

/// A declared provider.
#[derive(Debug, Clone)]
pub struct Provider {
    /// Identifier.
    pub id: ProviderId,
    /// The adapter family.
    pub family: ProviderFamily,
    /// Endpoints, in configuration order.
    pub endpoints: Vec<Endpoint>,
    /// Opaque handle to the credential. Never the secret.
    pub credential_ref: Option<CredentialRef>,
    /// Whether the provider is enabled.
    pub enabled: bool,
    /// The egress profile name applied to its connections.
    pub egress_profile: String,
}

/// What a target can do.
///
/// Every field is a declaration, never a default derived from the model name.
#[derive(Debug, Clone, PartialEq)]
pub struct Capabilities {
    /// Operations the target serves.
    pub operations: Vec<Operation>,
    /// Input modalities it accepts.
    pub modalities: Vec<Modality>,
    /// Whether it supports streaming.
    pub streaming: bool,
    /// Whether it supports tool calling.
    pub tools: bool,
    /// Whether it supports parallel tool calls.
    pub parallel_tool_calls: bool,
    /// Whether it supports JSON-object response format.
    pub json_mode: bool,
    /// Whether it supports schema-constrained output.
    pub structured_output: bool,
    /// Whether it exposes reasoning content.
    pub reasoning: bool,
    /// Whether prompt caching may be requested.
    ///
    /// Specification 7: Anthropic prompt caching headers are sent "only when
    /// explicitly allowed", because caching changes where prompt data rests.
    pub prompt_caching: bool,
    /// Maximum input context in tokens.
    pub max_context_tokens: u32,
    /// Maximum output tokens per request.
    pub max_output_tokens: u32,
    /// Embedding dimensionality, for embedding targets.
    pub embedding_dimensions: Option<u32>,
    /// Whether the endpoint offers a native tokenizer.
    pub native_tokenizer: bool,
}

impl Default for Capabilities {
    /// The most restrictive possible declaration.
    ///
    /// A target whose configuration omits a capability does not get it. The
    /// failure mode of the opposite default — assuming support and finding out
    /// at the provider — is a request that was admitted, metered, and possibly
    /// already streaming.
    fn default() -> Self {
        Self {
            operations: Vec::new(),
            modalities: vec![Modality::Text],
            streaming: false,
            tools: false,
            parallel_tool_calls: false,
            json_mode: false,
            structured_output: false,
            reasoning: false,
            prompt_caching: false,
            max_context_tokens: 0,
            max_output_tokens: 0,
            embedding_dimensions: None,
            native_tokenizer: false,
        }
    }
}

impl Capabilities {
    /// Whether the target serves this operation.
    #[must_use]
    pub fn supports_operation(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }

    /// Whether the target accepts every modality in `required`.
    #[must_use]
    pub fn supports_modalities(&self, required: &[Modality]) -> bool {
        required.iter().all(|m| self.modalities.contains(m))
    }
}

/// Operational state an administrator can set on a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminState {
    /// Available for selection.
    Enabled,
    /// Accepting no new requests, finishing existing ones.
    Draining,
    /// Withdrawn for planned work.
    Maintenance,
    /// Withdrawn by an operator overriding automated recovery.
    ///
    /// Specification 13: "Manual quarantine overrides automated recovery and
    /// requires reason, actor, expiry/review time, and audit record."
    Quarantined,
    /// Configured but switched off.
    Disabled,
}

impl AdminState {
    /// Whether a target in this state may be selected for a new request.
    #[must_use]
    pub const fn admits_new_requests(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Stable name for traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Draining => "draining",
            Self::Maintenance => "maintenance",
            Self::Quarantined => "quarantined",
            Self::Disabled => "disabled",
        }
    }
}

/// A concrete provider/model/endpoint tuple.
#[derive(Debug, Clone)]
pub struct Target {
    /// Identifier.
    pub id: TargetId,
    /// Which provider serves it.
    pub provider_id: ProviderId,
    /// The provider's own model name.
    pub native_model: String,
    /// Aliases that may resolve to this target.
    pub aliases: Vec<AliasId>,
    /// Declared capabilities.
    pub capabilities: Capabilities,
    /// Relative cost class, administrator-assigned.
    pub cost_class: CostClass,
    /// Data region this target's inference happens in.
    pub residency: Option<Residency>,
    /// Whether inference is local to this deployment.
    ///
    /// Feeds the locality term of the score (specification 6.3) and the
    /// `require_local` routing hint.
    pub is_local: bool,
    /// Administrative state.
    pub admin_state: AdminState,
    /// Index of the endpoint within the provider's endpoint list.
    pub endpoint_index: usize,
    /// Maximum concurrent requests the target will accept.
    pub max_concurrency: u32,
    /// Requests per second the target will accept.
    pub max_requests_per_second: u32,
}

impl Target {
    /// Whether this target satisfies a residency requirement.
    ///
    /// A target with no declared residency does not satisfy any requirement.
    /// Specification 6.2 makes residency an eligibility filter, and an
    /// undeclared region is unknown, not universal.
    #[must_use]
    pub fn satisfies_residency(&self, required: Option<&Residency>) -> bool {
        match required {
            None => true,
            Some(req) => self.residency.as_ref() == Some(req),
        }
    }

    /// Whether the target's cost class is within a ceiling.
    #[must_use]
    pub fn within_cost_ceiling(&self, ceiling: Option<CostClass>) -> bool {
        match ceiling {
            None => true,
            Some(max) => self.cost_class <= max,
        }
    }

    /// Whether the target publishes this alias.
    #[must_use]
    pub fn has_alias(&self, alias: &AliasId) -> bool {
        self.aliases.contains(alias)
    }
}

/// A client-visible alias and the targets it may resolve to.
#[derive(Debug, Clone)]
pub struct Alias {
    /// The client-visible name.
    pub id: AliasId,
    /// Targets permitted for this alias.
    pub permitted_targets: Vec<TargetId>,
    /// Whether failover across model families is allowed.
    ///
    /// Specification 6.5: "A model-family change must be explicitly allowed in
    /// the alias failover policy and visible in response metadata."
    pub allow_family_failover: bool,
    /// A description surfaced by the models endpoint.
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            id: TargetId::new("local:qwen-coder").unwrap(),
            provider_id: ProviderId::new("local").unwrap(),
            native_model: "qwen2.5-coder-32b".to_owned(),
            aliases: vec![AliasId::new("code-premium").unwrap()],
            capabilities: Capabilities {
                operations: vec![Operation::Chat],
                modalities: vec![Modality::Text],
                streaming: true,
                tools: true,
                max_context_tokens: 65_536,
                max_output_tokens: 8_192,
                ..Capabilities::default()
            },
            cost_class: CostClass::CHEAPEST,
            residency: Some(Residency::new("eu")),
            is_local: true,
            admin_state: AdminState::Enabled,
            endpoint_index: 0,
            max_concurrency: 8,
            max_requests_per_second: 20,
        }
    }

    #[test]
    fn default_capabilities_grant_nothing() {
        // The security-relevant default: an under-specified target must not
        // silently acquire capabilities it was never declared to have.
        let c = Capabilities::default();
        assert!(c.operations.is_empty());
        assert!(!c.streaming);
        assert!(!c.tools);
        assert!(!c.json_mode);
        assert!(!c.structured_output);
        assert!(!c.prompt_caching);
        assert_eq!(c.max_context_tokens, 0);
        assert_eq!(c.max_output_tokens, 0);
        assert!(!c.supports_operation(Operation::Chat));
    }

    #[test]
    fn modality_support_requires_every_requested_modality() {
        let c = Capabilities {
            modalities: vec![Modality::Text],
            ..Capabilities::default()
        };
        assert!(c.supports_modalities(&[Modality::Text]));
        assert!(!c.supports_modalities(&[Modality::Text, Modality::Image]));
        assert!(c.supports_modalities(&[]));

        let c = Capabilities {
            modalities: vec![Modality::Text, Modality::Image],
            ..Capabilities::default()
        };
        assert!(c.supports_modalities(&[Modality::Text, Modality::Image]));
        assert!(!c.supports_modalities(&[Modality::Audio]));
    }

    #[test]
    fn undeclared_residency_does_not_satisfy_a_requirement() {
        let mut t = target();
        assert!(t.satisfies_residency(Some(&Residency::new("eu"))));
        assert!(!t.satisfies_residency(Some(&Residency::new("us"))));
        assert!(t.satisfies_residency(None));

        t.residency = None;
        assert!(
            !t.satisfies_residency(Some(&Residency::new("eu"))),
            "an unknown region must not pass a residency filter"
        );
        assert!(t.satisfies_residency(None));
    }

    #[test]
    fn cost_ceiling_is_inclusive() {
        let mut t = target();
        t.cost_class = CostClass::new(3);
        assert!(t.within_cost_ceiling(Some(CostClass::new(3))));
        assert!(t.within_cost_ceiling(Some(CostClass::new(5))));
        assert!(!t.within_cost_ceiling(Some(CostClass::new(2))));
        assert!(t.within_cost_ceiling(None));
    }

    #[test]
    fn only_enabled_targets_admit_new_requests() {
        assert!(AdminState::Enabled.admits_new_requests());
        for state in [
            AdminState::Draining,
            AdminState::Maintenance,
            AdminState::Quarantined,
            AdminState::Disabled,
        ] {
            assert!(
                !state.admits_new_requests(),
                "{state:?} must not admit new requests"
            );
        }
    }

    #[test]
    fn endpoint_authority_omits_default_ports() {
        let e = Endpoint {
            scheme: EndpointScheme::Https,
            host: "api.example".to_owned(),
            port: 443,
            base_path: "/v1".to_owned(),
        };
        assert_eq!(e.authority(), "api.example");

        let e = Endpoint {
            scheme: EndpointScheme::Https,
            host: "api.example".to_owned(),
            port: 8443,
            base_path: String::new(),
        };
        assert_eq!(e.authority(), "api.example:8443");

        let e = Endpoint {
            scheme: EndpointScheme::Unix,
            host: "/run/llama.sock".to_owned(),
            port: 0,
            base_path: String::new(),
        };
        assert_eq!(e.authority(), "localhost");
    }

    #[test]
    fn endpoint_path_joining_is_stable() {
        let e = Endpoint {
            scheme: EndpointScheme::Https,
            host: "api.example".to_owned(),
            port: 443,
            base_path: "/v1".to_owned(),
        };
        assert_eq!(e.path("/chat/completions"), "/v1/chat/completions");
        assert_eq!(e.path("chat/completions"), "/v1/chat/completions");

        let e = Endpoint {
            base_path: "/v1/".to_owned(),
            ..e
        };
        assert_eq!(e.path("/chat"), "/v1/chat");

        let e = Endpoint {
            base_path: String::new(),
            ..e
        };
        assert_eq!(e.path("/chat"), "/chat");
    }

    #[test]
    fn pool_keys_separate_credential_classes() {
        let e = Endpoint {
            scheme: EndpointScheme::Https,
            host: "api.example".to_owned(),
            port: 443,
            base_path: "/v1".to_owned(),
        };
        // Two tenants using different credentials against the same endpoint
        // must not share a pooled connection.
        assert_ne!(e.pool_key("tenant_a"), e.pool_key("tenant_b"));
        assert_eq!(e.pool_key("tenant_a"), e.pool_key("tenant_a"));

        let other = Endpoint {
            port: 8443,
            ..e.clone()
        };
        assert_ne!(e.pool_key("x"), other.pool_key("x"));
    }

    #[test]
    fn provider_family_parsing_roundtrips() {
        for f in ProviderFamily::all() {
            assert_eq!(ProviderFamily::parse(f.as_str()), Some(*f));
        }
        assert_eq!(ProviderFamily::parse("llama.cpp"), Some(ProviderFamily::LlamaCpp));
        assert_eq!(ProviderFamily::parse("kimi"), Some(ProviderFamily::Moonshot));
        assert_eq!(ProviderFamily::parse("unknown"), None);
    }

    #[test]
    fn generic_adapter_requires_opt_in() {
        assert!(ProviderFamily::GenericOpenAi.requires_explicit_opt_in());
        for f in [
            ProviderFamily::OpenAi,
            ProviderFamily::Anthropic,
            ProviderFamily::LlamaCpp,
            ProviderFamily::DeepSeek,
            ProviderFamily::Moonshot,
        ] {
            assert!(!f.requires_explicit_opt_in());
        }
    }

    #[test]
    fn endpoint_scheme_tls_requirement() {
        assert!(EndpointScheme::Https.needs_tls());
        assert!(!EndpointScheme::Http.needs_tls());
        assert!(!EndpointScheme::Unix.needs_tls());
        assert_eq!(EndpointScheme::parse("https"), Some(EndpointScheme::Https));
        assert_eq!(EndpointScheme::parse("ftp"), None);
    }

    #[test]
    fn alias_membership() {
        let t = target();
        assert!(t.has_alias(&AliasId::new("code-premium").unwrap()));
        assert!(!t.has_alias(&AliasId::new("code-fast").unwrap()));
    }
}
