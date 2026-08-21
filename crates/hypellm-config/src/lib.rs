//! The native configuration grammar, schema, and validated snapshot builder.
//!
//! Specification 11: configuration is "a versioned immutable document activated
//! atomically". This crate covers everything up to activation: parse, validate,
//! resolve references, verify invariants, and compute the digest.
//! [`hypellm_store`](../hypellm_store/index.html) performs the durable commit and
//! the pointer swap.
//!
//! # Load path
//!
//! ```text
//! text ──parse──▶ Document ──validate_record──▶ ──build──▶ ValidatedConfig
//!                    │                                          │
//!                    └── to_canonical_string ───────────────────┴─▶ digest
//! ```
//!
//! Two documents that differ only in whitespace, comments, record order, or
//! field order produce identical canonical text and therefore an identical
//! digest. That is what makes "the active configuration digest" a meaningful
//! thing to compare across nodes (specification 11.2).
//!
//! ```
//! use hypellm_config::{ParseLimits, build, parse};
//!
//! let text = r#"
//!     settings state_dir=/var/lib/hypellm
//!     tenant id=acme
//!     credential id=cred_local
//!     provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
//!     target id=local:qwen provider=local model=qwen2.5-coder streaming=true \
//!            context=65536 max_output=8192 local=true
//!     alias id=code targets=local:qwen
//!     grant scope=tenant:acme allow=true
//!     binding id=default scope=tenant:acme prefer=local:qwen
//! "#;
//!
//! let document = parse(text, &ParseLimits::DEFAULT)?;
//! let config = build(&document, 1).map_err(|errors| errors[0].clone())?;
//! assert_eq!(config.snapshot.targets.len(), 1);
//! assert_eq!(config.snapshot.aliases.len(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
// Specification 18.2: configuration is administrator-authored, but it is parsed
// during startup and during a reload on a live process, so a panic here takes a
// node down. The workspace warns on these; this crate refuses them outright, so
// a new unchecked index or silent `as` cast is a build failure rather than one
// more line of lint output.
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::as_conversions))]

pub mod build;
pub mod fleet;
pub mod parse;
pub mod schema;

pub use build::{
    CredentialMeta, PriceSchedule, Quota, QuotaScope, RoleBinding, RoleSubject, Settings,
    TenantConfig, ValidatedConfig, build, price_in_effect,
};
pub use parse::{
    Document, ParseError, ParseErrorKind, ParseLimits, Position, Record, parse, quote_if_needed,
    split_list,
};
pub use schema::{ConfigError, Fields, SCHEMAS, Schema, schema_for, validate_record};

/// Parse and build in one step, collecting every error.
pub fn load(text: &str, version: u64) -> Result<ValidatedConfig, Vec<ConfigError>> {
    let document = parse(text, &ParseLimits::DEFAULT).map_err(|e| {
        vec![ConfigError::new(
            "parse_error",
            e.kind.to_string(),
            e.position,
        )]
    })?;
    build(&document, version)
}

// Tests index fixtures whose shape the test itself constructs; a panic there is
// a test failure, which is the intended signal. The escalation stays in force
// for the library code above.
#[allow(clippy::indexing_slicing, clippy::as_conversions)]
#[cfg(test)]
mod tests {
    #[test]
    fn byte_rates_are_refused_on_any_scope_but_global() {
        // Specification 12 lists byte rates only at the Global layer. A value
        // set on a narrower scope would be silently ignored — the shape of
        // configuration mistake found months later, when the limit turns out
        // never to have applied to anything.
        let ok = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=global input_bytes_per_second=1048576 output_bytes_per_second=4194304\n";
        let config = load(ok, 1).expect("a global byte rate must load");
        let quota = config.quotas.first().expect("one quota");
        assert_eq!(quota.byte_rates.input_per_second, 1_048_576);
        assert_eq!(quota.byte_rates.output_per_second, 4_194_304);

        let misplaced = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=tenant:acme input_bytes_per_second=1048576\n";
        let errors = load(misplaced, 1).expect_err("this must not load");
        assert!(
            errors.iter().any(|e| e.code == "byte_rates_not_global"),
            "expected byte_rates_not_global, got: {errors:?}"
        );
    }

    #[test]
    fn a_quota_may_carry_a_spend_budget_and_its_period() {
        // Specification 11.1 lists "budget limits" on a `quota` and
        // specification 12 gives the tenant layer a "daily/monthly budget
        // class" (`DI-053`). The figure is in the same minor units as the price
        // schedule, because a budget in anything else would need a conversion
        // the router has no source for.
        let text = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=tenant:acme budget=250000 budget_period=monthly\n";
        let config = load(text, 1).expect("a budgeted quota must load");
        let quota = config.quotas.first().expect("one quota");
        assert_eq!(quota.limits.budget_minor_units, 250_000);
        assert_eq!(
            quota.limits.budget_period,
            hypellm_core::admission::BudgetPeriod::Monthly
        );

        // Unset means no budget, consistent with every other limit here.
        let none = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=tenant:acme concurrency=4\n";
        let config = load(none, 1).expect("load");
        assert_eq!(
            config.quotas.first().map(|q| q.limits.budget_minor_units),
            Some(0)
        );
    }

    #[test]
    fn an_unknown_budget_period_is_an_error_rather_than_a_default() {
        // Defaulting a misspelled period to daily would silently apply a
        // monthly budget every day — thirty times the spend the operator
        // authorised.
        let text = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=tenant:acme budget=100 budget_period=weekly\n";
        let errors = load(text, 1).expect_err("this must not load");
        assert!(
            errors.iter().any(|e| e.code == "invalid_budget_period"),
            "expected invalid_budget_period, got: {errors:?}"
        );
    }

    #[test]
    fn a_quota_may_scope_to_an_alias_and_to_one_operation() {
        // Specification 12's admission table lists five layers; the
        // "Alias/model" one carries "operation-specific request/token and
        // context limits" and had no scope in the grammar at all.
        let text = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=alias:code concurrency=10\n\
quota scope=alias:code operation=embeddings concurrency=2\n";
        let config = load(text, 1).expect("an alias quota must load");
        assert_eq!(config.quotas.len(), 2);

        let wide = config.quotas.iter().find(|q| {
            matches!(&q.scope, QuotaScope::Alias { operation: None, .. })
        });
        assert!(wide.is_some(), "the alias-wide quota did not parse");

        let narrow = config.quotas.iter().find(|q| {
            matches!(
                &q.scope,
                QuotaScope::Alias {
                    operation: Some(op),
                    ..
                } if *op == hypellm_core::canonical::Operation::Embeddings
            )
        });
        assert_eq!(
            narrow.map(|q| q.limits.max_concurrency),
            Some(2),
            "the operation-specific quota did not parse"
        );
    }

    #[test]
    fn an_unknown_quota_operation_is_an_error_rather_than_a_wildcard() {
        // The fail-open shape this grammar's tests exist for: an operation that
        // does not parse must not quietly become "every operation", which would
        // apply a narrow limit far more widely than written — or, read the
        // other way, silently drop the restriction.
        let text = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=alias:code operation=not_an_operation concurrency=2\n";
        let errors = load(text, 1).expect_err("this must not load");
        assert!(
            errors.iter().any(|e| e.code == "invalid_operation"),
            "expected an invalid_operation error, got: {errors:?}"
        );
    }

    #[test]
    fn quota_partitions_divide_every_limit_so_the_deployment_honours_the_figure() {
        // `DI-029`: running N routers behind a load balancer multiplies every
        // tenant limit by N, because each counts alone. Specification 12
        // allows "conservative node partitions" as the answer that needs no
        // consensus, and this is the config half of it.
        let text = "\
settings state_dir=/tmp/x quota_partitions=4\n\
tenant id=acme\n\
quota scope=tenant:acme concurrency=40 queued=20 rps=100 burst=200 tpm=1000\n";
        let config = load(text, 1).expect("a partitioned configuration must load");
        let quota = config.quotas.first().expect("one quota");
        assert_eq!(quota.limits.max_concurrency, 10);
        assert_eq!(quota.limits.max_queued, 5);
        assert_eq!(quota.limits.requests_per_second, 25);
        assert_eq!(quota.limits.request_burst, 50);
        assert_eq!(quota.limits.tokens_per_minute, 250);

        // Unset leaves the figures exactly as written, which is what every
        // single-node deployment gets.
        let single = "\
settings state_dir=/tmp/x\n\
tenant id=acme\n\
quota scope=tenant:acme concurrency=40 queued=20 rps=100 burst=200 tpm=1000\n";
        let config = load(single, 1).expect("load");
        let quota = config.quotas.first().expect("one quota");
        assert_eq!(quota.limits.max_concurrency, 40);
        assert_eq!(quota.limits.tokens_per_minute, 1000);
    }

    #[test]
    fn a_quota_that_cannot_be_partitioned_is_a_configuration_error() {
        // Zero encodes "unlimited", so `concurrency=2` split eight ways would
        // divide to zero and become the loosest configuration expressible —
        // from the tightest one. Refused at load, naming the scope and both
        // numbers, because this is the sort of thing that is only noticed when
        // a limit that should have held does not.
        let text = "\
settings state_dir=/tmp/x quota_partitions=8\n\
tenant id=acme\n\
quota scope=tenant:acme concurrency=2\n";
        let errors = load(text, 1).expect_err("this must not load");
        assert!(
            errors.iter().any(|e| e.code == "quota_partition_underflow"),
            "expected a partition underflow, got: {errors:?}"
        );
        let message = errors
            .iter()
            .find(|e| e.code == "quota_partition_underflow")
            .map(|e| e.message.clone())
            .unwrap_or_default();
        assert!(
            message.contains("tenant:acme"),
            "the error must name the quota to edit: {message}"
        );
    }

    #[test]
    fn a_price_is_integer_arithmetic_that_rounds_up() {
        // Money in binary floating point is wrong in a way that compounds, and
        // Appendix B's determinism means two routers must compute the same
        // figure from the same inputs — so minor units and integers throughout.
        let price = PriceSchedule {
            target: hypellm_core::ids::TargetId::new("openai:gpt").expect("target"),
            input_per_million: 250,
            output_per_million: 1_000,
            cached_input_per_million: 25,
            currency: "USD".to_owned(),
            effective_from_millis: 0,
        };

        assert_eq!(price.cost_minor_units(1_000_000, 1_000_000, 1_000_000), 1_275);

        // Rounds *up*: an estimate that is too low is the one an operator acts
        // on and regrets. One input token is a fraction of a minor unit and
        // reports as one rather than as nothing.
        assert_eq!(price.cost_minor_units(1, 0, 0), 1);
        assert_eq!(price.cost_minor_units(0, 0, 0), 0);

        // Saturating rather than wrapping: an absurd token count produces an
        // absurd figure, never a small one. It does not reach `u64::MAX`
        // because the multiply saturates *before* the divide — which is the
        // correct order, and what stops the whole expression from wrapping.
        let absurd = price.cost_minor_units(u64::MAX, u64::MAX, u64::MAX);
        assert!(
            absurd > u64::from(u32::MAX),
            "an overflowing token count produced {absurd}, which reads as a small bill"
        );
        // Monotonic: more tokens never cost less.
        assert!(absurd >= price.cost_minor_units(u64::MAX / 2, 0, 0));
    }

    #[test]
    fn the_newest_effective_price_wins_and_a_future_one_does_not() {
        // What makes "effective dates" useful rather than a field somebody has
        // to edit at midnight: a price can be published ahead of time.
        let target = hypellm_core::ids::TargetId::new("openai:gpt").expect("target");
        let at = |from: u64, rate: u64| PriceSchedule {
            target: hypellm_core::ids::TargetId::new("openai:gpt").expect("target"),
            input_per_million: rate,
            output_per_million: rate,
            cached_input_per_million: rate,
            currency: "USD".to_owned(),
            effective_from_millis: from,
        };
        let prices = vec![at(0, 100), at(2_000, 300), at(1_000, 200)];

        assert_eq!(
            price_in_effect(&prices, &target, 0).map(|p| p.input_per_million),
            Some(100)
        );
        assert_eq!(
            price_in_effect(&prices, &target, 1_500).map(|p| p.input_per_million),
            Some(200),
            "the newest *past* price wins, whatever order the records are in"
        );
        assert_eq!(
            price_in_effect(&prices, &target, 5_000).map(|p| p.input_per_million),
            Some(300)
        );

        // A target with no price has none, rather than a zero that would report
        // a spend of nothing for something that costs money.
        let other = hypellm_core::ids::TargetId::new("anthropic:claude").expect("target");
        assert!(price_in_effect(&prices, &other, 5_000).is_none());
    }

    #[test]
    fn cached_input_defaults_to_the_input_price_rather_than_to_zero() {
        // A provider that discounts cached input still charges for it. An
        // omitted field must over-report rather than under-report.
        let text = "\
tenant id=acme
provider id=p family=openai scheme=https host=a.example
target id=p:m provider=p model=m operations=chat context=1000 max_output=100
alias id=a targets=p:m
grant scope=tenant:acme model=* allow=true
binding id=b scope=tenant:acme model=* prefer=p:m
price target=p:m input_per_million=250 output_per_million=1000
";
        let config = load(text, 1).expect("builds");
        let price = config.prices.first().expect("a price");
        assert_eq!(price.cached_input_per_million, 250);
        assert_eq!(price.currency, "USD");
    }

    #[test]
    fn a_price_for_an_undefined_target_is_an_error() {
        // Almost always a typo in the target id, and silently ignoring it would
        // report a spend of zero for a target that is costing money — the one
        // direction a cost estimate must not be wrong in.
        let text = "\
tenant id=acme
provider id=p family=openai scheme=https host=a.example
target id=p:m provider=p model=m operations=chat context=1000 max_output=100
alias id=a targets=p:m
grant scope=tenant:acme model=* allow=true
binding id=b scope=tenant:acme model=* prefer=p:m
price target=p:typo input_per_million=250
";
        let errors = load(text, 1).expect_err("must refuse");
        assert!(errors.iter().any(|e| e.code == "unknown_reference"));
    }

    use super::*;
    use hypellm_core::canonical::Operation;
    use hypellm_core::ids::{AliasId, ProviderId, TargetId, TenantId};
    use hypellm_core::target::{AdminState, EndpointScheme, ProviderFamily};

    /// A configuration exercising every record type.
    const FULL: &str = r#"
# Router-wide settings.
settings state_dir=/var/lib/hypellm admin_listen=127.0.0.1:9443 \
         weighted_tie_break=true cors_origins=https://admin.example

tenant id=acme inherit_global=true residency=eu
tenant id=other inherit_global=false

credential id=cred_openai scope=openai description="primary key"
credential id=cred_anthropic scope=anthropic

provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
provider id=openai family=openai scheme=https host=api.openai.com base_path=/v1 \
         credential=cred_openai egress=remote
provider id=anthropic family=anthropic scheme=https host=api.anthropic.com \
         credential=cred_anthropic egress=remote

target id=local:qwen provider=local model=qwen2.5-coder-32b local=true \
       operations=chat modalities=text streaming=true tools=true \
       context=65536 max_output=8192 cost=0 residency=eu concurrency=4 rps=20
target id=openai:gpt provider=openai model=gpt-4.1 operations=chat,embeddings \
       streaming=true tools=true json_mode=true structured_output=true \
       context=128000 max_output=16384 cost=4 residency=us
target id=anthropic:claude provider=anthropic model=claude-sonnet-5 \
       operations=chat streaming=true tools=true prompt_caching=true \
       context=200000 max_output=8192 cost=5 residency=eu

alias id=code-premium targets=local:qwen,anthropic:claude,openai:gpt \
      family_failover=true description="premium coding models"
alias id=code-fast targets=local:qwen

grant scope=tenant:acme model=* allow=true
grant scope=principal:user:42 model=code-premium allow=true

binding id=tenant-default scope=tenant:acme model=* prefer=local:qwen,openai:gpt
binding id=user-42 scope=principal:user:42 model=code-premium \
        prefer=local:qwen,anthropic:claude,openai:gpt deny=openai:* priority=10

quota scope=global concurrency=1000 rps=500 burst=1000
quota scope=tenant:acme concurrency=100 tpm=1000000 token_burst=50000
quota scope=target:local:qwen concurrency=4

group id=platform tenant=acme members=user:42,user:99 description="platform team"

role_binding subject=principal:user:42 role=viewer
role_binding subject=group:platform role=operator
"#;

    fn load_ok(text: &str) -> ValidatedConfig {
        load(text, 1).unwrap_or_else(|errors| {
            panic!(
                "expected success, got:\n{}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
    }

    fn load_err(text: &str) -> Vec<ConfigError> {
        load(text, 1).expect_err("expected failure")
    }

    fn codes(errors: &[ConfigError]) -> Vec<&str> {
        errors.iter().map(|e| e.code).collect()
    }

    #[test]
    fn full_configuration_builds() {
        let c = load_ok(FULL);

        assert_eq!(c.snapshot.providers.len(), 3);
        assert_eq!(c.snapshot.targets.len(), 3);
        assert_eq!(c.snapshot.aliases.len(), 2);
        assert_eq!(c.snapshot.bindings.len(), 2);
        assert_eq!(c.snapshot.grants.len(), 2);
        assert_eq!(c.quotas.len(), 3);
        assert_eq!(c.roles.len(), 2);
        assert_eq!(c.credentials.len(), 2);
        assert_eq!(c.tenants.len(), 2);

        assert_eq!(c.settings.state_dir, "/var/lib/hypellm");
        assert!(c.settings.weighted_tie_break);
        assert_eq!(c.settings.cors_origins, vec!["https://admin.example"]);
        assert!(!c.settings.allow_generic_adapter, "default is off");
        assert!(!c.settings.capture_bodies, "bodies are not captured by default");
    }

    #[test]
    fn capabilities_are_taken_from_declarations_only() {
        let c = load_ok(FULL);
        let qwen = c
            .snapshot
            .targets
            .get(&TargetId::new("local:qwen").unwrap())
            .expect("target");
        assert!(qwen.capabilities.streaming);
        assert!(qwen.capabilities.tools);
        assert!(qwen.is_local);
        assert_eq!(qwen.capabilities.max_context_tokens, 65_536);
        // Never declared, so never granted — specification 23.
        assert!(!qwen.capabilities.json_mode);
        assert!(!qwen.capabilities.structured_output);
        assert!(!qwen.capabilities.prompt_caching);
        assert!(!qwen.capabilities.reasoning);
        assert_eq!(qwen.capabilities.embedding_dimensions, None);

        let gpt = c
            .snapshot
            .targets
            .get(&TargetId::new("openai:gpt").unwrap())
            .expect("target");
        assert!(gpt.capabilities.supports_operation(Operation::Embeddings));
        assert!(gpt.capabilities.json_mode);
        assert!(!gpt.is_local);
        assert_eq!(gpt.admin_state, AdminState::Enabled);
    }

    #[test]
    fn preference_order_becomes_rank_order() {
        let c = load_ok(FULL);
        let binding = c
            .snapshot
            .bindings
            .iter()
            .find(|b| b.id.as_str() == "user-42")
            .expect("binding");
        assert_eq!(binding.preferences.len(), 3);
        assert_eq!(binding.preferences[0].rank, 0);
        assert_eq!(binding.preferences[1].rank, 1);
        assert_eq!(binding.preferences[2].rank, 2);
        assert_eq!(
            binding.preferences[0].selector,
            hypellm_core::policy::TargetSelector::Exact(TargetId::new("local:qwen").unwrap())
        );
        assert_eq!(
            binding.denies[0],
            hypellm_core::policy::TargetSelector::Provider(ProviderId::new("openai").unwrap())
        );
        assert_eq!(binding.priority, 10);
    }

    #[test]
    fn provider_families_and_endpoints_resolve() {
        let c = load_ok(FULL);
        let local = c
            .snapshot
            .providers
            .get(&ProviderId::new("local").unwrap())
            .expect("provider");
        assert_eq!(local.family, ProviderFamily::LlamaCpp);
        assert_eq!(local.endpoints[0].scheme, EndpointScheme::Http);
        assert_eq!(local.endpoints[0].port, 8080);
        assert!(local.credential_ref.is_none());

        let openai = c
            .snapshot
            .providers
            .get(&ProviderId::new("openai").unwrap())
            .expect("provider");
        assert_eq!(openai.endpoints[0].scheme, EndpointScheme::Https);
        assert_eq!(openai.endpoints[0].port, 443, "https defaults to 443");
        assert_eq!(openai.endpoints[0].base_path, "/v1");
        assert!(openai.credential_ref.is_some());
    }

    #[test]
    fn global_inheritance_follows_the_tenant_flag() {
        let c = load_ok(FULL);
        assert!(
            c.snapshot
                .global_inheritance
                .contains(&TenantId::new("acme").unwrap())
        );
        assert!(
            !c.snapshot
                .global_inheritance
                .contains(&TenantId::new("other").unwrap())
        );
    }

    // -- Reference resolution ------------------------------------------------

    #[test]
    fn dangling_references_are_rejected() {
        let cases = [
            (
                "target names a missing provider",
                "target id=t provider=nope model=m\nalias id=a targets=t\n",
            ),
            (
                "alias names a missing target",
                "alias id=a targets=missing\n",
            ),
            (
                "binding prefers a missing target",
                "binding id=b scope=global prefer=missing\n",
            ),
            (
                "binding pins a missing target",
                "binding id=b scope=global pin=missing\n",
            ),
            (
                "binding denies a missing provider",
                "binding id=b scope=global deny=nope:*\n",
            ),
            (
                "quota names a missing target",
                "quota scope=target:missing concurrency=1\n",
            ),
        ];
        for (name, text) in cases {
            let errors = load_err(text);
            assert!(
                codes(&errors).contains(&"unresolved_reference"),
                "{name}: got {:?}",
                codes(&errors)
            );
        }
    }

    #[test]
    fn a_provider_credential_must_be_declared() {
        let text = "\
provider id=p family=openai scheme=https host=api.example credential=cred_missing
target id=t provider=p model=m
alias id=a targets=t
";
        assert!(codes(&load_err(text)).contains(&"unresolved_reference"));
    }

    #[test]
    fn unreachable_targets_are_rejected() {
        // A target no alias lists can never be selected; it is configuration
        // that looks active but is not.
        let text = "\
provider id=p family=openai scheme=https host=api.example
target id=t provider=p model=m
";
        assert!(codes(&load_err(text)).contains(&"unreachable_target"));
    }

    #[test]
    fn duplicate_identifiers_are_rejected() {
        let text = "\
provider id=p family=openai scheme=https host=api.example
provider id=p family=anthropic scheme=https host=api2.example
";
        assert!(codes(&load_err(text)).contains(&"duplicate_id"));
    }

    #[test]
    fn duplicate_settings_records_are_rejected() {
        let text = "settings state_dir=/a\nsettings state_dir=/b\n";
        assert!(codes(&load_err(text)).contains(&"duplicate_singleton"));
    }

    // -- Egress and transport safety -----------------------------------------

    #[test]
    fn cleartext_to_a_remote_host_is_rejected() {
        // Specification 8.1: "remote cleartext forbidden". A provider
        // credential sent over plaintext to a named host is disclosed.
        for host in ["api.example.com", "10.0.0.5", "1.2.3.4"] {
            let text = format!(
                "provider id=p family=openai scheme=http host={host}\n\
                 target id=t provider=p model=m\nalias id=a targets=t\n"
            );
            let errors = load_err(&text);
            assert!(
                codes(&errors).contains(&"cleartext_not_permitted")
                    || codes(&errors).contains(&"endpoint_not_permitted"),
                "host {host} produced {:?}",
                codes(&errors)
            );
        }
        // Loopback cleartext is the documented local-development case.
        let text = "\
provider id=p family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=t provider=p model=m local=true
alias id=a targets=t
";
        assert!(load(text, 1).is_ok());
    }

    #[test]
    fn metadata_and_private_endpoints_are_rejected_under_the_remote_profile() {
        for host in ["169.254.169.254", "10.0.0.1", "192.168.1.1", "127.0.0.1"] {
            let text = format!(
                "provider id=p family=openai scheme=https host={host} egress=remote\n\
                 target id=t provider=p model=m\nalias id=a targets=t\n"
            );
            let errors = load_err(&text);
            assert!(
                codes(&errors).contains(&"endpoint_not_permitted"),
                "host {host} produced {:?}",
                codes(&errors)
            );
        }
    }

    #[test]
    fn the_metadata_address_is_rejected_under_every_profile() {
        for profile in ["remote", "local", "private_network", "none"] {
            let text = format!(
                "provider id=p family=openai scheme=https host=169.254.169.254 egress={profile}\n\
                 target id=t provider=p model=m\nalias id=a targets=t\n"
            );
            assert!(
                codes(&load_err(&text)).contains(&"endpoint_not_permitted"),
                "profile {profile} admitted the metadata address"
            );
        }
    }

    #[test]
    fn a_private_endpoint_needs_the_private_network_profile() {
        let text = "\
provider id=p family=openai scheme=https host=10.1.2.3 egress=private_network
target id=t provider=p model=m
alias id=a targets=t
";
        assert!(load(text, 1).is_ok());
    }

    #[test]
    fn unix_endpoints_require_an_absolute_path() {
        let ok = "\
provider id=p family=llamacpp scheme=unix host=/run/llama.sock egress=local
target id=t provider=p model=m local=true
alias id=a targets=t
";
        assert!(load(ok, 1).is_ok());

        let bad = ok.replace("host=/run/llama.sock", "host=run/llama.sock");
        assert!(codes(&load_err(&bad)).contains(&"invalid_endpoint"));
    }

    #[test]
    fn malformed_hosts_are_rejected() {
        for host in ["evil.example@internal", r#""has space""#, "host/path"] {
            let text = format!(
                "provider id=p family=openai scheme=https host={host}\n\
                 target id=t provider=p model=m\nalias id=a targets=t\n"
            );
            let errors = load_err(&text);
            assert!(
                codes(&errors).contains(&"invalid_endpoint"),
                "host {host} produced {:?}",
                codes(&errors)
            );
        }
    }

    #[test]
    fn the_generic_adapter_requires_an_explicit_opt_in() {
        // Specification 25: "Disabled by default; fixed endpoint and explicit
        // capabilities required."
        let text = "\
provider id=p family=generic_openai scheme=https host=api.example
target id=t provider=p model=m
alias id=a targets=t
";
        assert!(codes(&load_err(text)).contains(&"generic_adapter_not_enabled"));

        let enabled = format!("settings allow_generic_adapter=true\n{text}");
        assert!(load(&enabled, 1).is_ok());
    }

    #[test]
    fn an_invalid_model_selector_is_rejected_rather_than_widened() {
        // This used to fall back to `ModelSelector::Any`, so a typo in a grant
        // silently widened it from one alias to every alias — a fail-open in
        // the first filter specification 6.2 lists.
        let grant = "\
tenant id=acme
grant scope=tenant:acme model=\"not a valid alias\" allow=true
";
        assert!(codes(&load_err(grant)).contains(&"invalid_identifier"));

        let binding = "\
tenant id=acme
provider id=p family=openai scheme=https host=a.example
target id=t provider=p model=m
alias id=a targets=t
binding id=b scope=tenant:acme model=\"not a valid alias\" prefer=t
";
        assert!(codes(&load_err(binding)).contains(&"invalid_identifier"));
    }

    #[test]
    fn an_explicitly_empty_model_selector_is_rejected() {
        // Found by the fuzz target. `opt_str` treats an empty value as
        // absence, and an absent `model` legitimately means every alias — so
        // `model=` silently widened a grant to everything. Nobody writes
        // `model=` on purpose; it is a truncated line or a substitution that
        // produced nothing.
        let grant = "\
tenant id=acme
grant scope=tenant:acme model= allow=true
";
        assert!(codes(&load_err(grant)).contains(&"empty_field"));

        // Omitting it entirely is still the way to say "every alias".
        let omitted = "\
tenant id=acme
grant scope=tenant:acme allow=true
";
        let c = load_ok(omitted);
        assert!(matches!(
            c.snapshot.grants.first().map(|g| &g.model),
            Some(hypellm_core::policy::ModelSelector::Any)
        ));
    }

    #[test]
    fn valid_model_selectors_still_parse() {
        // The wildcard, a prefix, and an exact alias must all survive.
        let text = "\
tenant id=acme
provider id=p family=openai scheme=https host=a.example
target id=t provider=p model=m
alias id=code targets=t
grant scope=tenant:acme model=* allow=true
grant scope=tenant:acme model=code allow=true
grant scope=tenant:acme model=cod* allow=true
";
        let c = load_ok(text);
        assert_eq!(c.snapshot.grants.len(), 3);
    }

    #[test]
    fn a_tenant_cost_ceiling_is_read_from_configuration() {
        // Specification 6.2: "Estimated cost class and actual policy ceiling
        // permit selection." The ceiling is policy, so it must come from here
        // and not from a request field a caller could raise.
        let text = "\
tenant id=acme max_cost=3
tenant id=other
";
        let c = load_ok(text);
        let acme = c.tenants.get(&TenantId::new("acme").unwrap()).expect("acme");
        assert_eq!(acme.max_cost_class.map(|c| c.0), Some(3));

        // Absent means no ceiling, not a ceiling of zero — which would refuse
        // every target.
        let other = c.tenants.get(&TenantId::new("other").unwrap()).expect("other");
        assert_eq!(other.max_cost_class, None);
    }

    #[test]
    fn an_out_of_range_cost_ceiling_is_rejected() {
        assert!(codes(&load_err("tenant id=acme max_cost=42")).contains(&"invalid_cost_class"));
    }

    // -- Identity binding ----------------------------------------------------

    #[test]
    fn an_identity_binds_an_external_subject_to_a_local_principal() {
        // Specification 9.1: the stable identity is the (iss, sub) pair, and
        // authorization is by local role binding "never by email domain".
        //
        // Before this record existed the callback tried to use "{iss}|{sub}"
        // as a principal identifier. `|` and `/` are not legal in one, so every
        // sign-in was refused and the router could not be signed into at all.
        let text = "\
tenant id=acme
tenant id=other
identity issuer=https://accounts.google.com subject=1234567890 \\
         principal=user:operator tenant=other description=\"the on-call engineer\"
";
        let c = load_ok(text);
        assert_eq!(c.identities.len(), 1);
        let identity = c.identities.first().expect("the binding");
        assert_eq!(identity.issuer, "https://accounts.google.com");
        assert_eq!(identity.subject, "1234567890");
        assert_eq!(identity.principal.as_str(), "user:operator");
        // The tenant is the one named, not whichever sorts first — "acme"
        // would win a map-order lookup and is deliberately not the answer.
        assert_eq!(identity.tenant.as_str(), "other");
    }

    #[test]
    fn an_identity_naming_an_undefined_tenant_is_rejected() {
        let text = "\
tenant id=acme
identity issuer=https://accounts.google.com subject=1 principal=user:a tenant=nosuch
";
        assert!(codes(&load_err(text)).contains(&"unresolved_reference"));
    }

    #[test]
    fn one_external_subject_cannot_be_bound_twice() {
        // Two bindings for one (issuer, subject) would make the principal an
        // operator signs in as depend on record order.
        let text = "\
tenant id=acme
identity issuer=https://accounts.google.com subject=1 principal=user:a tenant=acme
identity issuer=https://accounts.google.com subject=1 principal=user:b tenant=acme
";
        assert!(codes(&load_err(text)).contains(&"duplicate_record"));
    }

    #[test]
    fn the_same_subject_at_a_different_issuer_is_a_different_identity() {
        // The subject is only unique within its issuer, so the pair is the key.
        let text = "\
tenant id=acme
identity issuer=https://accounts.google.com subject=1 principal=user:a tenant=acme
identity issuer=https://login.example.com subject=1 principal=user:b tenant=acme
";
        let c = load_ok(text);
        assert_eq!(c.identities.len(), 2);
    }

    #[test]
    fn an_identity_with_an_empty_issuer_or_subject_is_rejected() {
        for text in [
            "tenant id=acme\nidentity issuer= subject=1 principal=user:a tenant=acme\n",
            "tenant id=acme\nidentity issuer=https://a subject= principal=user:a tenant=acme\n",
        ] {
            assert!(
                !load(text, 1).is_ok(),
                "an empty identity component was accepted: {text}"
            );
        }
    }

    // -- Group membership ----------------------------------------------------

    #[test]
    fn group_membership_is_declared_not_inferred() {
        // Specification 25: "Local role bindings or separately provisioned
        // directory sync; do not infer Google group membership from email
        // domain." Membership is exactly what the record lists.
        let c = load_ok(FULL);
        assert_eq!(c.groups.len(), 1);
        let group = c.groups.first().expect("the platform group");
        assert_eq!(group.id.as_str(), "platform");
        assert_eq!(group.tenant.as_str(), "acme");

        let members: Vec<&str> = group.members.iter().map(|p| p.as_str()).collect();
        assert_eq!(members, vec!["user:42", "user:99"]);
        assert!(!members.contains(&"user:1"), "membership must not be open");
    }

    #[test]
    fn a_group_naming_an_undefined_tenant_is_rejected() {
        let text = "\
tenant id=acme
group id=g tenant=nosuch members=user:1
";
        assert!(codes(&load_err(text)).contains(&"unresolved_reference"));
    }

    #[test]
    fn a_duplicate_group_is_rejected() {
        // Two records with one identifier would make membership depend on
        // record order.
        let text = "\
tenant id=acme
group id=g tenant=acme members=user:1
group id=g tenant=acme members=user:2
";
        assert!(codes(&load_err(text)).contains(&"duplicate_record"));
    }

    #[test]
    fn a_repeated_member_within_one_group_is_rejected() {
        let text = "\
tenant id=acme
group id=g tenant=acme members=user:1,user:1
";
        assert!(codes(&load_err(text)).contains(&"duplicate_member"));
    }

    #[test]
    fn a_binding_or_role_naming_an_undefined_group_is_rejected() {
        // A group binding that matches nothing reads as an effective policy but
        // silently never applies.
        let binding = "\
tenant id=acme
provider id=p family=openai scheme=https host=a.example
target id=t provider=p model=m
alias id=a targets=t
binding id=b scope=group:ghost model=a prefer=t
";
        assert!(codes(&load_err(binding)).contains(&"unresolved_reference"));

        let role = "\
tenant id=acme
role_binding subject=group:ghost role=operator
";
        assert!(codes(&load_err(role)).contains(&"unresolved_reference"));
    }

    // -- Field validation ----------------------------------------------------

    #[test]
    fn invalid_enumerated_values_are_rejected() {
        let cases = [
            ("invalid_family", "provider id=p family=notreal scheme=https host=a.example"),
            ("invalid_scheme", "provider id=p family=openai scheme=ftp host=a.example"),
            ("invalid_egress_profile", "provider id=p family=openai scheme=https host=a.example egress=anything"),
            ("invalid_role", "role_binding subject=principal:u role=superuser"),
            ("invalid_scope", "binding id=b scope=nonsense"),
            ("invalid_subject", "role_binding subject=nonsense role=viewer"),
        ];
        for (code, text) in cases {
            let errors = load_err(text);
            assert!(
                codes(&errors).contains(&code),
                "{text} produced {:?}, expected {code}",
                codes(&errors)
            );
        }
    }

    #[test]
    fn a_fallback_without_a_pin_is_rejected() {
        // A fallback list only means something in the presence of a pin;
        // silently ignoring it would look like configured failover that never
        // takes effect.
        let text = "binding id=b scope=global fallback=t1\n";
        assert!(codes(&load_err(text)).contains(&"fallback_without_pin"));
    }

    #[test]
    fn an_alias_with_no_targets_is_rejected() {
        let text = "alias id=a targets=\"\"\n";
        assert!(codes(&load_err(text)).contains(&"empty_alias"));
    }

    #[test]
    fn unknown_fields_and_records_are_rejected() {
        assert!(codes(&load_err("provider id=p family=openai scheme=https host=a.example typo=1"))
            .contains(&"unknown_field"));
        assert!(codes(&load_err("include path=/etc/passwd")).contains(&"unknown_record_type"));
    }

    #[test]
    fn every_error_is_reported_not_just_the_first() {
        // An operator fixing a configuration should see the whole list.
        let text = "\
alias id=a1 targets=missing1
alias id=a2 targets=missing2
alias id=a3 targets=missing3
";
        let errors = load_err(text);
        assert!(errors.len() >= 3, "expected several errors, got {errors:?}");
    }

    // -- Digest --------------------------------------------------------------

    #[test]
    fn the_digest_is_stable_across_cosmetic_changes() {
        let a = load_ok(FULL);

        // Reformat: reorder records, change spacing, add comments.
        let reordered = {
            let mut lines: Vec<&str> = FULL.lines().collect();
            lines.reverse();
            // Reversing splits continuations, so rebuild from the canonical
            // form instead, which has no continuations.
            let _ = lines;
            a.canonical.clone()
        };
        let b = load_ok(&reordered);
        assert_eq!(a.digest, b.digest, "canonical form must reproduce the digest");
        assert_eq!(a.canonical, b.canonical);
    }

    #[test]
    fn the_digest_changes_when_meaning_changes() {
        let a = load_ok(FULL);
        let modified = FULL.replace("context=65536", "context=32768");
        let b = load_ok(&modified);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn comments_and_whitespace_do_not_affect_the_digest() {
        let base = "\
provider id=p family=openai scheme=https host=api.example
target id=t provider=p model=m
alias id=a targets=t
";
        let noisy = "\
# leading comment

provider    id=p   family=openai   scheme=https   host=api.example    # note

target id=t provider=p model=m

alias id=a targets=t
# trailing comment
";
        assert_eq!(load_ok(base).digest, load_ok(noisy).digest);
    }

    #[test]
    fn the_version_is_carried_into_the_snapshot() {
        let document = parse(FULL, &ParseLimits::DEFAULT).unwrap();
        let c = build(&document, 42).unwrap();
        assert_eq!(c.snapshot.version, 42);
    }

    // -- Routing over a built snapshot ---------------------------------------

    #[test]
    fn the_built_snapshot_routes() {
        use hypellm_core::canonical::{
            CanonicalRequest, ClientProtocol, Message, RequestLimits, Role, Sampling, StreamOptions,
        };
        use hypellm_core::ids::{PrincipalId, RequestId};
        use hypellm_core::policy::{IdealLiveState, RoutingContext};
        use hypellm_core::time::{Deadline, TestClock};
        use std::time::Duration;

        let c = load_ok(FULL);
        let clock = TestClock::new();
        let principal = PrincipalId::new("user:42").unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let groups = Vec::new();
        let attempted = Vec::new();
        let ctx = RoutingContext {
            principal: &principal,
            groups: &groups,
            tenant: &tenant,
            attempted: &attempted,
            now_millis: 0,
        };

        let req = CanonicalRequest {
            request_id: RequestId::from_u128(1),
            tenant: tenant.clone(),
            principal: principal.clone(),
            protocol: ClientProtocol::OpenAiChat,
            operation: Operation::Chat,
            requested_model: AliasId::new("code-premium").unwrap(),
            messages: vec![Message::text(Role::User, "hello")],
            inputs: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            response_format: None,
            sampling: Sampling::default(),
            reasoning_effort: Default::default(),
            limits: RequestLimits {
                max_output_tokens: Some(1024),
                deadline: Deadline::after(&clock, Duration::from_secs(60)),
                max_cost_class: None,
                min_quality_class: None,
                residency: None,
            },
            stream: StreamOptions {
                enabled: true,
                include_usage: false,
            },
            hints: hypellm_core::canonical::RoutingHints::default(),
        };

        let outcome = c.snapshot.route(&ctx, &req, &IdealLiveState);
        assert_eq!(
            outcome.candidates.first().map(|x| x.target.as_str()),
            Some("local:qwen"),
            "the user-42 binding ranks local first"
        );
        // The user-42 binding denies the whole openai provider.
        assert!(
            outcome
                .exclusions
                .iter()
                .any(|e| e.target.as_str() == "openai:gpt"
                    && e.reason == hypellm_core::decision::ExclusionReason::DeniedByPolicy)
        );
    }
}
