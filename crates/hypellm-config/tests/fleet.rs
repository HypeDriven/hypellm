//! Configuration tests for the fleet records and the document limits.
//!
//! Validation is off-path and fails closed. Every rule here rejects a
//! configuration that would produce a bad decision *later*, when the cost is
//! minutes of fleet time rather than a refused reload — and each test names the
//! decision it prevents rather than the field it checks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_config::{ParseLimits, ValidatedConfig, build, parse};

/// The smallest configuration that routes, before any fleet records.
const BASE: &str = r#"
settings state_dir=/var/lib/hypellm fleet_enabled=true
tenant id=acme
credential id=cred_local
provider id=spark family=llamacpp scheme=http host=10.0.0.105 port=8000 \
         egress=private_network
target id=spark:music3 provider=spark model=minimax-music3 capabilities=text-to-music \
       context=8192 max_output=4096 local=false
target id=spark:qwen38 provider=spark model=qwen38-27b capabilities=chat \
       context=131072 max_output=32768 local=false
alias id=music-standard capability=text-to-music targets=spark:music3
alias id=chat-standard capability=chat targets=spark:qwen38
grant scope=tenant:acme allow=true
binding id=default scope=tenant:acme prefer=spark:music3
"#;

fn load(extra: &str) -> Result<ValidatedConfig, Vec<String>> {
    let text = format!("{BASE}\n{extra}\n");
    let document = parse(&text, &ParseLimits::DEFAULT).map_err(|e| vec![e.to_string()])?;
    build(&document, 1).map_err(|errors| errors.iter().map(|e| e.code.to_owned()).collect())
}

fn codes(extra: &str) -> Vec<String> {
    load(extra).err().unwrap_or_default()
}

/// A complete, valid Spark declaration.
const SPARK: &str = r#"
fleet_agent id=local socket="/run/hypellm/fleet.sock" \
    observation_interval_ms=5000 observation_max_age_ms=30000
host id=spark agent=local arch=aarch64 status=enabled \
    reserved_memory_bytes=17179869184 max_concurrent_activations=1
accelerator host=spark id=gb10 kind=unified pool=spark-unified \
    memory_bytes=140384485376
deployment id=spark-music3 target=spark:music3 accelerator=gb10 \
    memory_bytes=68719476736 start_ms=180000 stop_ms=15000 drain_ms=30000 \
    probe_ms=10000 min_resident_ms=600000 autostart=true readiness=http_ok
"#;

#[test]
fn a_complete_fleet_declaration_builds() {
    let config = load(SPARK).expect("the fleet in the design document must build");
    assert!(config.fleet.enabled);
    assert_eq!(config.fleet.hosts.len(), 1);
    assert_eq!(config.fleet.accelerators.len(), 1);
    assert_eq!(config.fleet.deployments.len(), 1);
    // 140,384,485,376 less the 17,179,869,184 host reservation.
    let pool = hypellm_core::ids::PoolId::new("spark-unified").unwrap();
    assert_eq!(
        config.fleet.pool_capacity_bytes(&pool),
        140_384_485_376 - 17_179_869_184
    );
    assert!(!config.fleet.digest().is_empty());
}

#[test]
fn a_configuration_with_no_fleet_records_is_still_valid_and_inert() {
    // The compatibility promise: every configuration written before
    // orchestration existed keeps working, and routes identically.
    let config = load("").expect("a fleet-free configuration must still build");
    assert!(config.fleet.deployments.is_empty());
    assert!(
        !config.fleet.is_active(),
        "a fleet with no deployments has nothing to orchestrate"
    );
}

#[test]
fn a_deployment_larger_than_its_pool_is_refused_at_load() {
    // It could never be placed, so it is an activation that would always fail —
    // after paying for whatever it displaced.
    let oversized = SPARK.replace("memory_bytes=68719476736", "memory_bytes=999999999999");
    assert!(codes(&oversized).contains(&"deployment_exceeds_pool".to_owned()));
}

#[test]
fn two_deployments_for_one_target_are_refused() {
    // "Which of these is resident" would otherwise be answered by map order. A
    // model runnable in two places is two targets sharing an alias.
    let twice = format!(
        "{SPARK}
deployment id=spark-music3-again target=spark:music3 accelerator=gb10 \\
    memory_bytes=1073741824"
    );
    assert!(codes(&twice).contains(&"duplicate_deployment_target".to_owned()));
}

#[test]
fn an_artifact_on_the_wrong_architecture_is_refused_before_it_is_downloaded() {
    // An x86-64 image will never run on the Spark, and discovering that after
    // forty gigabytes is the most expensive way to learn it.
    let mismatched = format!(
        "{SPARK}
artifact id=music3-x86 kind=image arch=x86_64 size_bytes=1024 \\
    digest=\"sha256:{}\" source=mirror
deployment id=spark-other target=spark:qwen38 accelerator=gb10 \\
    memory_bytes=1073741824 artifact=music3-x86",
        "0".repeat(64)
    );
    assert!(codes(&mismatched).contains(&"artifact_arch_mismatch".to_owned()));
}

#[test]
fn a_dangling_reference_is_refused() {
    for (extra, code) in [
        (
            "deployment id=nowhere target=spark:qwen38 accelerator=missing memory_bytes=1",
            "unresolved_reference",
        ),
        (
            "deployment id=ghost target=spark:absent accelerator=gb10 memory_bytes=1",
            "unresolved_reference",
        ),
        (
            "host id=orphan agent=missing arch=x86_64",
            "unresolved_reference",
        ),
        (
            "accelerator host=missing id=gpu0 kind=cuda memory_bytes=1",
            "unresolved_reference",
        ),
    ] {
        let text = format!("{SPARK}\n{extra}");
        assert!(
            codes(&text).contains(&code.to_owned()),
            "{extra} was accepted"
        );
    }
}

#[test]
fn a_budget_that_underflows_to_zero_is_refused_with_an_alternative() {
    // A fleet that can never start anything, reported as an eligibility
    // rejection on every request, is worse than a configuration error — the
    // operator's intent is expressible, and the error says how.
    let text = format!("{SPARK}\nfleet_policy scope=fleet max_activations_per_hour=0");
    assert!(codes(&text).contains(&"invalid_budget".to_owned()));

    let text = format!("{SPARK}\nfleet_policy scope=fleet max_eviction_set=0");
    assert!(codes(&text).contains(&"invalid_budget".to_owned()));
}

#[test]
fn a_per_host_policy_overrides_the_fleet_default_whatever_the_record_order() {
    // Record order in a file must not change the effective limits.
    let after = format!(
        "{SPARK}
fleet_policy scope=fleet max_activations_per_hour=6
fleet_policy scope=host:spark max_eviction_set=1"
    );
    let before = format!(
        "{SPARK}
fleet_policy scope=host:spark max_eviction_set=1
fleet_policy scope=fleet max_activations_per_hour=6"
    );
    let host = hypellm_core::ids::HostId::new("spark").unwrap();
    for text in [after, before] {
        let config = load(&text).expect("builds");
        let policy = config.fleet.policy_for(&host);
        assert_eq!(policy.max_eviction_set, 1);
        assert_eq!(
            policy.max_activations_per_hour, 6,
            "a host override must inherit the fleet default it did not restate"
        );
    }
}

#[test]
fn an_observation_window_shorter_than_its_interval_is_refused() {
    // Belief that expires before the next observation is due means every
    // decision is made against stale state: a fleet that refuses everything and
    // cannot say why.
    let text = SPARK.replace("observation_max_age_ms=30000", "observation_max_age_ms=1000");
    assert!(codes(&text).contains(&"invalid_interval".to_owned()));
}

#[test]
fn a_malformed_artifact_digest_is_refused() {
    for digest in ["sha256:short", "deadbeef", "sha512:0000"] {
        let text = format!(
            "{SPARK}
artifact id=bad kind=image arch=aarch64 digest=\"{digest}\""
        );
        assert!(
            codes(&text).contains(&"invalid_digest".to_owned()),
            "{digest} was accepted"
        );
    }
}

#[test]
fn a_pool_shared_by_two_hosts_is_refused() {
    // The host reservation would belong to neither, and evicting on one machine
    // would appear to free memory on the other.
    let text = format!(
        "{SPARK}
host id=rtx5090 agent=local arch=x86_64
accelerator host=rtx5090 id=rtx0 kind=cuda memory_bytes=34359738368 pool=spark-unified"
    );
    assert!(codes(&text).contains(&"pool_spans_hosts".to_owned()));
}

#[test]
fn a_deployment_declaring_no_memory_is_refused() {
    let text = SPARK.replace("memory_bytes=68719476736", "memory_bytes=0");
    assert!(codes(&text).contains(&"invalid_memory".to_owned()));
}

#[test]
fn autostart_is_off_unless_declared() {
    // Routing demand starting a model is the feature; a configuration that
    // acquires it by omission is not.
    let text = SPARK.replace("autostart=true ", "");
    let config = load(&text).expect("builds");
    let deployment = hypellm_core::ids::DeploymentId::new("spark-music3").unwrap();
    assert!(!config.fleet.deployments[&deployment].autostart);
}

// -- Document limits ---------------------------------------------------------

#[test]
fn inline_document_limits_cannot_be_configured_to_exceed_the_body_limit() {
    // Base64 inflates by 4/3, so an aggregate that fits decoded may not fit on
    // the wire. A configuration that admits more than the body limit produces
    // requests that pass every declared bound and are then refused by the body
    // reader — a rejection naming the wrong limit.
    let text = "settings state_dir=/tmp max_body_bytes=1048576 \
                max_inline_document_bytes=1048576\ntenant id=acme";
    let document = parse(text, &ParseLimits::DEFAULT).expect("parses");
    let errors = build(&document, 1).expect_err("must be refused");
    assert!(
        errors.iter().any(|e| e.code == "invalid_document_limits"),
        "{errors:?}"
    );
}

#[test]
fn a_per_part_document_limit_above_the_aggregate_is_refused() {
    let text = "settings state_dir=/tmp max_document_bytes=16777216 \
                max_inline_document_bytes=8388608\ntenant id=acme";
    let document = parse(text, &ParseLimits::DEFAULT).expect("parses");
    let errors = build(&document, 1).expect_err("must be refused");
    assert!(errors.iter().any(|e| e.code == "invalid_document_limits"));
}

#[test]
fn the_default_document_limits_fit_the_default_body_limit() {
    // The defaults have to satisfy their own rule, or every deployment starts
    // with a configuration error.
    let document = parse("tenant id=acme", &ParseLimits::DEFAULT).expect("parses");
    let config = build(&document, 1).expect("the defaults must be self-consistent");
    let encoded = config
        .settings
        .max_inline_document_bytes
        .div_ceil(3)
        .saturating_mul(4);
    assert!(encoded <= config.settings.max_body_bytes);
}

// -- Capability contract on targets ------------------------------------------

#[test]
fn an_effort_multiplier_for_an_undeclared_tier_is_refused() {
    // A multiplier for a tier the target refuses reads, to whoever edits the
    // file next, as evidence that the tier is served.
    let text = "target id=spark:x provider=spark model=m reasoning_efforts=low \
                effort_multipliers=high:8";
    assert!(codes(text).contains(&"undeclared_reasoning_effort".to_owned()));
}

#[test]
fn unset_is_not_a_declarable_reasoning_tier() {
    let text = "target id=spark:x provider=spark model=m reasoning_efforts=unset";
    assert!(codes(text).contains(&"invalid_reasoning_effort".to_owned()));
}

#[test]
fn an_out_of_range_quality_class_is_an_error_rather_than_a_clamp() {
    // A typo that silently satisfied every floor in the configuration would be
    // worse than a refused reload.
    let text = "target id=spark:x provider=spark model=m quality_class=50";
    assert!(codes(text).contains(&"invalid_quality_class".to_owned()));
}

#[test]
fn a_target_declares_its_capabilities_efforts_and_quality() {
    let text = "target id=spark:tuned provider=spark model=m \
                capabilities=chat,vision reasoning_efforts=low,medium,high \
                effort_multipliers=medium:6,high:12 quality_class=7 \
                document_token_estimate=2048 modalities=text,image,document\n\
                alias id=tuned capability=chat targets=spark:tuned";
    let config = load(text).expect("builds");
    let target = &config.snapshot.targets[&hypellm_core::ids::TargetId::new("spark:tuned").unwrap()];
    assert_eq!(
        target.capabilities.verbs,
        vec![
            hypellm_core::target::Capability::Chat,
            hypellm_core::target::Capability::Vision
        ]
    );
    assert_eq!(target.capabilities.effort_multipliers.medium, 6);
    assert_eq!(target.capabilities.effort_multipliers.high, 12);
    // A tier the operator did not restate keeps its default.
    assert_eq!(target.capabilities.effort_multipliers.low, 2);
    assert_eq!(target.quality_class.0, 7);
    assert_eq!(target.document_token_estimate, Some(2048));
    assert!(
        target
            .capabilities
            .modalities
            .contains(&hypellm_core::canonical::Modality::Document)
    );
}

#[test]
fn an_unknown_capability_verb_is_refused_rather_than_ignored() {
    let text = "target id=spark:x provider=spark model=m capabilities=telepathy";
    assert!(codes(text).contains(&"invalid_capability".to_owned()));

    let text = "alias id=weird capability=telepathy targets=spark:music3";
    assert!(codes(text).contains(&"invalid_capability".to_owned()));
}
