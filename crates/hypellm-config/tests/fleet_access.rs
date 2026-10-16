//! Configuration tests for `fleet_grant` and `settings fleet_access_default`.
//!
//! A fleet grant that names something that does not exist never matches, and
//! for a deny that is a policy that silently fails open. Every reference is
//! therefore checked at load, and each test names the fail-open it prevents.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_config::{ParseLimits, ValidatedConfig, build, parse};
use hypellm_core::fleet_access::FleetAccessDefault;
use hypellm_core::ids::{HostId, TargetId};

const BASE: &str = r#"
settings state_dir=/var/lib/hypellm fleet_enabled=true
tenant id=acme
group id=devs tenant=acme members=user:42
credential id=cred_local
provider id=spark family=llamacpp scheme=http host=10.0.0.105 port=8000 \
         egress=private_network
provider id=gpu2 family=llamacpp scheme=http host=10.0.0.106 port=8000 \
         egress=private_network
target id=spark:qwen provider=spark model=qwen capabilities=chat context=8192 max_output=4096
target id=gpu2:qwen provider=gpu2 model=qwen capabilities=chat context=8192 max_output=4096
target id=spark:remote provider=spark model=other capabilities=chat context=8192 max_output=4096
alias id=chat targets=spark:qwen,gpu2:qwen,spark:remote
grant scope=tenant:acme allow=true
binding id=default scope=tenant:acme prefer=*
fleet_agent id=local socket="/run/hypellm/fleet.sock"
host id=spark agent=local arch=aarch64
host id=gpu2 agent=local arch=x86_64
accelerator id=spark-gpu0 host=spark kind=cuda memory_bytes=100000000000
accelerator id=gpu2-gpu0 host=gpu2 kind=cuda memory_bytes=100000000000
deployment id=d-spark target=spark:qwen accelerator=spark-gpu0 memory_bytes=1000
deployment id=d-gpu2 target=gpu2:qwen accelerator=gpu2-gpu0 memory_bytes=1000
"#;

fn load(extra: &str) -> Result<ValidatedConfig, Vec<String>> {
    load_with_settings("", extra)
}

/// `settings` is a singleton, so extra settings join the base record.
fn load_with_settings(settings: &str, extra: &str) -> Result<ValidatedConfig, Vec<String>> {
    let base = BASE.replace("fleet_enabled=true", &format!("fleet_enabled=true {settings}"));
    let text = format!("{base}\n{extra}\n");
    let document = parse(&text, &ParseLimits::DEFAULT).map_err(|e| vec![e.to_string()])?;
    build(&document, 1).map_err(|errors| errors.iter().map(|e| e.code.to_owned()).collect())
}

fn codes(extra: &str) -> Vec<String> {
    load(extra).err().unwrap_or_default()
}

#[test]
fn a_configuration_without_fleet_grants_lets_every_existing_credential_use_every_slave() {
    let config = load("").expect("builds");
    assert_eq!(config.snapshot.fleet_access_default, FleetAccessDefault::Allow);
    assert!(config.snapshot.fleet_grants.is_empty());
    // Placement comes from declared deployments; the undeployed target is not
    // fleet-managed.
    let placement = &config.snapshot.fleet_placement;
    assert_eq!(
        placement.get(&TargetId::new("spark:qwen").unwrap()),
        Some(&HostId::new("spark").unwrap())
    );
    assert!(!placement.contains_key(&TargetId::new("spark:remote").unwrap()));
}

#[test]
fn every_selector_form_builds() {
    let config = load_with_settings(
        "fleet_access_default=deny",
        r#"
fleet_grant id=a scope=principal:user:42 host=* model=* allow=true
fleet_grant id=b scope=group:devs host=spark model=chat allow=false
fleet_grant id=c scope=tenant:acme host=gpu2 model=target:gpu2:qwen allow=true
fleet_grant id=d scope=global host=spark model=ch* allow=false
"#,
    )
    .expect("builds");
    assert_eq!(config.snapshot.fleet_access_default, FleetAccessDefault::Deny);
    assert_eq!(config.snapshot.fleet_grants.len(), 4);
}

#[test]
fn a_grant_naming_a_host_that_does_not_exist_is_refused() {
    // `host=sprak allow=false` would otherwise deny nothing, silently.
    assert!(
        codes("fleet_grant id=a scope=global host=sprak model=* allow=false")
            .contains(&"unresolved_reference".to_owned())
    );
}

#[test]
fn a_grant_naming_a_target_with_no_deployment_is_refused() {
    // A target on no slave can never be matched by a fleet grant.
    assert!(
        codes("fleet_grant id=a scope=global host=* model=target:spark:remote allow=false")
            .contains(&"unresolved_reference".to_owned())
    );
}

#[test]
fn a_grant_naming_a_target_on_a_host_it_does_not_run_on_is_refused() {
    assert!(
        codes("fleet_grant id=a scope=global host=gpu2 model=target:spark:qwen allow=false")
            .contains(&"unresolved_reference".to_owned())
    );
}

#[test]
fn unresolved_scopes_and_aliases_are_refused() {
    for extra in [
        "fleet_grant id=a scope=tenant:globex host=* model=* allow=false",
        "fleet_grant id=a scope=group:nobody host=* model=* allow=false",
        "fleet_grant id=a scope=global host=* model=chta allow=false",
    ] {
        assert!(codes(extra).contains(&"unresolved_reference".to_owned()), "{extra}");
    }
}

#[test]
fn allow_must_be_stated_and_must_be_a_boolean() {
    // A grant whose direction is left to a default reads the same whether its
    // author meant to open the machine or to close it.
    assert!(!codes("fleet_grant id=a scope=global host=* model=*").is_empty());
    assert!(
        codes("fleet_grant id=a scope=global host=* model=* allow=yes")
            .contains(&"invalid_value".to_owned())
    );
}

#[test]
fn a_duplicate_grant_identifier_is_refused() {
    assert!(
        codes(
            "fleet_grant id=a scope=global host=* model=* allow=false\n\
             fleet_grant id=a scope=global host=spark model=* allow=true"
        )
        .contains(&"duplicate_record".to_owned())
    );
}

#[test]
fn an_unknown_default_is_refused_rather_than_read_as_allow() {
    let refused = load_with_settings("fleet_access_default=maybe", "").err().unwrap_or_default();
    assert!(refused.contains(&"invalid_value".to_owned()), "{refused:?}");
}

#[test]
fn fleet_grants_and_the_default_are_editable_through_drafts() {
    use hypellm_config::edit::{Edit, Identity, apply};
    let config = load("").expect("builds");
    let applied = apply(
        &config.canonical,
        &[
            Edit::Set {
                kind: "fleet_grant".to_owned(),
                identity: Identity::Id("fa-1".to_owned()),
                fields: vec![
                    ("scope".to_owned(), Some("principal:user:42".to_owned())),
                    ("host".to_owned(), Some("spark".to_owned())),
                    ("model".to_owned(), Some("*".to_owned())),
                    ("allow".to_owned(), Some("false".to_owned())),
                ],
            },
            Edit::Set {
                kind: "settings".to_owned(),
                identity: Identity::Singleton,
                fields: vec![("fleet_access_default".to_owned(), Some("deny".to_owned()))],
            },
        ],
    )
    .expect("applies");
    let document = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
    let rebuilt = build(&document, 2).expect("the edited text builds");
    assert_eq!(rebuilt.snapshot.fleet_grants.len(), 1);
    assert_eq!(rebuilt.snapshot.fleet_access_default, FleetAccessDefault::Deny);
}
