//! `settings conversation_affinity_ttl_ms` and `conversation_affinity_max_entries`.
//!
//! Affinity is on by default with a bounded table; zero in either switches it
//! off; and a value past the documented ceiling is refused rather than
//! clamped, because the table is router memory a request can fill.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_config::load;

const BASE: &str = "tenant id=acme
provider id=p family=llamacpp scheme=http host=127.0.0.1 port=8000
target id=p:m provider=p model=m capabilities=chat context=8192 max_output=1024
alias id=code targets=p:m
binding id=default scope=tenant:acme prefer=*
grant scope=tenant:acme model=* allow=true
";

fn with_settings(fields: &str) -> Result<hypellm_config::ValidatedConfig, Vec<String>> {
    load(&format!("settings state_dir=/tmp/x {fields}\n{BASE}"), 1)
        .map_err(|errors| errors.iter().map(|e| e.code.to_owned()).collect())
}

#[test]
fn affinity_is_on_and_bounded_by_default_and_zero_switches_it_off() {
    let default = with_settings("").expect("defaults load");
    assert_eq!(default.settings.conversation_affinity_ttl_ms, 600_000);
    assert_eq!(default.settings.conversation_affinity_max_entries, 10_000);

    let off = with_settings("conversation_affinity_ttl_ms=0").expect("zero loads");
    assert_eq!(off.settings.conversation_affinity_ttl_ms, 0);

    let tuned = with_settings(
        "conversation_affinity_ttl_ms=86400000 conversation_affinity_max_entries=1000000",
    )
    .expect("the ceilings themselves load");
    assert_eq!(tuned.settings.conversation_affinity_max_entries, 1_000_000);
}

#[test]
fn an_unbounded_affinity_table_is_refused() {
    for fields in [
        "conversation_affinity_max_entries=1000001",
        "conversation_affinity_ttl_ms=86400001",
    ] {
        let codes = with_settings(fields).expect_err(fields);
        assert!(
            codes.iter().any(|c| c == "invalid_conversation_affinity"),
            "{fields}: {codes:?}"
        );
    }
}
