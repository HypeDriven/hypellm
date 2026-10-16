//! `settings target_probe_interval_ms` and `target_probe_timeout_ms`.
//!
//! The liveness probe is on by default, so a document that says nothing gets
//! it; zero switches it off; and a pair that cannot work as written — a
//! timeout of zero, which would fail every probe and exclude every probed
//! target, or one that outlasts the interval — is refused rather than clamped.

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
fn the_probe_is_on_by_default_and_zero_switches_it_off() {
    let default = with_settings("").expect("defaults load");
    assert_eq!(default.settings.target_probe_interval_ms, 10_000);
    assert_eq!(default.settings.target_probe_timeout_ms, 2_000);

    let off = with_settings("target_probe_interval_ms=0 target_probe_timeout_ms=0")
        .expect("an off probe needs no valid timeout");
    assert_eq!(off.settings.target_probe_interval_ms, 0);

    let tuned = with_settings("target_probe_interval_ms=30000 target_probe_timeout_ms=5000")
        .expect("a sensible pair loads");
    assert_eq!(tuned.settings.target_probe_interval_ms, 30_000);
    assert_eq!(tuned.settings.target_probe_timeout_ms, 5_000);
}

#[test]
fn a_probe_pair_that_cannot_work_is_refused() {
    for fields in [
        // Every probe would fail at once and exclude every probed target.
        "target_probe_timeout_ms=0",
        // One hung endpoint would stretch every round past its schedule.
        "target_probe_interval_ms=2000 target_probe_timeout_ms=2000",
        // A probe longer than this is also how long it can delay a drain.
        "target_probe_interval_ms=60000 target_probe_timeout_ms=10001",
        // Faster than a liveness signal needs, at the slaves' expense.
        "target_probe_interval_ms=500 target_probe_timeout_ms=100",
    ] {
        let codes = with_settings(fields).expect_err(fields);
        assert!(
            codes.iter().any(|c| c == "invalid_probe_settings"),
            "{fields}: {codes:?}"
        );
    }
}
