//! `GET /admin/v1/usage/principals`: what each principal, and each of its
//! keys, used over a window.
//!
//! The view exists so an operator can see what a principal consumed before
//! setting its limits. The properties that matter are the usage view's own —
//! it never crosses a tenant, a principal-scoped reader sees only itself, and
//! a bounded aggregate says when its attribution is incomplete — plus the one
//! this view adds: a window means what it says.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod harness;

use harness::{ALIAS, Harness, LOCAL_TARGET, TENANT_A, TENANT_B};
use hypellm_admin_api::{UsageSample, UsageStatus};
use hypellm_core::canonical::{CostClass, Operation};
use hypellm_core::event::CanonicalUsage;
use hypellm_core::ids::{AliasId, KeyId, PrincipalId, TargetId, TenantId};
use hypellm_core::time::Clock;
use wire_json::Value;

const HOUR: u64 = 3_600_000;

/// Record one request, at the wall-clock time the pipeline would use.
fn record(
    admin: &Harness,
    tenant: &str,
    principal: &str,
    key: Option<&str>,
    status: UsageStatus,
    usage: CanonicalUsage,
) {
    let sample = UsageSample {
        tenant: TenantId::new(tenant).unwrap(),
        principal: PrincipalId::new(principal).unwrap(),
        alias: AliasId::new(ALIAS).unwrap(),
        target: TargetId::new(LOCAL_TARGET).ok(),
        operation: Operation::Chat,
        status,
        cost_class: CostClass::new(1),
        usage,
        key_id: key.map(|k| KeyId::new(k).unwrap()),
    };
    admin.state.usage.record(&sample, admin.clock.wall_millis());
}

fn ok(admin: &Harness, principal: &str, key: Option<&str>, input: u64, output: u64) {
    record(
        admin,
        TENANT_A,
        principal,
        key,
        UsageStatus::Success,
        CanonicalUsage::reported(input, output),
    );
}

/// Mint a key and return its identifier as text.
fn issue(admin: &Harness, tenant: &str, principal: &str) -> String {
    admin.issue_api_key(tenant, principal).0.as_str().to_owned()
}

fn principal_row<'a>(json: &'a Value, principal: &str) -> Option<&'a Value> {
    json.field_array("principals")
        .unwrap()
        .iter()
        .find(|row| row.field_str("principal").ok() == Some(principal))
}

fn key_row<'a>(json: &'a Value, key: &str) -> Option<&'a Value> {
    json.field_array("keys")
        .unwrap()
        .iter()
        .find(|row| row.field_str("key_id").ok() == Some(key))
}

fn count(row: &Value, field: &str) -> u64 {
    row.get(field).and_then(Value::as_u64).unwrap_or_else(|| panic!("no '{field}' in {row:?}"))
}

#[test]
fn a_tenant_reader_sees_each_principal_and_each_of_its_keys_with_failures_counted() {
    let admin = Harness::new();
    let key_one = issue(&admin, TENANT_A, "mikiyas.mulugeta");
    let key_two = issue(&admin, TENANT_A, "mikiyas.mulugeta");

    ok(&admin, "mikiyas.mulugeta", Some(&key_one), 100, 40);
    ok(&admin, "mikiyas.mulugeta", Some(&key_one), 10, 4);
    ok(&admin, "mikiyas.mulugeta", Some(&key_two), 7, 3);
    record(
        &admin,
        TENANT_A,
        "mikiyas.mulugeta",
        Some(&key_two),
        UsageStatus::Throttled,
        CanonicalUsage::default(),
    );
    record(
        &admin,
        TENANT_A,
        "mikiyas.mulugeta",
        Some(&key_two),
        UsageStatus::ClientError,
        CanonicalUsage::default(),
    );
    ok(&admin, "svc:dsh", None, 1, 1);

    let response = admin.get_query(&admin.operator(), "/admin/v1/usage/principals", "window=24h");
    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("scope").unwrap(), "tenant");
    assert_eq!(json.field_str("window").unwrap(), "24h");

    // The principal is the sum of its keys.
    let mikiyas = principal_row(&json, "mikiyas.mulugeta").expect("principal listed");
    assert_eq!(count(mikiyas, "requests"), 5);
    assert_eq!(count(mikiyas, "input_tokens"), 117);
    assert_eq!(count(mikiyas, "output_tokens"), 47);
    assert_eq!(count(mikiyas, "throttled_requests"), 1);
    assert_eq!(count(mikiyas, "failed_requests"), 1);
    assert_eq!(count(mikiyas, "keys"), 2);

    // Each key separately, attributed to the principal that holds it.
    let one = key_row(&json, &key_one).expect("first key listed");
    assert_eq!(count(one, "requests"), 2);
    assert_eq!(count(one, "input_tokens"), 110);
    assert_eq!(one.field_str("principal").unwrap(), "mikiyas.mulugeta");
    let two = key_row(&json, &key_two).expect("second key listed");
    assert_eq!(count(two, "requests"), 3);
    assert_eq!(count(two, "throttled_requests"), 1);
    assert_eq!(count(two, "failed_requests"), 1);
    // The key's lifetime budget rides along: unlimited here.
    let budget = two.get("budget").expect("budget");
    assert_eq!(budget.get("token_limit"), Some(&Value::Null));

    // A principal's keyless traffic counts toward it without inventing a key.
    let dsh = principal_row(&json, "svc:dsh").expect("keyless principal listed");
    assert_eq!(count(dsh, "requests"), 1);
    assert_eq!(count(dsh, "keys"), 0);
    assert_eq!(json.field_array("keys").unwrap().len(), 2);
}

#[test]
fn a_window_covers_the_hours_it_names_and_no_earlier_ones() {
    // Adversarial: the older traffic is far larger, so a window that ignored
    // its own boundary would be obvious in the totals.
    let admin = Harness::new();
    admin.advance(100 * HOUR);
    ok(&admin, "svc:dsh", None, 50_000, 50_000);
    admin.advance(48 * HOUR);
    ok(&admin, "svc:dsh", None, 3, 2);

    let day = admin.get_query(&admin.operator(), "/admin/v1/usage/principals", "window=24h").json();
    let row = principal_row(&day, "svc:dsh").unwrap();
    assert_eq!(count(row, "requests"), 1);
    assert_eq!(count(row, "input_tokens"), 3);
    // The window starts on an hour boundary and says where.
    let from = count(&day, "from");
    assert_eq!(from % HOUR, 0);
    assert!(from <= admin.clock.wall_millis() - 24 * HOUR);

    let week = admin.get_query(&admin.operator(), "/admin/v1/usage/principals", "window=7d").json();
    let row = principal_row(&week, "svc:dsh").unwrap();
    assert_eq!(count(row, "requests"), 2);
    assert_eq!(count(row, "input_tokens"), 50_003);
}

#[test]
fn a_window_reaching_past_the_routers_start_says_it_is_partial() {
    // Usage lives in memory. A "30 days" that silently meant "since Tuesday's
    // restart" would be read as a month of consumption.
    let admin = Harness::new();
    admin.advance(1_000 * HOUR);
    ok(&admin, "svc:dsh", None, 1, 1);
    let json = admin.get_query(&admin.operator(), "/admin/v1/usage/principals", "window=30d").json();
    assert_eq!(json.opt_field_bool("partial").unwrap(), Some(true));
    assert_eq!(count(&json, "counting_since"), admin.clock.wall_millis());
}

#[test]
fn a_viewer_sees_only_its_own_principal_and_its_own_keys() {
    let admin = Harness::new();
    let viewer = admin.viewer();
    let mine = viewer.principal.as_str().to_owned();
    let my_key = issue(&admin, TENANT_A, &mine);
    let their_key = issue(&admin, TENANT_A, "mikiyas.mulugeta");
    ok(&admin, &mine, Some(&my_key), 2, 2);
    ok(&admin, "mikiyas.mulugeta", Some(&their_key), 9_999, 9_999);

    let response = admin.get(&viewer, "/admin/v1/usage/principals");
    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("scope").unwrap(), "principal");
    assert_eq!(json.field_array("principals").unwrap().len(), 1);
    assert!(principal_row(&json, &mine).is_some());
    assert!(key_row(&json, &my_key).is_some());
    assert!(!response.body_contains("mikiyas.mulugeta"), "{}", response.body);
    assert!(!response.body_contains(&their_key), "{}", response.body);
    assert!(!response.body_contains("9999"), "{}", response.body);

    // Naming someone else answers with nothing — not a refusal, which would
    // confirm the name — and certainly not with their usage.
    let probed = admin.get_query(&viewer, "/admin/v1/usage/principals", "principal=mikiyas.mulugeta");
    assert_eq!(probed.status, 200, "{}", probed.body);
    assert!(probed.json().field_array("principals").unwrap().is_empty());
    assert!(probed.json().field_array("keys").unwrap().is_empty());
    assert!(!probed.body_contains(&their_key), "{}", probed.body);
}

#[test]
fn another_tenants_principal_never_appears_even_when_named() {
    let admin = Harness::new();
    let b_key = issue(&admin, TENANT_B, "user:mallory");
    record(
        &admin,
        TENANT_B,
        "user:mallory",
        Some(&b_key),
        UsageStatus::Success,
        CanonicalUsage::reported(777_777, 777_777),
    );
    ok(&admin, "user:alice", None, 1, 1);

    let operator_a = admin.operator_in(TENANT_A);
    for path in ["", "principal=user:mallory", "window=30d&principal=user%3Amallory"] {
        let response = admin.get_query(&operator_a, "/admin/v1/usage/principals", path);
        assert_eq!(response.status, 200, "{path}: {}", response.body);
        assert!(!response.body_contains("mallory"), "{path}: {}", response.body);
        assert!(!response.body_contains(&b_key), "{path}: {}", response.body);
        assert!(!response.body_contains("777777"), "{path}: {}", response.body);
    }

    // And the filter narrows within the tenant as asked.
    let alice = admin.get_query(&operator_a, "/admin/v1/usage/principals", "principal=user:alice")
        .json();
    assert_eq!(alice.field_array("principals").unwrap().len(), 1);
}

#[test]
fn a_caller_without_a_usage_permission_is_refused() {
    let admin = Harness::new();
    ok(&admin, "user:alice", None, 1, 1);
    let response = admin.get(&admin.unprivileged(), "/admin/v1/usage/principals");
    assert_eq!(response.status, 403, "{}", response.body);
    assert!(!response.body_contains("user:alice"), "{}", response.body);
}

#[test]
fn an_unknown_window_is_refused_without_echoing_it() {
    let admin = Harness::new();
    let response = admin.get_query(&admin.operator(), "/admin/v1/usage/principals", "window=hypellmk_leaked_secret");
    assert_eq!(response.status, 400, "{}", response.body);
    assert!(!response.body_contains("leaked_secret"), "{}", response.body);
}

#[test]
fn past_the_series_bound_usage_folds_into_a_remainder_the_totals_still_count() {
    // Bounded like every other aggregate: a caller minting keys cannot grow
    // the table, and the remainder is reported rather than dropped.
    let admin = Harness::new();
    let total = hypellm_admin_api::usage::MAX_ROLLUP_SERIES + 40;
    for n in 0..total {
        ok(&admin, "svc:dsh", Some(&format!("key{n}")), 1, 0);
    }
    assert!(admin.state.usage.rollup_len() <= hypellm_admin_api::usage::MAX_ROLLUP_SERIES + 1);

    let json = admin.get(&admin.operator(), "/admin/v1/usage/principals").json();
    assert_eq!(json.opt_field_bool("truncated").unwrap(), Some(true));
    let attributed = count(principal_row(&json, "svc:dsh").unwrap(), "requests");
    let folded = count(json.get("unattributed").unwrap(), "requests");
    assert_eq!(attributed + folded, total as u64, "every request is still counted");
    assert_eq!(folded, 40);

    // The remainder is nobody's: a principal-scoped reader is not shown it.
    let viewer = admin.viewer();
    let own = admin.get(&viewer, "/admin/v1/usage/principals").json();
    assert_eq!(own.get("unattributed"), Some(&Value::Null));
    assert_eq!(own.opt_field_bool("truncated").unwrap(), Some(false));
}

#[test]
fn hours_older_than_the_retention_window_are_dropped_as_the_clock_advances() {
    let admin = Harness::new();
    admin.advance(10 * HOUR);
    for n in 0..20 {
        ok(&admin, "svc:dsh", Some(&format!("old{n}")), 1, 1);
    }
    let held = admin.state.usage.rollup_len();
    assert_eq!(held, 20);
    admin.advance(31 * 24 * HOUR);
    ok(&admin, "svc:dsh", None, 1, 1);
    assert_eq!(admin.state.usage.rollup_len(), 1, "expired hours must not be retained");
}
