//! Key token budgets through the management API (specification 12.3).
//!
//! The endpoints here move a purchased allowance, usually on behalf of a
//! payment system that nobody is watching. So the properties are about what
//! cannot go wrong unattended: a credit is applied once however often it is
//! replayed, a stale update changes nothing, the permission reaches budgets
//! and nothing else, a key in another tenant does not exist, and every answer
//! of "done" is true of the ledger and of the log.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use harness::{
    ALLOWED_ORIGIN, ANY_ETAG, Harness, KEY_EDITOR_PRINCIPAL, Response, STALE_ETAG, TENANT_A,
    TENANT_B, TestSession, default_config,
};
use hypellm_admin_api::budget::decode_record;
use hypellm_core::budget::BudgetView;
use hypellm_core::ids::{KeyId, TenantId};
use hypellm_core::rbac::Role;
use hypellm_store::RecordKind;
use wire_http1::Method;
use wire_json::Value;

/// The service principal a payment system would run as.
const BILLING: &str = "svc:billing";

fn admin() -> Harness {
    Harness::with_config(&format!(
        "{}\nrole_binding subject=principal:{BILLING} role=key_budget_manager\n",
        default_config()
    ))
}

fn manager(admin: &Harness) -> TestSession {
    admin.session("user:finance", TENANT_A, &[Role::KeyBudgetManager])
}

fn path(key: &KeyId) -> String {
    format!("/admin/v1/keys/{}/budget", key.as_str())
}

fn credit_path(key: &KeyId) -> String {
    format!("/admin/v1/keys/{}/budget:credit", key.as_str())
}

fn put(admin: &Harness, session: &TestSession, key: &KeyId, body: &str, etag: &str) -> Response {
    admin
        .request(Method::Put, &path(key))
        .as_session(session)
        .json(body)
        .if_match(etag)
        .send()
}

fn credit(
    admin: &Harness,
    session: &TestSession,
    key: &KeyId,
    body: &str,
    etag: &str,
    operation: &str,
) -> Response {
    admin
        .request(Method::Post, &credit_path(key))
        .as_session(session)
        .json(body)
        .if_match(etag)
        .header("idempotency-key", operation)
        .send()
}

fn view(admin: &Harness, key: &KeyId) -> BudgetView {
    admin.state.budgets.view(key)
}

fn tenant_a() -> TenantId {
    TenantId::new(TENANT_A).unwrap()
}

/// Spend `tokens` the way a served request would.
fn spend(admin: &Harness, key: &KeyId, tokens: u64) {
    admin
        .state
        .budgets
        .reserve(key, &tenant_a(), tokens)
        .expect("a funded reservation")
        .settle(tokens);
}

fn u64_at(value: &Value, name: &str) -> Option<u64> {
    value.get(name).and_then(Value::as_u64)
}

/// The key's budget as the log would restore it.
fn durable_limit(admin: &Harness, key: &KeyId) -> Option<Option<u64>> {
    admin
        .state
        .store
        .records_of_kinds(&[RecordKind::KeyBudget])
        .expect("replay the log")
        .into_iter()
        .filter_map(|(_, payload)| decode_record(&payload))
        .filter(|record| &record.key == key)
        .next_back()
        .map(|record| record.limit)
}

// -- Reading ----------------------------------------------------------------

#[test]
fn a_budget_reports_limit_consumption_and_remainder_and_never_the_secret() {
    let admin = admin();
    let (key, secret) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);

    let fresh = admin.get(&session, &path(&key));
    assert_eq!(fresh.status, 200, "{}", fresh.body);
    let body = fresh.json();
    // Unlimited is `null`, not zero: zero is a budget that permits nothing.
    assert!(body.get("token_limit").unwrap().is_null());
    assert!(body.get("remaining_tokens").unwrap().is_null());
    assert_eq!(u64_at(&body, "consumed_tokens"), Some(0));

    admin.state.budgets.set(&key, &tenant_a(), None, Some(1000), None).unwrap();
    spend(&admin, &key, 250);
    let held = admin.state.budgets.reserve(&key, &tenant_a(), 100).unwrap();

    let response = admin.get(&session, &path(&key));
    let body = response.json();
    assert_eq!(u64_at(&body, "token_limit"), Some(1000));
    assert_eq!(u64_at(&body, "consumed_tokens"), Some(250));
    assert_eq!(u64_at(&body, "reserved_tokens"), Some(100));
    assert_eq!(u64_at(&body, "remaining_tokens"), Some(650));
    assert_eq!(u64_at(&body, "revision"), Some(1));
    assert!(response.etag.is_some());
    let secret_part = secret.rsplit('_').next().unwrap();
    assert!(!response.body.contains(secret_part), "the key secret was returned");
    held.release();
}

// -- Setting ----------------------------------------------------------------

#[test]
fn setting_a_limit_changes_the_ledger_and_the_log_and_is_audited() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    let etag = admin.get(&session, &path(&key)).expect_etag();
    let audited = admin.audit_count();

    let response = put(&admin, &session, &key, r#"{"token_limit":5000}"#, &etag);

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(u64_at(&response.json(), "token_limit"), Some(5000));
    assert_ne!(response.expect_etag(), etag, "the tag did not follow the limit");
    assert_eq!(view(&admin, &key).limit, Some(5000));
    assert_eq!(durable_limit(&admin, &key), Some(Some(5000)));
    assert_eq!(admin.audit_count(), audited + 1);
}

#[test]
fn an_update_without_or_with_a_stale_precondition_changes_nothing() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();

    let missing = admin
        .request(Method::Put, &path(&key))
        .as_session(&session)
        .json(r#"{"token_limit":999999}"#)
        .send();
    assert_eq!(missing.status, 428, "{}", missing.body);

    let stale = put(&admin, &session, &key, r#"{"token_limit":999999}"#, STALE_ETAG);
    assert_eq!(stale.status, 412, "{}", stale.body);
    assert_eq!(stale.error_code.as_deref(), Some("precondition_failed"));

    // The tag of a state two edits ago is stale too.
    let first = admin.get(&session, &path(&key)).expect_etag();
    assert_eq!(put(&admin, &session, &key, r#"{"token_limit":200}"#, &first).status, 200);
    let replayed = put(&admin, &session, &key, r#"{"token_limit":999999}"#, &first);
    assert_eq!(replayed.status, 412, "{}", replayed.body);

    assert_eq!(view(&admin, &key).limit, Some(200));
    assert_eq!(durable_limit(&admin, &key), Some(Some(200)));
}

#[test]
fn consumption_does_not_invalidate_an_operators_update() {
    // Specification 12.3: the tag covers the editable limit and payment
    // override. A key in use changes its counters constantly; if that moved
    // the tag, no update to a busy key could ever land.
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(1000), None).unwrap();
    let etag = admin.get(&session, &path(&key)).expect_etag();

    spend(&admin, &key, 300);

    let response = put(&admin, &session, &key, r#"{"token_limit":2000}"#, &etag);
    assert_eq!(response.status, 200, "{}", response.body);
    // And the update left what was spent alone.
    let budget = view(&admin, &key);
    assert_eq!((budget.limit, budget.consumed), (Some(2000), 300));
}

#[test]
fn removing_or_lowering_a_limit_never_resets_consumption() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(1000), None).unwrap();
    spend(&admin, &key, 400);

    let lowered = put(&admin, &session, &key, r#"{"token_limit":100}"#, ANY_ETAG);
    assert_eq!(u64_at(&lowered.json(), "consumed_tokens"), Some(400));
    assert_eq!(u64_at(&lowered.json(), "remaining_tokens"), Some(0));

    // `null` and an omitted limit both mean unlimited.
    let removed = put(&admin, &session, &key, r#"{"token_limit":null}"#, ANY_ETAG);
    assert!(removed.json().get("token_limit").unwrap().is_null());
    assert_eq!(u64_at(&removed.json(), "consumed_tokens"), Some(400));
    assert_eq!(put(&admin, &session, &key, r#"{"token_limit":7}"#, ANY_ETAG).status, 200);
    let omitted = put(&admin, &session, &key, "{}", ANY_ETAG);
    assert_eq!(omitted.status, 200, "{}", omitted.body);
    assert_eq!(view(&admin, &key).limit, None);
    assert_eq!(view(&admin, &key).consumed, 400);
}

#[test]
fn a_limit_that_is_not_a_representable_token_count_is_rejected() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();

    for body in [
        r#"{"token_limit":-1}"#,
        r#"{"token_limit":1.5}"#,
        r#"{"token_limit":"1000"}"#,
        r#"{"token_limit":true}"#,
        // One past the largest quantity the ledger carries exactly.
        r#"{"token_limit":9223372036854775808}"#,
        r#"{"token_limit":1e30}"#,
        r#"[1000]"#,
    ] {
        let response = put(&admin, &session, &key, body, ANY_ETAG);
        assert_eq!(response.status, 400, "{body} gave {}", response.body);
    }
    assert_eq!(view(&admin, &key).limit, Some(100));
    assert_eq!(view(&admin, &key).revision, 1);
}

#[test]
fn payment_instructions_override_the_tenant_default_and_null_inherits_it() {
    let admin = Harness::with_config(&default_config().replace(
        "tenant id=acme\n",
        "tenant id=acme payment_message=\"Ask your administrator.\" \
         payment_url=\"https://tenant.example/pay\"\n",
    ));
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    let url = |response: &Response| {
        response
            .json()
            .get("payment_required")
            .and_then(|p| p.get("payment_url"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    let inherited = admin.get(&session, &path(&key));
    assert_eq!(url(&inherited).as_deref(), Some("https://tenant.example/pay"));
    assert_eq!(inherited.json().get("payment_override").and_then(Value::as_bool), Some(false));

    let set = put(
        &admin,
        &session,
        &key,
        r#"{"token_limit":10,"payment_required":{"message":"Top up.","payment_url":"https://key.example/pay"}}"#,
        ANY_ETAG,
    );
    assert_eq!(url(&set).as_deref(), Some("https://key.example/pay"));
    assert_eq!(set.json().get("payment_override").and_then(Value::as_bool), Some(true));

    let cleared = put(&admin, &session, &key, r#"{"token_limit":10,"payment_required":null}"#, ANY_ETAG);
    assert_eq!(url(&cleared).as_deref(), Some("https://tenant.example/pay"));
    assert_eq!(view(&admin, &key).payment, None);
}

#[test]
fn payment_instructions_that_are_not_plain_https_data_are_refused() {
    // The value is repeated to every caller the key refuses. A redirect to
    // plain HTTP, a credential in the URL, or a control character in the
    // message is an operator mistake that would become a client's problem.
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);

    for payment in [
        r#"{"payment_url":"http://billing.example/tokens"}"#,
        r#"{"payment_url":"javascript:alert(1)"}"#,
        r#"{"payment_url":"https://user:secret@billing.example/"}"#,
        r#"{"payment_url":"/tokens"}"#,
        r#"{"payment_url":17}"#,
        r#"{"message":"line one\nline two"}"#,
        r#""https://billing.example/tokens""#,
    ] {
        let body = format!(r#"{{"token_limit":10,"payment_required":{payment}}}"#);
        let response = put(&admin, &session, &key, &body, ANY_ETAG);
        assert_eq!(response.status, 400, "{payment} gave {}", response.body);
    }
    let budget = view(&admin, &key);
    assert_eq!((budget.limit, budget.payment, budget.revision), (None, None, 0));
}

// -- Crediting --------------------------------------------------------------

#[test]
fn the_specifications_top_up_example_holds() {
    // 12.3: "a key with token_limit=1000000 and consumed_tokens=1000000 is
    // refused with 402. Crediting {"tokens": 500000} raises the limit to
    // 1500000 and makes 500000 tokens available ... Replaying that payment
    // leaves the allowance unchanged."
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(1_000_000), None).unwrap();
    spend(&admin, &key, 1_000_000);
    assert!(admin.state.budgets.reserve(&key, &tenant_a(), 1).is_err());
    let etag = admin.get(&session, &path(&key)).expect_etag();
    let audited = admin.audit_count();

    let first = credit(&admin, &session, &key, r#"{"tokens":500000}"#, &etag, "payment-7731");

    assert_eq!(first.status, 200, "{}", first.body);
    let body = first.json();
    assert_eq!(body.get("replayed").and_then(Value::as_bool), Some(false));
    let budget = body.get("budget").unwrap();
    assert_eq!(u64_at(budget, "token_limit"), Some(1_500_000));
    assert_eq!(u64_at(budget, "remaining_tokens"), Some(500_000));
    assert_eq!(u64_at(body.get("receipt").unwrap(), "tokens"), Some(500_000));
    assert_eq!(durable_limit(&admin, &key), Some(Some(1_500_000)));
    assert_eq!(admin.audit_count(), audited + 1);
    // New admissions observe the credit at once.
    admin.state.budgets.reserve(&key, &tenant_a(), 500_000).unwrap().release();

    // The payment system retries with the tag it had the first time.
    let replay = credit(&admin, &session, &key, r#"{"tokens":500000}"#, &etag, "payment-7731");

    assert_eq!(replay.status, 200, "{}", replay.body);
    let body = replay.json();
    assert_eq!(body.get("replayed").and_then(Value::as_bool), Some(true));
    assert_eq!(
        to_text(body.get("receipt").unwrap()),
        to_text(first.json().get("receipt").unwrap()),
        "the replay did not return the original receipt"
    );
    assert_eq!(view(&admin, &key).limit, Some(1_500_000));
    assert_eq!(admin.audit_count(), audited + 1, "a replay was audited as a credit");
}

fn to_text(value: &Value) -> String {
    wire_json::to_string(value)
}

#[test]
fn the_same_operation_with_different_content_is_a_conflict() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();
    assert_eq!(
        credit(&admin, &session, &key, r#"{"tokens":50}"#, ANY_ETAG, "payment-1").status,
        200
    );

    for body in [r#"{"tokens":5000}"#, r#"{"tokens":50,"reason":"a second look"}"#] {
        let conflict = credit(&admin, &session, &key, body, ANY_ETAG, "payment-1");
        assert_eq!(conflict.status, 409, "{}", conflict.body);
        assert_eq!(conflict.error_code.as_deref(), Some("idempotency_conflict"));
    }
    assert_eq!(view(&admin, &key).limit, Some(150));

    // Normalized content: key order, whitespace and unread fields are not a
    // different credit.
    let same = credit(&admin, &session, &key, r#"{ "note": 1, "tokens": 50 }"#, ANY_ETAG, "payment-1");
    assert_eq!(same.status, 200, "{}", same.body);
    assert_eq!(view(&admin, &key).limit, Some(150));
}

#[test]
fn a_credit_needs_both_its_precondition_and_its_operation_identifier() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();
    let request = || {
        admin
            .request(Method::Post, &credit_path(&key))
            .as_session(&session)
            .json(r#"{"tokens":50}"#)
    };

    let no_tag = request().header("idempotency-key", "payment-1").send();
    assert_eq!(no_tag.status, 428, "{}", no_tag.body);

    let no_operation = request().if_match(ANY_ETAG).send();
    assert_eq!(no_operation.status, 400, "{}", no_operation.body);

    let long = "k".repeat(129);
    for operation in ["", "has space", long.as_str(), "caf\u{e9}"] {
        let bad = request().if_match(ANY_ETAG).header("idempotency-key", operation).send();
        assert_eq!(bad.status, 400, "{operation:?} gave {}", bad.body);
    }

    let stale = request().if_match(STALE_ETAG).header("idempotency-key", "payment-1").send();
    assert_eq!(stale.status, 412, "{}", stale.body);

    assert_eq!(view(&admin, &key).limit, Some(100));
    // And none of those attempts left a receipt behind to be "replayed".
    assert_eq!(admin.state.budgets.receipt(&key, "payment-1"), None);
}

#[test]
fn a_credit_to_an_unlimited_budget_is_refused_not_converted() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);

    let response = credit(&admin, &session, &key, r#"{"tokens":50}"#, ANY_ETAG, "payment-1");

    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("validation_failed"));
    assert_eq!(view(&admin, &key).limit, None);
}

#[test]
fn invalid_and_overflowing_credits_are_rejected() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    let nearly_full = i64::MAX.unsigned_abs() - 10;
    admin.state.budgets.set(&key, &tenant_a(), None, Some(nearly_full), None).unwrap();

    for (n, body) in [
        r#"{"tokens":0}"#,
        r#"{"tokens":-5}"#,
        r#"{"tokens":2.5}"#,
        r#"{"tokens":"50"}"#,
        r#"{}"#,
        // Fits the type, overflows the limit.
        r#"{"tokens":11}"#,
        r#"{"tokens":9223372036854775807}"#,
        r#"{"tokens":5,"reason":""}"#,
    ]
    .iter()
    .enumerate()
    {
        let response = credit(&admin, &session, &key, body, ANY_ETAG, &format!("payment-{n}"));
        assert_eq!(response.status, 400, "{body} gave {}", response.body);
    }
    assert_eq!(view(&admin, &key).limit, Some(nearly_full));
}

#[test]
fn a_credit_receipt_is_recognised_after_a_restart() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();
    assert_eq!(
        credit(&admin, &session, &key, r#"{"tokens":50}"#, ANY_ETAG, "payment-1").status,
        200
    );

    // What a restarted router would hold: the log, replayed.
    let journal = std::sync::Arc::new(hypellm_core::budget::testing::MemoryJournal::new());
    let reborn = hypellm_core::budget::BudgetLedger::new(journal, 0);
    for (_, payload) in admin.state.store.records_of_kinds(&[RecordKind::KeyBudget]).unwrap() {
        reborn.restore(decode_record(&payload).expect("a readable record"));
    }

    let receipt = reborn.receipt(&key, "payment-1").expect("the receipt survived");
    assert_eq!((receipt.tokens, receipt.limit_after), (50, 150));
    let replay = reborn
        .credit(&key, &tenant_a(), None, 50, "payment-1", &receipt.request_digest, None, "x", 0)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(reborn.view(&key).limit, Some(150));
}

#[test]
fn crediting_a_revoked_key_does_not_bring_it_back() {
    let admin = admin();
    let (key, secret) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    admin.state.budgets.set(&key, &tenant_a(), None, Some(0), None).unwrap();
    admin.state.keys.revoke(&key);

    let response = credit(&admin, &session, &key, r#"{"tokens":50}"#, ANY_ETAG, "payment-1");

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        admin.state.keys.verify(&secret, None, 0).is_err(),
        "a top-up restored a revoked key"
    );
}

// -- Authority --------------------------------------------------------------

#[test]
fn only_manage_key_budgets_reaches_a_budget() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();

    for session in [
        admin.viewer(),
        admin.operator(),
        admin.policy_editor(),
        admin.policy_approver(),
        admin.credential_manager(),
        admin.auditor(),
        admin.unprivileged(),
    ] {
        let who = session.principal.clone();
        assert_eq!(admin.get(&session, &path(&key)).status, 403, "{who} read a budget");
        assert_eq!(
            put(&admin, &session, &key, r#"{"token_limit":999999}"#, ANY_ETAG).status,
            403,
            "{who} set a budget"
        );
        assert_eq!(
            credit(&admin, &session, &key, r#"{"tokens":999999}"#, ANY_ETAG, "p").status,
            403,
            "{who} credited a budget"
        );
    }
    assert_eq!(view(&admin, &key).limit, Some(100));
}

#[test]
fn a_budget_manager_can_do_nothing_else_with_a_key() {
    // Specification 12.3: "This permission does not grant key
    // creation/revocation, credential access, policy publication".
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    let session = manager(&admin);
    let keys_before = admin.state.keys.len();

    let minted = admin.post(&session, "/admin/v1/keys", r#"{"principal":"svc:x","scopes":["inference"]}"#);
    assert_eq!(minted.status, 403, "{}", minted.body);
    let revoked = admin.delete(&session, &format!("/admin/v1/keys/{}", key.as_str()));
    assert_eq!(revoked.status, 403, "{}", revoked.body);
    assert_eq!(admin.get(&session, "/admin/v1/keys").status, 403);
    assert_eq!(admin.get(&session, "/admin/v1/credentials").status, 403);

    assert_eq!(admin.state.keys.len(), keys_before);
    assert!(!admin.state.keys.get(&key).unwrap().revoked);
}

#[test]
fn a_service_key_with_the_role_credits_without_a_browser_session() {
    // The decoupled payment system of specification 12.3: a management key,
    // no cookie, no CSRF token.
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();
    let (_, service) =
        admin.issue_management_key(TENANT_A, BILLING, &["management:read", "management:write"]);
    let bearer = format!("Bearer {service}");

    let read = admin
        .request(Method::Get, &path(&key))
        .header("authorization", &bearer)
        .send();
    assert_eq!(read.status, 200, "{}", read.body);

    let credited = admin
        .request(Method::Post, &credit_path(&key))
        .header("authorization", &bearer)
        .header("idempotency-key", "payment-1")
        .if_match(&read.expect_etag())
        .json(r#"{"tokens":900}"#)
        .send();
    assert_eq!(credited.status, 200, "{}", credited.body);
    assert_eq!(view(&admin, &key).limit, Some(1000));

    // The same key cannot mint or revoke.
    let minted = admin
        .request(Method::Post, "/admin/v1/keys")
        .header("authorization", &bearer)
        .json(r#"{"principal":"svc:x","scopes":["inference"]}"#)
        .send();
    assert_eq!(minted.status, 403, "{}", minted.body);
}

#[test]
fn scopes_bound_what_a_service_key_may_do_to_a_budget() {
    let admin = admin();
    let (key, _) = admin.issue_api_key(TENANT_A, "svc:build");
    admin.state.budgets.set(&key, &tenant_a(), None, Some(100), None).unwrap();
    let attempt = |secret: &str, method: Method, target: &str| {
        admin
            .request(method, target)
            .header("authorization", &format!("Bearer {secret}"))
            .header("idempotency-key", "payment-1")
            .if_match(ANY_ETAG)
            .json(r#"{"tokens":900,"token_limit":999999}"#)
            .send()
    };

    // `management:read` reads and does not write.
    let (_, reader) = admin.issue_management_key(TENANT_A, BILLING, &["management:read"]);
    assert_eq!(attempt(&reader, Method::Get, &path(&key)).status, 200);
    assert_eq!(attempt(&reader, Method::Put, &path(&key)).status, 403);
    assert_eq!(attempt(&reader, Method::Post, &credit_path(&key)).status, 403);

    // "Inference scope alone grants no budget mutation" — nor a read.
    let (_, inference) = admin.issue_api_key(TENANT_A, BILLING);
    for (method, target) in [
        (Method::Get, path(&key)),
        (Method::Put, path(&key)),
        (Method::Post, credit_path(&key)),
    ] {
        assert_eq!(attempt(&inference, method, &target).status, 403);
    }

    // A write-scoped key whose principal holds some other role.
    let (_, editor) = admin.issue_management_key(
        TENANT_A,
        KEY_EDITOR_PRINCIPAL,
        &["management:read", "management:write"],
    );
    assert_eq!(attempt(&editor, Method::Post, &credit_path(&key)).status, 403);

    assert_eq!(view(&admin, &key).limit, Some(100));
}

#[test]
fn an_exhausted_budget_does_not_stop_its_own_keys_management_calls() {
    // Specification 12.3: "Budget exhaustion MUST NOT prevent
    // otherwise-authorized management calls."
    let admin = admin();
    let (service_id, service) =
        admin.issue_management_key(TENANT_A, BILLING, &["management:read", "management:write"]);
    admin.state.budgets.set(&service_id, &tenant_a(), None, Some(0), None).unwrap();

    let response = admin
        .request(Method::Get, &path(&service_id))
        .header("authorization", &format!("Bearer {service}"))
        .send();

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(view(&admin, &service_id).consumed, 0, "a management call was metered");
}

#[test]
fn a_key_in_another_tenant_does_not_exist() {
    let admin = admin();
    let (foreign, _) = admin.issue_api_key(TENANT_B, "svc:theirs");
    admin
        .state
        .budgets
        .set(&foreign, &TenantId::new(TENANT_B).unwrap(), None, Some(100), None)
        .unwrap();
    let session = manager(&admin);
    let absent = KeyId::new("ffffffffffffffff").unwrap();

    for (theirs, nobody) in [
        (admin.get(&session, &path(&foreign)), admin.get(&session, &path(&absent))),
        (
            put(&admin, &session, &foreign, r#"{"token_limit":1}"#, ANY_ETAG),
            put(&admin, &session, &absent, r#"{"token_limit":1}"#, ANY_ETAG),
        ),
        (
            credit(&admin, &session, &foreign, r#"{"tokens":5}"#, ANY_ETAG, "p-1"),
            credit(&admin, &session, &absent, r#"{"tokens":5}"#, ANY_ETAG, "p-1"),
        ),
        // Not even a stale tag distinguishes them: existence is decided first.
        (
            put(&admin, &session, &foreign, r#"{"token_limit":1}"#, STALE_ETAG),
            put(&admin, &session, &absent, r#"{"token_limit":1}"#, STALE_ETAG),
        ),
    ] {
        assert_eq!(theirs.status, 404, "{}", theirs.body);
        assert_eq!(theirs.error_code, nobody.error_code);
        assert_eq!(theirs.status, nobody.status);
        assert!(!theirs.body.contains("100"), "another tenant's limit leaked");
    }
    assert_eq!(view(&admin, &foreign).limit, Some(100));
}

// -- Keys -------------------------------------------------------------------

#[test]
fn a_key_can_be_created_with_its_budget_already_in_force() {
    let admin = admin();
    let oncall = admin.break_glass();

    let created = admin.post(
        &oncall,
        "/admin/v1/keys",
        r#"{"principal":"svc:build","scopes":["inference"],"token_limit":2000,
            "payment_required":{"payment_url":"https://billing.example/tokens"}}"#,
    );

    assert_eq!(created.status, 201, "{}", created.body);
    let key = KeyId::new(created.str_field("id")).unwrap();
    let budget = view(&admin, &key);
    assert_eq!(budget.limit, Some(2000));
    assert_eq!(
        budget.payment.as_ref().and_then(|p| p.payment_url()),
        Some("https://billing.example/tokens")
    );
    assert_eq!(durable_limit(&admin, &key), Some(Some(2000)));

    let listed = admin.get(&oncall, "/admin/v1/keys");
    let row = listed
        .data()
        .into_iter()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(key.as_str()))
        .expect("the key is listed");
    assert_eq!(u64_at(row.get("budget").unwrap(), "token_limit"), Some(2000));
}

#[test]
fn a_key_whose_budget_is_malformed_is_not_created_at_all() {
    // The dangerous failure is the quiet one: a key the operator asked to be
    // limited, created without the limit.
    let admin = admin();
    let oncall = admin.break_glass();
    let before = admin.state.keys.len();

    for body in [
        r#"{"principal":"svc:build","scopes":["inference"],"token_limit":-1}"#,
        r#"{"principal":"svc:build","scopes":["inference"],"token_limit":10,"payment_required":{"payment_url":"http://x.example/"}}"#,
    ] {
        let response = admin.post(&oncall, "/admin/v1/keys", body);
        assert_eq!(response.status, 400, "{}", response.body);
        assert!(!response.body_contains("secret"), "a secret was issued: {}", response.body);
    }
    assert_eq!(admin.state.keys.len(), before);
}

// -- Transport --------------------------------------------------------------

#[test]
fn a_browser_may_send_the_put_and_the_idempotency_header() {
    let admin = admin();
    let preflight = admin
        .request(Method::Options, "/admin/v1/keys/0123456789abcdef/budget")
        .origin(ALLOWED_ORIGIN)
        .header("access-control-request-method", "PUT")
        .send();

    let methods = preflight.header("Access-Control-Allow-Methods").unwrap_or_default();
    let headers = preflight.header("Access-Control-Allow-Headers").unwrap_or_default();
    assert!(methods.contains("PUT"), "{methods}");
    assert!(headers.contains("Idempotency-Key"), "{headers}");
    assert!(headers.contains("If-Match"), "{headers}");
}
