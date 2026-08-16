//! Tests of the harness itself (specification 21).
//!
//! Everything else under `tests/` builds on this fixture, so a fixture that
//! silently authenticated nobody, or that gave two "different" tenants the same
//! identity, would make a whole suite pass while proving nothing. These are the
//! checks that make the harness trustworthy enough to build on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use hypellm_core::rbac::Role;
use hypellm_core::time::Clock;
use harness::{Harness, LOCAL_TARGET, REMOTE_TARGET, TENANT_A, TENANT_B};
use wire_http1::Method;

#[test]
fn a_session_issued_by_the_harness_authorizes_a_read() {
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin.get(&operator, "/admin/v1/targets");

    assert_eq!(response.status, 200, "{}", response.body);
    let ids = response.ids();
    assert!(ids.contains(&LOCAL_TARGET.to_owned()), "{ids:?}");
    assert!(ids.contains(&REMOTE_TARGET.to_owned()), "{ids:?}");
}

#[test]
fn an_unauthenticated_request_is_refused_before_it_reaches_a_handler() {
    // Specification 16: every management resource sits behind a session. The
    // refusal must also disclose nothing about what exists.
    let admin = Harness::new();

    let response = admin.anonymous(Method::Get, "/admin/v1/targets");

    assert_eq!(response.status, 401);
    assert_eq!(response.error_code.as_deref(), Some("unauthenticated"));
    assert!(!response.body_contains(LOCAL_TARGET));
}

#[test]
fn a_forged_session_cookie_does_not_authenticate() {
    let admin = Harness::new();

    let response = admin
        .request(Method::Get, "/admin/v1/targets")
        .cookie("__Host-hypellm_session=not-a-real-token")
        .send();

    assert_eq!(response.status, 401);
}

#[test]
fn the_session_endpoint_reports_the_identity_the_harness_issued() {
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let response = admin.get(&editor, "/admin/v1/session");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.str_field("principal"), editor.principal.as_str());
    assert_eq!(response.str_field("tenant"), TENANT_A);
    let roles = response.json().field_array("roles").unwrap().to_vec();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].as_str(), Some(Role::PolicyEditor.as_str()));
}

#[test]
fn two_tenants_are_genuinely_distinct() {
    // The property the isolation suites depend on. A trace recorded for one
    // tenant must be invisible to the other — and invisible as *absent*, not as
    // forbidden, so that its existence is not confirmed.
    let admin = Harness::new();
    let here = admin.operator_in(TENANT_A);
    let there = admin.operator_in(TENANT_B);
    assert_ne!(here.tenant, there.tenant);
    assert_ne!(here.principal, there.principal);
    assert_ne!(here.token, there.token);

    let request_id = admin.record_decision(TENANT_A, 0x1234);
    let path = format!("/admin/v1/decisions/{request_id}");

    let own = admin.get(&here, &path);
    assert_eq!(own.status, 200, "{}", own.body);

    let other = admin.get(&there, &path);
    assert_eq!(other.status, 404, "{}", other.body);
    assert_eq!(other.error_code.as_deref(), Some("not_found"));
}

#[test]
fn a_session_lacking_the_permission_is_refused_rather_than_answered() {
    // A viewer holds ReadSummary and ReadOwnUsage and nothing else; the key
    // list requires ManageKeys (specification 9.3).
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/keys");

    assert_eq!(response.status, 403);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
}

#[test]
fn a_mutation_without_the_csrf_token_is_refused() {
    // Specification 9.1: state-changing requests carry a session-bound CSRF
    // token. The harness attaches one by default, so a test proving the refusal
    // has to be able to take it away again.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Patch, &format!("/admin/v1/targets/{LOCAL_TARGET}"))
        .as_session(&operator)
        .without_csrf()
        .if_match(harness::ANY_ETAG)
        .json(r#"{"state":"draining"}"#)
        .send();

    assert_eq!(response.status, 403);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
}

#[test]
fn a_request_from_a_hostile_origin_is_refused_before_the_cookie_is_read() {
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Get, "/admin/v1/targets")
        .as_session(&operator)
        .origin(harness::HOSTILE_ORIGIN)
        .send();

    assert_eq!(response.status, 403);
    assert_eq!(response.error_code.as_deref(), Some("origin_not_permitted"));

    // The allowlisted origin still works, so the refusal is the allowlist and
    // not a blanket rejection of every Origin header.
    let permitted = admin
        .request(Method::Get, "/admin/v1/targets")
        .as_session(&operator)
        .origin(harness::ALLOWED_ORIGIN)
        .send();
    assert_eq!(permitted.status, 200, "{}", permitted.body);
}

#[test]
fn the_clock_moves_only_when_a_test_moves_it() {
    let admin = Harness::new();
    let operator = admin.operator();
    assert_eq!(admin.clock.now_millis(), 0);

    assert_eq!(admin.get(&operator, "/admin/v1/overview").status, 200);

    // Past the idle window the session is gone, which is how the expiry tests
    // in the other suites will drive their own clocks.
    admin.advance(31 * 60 * 1000);
    let expired = admin.get(&operator, "/admin/v1/overview");
    assert_eq!(expired.status, 401, "{}", expired.body);
}

#[test]
fn reauthentication_restores_a_session_that_went_stale() {
    // ManageCredentials requires a recent authentication (specification 9.1),
    // so the harness has to be able to produce both states.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    admin.advance(6 * 60 * 1000);
    let stale = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"another-secret","secret":"s3cr3t"}"#,
    );
    assert_eq!(stale.status, 403, "{}", stale.body);
    assert_eq!(
        stale.error_code.as_deref(),
        Some("reauthentication_required")
    );

    let fresh = admin.reauthenticate(&manager);
    let accepted = admin.post(
        &fresh,
        "/admin/v1/credentials",
        r#"{"id":"another-secret","secret":"s3cr3t"}"#,
    );
    assert_eq!(accepted.status, 201, "{}", accepted.body);
}

#[test]
fn the_credential_sink_receives_what_the_api_says_it_stored() {
    // The harness's whole reason for owning a sink: telling a handler that
    // stored a secret from one that only claimed to.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let response = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{}:rotate", harness::CREDENTIAL),
        r#"{"secret":"the-new-provider-secret"}"#,
        harness::ANY_ETAG,
    );

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        admin.credentials.secret_text(harness::CREDENTIAL).as_deref(),
        Some("the-new-provider-secret")
    );
    assert!(
        !response.body_contains("the-new-provider-secret"),
        "a rotation response must not echo the secret: {}",
        response.body
    );
}

#[test]
fn a_harness_without_a_credential_sink_fails_closed() {
    let admin = Harness::builder().without_credential_sink().build();
    let manager = admin.credential_manager();

    let response = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{}:rotate", harness::CREDENTIAL),
        r#"{"secret":"the-new-provider-secret"}"#,
        harness::ANY_ETAG,
    );

    assert_eq!(response.status, 500, "{}", response.body);
    assert!(admin.credentials.is_empty());
}

#[test]
fn seeded_state_is_visible_to_the_endpoint_that_reads_it() {
    // Each seeding helper exists because a suite needs to put something in the
    // router that only the data plane would otherwise produce. If a helper
    // writes somewhere the handler does not read, the suite built on it would
    // test nothing.
    let admin = Harness::new();

    admin.record_usage(TENANT_A, "user:operator-acme", 100, 20);
    let usage = admin.get(&admin.operator(), "/admin/v1/usage");
    assert_eq!(usage.status, 200, "{}", usage.body);
    assert_eq!(usage.data().len(), 1);

    let before = admin.audit_count();
    admin.record_audit(
        TENANT_A,
        "user:auditor-acme",
        hypellm_store::AuditAction::Login,
        "session",
    );
    assert_eq!(admin.audit_count(), before + 1);
    let audit = admin.get(&admin.auditor(), "/admin/v1/audit");
    assert_eq!(audit.status, 200, "{}", audit.body);
    assert_eq!(audit.data().len(), 1);

    let draft = admin.create_draft("user:editor-acme", &harness::default_config());
    let drafts = admin.get(&admin.policy_editor(), "/admin/v1/policies");
    assert!(drafts.ids().contains(&draft), "{}", drafts.body);

    let (key_id, secret) = admin.issue_api_key(TENANT_B, "svc:other-tenant");
    let keys = admin.get(&admin.break_glass_in(TENANT_A), "/admin/v1/keys");
    assert_eq!(keys.status, 200, "{}", keys.body);
    assert!(
        !keys.ids().contains(&key_id.as_str().to_owned()),
        "another tenant's key must not be listed: {}",
        keys.body
    );
    assert!(!keys.body_contains(&secret));
}
