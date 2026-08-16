//! The users-and-access and settings views.
//!
//! Specification 15.3 requires both screens. Neither had an endpoint, so the
//! SPA rendered an honest "not available yet" for each; these are the backends
//! those two screens were waiting on.
//!
//! Both are read-only aggregations of things an operator may already see
//! elsewhere, which makes them exactly the shape that leaks: the interesting
//! assertions below are about what must *not* appear, and about the tenant
//! boundary of Appendix B.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod harness;

use harness::{Harness, TENANT_A, TENANT_B};

/// A configuration with identities, groups and credentials in both tenants, so
/// every listing has something to leak if it is not scoped.
fn config() -> String {
    format!(
        "\
tenant id={TENANT_A}
tenant id={TENANT_B}
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:model provider=local model=m local=true operations=chat \\
       streaming=true context=1000 max_output=100
alias id=test-alias targets=local:model
grant scope=tenant:{TENANT_A} model=* allow=true
grant scope=tenant:{TENANT_B} model=* allow=true
identity issuer=https://accounts.google.com subject=aaa1 \\
         principal=user:alice tenant={TENANT_A}
identity issuer=https://accounts.google.com subject=bbb2 \\
         principal=user:bob tenant={TENANT_B}
group id=team-a tenant={TENANT_A} members=user:alice
group id=team-b tenant={TENANT_B} members=user:bob
role_binding subject=principal:user:alice role=operator
role_binding subject=principal:user:bob role=auditor
"
    )
}

fn admin() -> Harness {
    Harness::with_config(&config())
}

// -- Access ------------------------------------------------------------------

#[test]
fn the_access_view_shows_the_callers_own_tenant() {
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let response = admin.get(&manager, "/admin/v1/access");
    assert_eq!(response.status, 200, "{}", response.body);

    let body = response.json();
    assert_eq!(body.field_str("tenant").unwrap(), TENANT_A);

    let identities = body.field_array("identities").unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].field_str("principal").unwrap(), "user:alice");
    assert_eq!(identities[0].field_str("subject").unwrap(), "aaa1");

    let groups = body.field_array("groups").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].field_str("id").unwrap(), "team-a");
}

#[test]
fn the_access_view_never_shows_another_tenants_identities_or_groups() {
    // Appendix B. An identity is a person's Google account; a group is who a
    // binding will match. Neither belongs to a neighbour.
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let body = admin.get(&manager, "/admin/v1/access").body;
    assert!(!body.contains("bbb2"), "another tenant's subject appeared");
    assert!(!body.contains("user:bob"), "another tenant's principal appeared");
    assert!(!body.contains("team-b"), "another tenant's group appeared");
}

#[test]
fn a_service_principal_is_listed_without_its_secret() {
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );
    let (key_id, secret) = admin.issue_api_key(TENANT_A, "svc:worker");

    let response = admin.get(&manager, "/admin/v1/access");
    let body = response.json();
    let principals = body.field_array("service_principals").unwrap();

    let listed = principals
        .iter()
        .find(|p| p.field_str("key_id").unwrap_or_default() == key_id.as_str())
        .expect("the key is listed");
    assert_eq!(listed.field_str("principal").unwrap(), "svc:worker");
    assert_eq!(listed.field_str("status").unwrap(), "active");

    // The identifier is the key's public prefix; the secret is not here.
    assert!(
        !response.body_contains(&secret),
        "the access view disclosed a key secret"
    );
}

#[test]
fn another_tenants_service_principal_is_not_listed() {
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );
    let (other_key, _) = admin.issue_api_key(TENANT_B, "svc:neighbour");

    let response = admin.get(&manager, "/admin/v1/access");
    assert!(
        !response.body_contains(other_key.as_str()),
        "another tenant's key was listed"
    );
    assert!(!response.body_contains("svc:neighbour"));
}

#[test]
fn a_live_session_is_listed_without_anything_replayable() {
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let response = admin.get(&manager, "/admin/v1/access");
    let body = response.json();
    let sessions = body.field_array("sessions").unwrap();
    assert!(!sessions.is_empty(), "the caller's own session is not listed");

    // The cookie token is never stored server-side, so it cannot appear — but
    // asserting it explicitly is what stops a future change from putting one
    // there.
    assert!(
        !response.body_contains(&manager.token),
        "a session token appeared in the access view"
    );
    assert!(
        !response.body_contains(&manager.csrf),
        "a CSRF token appeared in the access view"
    );

    let current = sessions
        .iter()
        .find(|s| s.opt_field_bool("is_current").ok().flatten().unwrap_or(false))
        .expect("the caller's own session is marked");
    assert_eq!(current.field_str("principal").unwrap(), "user:manager-a");
}

#[test]
fn a_session_belonging_to_another_tenant_is_not_listed() {
    let admin = admin();
    let manager = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );
    let neighbour = admin.session(
        "user:manager-b",
        TENANT_B,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let response = admin.get(&manager, "/admin/v1/access");
    assert!(
        !response.body_contains("user:manager-b"),
        "another tenant's session was listed"
    );
    assert!(!response.body_contains(&neighbour.token));
}

#[test]
fn the_access_view_requires_the_principal_permission() {
    let admin = admin();
    let viewer = admin.viewer_in(TENANT_A);
    let response = admin.get(&viewer, "/admin/v1/access");
    assert_eq!(response.status, 403, "{}", response.body);
    assert!(!response.body_contains("user:alice"));
}

// -- Settings ----------------------------------------------------------------

#[test]
fn the_settings_view_reports_what_the_screen_needs() {
    let admin = admin();
    let operator = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let response = admin.get(&operator, "/admin/v1/settings");
    assert_eq!(response.status, 200, "{}", response.body);

    let body = response.json();
    // Specification 15.3 names these five.
    assert!(body.get("oidc").is_some());
    assert!(body.get("retention").is_some());
    assert!(body.get("cors_origins").is_some());
    assert!(body.get("break_glass").is_some());
    assert!(body.get("deployment").is_some());

    // And it says plainly that it cannot be written through.
    assert!(body.opt_field_bool("read_only").ok().flatten().unwrap_or(false));
}

#[test]
fn the_settings_view_does_not_disclose_local_socket_paths() {
    // None is a secret, but each names a local attack surface — and the
    // control socket in particular is unauthenticated, so anything that can
    // open it can stop the router.
    let admin = Harness::builder()
        .config(&format!(
            "{}settings tls_helper_socket=/run/hypellm-tls.sock \\
         oidc_verifier_socket=/run/hypellm-verify.sock control_socket=/run/hypellm-ctl.sock\n",
            config()
        ))
        .build();
    let operator = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let response = admin.get(&operator, "/admin/v1/settings");
    assert_eq!(response.status, 200, "{}", response.body);

    for path in [
        "/run/hypellm-tls.sock",
        "/run/hypellm-verify.sock",
        "/run/hypellm-ctl.sock",
    ] {
        assert!(
            !response.body_contains(path),
            "the settings view disclosed the socket path {path}"
        );
    }

    // What it reports instead is whether each is wired.
    let body = response.json();
    assert!(
        body.get("deployment")
            .and_then(|d| d.get("outbound_tls_configured"))
            .and_then(wire_json::Value::as_bool)
            .unwrap_or(false)
    );
}

#[test]
fn the_settings_view_reports_the_callers_own_retention() {
    let admin = Harness::with_config(&format!(
        "\
tenant id={TENANT_A} retention_days=7 residency=eu max_cost=3
tenant id={TENANT_B} retention_days=365
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:model provider=local model=m local=true operations=chat \\
       streaming=true context=1000 max_output=100
alias id=test-alias targets=local:model
grant scope=tenant:{TENANT_A} model=* allow=true
"
    ));
    let operator = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let body = admin.get(&operator, "/admin/v1/settings").json();
    let retention = body.get("retention").expect("retention");
    assert_eq!(retention.field_i64("days").unwrap(), 7);
    assert_eq!(retention.field_str("residency").unwrap(), "eu");
    // Not the neighbour's 365.
    assert_ne!(retention.field_i64("days").unwrap(), 365);
}

#[test]
fn the_settings_view_is_honest_about_break_glass() {
    // The role can be bound, but no local break-glass sign-in exists, so
    // specification 22.4's recovery path needs a session established
    // beforehand. A screen that showed "break-glass: available" would be read
    // as a working escape hatch during exactly the incident where it is not.
    let admin = admin();
    let operator = admin.session(
        "user:manager-a",
        TENANT_A,
        &[hypellm_core::rbac::Role::BreakGlassAdmin],
    );

    let body = admin.get(&operator, "/admin/v1/settings").json();
    let break_glass = body.get("break_glass").expect("break_glass");
    assert!(
        !break_glass
            .opt_field_bool("local_authentication_implemented")
            .ok()
            .flatten()
            .unwrap_or(true)
    );
    assert!(break_glass.field_str("note").unwrap().contains("no local"));
}

#[test]
fn the_settings_view_requires_the_settings_permission() {
    let admin = admin();
    let viewer = admin.viewer_in(TENANT_A);
    let response = admin.get(&viewer, "/admin/v1/settings");
    assert_eq!(response.status, 403, "{}", response.body);
}
