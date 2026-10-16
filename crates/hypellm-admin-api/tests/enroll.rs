//! Slave enrollment (specification 26.8): the token, the public endpoints a
//! new machine calls, and the approval that drafts its records.
//!
//! The properties: a token is shown once and never stored; the public
//! endpoints take nothing but a valid token and refuse browsers; a used,
//! rejected or expired token answers exactly like a wrong one; and approval
//! drafts the machine without publishing it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

mod harness;

use harness::{Harness, TENANT_A, TestSession, default_config};
use hypellm_admin_api::AdminRequest;
use hypellm_core::ids::HostId;
use hypellm_core::rbac::Role;
use hypellm_store::RecordKind;
use wire_http1::{Headers, Method};
use wire_json::Value;

const AGENT_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M agent@router";

fn config(enroll_url: bool, agent_key: bool) -> String {
    let mut text = default_config();
    if enroll_url {
        text = text.replacen("settings ", "settings fleet_enroll_url=https://router.test ", 1);
    }
    text.push_str("fleet_agent id=local socket=/run/hypellm/fleet.sock");
    if agent_key {
        text.push_str(&format!(" ssh_public_key=\"{AGENT_KEY}\""));
    }
    text.push('\n');
    text
}

fn enrolling() -> Harness {
    Harness::with_config(&config(true, true))
}

fn operator(admin: &Harness) -> TestSession {
    admin.session("user:operator", TENANT_A, &[Role::Operator])
}

/// An operator who may also author drafts, which approval needs.
fn approver(admin: &Harness) -> TestSession {
    admin.session(
        "user:fleet-lead",
        TENANT_A,
        &[Role::Operator, Role::PolicyEditor],
    )
}

fn mint(admin: &Harness, session: &TestSession) -> (String, String) {
    let response = admin.post(
        session,
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local"}"#,
    );
    assert_eq!(response.status, 201, "{}", response.body);
    (response.str_field("id"), response.str_field("token"))
}

/// Call a public `/fleet/v1/` endpoint the way the install script does: no
/// session, no key, no `Origin`.
fn public(admin: &Harness, path: &str, body: &str, origin: Option<&str>) -> (u16, Value) {
    let mut headers = Headers::default();
    headers.append("content-type", "application/json").unwrap();
    if let Some(origin) = origin {
        headers.append("origin", origin).unwrap();
    }
    let request = AdminRequest {
        method: &Method::Post,
        path,
        query: None,
        headers: &headers,
        body: body.as_bytes(),
        peer: Some("100.64.0.9".parse().unwrap()),
        request_id: "r-1".to_owned(),
    };
    match admin.api.handle_enrollment(&request) {
        Ok(response) => (
            response.status,
            wire_json::parse_str(&response.body, &wire_json::Limits::SMALL).unwrap(),
        ),
        Err(error) => (
            error.status(),
            wire_json::parse_str(&error.to_json("r-1"), &wire_json::Limits::SMALL).unwrap(),
        ),
    }
}

fn report(token: &str, data_dir: &str) -> String {
    format!(
        r#"{{"token":"{token}","address":"192.168.1.20","arch":"x86_64","hostname":"rig","ssh_user":"albert","data_dir":"{data_dir}","memory_bytes":68719476736,"gpus":[{{"index":0,"name":"RTX 4090","memory_bytes":25769803776}}],"ssh_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M host@rig","device_key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX5iBIxDSO2VYlfFZRE/T1VJfwE4OL9kokNcCposqRRI=\n-----END PUBLIC KEY-----\n","kit_version":"1.0.0"}}"#
    )
}

fn register(admin: &Harness, token: &str) -> (u16, Value) {
    public(
        admin,
        "/fleet/v1/enroll:complete",
        &report(token, "/home/albert/.hypellm"),
        None,
    )
}

fn error_code(value: &Value) -> String {
    value
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_token_is_shown_once_and_never_stored_or_listed() {
    let admin = enrolling();
    let session = operator(&admin);
    let (_, token) = mint(&admin, &session);
    assert_eq!(token.len(), 64);

    let listed = admin.get(&session, "/admin/v1/fleet/enrollments");
    assert!(listed.is_ok(), "{}", listed.body);
    assert!(!listed.body.contains(&token), "the list revealed the token");

    for (_, payload) in admin
        .state
        .store
        .records_of_kinds(&[RecordKind::FleetEnrollment, RecordKind::AuditEvent])
        .unwrap()
    {
        assert!(
            !String::from_utf8_lossy(&payload).contains(&token),
            "the token reached the durable log"
        );
    }
}

#[test]
fn the_command_names_the_configured_origin_the_token_and_the_kit_version() {
    let admin = enrolling();
    let response = admin.post(
        &operator(&admin),
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local"}"#,
    );
    let command = response.str_field("command");
    let token = response.str_field("token");
    assert_eq!(
        command,
        format!(
            "curl -fsSL https://router.test/fleet/v1/install.sh | sh -s -- --router \
             https://router.test --token {token} --version 1.1.0"
        )
    );
}

#[test]
fn minting_needs_fleet_enroll_and_a_configured_origin_and_an_agent_key() {
    let admin = enrolling();
    for session in [
        admin.viewer(),
        admin.policy_editor(),
        admin.policy_approver(),
    ] {
        let response = admin.post(
            &session,
            "/admin/v1/fleet/enrollments",
            r#"{"host":"rig","agent":"local"}"#,
        );
        assert_eq!(response.status, 403, "{:?}: {}", session.roles, response.body);
    }
    assert!(admin.state.enrollments.list().is_empty(), "a refusal recorded nothing");

    let unconfigured = Harness::with_config(&config(false, true));
    let response = unconfigured.post(
        &operator(&unconfigured),
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local"}"#,
    );
    assert_eq!(response.status, 409, "{}", response.body);

    let keyless = Harness::with_config(&config(true, false));
    let response = keyless.post(
        &operator(&keyless),
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local"}"#,
    );
    assert_eq!(response.status, 409, "{}", response.body);
    assert!(response.body.contains("ssh_public_key"));
}

#[test]
fn a_host_identifier_that_would_inject_configuration_is_refused() {
    let admin = enrolling();
    for host in [r#"rig agent=evil"#, "rig\\nhost id=x", "rig#", ""] {
        let response = admin.post(
            &operator(&admin),
            "/admin/v1/fleet/enrollments",
            &format!(r#"{{"host":"{host}","agent":"local"}}"#),
        );
        assert_eq!(response.status, 400, "{host:?}: {}", response.body);
    }
}

#[test]
fn begin_reveals_the_agent_key_without_consuming_the_token() {
    let admin = enrolling();
    let (_, token) = mint(&admin, &operator(&admin));
    let body = format!(r#"{{"token":"{token}"}}"#);
    for _ in 0..2 {
        let (status, value) = public(&admin, "/fleet/v1/enroll:begin", &body, None);
        assert_eq!(status, 200, "{value:?}");
        assert_eq!(value.get("host").and_then(Value::as_str), Some("rig"));
        assert_eq!(
            value.get("agent_ssh_key").and_then(Value::as_str),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M"),
            "the agent key, without its comment"
        );
    }
    assert_eq!(register(&admin, &token).0, 201);
}

#[test]
fn a_registered_slave_is_not_a_fleet_member_and_its_token_is_spent() {
    let admin = enrolling();
    let session = operator(&admin);
    let (id, token) = mint(&admin, &session);

    let (status, value) = register(&admin, &token);
    assert_eq!(status, 201, "{value:?}");
    assert_eq!(value.get("state").and_then(Value::as_str), Some("registered"));

    // Registered, not admitted: nothing in the configuration names it.
    assert!(
        !admin
            .state
            .config()
            .fleet
            .hosts
            .contains_key(&HostId::new("rig").unwrap())
    );
    let listed = admin.get(&session, "/admin/v1/fleet/enrollments");
    assert!(listed.body.contains(&id));
    assert!(listed.body.contains("SHA256:PMco07vuSgY4X36KVLs/BWVRspIccQfR8awZG0Yr9OE"));
    assert!(!listed.body.contains("AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJ"), "fingerprints, not keys");

    // The same token again answers exactly like one that never existed.
    let (again, spent) = register(&admin, &token);
    let (_, never) = register(&admin, &"e".repeat(64));
    assert_eq!(again, 401);
    assert_eq!(error_code(&spent), error_code(&never));
    assert_eq!(
        spent.get("error").and_then(|e| e.get("message")),
        never.get("error").and_then(|e| e.get("message"))
    );
}

#[test]
fn a_hostile_registration_is_refused_and_does_not_spend_the_token() {
    let admin = enrolling();
    let (_, token) = mint(&admin, &operator(&admin));
    let (status, value) = public(
        &admin,
        "/fleet/v1/enroll:complete",
        &report(&token, "/home/albert/../../etc"),
        None,
    );
    assert_eq!(status, 400, "{value:?}");
    assert_eq!(register(&admin, &token).0, 201, "the token was still good");
}

#[test]
fn the_public_endpoints_refuse_browsers_and_are_absent_when_unconfigured() {
    let admin = enrolling();
    let (_, token) = mint(&admin, &operator(&admin));
    let body = format!(r#"{{"token":"{token}"}}"#);
    let (status, _) = public(
        &admin,
        "/fleet/v1/enroll:begin",
        &body,
        Some("https://router.test"),
    );
    assert_eq!(status, 403, "a request with an Origin is a browser's");

    let unconfigured = Harness::with_config(&config(false, true));
    let (status, _) = public(&unconfigured, "/fleet/v1/enroll:begin", &body, None);
    assert_eq!(status, 404);
}

#[test]
fn approval_drafts_the_host_and_its_accelerators_without_publishing_them() {
    let admin = enrolling();
    let lead = approver(&admin);
    let (id, token) = mint(&admin, &lead);
    assert_eq!(register(&admin, &token).0, 201);

    // An operator without edit_policy may enroll but not draft.
    let refused = admin.post(
        &operator(&admin),
        &format!("/admin/v1/fleet/enrollments/{id}:approve"),
        "",
    );
    assert_eq!(refused.status, 403, "{}", refused.body);

    let approved = admin.post(&lead, &format!("/admin/v1/fleet/enrollments/{id}:approve"), "");
    assert_eq!(approved.status, 200, "{}", approved.body);
    let draft_id = approved.str_field("draft_id");
    assert_eq!(approved.json().get("published").and_then(Value::as_bool), Some(false));

    let draft = admin
        .state
        .drafts
        .get(&draft_id, &hypellm_core::ids::TenantId::new(TENANT_A).unwrap())
        .expect("the draft exists");
    assert!(draft.text.contains("host agent=local arch=x86_64 id=rig"), "{}", draft.text);
    assert!(
        draft.text.contains("accelerator host=rig id=rig-gpu0 kind=cuda memory_bytes=25769803776"),
        "{}",
        draft.text
    );
    // Drafted, not published: the active configuration is untouched.
    assert!(
        !admin
            .state
            .config()
            .fleet
            .hosts
            .contains_key(&HostId::new("rig").unwrap())
    );

    // An approval cannot be repeated, and revocation follows it.
    let again = admin.post(&lead, &format!("/admin/v1/fleet/enrollments/{id}:approve"), "");
    assert_eq!(again.status, 409);
    let revoked = admin.post(&lead, &format!("/admin/v1/fleet/enrollments/{id}:revoke"), "");
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(revoked.str_field("state"), "revoked");
}

#[test]
fn a_rejected_enrollment_cannot_register_or_be_approved() {
    let admin = enrolling();
    let lead = approver(&admin);
    let (id, token) = mint(&admin, &lead);
    let rejected = admin.post(&lead, &format!("/admin/v1/fleet/enrollments/{id}:reject"), "");
    assert_eq!(rejected.status, 200, "{}", rejected.body);
    assert_eq!(register(&admin, &token).0, 401);
    let approve = admin.post(&lead, &format!("/admin/v1/fleet/enrollments/{id}:approve"), "");
    assert_eq!(approve.status, 409);
}

#[test]
fn an_expired_token_is_refused_as_unknown() {
    let admin = enrolling();
    let response = admin.post(
        &operator(&admin),
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local","ttl_seconds":60}"#,
    );
    let token = response.str_field("token");
    admin.advance(61_000);
    assert_eq!(register(&admin, &token).0, 401);
}
