//! The API key and provider credential endpoints (specification 16, 9.2, 9.3).
//!
//! These are the two management surfaces that mint and hold authenticators, so
//! the properties under test are not features but the things an attacker would
//! go looking for:
//!
//! - a key secret is shown exactly once and is retrievable nowhere else
//!   (specification 9.2, 15.3);
//! - a provider credential secret is write-only — no endpoint returns one, and
//!   no permission exists that would authorize it (specification 9.3);
//! - both endpoints answer for the caller's tenant only, and refuse a caller
//!   who lacks `ManageKeys` / `ManageCredentials` rather than answering
//!   (Appendix B, "management visibility never exceeds the caller's tenant and
//!   permissions");
//! - and a response that claims something happened is a response after which
//!   that thing has happened: the key is in the durable log, the revocation is
//!   in force, the secret is in the sink. The no-op handlers this suite exists
//!   to prevent all had honest-looking bodies.
//!
//! Two behaviours here are documented rather than asserted-against, and say so
//! in the test: a credential is a router-wide resource any credential manager
//! may rotate, and a created reference that the configuration does not declare
//! is a stored secret nothing will ever use. Both are findings, pinned so that
//! a change in the model is a visible failure rather than a silent widening.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use hypellm_auth::{KeyRejection, Scope};
use hypellm_core::ids::KeyId;
use hypellm_core::rbac::Role;
use hypellm_core::time::Clock;
use hypellm_store::{Frame, Log, RecordKind};
use harness::{ANY_ETAG, CREDENTIAL, Harness, STALE_ETAG, TENANT_A, TENANT_B, TestSession};
use wire_http1::Method;

/// The MAC key [`Harness`] opens its store with.
///
/// Replaying the log directly is the only way to see what actually reached
/// disk: the live `Store` holds the state directory's lock for the harness's
/// lifetime, so it cannot be reopened, and a second read-only handle on the
/// log file is the next best thing. A mismatch here fails the replay loudly
/// rather than silently finding no frames.
const STORE_MAC_KEY: &[u8] = b"harness-store-mac-key";

/// Every durable frame of one kind, read back from the log file.
fn durable_frames(admin: &Harness, kind: RecordKind) -> Vec<Frame> {
    // `log.bin` is the file name fixed by the `hypellm-store` module header.
    let path = admin.state.store.dir().join("log.bin");
    let mut log = Log::open(&path, false).expect("open the log for reading");
    let replay = log.replay(STORE_MAC_KEY).expect("replay the log");
    assert!(
        replay.truncated_at.is_none(),
        "the log has a torn tail at {:?}",
        replay.truncated_at
    );
    replay
        .frames
        .into_iter()
        .filter(|frame| frame.kind == kind)
        .collect()
}

/// Create a key through the API and return its identifier and one-time secret.
fn create_key(admin: &Harness, session: &TestSession, principal: &str) -> (String, String) {
    let response = admin.post(
        session,
        "/admin/v1/keys",
        &format!(r#"{{"principal":"{principal}","scopes":["inference"]}}"#),
    );
    assert_eq!(response.status, 201, "{}", response.body);
    (response.str_field("id"), response.str_field("secret"))
}

/// The ETag a rotation's `If-Match` will demand, as a client reads it.
///
/// Specification 15.4 requires the precondition on mutation, so every rotation
/// below carries one; taking it from the listing rather than sending `*` is
/// what proves the tag a read discloses is the tag the write accepts.
fn credential_etag(admin: &Harness, session: &TestSession, id: &str) -> String {
    admin
        .get(session, "/admin/v1/credentials")
        .data()
        .into_iter()
        .find(|item| item.field_str("id").ok() == Some(id))
        .unwrap_or_else(|| panic!("'{id}' is not in the credential listing"))
        .field_str("etag")
        .expect("a credential read must disclose its ETag")
        .to_owned()
}

/// The roles that hold neither `ManageKeys` nor `ManageCredentials`.
fn unprivileged_roles(admin: &Harness) -> Vec<TestSession> {
    vec![
        admin.viewer(),
        admin.operator(),
        admin.policy_editor(),
        admin.policy_approver(),
        admin.auditor(),
        admin.unprivileged(),
    ]
}

// -- Keys: the one-time secret ----------------------------------------------

#[test]
fn a_created_key_returns_its_secret_exactly_once_and_no_listing_returns_it_again() {
    // Specification 9.2: "display once". The secret exists in one response and
    // nowhere else; a management API that could re-read it would make every
    // read of the key list a credential disclosure.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let (key_id, secret) = create_key(&admin, &oncall, "svc:build");
    assert!(secret.starts_with("hypellmk_"), "{secret}");

    let listed = admin.get(&oncall, "/admin/v1/keys");
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert!(
        listed.ids().contains(&key_id),
        "the key it just created is missing: {}",
        listed.body
    );
    assert!(
        !listed.body_contains(&secret),
        "the key list disclosed the secret: {}",
        listed.body
    );
    for item in listed.data() {
        assert!(item.get("secret").is_none(), "a listed key carries 'secret'");
    }
}

#[test]
fn a_listed_key_never_carries_the_verifier_it_is_authenticated_against() {
    // The verifier is not the secret, but it is key-derived material: anything
    // holding the verifier key could confirm a guessed secret offline. It has
    // no reason to leave the process (specification 9.2).
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let (key_id, _secret) = create_key(&admin, &oncall, "svc:build");
    let record = admin
        .state
        .keys
        .get(&KeyId::new(&key_id).unwrap())
        .expect("the key is in the store");

    let listed = admin.get(&oncall, "/admin/v1/keys");
    assert!(
        !listed.body_contains(&record.verifier.to_hex()),
        "the key list disclosed the verifier: {}",
        listed.body
    );
    for item in listed.data() {
        assert!(item.get("verifier").is_none());
    }
}

#[test]
fn the_one_time_secret_actually_authenticates_and_carries_only_the_scopes_asked_for() {
    // A response body that looks like a key but does not authenticate is the
    // no-op failure mode in its purest form.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let response = admin.post(
        &oncall,
        "/admin/v1/keys",
        r#"{"principal":"svc:build","scopes":["inference"],"description":"CI"}"#,
    );
    assert_eq!(response.status, 201, "{}", response.body);
    let secret = response.str_field("secret");

    let now = admin.clock.wall_millis();
    let verified = admin
        .state
        .keys
        .verify_scoped(&secret, Scope::Inference, None, now)
        .expect("the returned secret authenticates");
    assert_eq!(verified.tenant.as_str(), TENANT_A);
    assert_eq!(verified.principal.as_str(), "svc:build");

    // A scope that was not requested is not granted.
    let refused = admin
        .state
        .keys
        .verify_scoped(&secret, Scope::Embeddings, None, now);
    assert!(
        matches!(refused, Err(KeyRejection::ScopeNotPermitted)),
        "{refused:?}"
    );
}

#[test]
fn a_key_secret_is_never_written_to_the_management_log() {
    // Specification 17: secrets do not reach telemetry. The one-time secret is
    // the one value in this API that would be catastrophic in a log file.
    //
    // These handlers emit no telemetry at all today — the sink is empty after a
    // creation — so this holds trivially. It is kept as the guard on the day a
    // management access log arrives, which is exactly when a hurried
    // `debug!("created {key:?}")` would land.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let (_id, secret) = create_key(&admin, &oncall, "svc:build");

    for line in admin.log_lines() {
        assert!(!line.contains(&secret), "a log line carried the secret: {line}");
    }
}

// -- Keys: durability --------------------------------------------------------

#[test]
fn a_created_key_reaches_the_durable_log_before_its_secret_is_handed_out() {
    // A key that authenticates now but is absent from the log would stop
    // working at the next restart, and the holder would have no way to know
    // until it did.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let (key_id, secret) = create_key(&admin, &oncall, "svc:build");

    let frames = durable_frames(&admin, RecordKind::ApiKey);
    assert_eq!(frames.len(), 1, "exactly one key record should be on disk");
    let record = hypellm_auth::KeyRecord::from_payload(&frames[0].payload)
        .expect("the durable payload decodes as a key record");
    assert_eq!(record.id.as_str(), key_id);
    assert_eq!(record.tenant.as_str(), TENANT_A);
    assert_eq!(record.principal.as_str(), "svc:build");
    assert!(!record.revoked);

    // And what reached disk is the verifier, not the secret: a state directory
    // read by an attacker must not yield anything that authenticates
    // (specification 9.2).
    assert!(
        !String::from_utf8_lossy(&frames[0].payload).contains(&secret),
        "the durable key record contains the secret"
    );
}

#[test]
fn key_creation_is_recorded_in_the_durable_audit_chain() {
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let before = admin.audit_count();

    let (_id, _secret) = create_key(&admin, &oncall, "svc:build");

    assert_eq!(
        admin.audit_count(),
        before + 1,
        "minting an authenticator must leave an audit record"
    );
}

// -- Keys: revocation --------------------------------------------------------

#[test]
fn revoking_a_key_stops_it_authenticating_immediately() {
    // Specification 22.3: "Revoke key id immediately; revocation bypasses
    // configuration publication delay."
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let (key_id, secret) = create_key(&admin, &oncall, "svc:build");
    let now = admin.clock.wall_millis();
    assert!(admin.state.keys.verify(&secret, None, now).is_ok());

    let revoked = admin.delete(&oncall, &format!("/admin/v1/keys/{key_id}"));
    assert_eq!(revoked.status, 204, "{}", revoked.body);

    let rejection = admin.state.keys.verify(&secret, None, now);
    assert!(
        matches!(rejection, Err(KeyRejection::Revoked)),
        "a revoked key still authenticates: {rejection:?}"
    );
}

#[test]
fn a_revocation_reaches_the_durable_log_so_a_restart_cannot_undo_it() {
    // A revocation that never reached disk would be replayed away at startup,
    // resurrecting a key that was revoked precisely because it leaked.
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let (key_id, _secret) = create_key(&admin, &oncall, "svc:build");

    assert_eq!(
        admin
            .delete(&oncall, &format!("/admin/v1/keys/{key_id}"))
            .status,
        204
    );

    let frames = durable_frames(&admin, RecordKind::ApiKeyRevocation);
    assert_eq!(frames.len(), 1, "the revocation is not on disk");
    assert_eq!(String::from_utf8_lossy(&frames[0].payload), key_id);
}

#[test]
fn a_revoked_key_is_still_listed_so_the_revocation_is_visible() {
    // Deleting the record outright would leave an operator unable to tell a
    // revoked key from one that never existed.
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let (key_id, _secret) = create_key(&admin, &oncall, "svc:build");

    assert_eq!(
        admin
            .delete(&oncall, &format!("/admin/v1/keys/{key_id}"))
            .status,
        204
    );

    let listed = admin.get(&oncall, "/admin/v1/keys");
    let item = listed
        .data()
        .into_iter()
        .find(|item| item.field_str("id").ok() == Some(key_id.as_str()))
        .expect("the revoked key is still listed");
    assert_eq!(item.get("revoked").and_then(wire_json::Value::as_bool), Some(true));
}

#[test]
fn revoking_an_unknown_or_malformed_key_identifier_is_a_not_found_rather_than_a_panic() {
    let admin = Harness::new();
    let oncall = admin.break_glass();

    for id in ["0000000000000000", "not-a-key-id", "a".repeat(300).as_str()] {
        let response = admin.delete(&oncall, &format!("/admin/v1/keys/{id}"));
        assert_eq!(response.status, 404, "id={id}: {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("not_found"));
    }

    assert!(
        durable_frames(&admin, RecordKind::ApiKeyRevocation).is_empty(),
        "a failed revocation wrote to the log"
    );
}

// -- Keys: tenant isolation --------------------------------------------------

#[test]
fn a_key_belonging_to_another_tenant_is_not_listed() {
    // Appendix B: management visibility never exceeds the caller's tenant.
    let admin = Harness::new();
    let (other_id, other_secret) = admin.issue_api_key(TENANT_B, "svc:their-build");
    let oncall = admin.break_glass_in(TENANT_A);
    let (own_id, _own_secret) = create_key(&admin, &oncall, "svc:our-build");

    let listed = admin.get(&oncall, "/admin/v1/keys");
    let ids = listed.ids();
    assert!(ids.contains(&own_id), "{}", listed.body);
    assert!(
        !ids.contains(&other_id.as_str().to_owned()),
        "another tenant's key is listed: {}",
        listed.body
    );
    assert!(!listed.body_contains("svc:their-build"), "{}", listed.body);
    assert!(!listed.body_contains(&other_secret));
}

#[test]
fn a_key_belonging_to_another_tenant_cannot_be_revoked() {
    // The refusal must also be a 404: a 403 would confirm that the identifier
    // names a real key in some other tenant.
    let admin = Harness::new();
    let (other_id, other_secret) = admin.issue_api_key(TENANT_B, "svc:their-build");
    let oncall = admin.break_glass_in(TENANT_A);

    let response = admin.delete(&oncall, &format!("/admin/v1/keys/{other_id}"));

    assert_eq!(response.status, 404, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("not_found"));
    assert!(
        admin
            .state
            .keys
            .verify(&other_secret, None, admin.clock.wall_millis())
            .is_ok(),
        "the other tenant's key was revoked across the boundary"
    );
    assert!(
        durable_frames(&admin, RecordKind::ApiKeyRevocation).is_empty(),
        "a cross-tenant revocation was written to the log"
    );
}

#[test]
fn a_key_is_minted_in_the_callers_tenant_whatever_the_body_asks_for() {
    // No client-controlled value may widen authority. A body naming another
    // tenant must not produce a key that authenticates there.
    let admin = Harness::new();
    let oncall = admin.break_glass_in(TENANT_A);

    let response = admin.post(
        &oncall,
        "/admin/v1/keys",
        &format!(r#"{{"principal":"svc:build","tenant":"{TENANT_B}","scopes":["inference"]}}"#),
    );
    assert_eq!(response.status, 201, "{}", response.body);

    let key_id = KeyId::new(response.str_field("id")).unwrap();
    let record = admin.state.keys.get(&key_id).expect("the key exists");
    assert_eq!(
        record.tenant.as_str(),
        TENANT_A,
        "the request body chose the tenant"
    );

    let elsewhere = admin.get(&admin.break_glass_in(TENANT_B), "/admin/v1/keys");
    assert!(
        !elsewhere.ids().contains(&key_id.as_str().to_owned()),
        "the key landed in the tenant the body named: {}",
        elsewhere.body
    );
}

#[test]
fn a_created_key_carries_no_roles_however_the_request_asks() {
    // Roles on a key are management authority. `create_key` passes an empty
    // role list; a body-supplied one would let a break-glass administrator mint
    // a non-expiring credential that is itself a break-glass administrator.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let response = admin.post(
        &oncall,
        "/admin/v1/keys",
        &format!(
            r#"{{"principal":"svc:build","scopes":["inference"],"roles":["{}"]}}"#,
            Role::BreakGlassAdmin.as_str()
        ),
    );
    assert_eq!(response.status, 201, "{}", response.body);

    let record = admin
        .state
        .keys
        .get(&KeyId::new(response.str_field("id")).unwrap())
        .expect("the key exists");
    assert!(
        record.roles.is_empty(),
        "the request body granted roles: {:?}",
        record.roles
    );
    assert!(record.permissions().is_empty());
}

#[test]
fn a_management_scoped_key_still_cannot_call_the_management_api() {
    // Specification 3: the management path is separated from the data plane.
    // `/admin/v1` authenticates sessions only, so a key — whatever scope it
    // carries — is not an admission ticket to it.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let response = admin.post(
        &oncall,
        "/admin/v1/keys",
        r#"{"principal":"svc:build","scopes":["management:write"]}"#,
    );
    assert_eq!(response.status, 201, "{}", response.body);
    let secret = response.str_field("secret");

    let attempt = admin
        .request(Method::Get, "/admin/v1/keys")
        .header("authorization", &format!("Bearer {secret}"))
        .send();
    assert_eq!(attempt.status, 401, "{}", attempt.body);
    assert_eq!(attempt.error_code.as_deref(), Some("unauthenticated"));
}

// -- Keys: authorization -----------------------------------------------------

#[test]
fn every_key_endpoint_refuses_a_caller_without_manage_keys() {
    // Specification 9.3 puts `ManageKeys` on the break-glass role alone. A
    // caller without it gets a refusal, not data and not a key.
    let admin = Harness::new();
    let (planted, _secret) = admin.issue_api_key(TENANT_A, "svc:planted");
    let before = admin.state.keys.len();

    for session in unprivileged_roles(&admin) {
        let listed = admin.get(&session, "/admin/v1/keys");
        assert_eq!(listed.status, 403, "{:?}: {}", session.roles, listed.body);
        assert_eq!(listed.error_code.as_deref(), Some("forbidden"));
        assert!(!listed.body_contains("svc:planted"), "{}", listed.body);

        let created = admin.post(
            &session,
            "/admin/v1/keys",
            r#"{"principal":"svc:build","scopes":["inference"]}"#,
        );
        assert_eq!(created.status, 403, "{:?}: {}", session.roles, created.body);
        assert!(!created.body_contains("hypellmk_"), "{}", created.body);

        let revoked = admin.delete(&session, &format!("/admin/v1/keys/{planted}"));
        assert_eq!(revoked.status, 403, "{:?}: {}", session.roles, revoked.body);
    }

    assert_eq!(admin.state.keys.len(), before, "a refused call created a key");
    assert!(
        !admin.state.keys.get(&planted).unwrap().revoked,
        "a refused call revoked a key"
    );
    assert!(durable_frames(&admin, RecordKind::ApiKey).is_empty());
}

#[test]
fn an_unauthenticated_caller_cannot_mint_or_revoke_a_key() {
    let admin = Harness::new();
    let (planted, _secret) = admin.issue_api_key(TENANT_A, "svc:planted");

    let created = admin
        .request(Method::Post, "/admin/v1/keys")
        .json(r#"{"principal":"svc:build","scopes":["inference"]}"#)
        .send();
    assert_eq!(created.status, 401, "{}", created.body);

    let revoked = admin.anonymous(Method::Delete, &format!("/admin/v1/keys/{planted}"));
    assert_eq!(revoked.status, 401, "{}", revoked.body);

    assert!(!admin.state.keys.get(&planted).unwrap().revoked);
    assert!(durable_frames(&admin, RecordKind::ApiKey).is_empty());
}

#[test]
fn minting_a_key_requires_a_recent_authentication() {
    // Specification 9.1: `ManageKeys` is a re-authentication permission. A
    // session left open on an unlocked laptop must not still be able to mint an
    // authenticator an hour later.
    let admin = Harness::new();
    let oncall = admin.break_glass();
    admin.advance(6 * 60 * 1000);

    let stale = admin.post(
        &oncall,
        "/admin/v1/keys",
        r#"{"principal":"svc:build","scopes":["inference"]}"#,
    );
    assert_eq!(stale.status, 403, "{}", stale.body);
    assert_eq!(
        stale.error_code.as_deref(),
        Some("reauthentication_required")
    );
    assert!(!stale.body_contains("hypellmk_"), "{}", stale.body);
    assert!(durable_frames(&admin, RecordKind::ApiKey).is_empty());

    let fresh = admin.reauthenticate(&oncall);
    let accepted = admin.post(
        &fresh,
        "/admin/v1/keys",
        r#"{"principal":"svc:build","scopes":["inference"]}"#,
    );
    assert_eq!(accepted.status, 201, "{}", accepted.body);
}

#[test]
fn minting_a_key_without_a_csrf_token_is_refused() {
    // Specification 9.1: a cross-site POST that mints a working credential
    // would be the worst possible CSRF outcome.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let response = admin
        .request(Method::Post, "/admin/v1/keys")
        .as_session(&oncall)
        .without_csrf()
        .json(r#"{"principal":"svc:build","scopes":["inference"]}"#)
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    assert!(durable_frames(&admin, RecordKind::ApiKey).is_empty());
}

// -- Keys: input validation --------------------------------------------------

#[test]
fn a_key_request_without_a_usable_scope_is_refused_rather_than_given_every_scope() {
    // An empty scope list must not be read as "unrestricted".
    let admin = Harness::new();
    let oncall = admin.break_glass();

    for body in [
        r#"{"principal":"svc:build"}"#,
        r#"{"principal":"svc:build","scopes":[]}"#,
        r#"{"principal":"svc:build","scopes":["root"]}"#,
        r#"{"scopes":["inference"]}"#,
        r#"{"principal":"not a principal","scopes":["inference"]}"#,
        "{",
    ] {
        let response = admin.post(&oncall, "/admin/v1/keys", body);
        assert_eq!(response.status, 400, "body={body}: {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("invalid_request"));
    }

    assert_eq!(admin.state.keys.len(), 0, "a refused request created a key");
    assert!(durable_frames(&admin, RecordKind::ApiKey).is_empty());
}

// -- Credentials: the secret goes to the sink and nowhere else ---------------

#[test]
fn creating_a_credential_puts_the_secret_in_the_sink_and_not_in_the_response() {
    // Specification 9.3: a credential manager can rotate a secret and cannot
    // read one back. The handler this replaced validated the secret's presence,
    // discarded it, and replied `stored: true`.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let response = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"cred-new","secret":"sk-live-0123456789"}"#,
    );

    assert_eq!(response.status, 201, "{}", response.body);
    assert_eq!(response.str_field("id"), "cred-new");
    assert_eq!(
        admin.credentials.secret_text("cred-new").as_deref(),
        Some("sk-live-0123456789"),
        "the sink did not receive the secret the response reported storing"
    );
    assert!(
        !response.body_contains("sk-live-0123456789"),
        "the response echoed the secret: {}",
        response.body
    );
}

#[test]
fn rotating_a_declared_credential_replaces_the_stored_secret() {
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let path = format!("/admin/v1/credentials/{CREDENTIAL}:rotate");

    let first_tag = credential_etag(&admin, &manager, CREDENTIAL);
    assert_eq!(
        admin
            .post_if_match(&manager, &path, r#"{"secret":"first"}"#, &first_tag)
            .status,
        200
    );
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("first")
    );

    // The first store of a secret moves the tag, so the stale one is refused.
    let stale = admin.post_if_match(&manager, &path, r#"{"secret":"wrong"}"#, &first_tag);
    assert_eq!(stale.status, 412, "{}", stale.body);
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("first"),
        "a refused rotation replaced the secret anyway"
    );

    let second = admin.post_if_match(
        &manager,
        &path,
        r#"{"secret":"second"}"#,
        &credential_etag(&admin, &manager, CREDENTIAL),
    );

    assert_eq!(second.status, 200, "{}", second.body);
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("second"),
        "the rotation reported success without replacing the secret"
    );
    assert_eq!(admin.credentials.len(), 1, "rotation created a second entry");
}

#[test]
fn no_credential_endpoint_discloses_a_secret_value() {
    // The disclosure sweep: every credential response and every log line, after
    // a create and a rotation with distinctive values.
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let created = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"cred-new","secret":"secret-from-create"}"#,
    );
    let rotated = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"secret-from-rotation"}"#,
        &credential_etag(&admin, &manager, CREDENTIAL),
    );
    let listed = admin.get(&manager, "/admin/v1/credentials");
    // A refusal would satisfy the sweep below trivially, so each call has to
    // have actually happened.
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    assert_eq!(listed.status, 200, "{}", listed.body);

    for response in [&created, &rotated, &listed] {
        for secret in ["secret-from-create", "secret-from-rotation"] {
            assert!(
                !response.body_contains(secret),
                "a credential response disclosed a secret: {}",
                response.body
            );
        }
    }
    for item in listed.data() {
        assert!(item.get("secret").is_none(), "a listed credential carries 'secret'");
        assert!(item.get("value").is_none());
    }
    // The handlers emit no telemetry today, so this sweep is a guard rather
    // than a live check — see `a_key_secret_is_never_written_to_the_management_log`.
    for line in admin.log_lines() {
        assert!(
            !line.contains("secret-from-create") && !line.contains("secret-from-rotation"),
            "a log line carried a credential secret: {line}"
        );
    }
}

#[test]
fn the_credential_list_shows_the_reference_and_its_rotation_metadata_only() {
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let listed = admin.get(&manager, "/admin/v1/credentials");

    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.ids(), vec![CREDENTIAL.to_owned()]);
    let item = &listed.data()[0];
    assert_eq!(
        item.get("rotates_after_days").and_then(wire_json::Value::as_u64),
        Some(90)
    );
    assert_eq!(
        item.field_str("description").ok(),
        Some("the remote provider credential")
    );
}

// -- Credentials: fail closed ------------------------------------------------

#[test]
fn rotating_a_credential_the_configuration_never_declared_is_refused_and_stores_nothing() {
    // Silently creating it would leave the operator believing they had rotated
    // a credential the router still holds under the name they meant to type.
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let before = admin.audit_count();

    let response = admin.post(
        &manager,
        "/admin/v1/credentials/cred-typo:rotate",
        r#"{"secret":"sk-live-0123456789"}"#,
    );

    assert_eq!(response.status, 404, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("not_found"));
    assert!(
        admin.credentials.is_empty(),
        "a refused rotation stored a secret: {:?}",
        admin.credentials.references()
    );
    assert_eq!(admin.audit_count(), before, "a refused rotation was audited");
}

#[test]
fn a_rotation_that_cannot_be_persisted_is_reported_as_a_failure_and_keeps_the_old_secret() {
    // Specification 18.3: security changes fail closed. An operator told the
    // rotation succeeded would decommission the old secret at the provider and
    // take the router offline.
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let path = format!("/admin/v1/credentials/{CREDENTIAL}:rotate");
    assert_eq!(
        admin
            .post_if_match(
                &manager,
                &path,
                r#"{"secret":"the-live-secret"}"#,
                &credential_etag(&admin, &manager, CREDENTIAL),
            )
            .status,
        200
    );
    let audited = admin.audit_count();
    let tag = credential_etag(&admin, &manager, CREDENTIAL);

    admin.credentials.fail_with("the secret facility is unreachable");
    let response = admin.post_if_match(&manager, &path, r#"{"secret":"the-new-secret"}"#, &tag);

    assert_eq!(response.status, 500, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("internal_fault"));
    assert!(!response.body_contains("the-new-secret"), "{}", response.body);
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("the-live-secret"),
        "a failed rotation destroyed the working secret"
    );
    assert_eq!(
        admin.audit_count(),
        audited,
        "a rotation that did not happen was audited as if it had"
    );
}

#[test]
fn a_deployment_with_nowhere_to_put_a_secret_refuses_to_create_one() {
    let admin = Harness::builder().without_credential_sink().build();
    let manager = admin.credential_manager();
    let before = admin.audit_count();

    let response = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"cred-new","secret":"sk-live-0123456789"}"#,
    );

    assert_eq!(response.status, 500, "{}", response.body);
    assert!(admin.credentials.is_empty());
    assert_eq!(admin.audit_count(), before);
}

#[test]
fn an_empty_or_missing_secret_is_refused_by_both_create_and_rotate() {
    // An empty secret would otherwise overwrite a working credential with
    // nothing, which fails on the next upstream request rather than here.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    for body in [r#"{"id":"cred-new","secret":""}"#, r#"{"id":"cred-new"}"#, "{}"] {
        let created = admin.post(&manager, "/admin/v1/credentials", body);
        assert_eq!(created.status, 400, "body={body}: {}", created.body);
        assert_eq!(created.error_code.as_deref(), Some("invalid_request"));
    }

    let path = format!("/admin/v1/credentials/{CREDENTIAL}:rotate");
    let tag = credential_etag(&admin, &manager, CREDENTIAL);
    for body in [r#"{"secret":""}"#, "{}", "not json"] {
        let rotated = admin.post_if_match(&manager, &path, body, &tag);
        assert_eq!(rotated.status, 400, "body={body}: {}", rotated.body);
    }

    assert!(
        admin.credentials.is_empty(),
        "a refused request stored something: {:?}",
        admin.credentials.references()
    );
}

#[test]
fn a_credential_reference_that_is_not_an_identifier_is_refused() {
    // The reference is handed to the platform secret facility, which may well
    // use it as a path component. Nothing but the identifier alphabet reaches
    // it (specification 10: no client-controlled value chooses a file path).
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let traversal = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"..\/..\/etc\/shadow","secret":"sk-live"}"#,
    );
    assert_eq!(traversal.status, 400, "{}", traversal.body);
    assert_eq!(traversal.error_code.as_deref(), Some("invalid_request"));

    let spaced = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"cred new","secret":"sk-live"}"#,
    );
    assert_eq!(spaced.status, 400, "{}", spaced.body);

    // On the rotation path the same input is a 404: an identifier that cannot
    // exist names nothing, and saying more would describe the parser.
    let rotated = admin.post(
        &manager,
        "/admin/v1/credentials/cred%20new:rotate",
        r#"{"secret":"sk-live"}"#,
    );
    assert_eq!(rotated.status, 404, "{}", rotated.body);

    assert!(
        admin.credentials.is_empty(),
        "a refused reference reached the sink: {:?}",
        admin.credentials.references()
    );
}

#[test]
fn an_unrecognised_credential_action_is_not_found() {
    let admin = Harness::new();
    let manager = admin.credential_manager();

    for path in [
        format!("/admin/v1/credentials/{CREDENTIAL}:delete"),
        format!("/admin/v1/credentials/{CREDENTIAL}"),
        format!("/admin/v1/credentials/{CREDENTIAL}:reveal"),
    ] {
        let response = admin.post(&manager, &path, r#"{"secret":"sk-live"}"#);
        assert_eq!(response.status, 404, "path={path}: {}", response.body);
    }

    assert!(admin.credentials.is_empty());
}

// -- Credentials: authorization ----------------------------------------------

#[test]
fn every_credential_endpoint_refuses_a_caller_without_manage_credentials() {
    // Specification 9.3: the credential manager role exists precisely so that
    // no other role touches provider secrets. An operator who could rotate one
    // could point a provider account at a key they control.
    let admin = Harness::new();

    for session in unprivileged_roles(&admin) {
        let listed = admin.get(&session, "/admin/v1/credentials");
        assert_eq!(listed.status, 403, "{:?}: {}", session.roles, listed.body);
        assert_eq!(listed.error_code.as_deref(), Some("forbidden"));
        assert!(!listed.body_contains(CREDENTIAL), "{}", listed.body);

        let created = admin.post(
            &session,
            "/admin/v1/credentials",
            r#"{"id":"cred-new","secret":"sk-live"}"#,
        );
        assert_eq!(created.status, 403, "{:?}: {}", session.roles, created.body);

        let rotated = admin.post(
            &session,
            &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
            r#"{"secret":"sk-live"}"#,
        );
        assert_eq!(rotated.status, 403, "{:?}: {}", session.roles, rotated.body);
    }

    assert!(
        admin.credentials.is_empty(),
        "a refused caller stored a secret: {:?}",
        admin.credentials.references()
    );
}

#[test]
fn an_unauthenticated_caller_cannot_rotate_a_credential() {
    let admin = Harness::new();

    let response = admin
        .request(Method::Post, &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"))
        .json(r#"{"secret":"sk-live"}"#)
        .send();

    assert_eq!(response.status, 401, "{}", response.body);
    assert!(admin.credentials.is_empty());
}

#[test]
fn rotating_a_credential_requires_a_recent_authentication() {
    let admin = Harness::new();
    let manager = admin.credential_manager();
    admin.advance(6 * 60 * 1000);

    let stale = admin.post(
        &manager,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"sk-live"}"#,
    );

    assert_eq!(stale.status, 403, "{}", stale.body);
    assert_eq!(
        stale.error_code.as_deref(),
        Some("reauthentication_required")
    );
    assert!(admin.credentials.is_empty(), "a stale session rotated a secret");
}

#[test]
fn rotating_a_credential_without_a_csrf_token_is_refused() {
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let response = admin
        .request(Method::Post, &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"))
        .as_session(&manager)
        .without_csrf()
        .json(r#"{"secret":"sk-live"}"#)
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    assert!(admin.credentials.is_empty());
}

// -- Credentials: honesty ----------------------------------------------------

#[test]
fn a_rotation_reports_the_overlap_window_it_actually_honours() {
    // Specification 22.2 step 16's bounded dual-accept window. This used to
    // report `overlap_seconds: 0` and a note explaining the absence — which was
    // the honest answer while there was no window. There is one now, and the
    // number an operator plans a cutover around has to be the one the router
    // enforces: both come from `hypellm_core::OVERLAP_HINT_MILLIS`.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let response = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"sk-live"}"#,
        &credential_etag(&admin, &manager, CREDENTIAL),
    );

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response
            .json()
            .get("overlap_seconds")
            .and_then(wire_json::Value::as_u64),
        Some(hypellm_core::OVERLAP_HINT_MILLIS / 1000)
    );
    // The note must point at the probe rather than reassure: the window keeps a
    // premature rotation from becoming an outage, it does not make one correct.
    assert!(response.str_field("note").contains("probe"));
}

#[test]
fn a_created_credential_is_a_secret_with_no_configuration_behind_it() {
    // Documented, not endorsed. `POST /credentials` answers 201 Created for a
    // reference the configuration does not declare: the secret reaches the
    // sink, but the credential appears in no listing and no provider can name
    // it until a policy publish declares it. An operator who creates one and
    // stops there has a stored secret nothing will ever use.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let created = admin.post(
        &manager,
        "/admin/v1/credentials",
        r#"{"id":"cred-new","secret":"sk-live"}"#,
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(admin.credentials.secret_text("cred-new").as_deref(), Some("sk-live"));

    let listed = admin.get(&manager, "/admin/v1/credentials");
    assert_eq!(
        listed.ids(),
        vec![CREDENTIAL.to_owned()],
        "the list is the configuration's declarations, so the new reference is absent"
    );
}

#[test]
fn a_credential_is_a_router_wide_resource_any_credential_manager_may_rotate() {
    // Documented, not endorsed. Credentials carry no tenant: the configuration
    // record has a free-text `scope` field that nothing enforces, so a
    // credential manager in one tenant may overwrite the secret another
    // tenant's provider authenticates with. Reported as a finding; asserted
    // here so that a change in the model is a visible test failure rather than
    // a silent widening.
    let admin = Harness::new();
    let stranger = admin.credential_manager_in(TENANT_B);

    let listed = admin.get(&stranger, "/admin/v1/credentials");
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert!(listed.ids().contains(&CREDENTIAL.to_owned()));

    let rotated = admin.post_if_match(
        &stranger,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"chosen-by-the-other-tenant"}"#,
        &credential_etag(&admin, &stranger, CREDENTIAL),
    );
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("chosen-by-the-other-tenant")
    );
}

// -- What the specification requires and the handlers do not -----------------

#[test]
fn a_rotation_without_a_current_if_match_precondition_is_refused() {
    // Two operators rotating the same credential in the same window both get a
    // 200, and the one whose secret lost the race has no way to know: the
    // provider account they just cut over to is not the one the router holds.
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let path = format!("/admin/v1/credentials/{CREDENTIAL}:rotate");

    let no_precondition = admin.post(&manager, &path, r#"{"secret":"sk-one"}"#);
    assert_eq!(no_precondition.status, 428, "{}", no_precondition.body);
    assert_eq!(
        no_precondition.error_code.as_deref(),
        Some("precondition_required")
    );

    let stale = admin.post_if_match(&manager, &path, r#"{"secret":"sk-two"}"#, STALE_ETAG);
    assert_eq!(stale.status, 412, "{}", stale.body);
    assert_eq!(stale.error_code.as_deref(), Some("precondition_failed"));

    assert!(
        admin.credentials.is_empty(),
        "a mutation with no valid precondition was applied"
    );

    // With a precondition that holds, the rotation goes through.
    let accepted = admin.post_if_match(&manager, &path, r#"{"secret":"sk-three"}"#, ANY_ETAG);
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("sk-three")
    );
}

#[test]
fn creating_a_credential_that_already_exists_is_refused_rather_than_overwriting_it() {
    let admin = Harness::new();
    let manager = admin.credential_manager();
    assert_eq!(
        admin
            .post_if_match(
                &manager,
                &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
                r#"{"secret":"the-live-secret"}"#,
                &credential_etag(&admin, &manager, CREDENTIAL),
            )
            .status,
        200
    );

    let response = admin.post(
        &manager,
        "/admin/v1/credentials",
        &format!(r#"{{"id":"{CREDENTIAL}","secret":"a-typo-away-from-a-rotation"}}"#),
    );

    assert_eq!(response.status, 409, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("conflict"));
    assert_eq!(
        admin.credentials.secret_text(CREDENTIAL).as_deref(),
        Some("the-live-secret"),
        "a create overwrote a live credential"
    );
}

#[test]
fn minting_a_key_is_visible_to_an_auditor_as_a_key_creation() {
    // Specification 15.3's audit screen shows "Actor/action/object/result". The
    // durable chain records the right event; the screen the operator reads does
    // not, so an attacker who mints a key through a stolen session leaves no
    // trace an auditor can see.
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let (key_id, _secret) = create_key(&admin, &oncall, "svc:build");

    let audit = admin.get(&admin.auditor(), "/admin/v1/audit");
    assert_eq!(audit.status, 200, "{}", audit.body);

    let entry = audit
        .data()
        .into_iter()
        .find(|item| item.field_str("object").ok() == Some(key_id.as_str()))
        .expect("the key creation is in the audit view");
    assert_eq!(entry.field_str("action").ok(), Some("key_created"));
    assert_eq!(entry.field_str("actor").ok(), Some(oncall.principal.as_str()));
    assert_eq!(entry.field_str("tenant").ok(), Some(TENANT_A));
}



#[test]
fn revocation_needs_no_precondition_and_is_idempotent() {
    // Specification 15.4 requires If-Match on mutation, and this endpoint
    // deliberately does not take one — see the reasoning on `revoke_key`.
    //
    // The property that makes the exemption safe is asserted here rather than
    // only argued in a comment: revocation is monotonic and idempotent, so
    // there is no lost update for a precondition to prevent, and two
    // responders reaching for the same leaked key during an incident both
    // succeed.
    let admin = Harness::new();
    let manager = admin.break_glass();
    let (key_id, _secret) = admin.issue_api_key(TENANT_A, "svc:leaked");

    let first = admin.delete(&manager, &format!("/admin/v1/keys/{key_id}"));
    assert!(
        first.status == 204 || first.status == 200,
        "a revocation without If-Match was refused: {} {}",
        first.status,
        first.body
    );

    // A second responder, racing the first, must not be turned away.
    let second = admin.delete(&manager, &format!("/admin/v1/keys/{key_id}"));
    assert_ne!(
        second.status, 412,
        "a concurrent revocation was refused with a precondition failure"
    );

    // And the key really is revoked, not merely reported as such.
    let record = admin.state.keys.get(&key_id).expect("the record survives");
    assert!(record.revoked, "the key was reported revoked but is still live");
}

// -- Source-constrained keys (specification 9.2) -----------------------------

#[test]
fn a_key_can_be_restricted_to_source_networks() {
    // Specification 9.2 describes source-constrained keys, and `KeyStore` has
    // enforced them since it existed — `verify` checks the restriction, and one
    // with an unknown peer address fails closed. But `create_key` always passed
    // `SourceRestriction::Any`, so there was no way to create one through the
    // API and specification 22.3's least-privilege replacement could not be
    // built.
    let admin = Harness::new();
    let response = admin
        .request(Method::Post, "/admin/v1/keys")
        .as_session(&admin.break_glass())
        .json(
            r#"{"principal":"svc:restricted","scopes":["inference"],
                "source_networks":["10.0.0.0/8","203.0.113.7/32"]}"#,
        )
        .send();
    assert_eq!(response.status, 201, "{}", response.body);

    let listing = admin
        .request(Method::Get, "/admin/v1/keys")
        .as_session(&admin.break_glass())
        .send();
    let json = listing.json();
    let row = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|k| k.field_str("principal").unwrap_or_default() == "svc:restricted")
        .expect("the key");
    let networks: Vec<&str> = row
        .field_array("source_networks")
        .expect("the restriction is disclosed")
        .iter()
        .filter_map(wire_json::Value::as_str)
        .collect();
    assert_eq!(networks, vec!["10.0.0.0/8", "203.0.113.7/32"]);

    // And it is enforced, not merely recorded.
    let key_id = row.field_str("id").expect("an id");
    let record = admin
        .state
        .keys
        .get(&hypellm_core::ids::KeyId::new(key_id).expect("key id"))
        .expect("the record");
    assert!(record.source.permits(Some("10.1.2.3".parse().unwrap())));
    assert!(record.source.permits(Some("203.0.113.7".parse().unwrap())));
    assert!(!record.source.permits(Some("198.51.100.1".parse().unwrap())));
    assert!(
        !record.source.permits(None),
        "a restricted key with an unknown peer must fail closed"
    );
}

#[test]
fn an_unrestricted_key_is_still_the_default_and_says_so() {
    let admin = Harness::new();
    let response = admin
        .request(Method::Post, "/admin/v1/keys")
        .as_session(&admin.break_glass())
        .json(r#"{"principal":"svc:open","scopes":["inference"]}"#)
        .send();
    assert_eq!(response.status, 201, "{}", response.body);

    let listing = admin
        .request(Method::Get, "/admin/v1/keys")
        .as_session(&admin.break_glass())
        .send();
    let json = listing.json();
    let row = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|k| k.field_str("principal").unwrap_or_default() == "svc:open")
        .expect("the key");
    // Null rather than an empty array: a listing must distinguish "usable from
    // anywhere" from "restricted to nothing".
    assert!(
        matches!(row.get("source_networks"), Some(wire_json::Value::Null)),
        "an unrestricted key must render null: {}",
        listing.body
    );
}

#[test]
fn a_malformed_source_restriction_is_refused_rather_than_widened() {
    // Each of these could plausibly be turned into "unrestricted" by a lenient
    // parser, which is the fail-open shape this codebase has already been bitten
    // by once — an explicitly empty `model=` widening a grant to every alias.
    let admin = Harness::new();
    for body in [
        // Present but empty reads as "restrict to nothing"; silently meaning
        // "do not restrict" is the widening.
        r#"{"principal":"svc:a","scopes":["inference"],"source_networks":[]}"#,
        // A bare address with no prefix: an operator who forgot the prefix on a
        // network should get an error, not a restriction one address wide.
        r#"{"principal":"svc:a","scopes":["inference"],"source_networks":["10.0.0.1"]}"#,
        r#"{"principal":"svc:a","scopes":["inference"],"source_networks":["not-an-address/8"]}"#,
        r#"{"principal":"svc:a","scopes":["inference"],"source_networks":["10.0.0.0/soon"]}"#,
        r#"{"principal":"svc:a","scopes":["inference"],"source_networks":["10.0.0.0/33"]}"#,
    ] {
        let response = admin
            .request(Method::Post, "/admin/v1/keys")
            .as_session(&admin.break_glass())
            .json(body)
            .send();
        assert_eq!(
            response.status, 400,
            "accepted a malformed restriction: {body}\n{}",
            response.body
        );
    }
}

#[test]
fn rotating_a_credential_drains_the_connections_opened_under_it() {
    // Specification 22.2 step 17: "Drain/recycle connections whose
    // authentication is connection-bound." `ConnectionPool::drain_key` existed
    // and was called only from its own unit test — rotation never touched the
    // pool, so a socket authenticated under the old secret could outlive it.
    //
    // Provider authentication in this router is per-request today, so nothing
    // is currently stale. The point of wiring it is that whoever adds a
    // provider with connection-bound authentication will not have to notice
    // this first.
    let admin = Harness::new();
    let manager = admin.credential_manager();
    let response = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"sk-rotated"}"#,
        &credential_etag(&admin, &manager, CREDENTIAL),
    );
    assert_eq!(response.status, 200, "{}", response.body);

    assert_eq!(
        admin.credentials.drained(),
        vec![CREDENTIAL.to_owned()],
        "rotation must ask for the credential's connections to be dropped"
    );
    assert_eq!(
        response.json().opt_field_i64("connections_drained").ok().flatten(),
        Some(2),
        "and must report what happened: {}",
        response.body
    );
}

#[test]
fn a_credential_probe_reports_a_verdict_without_leaking_the_provider_message() {
    // Specification 22.2 step 15: "Validate with a low-cost target-safe probe."
    // The gap this closes is not that a rotation might fail — it is how a failed
    // one presents. An upstream authentication failure reaches the client as
    // `internal_fault` and does not trip a breaker, so a bad rotation shows up
    // as a quiet per-request 500 and is found by users rather than by the
    // operator who caused it. With no dual-accept window (`DI-021`), there is
    // no fallback either.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    // The harness sink reports no probe capability, which must read as "cannot
    // validate", never as "valid".
    let response = admin
        .request(Method::Post, &format!("/admin/v1/credentials/{CREDENTIAL}:probe"))
        .as_session(&manager)
        .send();
    assert_eq!(
        response.status, 400,
        "an unprobeable credential must not report success: {}",
        response.body
    );
    assert!(
        !response.body_contains("\"ok\":true"),
        "a probe that could not run must never report ok: {}",
        response.body
    );
}

#[test]
fn probing_an_undeclared_credential_is_a_not_found() {
    let admin = Harness::new();
    let response = admin
        .request(Method::Post, "/admin/v1/credentials/no-such-credential:probe")
        .as_session(&admin.credential_manager())
        .send();
    assert_eq!(response.status, 404, "{}", response.body);
}

#[test]
fn probing_requires_the_credential_permission() {
    // A probe spends a real provider call with the tenant's credential, so it
    // is the same authority as being able to change what the router spends.
    let admin = Harness::new();
    let response = admin
        .request(Method::Post, &format!("/admin/v1/credentials/{CREDENTIAL}:probe"))
        .as_session(&admin.viewer())
        .send();
    assert_eq!(response.status, 403, "{}", response.body);
}

#[test]
fn a_credential_listing_reports_when_it_was_last_rotated() {
    // `rotates_after_days` was declared, displayed, and enforced by nothing:
    // an operator could set 30 and never learn that a credential was two years
    // old (`DI-011`). The router reports the fact rather than forcing a
    // rotation — cutting off a working credential on a timer would turn a
    // policy into an outage.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    let before = admin.get(&manager, "/admin/v1/credentials");
    let json = before.json();
    let row = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|c| c.field_str("id").unwrap_or_default() == CREDENTIAL)
        .expect("the credential");
    assert!(
        row.opt_field_bool("overdue").ok().flatten() == Some(false),
        "a credential with no recorded rotation must not read as overdue: {}",
        before.body
    );

    // Rotate, and the listing now knows when.
    let rotated = admin.post_if_match(
        &manager,
        &format!("/admin/v1/credentials/{CREDENTIAL}:rotate"),
        r#"{"secret":"sk-rotated-now"}"#,
        &credential_etag(&admin, &manager, CREDENTIAL),
    );
    assert_eq!(rotated.status, 200, "{}", rotated.body);

    let after = admin.get(&manager, "/admin/v1/credentials");
    let json = after.json();
    let row = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|c| c.field_str("id").unwrap_or_default() == CREDENTIAL)
        .expect("the credential");
    assert!(
        row.opt_field_str("last_rotated").ok().flatten().is_some(),
        "the rotation must be visible in the listing: {}",
        after.body
    );
    assert_eq!(
        row.opt_field_bool("overdue").ok().flatten(),
        Some(false),
        "a credential rotated just now is not overdue: {}",
        after.body
    );
}
