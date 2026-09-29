//! `POST /admin/v1/policies:edit` — the dashboard's record editor.
//!
//! The properties that matter: an edit produces a *draft* and changes nothing
//! live; it cannot reach record kinds that have their own guarded endpoints;
//! and it needs the same permission as writing the policy text by hand.

mod harness;

use harness::Harness;

#[test]
fn an_edit_creates_a_validated_draft_and_leaves_the_active_policy_alone() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let before = admin.state.config().digest;

    // Reorder the alias so the remote target is preferred, and raise the
    // binding's priority: the routing-priority screen's two actions.
    let body = r#"{"edits":[
        {"op":"set","kind":"alias","id":"test-alias","fields":{"targets":["remote:model","local:model"]}},
        {"op":"set","kind":"binding","id":"default","fields":{"priority":5}}
    ]}"#;
    let created = admin.post(&editor, "/admin/v1/policies:edit", body);
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(created.body_contains("\"valid\":true"), "{}", created.body);
    assert!(created.body_contains("\"published\":false"));

    let id = created.str_field("draft_id");
    let draft = admin
        .state
        .drafts
        .get(&id, &editor.tenant)
        .expect("the draft exists");
    assert!(draft.text.contains("targets=remote:model,local:model"), "{}", draft.text);
    assert!(draft.text.contains("priority=5"), "{}", draft.text);
    assert_eq!(
        admin.state.config().digest,
        before,
        "an edit must not change the active configuration before it is published"
    );
}

#[test]
fn an_edit_cannot_reach_kinds_with_their_own_endpoints() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    for body in [
        r#"{"edits":[{"op":"set","kind":"role_binding","id":"x","fields":{"role":"admin"}}]}"#,
        r#"{"edits":[{"op":"set","kind":"local_user","id":"x","fields":{}}]}"#,
        r#"{"edits":[{"op":"set","kind":"settings","fields":{"admin_listen":"0.0.0.0:80"}}]}"#,
        r#"{"edits":[{"op":"set","kind":"host","id":"h","fields":{"arch x":"y"}}]}"#,
    ] {
        let refused = admin.post(&editor, "/admin/v1/policies:edit", body);
        assert_eq!(refused.status, 400, "{body}: {}", refused.body);
    }
    assert_eq!(admin.state.drafts.len(), 0, "a refused edit must create no draft");
}

#[test]
fn an_invalid_result_is_reported_with_its_errors() {
    // A host naming an agent that does not exist is a valid *edit* and an
    // invalid *configuration*; the screen needs the reason, not a 500.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let created = admin.post(
        &editor,
        "/admin/v1/policies:edit",
        r#"{"edits":[{"op":"set","kind":"host","id":"spark3","fields":{"agent":"nowhere","arch":"x86_64"}}]}"#,
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(created.body_contains("\"valid\":false"));
    assert!(created.body_contains("unresolved_reference"), "{}", created.body);
}

#[test]
fn editing_needs_the_policy_edit_permission() {
    let admin = Harness::new();
    let body = r#"{"edits":[{"op":"set","kind":"binding","id":"default","fields":{"priority":1}}]}"#;
    for session in [admin.viewer(), admin.operator()] {
        let refused = admin.post(&session, "/admin/v1/policies:edit", body);
        assert_eq!(refused.status, 403, "{}", refused.body);
    }
    assert_eq!(admin.state.drafts.len(), 0);
}

#[test]
fn the_active_records_omit_local_user_verifiers() {
    let verifier = hypellm_crypto::PasswordVerifier::derive_with(
        "a-password-long-enough",
        hypellm_crypto::scrypt::MIN_LOG_N,
        hypellm_crypto::scrypt::DEFAULT_R,
        hypellm_crypto::scrypt::DEFAULT_P,
    )
    .expect("entropy")
    .encode();
    let admin = Harness::with_config(&format!(
        "{}local_user id=admin principal=user:admin tenant=acme verifier={verifier}\n",
        harness::default_config()
    ));
    let active = admin.get(&admin.policy_editor(), "/admin/v1/policies/active");
    assert_eq!(active.status, 200);
    assert!(active.body_contains("\"records\""));
    assert!(active.body_contains("\"kind\":\"alias\""));
    let records = active.json();
    let listed = records
        .get("records")
        .and_then(wire_json::Value::as_array)
        .expect("records");
    assert!(listed
        .iter()
        .all(|r| r.get("kind").and_then(wire_json::Value::as_str) != Some("local_user")));
    // The verifier is still in the canonical text an editor may read; what
    // matters is that the records view, which forms consume, does not add a
    // second copy that a screen might render.
    let records_text = listed
        .iter()
        .map(|r| format!("{r:?}"))
        .collect::<String>();
    assert!(!records_text.contains(&verifier));
}
