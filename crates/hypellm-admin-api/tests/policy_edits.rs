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

// -- A principal's ceiling ---------------------------------------------------

/// The three records the principal-access screen drafts for one principal:
/// a model it may not use, a target that may not serve it, and its queue class.
const CEILING: &str = r#"{"edits":[
    {"op":"set","kind":"grant","id":"pg-dsh-test-alias","fields":
        {"scope":"principal:svc:dsh","model":"test-alias","allow":false}},
    {"op":"set","kind":"binding","id":"pa-dsh-targets","fields":
        {"scope":"principal:svc:dsh","model":"*","deny":["remote:model"]}},
    {"op":"set","kind":"quota","id":"pq-dsh","fields":
        {"scope":"principal:svc:dsh","class":"interactive"}}
]}"#;

#[test]
fn a_principal_ceiling_is_a_draft_its_author_cannot_publish_and_a_second_person_can() {
    use hypellm_core::admission::PriorityClass;
    use hypellm_core::ids::{AliasId, PrincipalId, TenantId};
    use hypellm_core::policy::RoutingContext;

    let admin = Harness::new();
    let principal = PrincipalId::new("svc:dsh").unwrap();
    let tenant = TenantId::new("acme").unwrap();
    let alias = AliasId::new("test-alias").unwrap();
    let ctx = RoutingContext {
        principal: &principal,
        groups: &[],
        tenant: &tenant,
        attempted: &[],
        now_millis: 0,
        key: None,
    };
    let admission = admin.admission.clone().expect("the harness shares admission");
    let authorized = |admin: &Harness| {
        admin.state.config().snapshot.authorizes(&ctx, &alias, hypellm_core::canonical::Operation::Chat)
    };
    assert!(authorized(&admin), "the fixture must start with the tenant-wide allow in force");
    assert_eq!(admission.class_for(&tenant, &principal), PriorityClass::Standard);

    // One person who both edits and approves: the separation is between people,
    // so holding both permissions must not let them publish their own draft.
    let author = admin.session(
        "user:author",
        "acme",
        &[hypellm_core::rbac::Role::PolicyEditor, hypellm_core::rbac::Role::PolicyApprover],
    );
    let created = admin.post(&author, "/admin/v1/policies:edit", CEILING);
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(created.body_contains("\"valid\":true"), "{}", created.body);
    let id = created.str_field("draft_id");
    let path = format!("/admin/v1/policies/{id}:publish");

    let own = admin.post_if_match(&author, &path, "{}", harness::ANY_ETAG);
    assert_eq!(own.status, 403, "{}", own.body);
    assert!(authorized(&admin), "a refused publication must change nothing");

    let approver = admin.policy_approver();
    let published = admin.post_if_match(&approver, &path, "{}", harness::ANY_ETAG);
    assert_eq!(published.status, 200, "{}", published.body);

    // The state, not the status: the alias is no longer authorized for this
    // principal, the denied target is excluded, and the queue class moved
    // without a restart.
    assert!(!authorized(&admin), "the principal deny grant must outrank the tenant allow");
    let other = PrincipalId::new("svc:other").unwrap();
    let other_ctx = RoutingContext { principal: &other, ..ctx };
    assert!(
        admin.state.config().snapshot.authorizes(&other_ctx, &alias, hypellm_core::canonical::Operation::Chat),
        "another principal in the tenant must be unaffected"
    );
    assert_eq!(admission.class_for(&tenant, &principal), PriorityClass::Interactive);
    assert_eq!(admission.class_for(&tenant, &other), PriorityClass::Standard);

    let text = &admin.state.config().canonical;
    assert!(text.contains("deny=remote:model"), "{text}");
}

#[test]
fn an_edit_cannot_widen_a_tenant_grant_or_reach_a_shared_quota() {
    let admin = Harness::with_config(&format!(
        "{}quota id=pq-ci scope=principal:svc:ci concurrency=1\n",
        harness::default_config()
    ));
    let editor = admin.policy_editor();
    for body in [
        // The tenant-wide grant has no id, and a new one may not be tenant-wide.
        r#"{"edits":[{"op":"set","kind":"grant","id":"g","fields":{"scope":"tenant:acme","model":"*","allow":true}}]}"#,
        r#"{"edits":[{"op":"set","kind":"grant","id":"g","fields":{"scope":"global","allow":true}}]}"#,
        // A quota that throttles a whole tenant, the router or a machine.
        r#"{"edits":[{"op":"set","kind":"quota","id":"qt","fields":{"scope":"tenant:acme","concurrency":1000}}]}"#,
        r#"{"edits":[{"op":"set","kind":"quota","id":"qg","fields":{"scope":"global","concurrency":1000}}]}"#,
        // A principal's quota cannot be moved onto the tenant.
        r#"{"edits":[{"op":"set","kind":"quota","id":"pq-ci","fields":{"scope":"tenant:acme"}}]}"#,
        // Byte rates are Global-only, and `operation` qualifies alias quotas.
        r#"{"edits":[{"op":"set","kind":"quota","id":"pq-ci","fields":{"input_bytes_per_second":1}}]}"#,
    ] {
        let refused = admin.post(&editor, "/admin/v1/policies:edit", body);
        assert_eq!(refused.status, 400, "{body}: {}", refused.body);
    }
    assert_eq!(admin.state.drafts.len(), 0, "a refused edit must create no draft");

    // A second quota for the same principal would have replaced the first's
    // limit; it is a draft that does not validate.
    let second = admin.post(
        &editor,
        "/admin/v1/policies:edit",
        r#"{"edits":[{"op":"set","kind":"quota","id":"pq-ci-2","fields":{"scope":"principal:svc:ci","class":"batch"}}]}"#,
    );
    assert_eq!(second.status, 201, "{}", second.body);
    assert!(second.body_contains("\"valid\":false"), "{}", second.body);
    assert!(second.body_contains("duplicate_quota"), "{}", second.body);
}

#[test]
fn a_published_principal_limit_is_enforced_at_once_and_a_rollback_lifts_it() {
    use hypellm_core::admission::Rejection;
    use hypellm_core::ids::{PrincipalId, TargetId, TenantId};

    let admin = Harness::new();
    let admission = admin.admission.clone().expect("the harness shares admission");
    let person = PrincipalId::new("mikiyas.mulugeta").unwrap();
    let tenant = TenantId::new("acme").unwrap();
    let target = TargetId::new("local:model").unwrap();
    let reserve = || admission.reserve(&tenant, &person, &target, 1).map_err(|(r, _)| r);

    // Before: two at once are fine.
    let a = reserve().expect("unlimited");
    let b = reserve().expect("unlimited");
    drop((a, b));

    let author = admin.policy_editor();
    let created = admin.post(
        &author,
        "/admin/v1/policies:edit",
        r#"{"edits":[{"op":"set","kind":"quota","id":"pq-mikiyas","fields":
            {"scope":"principal:mikiyas.mulugeta","concurrency":1,"queued":2,"rps":5,"tpm":60000,"budget":500,"budget_period":"monthly"}}]}"#,
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(created.body_contains("\"valid\":true"), "{}", created.body);
    let path = format!("/admin/v1/policies/{}:publish", created.str_field("draft_id"));

    // Its author may not publish it, and the refusal changes nothing.
    let author_approver = admin.session(
        "user:editor-acme",
        "acme",
        &[hypellm_core::rbac::Role::PolicyEditor, hypellm_core::rbac::Role::PolicyApprover],
    );
    let own = admin.post_if_match(&author_approver, &path, "{}", harness::ANY_ETAG);
    assert_eq!(own.status, 403, "{}", own.body);
    let a = reserve().expect("still unlimited");
    let b = reserve().expect("still unlimited");
    drop((a, b));

    let approver = admin.policy_approver();
    let published = admin.post_if_match(&approver, &path, "{}", &admin.active_config_etag());
    assert_eq!(published.status, 200, "{}", published.body);

    // No restart: the running controller enforces the published limit.
    let scope = admission.configured_principal_scope(&person).expect("the principal has a scope");
    assert_eq!(scope.limits().max_concurrency, 1);
    assert_eq!(scope.limits().budget_minor_units, 500);
    let held = reserve().expect("one is allowed");
    assert_eq!(reserve().err(), Some(Rejection::ConcurrencyExhausted), "the second is refused");
    // Another principal in the tenant is untouched.
    let other = PrincipalId::new("svc:other").unwrap();
    let theirs = admission.reserve(&tenant, &other, &target, 1).expect("someone else is unaffected");
    drop(theirs);

    // Rollback restores the previous policy, live, and the request still in
    // flight is released against the scope that admitted it. A fresh session:
    // the harness's sessions have no identity record, so a publication
    // re-resolves them out of existence.
    let approver = admin.policy_approver();
    let rolled = admin.post_if_match(
        &approver,
        "/admin/v1/policies:rollback",
        r#"{"reason":"testing a principal limit rollback"}"#,
        &admin.active_config_etag(),
    );
    assert_eq!(rolled.status, 200, "{}", rolled.body);
    assert_eq!(scope.limits().max_concurrency, 0, "the limit is lifted without a restart");
    let second = reserve().expect("unlimited again");
    drop((held, second));
    assert_eq!(scope.in_flight(), 0);
    let (acquired, released) = scope.conservation();
    assert_eq!(acquired, released, "every reservation released exactly once across both changes");
}

#[test]
fn a_principal_target_deny_removes_that_slave_and_keeps_the_rest_routable() {
    // The binding the screen writes carries a deny and no preference. It must
    // exclude only what it names: a principal binding that left the tenant's
    // preferences behind would make every target `not_selected_by_any_binding`.
    let admin = Harness::with_config(&harness::default_config().replace(
        "binding id=default scope=tenant:acme model=* prefer=local:model",
        "binding id=default scope=tenant:acme model=* prefer=local:model,remote:model",
    ));
    let editor = admin.policy_editor();
    let simulate = |principal: &str| {
        let body = format!(r#"{{"model":"test-alias","principal":"{principal}"}}"#);
        let answer = admin.post(&editor_sim(&admin), "/admin/v1/policies/active:simulate", &body);
        assert_eq!(answer.status, 200, "{}", answer.body);
        answer.body
    };
    assert!(simulate("svc:dsh").contains("\"target\":\"remote:model\",\"rank\""), "both start as candidates");

    let created = admin.post(
        &editor,
        "/admin/v1/policies:edit",
        r#"{"edits":[{"op":"set","kind":"binding","id":"pa-dsh","fields":
            {"scope":"principal:svc:dsh","model":"*","deny":["remote:model"]}}]}"#,
    );
    assert!(created.body_contains("\"valid\":true"), "{}", created.body);
    let id = created.str_field("draft_id");
    let published = admin.post_if_match(
        &admin.policy_approver(),
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        harness::ANY_ETAG,
    );
    assert_eq!(published.status, 200, "{}", published.body);

    let dsh = simulate("svc:dsh");
    assert!(dsh.contains("\"chosen\":\"local:model\""), "{dsh}");
    assert!(dsh.contains("{\"target\":\"remote:model\",\"reason\":\"denied_by_policy\"}"), "{dsh}");
    let other = simulate("svc:other");
    assert!(other.contains("\"target\":\"remote:model\",\"rank\""), "another principal keeps both: {other}");
}

/// A session that may run simulations.
fn editor_sim(admin: &Harness) -> harness::TestSession {
    admin.session("user:simulator", "acme", &[hypellm_core::rbac::Role::PolicyEditor])
}
