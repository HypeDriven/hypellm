//! The target endpoints: `GET /admin/v1/targets` and `PATCH /admin/v1/targets/{id}`.
//!
//! Specification 16 lists these as "List/create targets; secrets referenced,
//! never returned" and "ETag-guarded update, drain, maintenance, quarantine".
//! Specification 13 makes drain, maintenance and quarantine *operational*
//! actions — an operator takes a target out of rotation now, without waiting
//! for a policy draft to be reviewed and published — and specification 15.4
//! requires `If-Match` on every mutation.
//!
//! Two questions run through the whole suite, because the handler this replaces
//! answered the first one honestly and the second one not at all:
//!
//! 1. Who may act? Every refusal is asserted together with the live state, so a
//!    handler that refuses *and then acts anyway* fails here.
//! 2. Did the action happen? A drain that returns `{"state":"draining"}` while
//!    traffic keeps arriving is worse than an error: the operator believes the
//!    target is out of rotation. Every state change is therefore checked twice —
//!    once against [`HealthRegistry::admin_state`], and once by routing a real
//!    request through the live policy snapshot and demanding the exclusion.
//!    Reading the response back is not evidence; the router's opinion is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod harness;

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, Message, Operation, RequestLimits, Role as ChatRole,
    RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::decision::ExclusionReason;
use hypellm_core::ids::{AliasId, PrincipalId, RequestId, TargetId, TenantId};
use hypellm_core::policy::{RouteOutcome, RoutingContext};
use hypellm_core::rbac::{Permission, Role};
use hypellm_core::target::AdminState;
use hypellm_core::time::{Clock, Deadline};
use harness::{
    ALIAS, ANY_ETAG, Harness, LOCAL_TARGET, STALE_ETAG, TENANT_A, TENANT_B, TestSession,
};
use wire_http1::Method;
use wire_json::Value;

/// The path of the target every test operates on.
const LOCAL_PATH: &str = "/admin/v1/targets/local:model";
/// A target identifier that is well formed but names nothing.
const ABSENT_PATH: &str = "/admin/v1/targets/local:does-not-exist";

// -- Helpers ----------------------------------------------------------------

fn target_id(id: &str) -> TargetId {
    TargetId::new(id).expect("a valid target identifier")
}

/// The live administrative override the router would read.
fn override_state(admin: &Harness, id: &str) -> Option<AdminState> {
    admin.state.health.admin_state(&target_id(id))
}

/// One element of the target listing, by identifier.
fn listed(admin: &Harness, session: &TestSession, id: &str) -> Value {
    admin
        .get(session, "/admin/v1/targets")
        .data()
        .into_iter()
        .find(|item| item.opt_field_str("id").ok().flatten() == Some(id))
        .unwrap_or_else(|| panic!("'{id}' is not in the listing"))
}

/// A plain chat request, the shape the data plane would route.
fn chat_request(tenant: &TenantId, principal: &PrincipalId) -> CanonicalRequest {
    CanonicalRequest {
        request_id: RequestId::from_u128(1),
        tenant: tenant.clone(),
        principal: principal.clone(),
        protocol: ClientProtocol::Native,
        operation: Operation::Chat,
        requested_model: AliasId::new(ALIAS).expect("a valid alias"),
        messages: vec![Message::text(ChatRole::User, "route me")],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        limits: RequestLimits {
            max_output_tokens: None,
            deadline: Deadline::at(u64::MAX),
            max_cost_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: RoutingHints::default(),
    }
}

/// Route a request for a tenant against the *live* health registry.
///
/// This is the only honest test of "out of rotation": the admin override is
/// applied by [`hypellm_core::policy::LiveState::admin_override`] during
/// eligibility filtering, so a handler that reports a drain it did not perform
/// shows up here as a target that is still a candidate.
fn route_for(admin: &Harness, tenant: &str, principal: &str) -> RouteOutcome {
    let tenant = TenantId::new(tenant).expect("a valid tenant");
    let principal = PrincipalId::new(principal).expect("a valid principal");
    let request = chat_request(&tenant, &principal);
    let attempted = Vec::new();
    let groups = Vec::new();
    let context = RoutingContext {
        principal: &principal,
        groups: &groups,
        tenant: &tenant,
        attempted: &attempted,
    };
    admin
        .config()
        .snapshot
        .route(&context, &request, &*admin.state.health)
}

fn is_candidate(outcome: &RouteOutcome, id: &str) -> bool {
    outcome.candidates.iter().any(|c| c.target.as_str() == id)
}

fn exclusion_for(outcome: &RouteOutcome, id: &str) -> Option<ExclusionReason> {
    outcome
        .exclusions
        .iter()
        .find(|e| e.target.as_str() == id)
        .map(|e| e.reason)
}

/// Assert that the local target is out of rotation for exactly one reason.
fn assert_excluded(admin: &Harness, reason: ExclusionReason) {
    let outcome = route_for(admin, TENANT_A, "user:client");
    assert!(
        !is_candidate(&outcome, LOCAL_TARGET),
        "the target is still an eligible candidate: {:?}",
        outcome
            .candidates
            .iter()
            .map(|c| c.target.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        exclusion_for(&outcome, LOCAL_TARGET),
        Some(reason),
        "the target was excluded, but not for the operator's reason"
    );
}

fn assert_in_rotation(admin: &Harness) {
    let outcome = route_for(admin, TENANT_A, "user:client");
    assert!(
        is_candidate(&outcome, LOCAL_TARGET),
        "the target should be routable; it was excluded as {:?}",
        exclusion_for(&outcome, LOCAL_TARGET)
    );
}

/// Quarantine the local target as part of a test's setup, insisting it worked.
fn quarantine(admin: &Harness, session: &TestSession, reason: &str) {
    let response = admin.patch(
        session,
        LOCAL_PATH,
        &format!(r#"{{"state":"quarantined","reason":"{reason}"}}"#),
        ANY_ETAG,
    );
    assert_eq!(response.status, 200, "setup failed: {}", response.body);
}

/// The ETag `PATCH /targets/{id}` compares `If-Match` against, as a client
/// reads it: the `etag` field the listing discloses.
fn listed_etag(admin: &Harness, session: &TestSession, id: &str) -> String {
    listed(admin, session, id)
        .field_str("etag")
        .expect("the listing must disclose each target's ETag")
        .to_owned()
}

// -- Listing ----------------------------------------------------------------

#[test]
fn a_viewer_can_list_the_fleet_and_read_each_targets_state() {
    // Specification 9.3: a viewer reads "sanitized health, configuration
    // summaries". Listing is the one target operation a viewer may perform.
    let admin = Harness::new();
    let response = admin.get(&admin.viewer(), "/admin/v1/targets");

    assert_eq!(response.status, 200);
    assert_eq!(response.ids(), vec!["local:model", "remote:model"]);

    let target = listed(&admin, &admin.viewer(), LOCAL_TARGET);
    assert_eq!(target.field_str("provider").unwrap(), "local");
    assert_eq!(target.field_str("model").unwrap(), "test-model");
    assert_eq!(target.field_str("state").unwrap(), "enabled");
    assert_eq!(target.opt_field_bool("quarantined").unwrap(), Some(false));
    assert_eq!(target.opt_field_bool("local").unwrap(), Some(true));

    let capabilities = target.opt_field_object("capabilities").unwrap().unwrap();
    assert_eq!(
        capabilities.get("tools").and_then(Value::as_bool),
        Some(true)
    );
    let operations = capabilities
        .get("operations")
        .and_then(Value::as_array)
        .unwrap();
    let operations: Vec<&str> = operations.iter().filter_map(Value::as_str).collect();
    assert_eq!(operations, vec!["chat", "embeddings"]);
}

#[test]
fn the_target_listing_carries_no_credential_key_or_session_material() {
    // Specification 16: "secrets referenced, never returned". The target
    // rendering has no credential field at all, which is stronger than
    // redacting one — but the assertion is on the bytes, because a leak that
    // matters is a leak in whatever field it hides in.
    let admin = Harness::new();
    let viewer = admin.viewer();
    let (_, key_secret) = admin.issue_api_key(TENANT_A, "user:viewer-acme");

    let response = admin.get(&viewer, "/admin/v1/targets");

    assert!(response.is_ok());
    assert!(
        !response.body_contains(&key_secret),
        "an API key secret appeared in the target listing"
    );
    assert!(
        !response.body_contains(&viewer.token),
        "the session token was echoed into the target listing"
    );
    assert!(
        !response.body_contains(&viewer.csrf),
        "the CSRF token was echoed into the target listing"
    );
    assert!(
        !response.body_contains("credential"),
        "the target listing named a credential: {}",
        response.body
    );
}

#[test]
fn an_unauthenticated_request_cannot_learn_which_targets_exist() {
    let admin = Harness::new();
    let response = admin.anonymous(Method::Get, "/admin/v1/targets");

    assert_eq!(response.status, 401);
    assert_eq!(response.error_code.as_deref(), Some("unauthenticated"));
    assert!(
        !response.body_contains(LOCAL_TARGET),
        "an anonymous caller was told a target's identifier"
    );
}

#[test]
fn a_session_holding_no_permission_cannot_list_targets() {
    // The fleet's topology — which providers exist, which models they serve,
    // what each costs — is not public to any authenticated principal.
    let admin = Harness::new();
    let response = admin.get(&admin.unprivileged(), "/admin/v1/targets");

    assert_eq!(response.status, 403);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains(LOCAL_TARGET));
}

#[test]
fn the_listing_pages_without_repeating_or_skipping_a_target() {
    // A bounded response is a specification 3.2 requirement, and a cursor that
    // repeats an item would make an operator's inventory wrong.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let first = admin.get_query(&viewer, "/admin/v1/targets", "limit=1");
    assert_eq!(first.ids(), vec!["local:model"]);
    assert_eq!(
        first.json().opt_field_bool("has_more").unwrap(),
        Some(true),
        "a truncated page must say so"
    );
    let cursor = first.json().field_str("next_cursor").unwrap().to_owned();

    let second = admin.get_query(
        &viewer,
        "/admin/v1/targets",
        &format!("limit=1&after={cursor}"),
    );
    assert_eq!(second.ids(), vec!["remote:model"]);
    assert_eq!(
        second.json().opt_field_bool("has_more").unwrap(),
        Some(false)
    );
}

#[test]
fn the_listing_shows_only_targets_the_callers_tenant_can_reach() {
    // Appendix B: "Management visibility never exceeds the caller's tenant and
    // permissions", and `GET /v1/models` on the data plane already honours this
    // through `PolicySnapshot::visible_aliases`. Here tenant B is authorized for
    // no alias at all, so no target is reachable by anyone in it — yet the
    // handler renders `config.snapshot.targets` unfiltered, disclosing the
    // provider, model name and cost class of every target in the deployment.
    let config = harness::default_config().replace(
        "grant scope=tenant:globex model=* allow=true",
        "grant scope=tenant:globex model=* allow=false",
    );
    let admin = Harness::with_config(&config);

    let permitted = admin.get(&admin.viewer_in(TENANT_A), "/admin/v1/targets");
    assert_eq!(permitted.ids(), vec!["local:model", "remote:model"]);

    let denied = admin.get(&admin.viewer_in(TENANT_B), "/admin/v1/targets");
    assert_eq!(denied.status, 200, "{}", denied.body);
    assert!(
        denied.ids().is_empty(),
        "a tenant authorized for no alias was shown the fleet: {:?}",
        denied.ids()
    );
    // Not merely absent from `data`: nothing about the fleet may appear at all.
    for leak in ["local:model", "remote:model", "test-model", "remote-test"] {
        assert!(
            !denied.body_contains(leak),
            "the listing disclosed '{leak}' to a tenant that cannot reach it: {}",
            denied.body
        );
    }
}

// -- Preconditions ----------------------------------------------------------

#[test]
fn an_update_without_an_if_match_is_refused_and_changes_nothing() {
    // Specification 15.4: "ETag/If-Match on mutation". Without it two operators
    // reading the same dashboard can overwrite each other silently.
    let admin = Harness::new();
    let response =
        admin.patch_without_if_match(&admin.operator(), LOCAL_PATH, r#"{"state":"draining"}"#);

    assert_eq!(response.status, 428);
    assert_eq!(
        response.error_code.as_deref(),
        Some("precondition_required")
    );
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        None,
        "a refused update still changed the target's state"
    );
    assert_in_rotation(&admin);
}

#[test]
fn a_stale_if_match_is_refused_with_412_and_changes_nothing() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"draining"}"#,
        STALE_ETAG,
    );

    assert_eq!(response.status, 412);
    assert_eq!(response.error_code.as_deref(), Some("precondition_failed"));
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        None,
        "an update refused as stale still changed the target's state"
    );
    assert_in_rotation(&admin);
}

#[test]
fn a_read_of_a_target_discloses_the_etag_its_update_will_demand() {
    // Without this a client can satisfy `If-Match` only by reimplementing the
    // server's canonical-JSON digest, or by sending `*` — which defeats the
    // point of the precondition. The tag has to be readable *and* be the one
    // the update actually demands, so both halves are asserted.
    let admin = Harness::new();
    let operator = admin.operator();

    let disclosed = listed(&admin, &operator, LOCAL_TARGET)
        .opt_field_str("etag")
        .unwrap()
        .map(str::to_owned)
        .expect("a read must disclose the target's ETag");
    assert!(disclosed.starts_with('"') && disclosed.ends_with('"'), "{disclosed}");

    // A tag from the same read, for a different target, must not satisfy it.
    let other = listed_etag(&admin, &operator, "remote:model");
    assert_ne!(disclosed, other, "one tag cannot stand for the whole fleet");
    let confused = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, &other);
    assert_eq!(confused.status, 412, "{}", confused.body);
    assert_eq!(override_state(&admin, LOCAL_TARGET), None);

    let accepted = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, &disclosed);
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Draining),
        "the update the precondition admitted did not take effect"
    );
}

#[test]
fn a_second_operator_working_from_a_stale_read_is_refused() {
    // The lost update specification 15.4 exists to prevent: two operators read
    // the same listing, the first drains the target, the second — who has not
    // seen that — puts it back into service. The second request carries a
    // precondition that is genuinely stale and must fail with 412.
    //
    // It does not, because `render_target` reads `Target::admin_state` from the
    // immutable policy snapshot and never `HealthRegistry::admin_state`. The
    // drain leaves the representation, and therefore the tag, unchanged.
    let admin = Harness::new();
    let first = admin.operator();
    let second = admin.session("user:operator-two", TENANT_A, &[Role::Operator]);

    let shared_etag = listed_etag(&admin, &first, LOCAL_TARGET);

    let drain = admin.patch(&first, LOCAL_PATH, r#"{"state":"draining"}"#, &shared_etag);
    assert_eq!(drain.status, 200);

    let clobber = admin.patch(&second, LOCAL_PATH, r#"{"state":"enabled"}"#, &shared_etag);
    assert_eq!(
        clobber.status, 412,
        "the second operator's read was stale and their write must be refused"
    );
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Draining),
        "a target an operator drained was silently returned to service"
    );
}

#[test]
fn a_precondition_survives_traffic_flowing_through_the_target() {
    // `render_target` folds `in_flight`, `total_requests` and `total_failures`
    // into the representation the ETag digests. Nothing about the target's
    // administrative state changed here — only that it served a request — yet
    // the operator's precondition is now stale, so a drain issued during the
    // load spike it is meant to relieve is refused.
    let admin = Harness::new();
    let operator = admin.operator();
    let etag = listed_etag(&admin, &operator, LOCAL_TARGET);

    admin
        .state
        .health
        .entry(&target_id(LOCAL_TARGET), Operation::Chat)
        .record_success(5, 10, admin.clock.now_millis());

    // The traffic really is visible in the listing — otherwise this would prove
    // nothing about a tag that ignores it.
    let listing = listed(&admin, &operator, LOCAL_TARGET);
    assert_eq!(listing.field_i64("total_requests").unwrap(), 1);
    assert_eq!(
        listing.field_str("etag").unwrap(),
        etag,
        "serving a request is not an edit and must not move the tag"
    );

    let response = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, &etag);
    assert_eq!(
        response.status, 200,
        "a request having flowed through the target is not a conflicting edit"
    );
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Draining)
    );
}

#[test]
fn the_etag_an_update_returns_can_be_used_for_the_following_update() {
    // RFC 9110: the ETag of a 200 response to a PATCH is the tag of the
    // resource's new representation, so a read-modify-write loop can continue
    // without re-reading. Here the handler returns the digest of its own reply
    // body — `{id, state, requested, quarantined, persists_across_restart}` —
    // which matches nothing, so the very next update is refused as stale.
    let admin = Harness::new();
    let operator = admin.operator();

    let first = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG);
    assert_eq!(first.status, 200);
    let handed_back = first.expect_etag();
    assert_eq!(
        handed_back,
        listed_etag(&admin, &operator, LOCAL_TARGET),
        "the tag on the reply must be the target's new representation, \
         not the digest of the reply body"
    );

    let second = admin.patch(&operator, LOCAL_PATH, r#"{"state":"enabled"}"#, &handed_back);
    assert_eq!(
        second.status, 200,
        "the tag the server just handed out was rejected by the server"
    );
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        None,
        "the second update in the loop did not take effect"
    );
    // And the tag it moved on to is not the one just spent.
    assert_ne!(second.expect_etag(), handed_back);
}

#[test]
fn a_request_without_a_csrf_token_cannot_drain_a_target() {
    // Specification 15.3: the management API is cookie-authenticated, so a
    // cross-site form post would otherwise be able to drain the fleet.
    let admin = Harness::new();
    let response = admin
        .request(Method::Patch, LOCAL_PATH)
        .as_session(&admin.operator())
        .without_csrf()
        .json(r#"{"state":"draining"}"#)
        .if_match(ANY_ETAG)
        .send();

    assert_eq!(response.status, 403);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    assert_eq!(override_state(&admin, LOCAL_TARGET), None);
    assert_in_rotation(&admin);
}

// -- Authorization ----------------------------------------------------------

#[test]
fn only_a_role_holding_operate_targets_can_change_a_target_state() {
    // The whole permission matrix, end to end, so that a role gaining or losing
    // a permission cannot quietly change who can take the fleet out of service.
    for role in Role::all() {
        let admin = Harness::new();
        let session = admin.session("user:matrix", TENANT_A, &[*role]);
        let response = admin.patch(&session, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG);

        if role.grants(Permission::OperateTargets) {
            assert_eq!(
                response.status, 200,
                "{role} must be able to drain a target"
            );
            assert_eq!(
                override_state(&admin, LOCAL_TARGET),
                Some(AdminState::Draining)
            );
        } else {
            assert_eq!(
                response.status, 403,
                "{role} must not be able to drain a target"
            );
            assert_eq!(response.error_code.as_deref(), Some("forbidden"));
            assert_eq!(
                override_state(&admin, LOCAL_TARGET),
                None,
                "{role} was refused but the target changed anyway"
            );
        }
    }
}

#[test]
fn only_a_role_holding_quarantine_targets_can_quarantine_one() {
    // Specification 13 makes quarantine the stronger action: it survives the
    // breaker's automated recovery, so it is gated separately from drain.
    for role in Role::all() {
        let admin = Harness::new();
        let session = admin.session("user:matrix", TENANT_A, &[*role]);
        let response = admin.patch(
            &session,
            LOCAL_PATH,
            r#"{"state":"quarantined","reason":"suspected prompt exfiltration"}"#,
            ANY_ETAG,
        );

        if role.grants(Permission::QuarantineTargets) {
            assert_eq!(response.status, 200, "{role} must be able to quarantine");
            assert!(admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)));
        } else {
            assert_eq!(
                response.status, 403,
                "{role} must not be able to quarantine"
            );
            assert!(
                !admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)),
                "{role} was refused but the target was quarantined anyway"
            );
        }
    }
}

#[test]
fn an_unauthorized_caller_cannot_learn_whether_a_target_exists() {
    // Authorization is checked before the identifier is resolved, so probing
    // `PATCH /targets/{guess}` cannot enumerate the fleet: both answers are the
    // same refusal.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let real = admin.patch(&viewer, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG);
    let fake = admin.patch(&viewer, ABSENT_PATH, r#"{"state":"draining"}"#, ANY_ETAG);

    assert_eq!(real.status, 403);
    assert_eq!(fake.status, 403);
    assert_eq!(real.error_code, fake.error_code);
    assert_eq!(
        real.body.replace(&real.request_id, ""),
        fake.body.replace(&fake.request_id, ""),
        "the refusals differ, which distinguishes a real target from an invented one"
    );
}

#[test]
fn an_unknown_target_is_not_found() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        ABSENT_PATH,
        r#"{"state":"draining"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 404);
    assert_eq!(response.error_code.as_deref(), Some("not_found"));
}

#[test]
fn a_malformed_target_identifier_is_refused_rather_than_accepted() {
    // A target identifier is never a path, a host, or anything the router will
    // dereference (specification 10), but a handler that accepted arbitrary
    // bytes here would still be a parser bug waiting to happen.
    let admin = Harness::new();
    let operator = admin.operator();

    for id in ["..%2Fetc%2Fpasswd", "local model", "", "local:model\u{7f}"] {
        let path = format!("/admin/v1/targets/{id}");
        let response = admin.patch(&operator, &path, r#"{"state":"draining"}"#, ANY_ETAG);
        assert!(
            response.status == 404 || response.status == 400,
            "'{id}' produced {}: {}",
            response.status,
            response.body
        );
        assert!(response.error_code.is_some());
    }
    assert_eq!(override_state(&admin, LOCAL_TARGET), None);
}

// -- The state actually changing --------------------------------------------

#[test]
fn draining_a_target_takes_it_out_of_rotation() {
    // The defect this endpoint shipped with: the response said `draining` while
    // the configured state lived in the immutable snapshot and traffic kept
    // arriving. Three independent witnesses, because the response alone lied.
    let admin = Harness::new();
    assert_in_rotation(&admin);

    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"draining","reason":"node reboot"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "draining");
    assert_eq!(response.str_field("requested"), "draining");
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Draining)
    );
    assert_excluded(&admin, ExclusionReason::TargetDraining);
}

#[test]
fn putting_a_target_into_maintenance_takes_it_out_of_rotation() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"maintenance"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "maintenance");
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Maintenance)
    );
    assert_excluded(&admin, ExclusionReason::TargetMaintenance);
}

#[test]
fn disabling_a_target_takes_it_out_of_rotation() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"disabled"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "disabled");
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Disabled)
    );
    assert_excluded(&admin, ExclusionReason::TargetDisabled);
}

#[test]
fn re_enabling_a_drained_target_returns_it_to_rotation() {
    // An operator who cannot undo a drain will not drain, so the reverse
    // direction matters as much as the forward one.
    let admin = Harness::new();
    let operator = admin.operator();

    assert_eq!(
        admin
            .patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG)
            .status,
        200
    );
    assert_excluded(&admin, ExclusionReason::TargetDraining);

    let response = admin.patch(&operator, LOCAL_PATH, r#"{"state":"enabled"}"#, ANY_ETAG);

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "enabled");
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        None,
        "an override of 'enabled' must be removed, not stored"
    );
    assert_in_rotation(&admin);
}

#[test]
fn an_update_says_plainly_that_the_override_will_not_survive_a_restart() {
    // The override lives in memory. An operator who drains a target before a
    // rolling restart needs to know the drain goes away with the process.
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"draining"}"#,
        ANY_ETAG,
    );

    assert_eq!(
        response
            .json()
            .opt_field_bool("persists_across_restart")
            .unwrap(),
        Some(false)
    );
}

#[test]
fn the_listing_reports_the_state_now_in_force() {
    // `render_target` reads `Target::admin_state` from the policy snapshot and
    // never the operator override, so the dashboard an operator checks after
    // draining a target shows `enabled` — the exact reassurance the no-op
    // handler used to give. Only `quarantined` is read from live state.
    let admin = Harness::new();
    let operator = admin.operator();

    let update = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG);
    assert_eq!(update.str_field("state"), "draining");

    let target = listed(&admin, &operator, LOCAL_TARGET);
    assert_eq!(
        target.field_str("state").unwrap(),
        "draining",
        "the listing contradicts the update that was just accepted"
    );

    // And back again, so the listing is tracking the override rather than
    // having been changed to report `draining` from somewhere else.
    assert_eq!(
        admin
            .patch(&operator, LOCAL_PATH, r#"{"state":"enabled"}"#, ANY_ETAG)
            .status,
        200
    );
    assert_eq!(
        listed(&admin, &operator, LOCAL_TARGET)
            .field_str("state")
            .unwrap(),
        "enabled"
    );
}

// -- Quarantine -------------------------------------------------------------

#[test]
fn quarantining_a_target_requires_a_reason() {
    // Specification 13 and 9.3: the strong actions carry a mandatory reason, so
    // that the audit record explains itself later.
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"quarantined"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.error_code.as_deref(), Some("invalid_request"));
    assert!(
        !admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)),
        "a quarantine refused for want of a reason was applied anyway"
    );
    assert_in_rotation(&admin);
}

#[test]
fn a_blank_reason_does_not_count_as_a_reason() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"quarantined","reason":"   "}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 400);
    assert!(!admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)));
}

#[test]
fn quarantining_a_target_takes_it_out_of_rotation_and_says_so() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"quarantined","reason":"leaking another tenant's completions"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "quarantined");
    assert_eq!(
        response.json().opt_field_bool("quarantined").unwrap(),
        Some(true)
    );
    assert!(admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)));
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Quarantined)
    );
    assert_excluded(&admin, ExclusionReason::TargetQuarantined);
}

#[test]
fn a_quarantine_outlives_a_healthy_breaker_but_not_its_own_duration() {
    // Specification 13: "manual quarantine overrides automated recovery". It is
    // still bounded, because an unbounded one is a fleet that silently shrinks.
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"quarantined","reason":"under investigation","duration_seconds":60}"#,
        ANY_ETAG,
    );
    assert_eq!(response.status, 200);

    // Perfect health does not lift it.
    let entry = admin
        .state
        .health
        .entry(&target_id(LOCAL_TARGET), Operation::Chat);
    for _ in 0..50 {
        entry.record_success(5, 10, admin.clock.now_millis());
    }
    assert_excluded(&admin, ExclusionReason::TargetQuarantined);

    admin.advance(61_000);
    assert!(!admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)));
    assert_in_rotation(&admin);
}

#[test]
fn lifting_a_quarantine_returns_the_target_to_rotation() {
    let admin = Harness::new();
    let operator = admin.operator();

    quarantine(&admin, &operator, "suspected compromise");
    assert_excluded(&admin, ExclusionReason::TargetQuarantined);

    let response = admin.patch(&operator, LOCAL_PATH, r#"{"state":"enabled"}"#, ANY_ETAG);

    assert_eq!(response.status, 200);
    assert_eq!(
        response.json().opt_field_bool("quarantined").unwrap(),
        Some(false)
    );
    assert!(!admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)));
    assert_in_rotation(&admin);
}

#[test]
fn a_role_that_cannot_quarantine_cannot_lift_one_either() {
    // Lifting is the dangerous half: it puts a target an operator distrusted
    // back in front of traffic, so it is gated by the same permission.
    let admin = Harness::new();
    quarantine(&admin, &admin.operator(), "suspected compromise");

    for role in Role::all() {
        if role.grants(Permission::QuarantineTargets) {
            continue;
        }
        let session = admin.session("user:lifter", TENANT_A, &[*role]);
        let response = admin.patch(&session, LOCAL_PATH, r#"{"state":"enabled"}"#, ANY_ETAG);

        assert_eq!(response.status, 403, "{role} lifted a quarantine");
        assert!(
            admin.state.health.is_quarantined(&target_id(LOCAL_TARGET)),
            "{role} was refused but the quarantine was lifted anyway"
        );
    }
    assert_excluded(&admin, ExclusionReason::TargetQuarantined);
}

#[test]
fn draining_a_quarantined_target_lifts_the_quarantine_and_reports_it() {
    // Requesting a weaker state for a quarantined target releases the
    // quarantine — deliberately, and behind `QuarantineTargets`. What matters
    // is that the operator is told: the reply reports the state now in force
    // and `quarantined: false`, so nobody believes the target is still fenced
    // off after asking merely to drain it.
    let admin = Harness::new();
    let operator = admin.operator();

    quarantine(&admin, &operator, "suspected compromise");

    let response = admin.patch(&operator, LOCAL_PATH, r#"{"state":"draining"}"#, ANY_ETAG);

    assert_eq!(response.status, 200);
    assert_eq!(response.str_field("state"), "draining");
    assert_eq!(
        response.json().opt_field_bool("quarantined").unwrap(),
        Some(false),
        "the reply must not let an operator think the quarantine survived"
    );
    assert_excluded(&admin, ExclusionReason::TargetDraining);
}

// -- Malformed updates ------------------------------------------------------

#[test]
fn an_unknown_state_is_refused_and_changes_nothing() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"paused"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.error_code.as_deref(), Some("invalid_request"));
    assert_eq!(override_state(&admin, LOCAL_TARGET), None);
    assert_in_rotation(&admin);
}

#[test]
fn an_update_naming_no_state_is_refused() {
    let admin = Harness::new();
    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"reason":"just because"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 400);
    assert_eq!(override_state(&admin, LOCAL_TARGET), None);
}

#[test]
fn a_body_that_is_not_json_is_refused_without_panicking() {
    // Specification 18.2: no panics on request input, on either plane.
    let admin = Harness::new();
    let operator = admin.operator();

    for body in [
        &b"not json at all"[..],
        b"{\"state\":",
        b"[]",
        b"{\"state\":123}",
        &[0xff, 0xfe, 0x00],
    ] {
        let response = admin
            .request(Method::Patch, LOCAL_PATH)
            .as_session(&operator)
            .body(body)
            .if_match(ANY_ETAG)
            .send();
        assert!(
            response.status >= 400 && response.status < 500,
            "body {body:?} produced {}",
            response.status
        );
        assert_eq!(override_state(&admin, LOCAL_TARGET), None);
    }
}

// -- Audit ------------------------------------------------------------------

#[test]
fn draining_a_target_leaves_a_record_in_the_durable_chain() {
    // Specification 13: operational actions are audited. The chain is the
    // record of record, and it must grow by exactly one per accepted action.
    let admin = Harness::new();
    let before = admin.audit_count();

    let response = admin.patch(
        &admin.operator(),
        LOCAL_PATH,
        r#"{"state":"draining","reason":"rolling restart"}"#,
        ANY_ETAG,
    );

    assert_eq!(response.status, 200);
    assert_eq!(admin.audit_count(), before + 1);
}

#[test]
fn a_refused_update_leaves_no_audit_record() {
    // An audit trail that records attempts as actions is as misleading as one
    // that records nothing.
    let admin = Harness::new();
    let before = admin.audit_count();

    let refusals = [
        admin.patch(
            &admin.viewer(),
            LOCAL_PATH,
            r#"{"state":"draining"}"#,
            ANY_ETAG,
        ),
        admin.patch(
            &admin.operator(),
            LOCAL_PATH,
            r#"{"state":"draining"}"#,
            STALE_ETAG,
        ),
        admin.patch(
            &admin.operator(),
            LOCAL_PATH,
            r#"{"state":"paused"}"#,
            ANY_ETAG,
        ),
        admin.patch(
            &admin.operator(),
            LOCAL_PATH,
            r#"{"state":"quarantined"}"#,
            ANY_ETAG,
        ),
    ];
    for refusal in &refusals {
        assert!(!refusal.is_ok(), "this update should have been refused");
    }

    assert_eq!(
        admin.audit_count(),
        before,
        "a refusal was audited as an action"
    );
}

#[test]
fn an_auditor_can_see_that_a_target_was_quarantined_and_why() {
    // The durable chain gets the real event, but the view the auditor reads is
    // fed by `AuditIndex::record`, which throws the event away and synthesizes
    // a placeholder: action `settings_changed`, timestamp 0, no object, and —
    // fatally — no tenant, so `recent_for_tenant` filters it out entirely. An
    // auditor investigating why a target left the fleet sees nothing at all.
    let admin = Harness::new();
    quarantine(
        &admin,
        &admin.operator(),
        "leaking another tenant's completions",
    );

    let audit = admin.get(&admin.auditor(), "/admin/v1/audit");
    let quarantine = audit
        .data()
        .into_iter()
        .find(|record| record.opt_field_str("object").ok().flatten() == Some(LOCAL_TARGET))
        .expect("the quarantine must appear in the audit view");

    assert_eq!(
        quarantine.field_str("action").unwrap(),
        "target_quarantined"
    );
    assert_eq!(quarantine.field_str("actor").unwrap(), "user:operator-acme");
    assert_eq!(
        quarantine.field_str("reason").unwrap(),
        "leaking another tenant's completions"
    );
}

// -- Tenancy ----------------------------------------------------------------

#[test]
fn a_drain_by_any_tenants_operator_removes_the_target_from_every_tenants_routing() {
    // Targets are fleet infrastructure: the configuration grammar gives them no
    // owning tenant, and the handler applies an override globally. So an
    // operator in tenant B can take out of service the target tenant A's
    // binding prefers, and neither the reply nor the audit reason says whose
    // traffic was affected. This is recorded rather than asserted-against
    // because it is the design as built; it is the blast radius any future
    // change to target ownership has to reckon with.
    let admin = Harness::new();
    let stranger = admin.operator_in(TENANT_B);

    let response = admin.patch(&stranger, LOCAL_PATH, r#"{"state":"disabled"}"#, ANY_ETAG);

    assert_eq!(response.status, 200);
    assert_eq!(
        override_state(&admin, LOCAL_TARGET),
        Some(AdminState::Disabled)
    );
    // Tenant A never asked for this and cannot see who did.
    assert_excluded(&admin, ExclusionReason::TargetDisabled);
}

#[test]
fn a_target_failing_on_one_operation_is_not_reported_as_healthy() {
    // The screen an operator watches during an outage. Health is tracked per
    // `(target, operation)`, and both the target list and the overview used to
    // read only `Operation::Chat` — so a target whose embeddings had tripped
    // its breaker showed `breaker_state: "closed"` and counted toward
    // `targets_healthy`. That reads as "the target is fine" at precisely the
    // moment it is not.
    let admin = Harness::new();
    let target = hypellm_core::ids::TargetId::new(LOCAL_TARGET).expect("target");
    let now = admin.clock.now_millis();

    // Trip the breaker on embeddings only, leaving chat untouched.
    let health = admin.state.health.entry(&target, Operation::Embeddings);
    for _ in 0..64 {
        health.record_failure(hypellm_core::event::UpstreamErrorClass::ServerError, now);
    }
    assert_eq!(
        admin
            .state
            .health
            .entry(&target, Operation::Chat)
            .breaker
            .state(now),
        hypellm_core::health::BreakerState::Closed,
        "the fixture must leave chat healthy, or it proves nothing"
    );

    let listing = admin
        .request(Method::Get, "/admin/v1/targets")
        .as_session(&admin.viewer())
        .send();
    assert_eq!(listing.status, 200, "{}", listing.body);
    let json = listing.json();
    let row = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|t| t.field_str("id").unwrap_or_default() == LOCAL_TARGET)
        .expect("the target");

    assert_ne!(
        row.field_str("breaker_state").unwrap_or_default(),
        "closed",
        "a target failing on embeddings was reported as healthy:\n{}",
        listing.body
    );
    // The summary is never the only answer available: the per-operation map
    // says which one is broken.
    let by_operation = row
        .opt_field_object("breaker_state_by_operation")
        .ok()
        .flatten()
        .expect("a per-operation breakdown");
    assert_eq!(by_operation.get("chat").and_then(Value::as_str), Some("closed"));
    assert_ne!(
        by_operation.get("embeddings").and_then(Value::as_str),
        Some("closed")
    );

    // And the overview counts on the same rule, so the two cannot disagree.
    let overview = admin
        .request(Method::Get, "/admin/v1/overview")
        .as_session(&admin.viewer())
        .send();
    let overview = overview.json();
    assert!(
        overview.opt_field_i64("targets_degraded").ok().flatten().unwrap_or(0) >= 1,
        "the overview still counted the target as healthy"
    );
}

// -- Deployment-wide listings are tenant-scoped (Appendix B) -----------------

/// A configuration where tenant B is granted nothing, so every deployment-wide
/// listing must come back empty for it.
fn two_tenant_config() -> String {
    let mut text = harness::default_config();
    // `default_config` grants tenant B a wildcard; narrow it to nothing so the
    // scoping is observable.
    text = text.replace("grant scope=tenant:globex model=* allow=true\n", "");
    text
}

#[test]
fn providers_are_not_listed_to_a_tenant_that_cannot_reach_them() {
    // Appendix B: "Management visibility never exceeds the caller's tenant and
    // permissions." This listing carries endpoint hostnames and credential
    // *references*, so an unscoped one told every tenant which providers the
    // deployment uses, where they live, and what their credentials are called.
    let admin = Harness::builder().config(&two_tenant_config()).build();

    let granted = admin
        .request(Method::Get, "/admin/v1/providers")
        .as_session(&admin.viewer_in(TENANT_A))
        .send();
    assert_eq!(granted.status, 200, "{}", granted.body);
    assert!(
        !granted.json().field_array("data").expect("a listing").is_empty(),
        "a tenant that can reach a provider must still see it: {}",
        granted.body
    );

    let ungranted = admin
        .request(Method::Get, "/admin/v1/providers")
        .as_session(&admin.viewer_in(TENANT_B))
        .send();
    assert_eq!(ungranted.status, 200, "{}", ungranted.body);
    assert!(
        ungranted.json().field_array("data").expect("a listing").is_empty(),
        "a tenant granted nothing saw the deployment's providers: {}",
        ungranted.body
    );
    // Specifically: no hostname and no credential reference.
    for leaked in ["api.provider.test", "provider-secret", "127.0.0.1"] {
        assert!(
            !ungranted.body.contains(leaked),
            "'{leaked}' leaked to a tenant with no grant:\n{}",
            ungranted.body
        );
    }
}

#[test]
fn aliases_are_not_listed_to_a_tenant_that_holds_no_grant() {
    let admin = Harness::builder().config(&two_tenant_config()).build();

    let ungranted = admin
        .request(Method::Get, "/admin/v1/aliases")
        .as_session(&admin.viewer_in(TENANT_B))
        .send();
    assert_eq!(ungranted.status, 200, "{}", ungranted.body);
    assert!(
        ungranted.json().field_array("data").expect("a listing").is_empty(),
        "an alias the tenant holds no grant for was listed: {}",
        ungranted.body
    );
}

#[test]
fn the_overview_counts_only_what_the_caller_can_see() {
    // The counts and the listings must agree, or an operator reads one screen
    // saying four targets and another showing none — and the difference is
    // itself a disclosure about the deployment's size.
    let admin = Harness::builder().config(&two_tenant_config()).build();

    let a = admin
        .request(Method::Get, "/admin/v1/overview")
        .as_session(&admin.viewer_in(TENANT_A))
        .send();
    let b = admin
        .request(Method::Get, "/admin/v1/overview")
        .as_session(&admin.viewer_in(TENANT_B))
        .send();
    assert_eq!(a.status, 200, "{}", a.body);
    assert_eq!(b.status, 200, "{}", b.body);

    let count = |r: &harness::Response, field: &str| -> i64 {
        r.json().opt_field_i64(field).ok().flatten().unwrap_or(-1)
    };
    assert!(count(&a, "targets_total") > 0, "{}", a.body);
    assert_eq!(count(&b, "targets_total"), 0, "{}", b.body);
    assert_eq!(count(&b, "providers"), 0, "{}", b.body);
    assert_eq!(count(&b, "aliases"), 0, "{}", b.body);
    assert_eq!(
        count(&b, "targets_healthy") + count(&b, "targets_degraded"),
        0,
        "the health counts must not disclose targets the listing hides: {}",
        b.body
    );

    // And the overview agrees with the listing it summarises.
    let listed = admin
        .request(Method::Get, "/admin/v1/targets")
        .as_session(&admin.viewer_in(TENANT_A))
        .send();
    assert_eq!(
        count(&a, "targets_total"),
        i64::try_from(listed.json().field_array("data").expect("a listing").len())
            .expect("small"),
        "the overview and the target listing disagree"
    );
}

// -- Proposing a target (`DI-047`) ------------------------------------------

/// The body a target proposal takes.
fn proposal(id: &str, provider: &str, model: &str) -> String {
    format!("{{\"id\":{id:?},\"provider\":{provider:?},\"model\":{model:?}}}")
}

#[test]
fn proposing_a_target_creates_a_draft_and_not_a_target() {
    // `DI-047`: specification 16 lists `POST /admin/v1/targets`, and the
    // obvious reading — create the target — would put a second mutation path
    // beside specification 15.4's draft → validate → approve → activate
    // discipline, making routing changeable with one signature.
    //
    // So the endpoint exists and returns a *draft*. This asserts the
    // distinction that matters: after a successful call, nothing routes
    // anywhere new.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let before = admin.state.config().snapshot.targets.len();
    let response = admin
        .request(Method::Post, "/admin/v1/targets")
        .as_session(&editor)
        .body(proposal("local:proposed", "local", "proposed-model").as_bytes())
        .send();

    assert_eq!(response.status, 201, "{}", response.body);
    let json = response.json();
    assert!(
        json.field_str("draft_id").is_ok(),
        "the response must name the draft it created: {}",
        response.body
    );
    assert_eq!(
        json.opt_field_bool("target_created").ok().flatten(),
        Some(false),
        "the response must say plainly that no target was created: {}",
        response.body
    );

    // The active policy is untouched: no new target, and the one proposed is
    // not reachable.
    let after = admin.state.config();
    assert_eq!(
        after.snapshot.targets.len(),
        before,
        "a proposal changed the active routing policy"
    );
    assert!(
        !after
            .snapshot
            .targets
            .contains_key(&TargetId::new("local:proposed").expect("id")),
        "the proposed target became live without an approval"
    );
}

#[test]
fn a_proposed_target_still_has_to_go_through_approval_to_take_effect() {
    // The draft a proposal produces must be an ordinary draft — the same
    // validation and the same second-approver rule. If it were exempt from
    // either, the endpoint would be the one-signature routing change the
    // deviation was recorded to avoid.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let created = admin
        .request(Method::Post, "/admin/v1/targets")
        .as_session(&editor)
        .body(proposal("local:proposed", "local", "proposed-model").as_bytes())
        .send();
    let draft_id = created.json().field_str("draft_id").expect("draft id").to_owned();

    // The author cannot publish their own draft (specification 9.3).
    let self_publish = admin
        .request(Method::Post, &format!("/admin/v1/policies/{draft_id}:publish"))
        .as_session(&editor)
        .header("If-Match", ANY_ETAG)
        .body(b"{}")
        .send();
    assert!(
        self_publish.status >= 400,
        "the proposer published their own draft: {}",
        self_publish.body
    );
}

#[test]
fn a_proposal_cannot_inject_a_second_configuration_record() {
    // The configuration grammar is line-oriented and space-separated
    // (specification 11.1), so an unchecked value could add records rather
    // than a field — and a *second* person reviews the draft and approves what
    // they were shown. Configuration injection here is a way to get a record
    // approved that nobody read.
    //
    // Every field is tried, not just `id`. `id` is independently rejected by
    // `TargetId::new`, so testing it alone would pass whether or not the
    // handler validated anything — `provider` and `model` have no such second
    // line of defence, and they are the fields this test is really about.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let hostile = [
        "x\ngrant scope=tenant:acme model=* allow=true",
        "x provider=other",
        "x # comment",
        "x\r\ntarget id=y",
        "",
        "x\ttab",
        "\"quoted\"",
    ];

    for value in hostile {
        for field in ["id", "provider", "model"] {
            let body = match field {
                "id" => proposal(value, "local", "m"),
                "provider" => proposal("local:proposed", value, "m"),
                _ => proposal("local:proposed", "local", value),
            };
            let response = admin
                .request(Method::Post, "/admin/v1/targets")
                .as_session(&editor)
                .body(body.as_bytes())
                .send();
            assert_eq!(
                response.status, 400,
                "a hostile {field} was accepted: {value:?} -> {}",
                response.body
            );
        }
    }

    // And nothing hostile reached a draft: the injected grant would be the
    // damage, so assert on the drafts rather than only on the status code.
    let tenant = hypellm_core::ids::TenantId::new(TENANT_A).expect("tenant");
    for draft in admin.state.drafts.list(&tenant) {
        assert!(
            !draft.text.contains("tenant:acme"),
            "an injected record reached a draft:\n{}",
            draft.text
        );
    }
}

#[test]
fn proposing_a_target_needs_policy_permission_not_target_permission() {
    // The permission must match what the call does. An operator holds
    // `OperateTargets` — enable, drain, quarantine — and authoring a policy
    // change is not that; if this accepted `OperateTargets` the endpoint would
    // be a way into the policy workflow from outside it.
    let admin = Harness::new();

    let operator = admin.operator();
    let refused = admin
        .request(Method::Post, "/admin/v1/targets")
        .as_session(&operator)
        .body(proposal("local:proposed", "local", "m").as_bytes())
        .send();
    assert_eq!(refused.status, 403, "{}", refused.body);

    let viewer = admin.viewer();
    let also_refused = admin
        .request(Method::Post, "/admin/v1/targets")
        .as_session(&viewer)
        .body(proposal("local:proposed", "local", "m").as_bytes())
        .send();
    assert_eq!(also_refused.status, 403, "{}", also_refused.body);
}

#[test]
fn proposing_a_target_that_already_exists_is_a_conflict() {
    // Not an error for its own sake: a proposal that silently produced a draft
    // with a duplicate record would fail validation later with a message about
    // the configuration rather than about the request, and the operator would
    // debug the wrong thing.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let response = admin
        .request(Method::Post, "/admin/v1/targets")
        .as_session(&editor)
        .body(proposal(LOCAL_TARGET, "local", "m").as_bytes())
        .send();
    assert_eq!(response.status, 409, "{}", response.body);
}
