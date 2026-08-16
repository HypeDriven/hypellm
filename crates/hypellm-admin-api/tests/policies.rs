//! Policy drafts, validation, simulation, and publication (`/admin/v1/policies`).
//!
//! Specification 15.3 gives the routing-policy screen "draft diff, validation,
//! simulation, approval, rollback"; specification 15.4 adds the two rules that
//! make it safe — "draft policy simulation accepts a sanitized request
//! descriptor and principal selector, returning exclusions and scores **without
//! provider invocation**", and "publishing requires validation and, where
//! configured, a distinct approver". Specification 9.3 spells the separation
//! out: a policy editor "cannot publish own draft by default".
//!
//! This is the most dangerous surface in the management API. A publish replaces
//! the routing policy for *every* tenant of the router: the destinations, the
//! grants, the residency filters, and the credential bindings. So the questions
//! each test here asks are the ones an attacker would ask.
//!
//! 1. Who may draft, who may simulate, who may publish, and does a caller
//!    without the permission get a refusal rather than data?
//! 2. Appendix B — "management visibility never exceeds the caller's tenant and
//!    permissions". Can one tenant read, validate, or publish another's draft?
//! 3. Specification 15.4 — is a publish without `If-Match` refused, and a stale
//!    one refused with 412?
//! 4. Does the handler do what its response says: is the draft really stored,
//!    is the activation really on disk before it takes effect, is the digest it
//!    reports the one now running?
//! 5. Does any response, or any log line, carry something it should not?
//!
//! Every test here runs. Where one asserted a property the handlers did not
//! hold, the handler was fixed rather than the assertion relaxed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]

mod harness;

use hypellm_admin_api::handlers::{AdminApi, AdminRequest, AdminState};
use hypellm_admin_api::{CorsPolicy, DraftStore};
use hypellm_auth::session;
use hypellm_core::canonical::Operation;
use hypellm_core::ids::TargetId;
use hypellm_core::time::Clock as _;
use hypellm_store::{Log, RecordKind};
use harness::{
    ALIAS, ALLOWED_ORIGIN, ANY_ETAG, Harness, HOSTILE_ORIGIN, LOCAL_TARGET, REMOTE_TARGET,
    STALE_ETAG, TENANT_A, TENANT_B, TestSession, default_config,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use wire_http1::{Headers, Method};

/// The MAC key the harness opens its store with, so a test can replay the log
/// the handlers wrote to and see the frames for itself.
const STORE_MAC_KEY: &[u8] = b"harness-store-mac-key";

// -- Fixtures ---------------------------------------------------------------

/// A configuration that builds and differs from the active one, so that
/// publishing it is observable in the version, the digest, and the log.
fn amended_config() -> String {
    let mut text = default_config();
    text.push_str("tenant id=initech\n");
    text.push_str("grant scope=tenant:initech model=* allow=true\n");
    text
}

/// A configuration that does not build: the alias names a target that is not
/// defined. The error message quotes the offending value, which is what makes
/// validation useful — and what makes cross-tenant validation a disclosure.
const UNBUILDABLE_CONFIG: &str = "alias id=a targets=does-not-exist\n";

/// The default configuration, but preferring the remote target.
///
/// `api.provider.test` is in the `.test` top-level domain, which RFC 6761
/// reserves and no resolver ever answers for. So a simulation that named this
/// target as its choice cannot have reached it.
fn remote_preferring_config() -> String {
    default_config().replace("prefer=local:model", "prefer=remote:model")
}

/// A `POST /admin/v1/policies` body carrying configuration text.
///
/// Rust's `{:?}` for `&str` escapes exactly what JSON needs for the ASCII these
/// fixtures are made of.
fn draft_body(configuration: &str) -> String {
    format!("{{\"configuration\":{configuration:?}}}")
}

/// Create a draft through the API and return its identifier.
fn draft(admin: &Harness, author: &TestSession, configuration: &str) -> String {
    let created = admin.post(author, "/admin/v1/policies", &draft_body(configuration));
    assert_eq!(created.status, 201, "creating a draft: {}", created.body);
    created.str_field("id")
}

/// Create and validate a draft, returning its identifier.
fn validated_draft(admin: &Harness, author: &TestSession, configuration: &str) -> String {
    let id = draft(admin, author, configuration);
    let validated = admin.post(author, &format!("/admin/v1/policies/{id}:validate"), "{}");
    assert_eq!(validated.status, 200, "validating: {}", validated.body);
    id
}

/// How many `ConfigActivation` frames the durable log holds.
///
/// Read from the log file directly rather than from any handler, because the
/// point of the assertion is that the activation reached disk — a handler that
/// merely says so would satisfy an in-memory counter just as well.
fn activation_frames(admin: &Harness) -> Vec<Vec<u8>> {
    let path = admin.state.store.dir().join("log.bin");
    let mut log = Log::open(&path, false).expect("open the durable log for reading");
    let replay = log.replay(STORE_MAC_KEY).expect("replay the durable log");
    replay
        .of_kind(RecordKind::ConfigActivation)
        .map(|frame| frame.payload.clone())
        .collect()
}

// -- Authorization ----------------------------------------------------------

#[test]
fn creating_a_draft_requires_the_edit_policy_permission() {
    // Specification 9.3 gives `edit_policy` to the policy editor and to
    // break-glass, and to nobody else. A draft is the first half of a
    // configuration change, so everyone else must be refused outright.
    let admin = Harness::new();
    let body = draft_body(&default_config());

    for session in [
        admin.viewer(),
        admin.operator(),
        admin.policy_approver(),
        admin.auditor(),
        admin.credential_manager(),
        admin.unprivileged(),
    ] {
        let refused = admin.post(&session, "/admin/v1/policies", &body);
        assert_eq!(
            refused.status, 403,
            "{} must not be able to draft policy",
            session.principal.as_str()
        );
        assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
    }

    // And the refusals left nothing behind.
    assert_eq!(admin.state.drafts.len(), 0);

    let created = admin.post(&admin.policy_editor(), "/admin/v1/policies", &body);
    assert_eq!(created.status, 201);
}

#[test]
fn listing_drafts_requires_a_policy_permission() {
    // The list discloses who is proposing what change to the router. An
    // operator or an auditor holds neither `edit_policy` nor `simulate_policy`
    // and must not see it.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    draft(&admin, &editor, &default_config());

    for session in [
        admin.viewer(),
        admin.operator(),
        admin.auditor(),
        admin.credential_manager(),
        admin.unprivileged(),
    ] {
        let refused = admin.get(&session, "/admin/v1/policies");
        assert_eq!(refused.status, 403, "{}", session.principal.as_str());
        assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
        assert!(
            !refused.body_contains("draft_"),
            "a refusal must not name the drafts it refused to show: {}",
            refused.body
        );
    }

    // Both halves of the policy workflow may read the queue.
    assert_eq!(admin.get(&editor, "/admin/v1/policies").status, 200);
    assert_eq!(
        admin.get(&admin.policy_approver(), "/admin/v1/policies").status,
        200
    );
}

#[test]
fn validating_a_draft_requires_a_policy_permission() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());
    let path = format!("/admin/v1/policies/{id}:validate");

    for session in [admin.viewer(), admin.operator(), admin.auditor()] {
        let refused = admin.post(&session, &path, "{}");
        assert_eq!(refused.status, 403, "{}", session.principal.as_str());
        assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
    }

    // An approver holds `simulate_policy`, which is enough to check a draft
    // before deciding whether to publish it — reviewing without being able to
    // validate would be reviewing blind.
    assert_eq!(
        admin.post(&admin.policy_approver(), &path, "{}").status,
        200
    );
    assert_eq!(admin.post(&editor, &path, "{}").status, 200);
}

#[test]
fn simulating_a_draft_requires_the_simulate_policy_permission() {
    // An operator holds `read_decision_traces` — the closest neighbouring
    // permission — and still may not simulate, because simulation runs the
    // routing function over a policy the operator is not entitled to reason
    // about.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());
    let path = format!("/admin/v1/policies/{id}:simulate");
    let body = format!("{{\"model\":\"{ALIAS}\"}}");

    for session in [admin.viewer(), admin.operator(), admin.auditor()] {
        let refused = admin.post(&session, &path, &body);
        assert_eq!(refused.status, 403, "{}", session.principal.as_str());
        assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
        assert!(
            !refused.body_contains(LOCAL_TARGET),
            "a refusal must not disclose the topology it refused to simulate"
        );
    }

    assert_eq!(admin.post(&editor, &path, &body).status, 200);
}

#[test]
fn publishing_requires_the_publish_policy_permission() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = validated_draft(&admin, &editor, &amended_config());
    let path = format!("/admin/v1/policies/{id}:publish");
    let before = admin.config().digest;

    for session in [
        admin.viewer(),
        admin.operator(),
        admin.auditor(),
        admin.credential_manager(),
        admin.unprivileged(),
        editor.clone(),
    ] {
        let refused = admin.post_if_match(&session, &path, "{}", ANY_ETAG);
        assert_eq!(refused.status, 403, "{}", session.principal.as_str());
        assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
    }

    assert_eq!(
        admin.config().digest,
        before,
        "a refused publish must leave the running configuration alone"
    );
    assert!(activation_frames(&admin).is_empty());
}

#[test]
fn the_editor_and_approver_roles_are_separated_in_both_directions() {
    // Specification 9.3: the policy editor drafts and simulates but cannot
    // publish; the policy approver publishes but cannot draft. Neither role can
    // complete a configuration change alone, which is the whole point of
    // splitting them.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();

    let id = validated_draft(&admin, &editor, &amended_config());

    let editor_publish =
        admin.post_if_match(&editor, &format!("/admin/v1/policies/{id}:publish"), "{}", ANY_ETAG);
    assert_eq!(editor_publish.status, 403);

    let approver_draft = admin.post(
        &approver,
        "/admin/v1/policies",
        &draft_body(&default_config()),
    );
    assert_eq!(approver_draft.status, 403);

    // Together they can.
    let published =
        admin.post_if_match(&approver, &format!("/admin/v1/policies/{id}:publish"), "{}", ANY_ETAG);
    assert_eq!(published.status, 200, "{}", published.body);
}

#[test]
fn no_policy_endpoint_answers_an_unauthenticated_caller() {
    let admin = Harness::new();
    let id = draft(&admin, &admin.policy_editor(), &default_config());

    let calls = [
        (Method::Get, "/admin/v1/policies".to_owned()),
        (Method::Post, "/admin/v1/policies".to_owned()),
        (Method::Post, format!("/admin/v1/policies/{id}:validate")),
        (Method::Post, format!("/admin/v1/policies/{id}:simulate")),
        (Method::Post, format!("/admin/v1/policies/{id}:publish")),
    ];

    for (method, path) in calls {
        let refused = admin.anonymous(method, &path);
        assert_eq!(refused.status, 401, "{path}");
        assert_eq!(refused.error_code.as_deref(), Some("unauthenticated"));
        assert!(
            !refused.body_contains("draft_"),
            "an anonymous caller must not learn a draft exists: {}",
            refused.body
        );
    }
}

#[test]
fn a_policy_mutation_without_a_csrf_token_is_refused() {
    // Every policy action is a POST, so every one of them is state-changing as
    // far as a browser is concerned and needs the session-bound token
    // (specification 9.1). Simulation counts: it is the reconnaissance step
    // before a publish.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    let attempts = [
        (&editor, "/admin/v1/policies".to_owned(), draft_body(&default_config())),
        (&editor, format!("/admin/v1/policies/{id}:validate"), "{}".to_owned()),
        (
            &editor,
            format!("/admin/v1/policies/{id}:simulate"),
            format!("{{\"model\":\"{ALIAS}\"}}"),
        ),
        (&approver, format!("/admin/v1/policies/{id}:publish"), "{}".to_owned()),
    ];

    for (session, path, body) in attempts {
        let refused = admin
            .request(Method::Post, &path)
            .as_session(session)
            .json(&body)
            .if_match(ANY_ETAG)
            .without_csrf()
            .send();
        assert_eq!(refused.status, 403, "{path}");
        assert_eq!(refused.error_code.as_deref(), Some("csrf_required"), "{path}");
    }

    assert!(
        activation_frames(&admin).is_empty(),
        "a forged cross-site publish must not have activated anything"
    );
}

#[test]
fn a_policy_request_from_an_unlisted_origin_is_refused() {
    // The origin check runs before the cookie is read (handlers.rs, step 1), so
    // a page on a look-alike host cannot ride the operator's session.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = validated_draft(&admin, &editor, &amended_config());

    let refused = admin
        .request(Method::Post, &format!("/admin/v1/policies/{id}:publish"))
        .as_session(&admin.policy_approver())
        .json("{}")
        .if_match(ANY_ETAG)
        .origin(HOSTILE_ORIGIN)
        .send();
    assert_eq!(refused.status, 403);
    assert_eq!(refused.error_code.as_deref(), Some("origin_not_permitted"));
    assert!(activation_frames(&admin).is_empty());

    // The allowlisted origin still works, so the refusal above is the origin
    // check and not something incidental.
    let allowed = admin
        .request(Method::Get, "/admin/v1/policies")
        .as_session(&editor)
        .origin(ALLOWED_ORIGIN)
        .send();
    assert_eq!(allowed.status, 200);
}

#[test]
fn publishing_requires_a_recent_authentication() {
    // Specification 9.1: "reauthentication is required for credential changes,
    // role grants, break-glass actions, and policy publication." A session left
    // open on a desk is not an approval.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());
    let path = format!("/admin/v1/policies/{id}:publish");

    admin.advance(6 * 60 * 1000);

    let stale = admin.post_if_match(&approver, &path, "{}", ANY_ETAG);
    assert_eq!(stale.status, 403);
    assert_eq!(
        stale.error_code.as_deref(),
        Some("reauthentication_required")
    );
    assert!(activation_frames(&admin).is_empty());

    // Drafting is not on the sensitive list, so the same stale session may
    // still draft — the freshness rule is targeted, not a blanket lockout.
    assert_eq!(
        admin
            .post(&editor, "/admin/v1/policies", &draft_body(&default_config()))
            .status,
        201
    );

    let fresh = admin.reauthenticate(&approver);
    let published = admin.post_if_match(&fresh, &path, "{}", ANY_ETAG);
    assert_eq!(published.status, 200, "{}", published.body);
}

#[test]
fn authorization_is_checked_before_a_draft_is_looked_up() {
    // A caller who may not touch policy must not be able to probe which draft
    // identifiers exist by comparing 403 against 404.
    let admin = Harness::new();
    let id = draft(&admin, &admin.policy_editor(), &default_config());
    let viewer = admin.viewer();

    let existing = admin.post(&viewer, &format!("/admin/v1/policies/{id}:validate"), "{}");
    let absent = admin.post(&viewer, "/admin/v1/policies/draft_99999:validate", "{}");

    assert_eq!(existing.status, 403);
    assert_eq!(absent.status, 403);
    assert_eq!(existing.error_code, absent.error_code);

    // Identical down to the message: the only thing that differs between the
    // two responses is the request identifier.
    let message = |response: &harness::Response| {
        response
            .json()
            .opt_field_object("error")
            .unwrap()
            .unwrap()
            .get("message")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(message(&existing), message(&absent));
}

// -- Drafting ---------------------------------------------------------------

#[test]
fn a_created_draft_is_actually_stored_and_listed() {
    // The no-op handlers this suite exists to catch answered 201 and kept
    // nothing. So the create response is only believed once the draft is read
    // back through a different endpoint.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let created = admin.post(
        &editor,
        "/admin/v1/policies",
        &draft_body(&default_config()),
    );
    assert_eq!(created.status, 201);
    let id = created.str_field("id");
    assert_eq!(created.str_field("author"), editor.principal.as_str());
    assert_eq!(
        created.json().opt_field_bool("validated").unwrap(),
        Some(false),
        "a new draft has not been validated and must not claim to be"
    );

    let listed = admin.get(&editor, "/admin/v1/policies");
    assert_eq!(listed.ids(), vec![id.clone()]);
    let entry = &listed.data()[0];
    assert_eq!(entry.field_str("author").unwrap(), editor.principal.as_str());
    assert_eq!(entry.opt_field_bool("validated").unwrap(), Some(false));
    assert_eq!(entry.opt_field_bool("valid").unwrap(), Some(false));
    assert_eq!(entry.field_i64("error_count").unwrap(), 0);
    assert!(
        entry.get("digest").is_none_or(wire_json::Value::is_null),
        "an unvalidated draft has no digest to report"
    );
}

#[test]
fn creating_a_draft_requires_a_configuration_field() {
    let admin = Harness::new();
    let editor = admin.policy_editor();

    for body in ["{}", "{\"config\":\"x\"}", "{\"configuration\":42}"] {
        let refused = admin.post(&editor, "/admin/v1/policies", body);
        assert_eq!(refused.status, 400, "{body}");
        assert_eq!(refused.error_code.as_deref(), Some("invalid_request"));
    }
    assert_eq!(admin.state.drafts.len(), 0);
}

#[test]
fn a_draft_body_that_is_not_json_is_refused_without_panicking() {
    // Specification 18.2: no panic on data-plane input, and the management
    // plane is no less exposed.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    for body in [
        &b"not json at all"[..],
        &b"{\"configuration\":"[..],
        &b""[..],
        &[0xff, 0xfe, 0x00][..],
    ] {
        let refused = admin
            .request(Method::Post, "/admin/v1/policies")
            .as_session(&editor)
            .body(body)
            .send();
        assert_eq!(refused.status, 400, "{body:?}");
        assert_eq!(refused.error_code.as_deref(), Some("invalid_request"));
    }
    assert_eq!(admin.state.drafts.len(), 0);
}

#[test]
fn creating_a_draft_is_recorded_in_the_durable_audit_chain() {
    // Specification 18.3: security changes fail closed, so the audit record is
    // written before the action is reported as done. The chain is the record an
    // investigator gets.
    let admin = Harness::new();
    let editor = admin.policy_editor();

    let before = admin.audit_count();
    draft(&admin, &editor, &default_config());
    assert_eq!(
        admin.audit_count(),
        before + 1,
        "a draft that was accepted must be in the audit chain"
    );
}

#[test]
fn the_draft_store_is_bounded_so_a_client_cannot_grow_it_without_limit() {
    // Specification 3.2: no unbounded buffer, queue, or table may originate
    // from a request. A policy editor who keeps drafting must not be able to
    // exhaust the management plane's memory.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let body = draft_body("tenant id=acme\n");

    for _ in 0..300 {
        let created = admin.post(&editor, "/admin/v1/policies", &body);
        assert_eq!(created.status, 201);
    }

    let held = admin.state.drafts.len();
    assert!(
        held <= 256,
        "the draft store grew to {held}; it must be capped"
    );
    assert!(held > 0, "the cap must evict, not refuse everything");
    assert_eq!(admin.get(&editor, "/admin/v1/policies").data().len(), held);
}

// -- Validation -------------------------------------------------------------

#[test]
fn validation_reports_every_error_in_a_bad_draft() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, UNBUILDABLE_CONFIG);

    let validated = admin.post(&editor, &format!("/admin/v1/policies/{id}:validate"), "{}");
    assert_eq!(validated.status, 200, "a bad draft is a valid question");
    assert_eq!(validated.str_field("id"), id);
    assert_eq!(
        validated.json().opt_field_bool("valid").unwrap(),
        Some(false)
    );
    assert!(
        validated.json().get("digest").is_none_or(wire_json::Value::is_null),
        "a draft that does not build has no digest"
    );

    let errors = validated.json().field_array("errors").unwrap().to_vec();
    assert!(!errors.is_empty(), "the errors must be reported, not hidden");
    for error in &errors {
        // An operator needs all four to fix the draft: what, why, and where.
        assert!(!error.field_str("code").unwrap().is_empty());
        assert!(!error.field_str("message").unwrap().is_empty());
        assert!(error.field_i64("line").unwrap() >= 1);
        assert!(error.field_i64("column").unwrap() >= 1);
    }
    assert_eq!(
        errors[0].field_str("code").unwrap(),
        "unresolved_reference"
    );
}

#[test]
fn validation_reports_a_full_digest_for_a_good_draft() {
    // The digest is what an approver compares against the diff they reviewed,
    // so it has to be the whole thing, not the short form the list carries.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &amended_config());

    let validated = admin.post(&editor, &format!("/admin/v1/policies/{id}:validate"), "{}");
    assert_eq!(validated.status, 200);
    assert_eq!(validated.json().opt_field_bool("valid").unwrap(), Some(true));
    assert!(validated.json().field_array("errors").unwrap().is_empty());

    let digest = validated.str_field("digest");
    assert_eq!(digest.len(), 64, "a full digest, not the short form");
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(
        digest,
        admin.config().digest.to_hex(),
        "this fixture must differ from the running configuration"
    );
}

#[test]
fn validation_updates_the_state_the_draft_list_reports() {
    // Validation is a mutation of the draft, and the list has to agree with it
    // — an approver decides from the list.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let good = draft(&admin, &editor, &amended_config());
    let bad = draft(&admin, &editor, UNBUILDABLE_CONFIG);

    for id in [&good, &bad] {
        let validated = admin.post(&editor, &format!("/admin/v1/policies/{id}:validate"), "{}");
        assert_eq!(validated.status, 200);
    }

    let listed = admin.get(&editor, "/admin/v1/policies");
    let entries = listed.data();
    let good_entry = entries
        .iter()
        .find(|e| e.field_str("id").unwrap() == good)
        .unwrap();
    let bad_entry = entries
        .iter()
        .find(|e| e.field_str("id").unwrap() == bad)
        .unwrap();

    assert_eq!(good_entry.opt_field_bool("validated").unwrap(), Some(true));
    assert_eq!(good_entry.opt_field_bool("valid").unwrap(), Some(true));
    assert_eq!(good_entry.field_i64("error_count").unwrap(), 0);
    assert_eq!(good_entry.field_str("digest").unwrap().len(), 12);

    assert_eq!(bad_entry.opt_field_bool("validated").unwrap(), Some(true));
    assert_eq!(bad_entry.opt_field_bool("valid").unwrap(), Some(false));
    assert!(bad_entry.field_i64("error_count").unwrap() > 0);
}

#[test]
fn validating_a_draft_that_does_not_exist_is_a_404() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let refused = admin.post(&editor, "/admin/v1/policies/draft_404:validate", "{}");
    assert_eq!(refused.status, 404);
    assert_eq!(refused.error_code.as_deref(), Some("not_found"));
}

// -- Simulation -------------------------------------------------------------

#[test]
fn simulation_returns_ranked_candidates_and_exclusion_reasons() {
    // Specification 15.4: simulation returns "exclusions and scores". A screen
    // that showed only the winner would not explain a routing surprise, which
    // is the reason the endpoint exists.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());

    let simulated = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\"}}"),
    );
    assert_eq!(simulated.status, 200, "{}", simulated.body);
    assert_eq!(simulated.str_field("draft"), id);
    assert_eq!(simulated.str_field("chosen"), LOCAL_TARGET);
    assert_eq!(
        simulated.json().opt_field_bool("pinned").unwrap(),
        Some(false)
    );

    let candidates = simulated.json().field_array("candidates").unwrap().to_vec();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].field_str("target").unwrap(), LOCAL_TARGET);
    assert_eq!(candidates[0].field_i64("rank").unwrap(), 0);
    assert!(
        candidates[0].field_i64("score").unwrap() > 0,
        "a candidate carries the integer score that ranked it"
    );

    let exclusions = simulated.json().field_array("exclusions").unwrap().to_vec();
    assert_eq!(exclusions.len(), 1);
    assert_eq!(exclusions[0].field_str("target").unwrap(), REMOTE_TARGET);
    assert_eq!(
        exclusions[0].field_str("reason").unwrap(),
        "not_selected_by_any_binding",
        "the reason must be the router's own stable code"
    );

    // The policy the answer came from is named, so an approver can tell which
    // draft they are looking at.
    assert_eq!(simulated.str_field("policy_digest").len(), 64);
}

#[test]
fn simulation_reports_the_filter_that_excluded_a_target() {
    // Specification 6.3 keeps security and capability constraints as
    // eligibility filters rather than score penalties, so the simulation has to
    // name the filter — `local_required` here, not a lower score.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());

    let simulated = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\",\"require_local\":true}}"),
    );
    assert_eq!(simulated.status, 200);

    let exclusions = simulated.json().field_array("exclusions").unwrap().to_vec();
    let remote = exclusions
        .iter()
        .find(|e| e.field_str("target").unwrap() == REMOTE_TARGET)
        .expect("the remote target must be accounted for");
    assert_eq!(remote.field_str("reason").unwrap(), "local_required");

    // And the excluded target is genuinely gone, not merely demoted.
    let candidates = simulated.json().field_array("candidates").unwrap().to_vec();
    assert!(
        candidates
            .iter()
            .all(|c| c.field_str("target").unwrap() != REMOTE_TARGET)
    );
}

#[test]
fn simulation_never_contacts_the_provider_it_reports_on() {
    // Specification 15.4: simulation returns exclusions and scores "without
    // provider invocation". The draft chooses a target whose host is in the
    // `.test` domain, so an invocation could not even have resolved it — and
    // every real attempt against a target passes through the health registry,
    // which afterwards has recorded nothing.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &remote_preferring_config());
    let remote = TargetId::new(REMOTE_TARGET).unwrap();

    let started = Instant::now();
    let simulated = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\"}}"),
    );
    let elapsed = started.elapsed();

    assert_eq!(simulated.status, 200, "{}", simulated.body);
    assert_eq!(
        simulated.str_field("chosen"),
        REMOTE_TARGET,
        "the fixture must have chosen the unreachable target"
    );

    let health = admin.state.health.entry(&remote, Operation::Chat);
    assert_eq!(
        health.total_requests(),
        0,
        "simulation attempted a request against the provider"
    );
    assert_eq!(health.in_flight(), 0);
    assert!(
        elapsed.as_secs() < 2,
        "simulation took {elapsed:?}; that is long enough to have dialled the provider"
    );
    assert!(
        !admin
            .log_lines()
            .iter()
            .any(|line| line.contains("api.provider.test")),
        "the management plane must not have gone anywhere near the endpoint"
    );
}

#[test]
fn simulation_runs_in_the_callers_tenant_and_ignores_a_tenant_in_the_body() {
    // Appendix B: management visibility never exceeds the caller's tenant. The
    // scenario's tenant is taken from the session, so naming another tenant in
    // the body must change nothing. The default configuration binds only
    // `acme`, which makes the two answers plainly different.
    let admin = Harness::new();
    let editor = admin.policy_editor_in(TENANT_A);
    let id = draft(&admin, &editor, &default_config());
    let path = format!("/admin/v1/policies/{id}:simulate");

    let own = admin.post(&editor, &path, &format!("{{\"model\":\"{ALIAS}\"}}"));
    let claimed = admin.post(
        &editor,
        &path,
        &format!("{{\"model\":\"{ALIAS}\",\"tenant\":\"{TENANT_B}\"}}"),
    );
    assert_eq!(claimed.status, 200);
    assert_eq!(
        claimed.body, own.body,
        "the tenant selector in the body must be inert"
    );

    // What tenant B's policy actually looks like: nothing is bound for it, so
    // an honest cross-tenant simulation would have looked like this. Their
    // editor has to raise the draft in their own tenant — tenant A's draft is
    // not theirs to read, let alone simulate.
    let their_editor = admin.policy_editor_in(TENANT_B);
    let theirs = draft(&admin, &their_editor, &default_config());
    let other = admin.post(
        &their_editor,
        &format!("/admin/v1/policies/{theirs}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\"}}"),
    );
    assert_eq!(other.status, 200);
    // The two tenants really do route differently, so `claimed` matching `own`
    // above is the body selector being inert rather than the fixture being
    // blind. Compared on the routing outcome, not the whole body: the draft
    // identifiers differ now that each tenant raises its own.
    assert!(
        !own.json().field_array("candidates").unwrap().is_empty(),
        "the caller's own tenant must route somewhere: {}",
        own.body
    );
    assert!(
        other.json().field_array("candidates").unwrap().is_empty(),
        "tenant B is bound to nothing and must route nowhere: {}",
        other.body
    );
    assert_eq!(other.json().get("chosen"), Some(&wire_json::Value::Null));
}

#[test]
fn simulating_a_draft_that_does_not_build_returns_the_validation_details() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, UNBUILDABLE_CONFIG);

    let refused = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        "{\"model\":\"a\"}",
    );
    assert_eq!(refused.status, 400);
    assert_eq!(refused.error_code.as_deref(), Some("validation_failed"));

    let details = refused
        .json()
        .opt_field_object("error")
        .unwrap()
        .unwrap()
        .get("details")
        .unwrap()
        .clone();
    let wire_json::Value::Array(details) = details else {
        panic!("the refusal must carry the details, not just a message");
    };
    assert!(!details.is_empty());
    assert_eq!(
        details[0].field_str("code").unwrap(),
        "unresolved_reference"
    );
    assert!(!details[0].field_str("location").unwrap().is_empty());
}

#[test]
fn simulation_requires_a_model_and_rejects_a_malformed_one() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());
    let path = format!("/admin/v1/policies/{id}:simulate");

    for body in [
        "{}",
        "{\"model\":123}",
        "{\"model\":\"\"}",
        "{\"model\":\"not a valid alias!\"}",
    ] {
        let refused = admin.post(&editor, &path, body);
        assert_eq!(refused.status, 400, "{body}");
        assert_eq!(refused.error_code.as_deref(), Some("invalid_request"), "{body}");
    }

    // A principal selector that is not an identifier is refused too, rather
    // than being coerced into something the router would route for.
    let refused = admin.post(
        &editor,
        &path,
        &format!("{{\"model\":\"{ALIAS}\",\"principal\":\"not a principal!\"}}"),
    );
    assert_eq!(refused.status, 400);
    assert_eq!(refused.error_code.as_deref(), Some("invalid_request"));
}

#[test]
fn simulation_neither_activates_the_draft_nor_counts_as_validating_it() {
    // Simulating is a read of a hypothetical. If it silently marked the draft
    // validated, an approver could publish a draft nobody ever validated —
    // which specification 15.4 forbids.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = draft(&admin, &editor, &amended_config());

    let before_digest = admin.config().digest;
    let before_version = admin.config().snapshot.version;

    let simulated = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\"}}"),
    );
    assert_eq!(simulated.status, 200);

    assert_eq!(admin.config().digest, before_digest);
    assert_eq!(admin.config().snapshot.version, before_version);
    assert!(activation_frames(&admin).is_empty());

    let listed = admin.get(&editor, "/admin/v1/policies");
    let entry = &listed.data()[0];
    assert_eq!(
        entry.opt_field_bool("validated").unwrap(),
        Some(false),
        "simulation is not validation"
    );

    let refused =
        admin.post_if_match(&approver, &format!("/admin/v1/policies/{id}:publish"), "{}", ANY_ETAG);
    assert_eq!(refused.status, 400);
    assert!(
        refused.body_contains("validated"),
        "the refusal must say the draft was never validated: {}",
        refused.body
    );
}

#[test]
fn simulation_ignores_prompt_text_and_never_echoes_or_logs_it() {
    // Specification 15.4 asks for a "sanitized request descriptor" — a size,
    // not a prompt. A simulation endpoint that accepted prompt text would be a
    // way of getting prompts into the management plane's logs, which
    // specification 17 keeps them out of.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());

    let canary = "CANARY-6c9f2a11-prompt-body";
    let simulated = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!(
            "{{\"model\":\"{ALIAS}\",\"prompt\":\"{canary}\",\
             \"messages\":[{{\"role\":\"user\",\"content\":\"{canary}\"}}]}}"
        ),
    );

    assert_eq!(simulated.status, 200, "{}", simulated.body);
    assert!(
        !simulated.body_contains(canary),
        "the response echoed prompt text: {}",
        simulated.body
    );
    assert!(
        !admin.log_lines().iter().any(|line| line.contains(canary)),
        "prompt text reached the management log"
    );
}

#[test]
fn a_simulation_descriptor_may_not_ask_for_an_unbounded_buffer() {
    // The descriptor is a size. `build_scenario` turns it into a filler string
    // of twice that many bytes with no upper bound, so the caller chooses how
    // much of the management plane's memory to consume. The value used here is
    // deliberately modest — 16 MB from a tiny body is already an amplification
    // of roughly a quarter of a million to one — so that running this test with
    // `--ignored` demonstrates the defect without taking the machine down.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());

    let refused = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\",\"input_tokens\":8000000}}"),
    );
    assert_eq!(
        refused.status, 400,
        "an absurd descriptor size must be refused, not honoured"
    );
    assert_eq!(refused.error_code.as_deref(), Some("invalid_request"));

    // A ceiling that refused everything would satisfy the assertion above and
    // break the endpoint, so a descriptor within the policy's own context
    // window still has to be answered — including one large enough to exceed it
    // and produce the exclusion an approver is asking about.
    let sane = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\",\"input_tokens\":1000}}"),
    );
    assert_eq!(sane.status, 200, "{}", sane.body);
    assert_eq!(sane.str_field("chosen"), LOCAL_TARGET);

    let over_context = admin.post(
        &editor,
        &format!("/admin/v1/policies/{id}:simulate"),
        &format!("{{\"model\":\"{ALIAS}\",\"input_tokens\":150000}}"),
    );
    assert_eq!(over_context.status, 200, "{}", over_context.body);
    let exclusions = over_context.json().field_array("exclusions").unwrap().to_vec();
    assert!(
        exclusions
            .iter()
            .any(|e| e.field_str("reason").unwrap() == "context_window_too_small"),
        "a descriptor over every target's context window must still be \
         simulable: {}",
        over_context.body
    );
}

#[test]
fn a_policy_path_that_is_not_an_action_is_not_an_endpoint() {
    // Specification 10: no client-controlled value may steer the request
    // anywhere. The draft identifier is taken from the path, so the path has to
    // be parsed strictly.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = draft(&admin, &editor, &default_config());

    for path in [
        format!("/admin/v1/policies/{id}"),
        format!("/admin/v1/policies/{id}:destroy"),
        format!("/admin/v1/policies/{id}:"),
        "/admin/v1/policies/../targets:validate".to_owned(),
        format!("/admin/v1/policies/{id}/nested:validate"),
        "/admin/v1/policies/:validate".to_owned(),
    ] {
        let refused = admin.post(&editor, &path, "{}");
        assert_eq!(refused.status, 404, "{path}");
        assert_eq!(refused.error_code.as_deref(), Some("not_found"), "{path}");
    }
}

// -- Publication ------------------------------------------------------------

#[test]
fn publishing_without_an_if_match_is_refused_and_changes_nothing() {
    // Specification 15.4 requires optimistic concurrency on mutation. Two
    // approvers publishing different drafts against the same base must not both
    // succeed silently.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());
    let before = admin.config();

    let refused = admin.post(&approver, &format!("/admin/v1/policies/{id}:publish"), "{}");
    assert_eq!(refused.status, 428);
    assert_eq!(
        refused.error_code.as_deref(),
        Some("precondition_required")
    );

    assert_eq!(admin.config().digest, before.digest);
    assert_eq!(admin.config().snapshot.version, before.snapshot.version);
    assert!(
        activation_frames(&admin).is_empty(),
        "nothing was activated, so nothing may be on disk claiming otherwise"
    );
}

#[test]
fn publishing_with_a_stale_if_match_is_refused_and_changes_nothing() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());
    let before = admin.config();

    let refused = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        STALE_ETAG,
    );
    assert_eq!(refused.status, 412);
    assert_eq!(refused.error_code.as_deref(), Some("precondition_failed"));

    assert_eq!(admin.config().digest, before.digest);
    assert_eq!(admin.config().snapshot.version, before.snapshot.version);
    assert!(activation_frames(&admin).is_empty());

    // The current tag is accepted, so the refusal above was staleness and not a
    // blanket rejection of `If-Match`.
    let current = admin.active_config_etag();
    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        &current,
    );
    assert_eq!(published.status, 200, "{}", published.body);
}

#[test]
fn publishing_records_the_activation_durably_and_then_activates_it() {
    // The order in the handler is: append the `ConfigActivation` frame, then
    // swap the pointer. What a test can observe is the pair — the frame is on
    // disk and its bytes are exactly the configuration now running. A crash
    // between the two leaves a record of an activation that did not take
    // effect, which an operator can see; the reverse would leave a running
    // configuration nobody can attribute.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    assert!(activation_frames(&admin).is_empty());
    let before_version = admin.config().snapshot.version;

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200, "{}", published.body);

    let frames = activation_frames(&admin);
    assert_eq!(frames.len(), 1, "exactly one activation was performed");

    let active = admin.config();
    assert_eq!(
        frames[0],
        active.canonical.as_bytes(),
        "the durable frame must be the configuration that is now running"
    );
    assert_eq!(
        published.str_field("digest"),
        active.digest.to_hex(),
        "the response must report the digest that is now active"
    );
    assert_eq!(published.str_field("draft"), id);
    assert_eq!(
        published.json().field_i64("version").unwrap(),
        i64::try_from(active.snapshot.version).unwrap()
    );
    assert!(active.snapshot.version > before_version);

    // The new policy is really in force: the added tenant is present.
    assert!(
        active
            .tenants
            .keys()
            .any(|tenant| tenant.as_str() == "initech"),
        "the published configuration is not the one that took effect"
    );
}

#[test]
fn the_published_digest_is_the_digest_validation_reported() {
    // An approver reviews a diff, sees a digest, and publishes. If publication
    // activated something with a different digest, the review would mean
    // nothing.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = draft(&admin, &editor, &amended_config());

    let validated = admin.post(&editor, &format!("/admin/v1/policies/{id}:validate"), "{}");
    let reviewed = validated.str_field("digest");

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);
    assert_eq!(published.str_field("digest"), reviewed);
    assert_eq!(admin.config().digest.to_hex(), reviewed);
}

#[test]
fn an_author_cannot_publish_their_own_draft() {
    // Specification 9.3: a policy editor "cannot publish own draft by default".
    // The interesting caller is break-glass, which holds both `edit_policy` and
    // `publish_policy` — the one identity that could otherwise change the
    // router's routing on its own.
    let admin = Harness::new();
    let author = admin.break_glass();
    let id = validated_draft(&admin, &author, &amended_config());
    let before = admin.config().digest;

    let refused = admin.post_if_match(
        &author,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 403);
    assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
    assert!(
        refused.body_contains("other than its author"),
        "the refusal must explain what is missing: {}",
        refused.body
    );

    assert_eq!(admin.config().digest, before);
    assert!(activation_frames(&admin).is_empty());

    // Somebody else can publish the very same draft, which is what makes the
    // refusal a separation of duties rather than a broken endpoint.
    let published = admin.post_if_match(
        &admin.policy_approver(),
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200, "{}", published.body);
}

#[test]
fn self_approval_is_permitted_only_where_the_deployment_enables_it() {
    // A single-operator deployment can turn the separation off deliberately.
    // "Deliberately" is the property: the same request that is refused by the
    // default deployment succeeds only against a `DraftStore` that was
    // constructed to allow it.
    let admin = Harness::new();
    assert!(
        !admin.state.drafts.allows_self_approval(),
        "the default deployment must enforce the separation"
    );

    let permissive = self_approving_api(&admin);
    let author = admin.break_glass();

    let created = post_to(
        &permissive,
        "/admin/v1/policies",
        &author,
        &draft_body(&amended_config()),
        None,
    );
    assert_eq!(created.0, 201, "{}", created.1);
    let id = parse_id(&created.1);

    let validated = post_to(
        &permissive,
        &format!("/admin/v1/policies/{id}:validate"),
        &author,
        "{}",
        None,
    );
    assert_eq!(validated.0, 200, "{}", validated.1);

    let published = post_to(
        &permissive,
        &format!("/admin/v1/policies/{id}:publish"),
        &author,
        "{}",
        Some(ANY_ETAG),
    );
    assert_eq!(
        published.0, 200,
        "a deployment that enables self-approval must honour it: {}",
        published.1
    );
}

#[test]
fn an_unvalidated_draft_cannot_be_published() {
    // Specification 15.4: "publishing requires validation."
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = draft(&admin, &editor, &amended_config());

    let refused = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 400);
    assert_eq!(refused.error_code.as_deref(), Some("validation_failed"));
    assert!(activation_frames(&admin).is_empty());
    assert_eq!(admin.config().snapshot.version, 1);
}

#[test]
fn a_draft_that_failed_validation_cannot_be_published() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, UNBUILDABLE_CONFIG);

    let refused = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 400);
    assert_eq!(refused.error_code.as_deref(), Some("validation_failed"));
    assert!(activation_frames(&admin).is_empty());
    assert_eq!(admin.config().snapshot.version, 1);
}

#[test]
fn publishing_a_draft_that_does_not_exist_is_a_404() {
    let admin = Harness::new();
    let refused = admin.post_if_match(
        &admin.policy_approver(),
        "/admin/v1/policies/draft_404:publish",
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 404);
    assert_eq!(refused.error_code.as_deref(), Some("not_found"));
    assert!(activation_frames(&admin).is_empty());
}

#[test]
fn publishing_is_recorded_in_the_durable_audit_chain() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    let before = admin.audit_count();
    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);
    assert_eq!(
        admin.audit_count(),
        before + 1,
        "who published which configuration must be in the chain"
    );
}

#[test]
fn a_second_publish_needs_the_new_precondition_not_the_old_one() {
    // After one publish the configuration has moved, so an approver still
    // holding the tag they read before it must be refused rather than clobber
    // the change they never saw.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let first = validated_draft(&admin, &editor, &amended_config());

    let mut second_text = amended_config();
    second_text.push_str("tenant id=umbrella\ngrant scope=tenant:umbrella model=* allow=true\n");
    let second = validated_draft(&admin, &editor, &second_text);

    let base = admin.active_config_etag();
    assert_eq!(
        admin
            .post_if_match(&approver, &format!("/admin/v1/policies/{first}:publish"), "{}", &base)
            .status,
        200
    );

    let refused = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{second}:publish"),
        "{}",
        &base,
    );
    assert_eq!(refused.status, 412, "{}", refused.body);
    assert_eq!(refused.error_code.as_deref(), Some("precondition_failed"));
    assert_eq!(activation_frames(&admin).len(), 1);

    let current = admin.active_config_etag();
    assert_eq!(
        admin
            .post_if_match(&approver, &format!("/admin/v1/policies/{second}:publish"), "{}", &current)
            .status,
        200
    );
    assert_eq!(activation_frames(&admin).len(), 2);
}

#[test]
fn the_etag_returned_by_publishing_identifies_the_configuration_it_activated() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let first = validated_draft(&admin, &editor, &amended_config());
    let mut second_text = amended_config();
    second_text.push_str("tenant id=umbrella\ngrant scope=tenant:umbrella model=* allow=true\n");
    let second = validated_draft(&admin, &editor, &second_text);

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{first}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);
    let returned = published.expect_etag();

    assert_eq!(
        returned,
        admin.active_config_etag(),
        "the tag handed back must be the tag the next publish is compared against"
    );

    let next = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{second}:publish"),
        "{}",
        &returned,
    );
    assert_eq!(
        next.status, 200,
        "a client that read the ETag it was given must be able to publish again"
    );
}

#[test]
fn a_refused_publish_does_not_consume_a_configuration_version() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();

    let good = validated_draft(&admin, &editor, &amended_config());
    let bad = validated_draft(&admin, &editor, UNBUILDABLE_CONFIG);

    let before = admin.config().snapshot.version;

    let refused = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{bad}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 400);

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{good}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);
    assert_eq!(
        published.json().field_i64("version").unwrap(),
        i64::try_from(before).unwrap() + 1,
        "configuration versions must run consecutively across a refused publish"
    );
}

#[test]
fn publishing_appears_in_the_audit_view_as_a_policy_publication() {
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);

    let audit = admin.get(&admin.auditor(), "/admin/v1/audit");
    assert_eq!(audit.status, 200);
    let entry = audit
        .data()
        .into_iter()
        .find(|e| e.field_str("action").unwrap_or_default() == "policy_published")
        .expect("the publication must be visible to an auditor");
    assert_eq!(entry.field_str("actor").unwrap(), approver.principal.as_str());
    assert_eq!(entry.opt_field_str("object").unwrap(), Some(id.as_str()));
}

// -- Tenant isolation -------------------------------------------------------

#[test]
fn a_draft_authored_in_another_tenant_is_not_disclosed() {
    let admin = Harness::new();
    let mine = draft(&admin, &admin.policy_editor_in(TENANT_A), &default_config());
    // A draft belonging to the other tenant, planted the way its own editor
    // would have created it.
    let theirs = admin.create_draft_in(
        TENANT_B,
        "user:editor-globex",
        "alias id=globex-private-alias targets=globex-secret-target\n",
    );

    let listed = admin.get(&admin.policy_editor_in(TENANT_A), "/admin/v1/policies");
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.ids(),
        vec![mine],
        "only the caller's own tenant's drafts may be listed"
    );

    let validated = admin.post(
        &admin.policy_editor_in(TENANT_A),
        &format!("/admin/v1/policies/{theirs}:validate"),
        "{}",
    );
    assert_eq!(
        validated.status, 404,
        "another tenant's draft must not exist as far as this caller is concerned"
    );
    assert!(
        !validated.body_contains("globex-secret-target"),
        "the refusal quoted the other tenant's draft: {}",
        validated.body
    );
}

#[test]
fn another_tenants_draft_cannot_be_published() {
    let admin = Harness::new();
    let theirs = admin.create_draft_in(TENANT_B, "user:editor-globex", &amended_config());
    admin
        .state
        .drafts
        .validate(
            &theirs,
            &hypellm_core::ids::TenantId::new(TENANT_B).unwrap(),
            2,
        )
        .expect("their own editor validated it");

    let refused = admin.post_if_match(
        &admin.policy_approver_in(TENANT_A),
        &format!("/admin/v1/policies/{theirs}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(refused.status, 404, "{}", refused.body);
    assert!(activation_frames(&admin).is_empty());
    assert_eq!(admin.config().snapshot.version, 1);
}

// -- Disclosure -------------------------------------------------------------

#[test]
fn no_policy_response_carries_a_session_or_csrf_token() {
    // Specification 5 and 17: nothing that authenticates a caller leaves the
    // process through a response body.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    let responses = [
        admin.post(&editor, "/admin/v1/policies", &draft_body(&default_config())),
        admin.get(&editor, "/admin/v1/policies"),
        admin.post(&editor, &format!("/admin/v1/policies/{id}:validate"), "{}"),
        admin.post(
            &editor,
            &format!("/admin/v1/policies/{id}:simulate"),
            &format!("{{\"model\":\"{ALIAS}\"}}"),
        ),
        admin.post_if_match(
            &approver,
            &format!("/admin/v1/policies/{id}:publish"),
            "{}",
            ANY_ETAG,
        ),
    ];

    for response in &responses {
        assert!(response.is_ok(), "{}", response.body);
        for secret in [
            editor.token.as_str(),
            editor.csrf.as_str(),
            approver.token.as_str(),
            approver.csrf.as_str(),
        ] {
            assert!(
                !response.body_contains(secret),
                "a policy response carried a session credential: {}",
                response.body
            );
        }
    }
}

#[test]
fn the_publish_response_carries_nothing_beyond_the_activation_it_performed() {
    // A narrow response is a security property in its own right: the fewer
    // fields, the fewer chances for one of them to be something the caller was
    // not entitled to.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let approver = admin.policy_approver();
    let id = validated_draft(&admin, &editor, &amended_config());

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        ANY_ETAG,
    );
    assert_eq!(published.status, 200);

    let wire_json::Value::Object(root) = published.json() else {
        panic!("the publish response must be an object");
    };
    let mut fields: Vec<&str> = root.iter().map(|(name, _)| name).collect();
    fields.sort_unstable();
    assert_eq!(fields, vec!["digest", "draft", "version"]);

    // In particular the configuration text itself is not echoed: the response
    // names the digest, and a reader fetches the policy through the endpoints
    // their permissions allow.
    assert!(!published.body_contains("initech"));
    assert!(!published.body_contains("provider-secret"));
}

// -- A second deployment, for the settings a harness cannot vary -------------

/// An API over the harness's own state but with a `DraftStore` that permits an
/// author to approve their own draft.
///
/// Everything else is shared with the harness — the same configuration, the
/// same session store, the same durable log — so the only thing that differs
/// between the two APIs is the setting under test.
fn self_approving_api(admin: &Harness) -> AdminApi {
    let state = Arc::new(AdminState {
        config: Arc::clone(&admin.state.config),
        keys: Arc::clone(&admin.state.keys),
        sessions: Arc::clone(&admin.state.sessions),
        oidc: Arc::clone(&admin.state.oidc),
        oidc_config: None,
        verifier: None,
        health: Arc::clone(&admin.state.health),
        store: Arc::clone(&admin.state.store),
        telemetry: Arc::clone(&admin.state.telemetry),
        clock: Arc::clone(&admin.state.clock),
        cors: CorsPolicy::with_origins(vec![ALLOWED_ORIGIN.to_owned()]),
        decisions: Arc::clone(&admin.state.decisions),
        usage: Arc::clone(&admin.state.usage),
        audit: Arc::clone(&admin.state.audit),
        drafts: DraftStore::with_self_approval(),
        break_glass: None,
        next_version: AtomicU64::new(admin.state.next_version.load(Ordering::SeqCst)),
        credentials: admin.state.credentials.clone(),
    });
    AdminApi::new(state)
}

/// `POST` to an API that is not the harness's, returning status and body.
fn post_to(
    api: &AdminApi,
    path: &str,
    session: &TestSession,
    body: &str,
    if_match: Option<&str>,
) -> (u16, String) {
    let mut headers = Headers::default();
    headers.append("cookie", &session.cookie()).unwrap();
    headers.append(session::CSRF_HEADER, &session.csrf).unwrap();
    headers.append("content-type", "application/json").unwrap();
    if let Some(tag) = if_match {
        headers.append("if-match", tag).unwrap();
    }

    let request_id = "0000000000000000000000000000ffff".to_owned();
    let request = AdminRequest {
        method: &Method::Post,
        path,
        query: None,
        headers: &headers,
        body: body.as_bytes(),
        peer: None,
        request_id: request_id.clone(),
    };

    match api.handle(&request) {
        Ok(response) => (response.status, response.body),
        Err(error) => (error.status(), error.to_json(&request_id)),
    }
}

/// The `id` of a created draft, from a raw response body.
fn parse_id(body: &str) -> String {
    wire_json::parse_str(body, &wire_json::Limits::DEFAULT)
        .expect("a JSON body")
        .field_str("id")
        .expect("an id")
        .to_owned()
}

// -- Rollback (specification 15.3) -------------------------------------------

#[test]
fn a_bad_publication_can_be_rolled_back_by_one_operator() {
    // Specification 15.3 requires the routing-policy screen to offer rollback,
    // and `AuditAction::PolicyRolledBack` has existed since the audit
    // vocabulary was written with no producer. `Activatable::rollback` was
    // likewise implemented and never called, so recovering from a bad publish
    // meant re-publishing the previous configuration as a new draft — which
    // needs a second approver, and therefore could not be done during an
    // incident by whoever happened to be awake.
    let admin = Harness::new();
    let before = admin.config().snapshot.version;

    // Publish something, then roll it back.
    let author = admin.policy_editor();
    let approver = admin.policy_approver();
    let draft_id = validated_draft(&admin, &author, &amended_config());

    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{draft_id}:publish"),
        "{}",
        &admin.active_config_etag(),
    );
    assert_eq!(published.status, 200, "{}", published.body);
    assert!(admin.config().snapshot.version > before);

    // One operator, holding only PublishPolicy.
    let rolled = admin.post_if_match(
        &approver,
        "/admin/v1/policies:rollback",
        r#"{"reason":"the new tenant broke routing, incident 4711"}"#,
        &admin.active_config_etag(),
    );
    assert_eq!(rolled.status, 200, "{}", rolled.body);

    // The restored configuration is active, under a *new* version number: the
    // sequence stays monotonic and an auditor sees the rollback as an event
    // rather than as history rewritten.
    let now = admin.config();
    assert!(
        now.snapshot.version > before + 1,
        "a rollback is an activation, not a rewind of the version counter"
    );
    assert!(
        !now.tenants.contains_key(
            &hypellm_core::ids::TenantId::new("initech").expect("tenant")
        ),
        "the published change must be gone"
    );
}

#[test]
fn a_rollback_is_recorded_with_its_reason() {
    let admin = Harness::new();
    let author = admin.policy_editor();
    let approver = admin.policy_approver();
    let draft_id = validated_draft(&admin, &author, &amended_config());
    let published = admin.post_if_match(
        &approver,
        &format!("/admin/v1/policies/{draft_id}:publish"),
        "{}",
        &admin.active_config_etag(),
    );
    assert_eq!(published.status, 200, "{}", published.body);

    let reason = "routing regression, incident 4711";
    let rolled = admin.post_if_match(
        &approver,
        "/admin/v1/policies:rollback",
        &format!(r#"{{"reason":"{reason}"}}"#),
        &admin.active_config_etag(),
    );
    assert_eq!(rolled.status, 200, "{}", rolled.body);

    let listing = admin.get(&admin.auditor(), "/admin/v1/audit");
    let json = listing.json();
    let record = json
        .field_array("data")
        .expect("a listing")
        .iter()
        .find(|r| r.field_str("action").unwrap_or_default() == "policy_rolled_back")
        .expect("the rollback must be in the audit view");
    assert_eq!(record.opt_field_str("reason").ok().flatten(), Some(reason));
}

#[test]
fn a_rollback_with_nothing_to_restore_is_refused_rather_than_reported_as_done() {
    // A silent no-op reporting success is the worst outcome here: an operator
    // would believe the bad configuration was gone.
    let admin = Harness::new();
    let rolled = admin.post_if_match(
        &admin.policy_approver(),
        "/admin/v1/policies:rollback",
        r#"{"reason":"nothing to undo, incident 4711"}"#,
        &admin.active_config_etag(),
    );
    // `validation_failed` maps to 400 in this API's status table.
    assert_eq!(rolled.status, 400, "{}", rolled.body);
    assert!(
        rolled.body_contains("no previous configuration"),
        "the refusal must say why: {}",
        rolled.body
    );
}

#[test]
fn a_rollback_requires_a_reason_and_the_publish_permission() {
    let admin = Harness::new();

    // No reason.
    let no_reason = admin.post_if_match(
        &admin.policy_approver(),
        "/admin/v1/policies:rollback",
        "{}",
        &admin.active_config_etag(),
    );
    assert_eq!(no_reason.status, 400, "{}", no_reason.body);

    // A session that may read policy but not publish it.
    let unprivileged = admin.post_if_match(
        &admin.viewer(),
        "/admin/v1/policies:rollback",
        r#"{"reason":"an attempt without the permission"}"#,
        &admin.active_config_etag(),
    );
    assert_eq!(unprivileged.status, 403, "{}", unprivileged.body);
}

// -- Live simulation (specifications 15.4, 22.1 step 11) ---------------------

/// A simulation body naming the default alias.
fn scenario_body() -> String {
    format!("{{\"model\":\"{ALIAS}\"}}")
}

#[test]
fn the_active_configuration_can_be_simulated_without_authoring_a_draft() {
    // Specification 22.1 step 11 asks an operator to simulate critical aliases
    // during an incident — about what is running. Requiring a draft made that
    // impossible: you would have had to author a draft of the configuration
    // already live to ask a question about it.
    let admin = Harness::new();
    let response = admin.post(
        &admin.policy_approver(),
        "/admin/v1/policies/active:simulate",
        &scenario_body(),
    );
    assert_eq!(response.status, 200, "{}", response.body);

    let json = response.json();
    assert_eq!(
        json.opt_field_i64("active_version").ok().flatten(),
        i64::try_from(admin.config().snapshot.version).ok(),
        "the answer must say which configuration it was about: {}",
        response.body
    );
    assert!(json.field_str("chosen").is_ok(), "{}", response.body);
}

#[test]
fn a_simulation_says_whether_it_ran_against_live_state_or_ideal() {
    // "No eligible target" means something different in each mode. An operator
    // reading the answer has to know whether that was policy or weather.
    let admin = Harness::new();
    let simulator = admin.policy_approver();

    let ideal = admin.post(
        &simulator,
        "/admin/v1/policies/active:simulate",
        &scenario_body(),
    );
    assert_eq!(
        ideal.json().field_str("live_state").unwrap_or_default(),
        "ideal"
    );

    let live = admin
        .request(Method::Post, "/admin/v1/policies/active:simulate")
        .as_session(&simulator)
        .query("live=true")
        .json(&scenario_body())
        .send();
    assert_eq!(live.status, 200, "{}", live.body);
    assert_eq!(
        live.json().field_str("live_state").unwrap_or_default(),
        "live"
    );
}

#[test]
fn a_live_simulation_sees_a_quarantined_target_and_an_ideal_one_does_not() {
    // The distinction that makes `live=true` worth having. Ideal answers "does
    // policy permit this", which is what a draft review wants — a target that
    // happens to be breaking now should not make a policy look wrong. Live
    // answers "would this work at this moment".
    let admin = Harness::new();
    let simulator = admin.policy_approver();
    let target = TargetId::new(LOCAL_TARGET).expect("target");

    admin
        .state
        .health
        .quarantine(&target, admin.clock.wall_millis() + 60_000);

    let ideal = admin.post(
        &simulator,
        "/admin/v1/policies/active:simulate",
        &scenario_body(),
    );
    let live = admin
        .request(Method::Post, "/admin/v1/policies/active:simulate")
        .as_session(&simulator)
        .query("live=true")
        .json(&scenario_body())
        .send();
    assert_eq!(ideal.status, 200, "{}", ideal.body);
    assert_eq!(live.status, 200, "{}", live.body);

    assert_eq!(
        ideal.json().field_str("chosen").unwrap_or_default(),
        LOCAL_TARGET,
        "an ideal simulation must ignore the quarantine: {}",
        ideal.body
    );

    let live_json = live.json();
    let chosen = live_json.opt_field_str("chosen").ok().flatten();
    assert_ne!(
        chosen,
        Some(LOCAL_TARGET),
        "a live simulation must see the quarantine: {}",
        live.body
    );
    assert!(
        live.body_contains("quarantined") || chosen.is_none(),
        "the exclusion should say why: {}",
        live.body
    );
}

#[test]
fn a_simulation_reserves_nothing_and_contacts_no_provider() {
    // Specification 15.4: "without provider invocation". A live simulation
    // *reads* admission and health state; consuming any would mean simulating
    // could cause the rejection it was investigating.
    let admin = Harness::new();
    let simulator = admin.policy_approver();
    let target = TargetId::new(LOCAL_TARGET).expect("target");
    let before = admin.state.health.entry(&target, Operation::Chat).in_flight();

    for _ in 0..25 {
        let response = admin
            .request(Method::Post, "/admin/v1/policies/active:simulate")
            .as_session(&simulator)
            .query("live=true")
            .json(&scenario_body())
            .send();
        assert_eq!(response.status, 200, "{}", response.body);
    }

    assert_eq!(
        admin.state.health.entry(&target, Operation::Chat).in_flight(),
        before,
        "simulating consumed capacity"
    );
    assert_eq!(
        admin.state.health.entry(&target, Operation::Chat).total_requests(),
        0,
        "simulating counted as a request"
    );
}

// -- Durable drafts (specification 15.3) -------------------------------------

#[test]
fn a_draft_is_recorded_durably_when_it_is_created() {
    // Specification 15.3 and 15.4 describe drafting, validation, simulation,
    // approval, and publication as a workflow. A workflow that loses its state
    // on restart is not one: a draft awaiting a second approver disappeared,
    // and during an incident that means re-authoring a whole configuration
    // under pressure.
    let admin = Harness::new();
    let id = draft(&admin, &admin.policy_editor(), &amended_config());

    let mut log = Log::open(&admin.dir.join("log.bin"), false).expect("open log");
    let replay = log.replay(STORE_MAC_KEY).expect("replay");
    let recorded: Vec<&hypellm_store::Frame> = replay
        .frames
        .iter()
        .filter(|f| f.kind == RecordKind::PolicyDraft)
        .collect();
    assert_eq!(recorded.len(), 1, "the draft must reach the durable log");

    let restored = hypellm_admin_api::Draft::from_payload(&recorded[0].payload)
        .expect("the record must decode");
    assert_eq!(restored.id, id);
    assert_eq!(restored.text, amended_config());
    // Deliberately *not* restored: a stored "valid" verdict replayed across an
    // upgrade would let a draft that no longer builds be published as though it
    // had been checked.
    assert!(!restored.validated);
    assert!(restored.digest.is_none());
}

#[test]
fn a_draft_record_is_protected() {
    // A draft is the text a publication will activate, and publication is the
    // most consequential management action there is. Without frame protection,
    // a draft could be edited on disk between authoring and approval — so the
    // approver reviews one document and publishes another.
    assert!(RecordKind::PolicyDraft.is_protected());
    assert!(RecordKind::PolicyDraftClosed.is_protected());
}

#[test]
fn publishing_a_draft_closes_it_durably() {
    // Otherwise replay would restore a draft that has already been published,
    // presenting a reviewed-and-activated configuration as though it were still
    // awaiting approval.
    let admin = Harness::new();
    let id = validated_draft(&admin, &admin.policy_editor(), &amended_config());
    let published = admin.post_if_match(
        &admin.policy_approver(),
        &format!("/admin/v1/policies/{id}:publish"),
        "{}",
        &admin.active_config_etag(),
    );
    assert_eq!(published.status, 200, "{}", published.body);

    let mut log = Log::open(&admin.dir.join("log.bin"), false).expect("open log");
    let replay = log.replay(STORE_MAC_KEY).expect("replay");
    let closed: Vec<&hypellm_store::Frame> = replay
        .frames
        .iter()
        .filter(|f| f.kind == RecordKind::PolicyDraftClosed)
        .collect();
    assert_eq!(closed.len(), 1, "publication must close the draft durably");
    assert_eq!(
        core::str::from_utf8(&closed[0].payload).expect("utf-8"),
        id
    );

    // And it is gone from the live store.
    assert_eq!(
        admin.get(&admin.policy_editor(), "/admin/v1/policies")
            .json()
            .field_array("data")
            .expect("a listing")
            .len(),
        0,
        "a published draft must not still be listed"
    );
}

#[test]
fn a_restored_draft_must_be_validated_again_and_can_then_be_published() {
    // The round trip that matters: what comes back is usable, and usable only
    // after re-validation.
    let admin = Harness::new();
    let editor = admin.policy_editor();
    let id = validated_draft(&admin, &editor, &amended_config());

    // Rebuild a draft store from the log, the way startup does.
    let store = hypellm_admin_api::DraftStore::new();
    let mut log = Log::open(&admin.dir.join("log.bin"), false).expect("open log");
    for frame in log.replay(STORE_MAC_KEY).expect("replay").frames {
        match frame.kind {
            RecordKind::PolicyDraft => {
                if let Some(d) = hypellm_admin_api::Draft::from_payload(&frame.payload) {
                    store.restore(d);
                }
            }
            RecordKind::PolicyDraftClosed => {
                if let Ok(text) = core::str::from_utf8(&frame.payload) {
                    store.close(text);
                }
            }
            _ => {}
        }
    }

    let tenant = hypellm_core::ids::TenantId::new(TENANT_A).expect("tenant");
    let restored = store.get(&id, &tenant).expect("the draft must come back");
    assert_eq!(restored.text, amended_config());
    assert!(
        !restored.is_valid(),
        "a restored draft must be re-validated rather than trusted"
    );

    // Validating it again makes it publishable, which is the point.
    assert!(store.validate(&id, &tenant, 2).is_some());
    assert!(store.get(&id, &tenant).expect("present").is_valid());
}

#[test]
fn a_restored_identifier_cannot_collide_with_a_new_one() {
    // The allocator is an in-memory counter, so a restart would otherwise reuse
    // identifiers a restored draft already holds — and a create would silently
    // overwrite a draft awaiting approval.
    let store = hypellm_admin_api::DraftStore::new();
    let author = hypellm_core::ids::PrincipalId::new("user:a").expect("principal");
    let tenant = hypellm_core::ids::TenantId::new(TENANT_A).expect("tenant");

    store.restore(hypellm_admin_api::Draft {
        id: "draft_7".to_owned(),
        text: "tenant id=acme\n".to_owned(),
        author: author.clone(),
        tenant: tenant.clone(),
        created_at_millis: 1,
        digest: None,
        errors: Vec::new(),
        validated: false,
    });

    let fresh = store.create("tenant id=acme\n".to_owned(), author, tenant.clone(), 2);
    assert_ne!(fresh.id, "draft_7", "the allocator reused a restored id");
    assert!(store.get("draft_7", &tenant).is_some(), "the restored draft was overwritten");
}
