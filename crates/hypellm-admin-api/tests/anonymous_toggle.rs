//! `POST /admin/v1/settings/anonymous` — the only thing that can switch
//! anonymous inference access on.
//!
//! The design this suite pins is that the configuration document and the
//! switch are separate. The document declares the *subject* — who an
//! uncredentialed caller would be served as — and can never declare *whether*
//! one is served: `anonymous_enabled` is not a settings key, so a file naming
//! it fails to load. The switch is a MAC-protected `AnonymousAccess` frame in
//! the store plus an `AtomicBool` the inference listener reads.
//!
//! What that buys, and what these tests exist to keep:
//!
//! - **Editing a file cannot open the router.** Anyone able to write
//!   `hypellm.conf` can change routing, but not authentication. The
//!   configuration half of that property is asserted in
//!   `crates/hypellm-router/tests/anonymous.rs`; this file asserts the other
//!   half, that the endpoint is the only way in.
//! - **The permission is `manage_settings`, not `manage_credentials`**, even
//!   though the control is rendered on the credentials screen. If the endpoint
//!   followed the screen, a role meant for rotating provider secrets could
//!   disable authentication fleet-wide.
//! - **A response that says it changed is a response after which it changed**,
//!   durably. Every success asserts the `AtomicBool` the request path reads
//!   *and* the frame on disk, because a handler that flipped one without the
//!   other would pass a status-code test and forget on restart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use harness::{Harness, TENANT_A};
use hypellm_store::{Log, RecordKind};

const STORE_MAC_KEY: &[u8] = b"harness-store-mac-key";

/// A configuration that declares an anonymous subject.
///
/// It cannot declare the switch, so a router built from this starts closed no
/// matter what the document says. That is the adversarial part: everything
/// anonymous access needs is present, and a credential is still required.
fn ready_but_off() -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-admin-api-tests default_deadline_ms=5000 \\
         retry_budget_ms=5000 max_attempts=3 \\
         anonymous_principal=svc:public anonymous_tenant={TENANT_A} \\
         anonymous_scopes=inference,models
tenant id={TENANT_A}
tenant id=globex
provider id=local family=openai scheme=http host=127.0.0.1 port=8081 \\
         base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat,embeddings streaming=true tools=true json_mode=true \\
       context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=local:model description=\"the test alias\"
grant scope=tenant:{TENANT_A} model=* allow=true
binding id=default scope=tenant:{TENANT_A} model=* prefer=local:model
"
    )
}

fn body(enabled: bool) -> String {
    format!(r#"{{"enabled":{enabled},"reason":"turning this on for the demo"}}"#)
}

/// The `AnonymousAccess` frames on disk, oldest first.
///
/// Read back from the log file rather than trusted from the handler: the switch
/// is only durable if it is actually there.
fn switch_frames(admin: &Harness) -> Vec<bool> {
    let path = admin.state.store.dir().join("log.bin");
    let mut log = Log::open(&path, false).expect("open the log for reading");
    let replay = log.replay(STORE_MAC_KEY).expect("replay the log");
    replay
        .frames
        .iter()
        .filter(|frame| frame.kind == RecordKind::AnonymousAccess)
        .map(|frame| {
            let text = core::str::from_utf8(&frame.payload).expect("utf-8 payload");
            let value = wire_json::parse_str(text, &wire_json::Limits::SMALL).expect("json");
            value
                .opt_field_bool("enabled")
                .expect("readable")
                .expect("an enabled field")
        })
        .collect()
}

/// Whether the inference listener would serve an uncredentialed request.
fn switched_on(admin: &Harness) -> bool {
    admin
        .state
        .anonymous_access
        .load(std::sync::atomic::Ordering::SeqCst)
}

// ------------------------------------------------------------- permission --

#[test]
fn a_credential_manager_cannot_switch_anonymous_access_on() {
    // The property the placement of this control makes load-bearing. The UI
    // lives on the credentials screen; the authority does not follow it there.
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.credential_manager();

    let response = admin.post(&session, "/admin/v1/settings/anonymous", &body(true));

    assert_eq!(response.status, 403, "body: {}", response.body);
    assert!(!switched_on(&admin), "a refused request must change nothing");
    assert!(switch_frames(&admin).is_empty(), "and must write no frame");
}

#[test]
fn an_unprivileged_session_cannot_switch_anonymous_access_on() {
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.unprivileged();
    let response = admin.post(&session, "/admin/v1/settings/anonymous", &body(true));
    assert_eq!(response.status, 403, "body: {}", response.body);
    assert!(!switched_on(&admin));
}

#[test]
fn an_anonymous_caller_cannot_switch_anonymous_access_on() {
    // The endpoint runs behind session authentication like every other
    // management route. Worth pinning explicitly: an open inference listener
    // must not imply an open management one, and the two planes share a
    // process.
    let admin = Harness::with_config(&ready_but_off());
    let response = admin.anonymous(harness::method_post(), "/admin/v1/settings/anonymous");
    assert!(
        response.status == 401 || response.status == 403,
        "an unauthenticated caller must be refused, got {}: {}",
        response.status,
        response.body
    );
    assert!(!switched_on(&admin));
}

// ----------------------------------------------------------------- switch --

#[test]
fn switching_on_takes_effect_and_is_written_to_disk() {
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    assert!(!switched_on(&admin), "a fresh router starts closed");

    let response = admin.post(&session, "/admin/v1/settings/anonymous", &body(true));
    assert!(response.is_ok(), "body: {}", response.body);

    assert!(
        switched_on(&admin),
        "the flag the inference listener reads must be set"
    );
    assert_eq!(
        switch_frames(&admin),
        vec![true],
        "and the change must be on disk, or it is forgotten on restart"
    );
}

#[test]
fn switching_off_takes_effect_and_is_written_to_disk() {
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    assert!(
        admin
            .post(&session, "/admin/v1/settings/anonymous", &body(true))
            .is_ok()
    );
    let response = admin.post(
        &session,
        "/admin/v1/settings/anonymous",
        r#"{"enabled":false,"reason":"the demo is over"}"#,
    );
    assert!(response.is_ok(), "body: {}", response.body);

    assert!(!switched_on(&admin), "a credential is required again");
    assert_eq!(
        switch_frames(&admin),
        vec![true, false],
        "both edges are recorded; an investigator needs the window, not just its start"
    );
}

#[test]
fn the_configuration_snapshot_is_not_touched_by_the_switch() {
    // The switch is runtime state. If it activated a configuration instead,
    // every toggle would burn a version, rewrite the document, and appear in
    // the policy history as a routing change — and `docker/hypellm.conf` would
    // then disagree with the digest the router reports.
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    let before = admin.config();
    assert!(
        admin
            .post(&session, "/admin/v1/settings/anonymous", &body(true))
            .is_ok()
    );
    let after = admin.config();

    assert_eq!(
        before.snapshot.version, after.snapshot.version,
        "the configuration version must not move"
    );
    assert_eq!(
        before.digest, after.digest,
        "and the document must be byte-identical"
    );
}

#[test]
fn switching_on_without_a_declared_subject_is_refused() {
    // `default_config` declares no anonymous subject, so there is nobody to
    // serve an uncredentialed request as. Refused with a message that says
    // which half is missing, rather than opening the router to a principal the
    // router invented.
    let admin = Harness::with_config(&harness::default_config());
    let session = admin.break_glass();

    let response = admin.post(&session, "/admin/v1/settings/anonymous", &body(true));

    assert_eq!(response.status, 400, "body: {}", response.body);
    assert!(
        response.body.contains("anonymous_principal"),
        "the refusal must name what is missing: {}",
        response.body
    );
    assert!(!switched_on(&admin), "nothing may have been switched on");
    assert!(switch_frames(&admin).is_empty());
}

// -------------------------------------------------------------- guard rails --

#[test]
fn a_change_requires_a_reason_of_usable_length() {
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    for attempt in [
        r#"{"enabled":true}"#,
        r#"{"enabled":true,"reason":""}"#,
        r#"{"enabled":true,"reason":"short"}"#,
    ] {
        let response = admin.post(&session, "/admin/v1/settings/anonymous", attempt);
        assert_eq!(response.status, 400, "`{attempt}` -> {}", response.body);
    }
    assert!(!switched_on(&admin));
    assert!(switch_frames(&admin).is_empty());
}

#[test]
fn a_missing_enabled_field_is_refused_rather_than_defaulted() {
    // Defaulting a missing boolean would make a malformed request a silent
    // "disable": the safe direction, and still the wrong behaviour, because the
    // operator asked for something the router did not do.
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();
    let response = admin.post(
        &session,
        "/admin/v1/settings/anonymous",
        r#"{"reason":"no enabled field at all"}"#,
    );
    assert_eq!(response.status, 400, "body: {}", response.body);
}

#[test]
fn a_no_op_is_refused_rather_than_recorded() {
    // Disabling something already disabled writes a frame and an audit entry
    // that an investigator has to rule out. It is a refusal, not a success.
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    let response = admin.post(
        &session,
        "/admin/v1/settings/anonymous",
        r#"{"enabled":false,"reason":"it is already off"}"#,
    );

    assert_eq!(response.status, 400, "body: {}", response.body);
    assert!(response.body.contains("already disabled"), "{}", response.body);
    assert!(
        switch_frames(&admin).is_empty(),
        "a refused no-op must not have written a frame"
    );
}

// -------------------------------------------------------------------- audit --

#[test]
fn the_change_reaches_the_audit_chain_and_the_log() {
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();
    let before = admin.audit_count();

    assert!(
        admin
            .post(&session, "/admin/v1/settings/anonymous", &body(true))
            .is_ok()
    );

    assert!(
        admin.audit_count() > before,
        "specification 17: a settings change is an audited action"
    );
    let logged = admin.log_lines().join("\n");
    assert!(
        logged.contains("settings.anonymous_access_enabled"),
        "switching on must be logged at critical: {logged}"
    );
}

// ------------------------------------------------------------------ the view --

#[test]
fn the_settings_view_reports_the_switch_and_the_subject() {
    // The screen reads `GET /settings`. If that view did not move with the
    // switch, the operator would press the button and see nothing change.
    let admin = Harness::with_config(&ready_but_off());
    let session = admin.break_glass();

    let before = admin.get(&session, "/admin/v1/settings");
    assert!(before.body_contains(r#""enabled":false"#), "{}", before.body);
    assert!(
        before.body_contains(r#""available":true"#),
        "a declared subject means the switch can be thrown: {}",
        before.body
    );
    assert!(
        before.body_contains("svc:public"),
        "the subject is named whether or not it is in use: {}",
        before.body
    );

    assert!(
        admin
            .post(&session, "/admin/v1/settings/anonymous", &body(true))
            .is_ok()
    );

    let after = admin.get(&session, "/admin/v1/settings");
    assert!(after.body_contains(r#""enabled":true"#), "{}", after.body);
}

#[test]
fn the_settings_view_reports_an_undeclared_subject_as_unavailable() {
    // So the screen can say "there is nobody to serve as" instead of offering a
    // button that answers 400.
    let admin = Harness::with_config(&harness::default_config());
    let session = admin.break_glass();
    let view = admin.get(&session, "/admin/v1/settings");
    assert!(
        view.body_contains(r#""available":false"#),
        "body: {}",
        view.body
    );
}
