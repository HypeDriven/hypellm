//! Point-in-time backup through the control socket (specification 11.2).
//!
//! The property that matters is not "did the command return `Ok`" — it is
//! whether what landed on disk is a *store*. A backup that copies a snapshot
//! without the log boundary, or a log whose frames no longer verify under the
//! state MAC key, reports success and restores nothing; the operator finds out
//! during the incident it was taken for. [`a_backup_reopens_as_a_store`] is the
//! test that would catch that, and it is why these assert on a reopened
//! `Store` rather than on file sizes.

use hypellm_router::startup::backup_state;
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use hypellm_store::{AuditAction, AuditEvent, RecordKind, Store, TempDir};

/// The MAC key `router_with_config` opens its store with.
const STORE_KEY: &[u8] = b"test-store-mac-key";

fn upstream() -> FakeUpstream {
    FakeUpstream::start(CannedResponse::json(200, r#"{"ok":true}"#))
}

/// A router whose `settings` carry `backup_dir` when `destination` is given.
fn router(destination: Option<&std::path::Path>, up: &FakeUpstream) -> TestRouter {
    let backup = destination.map_or_else(String::new, |p| {
        format!(" backup_dir={}", p.display())
    });
    let text = format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 \\
         max_attempts=3{backup}
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat,embeddings streaming=true tools=true json_mode=true \\
       context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=local:model description=\"the test model\"
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
",
        up.address.port()
    );
    router_with_config(up, &text)
}

#[test]
fn a_backup_without_a_configured_destination_is_refused() {
    let up = upstream();
    let router = router(None, &up);

    let refusal = backup_state(&router.state).expect_err("no destination is configured");
    assert!(
        refusal.contains("backup_dir"),
        "the refusal must name the setting an operator has to add, got: {refusal}"
    );

    // And it is a refusal, not a partial action: nothing was recorded as having
    // happened. A command that audits a backup it did not take is a lie in the
    // one record an investigation trusts.
    let records = router.state.store.audit_records(None, 64).expect("read audit");
    assert!(
        !records
            .iter()
            .any(|(_, r)| r.event.action == AuditAction::StateBackedUp),
        "a refused backup must not appear in the audit chain"
    );
}

#[test]
fn a_backup_reopens_as_a_store() {
    let up = upstream();
    let destination = TempDir::new("backup-target");
    let router = router(Some(destination.path()), &up);

    // Durable state worth losing. Written before the backup so the copy has a
    // frame to prove it carried, rather than an empty log that any broken
    // implementation would also produce.
    router
        .state
        .store
        .append(RecordKind::AnonymousAccess, br#"{"enabled":false}"#)
        .expect("append a frame");
    router
        .state
        .store
        .append_audit(AuditEvent::new(1_000, "user:someone", AuditAction::Login))
        .expect("append an audit record");

    let summary = backup_state(&router.state).expect("backup");
    assert!(
        summary.contains("audit_head"),
        "the reply an operator reads must carry the boundary, got: {summary}"
    );

    // The property: what was copied opens as a store under the same MAC key,
    // with the frames intact. `Store::open` verifies every frame and truncates
    // a torn tail, so a copy that lost or corrupted a byte shows up here as a
    // missing record rather than as a silent success.
    let (restored, recovery) = Store::open(destination.path(), STORE_KEY, 0).expect("reopen");
    assert!(
        !recovery.truncated,
        "the copied log ended mid-frame, so the boundary was wrong"
    );
    assert_eq!(
        restored.audit_head(),
        router.state.store.audit_head(),
        "the restored chain must continue from the same head the manifest names"
    );

    let restored_records = restored.audit_records(None, 64).expect("read audit");
    assert!(
        restored_records
            .iter()
            .any(|(_, r)| r.event.action == AuditAction::Login),
        "the copy lost an audit record that was durable before it ran"
    );
    assert!(
        restored_records
            .iter()
            .any(|(_, r)| r.event.action == AuditAction::StateBackedUp),
        "the backup must record itself: the copy is evidence of who took it"
    );
    assert!(
        restored
            .records_of_kinds(&[RecordKind::AnonymousAccess])
            .expect("read frames")
            .len()
            == 1,
        "the copy lost a non-audit frame"
    );
}

#[test]
fn a_backup_leaves_a_manifest_naming_its_boundary() {
    let up = upstream();
    let destination = TempDir::new("backup-manifest");
    let router = router(Some(destination.path()), &up);
    router
        .state
        .store
        .append_audit(AuditEvent::new(1, "user:someone", AuditAction::Login))
        .expect("append");

    backup_state(&router.state).expect("backup");

    let manifest = std::fs::read_to_string(destination.path().join("backup.manifest"))
        .expect("the manifest is written beside the copy");
    let head = hypellm_crypto::hex::encode(&router.state.store.audit_head());
    assert!(
        manifest.contains(&format!("audit_head {head}")),
        "a restore has no way to tell what boundary it holds; manifest was:\n{manifest}"
    );
    assert!(
        manifest
            .lines()
            .any(|l| l.starts_with("sequence ") && l != "sequence 0"),
        "the manifest must name the sequence the copy stops at; manifest was:\n{manifest}"
    );
}
