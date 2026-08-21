//! The read-only management surface: overview, catalogue, usage, audit, and
//! decision traces (specification 15.3, 16, and 17).
//!
//! These six endpoints are the ones an operator stares at all day, which makes
//! them the ones an attacker reads first. Three properties matter more than any
//! field name:
//!
//! * **Permission.** Each endpoint names one permission. A session that lacks
//!   it must get a refusal, never a partial answer.
//! * **Tenant.** Appendix B: "Management visibility never exceeds the caller's
//!   tenant and permissions." Usage, audit, and decision traces are per-tenant
//!   records, so a caller in one tenant must not see a row, a total, or even
//!   the existence of a request belonging to another.
//! * **Honesty.** A screen that reports a number the router does not hold is
//!   worse than no screen: the audit chain length, the healthy-target count and
//!   the usage totals are all read back from the state that produced them, so
//!   the tests read that state directly and compare.
//!
//! Specification 17 adds a fourth for the decision explorer specifically: a
//! trace carries "policy digest, candidates, exclusion reason codes, integer
//! score terms, reservations, attempts" — and nothing else. No prompt, no
//! credential, no upstream URL. `hypellm_core::decision` says so in its own
//! module header; this suite proves the JSON keeps the promise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use hypellm_admin_api::handlers::CredentialSink;
use hypellm_admin_api::{UsageSample, UsageStatus};
use hypellm_core::canonical::{CostClass, Operation};
use hypellm_core::decision::{
    Attempt, AttemptOutcome, Candidate, DecisionTrace, Exclusion, ExclusionReason, ScoreTerms,
};
use hypellm_core::event::{CanonicalUsage, UpstreamErrorClass};
use hypellm_core::ids::{AliasId, CredentialRef, PrincipalId, RequestId, TargetId, TenantId};
use hypellm_core::time::Clock;
use hypellm_store::AuditAction;
use harness::{ALIAS, CREDENTIAL, Harness, LOCAL_TARGET, REMOTE_TARGET, TENANT_A, TENANT_B};
use wire_http1::Method;
use wire_json::Value;

/// The host the remote provider is configured to reach. It must never appear in
/// a decision trace (specification 17).
const PROVIDER_HOST: &str = "api.provider.test";

/// A value distinguishable from anything else in a response, planted in the
/// credential sink so that a disclosure test has something specific to look for.
const SECRET_VALUE: &str = "sk-live-DO-NOT-DISCLOSE-9f3c1a";

/// Every read endpoint this suite covers.
const READ_ENDPOINTS: [&str; 6] = [
    "/admin/v1/overview",
    "/admin/v1/providers",
    "/admin/v1/aliases",
    "/admin/v1/usage",
    "/admin/v1/audit",
    "/admin/v1/decisions/00000000000000000000000000000001",
];

// -- Helpers ----------------------------------------------------------------

/// Put a secret behind the configured credential reference.
///
/// Nothing in the management API may hand it back: the reference is the name of
/// a secret, and only an adapter ever resolves one (specification 9.3).
fn plant_credential_secret(admin: &Harness) {
    let reference = CredentialRef::new(CREDENTIAL).expect("a valid credential reference");
    admin
        .credentials
        .store(&reference, SECRET_VALUE.as_bytes().to_vec())
        .expect("the sink accepts a secret");
}

/// Collect every string that appears anywhere in a JSON document, keys and
/// values alike.
///
/// A leak that hid in the fourth element of a nested array would still be a
/// leak, so the disclosure tests look at the whole tree rather than the fields
/// they happen to remember.
fn all_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                all_strings(item, out);
            }
        }
        Value::Object(object) => {
            for (key, item) in object.iter() {
                out.push(key.to_owned());
                all_strings(item, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The top-level field names of a response object, in order.
fn top_level_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .expect("a JSON object")
        .iter()
        .map(|(key, _)| key.to_owned())
        .collect()
}

/// A trace with something in every collection, so a redaction test has real
/// candidates, exclusions, and attempts to inspect rather than empty arrays.
fn detailed_trace(admin: &Harness, id: u128) -> DecisionTrace {
    let local = TargetId::new(LOCAL_TARGET).expect("a valid target");
    let remote = TargetId::new(REMOTE_TARGET).expect("a valid target");
    DecisionTrace {
        request_id: RequestId::from_u128(id),
        policy_digest: admin.config().digest,
        candidates: vec![
            Candidate {
                target: local.clone(),
                terms: ScoreTerms {
                    priority_rank: ScoreTerms::rank_term(0),
                    policy_weight: 1_000,
                    health: -500,
                    latency: -250,
                    queue: -125,
                    cost: 0,
                    locality: 5_000,
                    affinity: 0,
                    jitter: 17,
                },
                binding_precedence: 3,
                rank: 0,
                pin_rank: Candidate::PIN_TARGET,
                residency: Default::default(),
            },
            Candidate {
                target: remote.clone(),
                terms: ScoreTerms {
                    priority_rank: ScoreTerms::rank_term(1),
                    cost: -5_000,
                    ..ScoreTerms::default()
                },
                binding_precedence: 3,
                rank: 1,
                pin_rank: Candidate::PIN_TARGET,
                residency: Default::default(),
            },
        ],
        exclusions: vec![Exclusion {
            target: remote.clone(),
            reason: ExclusionReason::ResidencyMismatch,
        }],
        chosen: Some(local.clone()),
        attempts: vec![
            Attempt {
                target: remote,
                sequence: 0,
                first_byte_millis: None,
                total_millis: 120,
                outcome: AttemptOutcome::FailedBeforeAcceptance(UpstreamErrorClass::Connection),
            },
            Attempt {
                target: local,
                sequence: 1,
                first_byte_millis: Some(40),
                total_millis: 900,
                outcome: AttemptOutcome::Success,
            },
        ],
        routing_micros: 137,
        pinned: false,
    }
}

/// Record one usage sample with full control over its provenance.
fn record_sample(admin: &Harness, tenant: &str, principal: &str, usage: CanonicalUsage) {
    let sample = UsageSample {
        tenant: TenantId::new(tenant).expect("a valid tenant"),
        principal: PrincipalId::new(principal).expect("a valid principal"),
        alias: AliasId::new(ALIAS).expect("a valid alias"),
        target: TargetId::new(LOCAL_TARGET).ok(),
        operation: Operation::Chat,
        status: UsageStatus::Success,
        cost_class: CostClass::new(1),
        usage,
        key_id: None,
    };
    admin.state.usage.record(&sample, admin.clock.now_millis());
}

// -- Overview ---------------------------------------------------------------

#[test]
fn the_overview_refuses_a_session_that_does_not_hold_read_summary() {
    // Specification 16 puts the overview behind `ReadSummary`. A session with
    // no role is authenticated but authorized for nothing, and must learn
    // nothing about the deployment from the refusal.
    let admin = Harness::new();
    let nobody = admin.unprivileged();

    let response = admin.get(&nobody, "/admin/v1/overview");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains("targets_total"), "{}", response.body);
}

#[test]
fn the_overview_counts_agree_with_the_active_configuration() {
    // The overview is the first screen an operator reads; a count that came
    // from anywhere but the live snapshot would make it fiction.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/overview");

    assert_eq!(response.status, 200, "{}", response.body);
    let body = response.json();
    let config = admin.config();
    assert_eq!(
        body.field_i64("config_version").unwrap(),
        i64::try_from(config.snapshot.version).unwrap()
    );
    assert_eq!(
        body.field_i64("targets_total").unwrap(),
        i64::try_from(config.snapshot.targets.len()).unwrap()
    );
    assert_eq!(
        body.field_i64("providers").unwrap(),
        i64::try_from(config.snapshot.providers.len()).unwrap()
    );
    assert_eq!(
        body.field_i64("aliases").unwrap(),
        i64::try_from(config.snapshot.aliases.len()).unwrap()
    );
    // Healthy plus degraded must account for every target, or a target has
    // fallen out of the health view entirely.
    let healthy = body.field_i64("targets_healthy").unwrap();
    let degraded = body.field_i64("targets_degraded").unwrap();
    assert_eq!(
        healthy + degraded,
        i64::try_from(config.snapshot.targets.len()).unwrap()
    );
    assert_eq!(degraded, 0, "nothing is unhealthy in a fresh harness");
}

#[test]
fn a_quarantined_target_is_reported_as_degraded_rather_than_healthy() {
    // Specification 13: a quarantine takes a target out of service. An overview
    // that still called it healthy would hide the outage it caused.
    let admin = Harness::new();
    let viewer = admin.viewer();
    let target = TargetId::new(LOCAL_TARGET).unwrap();

    let before = admin.get(&viewer, "/admin/v1/overview");
    assert_eq!(before.json().field_i64("targets_degraded").unwrap(), 0);

    admin
        .state
        .health
        .quarantine(&target, admin.clock.wall_millis() + 3_600_000);

    let after = admin.get(&viewer, "/admin/v1/overview");
    assert_eq!(after.json().field_i64("targets_degraded").unwrap(), 1);
    assert_eq!(
        after.json().field_i64("targets_healthy").unwrap(),
        before.json().field_i64("targets_healthy").unwrap() - 1
    );
}

#[test]
fn the_overview_reports_the_length_of_the_durable_audit_chain() {
    // The audit counter is an integrity signal: an operator compares it with
    // what they expect to have happened. It must track the store, not a cache.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let before = admin.get(&viewer, "/admin/v1/overview");
    let counted = before.json().field_i64("audit_records").unwrap();
    assert_eq!(counted, i64::try_from(admin.audit_count()).unwrap());

    admin.record_audit(TENANT_A, "user:someone", AuditAction::TargetStateChanged, LOCAL_TARGET);
    admin.record_audit(TENANT_A, "user:someone", AuditAction::TargetStateChanged, LOCAL_TARGET);

    let after = admin.get(&viewer, "/admin/v1/overview");
    assert_eq!(after.json().field_i64("audit_records").unwrap(), counted + 2);
    assert_eq!(
        after.json().field_i64("audit_records").unwrap(),
        i64::try_from(admin.audit_count()).unwrap()
    );
}

#[test]
fn the_overview_shows_only_a_truncated_digest_of_the_policy_and_the_audit_head() {
    // Specification 17 bounds what a display field carries. A short digest is
    // enough to tell two snapshots apart on a screen; the full one belongs to
    // the audit envelope, which is what an integrity check reads.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/overview");

    let digest = response.str_field("config_digest");
    assert_eq!(digest, admin.config().digest.short());
    assert_eq!(digest.len(), 12, "a short digest is 6 bytes of hex");
    assert_eq!(response.str_field("audit_head").len(), 12);
}

#[test]
fn the_overview_discloses_no_credential_secret() {
    let admin = Harness::new();
    plant_credential_secret(&admin);
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/overview");

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(!response.body_contains(SECRET_VALUE), "{}", response.body);
}

#[test]
fn the_overview_does_not_reveal_how_many_other_tenants_the_router_serves() {
    let admin = Harness::new();
    let viewer = admin.viewer();
    // The fixture has to actually have something to leak, or the assertion
    // below holds for the wrong reason.
    assert_eq!(
        admin.config().tenants.len(),
        2,
        "the deployment must serve more than the caller's own tenant"
    );

    let response = admin.get(&viewer, "/admin/v1/overview");

    // A caller scoped to one tenant should be told about one, or not told at
    // all. No tenant name may appear either way.
    match response.json().opt_field_i64("tenants").unwrap() {
        None => {}
        Some(count) => assert_eq!(count, 1, "the caller's own tenant, and no other"),
    }
    assert!(
        !response.body_contains(TENANT_B),
        "the overview named another tenant: {}",
        response.body
    );
}

// -- Catalogue: providers and aliases ---------------------------------------

#[test]
fn listing_providers_refuses_a_session_that_does_not_hold_read_summary() {
    let admin = Harness::new();
    let nobody = admin.unprivileged();

    let response = admin.get(&nobody, "/admin/v1/providers");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains(PROVIDER_HOST), "{}", response.body);
}

#[test]
fn the_provider_list_names_the_credential_reference_but_never_its_secret() {
    // Specification 9.3: a credential is reachable only through an opaque
    // handle, resolved inside the adapter. The management API may say which
    // handle a provider uses; it may never resolve one.
    let admin = Harness::new();
    plant_credential_secret(&admin);
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/providers");

    assert_eq!(response.status, 200, "{}", response.body);
    let remote = response
        .data()
        .into_iter()
        .find(|p| p.field_str("id").unwrap() == "remote")
        .expect("the remote provider is listed");
    assert_eq!(remote.field_str("credential_ref").unwrap(), CREDENTIAL);
    assert!(!response.body_contains(SECRET_VALUE), "{}", response.body);

    // The local provider has no credential at all, and must not acquire one in
    // the rendering.
    let local = response
        .data()
        .into_iter()
        .find(|p| p.field_str("id").unwrap() == "local")
        .expect("the local provider is listed");
    assert!(local.opt_field_str("credential_ref").unwrap().is_none());
}

#[test]
fn the_provider_list_reports_the_egress_profile_that_governs_each_provider() {
    // Specification 10 makes the egress profile the thing that decides whether
    // a destination may leave the machine. An operator auditing data flow reads
    // it here, so it must come from the configuration rather than be inferred.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/providers");

    let mut seen: Vec<(String, String)> = response
        .data()
        .iter()
        .map(|p| {
            (
                p.field_str("id").unwrap().to_owned(),
                p.field_str("egress_profile").unwrap().to_owned(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("local".to_owned(), "local".to_owned()),
            ("remote".to_owned(), "remote".to_owned())
        ]
    );

    let remote = response
        .data()
        .into_iter()
        .find(|p| p.field_str("id").unwrap() == "remote")
        .expect("the remote provider is listed");
    let endpoints = remote.field_array("endpoints").unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].field_str("host").unwrap(), PROVIDER_HOST);
    assert_eq!(endpoints[0].field_i64("port").unwrap(), 443);
}

#[test]
fn listing_aliases_refuses_a_session_that_does_not_hold_read_summary() {
    let admin = Harness::new();
    let nobody = admin.unprivileged();

    let response = admin.get(&nobody, "/admin/v1/aliases");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains(ALIAS), "{}", response.body);
}

#[test]
fn the_alias_list_reports_exactly_the_targets_an_alias_may_reach() {
    // The permitted-target set is an eligibility filter (specification 6.2), so
    // an operator debugging "why did it not go there" needs it to be the real
    // set and not a summary of it.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/aliases");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.ids(), vec![ALIAS.to_owned()]);
    let alias = &response.data()[0];
    let mut targets: Vec<&str> = alias
        .field_array("targets")
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    targets.sort_unstable();
    assert_eq!(targets, vec![LOCAL_TARGET, REMOTE_TARGET]);
    assert_eq!(
        alias.field_str("description").unwrap(),
        "the test alias",
        "the configured description, not a generated one"
    );
}

// -- Authentication ---------------------------------------------------------

#[test]
fn every_observability_endpoint_refuses_an_unauthenticated_caller() {
    // Specification 16: the whole management surface sits behind a session.
    // One endpoint added later without one would be the whole breach.
    let admin = Harness::new();
    plant_credential_secret(&admin);
    admin.record_usage(TENANT_A, "user:viewer-acme", 10, 20);
    admin.record_audit(TENANT_A, "user:someone", AuditAction::KeyCreated, "key_x");
    let _ = admin.record_decision(TENANT_A, 1);

    for path in READ_ENDPOINTS {
        let response = admin.anonymous(Method::Get, path);
        assert_eq!(response.status, 401, "{path} answered {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("unauthenticated"), "{path}");
        assert!(!response.body_contains(LOCAL_TARGET), "{path}: {}", response.body);
        assert!(!response.body_contains(SECRET_VALUE), "{path}: {}", response.body);
    }
}

// -- Usage ------------------------------------------------------------------

#[test]
fn usage_refuses_a_caller_holding_neither_usage_permission() {
    // An auditor holds `ReadAudit` and `ExportAudit` but neither usage
    // permission: an audit role is not a billing role.
    let admin = Harness::new();
    admin.record_usage(TENANT_A, "user:auditor-acme", 100, 200);
    let auditor = admin.auditor();

    let response = admin.get(&auditor, "/admin/v1/usage");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains("input_tokens"), "{}", response.body);
}

#[test]
fn a_viewer_sees_only_their_own_usage_and_is_told_the_scope_is_their_own() {
    // Specification 15.3 scopes the usage screen to what the caller is
    // authorized for. `ReadOwnUsage` is one principal's rows — and the response
    // says so, so a viewer cannot mistake their own totals for the tenant's.
    let admin = Harness::new();
    let viewer = admin.viewer();
    admin.record_usage(TENANT_A, viewer.principal.as_str(), 10, 20);
    admin.record_usage(TENANT_A, "user:someone-else", 5_000, 6_000);

    let response = admin.get(&viewer, "/admin/v1/usage");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.str_field("scope"), "principal");
    assert_eq!(response.str_field("tenant"), TENANT_A);
    let rows = response.data();
    assert_eq!(rows.len(), 1, "{}", response.body);
    assert_eq!(rows[0].field_str("principal").unwrap(), viewer.principal.as_str());
    assert!(!response.body_contains("user:someone-else"), "{}", response.body);

    // The totals must agree with the rows shown, or the screen has added
    // another principal's tokens into this one's bill.
    let totals = response.json().opt_field_object("totals").unwrap().unwrap().clone();
    assert_eq!(totals.get("input_tokens").unwrap().as_u64().unwrap(), 10);
    assert_eq!(totals.get("output_tokens").unwrap().as_u64().unwrap(), 20);
    assert_eq!(totals.get("requests").unwrap().as_u64().unwrap(), 1);
}

#[test]
fn an_operator_sees_every_principal_in_their_own_tenant() {
    let admin = Harness::new();
    admin.record_usage(TENANT_A, "user:alice", 10, 20);
    admin.record_usage(TENANT_A, "user:bob", 1, 2);
    let operator = admin.operator();

    let response = admin.get(&operator, "/admin/v1/usage");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.str_field("scope"), "tenant");
    let rows = response.data();
    let mut principals: Vec<&str> = rows
        .iter()
        .map(|row| row.field_str("principal").unwrap())
        .collect();
    principals.sort_unstable();
    assert_eq!(principals, vec!["user:alice", "user:bob"]);
    let totals = response.json().opt_field_object("totals").unwrap().unwrap().clone();
    assert_eq!(totals.get("input_tokens").unwrap().as_u64().unwrap(), 11);
    assert_eq!(totals.get("output_tokens").unwrap().as_u64().unwrap(), 22);
}

#[test]
fn usage_never_crosses_a_tenant_boundary_even_for_a_tenant_wide_reader() {
    // Appendix B. `ReadTenantUsage` is the widest usage permission there is,
    // and it still stops at the caller's own tenant.
    let admin = Harness::new();
    admin.record_usage(TENANT_A, "user:alice", 10, 20);
    admin.record_usage(TENANT_B, "user:mallory", 999_999, 999_999);
    let operator_a = admin.operator_in(TENANT_A);
    let operator_b = admin.operator_in(TENANT_B);

    let a = admin.get(&operator_a, "/admin/v1/usage");
    assert_eq!(a.str_field("tenant"), TENANT_A);
    assert_eq!(a.data().len(), 1, "{}", a.body);
    assert!(!a.body_contains("user:mallory"), "{}", a.body);
    assert!(!a.body_contains("999999"), "{}", a.body);

    let b = admin.get(&operator_b, "/admin/v1/usage");
    assert_eq!(b.str_field("tenant"), TENANT_B);
    assert_eq!(b.data().len(), 1, "{}", b.body);
    assert!(!b.body_contains("user:alice"), "{}", b.body);

    // And each tenant's totals cover only its own rows.
    let a_totals = a.json().opt_field_object("totals").unwrap().unwrap().clone();
    assert_eq!(a_totals.get("input_tokens").unwrap().as_u64().unwrap(), 10);
}

#[test]
fn usage_reports_which_requests_were_router_estimated_rather_than_provider_reported() {
    // Specification 14: the two provenances must stay distinguishable. A screen
    // that silently added them would let an estimate be read as a bill.
    let admin = Harness::new();
    let viewer = admin.viewer();
    let principal = viewer.principal.as_str();
    record_sample(&admin, TENANT_A, principal, CanonicalUsage::reported(10, 20));
    record_sample(&admin, TENANT_A, principal, CanonicalUsage::estimated(30, 40));

    let response = admin.get(&viewer, "/admin/v1/usage");

    let rows = response.data();
    assert_eq!(rows.len(), 1, "the same dimensions fold into one row");
    assert_eq!(rows[0].field_i64("requests").unwrap(), 2);
    assert_eq!(rows[0].field_i64("input_tokens").unwrap(), 40);
    assert_eq!(
        rows[0].field_i64("estimated_requests").unwrap(),
        1,
        "one of the two requests carried an estimate"
    );
    assert!(!rows[0].opt_field_bool("aggregated").unwrap().unwrap());
}

#[test]
fn usage_states_when_its_counters_started_so_totals_are_not_read_as_all_time() {
    // The aggregate is in memory and starts at the first sample after a
    // restart. A total with no window is a number an operator cannot use.
    let admin = Harness::new();
    admin.advance(1_000);
    let viewer = admin.viewer();
    admin.record_usage(TENANT_A, viewer.principal.as_str(), 1, 1);

    let response = admin.get(&viewer, "/admin/v1/usage");

    assert_eq!(response.json().field_i64("since").unwrap(), 1_000);
    assert_eq!(
        response.json().opt_field_bool("truncated").unwrap(),
        Some(false),
        "nothing was folded into an unattributed remainder"
    );
}

#[test]
fn a_usage_reader_is_never_handed_a_credential_or_a_session_token() {
    let admin = Harness::new();
    plant_credential_secret(&admin);
    let operator = admin.operator();
    admin.record_usage(TENANT_A, operator.principal.as_str(), 7, 7);

    let response = admin.get(&operator, "/admin/v1/usage");

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(!response.body_contains(SECRET_VALUE), "{}", response.body);
    assert!(!response.body_contains(&operator.token), "{}", response.body);
    assert!(!response.body_contains(&operator.csrf), "{}", response.body);
}

// -- Audit ------------------------------------------------------------------

#[test]
fn the_audit_view_refuses_a_caller_that_does_not_hold_read_audit() {
    // An operator can quarantine a target but cannot read the audit log: that
    // separation is the point of the auditor role (specification 9.2).
    let admin = Harness::new();
    admin.record_audit(TENANT_A, "user:someone", AuditAction::KeyCreated, "key_secret_name");
    let operator = admin.operator();

    let response = admin.get(&operator, "/admin/v1/audit");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains("key_secret_name"), "{}", response.body);
}

#[test]
fn the_audit_view_shows_only_records_belonging_to_the_callers_tenant() {
    // Appendix B, and the reason `recent_for_tenant` exists: an auditor holding
    // `ReadAudit` in one tenant must not read another tenant's history.
    let admin = Harness::new();
    admin.record_audit(TENANT_A, "user:alice", AuditAction::TargetStateChanged, "object-a");
    admin.record_audit(TENANT_B, "user:mallory", AuditAction::PolicyPublished, "object-b");
    let auditor_a = admin.auditor_in(TENANT_A);
    let auditor_b = admin.auditor_in(TENANT_B);

    let a = admin.get(&auditor_a, "/admin/v1/audit");
    assert_eq!(a.status, 200, "{}", a.body);
    let a_rows = a.data();
    let objects: Vec<&str> = a_rows
        .iter()
        .map(|r| r.field_str("object").unwrap())
        .collect();
    assert_eq!(objects, vec!["object-a"]);
    assert!(!a.body_contains("user:mallory"), "{}", a.body);
    assert!(!a.body_contains("object-b"), "{}", a.body);

    let b = admin.get(&auditor_b, "/admin/v1/audit");
    let b_rows = b.data();
    let objects: Vec<&str> = b_rows
        .iter()
        .map(|r| r.field_str("object").unwrap())
        .collect();
    assert_eq!(objects, vec!["object-b"]);
    assert!(!b.body_contains("object-a"), "{}", b.body);
}

#[test]
fn the_audit_view_reports_the_actor_action_object_and_chain_link_of_each_record() {
    // Specification 15.3's audit screen is "actor/action/object/result" plus an
    // integrity checkpoint. Each field must come from the appended event.
    let admin = Harness::new();
    admin.record_audit(TENANT_A, "user:alice", AuditAction::TargetQuarantined, LOCAL_TARGET);
    let auditor = admin.auditor();

    let response = admin.get(&auditor, "/admin/v1/audit");

    let rows = response.data();
    assert_eq!(rows.len(), 1, "{}", response.body);
    let row = &rows[0];
    assert_eq!(row.field_str("actor").unwrap(), "user:alice");
    assert_eq!(
        row.field_str("action").unwrap(),
        AuditAction::TargetQuarantined.as_str()
    );
    assert_eq!(row.field_str("object").unwrap(), LOCAL_TARGET);
    assert_eq!(row.field_str("tenant").unwrap(), TENANT_A);
    assert_eq!(row.field_str("outcome").unwrap(), "success");
    assert!(
        row.field_i64("sequence").unwrap() >= 0,
        "the store sequence the record was written at"
    );
    assert_eq!(
        row.field_str("link").unwrap().len(),
        12,
        "a per-record chain link, truncated for display"
    );
    // A timestamp the record actually carries, not a placeholder.
    assert!(
        row.field_str("timestamp").unwrap().starts_with("2026-"),
        "{}",
        row.field_str("timestamp").unwrap()
    );
}

#[test]
fn the_audit_envelope_carries_the_chain_head_and_length_of_the_durable_log() {
    // The head and length are how an operator (or an external verifier) checks
    // that nothing was removed. They come from the store, not from the bounded
    // in-memory view, so they stay right even once the view has rolled over.
    let admin = Harness::new();
    admin.record_audit(TENANT_A, "user:alice", AuditAction::KeyCreated, "key_1");
    let auditor = admin.auditor();

    let response = admin.get(&auditor, "/admin/v1/audit");

    assert_eq!(response.status, 200, "{}", response.body);
    let head = response.str_field("chain_head");
    assert_eq!(head.len(), 64, "the full 32-byte head, not a display prefix");
    assert!(head.chars().all(|c| c.is_ascii_hexdigit()), "{head}");
    assert_eq!(
        response.json().field_i64("chain_length").unwrap(),
        i64::try_from(admin.audit_count()).unwrap()
    );
}

#[test]
fn the_audit_chain_head_advances_when_a_record_is_appended() {
    // A head that did not move would make the integrity check vacuous.
    let admin = Harness::new();
    let auditor = admin.auditor();
    admin.record_audit(TENANT_A, "user:alice", AuditAction::KeyCreated, "key_1");
    let first = admin.get(&auditor, "/admin/v1/audit");

    admin.record_audit(TENANT_A, "user:alice", AuditAction::KeyRevoked, "key_1");
    let second = admin.get(&auditor, "/admin/v1/audit");

    assert_ne!(
        first.str_field("chain_head"),
        second.str_field("chain_head")
    );
    assert_eq!(
        second.json().field_i64("chain_length").unwrap(),
        first.json().field_i64("chain_length").unwrap() + 1
    );
    assert_eq!(second.data().len(), 2);
}

#[test]
fn an_oversized_audit_page_request_is_clamped_rather_than_honoured() {
    // Specification 3.2: nothing a request asks for may be unbounded. A caller
    // asking for a hundred thousand records gets a page, not a heap.
    let admin = Harness::new();
    for n in 0..520u32 {
        admin.record_audit(
            TENANT_A,
            "user:alice",
            AuditAction::TargetStateChanged,
            &format!("object-{n}"),
        );
    }
    let auditor = admin.auditor();

    let response = admin.get_query(&auditor, "/admin/v1/audit", "limit=100000");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.data().len(),
        500,
        "the maximum page, not everything held"
    );
}

#[test]
fn an_audit_limit_that_is_zero_or_not_a_number_falls_back_to_a_bounded_page() {
    // A clamp that let zero through would return an empty screen, and one that
    // let a malformed value through would return whatever the parser produced.
    let admin = Harness::new();
    for n in 0..60u32 {
        admin.record_audit(
            TENANT_A,
            "user:alice",
            AuditAction::TargetStateChanged,
            &format!("object-{n}"),
        );
    }
    let auditor = admin.auditor();

    assert_eq!(
        admin.get_query(&auditor, "/admin/v1/audit", "limit=0").data().len(),
        1,
        "a zero page is clamped up to one, not down to nothing"
    );
    assert_eq!(
        admin
            .get_query(&auditor, "/admin/v1/audit", "limit=not-a-number")
            .data()
            .len(),
        50,
        "an unparseable limit falls back to the default page"
    );
    assert_eq!(
        admin.get_query(&auditor, "/admin/v1/audit", "limit=-5").data().len(),
        50,
        "a negative limit is not a usize and falls back to the default page"
    );
    assert_eq!(
        admin.get_query(&auditor, "/admin/v1/audit", "limit=7").data().len(),
        7
    );
}

#[test]
fn an_action_taken_through_the_management_api_appears_in_the_audit_view() {
    let admin = Harness::new();
    let operator = admin.operator();
    let auditor = admin.auditor();

    let patched = admin.patch(
        &operator,
        &format!("/admin/v1/targets/{LOCAL_TARGET}"),
        r#"{"state":"draining","reason":"planned maintenance"}"#,
        harness::ANY_ETAG,
    );
    assert_eq!(patched.status, 200, "{}", patched.body);

    let response = admin.get(&auditor, "/admin/v1/audit");
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        response.json().field_i64("chain_length").unwrap() > 0,
        "the record reached the durable chain"
    );
    let rows = response.data();
    assert_eq!(rows.len(), 1, "the change is visible to the auditor");
    assert_eq!(rows[0].field_str("object").unwrap(), LOCAL_TARGET);
    assert_eq!(
        rows[0].field_str("action").unwrap(),
        AuditAction::TargetStateChanged.as_str()
    );
    assert_eq!(rows[0].field_str("actor").unwrap(), operator.principal.as_str());
    assert_eq!(rows[0].field_str("tenant").unwrap(), TENANT_A);
    assert_eq!(rows[0].field_str("reason").unwrap(), "planned maintenance");
    // The synthesized event this guards against carried timestamp 0, which
    // renders as 1970 on the screen an operator reads.
    assert!(
        rows[0].field_str("timestamp").unwrap().starts_with("2026-"),
        "the indexed record is not the one that was appended: {}",
        rows[0].field_str("timestamp").unwrap()
    );
}

#[test]
fn the_audit_view_can_reach_records_older_than_a_single_page() {
    let admin = Harness::new();
    for n in 0..6u32 {
        admin.record_audit(
            TENANT_A,
            "user:alice",
            AuditAction::TargetStateChanged,
            &format!("object-{n}"),
        );
    }
    let auditor = admin.auditor();

    let first = admin.get_query(&auditor, "/admin/v1/audit", "limit=3");
    assert_eq!(first.data().len(), 3);
    let cursor = first
        .json()
        .opt_field_str("next_cursor")
        .unwrap()
        .expect("a cursor onto the next page")
        .to_owned();

    let second = admin.get_query(&auditor, "/admin/v1/audit", &format!("limit=3&after={cursor}"));
    let first_objects: Vec<String> = first
        .data()
        .iter()
        .map(|r| r.field_str("object").unwrap().to_owned())
        .collect();
    let second_objects: Vec<String> = second
        .data()
        .iter()
        .map(|r| r.field_str("object").unwrap().to_owned())
        .collect();
    assert_eq!(second_objects.len(), 3);
    for object in &second_objects {
        assert!(!first_objects.contains(object), "{object} was already shown");
    }
    // Between them the two pages account for every record, and the last page
    // says there is no more — a cursor that skipped records would pass the
    // disjointness check above on its own.
    let mut seen: Vec<String> = first_objects;
    seen.extend(second_objects);
    seen.sort();
    let expected: Vec<String> = (0..6u32).map(|n| format!("object-{n}")).collect();
    assert_eq!(seen, expected);
    assert_eq!(first.json().opt_field_bool("has_more").unwrap(), Some(true));
    assert_eq!(second.json().opt_field_bool("has_more").unwrap(), Some(false));
    assert!(second.json().get("next_cursor").is_none_or(wire_json::Value::is_null));
}

// -- Decision traces --------------------------------------------------------

#[test]
fn the_decision_explorer_refuses_a_caller_without_read_decision_traces() {
    // A viewer holds `ReadSummary` and `ReadOwnUsage` only. Routing traces name
    // every target considered and why each was rejected, which is operational
    // detail a read-only viewer is not granted.
    let admin = Harness::new();
    let id = admin.record_decision(TENANT_A, 0x1234);
    let viewer = admin.viewer();

    let response = admin.get(&viewer, &format!("/admin/v1/decisions/{id}"));

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains(LOCAL_TARGET), "{}", response.body);
}

#[test]
fn an_unknown_decision_identifier_is_reported_as_absent() {
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin.get(
        &operator,
        "/admin/v1/decisions/ffffffffffffffffffffffffffffffff",
    );

    assert_eq!(response.status, 404, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("not_found"));
}

#[test]
fn a_malformed_decision_identifier_is_refused_as_a_bad_request() {
    // The identifier is parsed before anything is looked up, so a caller cannot
    // use the endpoint to probe the cache with arbitrary strings.
    let admin = Harness::new();
    let operator = admin.operator();

    for raw in ["not-a-request-id", "0123456789abcdef", &"A".repeat(32)] {
        let response = admin.get(&operator, &format!("/admin/v1/decisions/{raw}"));
        assert_eq!(response.status, 400, "{raw}: {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("invalid_request"), "{raw}");
    }
}

#[test]
fn another_tenants_decision_trace_reads_as_absent_rather_than_forbidden() {
    // Appendix B, and the distinction the cache documents: answering
    // "forbidden" would confirm that a request with that identifier exists,
    // which is itself information about another tenant's traffic.
    let admin = Harness::new();
    let id = admin.record_decision(TENANT_B, 0x5150);
    let operator_a = admin.operator_in(TENANT_A);

    let response = admin.get(&operator_a, &format!("/admin/v1/decisions/{id}"));

    assert_eq!(response.status, 404, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("not_found"));
    assert!(!response.body_contains(&id), "{}", response.body);
    assert!(!response.body_contains(LOCAL_TARGET), "{}", response.body);

    // The owning tenant can still read it, so the 404 is isolation and not a
    // trace that was never recorded.
    let operator_b = admin.operator_in(TENANT_B);
    let owner = admin.get(&operator_b, &format!("/admin/v1/decisions/{id}"));
    assert_eq!(owner.status, 200, "{}", owner.body);
}

#[test]
fn a_decision_trace_carries_no_prompt_no_credential_and_no_upstream_url() {
    // Specification 17: the trace is "policy digest, candidates, exclusion
    // reason codes, integer score terms, reservations, attempts" — and nothing
    // else. `hypellm_core::decision` promises that no type in it holds a prompt,
    // a credential, or a URL; this checks the rendered JSON keeps the promise,
    // including inside nested candidates and attempts.
    let admin = Harness::new();
    plant_credential_secret(&admin);
    let trace = detailed_trace(&admin, 0xabc);
    let id = trace.request_id.to_string();
    admin.state.decisions.record(
        TenantId::new(TENANT_A).unwrap(),
        trace,
        admin.clock.wall_millis(),
    );
    let operator = admin.operator();

    let response = admin.get(&operator, &format!("/admin/v1/decisions/{id}"));

    assert_eq!(response.status, 200, "{}", response.body);

    // The shape is closed: an added field is how a prompt would arrive.
    assert_eq!(
        top_level_keys(&response.json()),
        vec![
            "request_id",
            "policy_digest",
            "pinned",
            "routing_micros",
            "chosen",
            "explanation",
            "candidates",
            "exclusions",
            "attempts"
        ]
    );

    let mut strings = Vec::new();
    all_strings(&response.json(), &mut strings);
    for string in &strings {
        assert!(
            !string.contains("://") && !string.contains(PROVIDER_HOST),
            "a decision trace disclosed a destination: {string}"
        );
        assert!(
            !string.contains(SECRET_VALUE) && !string.to_ascii_lowercase().contains("bearer"),
            "a decision trace disclosed a credential: {string}"
        );
    }
    // The whole body, in case something arrived somewhere the walk cannot see.
    assert!(!response.body_contains("://"), "{}", response.body);
    assert!(!response.body_contains(SECRET_VALUE), "{}", response.body);
    assert!(!response.body_contains(CREDENTIAL), "{}", response.body);
    assert!(
        !response.body_contains("test-model") && !response.body_contains("remote-test"),
        "the native model name belongs to the adapter, not the trace: {}",
        response.body
    );
}

#[test]
fn a_decision_trace_reports_every_candidate_exclusion_and_attempt_the_router_recorded() {
    // The explorer exists to answer "why did this not go where I expected"
    // (specification 15.3). A trace that dropped an exclusion, or renamed a
    // reason, would answer it wrongly.
    let admin = Harness::new();
    let trace = detailed_trace(&admin, 0xdef);
    let id = trace.request_id.to_string();
    let expected_explanation = trace.explain();
    admin.state.decisions.record(
        TenantId::new(TENANT_A).unwrap(),
        trace,
        admin.clock.wall_millis(),
    );
    let operator = admin.operator();

    let response = admin.get(&operator, &format!("/admin/v1/decisions/{id}"));
    let body = response.json();

    assert_eq!(response.str_field("request_id"), id);
    assert_eq!(response.str_field("chosen"), LOCAL_TARGET);
    assert_eq!(response.str_field("explanation"), expected_explanation);
    assert_eq!(body.field_i64("routing_micros").unwrap(), 137);
    assert_eq!(body.opt_field_bool("pinned").unwrap(), Some(false));
    assert_eq!(
        response.str_field("policy_digest"),
        admin.config().digest.short(),
        "the snapshot in force, short enough for a screen"
    );

    let candidates = body.field_array("candidates").unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].field_str("target").unwrap(), LOCAL_TARGET);
    assert_eq!(candidates[0].field_i64("rank").unwrap(), 0);
    // Specification 6.3: scoring is integer fixed-point. A float here would
    // make two runs of the same request orderable differently.
    assert!(
        candidates[0].get("score").unwrap().as_number().unwrap().is_int(),
        "{}",
        response.body
    );
    let terms = candidates[0].opt_field_object("terms").unwrap().unwrap();
    for name in [
        "priority_rank",
        "policy_weight",
        "health",
        "latency",
        "queue",
        "cost",
        "locality",
        "affinity",
        "jitter",
    ] {
        assert!(terms.get(name).is_some(), "missing score term {name}");
    }
    assert_eq!(terms.get("locality").unwrap().as_i64().unwrap(), 5_000);
    assert_eq!(terms.get("health").unwrap().as_i64().unwrap(), -500);

    let exclusions = body.field_array("exclusions").unwrap();
    assert_eq!(exclusions.len(), 1);
    assert_eq!(exclusions[0].field_str("target").unwrap(), REMOTE_TARGET);
    assert_eq!(
        exclusions[0].field_str("reason").unwrap(),
        ExclusionReason::ResidencyMismatch.code(),
        "a stable reason code, not prose"
    );

    let attempts = body.field_array("attempts").unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].field_str("outcome").unwrap(), "failed_before_acceptance");
    assert_eq!(
        attempts[0].field_str("error_class").unwrap(),
        UpstreamErrorClass::Connection.as_str(),
        "the class, never the provider's error text"
    );
    assert!(attempts[0].opt_field_i64("first_byte_millis").unwrap().is_none());
    assert_eq!(attempts[1].field_str("outcome").unwrap(), "success");
    assert_eq!(attempts[1].field_i64("first_byte_millis").unwrap(), 40);
    assert_eq!(attempts[1].field_i64("sequence").unwrap(), 1);
}

// -- Audit search and durable history (specifications 22.3, 16) --------------

/// Create audit records by performing real management actions, so the durable
/// chain holds what a real deployment's would.
fn make_audit_history(admin: &Harness, count: usize) -> Vec<String> {
    let manager = admin.break_glass();
    let mut ids = Vec::new();
    for n in 0..count {
        let created = admin.post(
            &manager,
            "/admin/v1/keys",
            &format!(
                r#"{{"principal":"svc:history-{n}","scopes":["inference"],"description":"d"}}"#
            ),
        );
        assert_eq!(created.status, 201, "{}", created.body);
        ids.push(created.str_field("id"));
    }
    ids
}

#[test]
fn the_audit_view_can_be_searched_by_actor_action_and_time() {
    // Specification 22.3 step 20: "Search authorized audit/usage by key
    // pseudonym, source constraints, models, and time." Before this the audit
    // endpoint supported a cursor and a limit and nothing else, so a
    // compromised-key investigation ran on the structured logs rather than on
    // the management API.
    let admin = Harness::new();
    make_audit_history(&admin, 3);
    let auditor = admin.auditor();

    // By action.
    let by_action = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .query("action=key_created&durable=true")
        .send();
    assert_eq!(by_action.status, 200, "{}", by_action.body);
    let json = by_action.json();
    let rows = json.field_array("data").expect("a listing");
    assert!(!rows.is_empty(), "the filter matched nothing: {}", by_action.body);
    for row in rows {
        assert_eq!(row.field_str("action").unwrap_or_default(), "key_created");
    }

    // A filter that matches nothing returns an empty list, not everything.
    let none = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .query("action=router_started&durable=true")
        .send();
    assert_eq!(none.status, 200, "{}", none.body);
    assert!(
        none.json().field_array("data").expect("a listing").is_empty(),
        "an unmatched filter must not fall back to everything: {}",
        none.body
    );

    // By time. Everything happened at the harness clock's current instant, so
    // a window ending before it must be empty and one containing it must not.
    let now = admin.clock.wall_millis();
    let future = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .query(&format!("since={}&durable=true", now + 1_000_000))
        .send();
    assert!(
        future.json().field_array("data").expect("a listing").is_empty(),
        "records from the future: {}",
        future.body
    );
}

#[test]
fn an_audit_filter_cannot_reach_another_tenants_records() {
    // Appendix B: "Management visibility never exceeds the caller's tenant and
    // permissions." A search parameter that could widen that would be a
    // cross-tenant read with a query string.
    let admin = Harness::new();
    let other = admin.break_glass_in(TENANT_B);
    let created = admin.post(
        &other,
        "/admin/v1/keys",
        r#"{"principal":"svc:elsewhere","scopes":["inference"],"description":"d"}"#,
    );
    assert_eq!(created.status, 201, "{}", created.body);

    // An auditor in tenant A, asking by an actor who only exists in tenant B.
    let listing = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&admin.auditor_in(TENANT_A))
        .query(&format!("actor={}&durable=true", other.principal))
        .send();
    assert_eq!(listing.status, 200, "{}", listing.body);
    assert!(
        listing.json().field_array("data").expect("a listing").is_empty(),
        "a query string reached another tenant's audit records: {}",
        listing.body
    );
}

#[test]
fn a_contradictory_time_window_is_refused_rather_than_silently_empty() {
    // An empty result and a refusal look the same to an operator staring at a
    // screen during an incident. Saying "this can never match" is the useful
    // answer.
    let admin = Harness::new();
    let listing = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&admin.auditor())
        .query("since=2000&until=1000")
        .send();
    assert_eq!(listing.status, 400, "{}", listing.body);
    assert!(listing.body_contains("can never match"));
}

#[test]
fn a_malformed_time_bound_is_refused() {
    let admin = Harness::new();
    for query in ["since=yesterday", "until=soon", "since=-1"] {
        let listing = admin
            .request(Method::Get, "/admin/v1/audit")
            .as_session(&admin.auditor())
            .query(query)
            .send();
        assert_eq!(listing.status, 400, "{query} was accepted: {}", listing.body);
    }
}

#[test]
fn the_durable_chain_holds_more_than_the_in_memory_ring() {
    // The ring is 2 048 records and starts empty on every restart, which is the
    // right shape for a screen showing recent activity and the wrong one for an
    // investigation. Asserted at small scale: the durable read must return the
    // same records the ring does, from a different source.
    let admin = Harness::new();
    make_audit_history(&admin, 5);
    let auditor = admin.auditor();

    let ring = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .send();
    let durable = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .query("durable=true")
        .send();
    assert_eq!(ring.status, 200, "{}", ring.body);
    assert_eq!(durable.status, 200, "{}", durable.body);

    let ring_json = ring.json();
    let durable_json = durable.json();
    let ring_rows = ring_json.field_array("data").expect("a listing");
    let durable_rows = durable_json.field_array("data").expect("a listing");
    assert!(!durable_rows.is_empty(), "the durable read found nothing");

    // Same shape from both sources: a caller must not be able to tell which
    // answered, or the two will drift.
    let sequences = |rows: &[Value]| -> Vec<i64> {
        rows.iter()
            .filter_map(|r| r.opt_field_i64("sequence").ok().flatten())
            .collect()
    };
    assert_eq!(
        sequences(ring_rows),
        sequences(durable_rows),
        "the ring and the durable chain disagree:\nring {}\ndurable {}",
        ring.body,
        durable.body
    );
}

#[test]
fn the_audit_trail_can_be_exported_with_its_checkpoints() {
    // Specification 11.2: "Audit records form a hash/MAC chain with periodic
    // signed checkpoints exported to immutable storage." Checkpoints were
    // produced and shipped nowhere; `AuditAction::AuditExported` had no
    // producer.
    let admin = Harness::new();
    make_audit_history(&admin, 3);

    let export = admin
        .request(Method::Get, "/admin/v1/audit/export")
        .as_session(&admin.auditor())
        .send();
    assert_eq!(export.status, 200, "{}", export.body);

    let json = export.json();
    assert_eq!(json.field_str("object").unwrap_or_default(), "audit_export");
    let records = json.field_array("records").expect("records");
    assert!(!records.is_empty(), "the export is empty: {}", export.body);

    // Oldest first: an export is read as a history, not as a screen.
    let sequences: Vec<i64> = records
        .iter()
        .filter_map(|r| r.opt_field_i64("sequence").ok().flatten())
        .collect();
    let mut sorted = sequences.clone();
    sorted.sort_unstable();
    assert_eq!(sequences, sorted, "an export must read forwards in time");

    // The checkpoints are the trust anchor: `AuditRecord::link` is unkeyed
    // SHA-256, so the chain proves ordering and only a checkpoint carries a MAC.
    assert!(
        json.field_array("checkpoints").is_ok(),
        "an export without checkpoints proves ordering and nothing else: {}",
        export.body
    );
    assert!(json.field_str("chain_head").is_ok());
    assert_eq!(
        json.opt_field_bool("truncated").ok().flatten(),
        Some(false),
        "a small export must not claim truncation"
    );
}

#[test]
fn exporting_is_itself_audited() {
    // Specification 17 lists export as an audited action. An export that leaves
    // no trace is how an audit trail is copied without anyone knowing.
    let admin = Harness::new();
    make_audit_history(&admin, 1);
    let auditor = admin.auditor();

    let before = admin.audit_count();
    let export = admin
        .request(Method::Get, "/admin/v1/audit/export")
        .as_session(&auditor)
        .send();
    assert_eq!(export.status, 200, "{}", export.body);
    assert_eq!(
        admin.audit_count(),
        before + 1,
        "the export left no record of itself"
    );

    let listing = admin
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&auditor)
        .query("action=audit_exported&durable=true")
        .send();
    let json = listing.json();
    assert!(
        !json.field_array("data").expect("a listing").is_empty(),
        "the export record is not visible to a reviewer: {}",
        listing.body
    );
}

#[test]
fn an_export_is_scoped_to_the_callers_tenant_and_permission() {
    let admin = Harness::new();
    let other = admin.break_glass_in(TENANT_B);
    let created = admin.post(
        &other,
        "/admin/v1/keys",
        r#"{"principal":"svc:elsewhere","scopes":["inference"],"description":"d"}"#,
    );
    assert_eq!(created.status, 201, "{}", created.body);

    let export = admin
        .request(Method::Get, "/admin/v1/audit/export")
        .as_session(&admin.auditor_in(TENANT_A))
        .send();
    assert_eq!(export.status, 200, "{}", export.body);
    assert_eq!(
        export.json().field_str("tenant").unwrap_or_default(),
        TENANT_A,
        "an export must state its scope"
    );
    assert!(
        !export.body_contains("svc:elsewhere"),
        "the export crossed a tenant boundary: {}",
        export.body
    );

    // `ReadAudit` alone is not enough: exporting copies the trail off the node.
    let viewer = admin
        .request(Method::Get, "/admin/v1/audit/export")
        .as_session(&admin.viewer())
        .send();
    assert_eq!(viewer.status, 403, "{}", viewer.body);
}
