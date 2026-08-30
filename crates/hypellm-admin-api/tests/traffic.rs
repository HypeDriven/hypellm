//! `GET /admin/v1/traffic` — the overview's rate, latency, and capacity panel.
//!
//! Specification 15.3 names "request rate, latency, errors, active streams,
//! capacity" among what the overview screen must show. Every one of those is a
//! number an operator acts on: they decide whether to raise a limit, quarantine
//! a target, or wake somebody. Three properties matter more than the field
//! names, and each has its own tests below.
//!
//! * **Tenant.** Appendix B: "management visibility never exceeds the caller's
//!   tenant and permissions." A rate is traffic volume, and one tenant's volume
//!   is not another's to read.
//! * **Honesty about what was measured.** A window shorter than the router's
//!   uptime, a quantile past the largest bucket, a tenant whose samples were
//!   dropped, a deployment with no admission controller — each is reported as
//!   itself rather than as a zero. A confident zero on this screen is the
//!   failure mode the whole endpoint exists to avoid.
//! * **Read-only in the strict sense.** The handler must not create an
//!   admission scope or roll a budget period. A management refresh that moved a
//!   tenant's spend boundary would be a mutation performed by looking at it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use harness::{Harness, LOCAL_TARGET, TENANT_A, TENANT_B};
use hypellm_admin_api::traffic::{self, TrafficSample};
use hypellm_admin_api::UsageStatus;
use hypellm_core::ids::{TargetId, TenantId};
use hypellm_core::time::Clock;
use wire_json::Value;

/// A completed request that succeeded, with the given timings.
fn served(router_ms: u64, upstream_ms: u64) -> TrafficSample {
    TrafficSample {
        status: UsageStatus::Success,
        router_millis: router_ms,
        upstream_millis: Some(upstream_ms),
        input_tokens: 10,
        output_tokens: 20,
    }
}

/// A request refused before any target was reached.
fn refused(status: UsageStatus) -> TrafficSample {
    TrafficSample {
        status,
        router_millis: 1,
        upstream_millis: None,
        input_tokens: 0,
        output_tokens: 0,
    }
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

/// The window of `window_millis` from a `/admin/v1/traffic` body.
fn window_of(body: &Value, window_millis: i64) -> Value {
    body.field_array("windows")
        .unwrap()
        .iter()
        .find(|entry| entry.field_i64("window_millis") == Ok(window_millis))
        .cloned()
        .unwrap_or_else(|| panic!("no {window_millis} ms window in {body:?}"))
}

fn capacity_of(body: &Value) -> Value {
    body.get("capacity").cloned().expect("a capacity object")
}

// -- Authorization and tenant scope -----------------------------------------

#[test]
fn traffic_refuses_a_session_that_does_not_hold_read_summary() {
    // Same gate as the overview it belongs to. A refusal must also disclose
    // nothing: a caller who cannot read the summary must not learn the router's
    // concurrency ceiling from the error body.
    let admin = Harness::new();
    let nobody = admin.unprivileged();

    let response = admin.get(&nobody, "/admin/v1/traffic");

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("forbidden"));
    assert!(!response.body_contains("max_concurrency"), "{}", response.body);
    assert!(!response.body_contains("windows"), "{}", response.body);
}

#[test]
fn one_tenants_request_rate_is_invisible_to_another_tenant() {
    // Appendix B. A request rate is a direct measure of how much business a
    // tenant is doing, and the overview's tenant *count* was already narrowed
    // for exactly this reason; a rate is the more sensitive of the two.
    let admin = Harness::new();
    let now = admin.clock.now_millis();
    for _ in 0..25 {
        admin.traffic.record(&tenant(TENANT_A), &served(2, 40), now);
    }

    let theirs = admin.get(&admin.viewer_in(TENANT_B), "/admin/v1/traffic");
    assert_eq!(theirs.status, 200, "{}", theirs.body);
    let window = window_of(&theirs.json(), 60_000);
    assert_eq!(
        window.field_i64("requests").unwrap(),
        0,
        "globex sent nothing; acme's traffic is not globex's to see"
    );

    let ours = admin.get(&admin.viewer_in(TENANT_A), "/admin/v1/traffic");
    assert_eq!(window_of(&ours.json(), 60_000).field_i64("requests").unwrap(), 25);
}

// -- Rate --------------------------------------------------------------------

#[test]
fn a_sample_that_has_aged_out_of_the_window_is_no_longer_counted_in_it() {
    // The point of the whole module: a rate is a windowed measurement. If a
    // sample never left the window the figure would be a cumulative counter
    // with a misleading label, which is the state this endpoint replaced.
    let admin = Harness::new();
    let viewer = admin.viewer();
    admin
        .traffic
        .record(&tenant(TENANT_A), &served(2, 40), admin.clock.now_millis());

    let fresh = admin.get(&viewer, "/admin/v1/traffic");
    assert_eq!(window_of(&fresh.json(), 60_000).field_i64("requests").unwrap(), 1);

    // Two minutes later the sample is outside the one-minute window but still
    // inside the five-minute one.
    admin.clock.advance(120_000);
    let later = admin.get(&viewer, "/admin/v1/traffic").json();
    assert_eq!(window_of(&later, 60_000).field_i64("requests").unwrap(), 0);
    assert_eq!(
        window_of(&later, traffic::WINDOW_MILLIS.try_into().unwrap())
            .field_i64("requests")
            .unwrap(),
        1,
        "the wider window still holds it"
    );
}

#[test]
fn the_covered_span_is_the_denominator_a_rate_must_be_divided_by() {
    // A router thirty seconds old has not lived through a one-minute window.
    // Reporting the nominal window as the divisor would understate its rate by
    // half, on exactly the screen an operator reads during a traffic spike.
    let admin = Harness::new();
    let viewer = admin.viewer();
    admin.clock.advance(30_000);
    admin
        .traffic
        .record(&tenant(TENANT_A), &served(2, 40), admin.clock.now_millis());

    let body = admin.get(&viewer, "/admin/v1/traffic").json();
    let minute = window_of(&body, 60_000);
    assert_eq!(minute.field_i64("window_millis").unwrap(), 60_000);
    assert_eq!(minute.field_i64("covered_millis").unwrap(), 30_000);
    assert_eq!(
        minute.opt_field_bool("complete").unwrap(),
        Some(false),
        "half a window is not a window"
    );

    // Once the router has been up long enough, the same window is complete.
    admin.clock.advance(60_000);
    let later = window_of(&admin.get(&viewer, "/admin/v1/traffic").json(), 60_000);
    assert_eq!(later.opt_field_bool("complete").unwrap(), Some(true));
}

#[test]
fn outcomes_are_reported_in_their_own_classes_rather_than_as_one_error_count() {
    // "Errors" on this screen decides what an operator does next: a client
    // error is somebody's broken integration, a throttle is a limit doing its
    // job, and a server error is an outage. Collapsing them would erase the
    // distinction that determines whether anyone gets woken up.
    let admin = Harness::new();
    let now = admin.clock.now_millis();
    let acme = tenant(TENANT_A);
    admin.traffic.record(&acme, &served(2, 40), now);
    admin.traffic.record(&acme, &served(2, 40), now);
    admin.traffic.record(&acme, &refused(UsageStatus::ClientError), now);
    admin.traffic.record(&acme, &refused(UsageStatus::Throttled), now);
    admin.traffic.record(&acme, &refused(UsageStatus::ServerError), now);

    let window = window_of(&admin.get(&admin.viewer(), "/admin/v1/traffic").json(), 60_000);
    assert_eq!(window.field_i64("requests").unwrap(), 5);
    assert_eq!(window.field_i64("successes").unwrap(), 2);
    assert_eq!(window.field_i64("client_errors").unwrap(), 1);
    assert_eq!(window.field_i64("throttled").unwrap(), 1);
    assert_eq!(window.field_i64("server_errors").unwrap(), 1);
}

// -- Latency -----------------------------------------------------------------

#[test]
fn latency_is_labelled_as_a_bucket_upper_bound_rather_than_a_measurement() {
    // Specification 19.1 puts measured distributions in `hypellm-bench`. This
    // series is bucketed, so a p99 of 5 ms means "at or below 5 ms". A console
    // that printed it as 5 ms would be claiming a precision nobody measured.
    let admin = Harness::new();
    for _ in 0..100 {
        admin
            .traffic
            .record(&tenant(TENANT_A), &served(3, 40), admin.clock.now_millis());
    }

    let body = admin.get(&admin.viewer(), "/admin/v1/traffic").json();
    assert_eq!(
        body.field_str("latency_estimate").unwrap(),
        "bucket_upper_bound"
    );
    assert_eq!(
        body.field_i64("largest_bucket_millis").unwrap(),
        i64::try_from(traffic::largest_bucket_millis()).unwrap()
    );

    let window = window_of(&body, 60_000);
    let router = window.get("router_latency").unwrap();
    // 3 ms samples fall in the (2, 5] bucket, so every quantile is 5.
    assert_eq!(router.field_i64("samples").unwrap(), 100);
    assert_eq!(router.opt_field_i64("p50_millis").unwrap(), Some(5));
    assert_eq!(router.opt_field_i64("p99_millis").unwrap(), Some(5));
    assert_eq!(router.opt_field_i64("mean_millis").unwrap(), Some(3));
}

#[test]
fn a_quantile_past_the_largest_bucket_is_absent_rather_than_reported_as_the_bound() {
    // The overflow bucket has no upper bound. Rendering it as 120000 would turn
    // "longer than two minutes" into "two minutes" — the difference between a
    // slow provider and a hung one.
    let admin = Harness::new();
    let slow = traffic::largest_bucket_millis() + 1;
    for _ in 0..10 {
        admin
            .traffic
            .record(&tenant(TENANT_A), &served(1, slow), admin.clock.now_millis());
    }

    let window = window_of(&admin.get(&admin.viewer(), "/admin/v1/traffic").json(), 60_000);
    let upstream = window.get("upstream_latency").unwrap();
    assert_eq!(upstream.field_i64("samples").unwrap(), 10);
    assert_eq!(upstream.opt_field_i64("p99_millis").unwrap(), None);
    assert_eq!(upstream.field_i64("above_largest_bucket").unwrap(), 10);
}

#[test]
fn a_request_that_reached_no_target_contributes_no_upstream_latency() {
    // A router refusing everything at admission would otherwise look like the
    // fastest one in the fleet: every refusal is a zero-millisecond "upstream
    // exchange" that never happened.
    let admin = Harness::new();
    let now = admin.clock.now_millis();
    for _ in 0..20 {
        admin
            .traffic
            .record(&tenant(TENANT_A), &refused(UsageStatus::Throttled), now);
    }

    let window = window_of(&admin.get(&admin.viewer(), "/admin/v1/traffic").json(), 60_000);
    assert_eq!(window.field_i64("requests").unwrap(), 20);
    assert_eq!(
        window.get("router_latency").unwrap().field_i64("samples").unwrap(),
        20
    );
    let upstream = window.get("upstream_latency").unwrap();
    assert_eq!(upstream.field_i64("samples").unwrap(), 0);
    assert_eq!(upstream.opt_field_i64("p50_millis").unwrap(), None);
}

// -- Capacity ----------------------------------------------------------------

#[test]
fn capacity_reports_the_limit_beside_the_occupancy() {
    // A utilisation needs both halves. An occupancy with no denominator cannot
    // answer the only question the panel exists for — "how close are we?"
    let admin = Harness::new();
    let capacity = capacity_of(&admin.get(&admin.viewer(), "/admin/v1/traffic").json());

    assert_eq!(capacity.opt_field_bool("available").unwrap(), Some(true));
    let global = capacity.get("global").unwrap();
    assert_eq!(global.field_str("name").unwrap(), "global");
    assert_eq!(global.field_i64("in_flight").unwrap(), 0);
    assert_eq!(
        global.field_i64("max_concurrency").unwrap(),
        16,
        "the harness ceiling, read from the controller the router shares"
    );

    let target = capacity
        .get("targets")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|row| row.field_str("id") == Ok(LOCAL_TARGET))
        .expect("the local target is visible to a viewer");
    assert_eq!(target.opt_field_bool("admission_scope").unwrap(), Some(true));
    assert!(target.field_i64("max_concurrency").unwrap() > 0);
}

#[test]
fn an_occupied_scope_is_reported_as_occupied() {
    // The counter must be the live one. A capacity panel built from a copy of
    // the limits would show a full router as idle, which is the failure that
    // makes an operator raise a limit that was never the problem.
    let admin = Harness::new();
    let viewer = admin.viewer();
    let controller = admin.admission.as_ref().expect("the harness has one");
    let target = TargetId::new(LOCAL_TARGET).unwrap();

    let before = capacity_of(&admin.get(&viewer, "/admin/v1/traffic").json());
    assert_eq!(before.get("global").unwrap().field_i64("in_flight").unwrap(), 0);

    let reservation = controller
        .reserve_for(
            &tenant(TENANT_A),
            &hypellm_core::ids::PrincipalId::new("user:someone").unwrap(),
            None,
            &target,
            1,
        )
        .expect("the harness ceiling admits one request");

    let during = capacity_of(&admin.get(&viewer, "/admin/v1/traffic").json());
    let global = during.get("global").unwrap();
    assert_eq!(global.field_i64("in_flight").unwrap(), 1);
    assert_eq!(global.field_i64("acquired").unwrap(), 1);
    assert_eq!(global.field_i64("released").unwrap(), 0);
    let row = during
        .get("targets")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|row| row.field_str("id") == Ok(LOCAL_TARGET))
        .unwrap();
    assert_eq!(row.field_i64("in_flight").unwrap(), 1);

    drop(reservation);

    // Appendix B's conservation law, visible on the screen: once nothing is in
    // flight the two counters must agree.
    let after = capacity_of(&admin.get(&viewer, "/admin/v1/traffic").json());
    let global = after.get("global").unwrap();
    assert_eq!(global.field_i64("in_flight").unwrap(), 0);
    assert_eq!(
        global.field_i64("acquired").unwrap(),
        global.field_i64("released").unwrap(),
        "an idle scope whose counters differ has leaked a reservation"
    );
}

#[test]
fn reading_the_panel_does_not_create_a_scope_for_the_callers_tenant() {
    // `AdmissionController::tenant_scope` creates on demand, and a scope
    // created by a reader starts its budget period at the read. Two operators
    // refreshing a dashboard would each shorten the tenant's next budget
    // period, which is a limit moved by looking at it.
    let admin = Harness::new();
    let controller = admin.admission.as_ref().expect("the harness has one");
    let acme = tenant(TENANT_A);
    assert!(controller.configured_tenant_scope(&acme).is_none());

    let body = admin.get(&admin.viewer(), "/admin/v1/traffic").json();

    assert!(
        controller.configured_tenant_scope(&acme).is_none(),
        "a management read must not bring an admission scope into existence"
    );
    let reported = capacity_of(&body);
    let scope = reported.get("tenant").unwrap();
    assert_eq!(
        scope.opt_field_bool("exists").unwrap(),
        Some(false),
        "the panel says the scope does not exist yet rather than inventing one"
    );
    assert_eq!(scope.field_str("name").unwrap(), format!("tenant:{TENANT_A}"));
}

#[test]
fn a_deployment_with_no_admission_controller_says_so_rather_than_reporting_zeros() {
    // The honesty rule. A capacity panel reading `0 / 0` on every row is
    // indistinguishable from a healthy idle router, so nobody goes looking for
    // the reason the numbers are missing.
    let admin = Harness::builder().without_admission().build();

    let capacity = capacity_of(&admin.get(&admin.viewer(), "/admin/v1/traffic").json());

    assert_eq!(capacity.opt_field_bool("available").unwrap(), Some(false));
    assert!(
        capacity.get("reason").and_then(Value::as_str).is_some(),
        "an absent capability names itself"
    );
    assert!(
        capacity.get("global").is_none(),
        "no limit is reported, rather than a zero one"
    );
}

// -- Bounds ------------------------------------------------------------------

#[test]
fn a_tenant_whose_samples_were_dropped_is_told_so_rather_than_shown_a_zero() {
    // The window holds a bounded number of rings. Past that a tenant's samples
    // are not recorded, and the honest answer is "not attributed" — a zero
    // would report the busiest tenant on the router as idle.
    let admin = Harness::new();
    let now = admin.clock.now_millis();
    for index in 0..traffic::MAX_TENANTS {
        let filler = TenantId::new(format!("filler-{index}")).unwrap();
        admin.traffic.record(&filler, &served(2, 40), now);
    }
    // `acme` never got a ring, and every ring is now in use.
    admin.traffic.record(&tenant(TENANT_A), &served(2, 40), now);

    let body = admin.get(&admin.viewer(), "/admin/v1/traffic").json();

    assert_eq!(body.opt_field_bool("attributed").unwrap(), Some(false));
    assert!(
        body.field_array("windows").unwrap().is_empty(),
        "an unattributed tenant is shown no window at all, not an empty one"
    );
    assert!(body.field_i64("unattributed_samples").unwrap() >= 1);
}

#[test]
fn the_window_set_is_fixed_and_not_chosen_by_the_caller() {
    // Specification 3.2: nothing unbounded originates from a request. The
    // windows are a fixed pair, so a query parameter cannot widen what the
    // router has to sum, and a stray one changes nothing.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let plain = admin.get(&viewer, "/admin/v1/traffic").json();
    let steered = admin
        .get_query(&viewer, "/admin/v1/traffic", "window=99999999")
        .json();

    let windows: Vec<i64> = plain
        .field_array("windows")
        .unwrap()
        .iter()
        .map(|entry| entry.field_i64("window_millis").unwrap())
        .collect();
    assert_eq!(
        windows,
        vec![60_000, i64::try_from(traffic::WINDOW_MILLIS).unwrap()]
    );
    assert_eq!(
        steered.field_array("windows").unwrap().len(),
        windows.len(),
        "a query parameter must not add a window"
    );
}

#[test]
fn the_panel_discloses_no_credential_and_no_upstream_host() {
    // Every read endpoint carries this obligation (specification 9.3, 17). The
    // capacity rows name targets, and a target row that leaked the endpoint it
    // dials would hand an attacker the map without any routing permission.
    let admin = Harness::new();
    let response = admin.get(&admin.viewer(), "/admin/v1/traffic");

    assert_eq!(response.status, 200, "{}", response.body);
    for needle in ["api.provider.test", "credential", "secret", "authorization"] {
        assert!(
            !response.body.to_ascii_lowercase().contains(needle),
            "the traffic panel leaked {needle}: {}",
            response.body
        );
    }
}
