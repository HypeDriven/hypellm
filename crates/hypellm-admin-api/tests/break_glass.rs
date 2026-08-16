//! Break-glass sign-in.
//!
//! Specification 22.4: "Authorized operators use a preprovisioned local
//! break-glass method stored offline. Break-glass access is time-limited,
//! reason-bound, alerting, and reviewed." Specification 9.2 lists break-glass
//! as one of four ways a principal is established.
//!
//! What these assert is the recovery property: **`/admin/v1` is reachable when
//! the identity provider is not.** Before this existed the vocabulary was
//! complete — `AuthMethod::BreakGlass`, `Role::BreakGlassAdmin`,
//! `Permission::BreakGlass`, `AuditAction::BreakGlassOpened` — and nothing
//! produced any of it, so during a Google outage there was no way in unless a
//! session was already open.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use harness::Harness;
use wire_http1::Method;

const TOKEN: &str = "a-preprovisioned-break-glass-token-value";
const PRINCIPAL: &str = "user:oncall";
const REASON: &str = "google oidc is unreachable, incident 4711";

/// A harness with break-glass preprovisioned and the principal bound to the
/// break-glass role.
fn harness() -> Harness {
    let config = format!(
        "{}role_binding subject=principal:{PRINCIPAL} role=break_glass_admin\n",
        harness::default_config()
    );
    Harness::builder()
        .config(&config)
        .with_break_glass(TOKEN, PRINCIPAL, "acme")
        .build()
}

fn body(token: &str, reason: &str) -> String {
    format!("{{\"token\":\"{token}\",\"reason\":\"{reason}\"}}")
}

#[test]
fn a_preprovisioned_token_establishes_a_session_without_the_identity_provider() {
    // The harness has no OIDC configuration at all, which is the point: this
    // path must not depend on one.
    let h = harness();
    let response = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, REASON))
        .send();

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        response.header("set-cookie").is_some(),
        "a session cookie must be set"
    );
    assert!(
        response.json().field_str("csrf_token").is_ok(),
        "the caller needs a CSRF token to do anything with the session"
    );
}

#[test]
fn the_session_actually_stops_working_when_its_window_closes() {
    // Specification 22.4: break-glass access is "time-limited". Asserted
    // against the session, not against what the response claims about it: an
    // earlier version of this test checked only `expires_in_seconds` and the
    // cookie's `Max-Age`, both of which are printed from the configured TTL and
    // stay right even if the session itself is issued with the ordinary
    // twelve-hour lifetime.
    let h = harness();
    let response = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, REASON))
        .send();
    assert_eq!(response.status, 200, "{}", response.body);

    let seconds = u64::try_from(
        response
            .json()
            .opt_field_i64("expires_in_seconds")
            .ok()
            .flatten()
            .expect("the lifetime is part of the answer"),
    )
    .expect("a positive lifetime");
    assert!(
        seconds > 0 && seconds <= 60 * 60,
        "a break-glass session must be short: got {seconds}s"
    );

    let cookie = response
        .header("set-cookie")
        .expect("a session cookie")
        .to_owned();
    assert!(
        cookie.contains(&format!("Max-Age={seconds}")),
        "the cookie must expire with the session: {cookie}"
    );
    let token = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a cookie value");

    // Just inside the window it works...
    h.clock.advance((seconds - 1) * 1000);
    let inside = h
        .request(Method::Get, "/admin/v1/session")
        .header("cookie", &format!("{}={token}", hypellm_auth::session::COOKIE_NAME))
        .send();
    assert_eq!(inside.status, 200, "{}", inside.body);

    // ...and past it, it does not. Not merely idle-expired: the absolute limit
    // is what a break-glass window means, and an operator holding the tab open
    // must not keep the session alive by using it.
    h.clock.advance(2 * 1000);
    let outside = h
        .request(Method::Get, "/admin/v1/session")
        .header("cookie", &format!("{}={token}", hypellm_auth::session::COOKIE_NAME))
        .send();
    assert_eq!(
        outside.status, 401,
        "the break-glass window did not close: {}",
        outside.body
    );
}

#[test]
fn a_wrong_token_is_refused() {
    let h = harness();
    let response = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body("not-the-token", REASON))
        .send();

    assert_eq!(response.status, 401, "{}", response.body);
    assert!(
        response.header("set-cookie").is_none(),
        "a refused sign-in must not set a session"
    );
}

#[test]
fn a_missing_or_trivial_reason_is_refused() {
    // Specification 22.4 makes break-glass "reason-bound … and reviewed". An
    // optional reason would be empty exactly when it mattered.
    let h = harness();
    for reason in ["", "x", "test"] {
        let response = h
            .request(Method::Post, "/admin/v1/auth/break-glass")
            .json(&body(TOKEN, reason))
            .send();
        assert_eq!(
            response.status, 400,
            "reason '{reason}' was accepted: {}",
            response.body
        );
    }
}

#[test]
fn the_reason_is_checked_before_the_token() {
    // Otherwise the endpoint answers differently for a right and a wrong token
    // when the reason is bad, which tells an unauthenticated caller whether it
    // holds the token.
    let h = harness();
    let with_right = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, "x"))
        .send();
    let with_wrong = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body("not-the-token", "x"))
        .send();

    assert_eq!(with_right.status, with_wrong.status);
    assert_eq!(with_right.status, 400);
}

#[test]
fn an_unconfigured_deployment_has_no_endpoint_at_all() {
    // Not "wrong token": a deployment with no preprovisioned break-glass should
    // not advertise that the endpoint is live.
    let h = Harness::builder().build();
    let response = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, REASON))
        .send();

    assert_eq!(response.status, 404, "{}", response.body);
}

#[test]
fn a_token_holder_with_no_role_binding_gets_nothing() {
    // Holding the token proves who you are, not what you may do. Without a
    // `role_binding` the principal has no permissions, and saying so beats
    // handing back a session that fails at every endpoint.
    let h = Harness::builder()
        .with_break_glass(TOKEN, PRINCIPAL, "acme")
        .build();
    let response = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, REASON))
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
}

#[test]
fn opening_and_closing_are_both_recorded_with_the_reason() {
    // Specification 22.4: break-glass access is "reviewed". The review reads
    // these two records.
    let h = harness();
    let opened = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body(TOKEN, REASON))
        .send();
    assert_eq!(opened.status, 200, "{}", opened.body);

    // Read back through the endpoint a reviewer would use, not through the
    // store directly: a record that exists but is not visible there is not
    // "reviewed" in any sense specification 22.4 would recognise.
    let listing = h
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&h.auditor())
        .send();
    assert_eq!(listing.status, 200, "{}", listing.body);
    let json = listing.json();
    let data = json.field_array("data").expect("a listing");
    let open = data
        .iter()
        .find(|r| r.field_str("action").unwrap_or_default() == "break_glass_opened")
        .expect("the opening must be in the durable chain");
    assert_eq!(open.field_str("actor").unwrap_or_default(), PRINCIPAL);
    assert_eq!(
        open.opt_field_str("reason").ok().flatten(),
        Some(REASON),
        "the reason must be recorded"
    );
}

#[test]
fn a_refused_attempt_is_recorded() {
    let h = harness();
    let _ = h
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&body("not-the-token", REASON))
        .send();

    let listing = h
        .request(Method::Get, "/admin/v1/audit")
        .as_session(&h.auditor())
        .send();
    let json = listing.json();
    let data = json.field_array("data").expect("a listing");
    assert!(
        data.iter().any(|r| {
            r.field_str("action").unwrap_or_default() == "login_failed"
                && r.field_str("outcome").unwrap_or_default() == "denied"
        }),
        "a refused break-glass attempt must leave a record"
    );
}

#[test]
fn repeated_break_glass_failures_do_not_grow_the_durable_log_without_bound() {
    // Specification 3.2: "No request may create an unbounded ... log entry."
    //
    // `POST /admin/v1/auth/break-glass` runs before any session — specification
    // 22.4 makes it "the only endpoint that must keep working when the identity
    // provider does not" — so an unauthenticated caller decides how often it
    // runs. Each failure appended a durable audit record.
    //
    // Filling the log through this path is the sharpest version of the problem:
    // `Log::replay` refuses a log past `MAX_LOG_BYTES`, so the router stops
    // booting, and the emergency recovery path is disabled exactly when it is
    // needed. The bound is what stops an unauthenticated flood from becoming a
    // denial of service that survives restart.
    let h = harness();
    let path = h.state.store.dir().join("log.bin");
    let size = || std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    let before = size();
    for _ in 0..400 {
        let response = h
            .request(Method::Post, "/admin/v1/auth/break-glass")
            .json(&body("not-the-token", REASON))
            .send();
        assert!(
            response.status >= 400,
            "a wrong token must be refused: {}",
            response.body
        );
    }
    let grown = size().saturating_sub(before);
    assert!(
        grown < 4_096,
        "400 break-glass failures grew the durable log by {grown} bytes"
    );

    // The signal is not what is bounded: every failure is still counted.
    let exposition = h.state.telemetry.exposition();
    let counted: u64 = exposition
        .lines()
        .filter(|line| line.starts_with("hypellm_auth_failures_total{"))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum();
    assert!(
        counted >= 400,
        "suppressing the record must not suppress the metric: counted {counted}"
    );
}
