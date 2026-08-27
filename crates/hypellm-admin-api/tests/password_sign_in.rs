//! Local username-and-password sign-in.
//!
//! **This path is a deviation, not a specification requirement.**
//! Specification 9.2 lists four ways a principal is established and a local
//! password is none of them; `docs/deferred-issues.md` records why it exists
//! anyway. That makes the tests here more important rather than less: nothing
//! in the specification describes what this endpoint must refuse, so the
//! refusals have to be written down somewhere, and this is where.
//!
//! What each of these asserts is a property an ordinary edit could plausibly
//! break — the lockout being checked after the hash instead of before it, a
//! refusal that distinguishes an unknown user from a wrong password, a session
//! that claims the identity provider vouched for it. None of them assert only a
//! status code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use harness::{ALLOWED_ORIGIN, Harness};
use hypellm_crypto::PasswordVerifier;
use hypellm_crypto::pbkdf2::MIN_ITERATIONS;
use wire_http1::Method;

const USERNAME: &str = "admin";
const PASSWORD: &str = "a-password-that-is-not-the-username";

/// Mirrors `MAX_PASSWORD_FAILURES` and `PASSWORD_LOCKOUT_WINDOW_MILLIS` in
/// `handlers.rs`. Duplicated rather than exported: a test that read the
/// constant would still pass if the constant changed to something useless.
const FAILURES_BEFORE_LOCKOUT: u32 = 5;
const LOCKOUT_WINDOW_MILLIS: u64 = 60_000;

/// A configuration with one local account, at the cheapest legal iteration
/// count so the suite stays fast in a debug build.
fn config_with_user(username: &str, password: &str, roles: &[&str]) -> String {
    let verifier = PasswordVerifier::derive(password, MIN_ITERATIONS)
        .expect("the test host has an entropy source")
        .encode();
    let mut text = format!(
        "{}local_user id={username} principal=user:{username} tenant=acme verifier={verifier}\n",
        harness::default_config()
    );
    for role in roles {
        text.push_str(&format!(
            "role_binding subject=principal:user:{username} role={role}\n"
        ));
    }
    text
}

fn harness() -> Harness {
    Harness::builder()
        .config(&config_with_user(USERNAME, PASSWORD, &["operator"]))
        .build()
}

fn body(username: &str, password: &str) -> String {
    format!("{{\"username\":\"{username}\",\"password\":\"{password}\"}}")
}

fn sign_in(h: &Harness, username: &str, password: &str) -> harness::Response {
    h.request(Method::Post, "/admin/v1/auth/password")
        .json(&body(username, password))
        .send()
}

#[test]
fn a_local_account_signs_in_without_the_identity_provider() {
    // The harness configures no OIDC at all, which is the point: this is the
    // path a deployment uses before it has one.
    let h = harness();
    let response = sign_in(&h, USERNAME, PASSWORD);

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
fn the_sign_in_screen_can_reach_it_from_the_browser() {
    // The same property the break-glass form depends on: this endpoint runs
    // before the session exists, so a browser POST carries an `Origin` and
    // cannot carry a session-bound CSRF token. Hoisting the CSRF check above
    // the pre-session match would leave every `curl` in the runbook working
    // and break sign-in for everyone with a browser.
    let h = harness();
    let response = h
        .request(Method::Post, "/admin/v1/auth/password")
        .origin(ALLOWED_ORIGIN)
        .json(&body(USERNAME, PASSWORD))
        .send();

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(response.header("set-cookie").is_some());
}

#[test]
fn the_session_it_issues_names_password_as_its_method() {
    // An investigation's first question is how a principal authenticated. A
    // password session reported as `oidc` would say the identity provider
    // vouched for someone it has never seen.
    let h = harness();
    let cookie = session_cookie(&sign_in(&h, USERNAME, PASSWORD));

    let session = h
        .request(Method::Get, "/admin/v1/session")
        .cookie(&cookie)
        .send();

    assert_eq!(session.status, 200, "{}", session.body);
    let json = session.json();
    assert_eq!(json.field_str("auth_method").unwrap(), "password");
    assert_eq!(json.field_str("principal").unwrap(), "user:admin");
    assert_eq!(json.field_str("tenant").unwrap(), "acme");
    assert_eq!(
        json.opt_field_bool("break_glass").unwrap(),
        Some(false),
        "an ordinary password session must not be reported as break-glass; \
         the emergency path is separately alerted and separately reviewed"
    );
}

#[test]
fn a_wrong_password_and_an_unknown_username_are_refused_identically() {
    // The property: the response is not an oracle. A body that said "no such
    // user" for one and "wrong password" for the other would enumerate the
    // configured accounts for anyone who asked.
    let h = harness();

    let wrong_password = sign_in(&h, USERNAME, "not-the-password");
    let unknown_user = sign_in(&h, "someone-else", PASSWORD);

    assert_eq!(wrong_password.status, 401, "{}", wrong_password.body);
    assert_eq!(unknown_user.status, 401, "{}", unknown_user.body);
    assert_eq!(
        wrong_password.error_code, unknown_user.error_code,
        "the two refusals must carry the same code"
    );
    assert_eq!(
        wrong_password.json().field_str("error").ok(),
        unknown_user.json().field_str("error").ok(),
    );
    // Compared on the message itself, because that is what a caller reads.
    assert_eq!(
        error_message(&wrong_password),
        error_message(&unknown_user),
        "the two refusals must be indistinguishable"
    );
    for response in [&wrong_password, &unknown_user] {
        assert!(
            response.header("set-cookie").is_none(),
            "a refused sign-in must not set a session cookie"
        );
    }
}

#[test]
fn a_router_with_no_local_accounts_does_not_advertise_the_endpoint() {
    // Same rule as break-glass: a deployment that configured no local account
    // should not tell whoever is probing that the endpoint is live. 404, not
    // 401 — the difference is the whole point.
    let h = Harness::new();
    let response = sign_in(&h, USERNAME, PASSWORD);

    assert_eq!(response.status, 404, "{}", response.body);
    assert!(response.header("set-cookie").is_none());
}

#[test]
fn a_local_user_with_no_role_binding_cannot_sign_in() {
    // Knowing the password proves who you are, not what you may do. A session
    // with no role can reach no screen, and issuing one is a confusing way to
    // fail — so it is refused with a reason instead.
    let h = Harness::builder()
        .config(&config_with_user(USERNAME, PASSWORD, &[]))
        .build();
    let response = sign_in(&h, USERNAME, PASSWORD);

    assert_eq!(response.status, 403, "{}", response.body);
    assert!(
        response.header("set-cookie").is_none(),
        "no session may be established for a principal that can do nothing"
    );
}

#[test]
fn repeated_failures_lock_the_account_and_the_right_password_does_not_reopen_it() {
    let h = harness();

    for attempt in 1..=FAILURES_BEFORE_LOCKOUT {
        let response = sign_in(&h, USERNAME, "not-the-password");
        assert_eq!(response.status, 401, "attempt {attempt}: {}", response.body);
    }

    let locked = sign_in(&h, USERNAME, PASSWORD);
    assert_eq!(
        locked.status, 429,
        "the correct password must not reopen a locked account: {}",
        locked.body
    );
    assert!(
        locked.header("set-cookie").is_none(),
        "a locked account must not be issued a session"
    );
}

#[test]
fn a_locked_account_is_refused_before_its_password_is_checked() {
    // The ordering, which the test above does *not* catch on its own: a
    // lockout checked after the verification still refuses the right password,
    // so both orderings answer 429 there. What separates them is the *wrong*
    // password — verify-first reaches the mismatch and answers 401, and only a
    // check that runs first answers 429.
    //
    // The ordering is what makes the lockout a bound on work rather than a
    // bound on outcomes. Specification 3.2: a locked account must cost a map
    // lookup, not the ~100 ms PBKDF2 verification an unauthenticated caller
    // would otherwise be able to buy five times a minute per configured
    // account.
    let h = harness();
    for _ in 0..FAILURES_BEFORE_LOCKOUT {
        sign_in(&h, USERNAME, "not-the-password");
    }

    let response = sign_in(&h, USERNAME, "still-not-the-password");
    assert_eq!(
        response.status, 429,
        "a locked account must be refused before the password is verified, \
         not after: {}",
        response.body
    );
}

#[test]
fn the_lockout_ends_with_its_window() {
    // The other half: a lockout that never expired would turn five typos into
    // a permanent loss of the management plane on a deployment whose only
    // other way in is a break-glass token kept offline.
    let h = harness();
    for _ in 0..FAILURES_BEFORE_LOCKOUT {
        sign_in(&h, USERNAME, "not-the-password");
    }
    assert_eq!(sign_in(&h, USERNAME, PASSWORD).status, 429);

    h.advance(LOCKOUT_WINDOW_MILLIS);

    let response = sign_in(&h, USERNAME, PASSWORD);
    assert_eq!(
        response.status, 200,
        "the window must expire: {}",
        response.body
    );
}

#[test]
fn a_sign_in_that_worked_clears_the_failures_before_it() {
    // Without this, an operator who mistypes four times and then succeeds is
    // one typo away from a lockout for the rest of the window — and would have
    // no way to tell why.
    let h = harness();
    for _ in 0..FAILURES_BEFORE_LOCKOUT - 1 {
        sign_in(&h, USERNAME, "not-the-password");
    }
    assert_eq!(sign_in(&h, USERNAME, PASSWORD).status, 200);

    // A full fresh budget, not one attempt.
    for attempt in 1..=FAILURES_BEFORE_LOCKOUT - 1 {
        let response = sign_in(&h, USERNAME, "not-the-password");
        assert_eq!(response.status, 401, "attempt {attempt}: {}", response.body);
    }
    assert_eq!(
        sign_in(&h, USERNAME, PASSWORD).status,
        200,
        "the counter must have been reset by the successful sign-in"
    );
}

#[test]
fn one_accounts_failures_do_not_lock_another() {
    // Keyed by account, not global. A shared counter would let anyone who can
    // reach the listener lock every administrator out by guessing at one name.
    let mut text = config_with_user(USERNAME, PASSWORD, &["operator"]);
    let other = PasswordVerifier::derive("second-account-password", MIN_ITERATIONS)
        .unwrap()
        .encode();
    text.push_str(&format!(
        "local_user id=second principal=user:second tenant=acme verifier={other}\n\
         role_binding subject=principal:user:second role=operator\n"
    ));
    let h = Harness::builder().config(&text).build();

    for _ in 0..FAILURES_BEFORE_LOCKOUT {
        sign_in(&h, USERNAME, "not-the-password");
    }
    assert_eq!(sign_in(&h, USERNAME, PASSWORD).status, 429);

    let response = sign_in(&h, "second", "second-account-password");
    assert_eq!(
        response.status, 200,
        "the second account must be unaffected: {}",
        response.body
    );
}

#[test]
fn an_unknown_username_is_never_locked_out() {
    // The failure map is keyed by a *configured* username, so a caller cannot
    // grow it by inventing names (specification 3.2). The observable
    // consequence is that an unknown name keeps answering 401 rather than
    // starting to answer 429, which is also what keeps the two refusals
    // indistinguishable after five attempts.
    let h = harness();
    for _ in 0..FAILURES_BEFORE_LOCKOUT * 2 {
        let response = sign_in(&h, "no-such-account", "whatever");
        assert_eq!(response.status, 401, "{}", response.body);
    }
}

#[test]
fn a_malformed_body_is_refused_the_same_way_a_wrong_password_is() {
    // Missing fields, wrong types and an empty username all end at the same
    // 401 rather than at a message describing the schema — which would tell a
    // prober that the endpoint is configured and worth attacking.
    let h = harness();
    for payload in [
        "{}",
        "{\"username\":\"\",\"password\":\"\"}",
        "{\"username\":\"admin\"}",
        "{\"password\":\"a-password-that-is-not-the-username\"}",
        "{\"username\":123,\"password\":true}",
    ] {
        let response = h
            .request(Method::Post, "/admin/v1/auth/password")
            .json(payload)
            .send();
        assert_eq!(response.status, 401, "{payload}: {}", response.body);
        assert!(response.header("set-cookie").is_none());
    }
}

#[test]
fn an_overlong_username_is_refused_without_a_lookup() {
    // Bounded before it is compared or written to an audit record
    // (specification 3.2). 64 is `MAX_USERNAME_LEN`.
    let h = harness();
    let response = sign_in(&h, &"a".repeat(65), PASSWORD);
    assert_eq!(response.status, 401, "{}", response.body);
}

#[test]
fn the_password_never_appears_in_a_response_or_a_log() {
    // The failure mode this catches is an error message that helpfully echoes
    // what was submitted, which would put the password in the browser's
    // console, the router's log, and any ticket the operator pastes it into.
    let h = harness();
    let refused = sign_in(&h, USERNAME, "a-distinctive-wrong-password");
    let accepted = sign_in(&h, USERNAME, PASSWORD);

    for response in [&refused, &accepted] {
        assert!(
            !response.body.contains("a-distinctive-wrong-password"),
            "the submitted password must not be echoed: {}",
            response.body
        );
        assert!(
            !response.body.contains(PASSWORD),
            "the correct password must not be echoed: {}",
            response.body
        );
    }

    let logs = h.log_lines();
    for line in &logs {
        assert!(
            !line.contains("a-distinctive-wrong-password") && !line.contains(PASSWORD),
            "a password reached the log: {line}"
        );
    }
}

#[test]
fn both_outcomes_reach_the_audit_chain() {
    // A sign-in path that is not recorded is one an investigation cannot see.
    // Asserted through the audit *view* rather than the durable log, because
    // that is the screen someone actually reads — appending without a tenant
    // leaves the chain correct and the view blank (`DI-051`).
    let h = harness();
    sign_in(&h, USERNAME, "not-the-password");
    sign_in(&h, USERNAME, PASSWORD);

    let audit = h.get(&h.auditor(), "/admin/v1/audit");
    assert_eq!(audit.status, 200, "{}", audit.body);
    let body = audit.body;
    assert!(
        body.contains("login_failed"),
        "the refusal must be visible in the audit view: {body}"
    );
    assert!(
        body.contains("password_incorrect"),
        "and it must say why: {body}"
    );
    assert!(
        body.contains("\"login\""),
        "the successful sign-in must be visible too: {body}"
    );
}

// -- helpers ----------------------------------------------------------------

fn session_cookie(response: &harness::Response) -> String {
    response
        .header("set-cookie")
        .expect("a session cookie")
        .split(';')
        .next()
        .expect("a cookie pair")
        .to_owned()
}

fn error_message(response: &harness::Response) -> String {
    response
        .json()
        .get("error")
        .and_then(|error| error.field_str("message").ok())
        .map(str::to_owned)
        .expect("an error message")
}
