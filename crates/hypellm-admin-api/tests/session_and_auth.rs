//! The gate every management request passes through (specification 9.1, 15.4).
//!
//! `GET /admin/v1/session` and `POST /admin/v1/logout` are the only two
//! endpoints this suite calls for their own sake. Everything else it calls is a
//! probe: the origin check, the session check, the CSRF check and the freshness
//! check run in `AdminApi::handle` *before* dispatch, so they are properties of
//! the whole management surface rather than of any one handler. A regression
//! here would not break one screen, it would open all of them.
//!
//! The order the gate runs in is itself a security property and is asserted
//! directly. A caller from a hostile origin must be stopped before their cookie
//! is consulted; an unauthenticated caller must not learn which endpoints exist;
//! a cross-site POST must be refused before it reaches a handler that would act.
//! Each of those is a test whose failure would be exploitable, not cosmetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use hypellm_auth::SessionPolicy;
use hypellm_auth::session::{COOKIE_NAME, CSRF_HEADER};
use hypellm_core::rbac::{Permission, Role};
use hypellm_core::time::Clock;
use harness::{ALLOWED_ORIGIN, HOSTILE_ORIGIN, Harness, LOCAL_TARGET, TENANT_A, TENANT_B};
use std::collections::BTreeSet;
use wire_http1::Method;

/// Every mutating route the gate stands in front of, including one that does
/// not exist. A CSRF check performed per handler would let the missing one
/// through; a check performed in the gate refuses them all identically.
const MUTATING_ROUTES: &[(Method, &str)] = &[
    (Method::Post, "/admin/v1/logout"),
    (Method::Post, "/admin/v1/policies"),
    (Method::Post, "/admin/v1/keys"),
    (Method::Post, "/admin/v1/credentials"),
    (Method::Post, "/admin/v1/credentials/provider-secret:rotate"),
    (Method::Patch, "/admin/v1/targets/local:model"),
    (Method::Delete, "/admin/v1/keys/some-key"),
    (Method::Post, "/admin/v1/there-is-no-such-endpoint"),
];

// -- Authentication ---------------------------------------------------------

#[test]
fn an_unauthenticated_caller_cannot_tell_a_real_endpoint_from_an_invented_one() {
    // The session check runs before routing, so both answers are the same 401.
    // If routing ran first, an anonymous scan would map the management surface —
    // and, on the paths that take an identifier, confirm which resources exist.
    let admin = Harness::new();

    let real = admin.anonymous(Method::Get, "/admin/v1/session");
    let invented = admin.anonymous(Method::Get, "/admin/v1/invented");

    assert_eq!(real.status, 401, "{}", real.body);
    assert_eq!(invented.status, 401, "{}", invented.body);
    assert_eq!(real.error_code, invented.error_code);

    // Compared as rendered JSON rather than field by field, so that a future
    // hint added anywhere inside the error object fails this test.
    let error_of = |response: &harness::Response| {
        format!("{:?}", response.json().as_object().unwrap().get("error"))
    };
    assert_eq!(
        error_of(&real),
        error_of(&invented),
        "the two refusals must be indistinguishable"
    );
    assert!(error_of(&real).contains("unauthenticated"), "{}", real.body);
}

#[test]
fn no_cookie_a_browser_could_be_tricked_into_sending_authenticates() {
    // Each of these is a way a real session cookie gets impersonated: a guessed
    // token, an emptied one, one padded past the accepted length, one set under
    // a name that merely looks like the `__Host-` one, and one set without the
    // prefix at all by a subdomain that cannot set the prefixed name.
    let admin = Harness::new();
    let live = admin.operator();
    let long = "a".repeat(200);

    let forgeries = [
        "__Host-hypellm_session=guessed-token",
        "__Host-hypellm_session=",
        "hypellm_session=stripped-prefix",
        "x__Host-hypellm_session=sibling-name",
        "__Host-hypellm_session_extra=near-miss-name",
        "__host-hypellm_session=case-folded-name",
    ];

    for cookie in forgeries {
        let response = admin
            .request(Method::Get, "/admin/v1/session")
            .cookie(cookie)
            .send();
        assert_eq!(response.status, 401, "'{cookie}' authenticated: {}", response.body);
    }

    for cookie in [
        format!("__Host-hypellm_session={long}"),
        format!("__Host-hypellm_session={} extra", live.token),
    ] {
        let response = admin
            .request(Method::Get, "/admin/v1/session")
            .cookie(&cookie)
            .send();
        assert_eq!(response.status, 401, "'{cookie}' authenticated: {}", response.body);
    }

    // The same token in a well-formed cookie still works, so the refusals above
    // are the cookie parser being strict and not the fixture being broken.
    let ok = admin.get(&live, "/admin/v1/session");
    assert_eq!(ok.status, 200, "{}", ok.body);
}

#[test]
fn a_session_token_presented_as_a_bearer_credential_is_not_accepted() {
    // The management session is a cookie, not a bearer token. Accepting it in an
    // Authorization header would hand any component that legitimately sees a
    // header — a proxy log, an error report — a usable credential, and would
    // sidestep the SameSite protection the cookie carries.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Get, "/admin/v1/session")
        .header("authorization", &format!("Bearer {}", operator.token))
        .send();

    assert_eq!(response.status, 401, "{}", response.body);
}

#[test]
fn the_sign_in_bypass_reaches_the_sign_in_endpoints_and_nothing_beside_them() {
    // `/auth/google/start` and `/auth/google/callback` are dispatched before the
    // session check, because a caller signing in has no session yet. That bypass
    // is matched on the exact path: a neighbouring path must fall back into the
    // gate rather than inherit the exemption.
    let admin = Harness::new();

    // Sign-in is not configured in this deployment, so the exempt paths answer
    // 404 — the point is that they answer at all without a session.
    for (method, path) in [
        (Method::Post, "/admin/v1/auth/google/start"),
        (Method::Get, "/admin/v1/auth/google/callback"),
    ] {
        let response = admin.anonymous(method, path);
        assert_eq!(response.status, 404, "{path}: {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("not_found"));
    }

    for (method, path) in [
        (Method::Post, "/admin/v1/auth/google/startx"),
        (Method::Post, "/admin/v1/auth/google/callback"),
        (Method::Get, "/admin/v1/auth/google/start"),
        (Method::Post, "/admin/v1/auth/google/start/../keys"),
    ] {
        let response = admin.anonymous(method, path);
        assert_eq!(
            response.status, 401,
            "{path} inherited the sign-in exemption: {}",
            response.body
        );
    }
}

// -- What a session discloses about itself ----------------------------------

#[test]
fn a_session_reports_its_own_principal_tenant_and_permissions_and_no_others() {
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin.get(&operator, "/admin/v1/session");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.str_field("principal"), operator.principal.as_str());
    assert_eq!(response.str_field("tenant"), TENANT_A);
    assert_eq!(response.str_field("auth_method"), "oidc");

    let reported: BTreeSet<String> = response
        .json()
        .field_array("permissions")
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect();
    let held: BTreeSet<String> = Role::Operator
        .permissions()
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    assert_eq!(reported, held, "{}", response.body);

    // The report is exact in both directions: a permission the role does not
    // carry must not appear, or the application will offer an action the API
    // will then refuse.
    for absent in [Permission::ManageKeys, Permission::PublishPolicy] {
        assert!(
            !reported.contains(absent.as_str()),
            "an operator was told it holds {absent}: {}",
            response.body
        );
    }
}

#[test]
fn an_unprivileged_session_is_told_it_holds_nothing() {
    // An authenticated principal with no role binding is a real state — someone
    // whose grant was removed while signed in. It must be able to see who it is,
    // and must be told the truth about what it can do.
    let admin = Harness::new();
    let nobody = admin.unprivileged();

    let response = admin.get(&nobody, "/admin/v1/session");

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(response.json().field_array("permissions").unwrap().is_empty());
    assert!(response.json().field_array("roles").unwrap().is_empty());

    let refused = admin.get(&nobody, "/admin/v1/targets");
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.error_code.as_deref(), Some("forbidden"));
}

#[test]
fn a_session_in_one_tenant_reports_that_tenant_and_never_the_other() {
    // Appendix B: management visibility never exceeds the caller's tenant. The
    // session document is the first thing the application reads, and a wrong
    // tenant here would scope every subsequent screen wrongly.
    let admin = Harness::new();
    let here = admin.operator_in(TENANT_A);
    let there = admin.operator_in(TENANT_B);

    let mine = admin.get(&here, "/admin/v1/session");
    let theirs = admin.get(&there, "/admin/v1/session");

    assert_eq!(mine.str_field("tenant"), TENANT_A);
    assert_eq!(theirs.str_field("tenant"), TENANT_B);
    assert!(!mine.body_contains(TENANT_B), "{}", mine.body);
    assert!(!theirs.body_contains(TENANT_A), "{}", theirs.body);
    assert!(!mine.body_contains(there.principal.as_str()), "{}", mine.body);
    assert!(!theirs.body_contains(here.principal.as_str()), "{}", theirs.body);
}

#[test]
fn a_session_reports_the_configuration_the_router_is_actually_serving() {
    // The application uses this pair to detect that the policy changed under it.
    // A stale or invented digest would make it show a configuration nobody is
    // routing on.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let response = admin.get(&viewer, "/admin/v1/session");

    let config = admin.config();
    assert_eq!(
        response.json().field_i64("config_version").unwrap(),
        i64::try_from(config.snapshot.version).unwrap()
    );
    assert_eq!(response.str_field("config_digest"), config.digest_short());
    // The short digest, not the full one: nothing is served by publishing the
    // whole thing, and the publish precondition is built from it.
    assert!(!response.body_contains(&config.digest.to_hex()), "{}", response.body);
}

#[test]
fn a_break_glass_session_is_reported_as_one() {
    // Specification 22.4 makes break-glass separately audited and visible. An
    // operator looking at the application must be able to see they are holding
    // the emergency role rather than their ordinary one.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    let response = admin.get(&oncall, "/admin/v1/session");

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.str_field("auth_method"), "break_glass");
    assert_eq!(
        response.json().opt_field_bool("break_glass").unwrap(),
        Some(true)
    );

    let ordinary = admin.get(&admin.operator(), "/admin/v1/session");
    assert_eq!(
        ordinary.json().opt_field_bool("break_glass").unwrap(),
        Some(false)
    );
}

#[test]
fn the_session_document_never_carries_the_cookie_that_authenticates_it() {
    // The cookie is HttpOnly precisely so that script cannot read it. Echoing it
    // in a JSON body — which script can read — would undo that, and would put a
    // live credential into every error report and browser cache the response
    // touches.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin.get(&operator, "/admin/v1/session");

    assert!(!response.body_contains(&operator.token), "{}", response.body);
    assert!(!response.body_contains(COOKIE_NAME), "{}", response.body);
    assert!(response.headers_named("set-cookie").is_empty());
}

#[test]
fn the_session_token_never_appears_in_a_response_or_a_log_line() {
    // Specification 17: bearer values stay out of telemetry and out of bodies. A
    // token in a log is a token in every backup and shipper downstream of it.
    //
    // The management path writes no log lines today, so the log half of this is
    // a guard on the first handler that starts writing one; the response half
    // covers every code path a request can take — success, refusal for
    // permission, and refusal for a bad token.
    let admin = Harness::new();
    let operator = admin.operator();
    let viewer = admin.viewer();

    let responses = [
        admin.get(&operator, "/admin/v1/session"),
        admin.get(&operator, "/admin/v1/overview"),
        admin.get(&viewer, "/admin/v1/keys"),
        admin
            .request(Method::Get, "/admin/v1/session")
            .cookie(&format!("{COOKIE_NAME}={}x", operator.token))
            .send(),
        admin.post(&operator, "/admin/v1/logout", ""),
    ];

    for response in &responses {
        assert!(
            !response.body_contains(&operator.token),
            "a {} response carried the session token: {}",
            response.status,
            response.body
        );
        for (name, value) in &response.headers {
            assert!(
                !value.contains(&operator.token),
                "{name} carried the session token"
            );
        }
    }

    for line in admin.log_lines() {
        assert!(!line.contains(&operator.token), "a log line carried the session token: {line}");
        assert!(!line.contains(&operator.csrf), "a log line carried the CSRF token: {line}");
    }
}

// -- Logout ------------------------------------------------------------------

#[test]
fn logging_out_invalidates_the_session_on_the_server_not_only_in_the_browser() {
    // Specification 9.1: "Logout invalidates the server session." A logout that
    // only cleared the cookie would leave a working credential in the hands of
    // anyone who had already captured it.
    let admin = Harness::new();
    let operator = admin.operator();
    assert_eq!(admin.get(&operator, "/admin/v1/session").status, 200);

    let logout = admin.post(&operator, "/admin/v1/logout", "");

    assert_eq!(logout.status, 204, "{}", logout.body);
    let after = admin.get(&operator, "/admin/v1/session");
    assert_eq!(after.status, 401, "the token still worked: {}", after.body);
    assert!(
        !admin
            .state
            .sessions
            .sessions_for(&operator.principal)
            .iter()
            .any(|s| s.digest == operator.session.digest),
        "the record survived the logout"
    );
}

#[test]
fn logging_out_clears_the_cookie_with_the_attributes_the_host_prefix_requires() {
    // A `__Host-` cookie is only overwritten by a Set-Cookie carrying Secure and
    // Path=/ with no Domain. Getting that wrong leaves the dead cookie in the
    // browser, and the user looking at a signed-in application that 401s.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin.post(&operator, "/admin/v1/logout", "");

    let cookies = response.headers_named("set-cookie");
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = cookies[0];
    assert!(cookie.starts_with(&format!("{COOKIE_NAME}=;")), "{cookie}");
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    assert!(cookie.contains("Path=/"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(!cookie.contains("Domain"), "a __Host- cookie carries no Domain: {cookie}");
    assert!(!cookie.contains(&operator.token), "{cookie}");
}

#[test]
fn logging_out_ends_one_session_and_leaves_the_principals_others_alive() {
    // Signing out of one browser must not sign the operator out of the console
    // they are mid-incident in. The store keys sessions by token digest, so this
    // is a property of what logout is given, not of who they are.
    let admin = Harness::new();
    let laptop = admin.session("user:operator-acme", TENANT_A, &[Role::Operator]);
    let console = admin.session("user:operator-acme", TENANT_A, &[Role::Operator]);
    assert_ne!(laptop.token, console.token);

    assert_eq!(admin.post(&laptop, "/admin/v1/logout", "").status, 204);

    assert_eq!(admin.get(&laptop, "/admin/v1/session").status, 401);
    let survivor = admin.get(&console, "/admin/v1/session");
    assert_eq!(survivor.status, 200, "{}", survivor.body);
}

#[test]
fn a_cross_site_logout_is_refused_and_the_session_survives_it() {
    // Forced sign-out is the cheapest cross-site attack on a management API:
    // no data moves, but the operator is repeatedly thrown out of the console.
    // The CSRF gate has to cover logout as much as it covers a mutation.
    let admin = Harness::new();
    let operator = admin.operator();

    let forged = admin
        .request(Method::Post, "/admin/v1/logout")
        .as_session(&operator)
        .without_csrf()
        .send();

    assert_eq!(forged.status, 403, "{}", forged.body);
    assert_eq!(forged.error_code.as_deref(), Some("csrf_required"));
    let still_signed_in = admin.get(&operator, "/admin/v1/session");
    assert_eq!(still_signed_in.status, 200, "{}", still_signed_in.body);
}

// -- CSRF --------------------------------------------------------------------

#[test]
fn every_mutating_route_is_refused_without_a_csrf_token_including_one_that_does_not_exist() {
    // The check is in the gate, so a handler added later inherits it. The
    // non-existent path is the load-bearing case: it proves the refusal happens
    // before routing, which is the only way a new mutating route cannot forget
    // to ask.
    let admin = Harness::new();
    let oncall = admin.break_glass();

    for (method, path) in MUTATING_ROUTES {
        let response = admin
            .request(method.clone(), path)
            .as_session(&oncall)
            .without_csrf()
            .json("{}")
            .send();
        assert_eq!(response.status, 403, "{method:?} {path}: {}", response.body);
        assert_eq!(
            response.error_code.as_deref(),
            Some("csrf_required"),
            "{method:?} {path}: {}",
            response.body
        );
    }
}

#[test]
fn a_read_needs_no_csrf_token() {
    // The other half of the rule. If safe methods demanded the header the
    // application would have to attach it everywhere, and the first thing anyone
    // would do is put it somewhere a page can read.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Get, "/admin/v1/session")
        .as_session(&operator)
        .without_csrf()
        .send();

    assert_eq!(response.status, 200, "{}", response.body);
}

#[test]
fn the_csrf_token_cannot_be_computed_from_the_cookie_it_is_bound_to() {
    // The token is a keyed digest of the session digest, so possession of the
    // cookie is not possession of the token. That is what makes the double
    // submit meaningful: a page that somehow reads the cookie still cannot forge
    // a mutation.
    let admin = Harness::new();
    let operator = admin.operator();
    assert_ne!(operator.csrf, operator.token);

    for presented in [operator.token.clone(), String::new(), "*".to_owned()] {
        let response = admin
            .request(Method::Post, "/admin/v1/logout")
            .as_session(&operator)
            .csrf(&presented)
            .send();
        assert_eq!(response.status, 403, "'{presented}' was accepted: {}", response.body);
        assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    }
}

#[test]
fn another_sessions_csrf_token_does_not_authorize_this_one() {
    // Tokens are per session, not per deployment. If they were interchangeable,
    // any signed-in user could hand an attacker a token that works against every
    // other user's cookie.
    let admin = Harness::new();
    let mine = admin.operator();
    let theirs = admin.operator_in(TENANT_B);

    let response = admin
        .request(Method::Post, "/admin/v1/logout")
        .as_session(&mine)
        .csrf(&theirs.csrf)
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    assert_eq!(admin.get(&mine, "/admin/v1/session").status, 200);
}

#[test]
fn a_csrf_token_dies_with_the_session_it_was_bound_to() {
    // Rotation on re-authentication (specification 9.1) has to carry the token
    // with it. A token that outlived the rotation would be a credential the
    // operator could not revoke by signing in again.
    let admin = Harness::new();
    let before = admin.operator();
    let after = admin.reauthenticate(&before);
    assert_ne!(before.csrf, after.csrf);

    let stale = admin
        .request(Method::Post, "/admin/v1/logout")
        .as_session(&after)
        .csrf(&before.csrf)
        .send();

    assert_eq!(stale.status, 403, "{}", stale.body);
    assert_eq!(stale.error_code.as_deref(), Some("csrf_required"));
}

#[test]
fn a_second_csrf_header_cannot_be_smuggled_past_the_first() {
    // Only the first value is consulted. A gate that accepted *any* of the
    // presented values would let a request that already carries an attacker's
    // header be rescued by appending a real one — the header-list equivalent of
    // request smuggling.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Post, "/admin/v1/logout")
        .as_session(&operator)
        .csrf("not-the-token")
        .header(CSRF_HEADER, &operator.csrf)
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("csrf_required"));
    assert_eq!(admin.get(&operator, "/admin/v1/session").status, 200);
}

// -- Cross-origin ------------------------------------------------------------

#[test]
fn a_request_from_an_unlisted_origin_is_refused_before_the_cookie_is_consulted() {
    // Specification 15.4 puts the origin check first. The evidence is in the
    // error code: an anonymous request from a hostile origin is refused for the
    // origin, not for the missing session, and a request that would have failed
    // authorization is refused for the origin too.
    let admin = Harness::new();
    let viewer = admin.viewer();

    let anonymous = admin
        .request(Method::Get, "/admin/v1/session")
        .origin(HOSTILE_ORIGIN)
        .send();
    assert_eq!(anonymous.status, 403, "{}", anonymous.body);
    assert_eq!(anonymous.error_code.as_deref(), Some("origin_not_permitted"));

    // A viewer has no ManageKeys, so a same-origin call here is 403 forbidden.
    // From a hostile origin the *origin* must be the reason, or the response
    // would leak whether the caller is authorized.
    let unauthorized = admin
        .request(Method::Get, "/admin/v1/keys")
        .as_session(&viewer)
        .origin(HOSTILE_ORIGIN)
        .send();
    assert_eq!(unauthorized.error_code.as_deref(), Some("origin_not_permitted"));

    let missing = admin
        .request(Method::Get, "/admin/v1/no-such-endpoint")
        .origin(HOSTILE_ORIGIN)
        .send();
    assert_eq!(missing.error_code.as_deref(), Some("origin_not_permitted"));
}

#[test]
fn the_origin_allowlist_is_matched_exactly() {
    // Every entry here is a near miss a suffix, prefix, or case-insensitive
    // matcher would accept. `https://admin.test.evil.example` is the one that
    // matters most: registering it costs nothing.
    let admin = Harness::new();
    let operator = admin.operator();

    for hostile in [
        HOSTILE_ORIGIN,
        "https://admin.test.evil.example",
        "https://evil.example/https://admin.test",
        "http://admin.test",
        "https://admin.test:8443",
        "https://ADMIN.TEST",
        "https://admin.test/",
        "https://xadmin.test",
        "null",
    ] {
        let response = admin
            .request(Method::Get, "/admin/v1/session")
            .as_session(&operator)
            .origin(hostile)
            .send();
        assert_eq!(
            response.error_code.as_deref(),
            Some("origin_not_permitted"),
            "'{hostile}' was admitted: {}",
            response.body
        );
    }

    let permitted = admin
        .request(Method::Get, "/admin/v1/session")
        .as_session(&operator)
        .origin(ALLOWED_ORIGIN)
        .send();
    assert_eq!(permitted.status, 200, "{}", permitted.body);
}

#[test]
fn a_listed_origin_may_read_and_may_mutate() {
    // The allowlist is a gate, not a read-only concession: the admin application
    // is served from an allowlisted origin and has to be able to act from there.
    let admin = Harness::new();
    let operator = admin.operator();

    let read = admin
        .request(Method::Get, "/admin/v1/targets")
        .as_session(&operator)
        .origin(ALLOWED_ORIGIN)
        .send();
    assert_eq!(read.status, 200, "{}", read.body);
    assert!(read.ids().contains(&LOCAL_TARGET.to_owned()));

    let mutate = admin
        .request(Method::Post, "/admin/v1/logout")
        .as_session(&operator)
        .origin(ALLOWED_ORIGIN)
        .send();
    assert_eq!(mutate.status, 204, "{}", mutate.body);
}

#[test]
fn a_preflight_from_a_listed_origin_is_answered_without_a_session() {
    // A browser sends the preflight without credentials. Demanding a session
    // here would block every cross-origin request the allowlist exists to
    // permit, and the failure would look like a CORS misconfiguration rather
    // than an auth one.
    let admin = Harness::new();

    let response = admin
        .request(Method::Options, "/admin/v1/targets")
        .origin(ALLOWED_ORIGIN)
        .send();

    assert_eq!(response.status, 204, "{}", response.body);
    assert_eq!(
        response.header("Access-Control-Allow-Origin"),
        Some(ALLOWED_ORIGIN)
    );
    assert_eq!(response.header("Access-Control-Allow-Credentials"), Some("true"));
    assert_eq!(response.header("Vary"), Some("Origin"));

    let allow_headers = response
        .header("Access-Control-Allow-Headers")
        .expect("allow-headers");
    assert!(allow_headers.contains(CSRF_HEADER), "{allow_headers}");
    assert!(allow_headers.contains("If-Match"), "{allow_headers}");

    let expose = response
        .header("Access-Control-Expose-Headers")
        .expect("expose-headers");
    assert!(expose.contains("ETag"), "an If-Match client must read the ETag: {expose}");
}

#[test]
fn a_preflight_from_an_unlisted_origin_carries_no_cors_headers_at_all() {
    // The refusal has to be silent as well as negative: a 403 that still carried
    // Access-Control-Allow-Origin would be granted by the browser regardless of
    // the status, because the browser only reads the headers.
    let admin = Harness::new();

    let response = admin
        .request(Method::Options, "/admin/v1/targets")
        .origin(HOSTILE_ORIGIN)
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("origin_not_permitted"));
    for (name, value) in &response.headers {
        assert!(
            !name.to_ascii_lowercase().starts_with("access-control-"),
            "the refusal carried {name}: {value}"
        );
    }
}

#[test]
fn a_same_origin_preflight_is_answered_without_granting_any_origin() {
    // No Origin means no CORS. Answering 204 keeps a same-origin OPTIONS working
    // while granting nothing to anybody.
    let admin = Harness::new();

    let response = admin.anonymous(Method::Options, "/admin/v1/targets");

    assert_eq!(response.status, 204, "{}", response.body);
    assert!(response.header("Access-Control-Allow-Origin").is_none());
}

#[test]
fn no_response_ever_grants_a_wildcard_origin() {
    // Specification 15.4: "no wildcard with cookies". Browsers reject
    // `Allow-Origin: *` alongside `Allow-Credentials: true`, so emitting it
    // would break the application; emitting it *without* credentials would make
    // the management API world-readable to any page that can reach it.
    let admin = Harness::new();
    let operator = admin.operator();

    let mut responses = vec![
        admin
            .request(Method::Options, "/admin/v1/targets")
            .origin(ALLOWED_ORIGIN)
            .send(),
        admin.anonymous(Method::Options, "/admin/v1/targets"),
    ];
    for origin in [Some(ALLOWED_ORIGIN), Some(HOSTILE_ORIGIN), None] {
        let mut builder = admin
            .request(Method::Get, "/admin/v1/session")
            .as_session(&operator);
        if let Some(origin) = origin {
            builder = builder.origin(origin);
        }
        responses.push(builder.send());
    }

    for response in &responses {
        for (name, value) in &response.headers {
            assert_ne!(value, "*", "{name} was a wildcard");
        }
        assert_ne!(response.header("Access-Control-Allow-Origin"), Some("*"));
        assert!(!response.body_contains("Access-Control"));
    }
}

#[test]
fn an_empty_allowlist_refuses_every_origin_while_same_origin_use_still_works() {
    // The default deployment serves the application from the router's own
    // origin, where the correct allowlist is empty. That must lock out every
    // cross-origin caller without breaking the console itself.
    let admin = Harness::builder().no_cors().build();
    let operator = admin.operator();

    for origin in [ALLOWED_ORIGIN, HOSTILE_ORIGIN] {
        let refused = admin
            .request(Method::Get, "/admin/v1/session")
            .as_session(&operator)
            .origin(origin)
            .send();
        assert_eq!(
            refused.error_code.as_deref(),
            Some("origin_not_permitted"),
            "'{origin}' was admitted with an empty allowlist: {}",
            refused.body
        );

        let preflight = admin
            .request(Method::Options, "/admin/v1/session")
            .origin(origin)
            .send();
        assert_eq!(preflight.status, 403, "{}", preflight.body);
    }

    let same_origin = admin.get(&operator, "/admin/v1/session");
    assert_eq!(same_origin.status, 200, "{}", same_origin.body);
}

#[test]
fn every_configured_origin_is_admitted_and_only_those() {
    let admin = Harness::builder()
        .cors_origins(&["https://one.test", "https://two.test"])
        .build();
    let operator = admin.operator();

    for origin in ["https://one.test", "https://two.test"] {
        let response = admin
            .request(Method::Get, "/admin/v1/session")
            .as_session(&operator)
            .origin(origin)
            .send();
        assert_eq!(response.status, 200, "'{origin}': {}", response.body);
    }

    let refused = admin
        .request(Method::Get, "/admin/v1/session")
        .as_session(&operator)
        .origin("https://three.test")
        .send();
    assert_eq!(refused.error_code.as_deref(), Some("origin_not_permitted"));
}

#[test]
fn the_origin_gate_runs_before_the_sign_in_endpoints() {
    // Sign-in is exempt from the session check, not from the origin check. If it
    // were exempt from both, a hostile page could drive the OIDC handshake and
    // read whatever the start endpoint returns.
    let admin = Harness::new();

    let response = admin
        .request(Method::Post, "/admin/v1/auth/google/start")
        .origin(HOSTILE_ORIGIN)
        .json("{}")
        .send();

    assert_eq!(response.status, 403, "{}", response.body);
    assert_eq!(response.error_code.as_deref(), Some("origin_not_permitted"));
}

#[test]
fn a_second_origin_header_cannot_reach_the_gate() {
    // The gate reads one Origin. That is only safe because the header parser
    // refuses a duplicate outright rather than letting the two disagree — the
    // classic way a checked value and a used value come apart.
    let mut headers = wire_http1::Headers::default();
    headers.append("origin", ALLOWED_ORIGIN).unwrap();
    assert!(
        headers.append("origin", HOSTILE_ORIGIN).is_err(),
        "a duplicate Origin must be refused before any handler sees it"
    );

    // The same reasoning covers the cookie: the gate reads the first session
    // cookie, so a second Cookie header must not be accepted either.
    let mut headers = wire_http1::Headers::default();
    headers.append("cookie", "__Host-hypellm_session=one").unwrap();
    assert!(
        headers.append("cookie", "__Host-hypellm_session=two").is_err(),
        "a duplicate Cookie must be refused before any handler sees it"
    );
}

#[test]
fn a_listed_origin_may_read_the_response_it_was_allowed_to_make() {
    // The preflight grants the request; the *actual* response has to carry
    // Access-Control-Allow-Origin as well, or the browser discards a 200 it
    // already received. Without this the cross-origin deployment specification
    // 15.4 describes cannot work at all.
    let admin = Harness::new();
    let operator = admin.operator();

    let response = admin
        .request(Method::Get, "/admin/v1/session")
        .as_session(&operator)
        .origin(ALLOWED_ORIGIN)
        .send();

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.header("Access-Control-Allow-Origin"),
        Some(ALLOWED_ORIGIN),
        "the allowed origin cannot read its own response"
    );
    assert_eq!(response.header("Access-Control-Allow-Credentials"), Some("true"));
    assert_eq!(response.header("Vary"), Some("Origin"));

    // And the grant is not handed out unconditionally: a same-origin request
    // carries no Origin and needs no CORS headers, and emitting one here would
    // be the reflect-anything mistake wearing the fix's clothes.
    let same_origin = admin.get(&operator, "/admin/v1/session");
    assert_eq!(same_origin.status, 200, "{}", same_origin.body);
    assert_eq!(same_origin.header("Access-Control-Allow-Origin"), None);

    // A wildcard is never emitted, with cookies or without (15.4).
    for (name, value) in &response.headers {
        assert_ne!(value, "*", "{name} must never be a wildcard");
    }
}

// -- Lifetime ----------------------------------------------------------------

#[test]
fn the_idle_window_is_exactly_the_configured_one() {
    // Two sessions, one clock. The one that was used is still live a
    // millisecond after the other has timed out, which pins the boundary from
    // both sides without a second harness.
    let admin = Harness::new();
    let idle_millis = admin.state.sessions.policy().idle_millis;
    let used = admin.operator();
    let untouched = admin.viewer();

    admin.advance(idle_millis - 1);
    let just_inside = admin.get(&used, "/admin/v1/session");
    assert_eq!(just_inside.status, 200, "{}", just_inside.body);

    admin.advance(1);
    let timed_out = admin.get(&untouched, "/admin/v1/session");
    assert_eq!(timed_out.status, 401, "{}", timed_out.body);
    assert_eq!(timed_out.error_code.as_deref(), Some("unauthenticated"));

    let still_live = admin.get(&used, "/admin/v1/session");
    assert_eq!(still_live.status, 200, "{}", still_live.body);
}

#[test]
fn a_timed_out_session_stays_dead() {
    // The record is dropped on the failed validation, so the token cannot come
    // back if the clock or the request pattern changes afterwards.
    let admin = Harness::new();
    let operator = admin.operator();

    admin.advance(admin.state.sessions.policy().idle_millis);
    assert_eq!(admin.get(&operator, "/admin/v1/session").status, 401);
    assert!(admin.state.sessions.sessions_for(&operator.principal).is_empty());

    assert_eq!(admin.get(&operator, "/admin/v1/session").status, 401);
    let logout = admin.post(&operator, "/admin/v1/logout", "");
    assert_eq!(logout.status, 401, "{}", logout.body);
}

#[test]
fn activity_slides_the_idle_window_but_not_the_absolute_lifetime() {
    // Specification 9.1 asks for "short idle *and* absolute lifetimes". A
    // console left open all day is signed out on the absolute limit however busy
    // it was; that is the limit an attacker holding a stolen cookie cannot keep
    // extending.
    let policy = SessionPolicy {
        idle_millis: 10 * 60 * 1000,
        absolute_millis: 60 * 60 * 1000,
        ..SessionPolicy::DEFAULT
    };
    let admin = Harness::builder().session_policy(policy).build();
    let operator = admin.operator();

    // Busy for the whole hour: eleven requests five minutes apart, each well
    // inside the idle window.
    for step in 1..=11 {
        admin.advance(5 * 60 * 1000);
        let response = admin.get(&operator, "/admin/v1/session");
        assert_eq!(
            response.status, 200,
            "the session died at minute {}: {}",
            step * 5,
            response.body
        );
    }
    assert_eq!(admin.clock.now_millis(), 55 * 60 * 1000);

    admin.advance(5 * 60 * 1000);
    let expired = admin.get(&operator, "/admin/v1/session");
    assert_eq!(
        expired.status, 401,
        "activity extended the absolute lifetime: {}",
        expired.body
    );
}

#[test]
fn a_wall_clock_step_neither_extends_nor_shortens_a_session() {
    // Session lifetimes are measured on the monotonic clock. If they were read
    // from the wall clock, an NTP step backwards would extend every live session
    // and a step forwards would sign the whole console out mid-incident.
    let admin = Harness::new();
    let operator = admin.operator();

    admin.skew_wall(24 * 60 * 60 * 1000);
    let after_jump_forward = admin.get(&operator, "/admin/v1/session");
    assert_eq!(after_jump_forward.status, 200, "{}", after_jump_forward.body);

    admin.advance(admin.state.sessions.policy().idle_millis);
    admin.skew_wall(-(48 * 60 * 60 * 1000));
    let after_jump_back = admin.get(&operator, "/admin/v1/session");
    assert_eq!(
        after_jump_back.status, 401,
        "a backwards wall-clock step revived an expired session: {}",
        after_jump_back.body
    );
}

#[test]
fn a_sensitive_action_needs_an_authentication_no_older_than_the_policy_allows() {
    // Specification 9.1 requires reauthentication for credential changes, role
    // grants, break-glass and publication. `ManageKeys` is one of them, so even
    // *reading* the key list goes stale — which is the intent: an unattended
    // console must not stay dangerous.
    let admin = Harness::new();
    let oncall = admin.break_glass();
    let window = admin.state.sessions.policy().reauthentication_millis;

    admin.advance(window);
    let fresh_enough = admin.get(&oncall, "/admin/v1/keys");
    assert_eq!(fresh_enough.status, 200, "{}", fresh_enough.body);

    admin.advance(1);
    let stale = admin.get(&oncall, "/admin/v1/keys");
    assert_eq!(stale.status, 403, "{}", stale.body);
    assert_eq!(stale.error_code.as_deref(), Some("reauthentication_required"));

    // The rest of the surface stays usable: freshness gates the sensitive
    // action, it does not end the session.
    let ordinary = admin.get(&oncall, "/admin/v1/overview");
    assert_eq!(ordinary.status, 200, "{}", ordinary.body);

    let renewed = admin.reauthenticate(&oncall);
    let restored = admin.get(&renewed, "/admin/v1/keys");
    assert_eq!(restored.status, 200, "{}", restored.body);
    // Rotation replaces the token, so the value an attacker may have captured
    // before the reauthentication is worthless afterwards.
    assert_eq!(admin.get(&oncall, "/admin/v1/session").status, 401);
}

#[test]
fn a_stale_authentication_is_refused_before_the_action_is_taken() {
    // The freshness check has to run before the side effect, not after. A
    // credential rotation that stored the secret and *then* reported
    // `reauthentication_required` would leave the deployment changed by a
    // request it told the operator it had refused.
    let admin = Harness::new();
    let manager = admin.credential_manager();

    admin.advance(admin.state.sessions.policy().reauthentication_millis + 1);
    let refused = admin.post(
        &manager,
        "/admin/v1/credentials/provider-secret:rotate",
        r#"{"secret":"rotated-behind-a-stale-session"}"#,
    );

    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.error_code.as_deref(), Some("reauthentication_required"));
    assert!(
        admin.credentials.is_empty(),
        "the refused rotation still wrote a secret: {:?}",
        admin.credentials.references()
    );
}

#[test]
fn an_error_response_carries_the_cross_origin_grant_too() {
    // A browser can only read a body it was granted access to, and that
    // includes an error body. Without the grant on the error path, an
    // allowlisted admin origin receives every 401, 403, 412 and 428 as an
    // opaque network failure — so the console can tell the operator that
    // something went wrong, but never that their session expired.
    let admin = Harness::new();

    // Unauthenticated: the handler refuses before it looks at anything else.
    let response = admin
        .request(Method::Get, "/admin/v1/targets")
        .origin(ALLOWED_ORIGIN)
        .send();

    assert_eq!(response.status, 401, "{}", response.body);
    assert_eq!(
        response.header("Access-Control-Allow-Origin"),
        Some(ALLOWED_ORIGIN),
        "the error carried no grant, so a browser cannot read why it failed"
    );
    assert_eq!(response.header("Access-Control-Allow-Credentials"), Some("true"));

    // And the body it can now read actually says what happened.
    assert!(response.error_code.is_some());
}

#[test]
fn a_refused_origin_is_not_handed_a_grant_by_the_error_path() {
    // The grant on errors must not become a way around the allowlist: an
    // origin the policy turned away must not be able to read the refusal
    // either.
    let admin = Harness::new();

    let response = admin
        .request(Method::Get, "/admin/v1/targets")
        .origin(HOSTILE_ORIGIN)
        .send();

    assert_ne!(response.status, 200);
    assert_eq!(
        response.header("Access-Control-Allow-Origin"),
        None,
        "a refused origin was handed a cross-origin grant"
    );
}
