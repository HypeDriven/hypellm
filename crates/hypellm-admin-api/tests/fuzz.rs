//! Fuzz targets for the management API.
//!
//! Specification 21 requires a Fuzz layer covering the "management API"; this
//! is that target. It drives the real `AdminApi::handle` through the same
//! harness the behavioural suites use, so a mutation reaches the gate, the
//! session check, the CSRF check and the handler exactly as a request would.
//!
//! # What is asserted beyond "does not panic"
//!
//! The management plane can change who may reach which model, mint and revoke
//! credentials, and publish policy. Its interesting failures are not crashes:
//!
//! - **Authorization bypass.** No body, however shaped, may make an
//!   unauthenticated or unprivileged caller succeed. The gate runs before
//!   dispatch, so this is a property of the whole surface rather than of any
//!   handler — which also means one regression would open all of them.
//! - **Tenant escape.** Appendix B: "Management visibility never exceeds the
//!   caller's tenant and permissions."
//! - **Leakage.** An error must not echo the request body back; a malformed
//!   body is frequently a mis-pasted secret.
//! - **Unbounded work.** Specification 3.2 bounds every input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

mod harness;

use hypellm_test_corpus::fuzz::{self, Rng};
use harness::Harness;
use wire_http1::Method;

const ITERATIONS: u32 = 6_000;

/// The mutating routes, with a body shape each would accept.
const ROUTES: &[(&str, &str)] = &[
    ("/admin/v1/keys", r#"{"tenant":"acme","principal":"svc:a","scopes":["inference"],"description":"d"}"#),
    ("/admin/v1/policies", r#"{"text":"tenant id=acme\n","description":"d"}"#),
    ("/admin/v1/credentials", r#"{"id":"provider-secret","secret":"sk-value","description":"d"}"#),
    ("/admin/v1/policies/p1:publish", r#"{"approver":"user:admin-acme"}"#),
    ("/admin/v1/policies/p1:simulate", r#"{"principal":"svc:a","tenant":"acme","model":"test-alias","operation":"chat","input_tokens":10}"#),
    ("/admin/v1/credentials/provider-secret:rotate", r#"{"secret":"sk-new"}"#),
    ("/admin/v1/targets/local:model", r#"{"state":"draining"}"#),
    ("/admin/v1/auth/break-glass", r#"{"token":"t","reason":"an incident happened"}"#),
];

fn seeds() -> Vec<&'static [u8]> {
    ROUTES.iter().map(|(_, body)| body.as_bytes()).collect()
}

#[test]
fn no_mutated_body_panics_a_handler() {
    let admin = Harness::new();
    let session = admin.break_glass();
    let seeds = seeds();
    let mut rng = Rng::new(0x00ad_0001);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b"{}"), &mut rng);
        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        let method = if path.starts_with("/admin/v1/targets/") {
            Method::Patch
        } else {
            Method::Post
        };
        // Whatever it decides, it must decide, and with a status.
        let response = admin
            .request(method, path)
            .as_session(&session)
            .if_match(&admin.active_config_etag())
            .body(&case)
            .send();
        assert!(
            (200..600).contains(&response.status),
            "{path} answered {} for:\n{}",
            response.status,
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn no_body_makes_an_unauthenticated_caller_succeed() {
    // The gate runs before dispatch, so this is a property of the whole
    // surface. A regression would not open one screen, it would open all of
    // them.
    let admin = Harness::new();
    let seeds = seeds();
    let mut rng = Rng::new(0x00ad_0002);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b"{}"), &mut rng);
        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        // Break-glass is deliberately reachable without a session; it has its
        // own suite and its own token check.
        if path.ends_with("break-glass") {
            continue;
        }
        let response = admin.request(Method::Post, path).body(&case).send();
        assert!(
            response.status == 401 || response.status == 403 || response.status == 404,
            "{path} answered {} to an unauthenticated caller:\n{}",
            response.status,
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn no_body_makes_an_unprivileged_session_succeed() {
    // Authenticated and authorized for nothing. Every mutating route requires a
    // permission; none of them may be reachable by shaping the body.
    let admin = Harness::new();
    let session = admin.unprivileged();
    let seeds = seeds();
    let mut rng = Rng::new(0x00ad_0003);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b"{}"), &mut rng);
        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        if path.ends_with("break-glass") {
            continue;
        }
        let response = admin
            .request(Method::Post, path)
            .as_session(&session)
            .if_match(&admin.active_config_etag())
            .body(&case)
            .send();
        assert!(
            response.status >= 400,
            "{path} answered {} to a session holding no permission:\n{}",
            response.status,
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn a_missing_csrf_header_is_refused_however_the_body_is_shaped() {
    let admin = Harness::new();
    let session = admin.break_glass();
    let seeds = seeds();
    let mut rng = Rng::new(0x00ad_0004);

    for _ in 0..2_000 {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b"{}"), &mut rng);
        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        if path.ends_with("break-glass") {
            continue;
        }
        let response = admin
            .request(Method::Post, path)
            .as_session(&session)
            .without_csrf()
            .body(&case)
            .send();
        assert!(
            response.status >= 400,
            "{path} accepted a cross-site POST: {}",
            response.status
        );
    }
}

#[test]
fn an_error_never_echoes_the_request_body() {
    // A malformed management body is frequently a mis-pasted secret. Nothing
    // the caller sent may come back in the error.
    const PLANTED: &str = "sk-live-planted-secret-value";
    let admin = Harness::new();
    let session = admin.break_glass();
    let seeds = seeds();
    let mut rng = Rng::new(0x00ad_0005);

    for _ in 0..ITERATIONS {
        let mut case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b"{}"), &mut rng);
        let at = rng.below(case.len().max(1)).min(case.len());
        case.splice(at..at, PLANTED.bytes());

        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        let response = admin
            .request(Method::Post, path)
            .as_session(&session)
            .if_match(&admin.active_config_etag())
            .body(&case)
            .send();
        if response.status < 400 {
            continue;
        }
        assert!(
            !response.body_contains(PLANTED),
            "{path} echoed the request body in a {} error:\n{}",
            response.status,
            response.body
        );
    }
}

#[test]
fn a_mutated_query_string_never_widens_a_listing() {
    // Pagination and filters are caller-controlled. Appendix B: management
    // visibility never exceeds the caller's tenant, whatever the query says.
    let admin = Harness::new();
    let auditor = admin.auditor_in("acme");
    let queries: &[&[u8]] = &[
        b"limit=50",
        b"limit=100000",
        b"after=abc",
        b"tenant=globex",
        b"limit=-1&after=",
        b"limit=50&tenant=globex&all=true",
    ];
    let mut rng = Rng::new(0x00ad_0006);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(queries).copied().unwrap_or(b""), &mut rng);
        let Ok(query) = core::str::from_utf8(&case) else {
            continue;
        };
        for path in ["/admin/v1/keys", "/admin/v1/audit", "/admin/v1/usage"] {
            let response = admin
                .request(Method::Get, path)
                .as_session(&auditor)
                .query(query)
                .send();
            if response.status != 200 {
                continue;
            }
            assert!(
                !response.body_contains("globex"),
                "{path} returned another tenant's rows for query {query:?}:\n{}",
                response.body
            );
        }
    }
}

#[test]
fn an_oversize_body_is_refused_rather_than_buffered() {
    let admin = Harness::new();
    let session = admin.break_glass();
    let mut body = String::from(r#"{"description":""#);
    body.push_str(&"a".repeat(8 * 1024 * 1024));
    body.push_str(r#""}"#);

    let response = admin
        .request(Method::Post, "/admin/v1/keys")
        .as_session(&session)
        .if_match(&admin.active_config_etag())
        .json(&body)
        .send();
    assert!(response.status >= 400, "an 8 MiB body was accepted");
}

#[test]
fn deeply_nested_input_is_refused_rather_than_overflowing_the_stack() {
    let admin = Harness::new();
    let session = admin.break_glass();
    let mut body = String::new();
    for _ in 0..10_000 {
        body.push_str(r#"{"a":"#);
    }
    body.push('1');
    for _ in 0..10_000 {
        body.push('}');
    }

    let response = admin
        .request(Method::Post, "/admin/v1/keys")
        .as_session(&session)
        .if_match(&admin.active_config_etag())
        .json(&body)
        .send();
    assert!(response.status >= 400, "10,000 levels of nesting accepted");
}

#[test]
fn random_bytes_on_every_route_are_handled() {
    let admin = Harness::new();
    let session = admin.break_glass();
    let mut rng = Rng::new(0x00ad_beef);

    for _ in 0..ITERATIONS {
        let len = rng.below(256);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let (path, _) = ROUTES[rng.below(ROUTES.len())];
        let response = admin
            .request(Method::Post, path)
            .as_session(&session)
            .if_match(&admin.active_config_etag())
            .body(&case)
            .send();
        assert!((200..600).contains(&response.status));
    }
}
