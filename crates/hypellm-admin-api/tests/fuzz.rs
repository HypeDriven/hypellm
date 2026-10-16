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
    ("/admin/v1/keys/0123456789abcdef/budget:credit", r#"{"tokens":500,"reason":"invoice 7"}"#),
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

// -- Key budgets -------------------------------------------------------------

/// A durable budget record: a finite limit, a mark, payment instructions and
/// a credit receipt.
const BUDGET_RECORD: &[u8] = br#"{"key":"0123456789abcdef","tenant":"acme","limit":1500000,"drawn":1000000,"revision":3,"payment_message":"Top up.","payment_url":"https://billing.example/tokens","receipt":{"idempotency_key":"pay-7","request_digest":"abc","tokens":500000,"limit_after":1500000,"revision_after":3,"at_millis":42,"actor":"svc:pay","reason":"invoice 7"}}"#;

#[test]
fn no_damaged_budget_record_is_restored_as_a_more_generous_one() {
    // The record is what a restart believes about a purchased allowance. The
    // failure that matters is not a crash but a quiet widening: a limit that
    // cannot be read being taken as "no limit", or a mark as "nothing spent".
    use hypellm_admin_api::budget::{decode_record, encode_record};
    use hypellm_core::budget::MAX_TOKENS;

    let (accepted, rejected) = fuzz::sweep(&[BUDGET_RECORD], 20_000, 0x00ad_b001, |case| {
        let Some(record) = decode_record(case) else {
            return false;
        };
        let json = wire_json::parse(case, &wire_json::Limits::SMALL).expect("decoded, so it parsed");
        if record.limit.is_none() {
            assert!(
                json.get("limit").is_none_or(wire_json::Value::is_null),
                "an unreadable limit was restored as unlimited: {}",
                String::from_utf8_lossy(case)
            );
        }
        assert_eq!(json.get("drawn").and_then(wire_json::Value::as_u64), Some(record.drawn));
        assert!(record.drawn <= MAX_TOKENS && record.limit.is_none_or(|limit| limit <= MAX_TOKENS));
        // What was decoded is exactly what would be written back.
        assert_eq!(decode_record(&encode_record(&record)), Some(record));
        true
    });
    assert!(accepted > 0, "no mutated record ever decoded; the seed is wrong");
    assert_eq!(accepted + rejected, 20_000);
}

#[test]
fn a_credit_moves_the_limit_by_the_amount_it_named_or_not_at_all() {
    // Every mutated body is a credit request from an authorized caller, each
    // under its own operation identifier. Whatever the body says, the limit
    // afterwards is the limit before plus exactly the positive integer the
    // body's `tokens` field holds — or unchanged.
    let admin = Harness::new();
    let session = admin.session(
        "user:finance",
        harness::TENANT_A,
        &[hypellm_core::rbac::Role::KeyBudgetManager],
    );
    let (key, _) = admin.issue_api_key(harness::TENANT_A, "svc:build");
    let tenant = hypellm_core::ids::TenantId::new(harness::TENANT_A).unwrap();
    admin.state.budgets.set(&key, &tenant, None, Some(0), None).unwrap();
    let path = format!("/admin/v1/keys/{}/budget:credit", key.as_str());

    let seeds: &[&[u8]] = &[
        br#"{"tokens":500,"reason":"invoice 7"}"#,
        br#"{"tokens":9223372036854775000}"#,
        br#"{"tokens":1}"#,
    ];
    // Fewer cases than the other targets: every applied credit is two
    // `fsync`s, an audit record and a ledger frame.
    let mut applied = 0_u32;
    for n in 0..1_500 {
        let body = fuzz::case_at(seeds, 0x00ad_b002, n);
        let before = admin.state.budgets.view(&key).limit.expect("still finite");
        let response = admin
            .request(Method::Post, &path)
            .as_session(&session)
            .if_match(harness::ANY_ETAG)
            .header("idempotency-key", &format!("operation-{n}"))
            .body(&body)
            .send();
        let after = admin.state.budgets.view(&key).limit.expect("a credit removed the limit");
        if response.status == 200 {
            let named = wire_json::parse(&body, &wire_json::Limits::SMALL)
                .ok()
                .and_then(|json| json.get("tokens").and_then(wire_json::Value::as_u64))
                .filter(|tokens| *tokens > 0);
            assert_eq!(
                named.and_then(|tokens| before.checked_add(tokens)),
                Some(after),
                "case {n}: {} moved the limit from {before} to {after}",
                String::from_utf8_lossy(&body)
            );
            applied += 1;
        } else {
            assert_eq!(after, before, "case {n}: a refused credit changed the limit");
        }
        assert!(after <= hypellm_core::budget::MAX_TOKENS, "case {n}: the limit overflowed");
    }
    assert!(applied > 0, "no mutated credit was ever applied; the seeds are wrong");
}

#[test]
fn no_enrollment_body_registers_a_machine_without_the_token() {
    // The registration endpoint takes no session and no key — the token is
    // the only credential. Mutating a well-formed report, including its token
    // field, must never produce a registration, and must never answer anything
    // that tells the caller more than "no".
    let config = harness::default_config().replacen(
        "settings ",
        "settings fleet_enroll_url=https://router.test ",
        1,
    ) + "fleet_agent id=local socket=/run/hypellm/fleet.sock \
         ssh_public_key=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M\"\n";
    let admin = Harness::with_config(&config);
    let operator = admin.operator();
    let minted = admin.post(
        &operator,
        "/admin/v1/fleet/enrollments",
        r#"{"host":"rig","agent":"local"}"#,
    );
    let token = minted.str_field("token");
    // A different, wrong token of the right shape, so the seed is one byte
    // flip away from a real one rather than nowhere near it.
    let mut wrong = token.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    let seed = format!(
        r#"{{"token":"{wrong}","address":"192.168.1.20","arch":"x86_64","hostname":"rig","ssh_user":"albert","data_dir":"/home/albert/.hypellm","memory_bytes":68719476736,"gpus":[],"ssh_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M","device_key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX5iBIxDSO2VYlfFZRE/T1VJfwE4OL9kokNcCposqRRI=\n-----END PUBLIC KEY-----\n","kit_version":"1.0.0"}}"#
    );
    let mut rng = Rng::new(0x00ad_0e01);
    let mut headers = wire_http1::Headers::default();
    headers.append("content-type", "application/json").unwrap();
    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(seed.as_bytes(), &mut rng);
        let request = hypellm_admin_api::AdminRequest {
            method: &Method::Post,
            path: "/fleet/v1/enroll:complete",
            query: None,
            headers: &headers,
            body: &case,
            peer: None,
            request_id: "fuzz".to_owned(),
        };
        if let Ok(response) = admin.api.handle_enrollment(&request) {
            // Only possible if the mutation produced the real token, which a
            // one-byte flip away from it can: the property is then that the
            // registration really is the one the token was minted for.
            assert!(
                String::from_utf8_lossy(&case).contains(&token),
                "registered without the token: {}",
                response.body
            );
        }
    }
    assert!(
        admin
            .state
            .enrollments
            .list()
            .iter()
            .all(|e| e.host.as_str() == "rig"),
        "only the minted enrollment exists"
    );
}
