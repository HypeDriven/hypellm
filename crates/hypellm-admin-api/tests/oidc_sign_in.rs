//! End-to-end Google sign-in.
//!
//! Specification 9.1 defines the flow: a fixed authorization endpoint, PKCE, a
//! server-side transaction carrying `state` and `nonce`, an authorization-code
//! exchange at the platform boundary, and a local principal resolved from
//! `(iss, sub)` — "never by email domain".
//!
//! # What was wrong before these tests
//!
//! Sign-in could not succeed at all, for three separate reasons, each of which
//! looked plausible in isolation:
//!
//! 1. The callback passed the raw authorization `code` to `TokenVerifier::verify`
//!    as though it were an identity token. No exchange happened.
//! 2. The PKCE `code_verifier` was generated, stored, and never transmitted, so
//!    the challenge in the authorization request proved nothing.
//! 3. The local principal was `PrincipalId::new("{iss}|{sub}")`, and `|` and `/`
//!    are not legal in an identifier — so every sign-in was refused with "this
//!    identity is not bound to a principal", and the tenant, had it got that
//!    far, was whichever one sorted first in map order.
//!
//! The fake verifier below asserts the exchange arrives with the right
//! verifier, because a test that only checks the sign-in succeeds would pass
//! just as well with PKCE removed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod harness;

use hypellm_auth::oidc::{CodeExchange, IdTokenClaims, OidcConfig, OidcError, TokenVerifier};
use hypellm_core::time::Clock;
use harness::Harness;
use std::sync::{Arc, Mutex};
use wire_http1::Method;

const ISSUER: &str = "https://accounts.google.com";
const SUBJECT: &str = "108143901234567890123";
const CLIENT_ID: &str = "hypellm-test.apps.googleusercontent.com";
const REDIRECT: &str = "https://admin.test/admin/v1/auth/google/callback";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// What the fake boundary was asked to do.
#[derive(Debug, Clone, Default)]
struct Exchanged {
    code: String,
    code_verifier: String,
    redirect_uri: String,
    client_id: String,
    token_endpoint: String,
}

/// A verifier that records the exchange and answers with fixed claims.
#[derive(Debug)]
struct FakeVerifier {
    /// Filled in by `exchange_code`, so a test can assert what crossed the
    /// boundary rather than only what came back.
    seen: Mutex<Vec<Exchanged>>,
    /// The nonce to echo. A test sets this to the transaction's real nonce by
    /// reading it back from the store.
    nonce: Mutex<Option<String>>,
    /// When set, every exchange fails, standing in for a provider refusal.
    refuse: Mutex<bool>,
}

impl FakeVerifier {
    fn new() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            nonce: Mutex::new(None),
            refuse: Mutex::new(false),
        }
    }

    fn exchanges(&self) -> Vec<Exchanged> {
        self.seen.lock().unwrap().clone()
    }

    fn echo_nonce(&self, nonce: &str) {
        *self.nonce.lock().unwrap() = Some(nonce.to_owned());
    }

    fn refuse_everything(&self) {
        *self.refuse.lock().unwrap() = true;
    }

    fn claims(&self, now_secs: u64) -> IdTokenClaims {
        IdTokenClaims {
            iss: ISSUER.to_owned(),
            sub: SUBJECT.to_owned(),
            aud: vec![CLIENT_ID.to_owned()],
            azp: Some(CLIENT_ID.to_owned()),
            exp: now_secs + 3600,
            iat: now_secs,
            nonce: self.nonce.lock().unwrap().clone(),
            email: Some("operator@example.com".to_owned()),
            email_verified: true,
            hd: Some("example.com".to_owned()),
            name: Some("Albert".to_owned()),
        }
    }
}

impl TokenVerifier for FakeVerifier {
    fn verify(&self, _id_token: &str) -> Result<IdTokenClaims, OidcError> {
        // Not the path a callback takes. Failing loudly here is what stops a
        // regression quietly reverting to passing the code to `verify`.
        panic!("the callback must exchange the authorization code, not verify it");
    }

    fn exchange_code(&self, request: &CodeExchange<'_>) -> Result<IdTokenClaims, OidcError> {
        self.seen.lock().unwrap().push(Exchanged {
            code: request.code.to_owned(),
            code_verifier: request.code_verifier.to_owned(),
            redirect_uri: request.redirect_uri.to_owned(),
            client_id: request.client_id.to_owned(),
            token_endpoint: request.token_endpoint.to_owned(),
        });

        if *self.refuse.lock().unwrap() {
            return Err(OidcError::SignatureInvalid);
        }
        // 2026-01-01, matching the harness clock's wall time.
        Ok(self.claims(1_767_225_600))
    }
}

fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        token_endpoint: TOKEN_ENDPOINT.to_owned(),
        redirect_uri: REDIRECT.to_owned(),
        hosted_domains: Vec::new(),
        clock_skew_millis: 60_000,
    }
}

/// A configuration binding the fake identity to a principal with a real role.
fn config_with_identity() -> String {
    format!(
        "\
tenant id=acme
tenant id=globex
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:model provider=local model=m local=true operations=chat \\
       streaming=true context=1000 max_output=100
alias id=test-alias targets=local:model
grant scope=tenant:globex model=* allow=true
identity issuer={ISSUER} subject={SUBJECT} principal=user:operator tenant=globex
role_binding subject=principal:user:operator role=operator
"
    )
}

fn harness_with_verifier() -> (Harness, Arc<FakeVerifier>) {
    let verifier = Arc::new(FakeVerifier::new());
    let admin = Harness::builder()
        .config(&config_with_identity())
        .oidc(oidc_config(), Arc::clone(&verifier) as Arc<dyn TokenVerifier>)
        .build();
    (admin, verifier)
}

/// Begin a sign-in and return `(handle, state, nonce, code_verifier)`.
fn begin(admin: &Harness) -> (String, String, String, String) {
    let request = admin
        .state
        .oidc
        .begin(
            admin.state.oidc_config.as_ref().expect("oidc configured"),
            "/targets",
            admin.clock.now_millis(),
        )
        .expect("the transaction opens");

    // Read the transaction back so the test can echo the real nonce and assert
    // against the real verifier, rather than against values it invented.
    // `peek` rather than `take`, because the callback still needs it.
    let handle = request.transaction_handle.clone();
    let transaction = admin
        .state
        .oidc
        .peek(&handle)
        .expect("the transaction is readable");

    (
        handle,
        transaction.state.clone(),
        transaction.nonce.clone(),
        transaction.code_verifier.clone(),
    )
}

#[test]
fn a_complete_sign_in_establishes_a_session_in_the_bound_tenant() {
    let (admin, verifier) = harness_with_verifier();
    let (handle, state, nonce, _code_verifier) = begin(&admin);
    verifier.echo_nonce(&nonce);

    let response = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    assert!(
        response.status == 200 || response.status == 204 || response.status == 302,
        "sign-in did not complete: {} {}",
        response.status,
        response.body
    );

    // The tenant is the one the identity record names. `acme` sorts first and
    // would have won a map-order lookup, so this is the assertion that pins
    // the fix rather than merely observing a success.
    let cookie = response
        .headers_named("Set-Cookie")
        .into_iter()
        .find(|value| value.contains("__Host-hypellm_session="))
        .expect("a session cookie was issued");
    let token = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, v)| v.to_owned())
        .expect("a session token");

    let session = admin
        .state
        .sessions
        .validate(&token, admin.clock.now_millis())
        .expect("the issued session validates");

    assert_eq!(session.tenant.as_str(), "globex");
    assert_eq!(session.principal.as_str(), "user:operator");
    assert_eq!(session.method, hypellm_auth::AuthMethod::Oidc);
}

#[test]
fn the_pkce_verifier_reaches_the_token_exchange() {
    // PKCE only protects anything if the verifier is transmitted. Without this
    // assertion the flow would pass every other test in this file with the
    // verifier removed entirely.
    let (admin, verifier) = harness_with_verifier();
    let (handle, state, nonce, code_verifier) = begin(&admin);
    verifier.echo_nonce(&nonce);

    admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    let exchanges = verifier.exchanges();
    assert_eq!(exchanges.len(), 1, "the code was not exchanged exactly once");

    let exchange = &exchanges[0];
    assert_eq!(exchange.code, "auth-code-xyz");
    assert_eq!(
        exchange.code_verifier, code_verifier,
        "the exchange did not carry the transaction's PKCE verifier"
    );
    assert!(!exchange.code_verifier.is_empty());

    // The destination and identity come from configuration, never from the
    // callback's query string — otherwise a replayed callback could redirect
    // the exchange.
    assert_eq!(exchange.redirect_uri, REDIRECT);
    assert_eq!(exchange.client_id, CLIENT_ID);
    assert_eq!(exchange.token_endpoint, TOKEN_ENDPOINT);
}

#[test]
fn an_identity_the_configuration_does_not_bind_is_refused() {
    // Specification 9.1: authorization is by local binding. A valid Google
    // account that nobody granted access to must not get a session.
    let verifier = Arc::new(FakeVerifier::new());
    let admin = Harness::builder()
        // Same tenants, no `identity` record.
        .config(
            "\
tenant id=acme
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:model provider=local model=m local=true operations=chat \
       streaming=true context=1000 max_output=100
alias id=test-alias targets=local:model
grant scope=tenant:acme model=* allow=true
",
        )
        .oidc(oidc_config(), Arc::clone(&verifier) as Arc<dyn TokenVerifier>)
        .build();

    let (handle, state, nonce, _) = begin(&admin);
    verifier.echo_nonce(&nonce);

    let response = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    assert!(
        response.status >= 400,
        "an unbound identity was signed in: {} {}",
        response.status,
        response.body
    );
    assert!(
        response.headers_named("Set-Cookie")
            .iter()
            .all(|c| !c.contains("__Host-hypellm_session=")),
        "a session cookie was issued to an unbound identity"
    );
}

#[test]
fn a_callback_whose_state_does_not_match_is_refused() {
    // The `state` parameter binds the callback to the browser that started it.
    let (admin, verifier) = harness_with_verifier();
    let (handle, _state, nonce, _) = begin(&admin);
    verifier.echo_nonce(&nonce);

    let response = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query("code=auth-code-xyz&state=not-the-state-we-issued")
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    assert!(response.status >= 400, "{} {}", response.status, response.body);
    assert!(
        verifier.exchanges().is_empty(),
        "a code was exchanged before the state was checked"
    );
}

#[test]
fn a_provider_refusal_does_not_establish_a_session() {
    let (admin, verifier) = harness_with_verifier();
    let (handle, state, nonce, _) = begin(&admin);
    verifier.echo_nonce(&nonce);
    verifier.refuse_everything();

    let response = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    assert!(response.status >= 400, "{} {}", response.status, response.body);
    assert!(
        response.headers_named("Set-Cookie")
            .iter()
            .all(|c| !c.contains("__Host-hypellm_session=")),
    );
}

#[test]
fn a_transaction_cannot_be_replayed() {
    // Single use: an attacker who captures a callback URL must not be able to
    // replay it into a second session.
    let (admin, verifier) = harness_with_verifier();
    let (handle, state, nonce, _) = begin(&admin);
    verifier.echo_nonce(&nonce);

    let first = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();
    assert!(first.status < 400, "{} {}", first.status, first.body);

    let replay = admin
        .request(Method::Get, "/admin/v1/auth/google/callback")
        .query(&format!("code=auth-code-xyz&state={state}"))
        .cookie(&format!("__Host-hypellm_oidc={handle}"))
        .send();

    assert!(
        replay.status >= 400,
        "a captured callback was replayed into a second session: {} {}",
        replay.status,
        replay.body
    );
}

#[test]
fn repeated_anonymous_sign_in_failures_do_not_grow_the_durable_log_without_bound() {
    // Specification 3.2: "No request may create an unbounded thread, task,
    // buffer, channel, retry loop, **or log entry**."
    //
    // `/admin/v1/auth/google/callback` runs before any session by definition,
    // so an unauthenticated caller who can reach the management listener
    // decides how often this path runs. Each failure used to append a durable
    // `LoginFailed` audit record — an fsync under the global store log mutex,
    // and a frame that never goes away.
    //
    // The consequence is worse than the write cost. `Log::replay` refuses a log
    // larger than `MAX_LOG_BYTES` (256 MiB), so a caller who fills it makes the
    // router **unbootable**, and the operator's remedy — compaction — discards
    // API keys, the audit chain, and configuration activations (`DI-044`). An
    // unauthenticated flood would become a denial of service that survives
    // restart.
    //
    // The signal itself is not the problem and must not be lost: the metric
    // still counts every failure. What is bounded is how many of them become
    // durable frames.
    let (admin, _verifier) = harness_with_verifier();
    let path = admin.state.store.dir().join("log.bin");
    let size = || std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    let before = size();
    for _ in 0..400 {
        let response = admin
            .request(Method::Get, "/admin/v1/auth/google/callback")
            .query("code=&state=nonexistent")
            .send();
        assert!(
            response.status >= 400,
            "an anonymous callback must fail: {}",
            response.body
        );
    }
    let after = size();

    // A bound, not a prohibition: the first failures in a window are recorded,
    // and a suppression record says how many followed. 400 failures must not
    // produce 400 frames.
    let grown = after.saturating_sub(before);
    assert!(
        grown < 4_096,
        "400 anonymous sign-in failures grew the durable log by {grown} bytes; \
         an unauthenticated caller controls how many times this runs"
    );

    // And the signal survives: every failure is still counted. Summed across
    // reasons rather than asserted on one, because which refusal a malformed
    // callback lands on is an implementation detail — that *all* of them are
    // counted is the property.
    let exposition = admin.state.telemetry.exposition();
    let counted: u64 = exposition
        .lines()
        .filter(|line| line.starts_with("hypellm_auth_failures_total{"))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum();
    assert!(
        counted >= 400,
        "suppressing the audit record must not suppress the metric: counted {counted} in:\n{exposition}"
    );
}

/// Audit payloads currently in the durable log.
///
/// Read from the log file rather than from any handler, because the property
/// under test is that a specific record reached disk — an in-memory index would
/// be satisfied by a handler that merely said so.
fn audit_payloads(admin: &Harness) -> Vec<String> {
    let path = admin.state.store.dir().join("log.bin");
    let mut log = hypellm_store::Log::open(&path, false).expect("open the durable log");
    let replay = log
        .replay(b"harness-store-mac-key")
        .expect("replay the durable log");
    replay
        .of_kind(hypellm_store::RecordKind::AuditEvent)
        .map(|frame| String::from_utf8_lossy(&frame.payload).into_owned())
        .collect()
}

#[test]
fn a_flood_of_sign_in_failures_cannot_hide_a_break_glass_attack() {
    // The reason the two audit budgets are separate rather than one. If they
    // shared a budget, an attacker could exhaust it with noise on the ordinary
    // sign-in path and have their attempts against the *emergency* path
    // suppressed along with it — hiding an attack on the more sensitive
    // endpoint behind traffic on the less sensitive one.
    //
    // Asserted on the record reaching disk, not on the log file growing: a
    // shared budget still writes a suppression summary when its window rolls,
    // so the file grows either way and a size check would pass without the
    // break-glass attempt ever being recorded.
    //
    // This needs a harness with *both* configured. The break-glass suite's own
    // harness has no OIDC at all — deliberately, since that path must work
    // without one — so the sign-in flood there never reaches the budget, and
    // the same test written against it passes whatever the budgets do.
    const TOKEN: &str = "a-preprovisioned-break-glass-token-value";
    const PRINCIPAL: &str = "user:oncall";
    let verifier = Arc::new(FakeVerifier::new());
    let config = format!(
        "{}role_binding subject=principal:{PRINCIPAL} role=break_glass_admin\n",
        config_with_identity()
    );
    let admin = Harness::builder()
        .config(&config)
        .oidc(oidc_config(), Arc::clone(&verifier) as Arc<dyn TokenVerifier>)
        .with_break_glass(TOKEN, PRINCIPAL, "acme")
        .build();

    // Exhaust the sign-in path's budget.
    let quiet = audit_payloads(&admin).len();
    for _ in 0..400 {
        let response = admin
            .request(Method::Get, "/admin/v1/auth/google/callback")
            .query("code=&state=nonexistent")
            .send();
        assert!(response.status >= 400, "{}", response.body);
    }
    let before = audit_payloads(&admin);
    let written = before.len().saturating_sub(quiet);

    // The premise, checked rather than assumed. If the flood never reached the
    // audit path at all — a harness without OIDC configured refuses earlier —
    // nothing below would prove anything, and the test would pass regardless of
    // how the budgets are arranged.
    assert!(
        written > 0,
        "the sign-in flood never reached the audit path, so this proves nothing"
    );
    assert!(
        written <= 16,
        "the sign-in budget did not engage: 400 failures wrote {written} records"
    );
    assert!(
        !before.iter().any(|p| p.contains("break_glass_token_invalid")),
        "the fixture already contains a break-glass failure"
    );

    let response = admin
        .request(Method::Post, "/admin/v1/auth/break-glass")
        .json(&format!(
            "{{\"token\":\"wrong\",\"reason\":\"incident 4711\"}}"
        ))
        .send();
    assert!(response.status >= 400, "{}", response.body);

    assert!(
        audit_payloads(&admin)
            .iter()
            .any(|p| p.contains("break_glass_token_invalid")),
        "a break-glass failure was suppressed by unrelated sign-in traffic"
    );
}
