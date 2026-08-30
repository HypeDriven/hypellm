//! Anonymous inference access: the `anonymous_enabled` deviation.
//!
//! Specification 9.2 requires every inference request to authenticate, and the
//! router's default is exactly that. This suite covers the setting that lets a
//! deployment turn it off, and the properties that keep the setting from being
//! worse than it looks.
//!
//! The interesting one is not "does an open router serve a request" — it is
//! [`a_rejected_key_is_not_downgraded_to_anonymous`]. The obvious way to write
//! the feature is to treat authentication failure as "no principal, fall back
//! to the anonymous one", which silently turns every revoked and expired key
//! into a working credential and would leave revocation reporting success while
//! doing nothing. The fallback is reachable only when *no* credential was
//! presented, and that test is what holds the line.

use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use hypellm_core::time::Clock;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const CHAT_BODY: &str = r#"{"model":"test-alias","messages":[{"role":"user","content":"hi"}]}"#;

/// Configuration text with an `anonymous` clause spliced into `settings`.
///
/// `anonymous` is passed verbatim so a test can write a deliberately broken
/// clause and assert on the error, which a typed builder would refuse to
/// construct.
fn config_text(port: u16, anonymous: &str) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 \\
         max_attempts=3 {anonymous}
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat,embeddings streaming=true tools=true json_mode=true \\
       context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=local:model description=\"the test model\"
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
"
    )
}

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
    _upstream: FakeUpstream,
}

impl Harness {
    /// `anonymous` is spliced into `settings`; `enabled` is the runtime switch.
    ///
    /// They are two arguments because they are two mechanisms. The document
    /// declares the subject and can never switch anonymous access on; the
    /// switch is runtime state the management API owns. A harness that took one
    /// argument would be modelling a design the router does not have.
    fn with(anonymous: &str, enabled: bool) -> Self {
        let upstream = FakeUpstream::start(CannedResponse::json(
            200,
            r#"{"id":"c1","object":"chat.completion","created":1,"model":"test-model",
                "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},
                "finish_reason":"stop"}],
                "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        ));
        let text = config_text(upstream.address.port(), anonymous);
        let router = router_with_config(&upstream, &text);
        router
            .state
            .anonymous_access
            .store(enabled, std::sync::atomic::Ordering::SeqCst);

        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server =
            Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).expect("bind");
        let address = server.local_addr().expect("address");
        let shutdown = server.shutdown_handle();
        let handler = Arc::new(InferenceHandler::new(Arc::clone(&router.state)));
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
            router,
            _upstream: upstream,
        }
    }

    /// `credential` is the exact `Authorization` value, or `None` to send none.
    fn get(&self, path: &str, credential: Option<&str>) -> (u16, String) {
        let mut raw = format!(
            "GET {path} HTTP/1.1\r\nHost: router.test\r\nConnection: close\r\n"
        );
        if let Some(value) = credential {
            raw.push_str(&format!("Authorization: {value}\r\n"));
        }
        raw.push_str("\r\n");
        send(self.address, &raw)
    }

    fn chat(&self, credential: Option<&str>) -> (u16, String) {
        let mut raw = String::from(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: router.test\r\n\
             Content-Type: application/json\r\nConnection: close\r\n",
        );
        if let Some(value) = credential {
            raw.push_str(&format!("Authorization: {value}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{CHAT_BODY}", CHAT_BODY.len()));
        send(self.address, &raw)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn send(address: SocketAddr, raw: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(raw.as_bytes()).expect("write");

    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let done = line == "\r\n";
                head.push_str(&line);
                if done {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let mut body = String::new();
    let _ = reader.read_to_string(&mut body);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, body)
}

/// A declared subject. Inert on its own — it says who, never whether.
const SUBJECT: &str = "anonymous_principal=svc:public anonymous_tenant=acme";

// ---------------------------------------------------------------- behaviour -

#[test]
fn an_uncredentialed_request_is_refused_when_the_switch_is_off() {
    // The default, and the specification 9.2 behaviour. The fixture is
    // adversarial: the subject *is* declared, so this proves the declaration
    // alone opens nothing — which is the property that lets the subject live in
    // a configuration file at all.
    let harness = Harness::with(SUBJECT, false);
    let (status, body) = harness.chat(None);
    assert_eq!(status, 401, "body: {body}");
    let (status, _) = harness.get("/v1/models", None);
    assert_eq!(status, 401);
}

#[test]
fn an_uncredentialed_request_is_served_as_the_configured_anonymous_principal() {
    let harness = Harness::with(SUBJECT, true);
    let (status, body) = harness.chat(None);
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = harness.get("/v1/models", None);
    assert_eq!(status, 200, "body: {body}");
    assert!(
        body.contains("test-alias"),
        "the anonymous principal's tenant grants the alias, so it must be listed: {body}"
    );
}

#[test]
fn a_rejected_key_is_not_downgraded_to_anonymous() {
    // The property the whole feature turns on, and the one an obvious
    // implementation gets wrong.
    //
    // Anonymous access is *enabled* here, which is what makes the fixture
    // adversarial: the router has a perfectly good principal it could fall
    // back to, and must not. If authentication failure fell through to the
    // anonymous path, revocation would report success and change nothing —
    // every revoked key in the store would keep working, and the Keys screen
    // would say "Revoked" beside a credential that still completes requests.
    let harness = Harness::with(SUBJECT, true);

    for presented in [
        "Bearer not-a-real-key",
        "Bearer key_deadbeef.0000000000000000",
        "Bearer ",
        "Basic YWRtaW46YWRtaW4=",
    ] {
        let (status, body) = harness.chat(Some(presented));
        assert_eq!(
            status, 401,
            "presenting `{presented}` must be refused, not served anonymously: {body}"
        );
    }

    // And the valid key still works, so the test above is not passing because
    // everything is refused.
    let key = harness.router.api_key.clone();
    let (status, body) = harness.chat(Some(&format!("Bearer {key}")));
    assert_eq!(status, 200, "the real key must still authenticate: {body}");
}

#[test]
fn an_anonymous_caller_holds_only_the_scopes_it_was_configured_with() {
    // `models` but not `inference`: discovery is open, completion is not. A
    // scope list that was ignored would serve the chat request.
    let harness = Harness::with(
        "anonymous_principal=svc:public anonymous_tenant=acme anonymous_scopes=models",
        true,
    );

    let (status, body) = harness.get("/v1/models", None);
    assert_eq!(status, 200, "models is granted: {body}");

    let (status, body) = harness.chat(None);
    assert_eq!(
        status, 403,
        "inference was not granted, so this must be forbidden rather than routed: {body}"
    );
}

#[test]
fn an_anonymous_request_is_not_recorded_as_having_presented_a_key() {
    // Specification 17 and 22.3: an investigation's first question is how the
    // principal authenticated. `AuthMethod` answers it, and the answer for an
    // open request is "it did not" — not `api_key`, which would name a
    // credential that was never issued.
    use hypellm_auth::{AuthMethod, Principal};
    let principal = Principal::anonymous(
        hypellm_core::ids::PrincipalId::new("svc:public").expect("principal"),
        hypellm_core::ids::TenantId::new("acme").expect("tenant"),
        vec![hypellm_auth::Scope::Inference],
        Vec::new(),
    );
    assert_eq!(principal.method, AuthMethod::Anonymous);
    assert_eq!(principal.method.as_str(), "anonymous");
    assert_ne!(principal.method, AuthMethod::ApiKey);
    assert!(
        principal.key_id.is_none(),
        "no key was presented, so no key id may be attributed"
    );
    assert!(
        principal.roles.is_empty(),
        "an anonymous caller holds no management role"
    );
}

// ------------------------------------------------------------ configuration -

fn errors_for(anonymous: &str) -> Vec<(&'static str, String)> {
    match hypellm_config::load(&config_text(9999, anonymous), 1) {
        Ok(_) => Vec::new(),
        Err(errors) => errors.into_iter().map(|e| (e.code, e.message)).collect(),
    }
}

#[test]
fn a_configuration_file_cannot_switch_anonymous_access_on() {
    // The property the whole design exists for. `anonymous_enabled` is not a
    // settings key, so a document naming it does not build — in either
    // direction, because a key that silently did nothing when set to `false`
    // would read as one that works.
    //
    // Without this, anyone able to write the configuration file could open the
    // router by editing a line and waiting for a restart. The switch is
    // `RecordKind::AnonymousAccess` in the store and reachable only through
    // `POST /admin/v1/settings/anonymous`.
    for clause in [
        "anonymous_enabled=true",
        "anonymous_enabled=false",
        "anonymous_principal=svc:public anonymous_tenant=acme anonymous_enabled=true",
    ] {
        let errors = errors_for(clause);
        assert!(
            errors
                .iter()
                .any(|(code, message)| *code == "unknown_field"
                    && message.contains("anonymous_enabled")),
            "`{clause}` must not build: {errors:?}"
        );
    }
}

#[test]
fn a_half_declared_subject_is_a_configuration_error() {
    // Refused at load, not at the moment somebody presses the toggle. A
    // principal with no tenant would be discovered by an operator switching
    // anonymous access on, weeks after the document that caused it was
    // published, and reported from an endpoint they did not edit.
    for clause in [
        "anonymous_principal=svc:public",
        "anonymous_tenant=acme",
    ] {
        let errors = errors_for(clause);
        assert!(
            errors.iter().any(|(code, _)| *code == "incomplete_record"),
            "`{clause}` must not build: {errors:?}"
        );
    }
}

#[test]
fn declaring_no_subject_at_all_is_the_default_and_valid() {
    assert!(errors_for("").is_empty());
}

#[test]
fn a_declared_subject_is_inert_and_valid() {
    // The state `docker/hypellm.conf` ships in: the subject is named, and
    // naming it switches nothing on. If this ever became an error, the subject
    // could not live in configuration at all.
    assert!(errors_for(SUBJECT).is_empty());
}

#[test]
fn an_anonymous_management_scope_is_a_configuration_error() {
    // An unauthenticated caller holding `management:write` is an
    // unauthenticated administrator. A typo in a scope list must not be able
    // to grant it, and it is refused when the subject is *declared* rather
    // than when it is switched on — so the refusal reaches whoever wrote it.
    for scope in ["management:read", "management:write"] {
        let errors = errors_for(&format!("{SUBJECT} anonymous_scopes=inference,{scope}"));
        assert!(
            errors
                .iter()
                .any(|(code, message)| *code == "invalid_value" && message.contains(scope)),
            "`{scope}` must be refused: {errors:?}"
        );
    }
}

#[test]
fn an_anonymous_tenant_that_does_not_exist_is_a_configuration_error() {
    // Without this the router builds and starts, and the first uncredentialed
    // request after somebody switches anonymous access on is excluded as
    // `not_selected_by_any_binding` — an open router that answers nothing,
    // which reads as a routing bug rather than the configuration error it is.
    let errors = errors_for("anonymous_principal=svc:public anonymous_tenant=nonexistent");
    assert!(
        errors
            .iter()
            .any(|(code, _)| *code == "unresolved_reference"),
        "a tenant that is not declared must be refused: {errors:?}"
    );
}

#[test]
fn an_unknown_anonymous_scope_is_a_configuration_error() {
    let errors = errors_for(&format!("{SUBJECT} anonymous_scopes=inference,infrence"));
    assert!(
        errors
            .iter()
            .any(|(code, message)| *code == "invalid_value" && message.contains("infrence")),
        "a misspelled scope must be named rather than silently dropped: {errors:?}"
    );
}

#[test]
fn the_configuration_scope_list_matches_the_authentication_crate() {
    // `hypellm-config` cannot see `hypellm_auth::Scope` — they are siblings —
    // so `ANONYMOUS_SCOPE_NAMES` duplicates the four inference scope names.
    // This crate depends on both and is where the drift is caught: a scope
    // added to the enum and not to that list would become an
    // "is not a scope" configuration error for a name that is one.
    use hypellm_auth::Scope;
    for scope in [
        Scope::Inference,
        Scope::Embeddings,
        Scope::Models,
        Scope::Tokenize,
    ] {
        let errors = errors_for(&format!("{SUBJECT} anonymous_scopes={}", scope.as_str()));
        assert!(
            errors.is_empty(),
            "`{}` is a real scope and must be accepted: {errors:?}",
            scope.as_str()
        );
    }
    // The two management scopes are rejected by a *different* rule, and the
    // message has to say which — "is not a scope" would be a wrong answer to
    // someone who wrote a real scope name.
    for scope in [Scope::ManagementRead, Scope::ManagementWrite] {
        let errors = errors_for(&format!("{SUBJECT} anonymous_scopes={}", scope.as_str()));
        assert!(
            errors
                .iter()
                .any(|(_, message)| message.contains("may not hold a management scope")),
            "`{}` must be refused as a management scope, not as an unknown one: {errors:?}",
            scope.as_str()
        );
    }
}
