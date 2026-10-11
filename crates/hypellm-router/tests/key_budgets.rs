//! Per-key token budgets on the inference path (specification 12.1, 12.2).
//!
//! Each test drives the real listener or the real pipeline against a fake
//! provider on a real socket, and asserts what the ledger holds afterwards —
//! not only the status the caller saw. The properties are the specification's:
//! a key that cannot fund a request gets HTTP 402 and the provider is never
//! called; a request is charged what the provider reported and nothing when
//! the provider refused it; a reservation whose usage is unknown is kept;
//! every attempt is funded; and what was spent stays spent across a restart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hypellm_admin_api::budget::decode_record;
use hypellm_core::budget::testing::MemoryJournal;
use hypellm_core::budget::{BudgetLedger, BudgetView, PaymentInstructions};
use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::{AliasId, KeyId, TenantId};
use hypellm_core::rbac::PermissionSet;
use hypellm_core::time::Clock;
use hypellm_router::dispatch::{EventSink, SinkClosed};
use hypellm_router::pipeline;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{
    CannedResponse, FakeUpstream, TestRouter, default_config_text, router_with_config,
};
use hypellm_store::RecordKind;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use wire_json::{Limits, Value, parse_str};

const CHAT: &str =
    r#"{"model":"test-alias","messages":[{"role":"user","content":"Explain backpressure."}]}"#;
const CHAT_STREAM: &str = r#"{"model":"test-alias","stream":true,"messages":[{"role":"user","content":"Explain backpressure."}]}"#;
const MESSAGES: &str = r#"{"model":"test-alias","max_tokens":64,"messages":[{"role":"user","content":"Explain backpressure."}]}"#;
const RESPONSES: &str = r#"{"model":"test-alias","input":"Explain backpressure."}"#;

/// 12 prompt tokens and 5 completion tokens: 17 in all.
const COMPLETION: &str = r#"{"id":"chatcmpl-up1","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"Flow control."},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#;

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
    upstream: FakeUpstream,
}

struct Response {
    status: u16,
    head: String,
    body: String,
}

impl Response {
    fn json(&self) -> Value {
        parse_str(&self.body, &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn error_field(&self, name: &str) -> Option<String> {
        self.json()
            .get("error")
            .and_then(|error| error.get(name))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

impl Harness {
    fn new(upstream: FakeUpstream) -> Self {
        let config = default_config_text(upstream.address.port());
        Self::with_config(upstream, &config)
    }

    fn with_config(upstream: FakeUpstream, config: &str) -> Self {
        let router = router_with_config(&upstream, config);
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).expect("bind");
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
            upstream,
        }
    }

    fn key(&self) -> KeyId {
        key_of(&self.router)
    }

    fn set_limit(&self, limit: Option<u64>) {
        self.set_budget(limit, None);
    }

    fn set_budget(&self, limit: Option<u64>, payment: Option<PaymentInstructions>) {
        self.router
            .state
            .budgets
            .set(&self.key(), &tenant(), None, limit, payment)
            .expect("set the budget");
    }

    fn budget(&self) -> BudgetView {
        self.router.state.budgets.view(&self.key())
    }

    fn post(&self, path: &str, body: &str) -> Response {
        let raw = format!(
            "POST {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
             Connection: close\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{body}",
            self.router.api_key,
            body.len()
        );
        let mut stream = TcpStream::connect(self.address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let done = line == "\r\n";
                    head.push_str(&line);
                    if done {
                        break;
                    }
                }
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
        Response { status, head, body }
    }

    /// Nothing is left holding capacity: the admission reservation a refused
    /// or finished request took has been returned.
    fn assert_nothing_in_flight(&self) {
        assert_eq!(self.router.state.admission.global().in_flight(), 0);
        assert_eq!(self.budget().reserved, 0);
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

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

/// The identifier inside `hypellmk_<id>_<secret>`.
fn key_of(router: &TestRouter) -> KeyId {
    KeyId::new(router.api_key.split('_').nth(1).expect("key id")).expect("key id")
}

fn ok_upstream() -> FakeUpstream {
    FakeUpstream::start(CannedResponse::json(200, COMPLETION))
}

fn assert_budget_refusal(response: &Response) {
    assert_eq!(response.status, 402, "{}{}", response.head, response.body);
    assert_eq!(
        response.error_field("code").as_deref(),
        Some("token_budget_exhausted")
    );
    assert_eq!(response.error_field("type").as_deref(), Some("payment_required"));
    assert_eq!(response.header("Cache-Control"), Some("no-store"));
    // Not a rate limit: nothing tells the client to come back later.
    assert_eq!(response.header("Retry-After"), None);
}

// -- Refusal ----------------------------------------------------------------

#[test]
fn an_exhausted_key_gets_402_and_the_provider_is_never_called() {
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(0));

    let response = harness.post("/v1/chat/completions", CHAT);

    assert_budget_refusal(&response);
    assert_eq!(harness.upstream.served(), 0, "the provider was invoked");
    // No instructions were configured, so none are invented.
    assert!(response.json().get("error").unwrap().get("payment_required").is_none());
    assert_eq!(harness.budget().consumed, 0);
    harness.assert_nothing_in_flight();
}

#[test]
fn a_request_that_does_not_fit_is_refused_although_credit_remains() {
    // The target enforces 8192 output tokens for a client that named no limit,
    // so the reservation is above 8192. 8000 tokens of credit is not nothing —
    // and specification 12.1 refuses it anyway, rather than admitting the
    // request against credit the key does not have.
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(8000));

    assert_budget_refusal(&harness.post("/v1/chat/completions", CHAT));
    assert_eq!(harness.upstream.served(), 0);
    assert_eq!(harness.budget().remaining(), Some(8000), "the refusal cost credit");
}

#[test]
fn an_unlimited_key_is_served_and_its_consumption_is_still_counted() {
    let harness = Harness::new(ok_upstream());

    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);

    let budget = harness.budget();
    assert_eq!((budget.limit, budget.consumed), (None, 17));
}

#[test]
fn every_protocol_keeps_the_402_and_the_code() {
    let upstream = ok_upstream();
    let config = default_config_text(upstream.address.port())
        .replace("operations=chat,embeddings", "operations=chat,embeddings,responses");
    let harness = Harness::with_config(upstream, &config);
    harness.set_budget(
        Some(0),
        PaymentInstructions::new(Some("Top up."), Some("https://billing.example/tokens")).unwrap(),
    );

    for (path, body) in [
        ("/v1/chat/completions", CHAT),
        ("/v1/messages", MESSAGES),
        ("/v1/responses", RESPONSES),
    ] {
        let response = harness.post(path, body);
        assert_budget_refusal(&response);
        let json = response.json();
        let payment = json
            .get("error")
            .and_then(|error| error.get("payment_required"))
            .unwrap_or_else(|| panic!("{path} dropped the payment details: {}", response.body));
        assert_eq!(payment.get("message").and_then(Value::as_str), Some("Top up."));
        assert_eq!(
            payment.get("payment_url").and_then(Value::as_str),
            Some("https://billing.example/tokens")
        );
    }
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn a_key_override_replaces_the_tenant_default_and_removing_it_restores_it() {
    let upstream = ok_upstream();
    let config = default_config_text(upstream.address.port()).replace(
        "tenant id=acme\n",
        "tenant id=acme payment_message=\"Ask your administrator.\" \
         payment_url=\"https://tenant.example/pay\"\n",
    );
    let harness = Harness::with_config(upstream, &config);
    let url = |response: &Response| {
        response
            .json()
            .get("error")
            .and_then(|e| e.get("payment_required"))
            .and_then(|p| p.get("payment_url"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    harness.set_limit(Some(0));
    let inherited = harness.post("/v1/chat/completions", CHAT);
    assert_eq!(url(&inherited).as_deref(), Some("https://tenant.example/pay"));

    harness.set_budget(
        Some(0),
        PaymentInstructions::new(None, Some("https://key.example/pay")).unwrap(),
    );
    let overridden = harness.post("/v1/chat/completions", CHAT);
    assert_eq!(url(&overridden).as_deref(), Some("https://key.example/pay"));
    // The override is the whole object, not a merge with the tenant's message.
    assert!(!overridden.body.contains("Ask your administrator."));

    harness.set_limit(Some(0));
    let restored = harness.post("/v1/chat/completions", CHAT);
    assert_eq!(url(&restored).as_deref(), Some("https://tenant.example/pay"));
}

// -- Streaming --------------------------------------------------------------

#[test]
fn a_streamed_request_that_cannot_be_funded_gets_a_real_402() {
    // Specification 12.1: "Streaming MUST reserve before HTTP headers are
    // sent." A 200 followed by an error frame would be the one answer the
    // specification rules out by name.
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(0));

    let response = harness.post("/v1/chat/completions", CHAT_STREAM);

    assert_budget_refusal(&response);
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    assert!(!response.body.contains("data:"), "an SSE frame was sent: {}", response.body);
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn a_funded_stream_opens_as_before_and_is_charged_what_the_provider_reported() {
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"id":"c1","model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":"Flow"},"finish_reason":null}]}"#,
        r#"{"id":"c1","model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"{"id":"c1","model":"test-model","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#,
    ]));
    let harness = Harness::new(upstream);
    harness.set_limit(Some(1_000_000));

    let response = harness.post("/v1/chat/completions", CHAT_STREAM);

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("Content-Type"), Some("text/event-stream"));
    assert!(response.body.contains("Flow"));
    assert!(response.body.contains("[DONE]"));
    // The client did not ask for usage. The router did, on the key's behalf,
    // or there would be nothing to settle against.
    let sent = harness.upstream.last_body().unwrap_or_default();
    assert!(sent.contains("include_usage"), "usage was not requested upstream: {sent}");
    assert_eq!(harness.budget().consumed, 17);
    harness.assert_nothing_in_flight();
}

// -- Settlement -------------------------------------------------------------

#[test]
fn a_served_request_is_charged_input_plus_output_as_reported() {
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(1_000_000));

    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);

    let budget = harness.budget();
    assert_eq!(budget.consumed, 12 + 5);
    assert_eq!(budget.remaining(), Some(1_000_000 - 17));
    harness.assert_nothing_in_flight();
}

#[test]
fn an_attempt_the_provider_refused_costs_nothing() {
    // "Requests rejected before upstream acceptance incur no token charge."
    let harness = Harness::new(FakeUpstream::start(CannedResponse::json(
        400,
        r#"{"error":{"type":"invalid_request_error","message":"no"}}"#,
    )));
    harness.set_limit(Some(1_000_000));

    let response = harness.post("/v1/chat/completions", CHAT);

    assert_ne!(response.status, 200);
    assert_eq!(harness.upstream.served(), 1);
    assert_eq!(harness.budget().consumed, 0);
    harness.assert_nothing_in_flight();
}

#[test]
fn an_accepted_reply_with_no_usage_keeps_its_reservation_as_the_charge() {
    // "If final usage is unavailable after upstream acceptance, retain the
    // reservation as a conservative charge rather than refunding uncertain
    // consumption." The router could estimate what was used; that estimate is
    // the uncertainty the sentence is about.
    let harness = Harness::new(FakeUpstream::start(CannedResponse::json(
        200,
        r#"{"id":"c1","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"Flow control."},"finish_reason":"stop"}]}"#,
    )));
    harness.set_limit(Some(1_000_000));

    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);

    let consumed = harness.budget().consumed;
    assert!(
        consumed > 8192,
        "an unmetered reply was charged {consumed}, less than the output limit it was held to"
    );
    harness.assert_nothing_in_flight();
}

/// A client that takes the first frame and goes away.
struct Gone;

impl EventSink for Gone {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        Err(SinkClosed)
    }
}

fn pipeline_request() -> CanonicalRequest {
    let mut request = hypellm_adapters::testing::request_fixture();
    request.requested_model = AliasId::new("test-alias").unwrap();
    request
}

#[test]
fn a_client_that_disconnects_after_acceptance_is_charged_its_reservation() {
    let upstream = ok_upstream();
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    let key = key_of(&router);
    router
        .state
        .budgets
        .set(&key, &tenant(), None, Some(1_000_000), None)
        .unwrap();

    let outcome = pipeline::execute_for_key(
        &router.state,
        &pipeline_request(),
        &[],
        PermissionSet::empty(),
        Some(&key),
        &mut Gone,
    );

    assert!(!outcome.is_success());
    let budget = router.state.budgets.view(&key);
    // The fixture asks for 512 output tokens; the provider was reached and the
    // caller never learned what it used.
    assert!(budget.consumed >= 512, "{budget:?}");
    assert_eq!(budget.reserved, 0);
}

#[test]
fn a_caller_without_a_key_has_no_budget_to_charge() {
    let upstream = ok_upstream();
    let router = router_with_config(&upstream, &default_config_text(upstream.address.port()));
    let key = key_of(&router);
    router.state.budgets.set(&key, &tenant(), None, Some(0), None).unwrap();

    struct Accept;
    impl EventSink for Accept {
        fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
            Ok(())
        }
    }
    let outcome = pipeline::execute(
        &router.state,
        &pipeline_request(),
        &[],
        PermissionSet::empty(),
        &mut Accept,
    );

    assert!(outcome.is_success(), "{:?}", outcome.error);
    assert_eq!(router.state.budgets.view(&key).consumed, 0);
}

// -- Failover ---------------------------------------------------------------

fn two_target_config(port: u16) -> String {
    default_config_text(port)
        .replace(
            "alias id=test-alias targets=local:model",
            "target id=local:second provider=local model=second-model local=true \\\n       \
             operations=chat streaming=true context=100000 max_output=8192 concurrency=8\n\
             alias id=test-alias targets=local:model,local:second",
        )
        .replace("prefer=local:model", "prefer=local:model,local:second")
}

#[test]
fn a_failed_attempt_returns_its_hold_and_only_the_accepted_one_is_charged() {
    // The first target answers 503 before acceptance, the second serves. Each
    // attempt reserved; the first must have given its hold back, or two
    // attempts would cost a caller two reservations for one answer.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, r#"{"error":{"message":"loading"}}"#),
        CannedResponse::json(200, COMPLETION),
    ]);
    let config = two_target_config(upstream.address.port());
    let harness = Harness::with_config(upstream, &config);
    harness.set_limit(Some(1_000_000));

    let response = harness.post("/v1/chat/completions", CHAT);

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 2, "the failover did not happen");
    assert_eq!(harness.budget().consumed, 17);
    harness.assert_nothing_in_flight();
}

// -- Top-up and restart -----------------------------------------------------

#[test]
fn a_credit_admits_the_next_request_with_no_restart_or_new_key() {
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(10_000));
    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);
    harness.set_limit(Some(17));
    assert_budget_refusal(&harness.post("/v1/chat/completions", CHAT));

    let credited = harness
        .router
        .state
        .budgets
        .credit(&harness.key(), &tenant(), None, 500_000, "pay-1", "digest", None, "svc:pay", 1)
        .expect("credit");
    assert_eq!(credited.view.remaining(), Some(500_000));

    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);
    assert_eq!(harness.budget().consumed, 34);
}

/// The ledger a router would rebuild from what is on disk right now.
fn ledger_after_restart(router: &TestRouter) -> Arc<BudgetLedger> {
    let ledger = Arc::new(BudgetLedger::new(Arc::new(MemoryJournal::new()), 0));
    let frames = router
        .state
        .store
        .records_of_kinds(&[RecordKind::KeyBudget])
        .expect("replay the log");
    assert!(!frames.is_empty(), "no budget record reached the log");
    for (_, payload) in frames {
        ledger.restore(decode_record(&payload).expect("a readable budget record"));
    }
    ledger
}

#[test]
fn what_was_spent_is_still_spent_after_an_unclean_restart() {
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(100_000));
    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);
    let before = harness.budget();
    assert_eq!(before.consumed, 17);

    // No flush: the process is taken to have died here.
    let after = ledger_after_restart(&harness.router).view(&harness.key());

    assert_eq!(after.limit, Some(100_000));
    assert!(
        after.consumed >= before.consumed,
        "a restart returned credit: {before:?} became {after:?}"
    );
    assert!(after.consumed <= 100_000);
}

#[test]
fn a_clean_shutdown_records_exactly_what_was_used() {
    let harness = Harness::new(ok_upstream());
    harness.set_limit(Some(100_000));
    assert_eq!(harness.post("/v1/chat/completions", CHAT).status, 200);

    assert_eq!(harness.router.state.budgets.flush(), 0);

    assert_eq!(
        ledger_after_restart(&harness.router).view(&harness.key()).consumed,
        17
    );
}
