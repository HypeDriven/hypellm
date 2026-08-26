//! End-to-end tests: a real listener, a real pipeline, a fake provider.
//!
//! These exercise the whole path — transport, authentication, protocol
//! translation, routing, admission, the adapter, the egress guard, streaming,
//! and metering — against a provider that answers on a real socket. Unit tests
//! prove each piece; these prove they compose.

use hypellm_core::time::Clock;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{
    CannedResponse, FakeUpstream, TestRouter, default_config_text, router_for, router_with_config,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use wire_json::{Limits, parse_str};

/// A running router in front of a fake upstream.
struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
    upstream: FakeUpstream,
}

impl Harness {
    fn start(upstream: FakeUpstream, router: TestRouter) -> Self {
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let mut server =
            Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).expect("bind");
        server.observe(hypellm_router::server::ListenerMetrics::new(
            Arc::clone(&router.state.telemetry),
            "inference",
        ));
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

    fn default(response: CannedResponse) -> Self {
        let upstream = FakeUpstream::start(response);
        let router = router_for(&upstream);
        Self::start(upstream, router)
    }

    fn request(&self, method: &str, path: &str, body: &str, authorized: bool) -> Response {
        let mut headers = format!(
            "{method} {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\nConnection: close\r\n"
        );
        if authorized {
            headers.push_str(&format!("Authorization: Bearer {}\r\n", self.router.api_key));
        }
        headers.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        headers.push_str(body);
        self.raw(&headers)
    }

    /// A chat request issued on its own thread, so several can be in flight.
    fn spawn_request(&self) -> std::thread::JoinHandle<Response> {
        let address = self.address;
        let key = self.router.api_key.clone();
        std::thread::spawn(move || {
            let raw = format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: router.test\r\n\
                 Content-Type: application/json\r\nConnection: close\r\n\
                 Authorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{CHAT_BODY}",
                CHAT_BODY.len()
            );
            raw_to(address, &raw)
        })
    }

    fn raw(&self, raw: &str) -> Response {
        raw_to(self.address, raw)
    }
}

fn raw_to(address: SocketAddr, raw: &str) -> Response {
    {
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

        Response { status, head, body }
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

struct Response {
    status: u16,
    head: String,
    body: String,
}

impl Response {
    fn json(&self) -> wire_json::Value {
        parse_str(&self.body, &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }

    fn sse_payloads(&self) -> Vec<String> {
        let mut parser = wire_sse::SseParser::with_default_limits();
        parser.push(self.body.as_bytes()).expect("valid SSE");
        parser
            .drain()
            .expect("valid SSE")
            .into_iter()
            .map(|event| event.data)
            .collect()
    }

    fn sse_events(&self) -> Vec<(Option<String>, String)> {
        let mut parser = wire_sse::SseParser::with_default_limits();
        parser.push(self.body.as_bytes()).expect("valid SSE");
        parser
            .drain()
            .expect("valid SSE")
            .into_iter()
            .map(|event| (event.event, event.data))
            .collect()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(str::trim)
    }
}

const CHAT_BODY: &str =
    r#"{"model":"test-alias","messages":[{"role":"user","content":"Explain backpressure."}]}"#;

/// A router built from explicit configuration text.
///
/// `router_with_config` ignores its upstream argument — the address is already
/// in the text — but the signature requires one, so this keeps the queueing
/// tests from having to fabricate a second listener.
fn router_with_config_text(config: &str) -> TestRouter {
    let placeholder = FakeUpstream::start(CannedResponse::json(200, "{}"));
    router_with_config(&placeholder, config)
}

fn chat_completion_response() -> CannedResponse {
    CannedResponse::json(
        200,
        r#"{"id":"chatcmpl-up1","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"Backpressure is flow control."},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#,
    )
}

// -- Health and discovery ---------------------------------------------------

#[test]
fn liveness_answers_without_configuration() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("GET", "/health/live", "", false);
    assert_eq!(response.status, 200);
    assert_eq!(response.json().field_str("status").unwrap(), "ok");
}

#[test]
fn readiness_reports_the_verdict_and_nothing_that_fingerprints_the_deployment() {
    // Specification 8: health endpoints expose "no sensitive provider detail".
    // A load balancer needs the verdict; an unauthenticated caller on the
    // inference port does not need the configuration version and digest, which
    // together fingerprint the active configuration and reveal the moment it
    // changes. The detailed form lives on the management listener.
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("GET", "/health/ready", "", false);
    assert_eq!(response.status, 200);

    let json = response.json();
    assert_eq!(json.field_str("status").unwrap(), "ready");
    assert!(
        json.opt_field_i64("config_version").ok().flatten().is_none(),
        "the configuration version must not be disclosed pre-auth: {}",
        response.body
    );
    assert!(
        json.opt_field_str("config_digest").ok().flatten().is_none(),
        "the configuration digest must not be disclosed pre-auth: {}",
        response.body
    );
    // Nor anything else about the deployment.
    for leaked in ["local:model", "test-model", "127.0.0.1", "test-alias"] {
        assert!(
            !response.body.contains(leaked),
            "'{leaked}' appeared in an unauthenticated readiness response:\n{}",
            response.body
        );
    }
}

#[test]
fn the_model_list_shows_only_authorized_aliases() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("GET", "/v1/models", "", true);
    assert_eq!(response.status, 200);
    let json = response.json();
    let data = json.field_array("data").unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].field_str("id").unwrap(), "test-alias");
    assert_eq!(data[0].field_str("description").unwrap(), "the test model");
}

#[test]
fn the_metrics_exposition_is_not_reachable_from_the_data_plane() {
    // Specification 17's exposition lists target identifiers, queue depths,
    // breaker states, auth failure counts, and the active configuration
    // version. Specification 3 separates the data path from the management
    // path so that an inference caller cannot read that map of the deployment.
    //
    // It used to be served here, ahead of authentication, to anyone who could
    // reach the inference port.
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    let anonymous = harness.request("GET", "/metrics", "", false);
    assert_ne!(anonymous.status, 200);
    assert!(!anonymous.body.contains("hypellm_requests_total"));

    // Nor with a valid inference credential: the endpoint is simply not part
    // of this listener's surface.
    let authenticated = harness.request("GET", "/metrics", "", true);
    assert_ne!(authenticated.status, 200);
    assert!(!authenticated.body.contains("hypellm_requests_total"));
}

#[test]
fn the_metrics_exposition_still_reports_without_high_cardinality_labels() {
    // The exposition itself is unchanged; only where it is served moved.
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    let body = harness.router.state.telemetry.exposition();
    assert!(body.contains("hypellm_requests_total"));
    assert!(body.contains("# TYPE"));
    // Specification 17: "High-cardinality labels such as raw user id, request
    // id, prompt, URL, and error text are forbidden in metrics."
    assert!(!body.contains("request_id"));
    assert!(!body.contains("principal"));
}

#[test]
fn the_exposition_carries_every_signal_the_specification_names() {
    // Specification 17's signal table: "Requests, active streams, tokens,
    // bytes, queue depth/wait, target latency/error, breaker state, auth
    // failures, config version."
    //
    // Ten of these were declared in `names` and emitted by nothing, so the
    // exposition looked complete in source and reported nothing in production.
    // This asserts against the rendered text, which is what a collector sees.
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, false);

    let body = harness.router.state.telemetry.exposition();
    for name in [
        "hypellm_requests_total",
        "hypellm_tokens_total",
        "hypellm_client_bytes_in_total",
        "hypellm_client_bytes_out_total",
        "hypellm_open_connections",
        "hypellm_upstream_latency_milliseconds",
        "hypellm_breaker_state",
        "hypellm_auth_failures_total",
        "hypellm_router_overhead_milliseconds",
    ] {
        assert!(body.contains(name), "{name} is absent from the exposition:\n{body}");
    }

    // The breaker gauge is one series per state with a zero/one value, so an
    // alert can name the state it cares about instead of decoding an ordinal.
    assert!(
        body.contains("breaker_state=\"closed\""),
        "the breaker gauge must name its states:\n{body}"
    );
    // Still no high-cardinality label anywhere in the new series.
    assert!(!body.contains("request_id"));
    assert!(!body.contains("principal"));
}

#[test]
fn a_stream_reports_how_long_it_spent_blocked_on_the_client() {
    // `DI-037`: specification 14 asks for explicit high/low watermarks that
    // pause upstream reads. The blocking model produces that behaviour without
    // a tunable — the connection thread stops reading upstream precisely
    // because it is blocked writing — so there is no watermark to set. What
    // there was, until now, was no way to see it either: "the client is slow"
    // and "the provider is slow" looked identical from outside.
    //
    // The series must exist after a stream, carry the operation label, and
    // carry nothing higher-cardinality than that (specification 7.1).
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Back"}}]}"#,
        r#"{"id":"1","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
    ]));
    let router = router_for(&upstream);
    let harness = Harness::start(upstream, router);

    let body =
        r#"{"model":"test-alias","messages":[{"role":"user","content":"x"}],"stream":true}"#;
    let response = harness.request("POST", "/v1/chat/completions", body, true);
    assert_eq!(response.status, 200);

    let exposition = harness.router.state.telemetry.exposition();
    assert!(
        exposition.contains("hypellm_stream_backpressure_milliseconds"),
        "a completed stream emitted no backpressure series:\n{exposition}"
    );
    assert!(
        exposition.contains("hypellm_stream_backpressure_milliseconds_count{operation=\"chat\"}"),
        "the series must be labelled by operation:\n{exposition}"
    );

    // A non-streaming request must not emit it: the metric is about the
    // streaming write path, and a count inflated by every request would not
    // answer the question it exists for.
    let quiet = Harness::default(chat_completion_response());
    quiet.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert!(
        !quiet
            .router
            .state
            .telemetry
            .exposition()
            .contains("hypellm_stream_backpressure_milliseconds"),
        "a non-streaming request emitted a stream backpressure observation"
    );
}

#[test]
fn client_bytes_are_counted_per_listener() {
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    let labels = hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Listener, "inference");
    let inbound = harness
        .router
        .state
        .telemetry
        .metrics
        .counter_value("hypellm_client_bytes_in_total", &labels)
        .unwrap_or(0);
    let outbound = harness
        .router
        .state
        .telemetry
        .metrics
        .counter_value("hypellm_client_bytes_out_total", &labels)
        .unwrap_or(0);

    // At least the request head and body went in, and a response came out.
    assert!(
        inbound >= CHAT_BODY.len() as u64,
        "inbound bytes {inbound} did not cover the body"
    );
    assert!(outbound > 0, "no outbound bytes were counted");
}

#[test]
fn a_request_waits_for_a_slot_instead_of_being_refused() {
    // Specification 3.2 lists queued requests as a bounded resource "per target
    // and principal; finite; queue timeout mandatory", and specification 12
    // sets the order. Before this, `queued=` was accepted by the configuration
    // grammar, stored on the scope, and consulted by nothing: a target at its
    // concurrency limit refused immediately no matter what the operator wrote.
    let upstream = FakeUpstream::start(
        chat_completion_response().after(std::time::Duration::from_millis(250)),
    );
    let config = default_config_text(upstream.address.port())
        .replace("concurrency=8", "concurrency=1")
        + "quota scope=target:local:model concurrency=1 queued=4\n";
    let harness = Harness::start(upstream, router_with_config_text(&config));

    // Two requests at once against a target that admits one.
    let first = harness.spawn_request();
    std::thread::sleep(std::time::Duration::from_millis(60));
    let second = harness.spawn_request();

    let a = first.join().expect("first thread");
    let b = second.join().expect("second thread");
    assert_eq!(a.status, 200, "the first request should be served");
    assert_eq!(
        b.status, 200,
        "the second request waited for the slot rather than being refused:\n{}",
        b.body
    );
    assert_eq!(
        harness.upstream.served(),
        2,
        "both requests reached the provider"
    );

    let exposition = harness.router.state.telemetry.exposition();
    assert!(
        exposition.contains("hypellm_queue_wait_milliseconds"),
        "the queue wait must be measured:\n{exposition}"
    );
    assert!(
        exposition.contains("hypellm_queue_depth"),
        "the queue depth must be published:\n{exposition}"
    );
}

#[test]
fn a_target_with_no_queue_still_refuses_immediately() {
    // Queueing is opt-in. With no `queued=` the behaviour is what it was: the
    // second request is refused rather than made to wait.
    let upstream = FakeUpstream::start(
        chat_completion_response().after(std::time::Duration::from_millis(250)),
    );
    let config = default_config_text(upstream.address.port())
        .replace("concurrency=8", "concurrency=1")
        + "quota scope=target:local:model concurrency=1\n";
    let harness = Harness::start(upstream, router_with_config_text(&config));

    let first = harness.spawn_request();
    std::thread::sleep(std::time::Duration::from_millis(60));
    let second = harness.spawn_request();

    let _ = first.join().expect("first thread");
    let b = second.join().expect("second thread");
    assert_eq!(b.status, 429, "expected an immediate refusal, got:\n{}", b.body);
}

#[test]
fn every_request_gets_its_own_identifier() {
    // Specification 17 keys the decision trace, the audit record, and
    // `X-Request-Id` on this. The router used to fall back to `0` when entropy
    // was unavailable, which assigned every request the same identifier and
    // collapsed correlation with nothing said; it now refuses instead.
    //
    // Entropy failure has no injection seam, so what this can assert is the
    // property a reintroduced fallback would break: identifiers are present,
    // distinct, and never the all-zero value.
    let harness = Harness::default(chat_completion_response());
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
        assert_eq!(response.status, 200, "{}", response.body);
        let id = response
            .json()
            .field_str("id")
            .map(ToOwned::to_owned)
            .or_else(|_| {
                response
                    .header("x-request-id")
                    .map(ToOwned::to_owned)
                    .ok_or(())
            })
            .expect("a response carries an identifier");
        assert_ne!(id, "0".repeat(32), "the all-zero fallback identifier is back");
        seen.insert(id);
    }

    // Also asserted on the error path, which is the one that answers before a
    // request id would otherwise have been needed for anything.
    let refused = harness.request("POST", "/v1/chat/completions", CHAT_BODY, false);
    let refused_id = refused
        .json()
        .field_str("request_id")
        .expect("an error carries a request id")
        .to_owned();
    assert_ne!(refused_id, "0".repeat(32));
    seen.insert(refused_id);

    assert_eq!(seen.len(), 9, "identifiers must be distinct: {seen:?}");
}

#[test]
fn a_credential_probe_reaches_the_provider_through_the_ordinary_path() {
    // Specification 22.2 step 15. Asserted here rather than in the management
    // suite because this is the half that matters: the probe must go through
    // the real adapter and dispatch path, or it validates the special code path
    // instead of the one requests take.
    let upstream = FakeUpstream::start(chat_completion_response());
    let config = default_config_text(upstream.address.port())
        .replace(
            "provider id=local family=openai scheme=http host=127.0.0.1",
            "credential id=probe-cred\nprovider id=local family=openai credential=probe-cred \\\n         scheme=http host=127.0.0.1",
        );
    let router = router_with_config(&upstream, &config);
    let state = std::sync::Arc::clone(&router.state);
    let harness = Harness::start(upstream, router);

    let reference = hypellm_core::ids::CredentialRef::new("probe-cred").expect("reference");
    let sink = hypellm_router::state::CredentialSinkAdapter::new(std::sync::Arc::clone(&state));
    let outcome = hypellm_admin_api::CredentialSink::probe(&sink, &reference)
        .expect("a declared credential with an enabled target must be probeable");

    assert!(outcome.ok, "the probe should have succeeded: {outcome:?}");
    assert_eq!(outcome.target, "local:model");
    assert_eq!(
        harness.upstream.served(),
        1,
        "the probe must actually reach the provider"
    );

    // A probe asks for one token: it exists to prove the credential is
    // accepted, not to generate anything.
    let received = harness.upstream.received();
    let body = received.first().expect("a request body");
    let text = String::from_utf8_lossy(body);
    assert!(
        text.contains("\"max_tokens\":1") || text.contains("\"max_output_tokens\":1"),
        "a probe must be as close to free as the provider allows:\n{text}"
    );
}

#[test]
fn a_probe_against_a_rejecting_provider_reports_failure_not_success() {
    let upstream = FakeUpstream::start(CannedResponse::json(
        401,
        r#"{"error":{"message":"Incorrect API key provided: sk-live-REDACTME","type":"invalid_request_error","code":"invalid_api_key"}}"#,
    ));
    let config = default_config_text(upstream.address.port())
        .replace(
            "provider id=local family=openai scheme=http host=127.0.0.1",
            "credential id=probe-cred\nprovider id=local family=openai credential=probe-cred \\\n         scheme=http host=127.0.0.1",
        );
    let router = router_with_config(&upstream, &config);
    let state = std::sync::Arc::clone(&router.state);
    let _harness = Harness::start(upstream, router);

    let reference = hypellm_core::ids::CredentialRef::new("probe-cred").expect("reference");
    let sink = hypellm_router::state::CredentialSinkAdapter::new(state);
    let outcome = hypellm_admin_api::CredentialSink::probe(&sink, &reference).expect("probeable");

    assert!(!outcome.ok, "a 401 must not read as a valid credential");
    assert!(outcome.class.is_some(), "the failure must be classified");

    // Specification 10: the provider's message never crosses into a management
    // response. The narrowed code may; the text around it may not.
    let rendered = format!("{outcome:?}");
    assert!(
        !rendered.contains("sk-live-REDACTME"),
        "the probe leaked the provider message: {rendered}"
    );
    assert!(
        !rendered.contains("Incorrect API key provided"),
        "the probe leaked the provider message: {rendered}"
    );
}

#[test]
fn a_silent_upstream_produces_keepalives_rather_than_nothing() {
    // Specification 14 requires periodic keepalives on an open stream. A
    // provider can be silent for a long time before its first token — a cold
    // model, a queue, a long prompt — and an intermediary with an idle timeout
    // drops a connection that has sent nothing, turning a slow answer into a
    // failed one.
    //
    // `settings keepalive_interval_ms` was parsed and read by nothing
    // (`DI-011`), so no keepalive was ever written.
    let upstream = FakeUpstream::start(
        CannedResponse::event_stream(&[
            r#"{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ])
        .silent_before_body(std::time::Duration::from_millis(600)),
    );
    let config = default_config_text(upstream.address.port())
        .replace("max_attempts=3", "max_attempts=3 keepalive_interval_ms=100");
    let harness = Harness::start(upstream, router_with_config_text(&config));

    let response = harness.request(
        "POST",
        "/v1/chat/completions",
        r#"{"model":"test-alias","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        true,
    );
    assert_eq!(response.status, 200, "{}", response.body);

    // SSE comments: ignored by every conforming client, counted as traffic by
    // every idle-timeout intermediary.
    let comments = response
        .body
        .lines()
        .filter(|line| line.starts_with(':'))
        .count();
    assert!(
        comments >= 2,
        "a 600 ms silence at a 100 ms cadence produced {comments} keepalive(s):\n{}",
        response.body
    );

    // And the completion still arrives intact: a keepalive must not disturb the
    // stream it is keeping open.
    assert!(
        response.body.contains("hello"),
        "the completion was lost:\n{}",
        response.body
    );
    assert!(response.body.contains("[DONE]"), "{}", response.body);
}

#[test]
fn keepalives_are_off_when_the_interval_is_zero() {
    // Zero disables it, and the read then waits out the whole deadline as it
    // did before. An operator who has an edge that dislikes comments must be
    // able to turn them off.
    let upstream = FakeUpstream::start(
        CannedResponse::event_stream(&[
            r#"{"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}"#,
        ])
        .silent_before_body(std::time::Duration::from_millis(300)),
    );
    let config = default_config_text(upstream.address.port())
        .replace("max_attempts=3", "max_attempts=3 keepalive_interval_ms=0");
    let harness = Harness::start(upstream, router_with_config_text(&config));

    let response = harness.request(
        "POST",
        "/v1/chat/completions",
        r#"{"model":"test-alias","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        true,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.body.lines().filter(|l| l.starts_with(':')).count(),
        0,
        "keepalives were written despite being disabled:\n{}",
        response.body
    );
}

#[test]
fn usage_is_attributed_to_the_api_key_that_produced_it() {
    // Specification 22.3 step 20: "Search authorized audit/usage by key
    // pseudonym". Usage carried a *principal*, and one principal can hold
    // several keys, so a compromised-key investigation could not ask what that
    // key had spent (`DI-023`).
    let harness = Harness::default(chat_completion_response());
    for _ in 0..3 {
        let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
        assert_eq!(response.status, 200, "{}", response.body);
    }

    let tenant = hypellm_core::ids::TenantId::new("acme").expect("tenant");
    let attributed = harness.router.state.usage.keys(&tenant);
    assert_eq!(
        attributed.len(),
        1,
        "exactly one key served these requests: {attributed:?}"
    );
    let (key, totals) = attributed.first().expect("a row");
    assert_eq!(totals.requests, 3);
    assert!(totals.input_tokens > 0, "tokens must be attributed too");

    // The key in the row is the one that authenticated, not a guess. Checked
    // by resolving it in the key store rather than by pattern-matching the
    // secret: the identifier's relationship to the secret string is an
    // encoding detail, and asserting on it would test the encoding.
    let record = harness
        .router
        .state
        .keys
        .get(key)
        .expect("the attributed key must exist in the key store");
    assert_eq!(record.principal.as_str(), "svc:test");
    assert_eq!(record.tenant.as_str(), "acme");
}

#[test]
fn a_rotation_the_provider_has_not_accepted_is_survived_and_reported() {
    // Specification 22.2 step 16: "Activate new reference atomically with
    // bounded overlap." Rotating before the provider activates the new secret
    // used to take the target out of service until somebody noticed — and with
    // no fallback, every request failed.
    //
    // The upstream here refuses the *new* secret and accepts the old one, which
    // is exactly what a premature rotation looks like from the router.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(
            401,
            r#"{"error":{"message":"Incorrect API key","type":"invalid_request_error","code":"invalid_api_key"}}"#,
        ),
        chat_completion_response(),
    ]);
    let config = default_config_text(upstream.address.port()).replace(
        "provider id=local family=openai scheme=http host=127.0.0.1",
        "credential id=rotating\nprovider id=local family=openai credential=rotating \\\n         scheme=http host=127.0.0.1",
    );
    let router = router_with_config_text(&config);
    let state = std::sync::Arc::clone(&router.state);
    let reference = hypellm_core::ids::CredentialRef::new("rotating").expect("reference");

    // Establish an original secret, then rotate to one the provider refuses.
    let now = state.clock.wall_millis();
    state.credentials.rotate(&reference, b"sk-original".to_vec(), now);
    state
        .credentials
        .rotate(&reference, b"sk-rotated-too-early".to_vec(), now + 1);

    let harness = Harness::start(upstream, router);
    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    // The request is served rather than failed: the superseded secret carried
    // it.
    assert_eq!(
        response.status, 200,
        "the overlap window did not cover a premature rotation: {}",
        response.body
    );
    assert_eq!(
        harness.upstream.served(),
        2,
        "the fallback should be one extra exchange, not more"
    );

    // And it is *reported*, which is the half that keeps a bad rotation from
    // hiding until the window closes and everything fails at once.
    assert!(
        state
            .credentials
            .rotation_unaccepted(&reference, state.clock.wall_millis()),
        "the fallback must be visible on the credential"
    );
    let exposition = state.telemetry.exposition();
    assert!(
        exposition.contains("hypellm_credential_fallbacks_total"),
        "the fallback must be counted:\n{exposition}"
    );
}

#[test]
fn a_healthy_rotation_uses_no_fallback_and_reports_nothing() {
    // The common case must stay silent, or the alarm becomes noise. A rotation
    // the provider has already accepted retires the superseded secret on its
    // first success, so the window lasts one request.
    let upstream = FakeUpstream::start(chat_completion_response());
    let config = default_config_text(upstream.address.port()).replace(
        "provider id=local family=openai scheme=http host=127.0.0.1",
        "credential id=rotating\nprovider id=local family=openai credential=rotating \\\n         scheme=http host=127.0.0.1",
    );
    let router = router_with_config_text(&config);
    let state = std::sync::Arc::clone(&router.state);
    let reference = hypellm_core::ids::CredentialRef::new("rotating").expect("reference");

    let now = state.clock.wall_millis();
    state.credentials.rotate(&reference, b"sk-original".to_vec(), now);
    state
        .credentials
        .rotate(&reference, b"sk-accepted".to_vec(), now + 1);

    let harness = Harness::start(upstream, router);
    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 1, "no fallback should be needed");
    assert!(
        !state
            .credentials
            .rotation_unaccepted(&reference, state.clock.wall_millis()),
        "a healthy rotation must not raise an alarm"
    );
}

// -- Authentication ---------------------------------------------------------

#[test]
fn an_unauthenticated_request_is_refused() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, false);
    assert_eq!(response.status, 401);
    assert_eq!(
        response.json().get("error").unwrap().field_str("code").unwrap(),
        "unauthenticated"
    );
    assert_eq!(response.header("www-authenticate"), Some("Bearer"));
    assert_eq!(harness.upstream.served(), 0, "no upstream call was made");
}

#[test]
fn a_forged_key_is_refused_indistinguishably() {
    let harness = Harness::default(chat_completion_response());
    let forged = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer hypellmk_00000000deadbeef_{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CHAT_BODY}",
        "A".repeat(43),
        CHAT_BODY.len()
    );
    let response = harness.raw(&forged);
    assert_eq!(response.status, 401);

    let unauthenticated = harness.request("POST", "/v1/chat/completions", CHAT_BODY, false);
    assert_eq!(
        response.json().get("error").unwrap().field_str("message").unwrap(),
        unauthenticated
            .json()
            .get("error")
            .unwrap()
            .field_str("message")
            .unwrap(),
        "a forged key and an absent one must look identical"
    );
}

// -- The happy path ---------------------------------------------------------

#[test]
fn a_chat_completion_round_trips() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("object").unwrap(), "chat.completion");
    // The client sees the alias it asked for, not the native model.
    assert_eq!(json.field_str("model").unwrap(), "test-alias");
    let choice = &json.field_array("choices").unwrap()[0];
    assert_eq!(
        choice.get("message").unwrap().field_str("content").unwrap(),
        "Backpressure is flow control."
    );
    assert_eq!(choice.field_str("finish_reason").unwrap(), "stop");

    // Usage is provider-reported and marked as such.
    let usage = json.get("usage").unwrap();
    assert_eq!(usage.field_i64("prompt_tokens").unwrap(), 12);
    assert_eq!(usage.field_i64("total_tokens").unwrap(), 17);
    assert_eq!(
        usage.get("hypellm").unwrap().field_str("usage_source").unwrap(),
        "provider_reported"
    );

    // The native model reached is visible in metadata (specification 6.5).
    assert_eq!(
        json.get("hypellm").unwrap().field_str("native_model").unwrap(),
        "test-model"
    );

    assert_eq!(harness.upstream.served(), 1);
}

#[test]
fn the_upstream_receives_the_native_model_not_the_alias() {
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    let sent = harness.upstream.last_body().expect("a request body");
    let json = parse_str(&sent, &Limits::DEFAULT).expect("valid JSON");
    assert_eq!(json.field_str("model").unwrap(), "test-model");
    assert_eq!(json.field_array("messages").unwrap().len(), 1);
    // The router does not invent parameters the client did not set.
    assert!(json.get("temperature").is_none());

    // `max_tokens` is the exception, and deliberately so: an absent output
    // limit is not "the provider picks something sensible". A llama.cpp target
    // started without `-n` reports `n_predict: -1` and generates until its slot
    // context fills, holding a concurrency slot long after whoever asked has
    // gone. `declared_output_limit` in the OpenAI adapter falls back to what
    // the target declared — `max_output=8192` in `default_config_text` — and
    // only where the target declares one, since `max_output` defaults to 0
    // meaning undeclared rather than unlimited.
    assert_eq!(json.field_i64("max_tokens").ok(), Some(8192));
}

#[test]
fn the_credential_never_appears_in_a_log_line() {
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    let logs = harness.router.logs.lines().join("\n");
    assert!(!logs.is_empty(), "the request should have been logged");
    assert!(!logs.contains(&harness.router.api_key));
    assert!(!logs.contains("hypellmk_"));
    // Nor does the prompt.
    assert!(!logs.contains("Explain backpressure"));
    // Nor the completion.
    assert!(!logs.contains("flow control"));
}

#[test]
fn the_tenant_is_pseudonymous_in_logs() {
    let harness = Harness::default(chat_completion_response());
    harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    let logs = harness.router.logs.lines().join("\n");
    assert!(!logs.contains("\"tenant\":\"acme\""), "{logs}");
    assert!(logs.contains("\"tenant\":\""));
}

// -- Streaming --------------------------------------------------------------

#[test]
fn a_streaming_chat_completion_arrives_as_sse() {
    let upstream = FakeUpstream::start(CannedResponse::event_stream(&[
        r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Back"}}]}"#,
        r#"{"id":"1","choices":[{"delta":{"content":"pressure"}}]}"#,
        r#"{"id":"1","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
    ]));
    let router = router_for(&upstream);
    let harness = Harness::start(upstream, router);

    let body =
        r#"{"model":"test-alias","messages":[{"role":"user","content":"x"}],"stream":true}"#;
    let response = harness.request("POST", "/v1/chat/completions", body, true);

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));
    assert_eq!(response.header("cache-control"), Some("no-store"));

    let payloads = response.sse_payloads();
    assert!(payloads.len() >= 4, "payloads: {payloads:?}");
    assert_eq!(payloads.last().unwrap(), "[DONE]");

    // Reassembling the deltas reproduces the completion.
    let mut text = String::new();
    for payload in &payloads {
        if payload == "[DONE]" {
            continue;
        }
        let chunk = parse_str(payload, &Limits::DEFAULT).expect("chunk is JSON");
        assert_eq!(chunk.field_str("object").unwrap(), "chat.completion.chunk");
        if let Some(delta) = chunk.field_array("choices").ok().and_then(|c| c.first()) {
            if let Some(content) = delta.get("delta").and_then(|d| d.get("content")) {
                text.push_str(content.as_str().unwrap_or(""));
            }
        }
    }
    assert_eq!(text, "Backpressure");
}

#[test]
fn an_anthropic_stream_follows_the_named_event_profile() {
    let upstream = FakeUpstream::start(CannedResponse::named_event_stream(&[
        (
            "message_start",
            r#"{"type":"message_start","message":{"id":"msg_up","model":"test-model","usage":{"input_tokens":9,"output_tokens":0}}}"#,
        ),
        (
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        ),
        (
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
        ),
        (
            "message_delta",
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}"#,
        ),
        ("message_stop", r#"{"type":"message_stop"}"#),
    ]));

    let config = hypellm_router::testing::default_config_text(upstream.address.port())
        .replace("family=openai", "family=anthropic");
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let body = r#"{"model":"test-alias","max_tokens":100,"messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    let response = harness.request("POST", "/v1/messages", body, true);

    assert_eq!(response.status, 200, "{}", response.body);
    let events = response.sse_events();
    let names: Vec<&str> = events
        .iter()
        .filter_map(|(name, _)| name.as_deref())
        .collect();

    assert_eq!(names.first(), Some(&"message_start"));
    assert_eq!(names.last(), Some(&"message_stop"));
    assert!(names.contains(&"content_block_start"));
    assert!(names.contains(&"content_block_delta"));
    assert!(names.contains(&"message_delta"));

    // Every opened block is closed.
    let starts = names.iter().filter(|n| **n == "content_block_start").count();
    let stops = names.iter().filter(|n| **n == "content_block_stop").count();
    assert_eq!(starts, stops, "unbalanced blocks: {names:?}");
}

// -- Errors -----------------------------------------------------------------

#[test]
fn an_unknown_alias_is_a_model_not_found() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request(
        "POST",
        "/v1/chat/completions",
        r#"{"model":"no-such-alias","messages":[{"role":"user","content":"x"}]}"#,
        true,
    );
    assert_eq!(response.status, 404);
    assert_eq!(
        response.json().get("error").unwrap().field_str("code").unwrap(),
        "model_not_found"
    );
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn a_provider_error_is_translated_without_its_message() {
    let upstream = FakeUpstream::start(CannedResponse::json(
        400,
        r#"{"error":{"message":"the prompt 'CONFIDENTIAL' was rejected by host db-7.internal","type":"invalid_request_error"}}"#,
    ));
    let router = router_for(&upstream);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(response.status, 400);
    let message = response
        .json()
        .get("error")
        .unwrap()
        .field_str("message")
        .unwrap()
        .to_owned();
    assert!(!message.contains("CONFIDENTIAL"));
    assert!(!message.contains("db-7.internal"));
}

#[test]
fn a_malformed_request_body_is_rejected_before_any_upstream_call() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("POST", "/v1/chat/completions", "{not json", true);
    assert_eq!(response.status, 400);
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn an_unknown_endpoint_is_refused() {
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("POST", "/v1/nonexistent", "{}", true);
    assert_eq!(response.status, 400);
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn a_smuggling_attempt_never_reaches_routing() {
    let harness = Harness::default(chat_completion_response());
    let raw = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        harness.router.api_key
    );
    let response = harness.raw(&raw);
    assert_eq!(response.status, 400);
    assert!(response.body.contains("conflicting_framing"));
    assert_eq!(harness.upstream.served(), 0);
}

// -- Failover ---------------------------------------------------------------

#[test]
fn a_retriable_failure_fails_over_to_the_next_target() {
    // Two targets on the same fake upstream: the first answer is a 503, the
    // second a success. The router must try again rather than surfacing the
    // first failure.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, r#"{"error":{"type":"api_error"}}"#),
        CannedResponse::json(
            200,
            r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"recovered"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        ),
    ]);

    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:first provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
target id=local:second provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
alias id=test-alias targets=local:first,local:second family_failover=true
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:first,local:second
"
    );
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.json().field_array("choices").unwrap()[0]
            .get("message")
            .unwrap()
            .field_str("content")
            .unwrap(),
        "recovered"
    );
    assert_eq!(harness.upstream.served(), 2, "the router should have retried");
}

#[test]
fn a_tenant_residency_requirement_excludes_a_target_in_another_region() {
    // Specification 6.2 lists residency among the eligibility filters, and
    // Appendix A's worked example excludes a target on exactly this basis.
    //
    // Before the tenant's configured region reached the canonical request, the
    // parsers hardcoded `residency: None` and this filter could never exclude
    // anything: a US target served an EU tenant.
    let upstream = FakeUpstream::start_sequence(vec![CannedResponse::json(
        200,
        r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
    )]);
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000
tenant id=acme residency=eu
provider id=p family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=p:us provider=p model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 residency=us
alias id=test-alias targets=p:us
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=p:us
"
    );
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_ne!(response.status, 200, "an out-of-region target must not serve: {}", response.body);
    assert_eq!(
        harness.upstream.served(),
        0,
        "the request must not reach a provider outside the tenant's region"
    );
}

#[test]
fn a_tenant_cost_ceiling_excludes_a_more_expensive_target() {
    // Specification 6.2: "Estimated cost class and actual policy ceiling permit
    // selection." The ceiling was likewise unreachable.
    let upstream = FakeUpstream::start_sequence(vec![CannedResponse::json(
        200,
        r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
    )]);
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000
tenant id=acme max_cost=2
provider id=p family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=p:pricey provider=p model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 cost=7
alias id=test-alias targets=p:pricey
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=p:pricey
"
    );
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_ne!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 0);
}

#[test]
fn a_target_within_the_tenants_ceiling_and_region_is_served() {
    // The control: same shape, but the target satisfies both constraints. A
    // filter that excludes everything is not a working filter.
    let upstream = FakeUpstream::start_sequence(vec![CannedResponse::json(
        200,
        r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
    )]);
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000
tenant id=acme residency=eu max_cost=5
provider id=p family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=p:ok provider=p model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 residency=eu cost=3
alias id=test-alias targets=p:ok
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=p:ok
"
    );
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 1);
}

/// Two targets whose providers are in *different* model families, sharing one
/// fake upstream so that both would succeed if tried. The only variable is the
/// alias's `family_failover` flag.
fn family_failover_config(port: u16, allow: bool) -> String {
    format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=one family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
provider id=two family=deepseek scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=one:model provider=one model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
target id=two:model provider=two model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
alias id=test-alias targets=one:model,two:model family_failover={allow}
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=one:model,two:model
"
    )
}

fn family_failover_upstream() -> FakeUpstream {
    FakeUpstream::start_sequence(vec![
        CannedResponse::json(503, r#"{"error":{"type":"api_error"}}"#),
        CannedResponse::json(
            200,
            r#"{"id":"ok","model":"test-model","choices":[{"message":{"content":"recovered"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        ),
    ])
}

#[test]
fn a_cross_family_failover_is_refused_unless_the_alias_allows_it() {
    // Specification 6.5: "A model-family change must be explicitly allowed in
    // the alias failover policy."
    //
    // The policy engine carries this check too, but it is reachable only when
    // routing is given a non-empty attempted list, and routing runs once per
    // request with an empty one — so before this test the check was dead code
    // and a cross-family failover happened regardless of the flag.
    let upstream = family_failover_upstream();
    let port = upstream.address.port();
    let router = router_with_config(&upstream, &family_failover_config(port, false));
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_ne!(response.status, 200, "the second family must not be tried: {}", response.body);
    assert_eq!(
        harness.upstream.served(),
        1,
        "only the first family may be attempted when family_failover=false"
    );
}

#[test]
fn a_cross_family_failover_proceeds_when_the_alias_allows_it() {
    // The control for the test above: same two families, same upstream, same
    // 503-then-200 sequence. Only the flag differs, so a difference in
    // behaviour can only be attributed to it.
    let upstream = family_failover_upstream();
    let port = upstream.address.port();
    let router = router_with_config(&upstream, &family_failover_config(port, true));
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 2, "the second family should have been tried");
}

#[test]
fn a_non_retriable_failure_is_not_retried() {
    // A 400 means the same request would fail the same way elsewhere.
    let upstream = FakeUpstream::start_sequence(vec![
        CannedResponse::json(400, r#"{"error":{"type":"invalid_request_error"}}"#),
        CannedResponse::json(200, r#"{"choices":[{"message":{"content":"x"}}]}"#),
    ]);
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:first provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
target id=local:second provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
alias id=test-alias targets=local:first,local:second family_failover=true
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:first,local:second
"
    );
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(response.status, 400);
    assert_eq!(
        harness.upstream.served(),
        1,
        "a non-retriable failure must not be retried"
    );
}

// -- The Responses API ------------------------------------------------------
//
// Specification 7 puts `POST /v1/responses` first for the OpenAI family and
// specification 8 marks it a MUST for new integrations. It is a *different*
// dialect from Chat Completions on both sides of the router — the caller's
// request shape and the upstream's request shape — and the two sides are
// independent. The tests below therefore drive the whole path rather than
// either translator alone: a unit test on the client parser and a unit test on
// the adapter encoder both pass while the router sends a Chat body to a
// Responses endpoint, because neither one observes the other.

/// A router whose single target declares the `responses` operation.
///
/// `operations` is an eligibility filter ([`hypellm_core::target::Capabilities::
/// supports_operation`]), so a target that does not declare `responses` is
/// excluded from a `/v1/responses` request rather than serving it as chat.
fn responses_config(port: u16) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat,responses,embeddings streaming=true tools=true json_mode=true \\
       context=100000 max_output=8192 concurrency=8
alias id=test-alias targets=local:model description=\"the test model\"
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
"
    )
}

fn responses_harness(response: CannedResponse) -> Harness {
    let upstream = FakeUpstream::start(response);
    let router = router_with_config(&upstream, &responses_config(upstream.address.port()));
    Harness::start(upstream, router)
}

const RESPONSES_BODY: &str = r#"{"model":"test-alias","input":"Explain backpressure."}"#;

/// A minimal upstream Responses body: one message item, one text part.
fn responses_completion() -> CannedResponse {
    CannedResponse::json(
        200,
        r#"{"id":"resp_up1","object":"response","created_at":1767225600,"status":"completed","model":"test-model","output":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Backpressure is flow control.","annotations":[]}]}],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}"#,
    )
}

/// The raw request the fake upstream received, as (request line, body).
fn upstream_request(harness: &Harness) -> (String, wire_json::Value) {
    let received = harness.upstream.received();
    let raw = received.last().expect("the upstream received a request");
    let text = String::from_utf8_lossy(raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("the request has a body separator");
    let line = head.lines().next().unwrap_or_default().to_owned();
    let json = parse_str(body, &Limits::DEFAULT)
        .unwrap_or_else(|e| panic!("upstream body is not JSON ({e}): {body}"));
    (line, json)
}

#[test]
fn a_responses_request_returns_an_output_array_and_never_choices() {
    let harness = responses_harness(responses_completion());
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);

    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("object").unwrap(), "response");
    assert_eq!(json.field_str("status").unwrap(), "completed");
    // The alias, not the native model.
    assert_eq!(json.field_str("model").unwrap(), "test-alias");

    // The whole point of the dialect: typed items, not `choices`.
    assert!(
        json.get("choices").is_none(),
        "a Responses body must not carry a Chat Completions `choices` array: {}",
        response.body
    );
    let output = json.field_array("output").unwrap();
    assert_eq!(output.len(), 1, "output: {:?}", output);
    let item = &output[0];
    assert_eq!(item.field_str("type").unwrap(), "message");
    assert_eq!(item.field_str("role").unwrap(), "assistant");
    let parts = item.field_array("content").unwrap();
    assert_eq!(parts[0].field_str("type").unwrap(), "output_text");
    assert_eq!(
        parts[0].field_str("text").unwrap(),
        "Backpressure is flow control."
    );
    // Clients iterate annotations unconditionally.
    assert!(parts[0].field_array("annotations").is_ok());

    // Usage is spelled for this dialect, and there is no `finish_reason`.
    let usage = json.get("usage").unwrap();
    assert_eq!(usage.field_i64("input_tokens").unwrap(), 10);
    assert_eq!(usage.field_i64("output_tokens").unwrap(), 5);
    assert_eq!(usage.field_i64("total_tokens").unwrap(), 15);
    assert!(usage.get("prompt_tokens").is_none());
    assert!(item.get("finish_reason").is_none());
}

#[test]
fn the_upstream_receives_a_responses_body_at_the_responses_path() {
    // This is the assertion that catches a router which parses the Responses
    // dialect on the way in, converts to canonical, and then re-encodes it as
    // Chat Completions on the way out. Both translators are individually
    // correct in that failure; only the composition is wrong, and the caller
    // still gets a plausible answer because the fake upstream would happily
    // answer a chat body too.
    let harness = responses_harness(responses_completion());
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);

    let (line, sent) = upstream_request(&harness);
    assert!(
        line.starts_with("POST /v1/responses "),
        "the Responses operation must be sent to the Responses endpoint, got: {line}"
    );

    // `input`, not `messages`.
    let input = sent.field_array("input").unwrap_or_else(|_| {
        panic!("the upstream body must carry `input`: {sent:?}");
    });
    assert!(
        sent.get("messages").is_none(),
        "`messages` is the Chat Completions spelling and must not be sent to /responses"
    );
    assert!(
        sent.get("max_tokens").is_none(),
        "`max_tokens` is the Chat Completions spelling; this dialect uses `max_output_tokens`"
    );

    // The item shape is the Responses one: `input_text`, not `text`.
    assert_eq!(input.len(), 1);
    assert_eq!(input[0].field_str("type").unwrap(), "message");
    assert_eq!(input[0].field_str("role").unwrap(), "user");
    let parts = input[0].field_array("content").unwrap();
    assert_eq!(parts[0].field_str("type").unwrap(), "input_text");
    assert_eq!(parts[0].field_str("text").unwrap(), "Explain backpressure.");

    // The native model still replaces the alias, as on every other path.
    assert_eq!(sent.field_str("model").unwrap(), "test-model");
}

#[test]
fn the_responses_dialect_hoists_instructions_and_renames_the_output_ceiling() {
    let harness = responses_harness(responses_completion());
    let body = r#"{"model":"test-alias","instructions":"Be terse.","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_output_tokens":64}"#;
    let response = harness.request("POST", "/v1/responses", body, true);
    assert_eq!(response.status, 200, "{}", response.body);

    let (_, sent) = upstream_request(&harness);
    // `instructions` is a top-level field on both sides, never a system turn.
    assert_eq!(sent.field_str("instructions").unwrap(), "Be terse.");
    assert_eq!(sent.field_i64("max_output_tokens").unwrap(), 64);
    assert!(sent.get("max_tokens").is_none());
    for item in sent.field_array("input").unwrap() {
        assert_ne!(
            item.field_str("role").unwrap_or_default(),
            "system",
            "instructions must not be replayed as a system message"
        );
    }
}

#[test]
fn a_responses_stream_emits_named_frames_and_no_done_sentinel() {
    let upstream = FakeUpstream::start(CannedResponse::named_event_stream(&[
        (
            "response.created",
            r#"{"type":"response.created","response":{"id":"resp_up1","object":"response","status":"in_progress","model":"test-model","output":[]}}"#,
        ),
        (
            "response.output_item.added",
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[]}}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"Back"}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"pressure"}"#,
        ),
        (
            "response.output_text.done",
            r#"{"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"Backpressure"}"#,
        ),
        (
            "response.completed",
            r#"{"type":"response.completed","response":{"id":"resp_up1","object":"response","status":"completed","model":"test-model","output":[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Backpressure","annotations":[]}]}],"usage":{"input_tokens":7,"output_tokens":2,"total_tokens":9}}}"#,
        ),
    ]));
    let router = router_with_config(&upstream, &responses_config(upstream.address.port()));
    let harness = Harness::start(upstream, router);

    let body = r#"{"model":"test-alias","input":"x","stream":true}"#;
    let response = harness.request("POST", "/v1/responses", body, true);

    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));

    let events = response.sse_events();
    let names: Vec<&str> = events
        .iter()
        .filter_map(|(name, _)| name.as_deref())
        .collect();

    // Every frame is named, and the name repeats inside the payload.
    assert_eq!(
        names.len(),
        events.len(),
        "every Responses frame carries an `event:` name: {names:?}"
    );
    assert_eq!(names.first(), Some(&"response.created"));
    assert!(names.contains(&"response.output_item.added"));
    assert!(names.contains(&"response.content_part.added"));
    assert!(names.contains(&"response.output_text.delta"));
    assert!(names.contains(&"response.output_text.done"));
    assert!(names.contains(&"response.output_item.done"));
    assert_eq!(names.last(), Some(&"response.completed"));

    // There is no `[DONE]` sentinel in this dialect; a reader that waits for
    // one hangs, and a reader that does not expect one chokes on it.
    for (_, data) in &events {
        assert_ne!(
            data.trim(),
            "[DONE]",
            "the Responses stream must not emit the Chat Completions sentinel"
        );
    }

    // Reassembling the deltas reproduces the completion.
    let mut text = String::new();
    for (name, data) in &events {
        let payload = parse_str(data, &Limits::DEFAULT).expect("frame is JSON");
        assert_eq!(
            payload.field_str("type").unwrap(),
            name.as_deref().unwrap_or_default(),
            "the payload `type` must repeat the event name"
        );
        if name.as_deref() == Some("response.output_text.delta") {
            text.push_str(payload.field_str("delta").unwrap());
        }
    }
    assert_eq!(text, "Backpressure");

    // The terminal frame restates the whole response, with usage.
    let (_, terminal) = events.last().expect("a terminal frame");
    let terminal = parse_str(terminal, &Limits::DEFAULT).expect("terminal is JSON");
    let response_object = terminal.get("response").expect("a response object");
    assert_eq!(response_object.field_str("status").unwrap(), "completed");
    assert_eq!(
        response_object
            .get("usage")
            .unwrap()
            .field_i64("output_tokens")
            .unwrap(),
        2
    );
    let output = response_object.field_array("output").unwrap();
    assert_eq!(
        output[0].field_array("content").unwrap()[0]
            .field_str("text")
            .unwrap(),
        "Backpressure"
    );

    // And the upstream was asked in the same dialect.
    let (line, sent) = upstream_request(&harness);
    assert!(line.starts_with("POST /v1/responses "), "{line}");
    assert!(sent.get("input").is_some());
    assert!(sent.get("messages").is_none());
    assert_eq!(
        sent.get("stream").and_then(wire_json::Value::as_bool),
        Some(true)
    );
}

#[test]
fn a_truncated_responses_stream_terminates_with_response_incomplete() {
    // The terminal frame is not always `response.completed`: a stream that hit
    // the output ceiling ends on `response.incomplete`, and a client watching
    // only for `.completed` must not be told the turn finished cleanly. This is
    // the streaming counterpart of the non-streaming status mapping, and it
    // goes through the same code — which is why getting it wrong breaks both.
    let upstream = FakeUpstream::start(CannedResponse::named_event_stream(&[
        (
            "response.created",
            r#"{"type":"response.created","response":{"id":"resp_up7","object":"response","status":"in_progress","model":"test-model","output":[]}}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"Backpr"}"#,
        ),
        (
            "response.incomplete",
            r#"{"type":"response.incomplete","response":{"id":"resp_up7","object":"response","status":"incomplete","model":"test-model","output":[],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":4,"output_tokens":2,"total_tokens":6}}}"#,
        ),
    ]));
    let router = router_with_config(&upstream, &responses_config(upstream.address.port()));
    let harness = Harness::start(upstream, router);

    let body = r#"{"model":"test-alias","input":"x","stream":true,"max_output_tokens":2}"#;
    let response = harness.request("POST", "/v1/responses", body, true);
    assert_eq!(response.status, 200, "{}", response.body);

    let events = response.sse_events();
    let (name, data) = events.last().expect("a terminal frame");
    assert_eq!(
        name.as_deref(),
        Some("response.incomplete"),
        "a truncated stream must not end on `response.completed`: {:?}",
        events.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    let terminal = parse_str(data, &Limits::DEFAULT).expect("terminal is JSON");
    let object = terminal.get("response").expect("a response object");
    assert_eq!(object.field_str("status").unwrap(), "incomplete");
    assert_eq!(
        object
            .get("incomplete_details")
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str()),
        Some("max_output_tokens")
    );
    // The partial text still arrived, and no `[DONE]` followed the terminal.
    let text: String = events
        .iter()
        .filter(|(n, _)| n.as_deref() == Some("response.output_text.delta"))
        .filter_map(|(_, d)| parse_str(d, &Limits::DEFAULT).ok())
        .filter_map(|v| v.field_str("delta").ok().map(str::to_owned))
        .collect();
    assert_eq!(text, "Backpr");
    for (_, data) in &events {
        assert_ne!(data.trim(), "[DONE]");
    }
}

#[test]
fn a_responses_tool_call_round_trips_with_its_identity_intact() {
    // The adapter decodes provider output into canonical events and the client
    // renderer turns canonical events back into caller output. A tool call is
    // where the two sides most easily disagree, because its identity lives in
    // three places — `call_id`, `name`, and the raw `arguments` text — and each
    // is carried by a different canonical field.
    let harness = responses_harness(CannedResponse::json(
        200,
        r#"{"id":"resp_up2","object":"response","status":"completed","model":"test-model","output":[{"type":"function_call","id":"fc_up","call_id":"call_42","name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}],"usage":{"input_tokens":8,"output_tokens":4,"total_tokens":12}}"#,
    ));

    let body = r#"{"model":"test-alias","input":"weather?","tools":[{"type":"function","name":"get_weather","description":"looks up weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}],"tool_choice":"auto"}"#;
    let response = harness.request("POST", "/v1/responses", body, true);
    assert_eq!(response.status, 200, "{}", response.body);

    // The tool definition reached the upstream flat, not nested under
    // `function` the way Chat Completions nests it.
    let (_, sent) = upstream_request(&harness);
    let tools = sent.field_array("tools").unwrap();
    assert_eq!(tools[0].field_str("type").unwrap(), "function");
    assert_eq!(tools[0].field_str("name").unwrap(), "get_weather");
    assert!(
        tools[0].get("function").is_none(),
        "a Responses tool is flat, not nested under `function`"
    );
    assert_eq!(sent.field_str("tool_choice").unwrap(), "auto");

    // And came back as a typed `function_call` item with the same identity.
    let json = response.json();
    let output = json.field_array("output").unwrap();
    let call = output
        .iter()
        .find(|item| item.field_str("type").unwrap_or_default() == "function_call")
        .expect("a function_call output item");
    assert_eq!(call.field_str("call_id").unwrap(), "call_42");
    assert_eq!(call.field_str("name").unwrap(), "get_weather");
    // Specification 14: the argument text the model produced, not a re-encoded
    // value tree.
    assert_eq!(call.field_str("arguments").unwrap(), r#"{"city":"Oslo"}"#);
    assert!(json.get("choices").is_none());
}

#[test]
fn a_truncated_responses_generation_is_reported_as_incomplete_not_completed() {
    // There is no `finish_reason` here: completion is a `status`, and the
    // truncation reason is `incomplete_details.reason`. Reporting `completed`
    // for a generation that hit the output ceiling tells the caller the model
    // was finished when it was cut off.
    let harness = responses_harness(CannedResponse::json(
        200,
        r#"{"id":"resp_up3","object":"response","status":"incomplete","model":"test-model","output":[{"type":"message","id":"msg_1","status":"incomplete","role":"assistant","content":[{"type":"output_text","text":"Backpr","annotations":[]}]}],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":4,"output_tokens":2,"total_tokens":6}}"#,
    ));
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);

    let json = response.json();
    assert_eq!(
        json.field_str("status").unwrap(),
        "incomplete",
        "a length-truncated generation is not a completed one"
    );
    assert_eq!(
        json.get("incomplete_details")
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str()),
        Some("max_output_tokens")
    );
    // The partial text still reaches the caller.
    assert_eq!(
        json.field_array("output").unwrap()[0]
            .field_array("content")
            .unwrap()[0]
            .field_str("text")
            .unwrap(),
        "Backpr"
    );
}

#[test]
fn an_unrecognised_responses_status_is_never_reported_as_a_clean_stop() {
    // A status this router does not know is not a completion. Mapping it to
    // `Stop` would tell the caller the model finished naturally when the router
    // has no idea whether it did.
    let harness = responses_harness(CannedResponse::json(
        200,
        r#"{"id":"resp_up4","object":"response","status":"queued_for_moderation","model":"test-model","output":[{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[{"type":"output_text","text":"partial","annotations":[]}]}],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}"#,
    ));
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);

    let json = response.json();
    assert_ne!(
        json.field_str("status").unwrap(),
        "completed",
        "an unrecognised upstream status must not be laundered into a clean completion"
    );
    // `incomplete` is the honest spelling: the router knows the turn did not
    // complete and does not know why.
    assert_eq!(json.field_str("status").unwrap(), "incomplete");
    assert!(
        json.get("incomplete_details").is_none_or(wire_json::Value::is_null),
        "no reason may be invented for a status the router could not read: {}",
        response.body
    );

    // The content produced before the unknown status still reaches the caller;
    // being honest about the status must not cost the caller their output.
    assert_eq!(
        json.field_array("output").unwrap()[0]
            .field_array("content")
            .unwrap()[0]
            .field_str("text")
            .unwrap(),
        "partial"
    );
}

#[test]
fn a_recognised_responses_completion_is_still_reported_as_completed() {
    // The control for the test above. A status mapping that reports every
    // response as `incomplete` is not an honest mapping, it is a broken one.
    let harness = responses_harness(responses_completion());
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.json().field_str("status").unwrap(), "completed");
}

#[test]
fn a_responses_turn_waiting_on_a_tool_result_is_still_a_completed_response() {
    // `completed` is correct here — the response is finished and the
    // outstanding work is visible as a `function_call` item — even though the
    // Chat dialect calls the same turn `tool_calls`. The two must not be
    // conflated in either direction.
    let harness = responses_harness(CannedResponse::json(
        200,
        r#"{"id":"resp_up6","object":"response","status":"completed","model":"test-model","output":[{"type":"function_call","id":"fc_1","call_id":"call_9","name":"f","arguments":"{}"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#,
    ));
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("status").unwrap(), "completed");
    assert_eq!(
        json.field_array("output").unwrap()[0]
            .field_str("type")
            .unwrap(),
        "function_call"
    );
}

#[test]
fn a_provider_error_on_the_responses_path_never_reaches_the_caller() {
    // Specification 8.2, as the Chat path already guarantees.
    let upstream = FakeUpstream::start(CannedResponse::json(
        400,
        r#"{"error":{"message":"the prompt 'CONFIDENTIAL' was rejected by host db-7.internal","type":"invalid_request_error"}}"#,
    ));
    let router = router_with_config(&upstream, &responses_config(upstream.address.port()));
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(response.status, 400, "{}", response.body);
    assert!(!response.body.contains("CONFIDENTIAL"), "{}", response.body);
    assert!(!response.body.contains("db-7.internal"), "{}", response.body);
}

#[test]
fn a_failed_responses_generation_does_not_leak_its_provider_message() {
    // A transport 200 carrying `status: "failed"` is the other error path: the
    // body is a success as far as HTTP is concerned, so the redaction has to
    // happen in the decoder rather than in the status mapping.
    let harness = responses_harness(CannedResponse::json(
        200,
        r#"{"id":"resp_up5","object":"response","status":"failed","model":"test-model","output":[],"error":{"code":"server_error","message":"backend node db-7.internal refused the prompt 'CONFIDENTIAL'"}}"#,
    ));
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);

    assert_ne!(response.status, 200, "a failed generation is not a success");
    assert!(!response.body.contains("CONFIDENTIAL"), "{}", response.body);
    assert!(!response.body.contains("db-7.internal"), "{}", response.body);
}

#[test]
fn the_chat_and_responses_dialects_are_not_merged() {
    // The same router, the same alias, the same upstream — two callers, two
    // shapes. A refactor that unified the two renderers would break exactly
    // this and nothing else.
    let upstream = FakeUpstream::start_sequence(vec![
        chat_completion_response(),
        responses_completion(),
    ]);
    let router = router_with_config(&upstream, &responses_config(upstream.address.port()));
    let harness = Harness::start(upstream, router);

    let chat = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(chat.status, 200, "{}", chat.body);
    let chat_json = chat.json();
    assert_eq!(chat_json.field_str("object").unwrap(), "chat.completion");
    assert!(
        chat_json.get("output").is_none(),
        "a Chat Completions body must not carry a Responses `output` array"
    );
    assert_eq!(
        chat_json.field_array("choices").unwrap()[0]
            .field_str("finish_reason")
            .unwrap(),
        "stop"
    );
    let (chat_line, chat_sent) = upstream_request(&harness);
    assert!(chat_line.starts_with("POST /v1/chat/completions "), "{chat_line}");
    assert!(chat_sent.get("messages").is_some());
    assert!(chat_sent.get("input").is_none());

    let responses = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);
    assert_eq!(responses.status, 200, "{}", responses.body);
    let responses_json = responses.json();
    assert_eq!(responses_json.field_str("object").unwrap(), "response");
    assert!(responses_json.get("choices").is_none());
    assert!(responses_json.field_array("output").is_ok());
    let (responses_line, responses_sent) = upstream_request(&harness);
    assert!(responses_line.starts_with("POST /v1/responses "), "{responses_line}");
    assert!(responses_sent.get("input").is_some());
    assert!(responses_sent.get("messages").is_none());
}

#[test]
fn a_target_that_does_not_declare_responses_does_not_serve_it_as_chat() {
    // `operations` is an eligibility filter. A target declaring only `chat`
    // must be excluded from a Responses request, not silently downgraded to
    // the dialect it does speak.
    let harness = Harness::default(chat_completion_response());
    let response = harness.request("POST", "/v1/responses", RESPONSES_BODY, true);

    assert_ne!(
        response.status, 200,
        "a chat-only target must not serve a Responses request: {}",
        response.body
    );
    assert_eq!(
        harness.upstream.served(),
        0,
        "no upstream call may be made for an operation no target supports"
    );
}

// -- Embeddings -------------------------------------------------------------

#[test]
fn an_embeddings_request_round_trips() {
    let upstream = FakeUpstream::start(CannedResponse::json(
        200,
        r#"{"model":"test-model","data":[{"index":0,"embedding":[0.1,0.2]},{"index":1,"embedding":[0.3,0.4]}],"usage":{"prompt_tokens":4,"completion_tokens":0}}"#,
    ));
    let router = router_for(&upstream);
    let harness = Harness::start(upstream, router);

    let response = harness.request(
        "POST",
        "/v1/embeddings",
        r#"{"model":"test-alias","input":["a","b"]}"#,
        true,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    let json = response.json();
    assert_eq!(json.field_str("object").unwrap(), "list");
    let data = json.field_array("data").unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0].field_array("embedding").unwrap().len(), 2);
}

// -- Keep-alive and transport ----------------------------------------------

#[test]
fn several_requests_share_one_connection() {
    let harness = Harness::default(chat_completion_response());
    let mut stream = TcpStream::connect(harness.address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");

    for _ in 0..3 {
        let request = format!(
            "GET /health/live HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {}\r\n\r\n",
            harness.router.api_key
        );
        stream.write_all(request.as_bytes()).expect("write");

        let mut raw = Vec::new();
        let mut chunk = [0u8; 512];
        let head_end = loop {
            if let Some(position) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break position + 4;
            }
            let n = stream.read(&mut chunk).expect("read");
            assert!(n > 0, "the connection closed unexpectedly");
            raw.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while raw.len() < head_end + length {
            let n = stream.read(&mut chunk).expect("read body");
            assert!(n > 0);
            raw.extend_from_slice(&chunk[..n]);
        }
    }
}

// -- Connection reuse -------------------------------------------------------

#[test]
fn an_upstream_that_closed_a_pooled_connection_does_not_fail_the_next_request() {
    // A connection returned to the pool can be closed by the peer at any moment
    // while it is idle, and nothing observes that until the next exchange is
    // attempted. The failure says nothing about the upstream — the request was
    // never delivered — so it must be retried once on a fresh socket rather
    // than surfaced.
    //
    // The fake upstream serves one request per connection and then closes,
    // while advertising a persistent connection by sending `Content-Length`
    // without `Connection: close`. That is exactly the shape of the race, and
    // before the retry the *second* request through any harness returned 502
    // `upstream_invalid_response` — naming an upstream that was never reached.
    let upstream = FakeUpstream::start(chat_completion_response());
    let router = router_for(&upstream);
    let harness = Harness::start(upstream, router);

    for attempt in 1..=3 {
        let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
        assert_eq!(response.status, 200, "request {attempt}: {}", response.body);
        assert_eq!(
            response.json().field_array("choices").unwrap()[0]
                .get("message")
                .unwrap()
                .field_str("content")
                .unwrap(),
            "Backpressure is flow control.",
            "request {attempt} must carry the completion, not an empty success"
        );
    }
}

#[test]
fn a_live_connection_that_answers_and_then_fails_is_never_replayed() {
    // The other half of the retry above, and the one that makes it safe.
    //
    // Retrying because a socket came from the pool is not enough: a *live*
    // pooled connection can also fail while reading the head — a timeout, a
    // partial head, a truncated one — and in that case the provider may well
    // have read the request and started work. Replaying a non-idempotent POST
    // there runs the inference twice and bills it twice. Specification 6.5
    // permits a retry after acceptance only for idempotent requests.
    //
    // This upstream keeps the connection alive across both requests, so the
    // second one lands on a socket that is genuinely open, and answers it with
    // a partial head before closing. If the retry fired, a third request would
    // arrive on a fresh connection.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = std::sync::Arc::clone(&seen);

    let upstream_thread = std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buffer = [0u8; 64 * 1024];

        // First exchange: a complete response, connection left open, so the
        // router pools the socket.
        if socket.read(&mut buffer).is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = r#"{"id":"c1","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"one"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes());
            let _ = socket.write_all(body.as_bytes());
            let _ = socket.flush();
        }

        // Second exchange on the same live socket: a partial head, then close.
        // The provider has read the request; it simply failed to finish
        // answering.
        if socket.read(&mut buffer).is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Ty");
            let _ = socket.flush();
        }
        drop(socket);

        // Anything after this is the replay the test forbids. Accept it so the
        // count is observable rather than hanging the router.
        let _ = listener.set_nonblocking(true);
        for _ in 0..40 {
            if let Ok((mut extra, _)) = listener.accept() {
                let _ = extra.set_read_timeout(Some(Duration::from_millis(200)));
                if extra.read(&mut buffer).is_ok() {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    });

    let harness = Harness::start(
        FakeUpstream::start(chat_completion_response()),
        router_with_config_text(&default_config_text(port)),
    );

    let first = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_eq!(first.status, 200, "{}", first.body);
    let second = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_ne!(
        second.status, 200,
        "a truncated head must be reported, not papered over: {}",
        second.body
    );

    drop(harness);
    let _ = upstream_thread.join();
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the request was replayed to a provider that had already read it"
    );
}

#[test]
fn a_genuinely_unreachable_upstream_is_still_reported_as_a_failure() {
    // The control for the retry above: it must not turn a real connection
    // failure into an infinite loop or a false success. The provider points at
    // a port nothing is listening on, so no connection can ever be established
    // and there is no pooled socket to blame.
    let upstream = FakeUpstream::start(chat_completion_response());
    let dead_port = {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = socket.local_addr().expect("addr").port();
        drop(socket);
        port
    };
    let config = hypellm_router::testing::default_config_text(dead_port);
    let router = router_with_config(&upstream, &config);
    let harness = Harness::start(upstream, router);

    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);
    assert_ne!(response.status, 200, "{}", response.body);
    assert_eq!(harness.upstream.served(), 0);
}

// -- Fleet orchestration, end to end -----------------------------------------
//
// The goal the whole feature exists for, asserted at the outermost boundary: a
// request arrives on the inference listener, the model it needs is not running,
// the router starts it, and the caller gets an answer. Everything in between —
// the plan, the lease, the agent verbs, the readiness confirmation — is
// exercised by the real code on a real socket.

fn fleet_config_text(port: u16, socket: &str) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=60000 retry_budget_ms=60000 \\
         max_attempts=3 fleet_enabled=true
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true \\
       operations=chat,embeddings streaming=true tools=true json_mode=true \\
       capabilities=chat context=100000 max_output=8192 concurrency=8
alias id=test-alias capability=chat targets=local:model description=\"the test model\"
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
fleet_agent id=local socket=\"{socket}\" observation_interval_ms=1000 \\
    observation_max_age_ms=600000 request_timeout_ms=5000
host id=h1 agent=local arch=x86_64 reserved_memory_bytes=0 max_concurrent_activations=1
accelerator host=h1 id=gpu0 kind=cuda memory_bytes=17179869184
deployment id=d-model target=local:model accelerator=gpu0 memory_bytes=8589934592 \\
    start_ms=1000 stop_ms=500 drain_ms=500 probe_ms=500 min_resident_ms=0 \\
    autostart=true readiness=http_ok
"
    )
}

fn fleet_socket(name: &str) -> String {
    format!("/tmp/hypellm-e2e-{name}-{}.sock", std::process::id())
}

const FLEET_KEY: &[u8] = b"an-end-to-end-fleet-key-0123456789";

#[test]
fn a_request_for_a_cold_model_starts_it_and_is_then_served() {
    let socket = fleet_socket("cold");
    let upstream = FakeUpstream::start(chat_completion_response());
    let router = router_with_config_text(&fleet_config_text(upstream.address.port(), &socket));

    // The agent admits the one declared deployment and reports it stopped until
    // the router asks for it.
    let digest = router.state.config().fleet.digest();
    let mut agent = hypellm_net::fleet_sim::SimulatedAgent::start(
        &socket,
        hypellm_net::fleet_sim::AgentScript::empty(digest, FLEET_KEY)
            .with_deployment("d-model", hypellm_net::fleet_sim::Behaviour::ReadyAfter(1))
            .with_state("d-model", "stopped"),
    );
    hypellm_router::testing::attach_fleet(&router, FLEET_KEY);

    let harness = Harness::start(upstream, router);
    let response = harness.request("POST", "/v1/chat/completions", CHAT_BODY, true);

    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(response.body.contains("chat.completion"));

    let verbs = agent.verbs();
    assert!(
        verbs.iter().any(|v| v.starts_with("ACTIVATE d-model ")),
        "the request must have started the model: {verbs:?}"
    );
    assert_eq!(agent.state_of("d-model").as_deref(), Some("ready"));
    assert_eq!(
        harness.upstream.served(),
        1,
        "and the model must then actually have served it"
    );
    agent.stop();
}

#[test]
fn a_second_request_does_not_start_an_already_running_model_again() {
    // The activation must be paid for once. A second request finding the model
    // resident is the ordinary warm path, and it must not touch the agent at
    // all beyond observation.
    let socket = fleet_socket("warm");
    let upstream = FakeUpstream::start_sequence(vec![
        chat_completion_response(),
        chat_completion_response(),
    ]);
    let router = router_with_config_text(&fleet_config_text(upstream.address.port(), &socket));
    let digest = router.state.config().fleet.digest();
    let mut agent = hypellm_net::fleet_sim::SimulatedAgent::start(
        &socket,
        hypellm_net::fleet_sim::AgentScript::empty(digest, FLEET_KEY)
            .with_deployment("d-model", hypellm_net::fleet_sim::Behaviour::ReadyAfter(1))
            .with_state("d-model", "stopped"),
    );
    hypellm_router::testing::attach_fleet(&router, FLEET_KEY);

    let harness = Harness::start(upstream, router);
    assert_eq!(
        harness
            .request("POST", "/v1/chat/completions", CHAT_BODY, true)
            .status,
        200
    );
    assert_eq!(
        harness
            .request("POST", "/v1/chat/completions", CHAT_BODY, true)
            .status,
        200
    );

    let activations = agent
        .verbs()
        .iter()
        .filter(|v| v.starts_with("ACTIVATE "))
        .count();
    assert_eq!(activations, 1, "one swap, two requests");
    assert_eq!(harness.upstream.served(), 2);
    agent.stop();
}

#[test]
fn a_key_without_the_fleet_permission_cannot_cause_an_activation() {
    // The security property, at the outermost boundary. The model is declared,
    // the deployment is `autostart`, the agent is ready — and an ordinary
    // inference key still cannot make the fleet do work.
    let socket = fleet_socket("unpriv");
    let upstream = FakeUpstream::start(chat_completion_response());
    let router = router_with_config_text(&fleet_config_text(upstream.address.port(), &socket));
    let digest = router.state.config().fleet.digest();
    let mut agent = hypellm_net::fleet_sim::SimulatedAgent::start(
        &socket,
        hypellm_net::fleet_sim::AgentScript::empty(digest, FLEET_KEY)
            .with_deployment("d-model", hypellm_net::fleet_sim::Behaviour::ReadyAfter(1))
            .with_state("d-model", "stopped"),
    );
    hypellm_router::testing::attach_fleet(&router, FLEET_KEY);

    // A second key with inference scope and no roles at all.
    let plain = router
        .state
        .keys
        .create(
            hypellm_core::ids::TenantId::new("acme").expect("tenant"),
            hypellm_core::ids::PrincipalId::new("svc:plain").expect("principal"),
            vec![hypellm_auth::Scope::Inference],
            Vec::new(),
            None,
            hypellm_auth::SourceRestriction::Any,
            Some("a key with no fleet permission".to_owned()),
            router.state.clock.wall_millis(),
        )
        .expect("create key")
        .into_secret();

    let harness = Harness::start(upstream, router);
    let raw = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: router.test\r\n\
         Content-Type: application/json\r\nConnection: close\r\n\
         Authorization: Bearer {plain}\r\nContent-Length: {}\r\n\r\n{CHAT_BODY}",
        CHAT_BODY.len()
    );
    let response = harness.raw(&raw);

    assert_eq!(
        response.status, 503,
        "the model is not running and this caller may not start it: {}",
        response.body
    );
    // And nothing about the fleet reaches the caller.
    for leak in ["h1", "gpu0", "d-model", "activation", "evict"] {
        assert!(
            !response.body.contains(leak),
            "a data-plane error disclosed {leak}: {}",
            response.body
        );
    }
    assert!(
        !agent.verbs().iter().any(|v| v.starts_with("ACTIVATE")),
        "an unauthorized caller must not reach the agent: {:?}",
        agent.verbs()
    );
    agent.stop();
}
