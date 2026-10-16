//! What the usage views report is what the data plane actually did.
//!
//! The management view reads `UsageAggregate::window`; these tests drive real
//! requests through the inference listener and hold the aggregate to them, so
//! a recording seam that dropped the key, miscounted a refusal or mispriced a
//! token would show here rather than on an operator's screen.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use hypellm_core::ids::{KeyId, PrincipalId, TenantId};
use hypellm_core::time::Clock;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
}

impl Harness {
    fn start(router: TestRouter) -> Self {
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
        }
    }

    fn chat(&self, model: &str) -> u16 {
        let body = format!(r#"{{"model":"{model}","messages":[{{"role":"user","content":"x"}}]}}"#);
        let mut stream = TcpStream::connect(self.address).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        let raw = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
             Connection: close\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{body}",
            self.router.api_key,
            body.len()
        );
        stream.write_all(raw.as_bytes()).expect("write");
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).expect("status line");
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest);
        status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    fn key_id(&self) -> KeyId {
        KeyId::new(self.router.api_key.split('_').nth(1).expect("key id")).expect("key id")
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

/// One prompt token and three completion tokens, as the provider reports them.
fn reported() -> CannedResponse {
    CannedResponse::json(
        200,
        r#"{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":3,"total_tokens":4}}"#,
    )
}

/// One alias granted, one not. Output is priced at three times input and the
/// cache at nothing, so a charge that confused output with cached input reads
/// a different number.
fn config(port: u16) -> String {
    format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=1
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 concurrency=8
alias id=agent targets=local:model
alias id=hidden targets=local:model
grant scope=tenant:acme model=agent allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
price target=local:model input_per_million=1000000 output_per_million=3000000 \\
      cached_input_per_million=0 currency=USD
quota scope=principal:svc:test budget=1000000 budget_period=daily
"
    )
}

#[test]
fn the_window_view_reports_the_requests_the_key_actually_made() {
    let upstream = FakeUpstream::start(reported());
    let harness = Harness::start(router_with_config(&upstream, &config(upstream.address.port())));

    for _ in 0..3 {
        assert_eq!(harness.chat("agent"), 200);
    }
    // Refused before routing: an alias the principal has no grant for.
    assert_eq!(harness.chat("hidden"), 404);

    let state = &harness.router.state;
    let tenant = TenantId::new("acme").unwrap();
    let principal = PrincipalId::new("svc:test").unwrap();
    let now = state.clock.wall_millis();
    let window = state.usage.window(&tenant, Some(&principal), now - 3_600_000);

    assert_eq!(window.rows.len(), 1, "{:?}", window.rows);
    let row = &window.rows[0];
    assert_eq!(row.principal.as_ref(), Some(&principal));
    assert_eq!(row.key.as_ref(), Some(&harness.key_id()), "usage must carry the key that made it");
    assert_eq!(row.totals.requests, 4);
    assert_eq!(row.totals.input_tokens, 3);
    assert_eq!(row.totals.output_tokens, 9);
    assert_eq!(row.totals.failed_requests, 1, "the refused request is counted as failed");
    assert_eq!(row.totals.throttled_requests, 0);
    assert_eq!(upstream.served(), 3);

    // Another tenant reads nothing of it.
    let other = TenantId::new("globex").unwrap();
    assert!(state.usage.window(&other, None, now - 3_600_000).rows.is_empty());
}

#[test]
fn spend_is_charged_at_the_output_rate_for_output_tokens() {
    // `cost_minor_units` takes (input, output, cached_input). Three requests
    // of one input and three output tokens at 1 and 3 per token are 30 minor
    // units; with output and cached input swapped they would be 3.
    let upstream = FakeUpstream::start(reported());
    let harness = Harness::start(router_with_config(&upstream, &config(upstream.address.port())));
    for _ in 0..3 {
        assert_eq!(harness.chat("agent"), 200);
    }
    let state = &harness.router.state;
    let scope = state
        .admission
        .configured_principal_scope(&PrincipalId::new("svc:test").unwrap())
        .expect("the principal's quota is configured");
    assert_eq!(scope.spent_this_period(state.clock.now_millis()), 30);
}
