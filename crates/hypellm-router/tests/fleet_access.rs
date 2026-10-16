//! Fleet grants on the data path: a caller kept off a slave is not served by
//! it, is not told it exists, and is still served by the slaves they may use.
//!
//! Two slaves, both answered by one fake provider so the test can tell which
//! one was chosen from the model name the router sent. The slave the caller is
//! kept off is the local, cheap one that scoring prefers — a filter that only
//! held when it agreed with the score would pass a weaker fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::ids::{PrincipalId, TenantId};
use hypellm_core::time::Clock;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn config(port: u16, grants: &str) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=spark family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
provider id=gpu2 family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=spark:qwen provider=spark model=model-on-spark local=true cost=0 \\
       operations=chat context=100000 max_output=8192 concurrency=8
target id=gpu2:qwen provider=gpu2 model=model-on-gpu2 local=true cost=5 \\
       operations=chat context=100000 max_output=8192 concurrency=8
alias id=coder targets=spark:qwen,gpu2:qwen
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
fleet_agent id=local socket=\"/run/hypellm/fleet.sock\"
host id=spark agent=local arch=aarch64
host id=gpu2 agent=local arch=x86_64
accelerator id=spark-gpu0 host=spark kind=cuda memory_bytes=100000000000
accelerator id=gpu2-gpu0 host=gpu2 kind=cuda memory_bytes=100000000000
deployment id=d-spark target=spark:qwen accelerator=spark-gpu0 memory_bytes=1000
deployment id=d-gpu2 target=gpu2:qwen accelerator=gpu2-gpu0 memory_bytes=1000
{grants}
"
    )
}

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    router: TestRouter,
    upstream: FakeUpstream,
    /// A second credential, for a principal no grant mentions.
    other_key: String,
}

impl Harness {
    fn start(grants: &str) -> Self {
        let upstream = FakeUpstream::start(CannedResponse::json(
            200,
            r#"{"id":"c1","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#,
        ));
        let router = router_with_config(&upstream, &config(upstream.address.port(), grants));
        let other_key = router
            .state
            .keys
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:other").unwrap(),
                vec![hypellm_auth::Scope::Inference, hypellm_auth::Scope::Models],
                None,
                hypellm_auth::SourceRestriction::Any,
                None,
                router.state.clock.wall_millis(),
            )
            .unwrap()
            .into_secret();
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).unwrap();
        let address = server.local_addr().unwrap();
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
            other_key,
        }
    }

    fn send(&self, key: &str, method: &str, path: &str, body: &str) -> (u16, String) {
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
             Connection: close\r\nAuthorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut text = String::new();
        let _ = stream.read_to_string(&mut text);
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    fn chat(&self, key: &str) -> (u16, String) {
        self.send(
            key,
            "POST",
            "/v1/chat/completions",
            r#"{"model":"coder","messages":[{"role":"user","content":"hi"}]}"#,
        )
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

#[test]
fn a_caller_kept_off_the_preferred_slave_is_served_by_one_they_may_use() {
    let harness = Harness::start(
        "fleet_grant id=off-spark scope=principal:svc:test host=spark model=* allow=false",
    );
    let key = harness.router.api_key.clone();
    let (status, body) = harness.chat(&key);
    assert_eq!(status, 200, "{body}");
    let sent = harness.upstream.last_body().unwrap_or_default();
    assert!(sent.contains("model-on-gpu2"), "routed to the denied slave: {sent}");

    // Everyone else still gets the slave scoring prefers.
    let (status, _) = harness.chat(&harness.other_key);
    assert_eq!(status, 200);
    let sent = harness.upstream.last_body().unwrap_or_default();
    assert!(sent.contains("model-on-spark"), "{sent}");
}

#[test]
fn a_caller_kept_off_every_slave_is_told_the_model_does_not_exist() {
    let harness = Harness::start(
        "fleet_grant id=off scope=principal:svc:test host=* model=* allow=false",
    );
    let key = harness.router.api_key.clone();
    let served_before = harness.upstream.served();
    let (status, body) = harness.chat(&key);
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("model_not_found"), "{body}");
    // Nothing names a machine: a data-plane caller learns no topology.
    for host in ["spark", "gpu2"] {
        assert!(!body.contains(host), "the error named {host}: {body}");
    }
    assert_eq!(harness.upstream.served(), served_before, "the provider was called");

    // And `/v1/models` agrees with the error: the alias is not listed.
    let (_, models) = harness.send(&key, "GET", "/v1/models", "");
    assert!(!models.contains("\"coder\""), "{models}");
    let (_, models) = harness.send(&harness.other_key, "GET", "/v1/models", "");
    assert!(models.contains("\"coder\""), "{models}");
}

#[test]
fn under_a_deny_default_an_explicit_grant_is_the_only_way_in() {
    let harness = Harness::start(
        "fleet_grant id=svc-test-gpu2 scope=principal:svc:test host=gpu2 model=target:gpu2:qwen allow=true",
    );
    // Flip the default by publishing a configuration that says so, as the
    // dashboard would.
    let text = config(harness.upstream.address.port(), "")
        .replace("max_attempts=3", "max_attempts=3 fleet_access_default=deny")
        + "fleet_grant id=svc-test-gpu2 scope=principal:svc:test host=gpu2 model=target:gpu2:qwen allow=true\n";
    let next = hypellm_config::load(&text, 2).expect("builds");
    harness.router.state.config.activate(next);

    let key = harness.router.api_key.clone();
    let (status, body) = harness.chat(&key);
    assert_eq!(status, 200, "{body}");
    assert!(harness.upstream.last_body().unwrap_or_default().contains("model-on-gpu2"));

    // A principal with no grant is now kept off every slave.
    let (status, body) = harness.chat(&harness.other_key);
    assert_eq!(status, 404, "{body}");
}
