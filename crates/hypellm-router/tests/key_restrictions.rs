//! Per-key restrictions on the inference listener.
//!
//! A key narrows what its principal may use and can never widen it. These
//! tests hold the data plane to that: a restricted alias answers exactly as an
//! ungranted one, a restricted target is never dialled however well it ranks,
//! and a key's priority class lowers its principal's but never raises it.
//!
//! The restriction is written straight into the key store here; the
//! management endpoint that writes it is tested in `hypellm-admin-api`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use hypellm_core::admission::PriorityClass;
use hypellm_core::ids::{AliasId, KeyId, TargetId};
use hypellm_core::key_restriction::KeyRestriction;
use hypellm_core::time::Clock;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_with_config};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use wire_json::{Limits, parse_str};

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

    /// The test key's record identifier: `hypellmk_<id>_<secret>`.
    fn key_id(&self) -> KeyId {
        key_id_of(&self.router.api_key)
    }

    fn restrict(&self, restriction: KeyRestriction) {
        assert!(self.router.state.keys.set_restrictions(&self.key_id(), restriction));
    }

    fn request(&self, method: &str, path: &str, body: &str) -> Response {
        send(self.address, &self.router.api_key, method, path, body)
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

fn key_id_of(secret: &str) -> KeyId {
    KeyId::new(secret.split('_').nth(1).expect("key id")).expect("key id")
}

struct Response {
    status: u16,
    body: String,
}

impl Response {
    fn json(&self) -> wire_json::Value {
        parse_str(&self.body, &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }

    /// The error object with its per-request identifier removed, so two
    /// refusals can be compared byte for byte.
    fn error_shape(&self) -> String {
        let json = self.json();
        let error = json.get("error").expect("an error object");
        let mut fields: Vec<String> = error
            .as_object()
            .expect("object")
            .iter()
            .filter(|(name, _)| *name != "request_id")
            .map(|(name, value)| format!("{name}={}", wire_json::to_string(value)))
            .collect();
        fields.sort();
        fields.join(";")
    }
}

fn send(address: SocketAddr, key: &str, method: &str, path: &str, body: &str) -> Response {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
         Connection: close\r\nAuthorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(raw.as_bytes()).expect("write");
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status line");
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
    let mut body = String::new();
    let _ = reader.read_to_string(&mut body);
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Response { status, body }
}

fn ok_response(content: &str) -> CannedResponse {
    CannedResponse::json(
        200,
        &format!(
            r#"{{"id":"c","model":"m","choices":[{{"index":0,"message":{{"role":"assistant","content":"{content}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
        ),
    )
}

fn chat(model: &str, content: &str) -> String {
    format!(r#"{{"model":"{model}","messages":[{{"role":"user","content":"{content}"}}]}}"#)
}

fn alias(s: &str) -> AliasId {
    AliasId::new(s).unwrap()
}

/// Three aliases on one upstream. `agent` and `chat` are granted to the
/// tenant; `hidden` is granted to nobody, which is what a restricted alias
/// must be indistinguishable from.
fn three_aliases(port: u16) -> String {
    format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192
alias id=agent targets=local:model
alias id=chat targets=local:model
alias id=hidden targets=local:model
grant scope=tenant:acme model=agent allow=true
grant scope=tenant:acme model=chat allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
"
    )
}

#[test]
fn a_restricted_alias_is_refused_exactly_as_an_ungranted_one_and_is_not_listed() {
    let upstream = FakeUpstream::start(ok_response("served"));
    let harness = Harness::start(router_with_config(
        &upstream,
        &three_aliases(upstream.address.port()),
    ));

    // Before: the principal's ceiling lets the key use both granted aliases.
    assert_eq!(harness.request("POST", "/v1/chat/completions", &chat("chat", "x")).status, 200);

    harness.restrict(KeyRestriction {
        models: Some([alias("agent")].into_iter().collect()),
        ..KeyRestriction::default()
    });
    let served_before = upstream.served();

    let restricted = harness.request("POST", "/v1/chat/completions", &chat("chat", "x"));
    let ungranted = harness.request("POST", "/v1/chat/completions", &chat("hidden", "x"));
    assert_eq!(restricted.status, ungranted.status, "{}", restricted.body);
    assert_eq!(
        restricted.error_shape(),
        ungranted.error_shape(),
        "a restricted alias must not be distinguishable from one the principal has no grant for"
    );
    assert_eq!(restricted.status, 404, "{}", restricted.body);
    assert_eq!(upstream.served(), served_before, "a restricted alias reached the provider");

    // The alias it keeps still works.
    assert_eq!(harness.request("POST", "/v1/chat/completions", &chat("agent", "x")).status, 200);

    // And the listing shows what the key can call, not what its principal can.
    let listed = harness.request("GET", "/v1/models", "");
    let ids: Vec<String> = listed
        .json()
        .field_array("data")
        .unwrap()
        .iter()
        .map(|m| m.field_str("id").unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec!["agent".to_owned()]);
}

#[test]
fn a_restriction_cannot_reach_an_alias_its_principal_is_not_granted() {
    // Naming an ungranted alias in the key's list adds nothing: the grant is
    // still required, so the key's set is always a subset.
    let upstream = FakeUpstream::start(ok_response("served"));
    let harness = Harness::start(router_with_config(
        &upstream,
        &three_aliases(upstream.address.port()),
    ));
    harness.restrict(KeyRestriction {
        models: Some([alias("agent"), alias("hidden")].into_iter().collect()),
        ..KeyRestriction::default()
    });
    assert_eq!(harness.request("POST", "/v1/chat/completions", &chat("hidden", "x")).status, 404);
    assert_eq!(upstream.served(), 0);
}

#[test]
fn a_key_limited_to_one_target_is_never_served_by_a_better_ranked_one() {
    // Adversarial: the target the key is kept off is preferred by the binding,
    // local, and cheaper — everything that would make routing pick it.
    let preferred = FakeUpstream::start(ok_response("preferred"));
    let allowed = FakeUpstream::start(ok_response("allowed"));
    let config = format!(
        "\
settings default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
tenant id=acme
provider id=near family=openai scheme=http host=127.0.0.1 port={near} base_path=/v1 egress=local
provider id=far family=openai scheme=http host=127.0.0.1 port={far} base_path=/v1 egress=local
target id=near:model provider=near model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 cost=0
target id=far:model provider=far model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 cost=9
alias id=agent targets=near:model,far:model family_failover=true
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=near:model,far:model
",
        near = preferred.address.port(),
        far = allowed.address.port(),
    );
    let harness = Harness::start(router_with_config(&preferred, &config));

    let open = harness.request("POST", "/v1/chat/completions", &chat("agent", "x"));
    assert_eq!(open.status, 200, "{}", open.body);
    assert_eq!(preferred.served(), 1, "the fixture must prefer the near target");

    harness.restrict(KeyRestriction {
        targets: Some([TargetId::new("far:model").unwrap()].into_iter().collect()),
        ..KeyRestriction::default()
    });
    for _ in 0..3 {
        let response = harness.request("POST", "/v1/chat/completions", &chat("agent", "x"));
        assert_eq!(response.status, 200, "{}", response.body);
    }
    assert_eq!(preferred.served(), 1, "a restricted target was dialled");
    assert_eq!(allowed.served(), 3);

    // Restricted to a target the alias does not have: nothing remains, and it
    // answers as an alias the key cannot see, which is what `/v1/models`
    // now says it is.
    harness.restrict(KeyRestriction {
        targets: Some([TargetId::new("elsewhere:model").unwrap()].into_iter().collect()),
        ..KeyRestriction::default()
    });
    let none = harness.request("POST", "/v1/chat/completions", &chat("agent", "x"));
    assert_eq!(none.status, 404, "{}", none.body);
    assert!(
        harness
            .request("GET", "/v1/models", "")
            .json()
            .field_array("data")
            .unwrap()
            .is_empty()
    );
    assert_eq!(preferred.served() + allowed.served(), 4);
}

#[test]
fn a_batch_key_queues_behind_a_standard_one_from_the_same_principal() {
    // One slot, a queue. The first request holds the slot; a batch-restricted
    // key queues next, then an unrestricted key of the same principal. When
    // the slot frees, the standard request must go first. Without the cap the
    // two queue at the principal's class and FIFO serves the batch one first.
    let upstream = FakeUpstream::start(ok_response("ok").after(Duration::from_millis(300)));
    let port = upstream.address.port();
    let config = format!(
        "\
settings default_deadline_ms=10000 retry_budget_ms=10000 max_attempts=1
tenant id=acme
provider id=local family=openai scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
target id=local:model provider=local model=test-model local=true operations=chat \\
       streaming=true context=100000 max_output=8192 concurrency=1
alias id=agent targets=local:model
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
quota scope=target:local:model concurrency=1 queued=4
"
    );
    let harness = Harness::start(router_with_config(&upstream, &config));

    let standard_key = harness
        .router
        .state
        .keys
        .create(
            hypellm_core::ids::TenantId::new("acme").unwrap(),
            hypellm_core::ids::PrincipalId::new("svc:test").unwrap(),
            vec![hypellm_auth::Scope::Inference],
            None,
            hypellm_auth::SourceRestriction::Any,
            None,
            harness.router.state.clock.wall_millis(),
        )
        .unwrap()
        .into_secret();
    harness.restrict(KeyRestriction {
        priority: Some(PriorityClass::Batch),
        ..KeyRestriction::default()
    });

    let address = harness.address;
    let spawn = |key: String, content: &'static str| {
        std::thread::spawn(move || {
            send(address, &key, "POST", "/v1/chat/completions", &chat("agent", content))
        })
    };
    let hold = spawn(standard_key.clone(), "hold");
    std::thread::sleep(Duration::from_millis(80));
    let batch = spawn(harness.router.api_key.clone(), "batch");
    std::thread::sleep(Duration::from_millis(80));
    let standard = spawn(standard_key, "standard");

    for handle in [hold, batch, standard] {
        let response = handle.join().expect("thread");
        assert_eq!(response.status, 200, "{}", response.body);
    }
    let order: Vec<&str> = upstream
        .received()
        .iter()
        .map(|raw| {
            let text = String::from_utf8_lossy(raw);
            ["hold", "batch", "standard"]
                .into_iter()
                .find(|marker| text.contains(&format!("\"{marker}\"")))
                .unwrap_or("?")
        })
        .collect();
    assert_eq!(order, vec!["hold", "standard", "batch"]);
}
