//! Test harness: a complete router over a fake upstream.
//!
//! Public so that the integration tests, the compatibility suite, and the
//! benchmark harness all build the *same* router. A test that assembles its
//! own state differently proves less than it appears to.

use hypellm_auth::{KeyStore, SessionPolicy, SessionStore, TrustedEdge};
use hypellm_config::ValidatedConfig;
use hypellm_core::admission::{AdmissionController, ScopeLimits};
use hypellm_core::health::{BreakerConfig, HealthRegistry};
use hypellm_core::time::{Clock, SystemClock};
use hypellm_net::{ConnectionPool, Egress, PoolConfig, Resolver, StaticResolver};
use hypellm_store::{Activatable, Store, TempDir};
use hypellm_telemetry::{Logger, MemorySink, Severity, Sink, Telemetry};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::state::{CredentialStore, RouterState};

/// A canned upstream response.
#[derive(Debug, Clone)]
pub struct CannedResponse {
    /// The status line status.
    pub status: u16,
    /// Headers, as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// Whether to send the body as an unterminated stream and then close.
    pub streaming: bool,
    /// How long to wait after sending the head before sending the body.
    pub body_delay: std::time::Duration,
    /// How long to hold the request before answering.
    ///
    /// The only way to have two requests in flight at once in a test, which is
    /// what admission queueing and concurrency limits are about.
    pub delay: std::time::Duration,
}

impl CannedResponse {
    /// A JSON response.
    #[must_use]
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
            streaming: false,
            delay: std::time::Duration::ZERO,
            body_delay: std::time::Duration::ZERO,
        }
    }

    /// Send the head immediately, then go quiet for `delay` before the body.
    ///
    /// Distinct from `after`, which delays the whole exchange. This is the
    /// shape a real provider has — 200 and headers at once, then thinking —
    /// and it is the silence specification 14's keepalives exist for. A fake
    /// that delays the head instead exercises the *head* read, where a
    /// keepalive would be impossible anyway because nothing has been sent to
    /// the client yet.
    #[must_use]
    pub fn silent_before_body(mut self, delay: std::time::Duration) -> Self {
        self.body_delay = delay;
        self
    }

    /// The same response, held for `delay` before it is sent.
    #[must_use]
    pub fn after(mut self, delay: std::time::Duration) -> Self {
        self.delay = delay;
        self
    }

    /// An event stream, sent then closed.
    #[must_use]
    pub fn event_stream(frames: &[&str]) -> Self {
        let mut body = String::new();
        for frame in frames {
            wire_sse::encode_data(&mut body, frame);
        }
        wire_sse::encode_done(&mut body);
        Self {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "text/event-stream".to_owned(),
            )],
            body: body.into_bytes(),
            streaming: true,
            delay: std::time::Duration::ZERO,
            body_delay: std::time::Duration::ZERO,
        }
    }

    /// An Anthropic-style named event stream.
    #[must_use]
    pub fn named_event_stream(frames: &[(&str, &str)]) -> Self {
        let mut body = String::new();
        for (name, data) in frames {
            wire_sse::encode_event(&mut body, name, data);
        }
        Self {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "text/event-stream".to_owned(),
            )],
            body: body.into_bytes(),
            streaming: true,
            delay: std::time::Duration::ZERO,
            body_delay: std::time::Duration::ZERO,
        }
    }

    /// The head alone, when the body is sent separately.
    fn head_wire(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} OK\r\n", self.status).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if self.streaming {
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        } else {
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        }
        out
    }

    fn to_wire(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} OK\r\n", self.status).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if self.streaming {
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        } else {
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }
}

/// A fake provider that answers with canned responses.
#[derive(Debug)]
pub struct FakeUpstream {
    /// The address it listens on.
    pub address: std::net::SocketAddr,
    /// How many requests it has served.
    served: Arc<AtomicU64>,
    /// The bodies it received.
    received: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Set on drop so the accept loop exits instead of blocking forever.
    stopping: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeUpstream {
    /// Start an upstream that answers every request with `response`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot bind, which in a test means the environment is
    /// broken.
    #[must_use]
    pub fn start(response: CannedResponse) -> Self {
        Self::start_sequence(vec![response])
    }

    /// Start an upstream that answers each request with the next response,
    /// repeating the last one once the sequence is exhausted.
    ///
    /// This is how failover is exercised: a failure followed by a success.
    ///
    /// # Panics
    ///
    /// Panics if it cannot bind.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "test scaffolding: a harness that cannot bind must fail loudly, \
                  and this is never reached from the request path"
    )]
    pub fn start_sequence(responses: Vec<CannedResponse>) -> Self {
        assert!(!responses.is_empty(), "at least one response is required");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake upstream");
        let address = listener.local_addr().expect("upstream address");
        let served = Arc::new(AtomicU64::new(0));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));

        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_served = Arc::clone(&served);
        let thread_received = Arc::clone(&received);
        let thread_stopping = Arc::clone(&stopping);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                // Checked after accept returns: the drop handler sets the flag
                // and then connects, so this iteration sees it and returns.
                if thread_stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut socket) = stream else { break };
                let index = usize::try_from(thread_served.fetch_add(1, Ordering::SeqCst))
                    .unwrap_or(usize::MAX);
                // `responses` is non-empty (asserted above), so `last` always
                // answers and the `else` arm is unreachable.
                let Some(response) = responses.get(index).or_else(|| responses.last()) else {
                    break;
                };

                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buffer = vec![0u8; 64 * 1024];
                if let Ok(n) = socket.read(&mut buffer) {
                    buffer.truncate(n);
                    if let Ok(mut log) = thread_received.lock() {
                        log.push(buffer);
                    }
                }
                if !response.delay.is_zero() {
                    std::thread::sleep(response.delay);
                }
                if response.body_delay.is_zero() {
                    let _ = socket.write_all(&response.to_wire());
                } else {
                    // Head first, then silence, then the body: what a provider
                    // that has accepted the request and is thinking looks like.
                    let _ = socket.write_all(&response.head_wire());
                    let _ = socket.flush();
                    std::thread::sleep(response.body_delay);
                    let _ = socket.write_all(&response.body);
                }
                let _ = socket.flush();
                let _ = socket.shutdown(std::net::Shutdown::Write);
            }
        });

        Self {
            address,
            served,
            received,
            stopping,
            handle: Some(handle),
        }
    }

    /// How many requests it has served.
    #[must_use]
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::SeqCst)
    }

    /// The raw requests it received.
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// The body of the last request it received.
    #[must_use]
    pub fn last_body(&self) -> Option<String> {
        let received = self.received();
        let last = received.last()?;
        let text = String::from_utf8_lossy(last);
        let (_, body) = text.split_once("\r\n\r\n")?;
        Some(body.to_owned())
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        // Signal first, *then* connect to unblock the pending accept, so the
        // loop observes the flag on the iteration that connection wakes.
        // Connecting without signalling first would just serve one more
        // request and go back to blocking.
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect_timeout(&self.address, Duration::from_millis(200));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A router assembled over a fake upstream, ready to serve.
#[derive(Debug)]
pub struct TestRouter {
    /// The shared state.
    pub state: Arc<RouterState>,
    /// The captured log lines.
    pub logs: Arc<MemorySink>,
    /// The state directory, kept alive for the router's lifetime.
    pub dir: TempDir,
    /// The API key to present.
    pub api_key: String,
}

/// A sink that forwards to a shared memory sink.
#[derive(Debug)]
struct SharedSink(Arc<MemorySink>);

impl Sink for SharedSink {
    fn write_line(&self, line: &str) {
        self.0.write_line(line);
    }
}

/// Build a router whose only provider is `upstream`.
///
/// # Panics
///
/// Panics if the configuration does not build, which would mean the fixture
/// itself is wrong.
#[must_use]
pub fn router_for(upstream: &FakeUpstream) -> TestRouter {
    router_with_config(upstream, &default_config_text(upstream.address.port()))
}

/// Attach a fleet runtime to a test router.
///
/// The runtime is built after the state, exactly as startup does, and published
/// into the same `OnceLock` every holder of the `Arc` reads. A test that wants
/// the *whole* path — request in, container started, response out — needs this
/// plus a `SimulatedAgent` on the socket the configuration names.
///
/// # Panics
///
/// Panics if the configuration declares no active fleet, or if the runtime has
/// already been attached: both mean the fixture is wrong.
#[allow(
    clippy::expect_used,
    reason = "test scaffolding: a harness whose fixture does not build has \
              nothing to assert, so it fails loudly; not reachable from the \
              request path"
)]
pub fn attach_fleet(router: &TestRouter, key: &[u8]) {
    let config = router.state.config();
    let runtime = crate::fleet::FleetRuntime::new(
        Arc::clone(&config.fleet),
        key.to_vec(),
        Arc::clone(&router.state.clock),
        Arc::clone(&router.state.telemetry),
        Arc::clone(&router.state.store),
    )
    .expect("the test configuration must declare an enabled fleet with deployments");
    runtime.adopt_policy(&config.snapshot);
    runtime.observe();
    assert!(
        router.state.fleet.set(Arc::new(runtime)).is_ok(),
        "a fleet runtime was already attached"
    );
}

/// The configuration a test router uses by default.
#[must_use]
pub fn default_config_text(port: u16) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=5000 retry_budget_ms=5000 max_attempts=3
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

/// Build a router from explicit configuration text.
///
/// # Panics
///
/// Panics if the configuration does not build.
#[must_use]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test scaffolding: a harness whose fixture does not build has \
              nothing to assert, so it fails loudly; not reachable from the \
              request path"
)]
pub fn router_with_config(_upstream: &FakeUpstream, config_text: &str) -> TestRouter {
    let config = hypellm_config::load(config_text, 1).unwrap_or_else(|errors| {
        panic!(
            "test configuration failed to build:\n{}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        )
    });

    let dir = TempDir::new("router");
    let (store, _) = Store::open(dir.path(), b"test-store-mac-key", 0).expect("open store");

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let logs = Arc::new(MemorySink::new());
    let telemetry = Telemetry::new(
        Logger::new(
            Box::new(SharedSink(Arc::clone(&logs))),
            Severity::Debug,
            Arc::clone(&clock),
        ),
        b"test-pseudonym-key",
    );

    let health = Arc::new(HealthRegistry::new(
        Arc::clone(&clock),
        BreakerConfig::DEFAULT,
    ));
    for (id, target) in &config.snapshot.targets {
        health.set_capacity(id, target.max_concurrency);
        health.set_queue_allowance(
            id,
            config
                .quotas
                .iter()
                .find(|q| q.scope == hypellm_config::QuotaScope::Target(id.clone()))
                .map_or(0, |q| q.limits.max_queued),
        );
    }

    let mut admission = AdmissionController::new(
        Arc::clone(&clock),
        ScopeLimits {
            max_concurrency: 256,
            ..ScopeLimits::UNLIMITED
        },
    );
    admission.set_default_tenant_limits(ScopeLimits::UNLIMITED);
    admission.set_default_principal_limits(ScopeLimits::UNLIMITED);
    for quota in &config.quotas {
        match &quota.scope {
            hypellm_config::QuotaScope::Tenant(t) => {
                admission.configure_tenant(t, quota.limits);
                admission.set_class(&format!("tenant:{t}"), quota.class);
            }
            hypellm_config::QuotaScope::Principal(p) => {
                admission.configure_principal(p, quota.limits);
                admission.set_class(&format!("principal:{p}"), quota.class);
            }
            hypellm_config::QuotaScope::Target(t) => admission.configure_target(t, quota.limits),
            hypellm_config::QuotaScope::Alias { alias, operation } => {
                admission.configure_alias(alias, *operation, quota.limits);
            }
            hypellm_config::QuotaScope::Global => {}
        }
    }

    let resolver = Resolver::new(Box::new(StaticResolver::new().with(
        "127.0.0.1",
        vec![IpAddr::from([127, 0, 0, 1])],
    )));
    let egress = Egress::new(
        resolver,
        ConnectionPool::new(PoolConfig::DEFAULT, Arc::clone(&clock)),
        None,
        Duration::from_secs(5),
    );

    let keys = KeyStore::new(b"test-verifier-key");
    let new_key = keys
        .create(
            hypellm_core::ids::TenantId::new("acme").expect("tenant"),
            hypellm_core::ids::PrincipalId::new("svc:test").expect("principal"),
            vec![
                hypellm_auth::Scope::Inference,
                hypellm_auth::Scope::Embeddings,
                hypellm_auth::Scope::Models,
                hypellm_auth::Scope::Tokenize,
            ],
            // The operator role, so the harness key may cause fleet work. A
            // plain inference key deliberately may not: `fleet.activate` is
            // permission to make the *fleet* do something, not permission to
            // reach a model, and the fleet tests below rely on that distinction
            // being real.
            vec![hypellm_core::rbac::Role::Operator],
            None,
            hypellm_auth::SourceRestriction::Any,
            Some("integration test key".to_owned()),
            clock.wall_millis(),
        )
        .expect("create key");
    let api_key = new_key.into_secret();

    let credentials = CredentialStore::new();
    for credential in &config.credentials {
        credentials.set(&credential.id, b"test-provider-secret".to_vec());
    }

    let state = RouterState {
        anonymous_access: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        config: Arc::new(Activatable::new(config)),
        keys: Arc::new(keys),
        sessions: Arc::new(SessionStore::new(b"test-session-key", SessionPolicy::DEFAULT)),
        credentials: Arc::new(credentials),
        health,
        admission: Arc::new(admission),
        egress,
        telemetry: Arc::new(telemetry),
        store: Arc::new(store),
        clock,
        trusted_edge: TrustedEdge::none(),
        decisions: Arc::new(hypellm_admin_api::DecisionCache::default()),
        usage: Arc::new(hypellm_admin_api::UsageAggregate::default()),
        traffic: Arc::new(hypellm_admin_api::TrafficWindow::default()),
        fleet: std::sync::OnceLock::new(),
    };

    TestRouter {
        state: Arc::new(state),
        logs,
        dir,
        api_key,
    }
}

/// A validated configuration built from text, for tests that need one alone.
///
/// # Panics
///
/// Panics if the configuration does not build.
#[must_use]
#[allow(
    clippy::panic,
    reason = "test scaffolding: a fixture that does not build has nothing to \
              assert; not reachable from the request path"
)]
pub fn config_from(text: &str) -> ValidatedConfig {
    hypellm_config::load(text, 1).unwrap_or_else(|errors| {
        panic!(
            "configuration failed to build:\n{}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        )
    })
}
