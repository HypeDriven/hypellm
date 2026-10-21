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

    /// An event stream framed with chunked encoding on a keep-alive
    /// connection: one chunk per event, `[DONE]`, then `after_done` as a
    /// further chunk if given, then the terminator.
    ///
    /// The shape a real provider sends, and the only one whose connection the
    /// router can reuse. The fake keeps serving requests on the connection
    /// until the router closes it, so [`FakeUpstream::connections`] shows
    /// whether it did.
    #[must_use]
    pub fn chunked_event_stream(frames: &[&str], after_done: Option<&str>) -> Self {
        let mut body = Vec::new();
        for frame in frames {
            let mut event = String::new();
            wire_sse::encode_data(&mut event, frame);
            wire_http1::encode_chunk(&mut body, event.as_bytes());
        }
        let mut done = String::new();
        wire_sse::encode_done(&mut done);
        wire_http1::encode_chunk(&mut body, done.as_bytes());
        if let Some(extra) = after_done {
            wire_http1::encode_chunk(&mut body, extra.as_bytes());
        }
        wire_http1::encode_last_chunk(&mut body);
        Self {
            status: 200,
            headers: vec![
                ("Content-Type".to_owned(), "text/event-stream".to_owned()),
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
            ],
            body,
            streaming: true,
            delay: std::time::Duration::ZERO,
            body_delay: std::time::Duration::ZERO,
        }
    }

    /// Whether the body is chunked, and the connection therefore kept alive.
    fn keeps_alive(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
        })
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
        if self.keeps_alive() {
            out.extend_from_slice(b"\r\n");
        } else if self.streaming {
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
        if self.keeps_alive() {
            out.extend_from_slice(b"\r\n");
        } else if self.streaming {
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
    /// How many connections it has accepted.
    connections: Arc<AtomicU64>,
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
        let connections = Arc::new(AtomicU64::new(0));
        let thread_connections = Arc::clone(&connections);
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
                thread_connections.fetch_add(1, Ordering::SeqCst);
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                // One request per iteration. A keep-alive response keeps the
                // connection for the next request; anything else ends it.
                loop {
                    let mut buffer = vec![0u8; 64 * 1024];
                    let n = match socket.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let index = usize::try_from(thread_served.fetch_add(1, Ordering::SeqCst))
                        .unwrap_or(usize::MAX);
                    // `responses` is non-empty (asserted above), so `last`
                    // always answers and the `else` arm is unreachable.
                    let Some(response) = responses.get(index).or_else(|| responses.last())
                    else {
                        break;
                    };
                    buffer.truncate(n);
                    if let Ok(mut log) = thread_received.lock() {
                        log.push(buffer);
                    }
                    if !response.delay.is_zero() {
                        std::thread::sleep(response.delay);
                    }
                    if response.keeps_alive() {
                        // The terminator in its own write, a moment later: a
                        // real provider flushes `[DONE]` as soon as it has it,
                        // and the router must not depend on the end of the
                        // framing arriving in the same read.
                        let wire = response.to_wire();
                        let split = wire.len().saturating_sub(b"0\r\n\r\n".len());
                        let (events, terminator) = wire.split_at(split);
                        let _ = socket.write_all(events);
                        let _ = socket.flush();
                        std::thread::sleep(Duration::from_millis(20));
                        let _ = socket.write_all(terminator);
                    } else if response.body_delay.is_zero() {
                        let _ = socket.write_all(&response.to_wire());
                    } else {
                        // Head first, then silence, then the body: what a
                        // provider that has accepted the request and is
                        // thinking looks like.
                        let _ = socket.write_all(&response.head_wire());
                        let _ = socket.flush();
                        std::thread::sleep(response.body_delay);
                        let _ = socket.write_all(&response.body);
                    }
                    let _ = socket.flush();
                    if !response.keeps_alive() || thread_stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    // Waiting on an idle pooled connection blocks the accept
                    // loop, so the wait for a follow-up request is short.
                    let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
                }
                let _ = socket.flush();
                let _ = socket.shutdown(std::net::Shutdown::Write);
            }
        });

        Self {
            address,
            served,
            connections,
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

    /// How many connections it has accepted.
    #[must_use]
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
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
    let (store, recovery) = Store::open(dir.path(), b"test-store-mac-key", 0).expect("open store");
    let store = Arc::new(store);
    let (budgets, _) = hypellm_admin_api::budget::restore(
        &store,
        &recovery,
        config.settings.budget_draw_tokens,
    );

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
    admission.configure_machines(&config.admission_plan());

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

    let enrollments = Arc::new(hypellm_fleet::enroll::EnrollmentRegistry::new(Arc::new(
        hypellm_admin_api::enroll::StoreJournal::new(Arc::clone(&store)),
    )));
    let telemetry = Arc::new(telemetry);
    let enrollment_telemetry = Arc::clone(&telemetry);
    let state = RouterState {
        // The harness enables jobs unconditionally, so a test that exercises
        // `/v1/jobs` does not have to remember to turn it on in its fixture.
        // The workers are started by `serve`; a test driving the store
        // directly needs none.
        jobs: Some(Arc::new(
            crate::jobs::JobStore::new(crate::jobs::JobLimits::DEFAULT).with_spool(
                crate::spool::Spool::open(dir.path(), 64 * 1024 * 1024, 256 * 1024 * 1024)
                    .expect("the test spool"),
                250,
            ),
        )),
        anonymous_access: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        config: Arc::new(Activatable::new(config)),
        keys: Arc::new(keys),
        budgets,
        sessions: Arc::new(SessionStore::new(b"test-session-key", SessionPolicy::DEFAULT)),
        credentials: Arc::new(credentials),
        health,
        admission: Arc::new(admission),
        egress,
        telemetry,
        store,
        clock,
        trusted_edge: TrustedEdge::none(),
        decisions: Arc::new(hypellm_admin_api::DecisionCache::default()),
        usage: Arc::new(hypellm_admin_api::UsageAggregate::default()),
        traffic: Arc::new(hypellm_admin_api::TrafficWindow::default()),
        fleet: std::sync::OnceLock::new(),
        admin_fleet: hypellm_admin_api::FleetSlot::default(),
        recovery_waiters: std::sync::atomic::AtomicU32::new(0),
        parked_requests: std::sync::atomic::AtomicU32::new(0),
        enrollment_offers: Arc::new(crate::fleet::EnrollmentOfferer::new(
            Arc::clone(&enrollments),
            Arc::clone(&enrollment_telemetry),
        )),
        enrollments,
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

// -- A simulated job shim (orchestration §11.3) ------------------------------

/// What a [`SimulatedShim`] does, part by part.
#[derive(Debug, Clone)]
pub struct ShimPart {
    /// The part's name, as the status reports it.
    pub name: String,
    /// The media type the status declares.
    pub declared_type: String,
    /// The length the status declares.
    pub declared_bytes: u64,
    /// The media type the part's head actually carries.
    pub served_type: String,
    /// The bytes actually served.
    pub body: Vec<u8>,
}

impl ShimPart {
    /// An honest part: declared exactly as served.
    #[must_use]
    pub fn honest(name: &str, media_type: &str, body: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            declared_type: media_type.to_owned(),
            declared_bytes: u64::try_from(body.len()).unwrap_or(u64::MAX),
            served_type: media_type.to_owned(),
            body: body.to_vec(),
        }
    }
}

/// How a [`SimulatedShim`] behaves.
#[derive(Debug, Clone)]
pub struct ShimScript {
    /// The bearer it requires.
    pub bearer: String,
    /// Refusals answered to the first submits, as `(status, error token)`.
    pub submit_refusals: Vec<(u16, &'static str)>,
    /// The job id it hands out.
    pub job_id: String,
    /// Status polls answered `running` before the job finishes.
    pub polls_before_done: u32,
    /// `Some(error)` fails the job with it instead of succeeding.
    pub fail_with: Option<&'static str>,
    /// What a succeeded job produced.
    pub parts: Vec<ShimPart>,
}

impl ShimScript {
    /// One job, done after two polls, producing `parts`.
    #[must_use]
    pub fn succeeding(parts: Vec<ShimPart>) -> Self {
        Self {
            bearer: "test-provider-secret".to_owned(),
            submit_refusals: Vec::new(),
            job_id: "sim_0001".to_owned(),
            polls_before_done: 2,
            fail_with: None,
            parts,
        }
    }
}

#[derive(Debug, Default)]
struct ShimState {
    submits: Vec<Vec<u8>>,
    log: Vec<String>,
    polls: u32,
    cancelled: bool,
    refusals_left: Vec<(u16, &'static str)>,
}

/// A job shim speaking the protocol over a real socket, scripted.
///
/// One request per connection, answered with `Connection: close`, so the
/// router's pooled-socket handling is exercised as a peer that closes.
#[derive(Debug)]
pub struct SimulatedShim {
    /// Where it listens.
    pub address: std::net::SocketAddr,
    state: Arc<std::sync::Mutex<ShimState>>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SimulatedShim {
    /// Start a shim following `script`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot bind.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "test scaffolding: a harness that cannot bind must fail loudly"
    )]
    pub fn start(script: ShimScript) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind simulated shim");
        let address = listener.local_addr().expect("shim address");
        let state = Arc::new(std::sync::Mutex::new(ShimState {
            refusals_left: script.submit_refusals.clone(),
            ..ShimState::default()
        }));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stopping = Arc::clone(&stopping);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut socket) = stream else { break };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let Some((method, path, auth, body)) = read_request(&mut socket) else {
                    continue;
                };
                let reply = shim_reply(&script, &thread_state, &method, &path, &auth, body);
                let _ = socket.write_all(&reply);
                let _ = socket.flush();
            }
        });
        Self {
            address,
            state,
            stopping,
            handle: Some(handle),
        }
    }

    /// Every submit body received, in order.
    #[must_use]
    pub fn submits(&self) -> Vec<Vec<u8>> {
        self.state.lock().map(|s| s.submits.clone()).unwrap_or_default()
    }

    /// Every request, as `METHOD path auth-ok`.
    #[must_use]
    pub fn log(&self) -> Vec<String> {
        self.state.lock().map(|s| s.log.clone()).unwrap_or_default()
    }
}

impl Drop for SimulatedShim {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.address);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one request: method, path, the `Authorization` value and the body.
fn read_request(socket: &mut std::net::TcpStream) -> Option<(String, String, String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(chunk.get(..read)?);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(buffer.get(..head_end)?).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let mut length = 0_usize;
    let mut auth = String::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().ok()?,
            "authorization" => value.trim().clone_into(&mut auth),
            _ => {}
        }
    }
    let mut body = buffer.get(head_end + 4..)?.to_vec();
    while body.len() < length {
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(chunk.get(..read)?);
    }
    Some((method, path, auth, body))
}

fn shim_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn shim_reply(
    script: &ShimScript,
    state: &std::sync::Mutex<ShimState>,
    method: &str,
    path: &str,
    auth: &str,
    body: Vec<u8>,
) -> Vec<u8> {
    let json = |status: u16, text: &str| shim_response(status, "application/json", text.as_bytes());
    let Ok(mut state) = state.lock() else {
        return json(500, r#"{"error":"internal"}"#);
    };
    let authorised = auth == format!("Bearer {}", script.bearer);
    state.log.push(format!("{method} {path} {}", if authorised { "auth" } else { "noauth" }));
    if !authorised {
        return json(401, r#"{"error":"invalid_input"}"#);
    }
    let job = format!("/job/v1/jobs/{}", script.job_id);
    match (method, path) {
        ("POST", "/job/v1/jobs") => {
            state.submits.push(body);
            if !state.refusals_left.is_empty() {
                let (status, error) = state.refusals_left.remove(0);
                return json(status, &format!(r#"{{"error":"{error}"}}"#));
            }
            json(202, &format!(r#"{{"id":"{}"}}"#, script.job_id))
        }
        ("GET", p) if p == job => {
            state.polls = state.polls.saturating_add(1);
            if state.cancelled {
                return json(200, r#"{"state":"cancelled"}"#);
            }
            if state.polls <= script.polls_before_done {
                return json(200, r#"{"state":"running","progress_permille":500,"eta_ms":1000}"#);
            }
            if let Some(error) = script.fail_with {
                return json(200, &format!(r#"{{"state":"failed","error":"{error}"}}"#));
            }
            let parts: Vec<String> = script
                .parts
                .iter()
                .map(|p| {
                    format!(
                        r#"{{"name":"{}","media_type":"{}","bytes":{}}}"#,
                        p.name, p.declared_type, p.declared_bytes
                    )
                })
                .collect();
            json(
                200,
                &format!(
                    r#"{{"state":"succeeded","progress_permille":1000,"elapsed_ms":4200,"parts":[{}]}}"#,
                    parts.join(",")
                ),
            )
        }
        ("DELETE", p) if p == job => {
            state.cancelled = true;
            json(202, r#"{"stopped":true}"#)
        }
        ("GET", p) => match p
            .strip_prefix(&format!("{job}/parts/"))
            .and_then(|name| script.parts.iter().find(|part| part.name == name))
        {
            Some(part) => shim_response(200, &part.served_type, &part.body),
            None => json(404, r#"{"error":"invalid_input"}"#),
        },
        _ => json(404, r#"{"error":"invalid_input"}"#),
    }
}
