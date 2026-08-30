//! A wired, in-process management API for the `/admin/v1` suites.
//!
//! Specification 16 fixes the management surface and 15.4 its behaviour;
//! Appendix B adds the property every suite here is really testing —
//! "management visibility never exceeds the caller's tenant and permissions".
//! Proving that needs a whole [`AdminState`]: a real configuration, a real
//! durable store, real sessions, and two tenants that are genuinely distinct.
//!
//! This module is that assembly, and nothing else. It makes no assertions about
//! handler behaviour: a harness that quietly compensates for a broken handler —
//! by supplying a permission the caller did not ask for, or by filtering a
//! response before the test sees it — would hide exactly the defects the suites
//! exist to find. Every response is returned as the handler produced it,
//! including its error.
//!
//! # Shape of a test
//!
//! ```ignore
//! let admin = Harness::new();
//! let operator = admin.operator();
//! let response = admin.get(&operator, "/admin/v1/targets");
//! assert_eq!(response.status, 200);
//! ```
//!
//! # Time
//!
//! The clock is a [`TestClock`] starting at monotonic zero, so every session
//! begins freshly authenticated and nothing expires until a test says so.
//! `advance` moves both the monotonic and wall clocks; remember that a session
//! passes its idle timeout after `SessionPolicy::idle_millis` (30 minutes by
//! default) and that the permissions in [`Permission::requires_reauthentication`]
//! stop working 5 minutes after the session was issued. [`Harness::reauthenticate`]
//! is the way back.

#![allow(dead_code, reason = "each test binary uses a different part of the harness")]
#![allow(
    unreachable_pub,
    reason = "the harness is a private module of each test binary, but its API is written as public so it reads the same from every suite"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test support code: a broken fixture should fail loudly"
)]
#![allow(
    clippy::wrong_self_convention,
    reason = "`as_session` names the request's authentication, not a conversion"
)]

use hypellm_admin_api::handlers::{AdminApi, AdminRequest, AdminState, CredentialSink};
use hypellm_admin_api::response::etag_for;
use hypellm_admin_api::{AuditIndex, CorsPolicy, DecisionCache, DraftStore, UsageAggregate};
use hypellm_admin_api::{UsageSample, UsageStatus};
use hypellm_auth::oidc;
use hypellm_auth::session::{self, Session};
use hypellm_auth::{AuthMethod, KeyStore, Scope, SessionPolicy, SessionStore, SourceRestriction};
use hypellm_config::ValidatedConfig;
use hypellm_core::canonical::{CostClass, Operation};
use hypellm_core::decision::DecisionTrace;
use hypellm_core::event::CanonicalUsage;
use hypellm_core::health::{BreakerConfig, HealthRegistry};
use hypellm_core::ids::{
    AliasId, CredentialRef, KeyId, PrincipalId, RequestId, TargetId, TenantId,
};
use hypellm_core::rbac::Role;
use hypellm_core::time::{Clock, TestClock};
use hypellm_store::{Activatable, AuditAction, AuditEvent, Store, TempDir};
use hypellm_telemetry::{Logger, MemorySink, Severity, Sink, Telemetry};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use wire_http1::{Headers, Method};
use wire_json::{Limits, Value, parse_str};

/// The tenant a session belongs to unless a test says otherwise.
pub const TENANT_A: &str = "acme";
/// A second, unrelated tenant. Nothing in the default configuration links the
/// two, so anything one can see of the other is a leak.
pub const TENANT_B: &str = "globex";

/// A target in the default configuration.
pub const LOCAL_TARGET: &str = "local:model";
/// A second target, on a remote provider with a credential attached.
pub const REMOTE_TARGET: &str = "remote:model";
/// The alias both targets serve.
pub const ALIAS: &str = "test-alias";
/// The credential reference the remote provider uses.
pub const CREDENTIAL: &str = "provider-secret";

/// An origin on the default CORS allowlist.
pub const ALLOWED_ORIGIN: &str = "https://admin.test";

/// The `POST` method, for tests that build a request by hand.
///
/// A function rather than a re-export of the enum: `wire_http1::Method` is an
/// implementation detail of the transport, and a test that named it directly
/// would couple every suite to it.
#[must_use]
pub fn method_post() -> Method {
    Method::Post
}
/// An origin that is not, and never should be, permitted.
pub const HOSTILE_ORIGIN: &str = "https://admin.test.evil.example";

/// An `If-Match` that matches whatever the resource currently is (RFC 9110).
///
/// Several resources have no endpoint that discloses their ETag, so `*` is the
/// only precondition a real client could send. Tests that want to prove the
/// *stale* case want [`STALE_ETAG`].
pub const ANY_ETAG: &str = "*";

/// A syntactically valid ETag that cannot be any resource's current one.
pub const STALE_ETAG: &str =
    "\"0000000000000000000000000000000000000000000000000000000000000000\"";

/// The configuration every harness uses unless a test supplies its own.
///
/// Two tenants, two providers, two targets, one credential, and one alias. The
/// second tenant has a grant of its own so that a caller there is a legitimate
/// user of the router rather than an unconfigured principal — the isolation
/// tests must fail because of the tenant boundary, not because the tenant does
/// not exist.
#[must_use]
pub fn default_config() -> String {
    "\
settings state_dir=/tmp/hypellm-admin-api-tests default_deadline_ms=5000 \\
         retry_budget_ms=5000 max_attempts=3
tenant id=acme
tenant id=globex
credential id=provider-secret description=\"the remote provider credential\" \\
           rotates_after_days=90
provider id=local family=openai scheme=http host=127.0.0.1 port=8081 \\
         base_path=/v1 egress=local
provider id=remote family=openai scheme=https host=api.provider.test port=443 \\
         base_path=/v1 credential=provider-secret egress=remote
target id=local:model provider=local model=test-model local=true \\
       operations=chat,embeddings streaming=true tools=true json_mode=true \\
       context=100000 max_output=8192 concurrency=8
target id=remote:model provider=remote model=remote-test \\
       operations=chat streaming=true context=100000 max_output=8192 \\
       concurrency=4 cost=5
alias id=test-alias targets=local:model,remote:model description=\"the test alias\"
grant scope=tenant:acme model=* allow=true
grant scope=tenant:globex model=* allow=true
binding id=default scope=tenant:acme model=* prefer=local:model
"
    .to_owned()
}

// -- The credential sink ----------------------------------------------------

/// An in-memory [`CredentialSink`].
///
/// Write-only through the trait, exactly like the production one, but a test
/// can read what landed — which is the only way to tell a handler that stored a
/// secret from one that reported storing it. That distinction is why the
/// credential handlers were rewritten, so it is worth being able to prove.
#[derive(Debug, Default)]
pub struct MemoryCredentialSink {
    stored: Mutex<BTreeMap<String, Vec<u8>>>,
    failure: Mutex<Option<String>>,
    /// References the handler asked to drain connections for, in order.
    drained: Mutex<Vec<String>>,
}

impl MemoryCredentialSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The secret held under a reference, if any.
    #[must_use]
    pub fn secret(&self, reference: &str) -> Option<Vec<u8>> {
        self.stored.lock().ok()?.get(reference).cloned()
    }

    /// The secret held under a reference, as text.
    #[must_use]
    pub fn secret_text(&self, reference: &str) -> Option<String> {
        self.secret(reference)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    /// References the handler asked to drain connections for, in order.
    #[must_use]
    pub fn drained(&self) -> Vec<String> {
        self.drained.lock().map(|d| d.clone()).unwrap_or_default()
    }

    /// Every reference stored, sorted.
    #[must_use]
    pub fn references(&self) -> Vec<String> {
        self.stored
            .lock()
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// How many references are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stored.lock().map_or(0, |s| s.len())
    }

    /// Whether nothing has been stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Make every subsequent store fail, as a full disk or an unreachable
    /// secret facility would.
    pub fn fail_with(&self, message: &str) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(message.to_owned());
        }
    }

    /// Stop failing.
    pub fn recover(&self) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = None;
        }
    }
}

impl CredentialSink for MemoryCredentialSink {
    fn store(&self, reference: &CredentialRef, secret: Vec<u8>) -> Result<(), String> {
        if let Some(message) = self.failure.lock().ok().and_then(|f| f.clone()) {
            return Err(message);
        }
        self.stored
            .lock()
            .map_err(|_| "poisoned".to_owned())?
            .insert(reference.as_str().to_owned(), secret);
        Ok(())
    }

    fn contains(&self, reference: &CredentialRef) -> bool {
        self.stored
            .lock()
            .is_ok_and(|s| s.contains_key(reference.as_str()))
    }

    fn drain_connections(&self, reference: &CredentialRef) -> usize {
        if let Ok(mut drained) = self.drained.lock() {
            drained.push(reference.as_str().to_owned());
        }
        // A fixed non-zero count, so a test can tell "the handler asked and got
        // an answer" from "the handler never asked".
        2
    }
}

/// A log sink that forwards into a shared buffer a test can read.
#[derive(Debug)]
struct SharedSink(Arc<MemorySink>);

impl Sink for SharedSink {
    fn write_line(&self, line: &str) {
        self.0.write_line(line);
    }
}

// -- Sessions ---------------------------------------------------------------

/// An issued management session, plus the two bearer values a request needs.
#[derive(Debug, Clone)]
pub struct TestSession {
    /// The cookie value.
    pub token: String,
    /// The session-bound CSRF token.
    pub csrf: String,
    /// Who the session belongs to.
    pub principal: PrincipalId,
    /// The tenant it is scoped to.
    pub tenant: TenantId,
    /// The roles it holds.
    pub roles: Vec<Role>,
    /// The stored record, for tests that need the digest or timestamps.
    pub session: Session,
}

impl TestSession {
    /// The `Cookie` header value carrying this session.
    #[must_use]
    pub fn cookie(&self) -> String {
        format!("{}={}", session::COOKIE_NAME, self.token)
    }
}

// -- Requests and responses -------------------------------------------------

/// What a handler returned, normalized so that success and failure read the
/// same way at a call site.
#[derive(Debug, Clone)]
pub struct Response {
    /// The HTTP status, from the response or from the error's mapping.
    pub status: u16,
    /// The JSON body, or empty for a 204.
    pub body: String,
    /// The `ETag`, when the handler produced one.
    pub etag: Option<String>,
    /// Extra headers, such as `Set-Cookie`.
    pub headers: Vec<(String, String)>,
    /// The stable error code, when the handler refused.
    pub error_code: Option<String>,
    /// The identifier the request carried.
    pub request_id: String,
}

impl Response {
    /// Whether the handler succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.error_code.is_none()
    }

    /// The parsed body.
    ///
    /// # Panics
    ///
    /// Panics if the body is absent or not JSON, which in a test means the
    /// assertion about to be made was misplaced.
    #[must_use]
    pub fn json(&self) -> Value {
        self.try_json()
            .unwrap_or_else(|| panic!("expected a JSON body, got {:?}", self.body))
    }

    /// The parsed body, or `None` for an empty one.
    #[must_use]
    pub fn try_json(&self) -> Option<Value> {
        if self.body.is_empty() {
            return None;
        }
        parse_str(&self.body, &Limits::DEFAULT).ok()
    }

    /// The `data` array of a list envelope.
    ///
    /// # Panics
    ///
    /// Panics if the body is not a list envelope.
    #[must_use]
    pub fn data(&self) -> Vec<Value> {
        self.json()
            .field_array("data")
            .unwrap_or_else(|_| panic!("expected a list envelope, got {}", self.body))
            .to_vec()
    }

    /// The `id` of each element of a list envelope, in order.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.data()
            .iter()
            .filter_map(|item| item.opt_field_str("id").ok().flatten().map(str::to_owned))
            .collect()
    }

    /// A top-level string field.
    ///
    /// # Panics
    ///
    /// Panics if the field is absent or not a string.
    #[must_use]
    pub fn str_field(&self, name: &str) -> String {
        self.json()
            .field_str(name)
            .unwrap_or_else(|_| panic!("no string field '{name}' in {}", self.body))
            .to_owned()
    }

    /// The `ETag`.
    ///
    /// # Panics
    ///
    /// Panics if the response carried none.
    #[must_use]
    pub fn expect_etag(&self) -> String {
        self.etag
            .clone()
            .unwrap_or_else(|| panic!("expected an ETag on a {} response", self.status))
    }

    /// The first header with this name, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header with this name, in order. `Set-Cookie` may repeat.
    #[must_use]
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Whether the raw body contains a substring.
    ///
    /// The blunt instrument the disclosure tests want: no response may carry a
    /// key secret, a provider credential, or a session token, whatever field it
    /// might be hiding in.
    #[must_use]
    pub fn body_contains(&self, needle: &str) -> bool {
        self.body.contains(needle)
    }
}

/// A management request under construction.
///
/// Everything is explicit. In particular the CSRF token is attached only by
/// [`RequestBuilder::as_session`] and can be removed again with
/// [`RequestBuilder::without_csrf`], so a test can prove that a mutation
/// without one is refused.
#[derive(Debug)]
pub struct RequestBuilder<'a> {
    harness: &'a Harness,
    method: Method,
    path: String,
    query: Option<String>,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    peer: Option<IpAddr>,
}

impl<'a> RequestBuilder<'a> {
    /// Authenticate as a session, attaching its cookie and CSRF token.
    #[must_use]
    pub fn as_session(mut self, session: &TestSession) -> Self {
        self.headers.push(("cookie".to_owned(), session.cookie()));
        self.headers
            .push((session::CSRF_HEADER.to_owned(), session.csrf.clone()));
        self
    }

    /// Present a raw cookie header value, for malformed and forged cookies.
    #[must_use]
    pub fn cookie(mut self, value: &str) -> Self {
        self.headers.push(("cookie".to_owned(), value.to_owned()));
        self
    }

    /// Drop the CSRF header, whatever set it.
    #[must_use]
    pub fn without_csrf(mut self) -> Self {
        self.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case(session::CSRF_HEADER));
        self
    }

    /// Present a specific CSRF token, replacing any already set.
    #[must_use]
    pub fn csrf(mut self, token: &str) -> Self {
        self = self.without_csrf();
        self.headers
            .push((session::CSRF_HEADER.to_owned(), token.to_owned()));
        self
    }

    /// Set the query string, without the leading `?`.
    #[must_use]
    pub fn query(mut self, query: &str) -> Self {
        self.query = Some(query.to_owned());
        self
    }

    /// Set a JSON body.
    #[must_use]
    pub fn json(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }

    /// Set a raw body, for malformed input.
    #[must_use]
    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Set `If-Match`.
    #[must_use]
    pub fn if_match(mut self, etag: &str) -> Self {
        self.headers.push(("if-match".to_owned(), etag.to_owned()));
        self
    }

    /// Set `Origin`.
    #[must_use]
    pub fn origin(mut self, origin: &str) -> Self {
        self.headers.push(("origin".to_owned(), origin.to_owned()));
        self
    }

    /// Set any header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Set the peer address.
    #[must_use]
    pub fn peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Serve the request.
    ///
    /// # Panics
    ///
    /// Panics if a header name or value is not valid HTTP, which would mean the
    /// test constructed something no parser would have accepted anyway.
    #[must_use]
    pub fn send(self) -> Response {
        let mut headers = Headers::default();
        for (name, value) in &self.headers {
            headers
                .append(name, value)
                .unwrap_or_else(|e| panic!("invalid test header '{name}': {e}"));
        }
        if !self.body.is_empty() {
            headers
                .append("content-type", "application/json")
                .expect("content type");
        }

        let request_id = self.harness.next_request_id();
        let request = AdminRequest {
            method: &self.method,
            path: &self.path,
            query: self.query.as_deref(),
            headers: &headers,
            body: &self.body,
            peer: self.peer,
            request_id: request_id.clone(),
        };

        match self.harness.api.handle(&request) {
            Ok(response) => Response {
                status: response.status,
                body: response.body,
                etag: response.etag,
                headers: response.headers,
                error_code: None,
                request_id,
            },
            Err(error) => Response {
                status: error.status(),
                body: error.to_json(&request_id),
                etag: None,
                // The error's own headers, not an empty list: the router emits
                // them (see `hypellm_router::admin::write_error`), and the
                // cross-origin grant on an error response is only observable
                // to a test that carries them through.
                headers: error.headers.clone(),
                error_code: Some(error.code.as_str().to_owned()),
                request_id,
            },
        }
    }
}

// -- The harness ------------------------------------------------------------

/// A complete management API, ready to serve.
#[derive(Debug)]
pub struct Harness {
    /// The API under test.
    pub api: AdminApi,
    /// Its state, for direct inspection and seeding.
    pub state: Arc<AdminState>,
    /// The clock every component reads.
    pub clock: Arc<TestClock>,
    /// Where credential secrets land.
    pub credentials: Arc<MemoryCredentialSink>,
    /// Captured log lines, for redaction tests.
    pub logs: Arc<MemorySink>,
    /// The rolling rate and latency window, for seeding traffic.
    pub traffic: Arc<hypellm_admin_api::TrafficWindow>,
    /// Admission control, for occupying capacity. `None` when the deployment
    /// was built without one.
    pub admission: Option<Arc<hypellm_core::admission::AdmissionController>>,
    /// The state directory, kept alive for the store's lifetime.
    pub dir: TempDir,
    request_counter: AtomicU64,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    /// A harness over [`default_config`].
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// A harness over explicit configuration text.
    #[must_use]
    pub fn with_config(text: &str) -> Self {
        Self::builder().config(text).build()
    }

    /// A harness with something adjusted.
    #[must_use]
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::new()
    }

    // -- Sessions -----------------------------------------------------------

    /// Issue a session for a principal, a tenant, and a set of roles.
    ///
    /// # Panics
    ///
    /// Panics if the principal or tenant is not a valid identifier.
    #[must_use]
    pub fn session(&self, principal: &str, tenant: &str, roles: &[Role]) -> TestSession {
        self.session_with_method(principal, tenant, roles, AuthMethod::Oidc)
    }

    /// Issue a session that authenticated by a specific method.
    ///
    /// # Panics
    ///
    /// Panics if the identifiers are invalid or the store cannot issue.
    #[must_use]
    pub fn session_with_method(
        &self,
        principal: &str,
        tenant: &str,
        roles: &[Role],
        method: AuthMethod,
    ) -> TestSession {
        let principal = PrincipalId::new(principal).expect("a valid principal");
        let tenant = TenantId::new(tenant).expect("a valid tenant");
        let issued = self
            .state
            .sessions
            .issue(
                principal.clone(),
                tenant.clone(),
                Some(format!("https://issuer.test|{principal}")),
                Some(format!("{principal}@example.test")),
                roles.to_vec(),
                method,
                self.clock.now_millis(),
            )
            .expect("issue a session");

        TestSession {
            token: issued.token,
            csrf: issued.csrf_token,
            principal,
            tenant,
            roles: roles.to_vec(),
            session: issued.session,
        }
    }

    /// Rotate a session's token, refreshing its authentication time.
    ///
    /// What a real operator's re-authentication does, and the way past
    /// [`hypellm_core::rbac::Permission::requires_reauthentication`] once the
    /// clock has moved. The old token is dead afterwards.
    ///
    /// # Panics
    ///
    /// Panics if the session is no longer known to the store.
    #[must_use]
    pub fn reauthenticate(&self, session: &TestSession) -> TestSession {
        let issued = self
            .state
            .sessions
            .rotate(&session.token, self.clock.now_millis())
            .expect("rotate a live session");
        TestSession {
            token: issued.token,
            csrf: issued.csrf_token,
            principal: session.principal.clone(),
            tenant: session.tenant.clone(),
            roles: session.roles.clone(),
            session: issued.session,
        }
    }

    /// A viewer in tenant A: read summaries and own usage, nothing else.
    #[must_use]
    pub fn viewer(&self) -> TestSession {
        self.viewer_in(TENANT_A)
    }

    /// A viewer in a named tenant.
    #[must_use]
    pub fn viewer_in(&self, tenant: &str) -> TestSession {
        self.session(&format!("user:viewer-{tenant}"), tenant, &[Role::Viewer])
    }

    /// An operator in tenant A: target state, quarantine, decision traces,
    /// tenant usage.
    #[must_use]
    pub fn operator(&self) -> TestSession {
        self.operator_in(TENANT_A)
    }

    /// An operator in a named tenant.
    #[must_use]
    pub fn operator_in(&self, tenant: &str) -> TestSession {
        self.session(&format!("user:operator-{tenant}"), tenant, &[Role::Operator])
    }

    /// A policy editor in tenant A: draft and simulate, but never publish.
    #[must_use]
    pub fn policy_editor(&self) -> TestSession {
        self.policy_editor_in(TENANT_A)
    }

    /// A policy editor in a named tenant.
    #[must_use]
    pub fn policy_editor_in(&self, tenant: &str) -> TestSession {
        self.session(
            &format!("user:editor-{tenant}"),
            tenant,
            &[Role::PolicyEditor],
        )
    }

    /// A policy approver in tenant A: publish, but never draft.
    #[must_use]
    pub fn policy_approver(&self) -> TestSession {
        self.policy_approver_in(TENANT_A)
    }

    /// A policy approver in a named tenant.
    #[must_use]
    pub fn policy_approver_in(&self, tenant: &str) -> TestSession {
        self.session(
            &format!("user:approver-{tenant}"),
            tenant,
            &[Role::PolicyApprover],
        )
    }

    /// A credential manager in tenant A: rotate secrets, never read one.
    #[must_use]
    pub fn credential_manager(&self) -> TestSession {
        self.credential_manager_in(TENANT_A)
    }

    /// A credential manager in a named tenant.
    #[must_use]
    pub fn credential_manager_in(&self, tenant: &str) -> TestSession {
        self.session(
            &format!("user:credentials-{tenant}"),
            tenant,
            &[Role::CredentialManager],
        )
    }

    /// An auditor in tenant A: read and export audit.
    #[must_use]
    pub fn auditor(&self) -> TestSession {
        self.auditor_in(TENANT_A)
    }

    /// An auditor in a named tenant.
    #[must_use]
    pub fn auditor_in(&self, tenant: &str) -> TestSession {
        self.session(&format!("user:auditor-{tenant}"), tenant, &[Role::Auditor])
    }

    /// A break-glass administrator in tenant A.
    ///
    /// The only role carrying `ManageKeys`, so the key endpoints need one
    /// (specification 9.3).
    #[must_use]
    pub fn break_glass(&self) -> TestSession {
        self.break_glass_in(TENANT_A)
    }

    /// A break-glass administrator in a named tenant.
    #[must_use]
    pub fn break_glass_in(&self, tenant: &str) -> TestSession {
        self.session_with_method(
            &format!("user:oncall-{tenant}"),
            tenant,
            &[Role::BreakGlassAdmin],
            AuthMethod::BreakGlass,
        )
    }

    /// A session holding no role at all: authenticated, authorized for nothing.
    #[must_use]
    pub fn unprivileged(&self) -> TestSession {
        self.session("user:nobody", TENANT_A, &[])
    }

    // -- Requests -----------------------------------------------------------

    /// Start a request with full control over every part of it.
    #[must_use]
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            harness: self,
            method,
            path: path.to_owned(),
            query: None,
            body: Vec::new(),
            headers: Vec::new(),
            peer: None,
        }
    }

    /// `GET` as a session.
    #[must_use]
    pub fn get(&self, session: &TestSession, path: &str) -> Response {
        self.request(Method::Get, path).as_session(session).send()
    }

    /// `GET` with a query string, as a session.
    #[must_use]
    pub fn get_query(&self, session: &TestSession, path: &str, query: &str) -> Response {
        self.request(Method::Get, path)
            .as_session(session)
            .query(query)
            .send()
    }

    /// `POST` a JSON body as a session, with the CSRF token attached.
    #[must_use]
    pub fn post(&self, session: &TestSession, path: &str, body: &str) -> Response {
        self.request(Method::Post, path)
            .as_session(session)
            .json(body)
            .send()
    }

    /// `POST` with an `If-Match`.
    #[must_use]
    pub fn post_if_match(
        &self,
        session: &TestSession,
        path: &str,
        body: &str,
        etag: &str,
    ) -> Response {
        self.request(Method::Post, path)
            .as_session(session)
            .json(body)
            .if_match(etag)
            .send()
    }

    /// `PATCH` with an `If-Match`, which every mutation is supposed to require.
    #[must_use]
    pub fn patch(&self, session: &TestSession, path: &str, body: &str, etag: &str) -> Response {
        self.request(Method::Patch, path)
            .as_session(session)
            .json(body)
            .if_match(etag)
            .send()
    }

    /// `PATCH` with no `If-Match` at all.
    #[must_use]
    pub fn patch_without_if_match(
        &self,
        session: &TestSession,
        path: &str,
        body: &str,
    ) -> Response {
        self.request(Method::Patch, path)
            .as_session(session)
            .json(body)
            .send()
    }

    /// `DELETE` as a session.
    #[must_use]
    pub fn delete(&self, session: &TestSession, path: &str) -> Response {
        self.request(Method::Delete, path)
            .as_session(session)
            .send()
    }

    /// A request carrying no session at all.
    #[must_use]
    pub fn anonymous(&self, method: Method, path: &str) -> Response {
        self.request(method, path).send()
    }

    // -- Time ---------------------------------------------------------------

    /// Move both clocks forward.
    pub fn advance(&self, millis: u64) {
        self.clock.advance(millis);
    }

    /// Move the wall clock alone, simulating an NTP step.
    pub fn skew_wall(&self, delta: i64) {
        self.clock.skew_wall(delta);
    }

    // -- Seeding ------------------------------------------------------------

    /// Put a decision trace in the cache for a tenant, and return its request
    /// identifier as the API spells it.
    ///
    /// The trace is empty apart from its identity: the tenant on the entry is
    /// what authorizes the read, and that is what the isolation tests care
    /// about.
    ///
    /// # Panics
    ///
    /// Panics if the tenant is not a valid identifier.
    pub fn record_decision(&self, tenant: &str, id: u128) -> String {
        let request_id = RequestId::from_u128(id);
        let trace = DecisionTrace {
            request_id,
            policy_digest: self.config().digest,
            candidates: Vec::new(),
            exclusions: Vec::new(),
            chosen: TargetId::new(LOCAL_TARGET).ok(),
            attempts: Vec::new(),
            routing_micros: 42,
            pinned: false,
        };
        self.state.decisions.record(
            TenantId::new(tenant).expect("a valid tenant"),
            trace,
            self.clock.wall_millis(),
        );
        request_id.to_string()
    }

    /// Record one completed request against the usage aggregate.
    ///
    /// # Panics
    ///
    /// Panics if any identifier is invalid.
    pub fn record_usage(
        &self,
        tenant: &str,
        principal: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        let sample = UsageSample {
            tenant: TenantId::new(tenant).expect("a valid tenant"),
            principal: PrincipalId::new(principal).expect("a valid principal"),
            alias: AliasId::new(ALIAS).expect("a valid alias"),
            target: TargetId::new(LOCAL_TARGET).ok(),
            operation: Operation::Chat,
            status: UsageStatus::Success,
            cost_class: CostClass::new(1),
            usage: CanonicalUsage::reported(input_tokens, output_tokens),
            key_id: None,
        };
        self.state
            .usage
            .record(&sample, self.clock.now_millis());
    }

    /// Append an audit event to the durable chain and the view index.
    ///
    /// Both, because the audit endpoint reads the index while the envelope's
    /// chain head and length come from the store; seeding one alone would give
    /// a test a view the router could never produce.
    ///
    /// # Panics
    ///
    /// Panics if the store refuses the append.
    pub fn record_audit(&self, tenant: &str, actor: &str, action: AuditAction, object: &str) {
        let event = AuditEvent::new(self.clock.wall_millis(), actor, action)
            .with_tenant(tenant)
            .with_object(object);
        let appended = self
            .state
            .store
            .append_audit(event.clone())
            .expect("append an audit event");
        self.state
            .audit
            .push_event(appended.sequence, event, appended.link);
    }

    /// Create an API key directly, bypassing the API.
    ///
    /// For tests that need a key belonging to *another* tenant, which the API
    /// deliberately cannot create.
    ///
    /// # Panics
    ///
    /// Panics if the identifiers are invalid or the store refuses.
    pub fn issue_api_key(&self, tenant: &str, principal: &str) -> (KeyId, String) {
        let new_key = self
            .state
            .keys
            .create(
                TenantId::new(tenant).expect("a valid tenant"),
                PrincipalId::new(principal).expect("a valid principal"),
                vec![Scope::Inference],
                Vec::new(),
                None,
                SourceRestriction::Any,
                Some("harness key".to_owned()),
                self.clock.wall_millis(),
            )
            .expect("create a key");
        let id = new_key.id().clone();
        (id, new_key.into_secret())
    }

    /// Create a policy draft directly in [`TENANT_A`], and return its
    /// identifier.
    ///
    /// # Panics
    ///
    /// Panics if the author is not a valid principal.
    pub fn create_draft(&self, author: &str, text: &str) -> String {
        self.create_draft_in(TENANT_A, author, text)
    }

    /// Create a policy draft directly in a named tenant.
    ///
    /// For tests that need a draft belonging to *another* tenant, planted the
    /// way that tenant's own editor would have created it.
    ///
    /// # Panics
    ///
    /// Panics if the author or tenant is not a valid identifier.
    pub fn create_draft_in(&self, tenant: &str, author: &str, text: &str) -> String {
        let draft = self.state.drafts.create(
            text.to_owned(),
            PrincipalId::new(author).expect("a valid principal"),
            TenantId::new(tenant).expect("a valid tenant"),
            self.clock.wall_millis(),
        );
        draft.id.clone()
    }

    // -- Inspection ---------------------------------------------------------

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> Arc<ValidatedConfig> {
        self.state.config()
    }

    /// The ETag `POST /admin/v1/policies/{id}:publish` compares `If-Match`
    /// against.
    ///
    /// Reproduces the handler's private `active_etag`, because no endpoint
    /// discloses it: `version` and the *full* digest are what it is built from,
    /// and the session and overview responses carry only a short digest. A test
    /// that wants the stale case wants [`STALE_ETAG`] instead.
    #[must_use]
    pub fn active_config_etag(&self) -> String {
        let config = self.config();
        let mut object = wire_json::Object::new();
        object.push("version", Value::from(config.snapshot.version));
        object.push("digest", Value::from(config.digest.to_hex()));
        etag_for(&Value::Object(object))
    }

    /// How many records the durable audit chain holds.
    #[must_use]
    pub fn audit_count(&self) -> u64 {
        self.state.store.audit_count()
    }

    /// Every captured log line.
    #[must_use]
    pub fn log_lines(&self) -> Vec<String> {
        self.logs.lines()
    }

    fn next_request_id(&self) -> String {
        let n = self.request_counter.fetch_add(1, Ordering::SeqCst);
        format!("{n:032x}")
    }
}

// -- Assembly ---------------------------------------------------------------

/// A harness with something adjusted before it is wired.
#[derive(Debug)]
pub struct HarnessBuilder {
    /// The break-glass policy the built state carries, if any.
    break_glass: Option<hypellm_admin_api::BreakGlassPolicy>,
    config_text: String,
    cors: CorsPolicy,
    session_policy: SessionPolicy,
    with_credential_sink: bool,
    /// Whether the built state shares an admission controller.
    with_admission: bool,
    /// The fleet control this harness serves, when a test supplies one.
    fleet: Option<Arc<dyn hypellm_admin_api::FleetControl>>,
    oidc_config: Option<oidc::OidcConfig>,
    verifier: Option<Arc<dyn oidc::TokenVerifier>>,
}

impl HarnessBuilder {
    /// Preprovision a break-glass token, returning the harness and the token.
    ///
    /// The token is generated here rather than fixed so that a test cannot
    /// accidentally pass by comparing against a constant that also appears in
    /// the implementation.
    #[must_use]
    pub fn with_break_glass(mut self, token: &str, principal: &str, tenant: &str) -> Self {
        self.break_glass = Some(hypellm_admin_api::BreakGlassPolicy {
            verifier: hypellm_crypto::sha256::sha256_parts(&[
                b"hypellm/break-glass/v1\0",
                token.as_bytes(),
            ])
            .to_vec(),
            principal: hypellm_core::ids::PrincipalId::new(principal).expect("principal"),
            tenant: hypellm_core::ids::TenantId::new(tenant).expect("tenant"),
            ttl_millis: 15 * 60 * 1000,
        });
        self
    }

    fn new() -> Self {
        Self {
            config_text: default_config(),
            cors: CorsPolicy::with_origins(vec![ALLOWED_ORIGIN.to_owned()]),
            break_glass: None,
            session_policy: SessionPolicy::DEFAULT,
            with_credential_sink: true,
            with_admission: true,
            fleet: None,
            oidc_config: None,
            verifier: None,
        }
    }

    /// Serve `/admin/v1/fleet` from this control.
    ///
    /// Absent, the surface answers "not configured on this router" — which is
    /// itself a behaviour worth testing, so it stays the default.
    #[must_use]
    pub fn fleet(mut self, control: Arc<dyn hypellm_admin_api::FleetControl>) -> Self {
        self.fleet = Some(control);
        self
    }

    /// Use explicit configuration text.
    #[must_use]
    pub fn config(mut self, text: &str) -> Self {
        self.config_text = text.to_owned();
        self
    }

    /// Replace the cross-origin allowlist.
    #[must_use]
    pub fn cors_origins(mut self, origins: &[&str]) -> Self {
        self.cors = CorsPolicy::with_origins(origins.iter().map(|o| (*o).to_owned()).collect());
        self
    }

    /// Permit nothing cross-origin.
    #[must_use]
    pub fn no_cors(mut self) -> Self {
        self.cors = CorsPolicy::none();
        self
    }

    /// Replace the session lifetime policy.
    #[must_use]
    pub fn session_policy(mut self, policy: SessionPolicy) -> Self {
        self.session_policy = policy;
        self
    }

    /// Build a deployment with nowhere to put a credential secret, so that the
    /// credential endpoints must fail closed (specification 15.3).
    #[must_use]
    pub fn without_credential_sink(mut self) -> Self {
        self.with_credential_sink = false;
        self
    }

    /// Build a deployment whose management API sees no admission controller,
    /// so that the capacity panel must say so rather than render zeros.
    #[must_use]
    pub fn without_admission(mut self) -> Self {
        self.with_admission = false;
        self
    }

    /// Configure sign-in.
    #[must_use]
    pub fn oidc(mut self, config: oidc::OidcConfig, verifier: Arc<dyn oidc::TokenVerifier>) -> Self {
        self.oidc_config = Some(config);
        self.verifier = Some(verifier);
        self
    }

    /// Wire it all together.
    ///
    /// # Panics
    ///
    /// Panics if the configuration does not build or the store cannot open —
    /// either means the fixture is wrong, not the code under test.
    #[must_use]
    pub fn build(self) -> Harness {
        let config = hypellm_config::load(&self.config_text, 1).unwrap_or_else(|errors| {
            panic!(
                "the harness configuration failed to build:\n{}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        });

        let dir = TempDir::new("admin-api");
        let (store, _recovery) =
            Store::open(dir.path(), b"harness-store-mac-key", 0).expect("open the store");

        let clock = Arc::new(TestClock::new());
        let shared_clock: Arc<dyn Clock> = clock.clone();

        let logs = Arc::new(MemorySink::new());
        let telemetry = Telemetry::new(
            Logger::new(
                Box::new(SharedSink(Arc::clone(&logs))),
                Severity::Debug,
                Arc::clone(&shared_clock),
            ),
            b"harness-pseudonym-key",
        );

        let health = Arc::new(HealthRegistry::new(
            Arc::clone(&shared_clock),
            BreakerConfig::DEFAULT,
        ));
        for (id, target) in &config.snapshot.targets {
            health.set_capacity(id, target.max_concurrency);
        }

        let credentials = MemoryCredentialSink::new();
        let shared_sink: Arc<dyn CredentialSink> = credentials.clone();
        let sink = if self.with_credential_sink {
            Some(shared_sink)
        } else {
            None
        };

        // A real controller over the harness's own targets, so a capacity test
        // reads the same type the router shares rather than a stub that can
        // drift from it. The global ceiling is small enough that a test can
        // fill it without simulating a thousand requests.
        let admission = if self.with_admission {
            let controller = hypellm_core::admission::AdmissionController::new(
                Arc::clone(&shared_clock),
                hypellm_core::admission::ScopeLimits {
                    max_concurrency: 16,
                    ..hypellm_core::admission::ScopeLimits::UNLIMITED
                },
            );
            for (id, target) in &config.snapshot.targets {
                controller.configure_target(
                    id,
                    hypellm_core::admission::ScopeLimits {
                        max_concurrency: target.max_concurrency,
                        ..hypellm_core::admission::ScopeLimits::UNLIMITED
                    },
                );
            }
            Some(Arc::new(controller))
        } else {
            None
        };
        let traffic = Arc::new(hypellm_admin_api::TrafficWindow::new(clock.now_millis()));

        let version = config.snapshot.version;
        let state = Arc::new(AdminState {
            anonymous_access: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            config: Arc::new(Activatable::new(config)),
            keys: Arc::new(KeyStore::new(b"harness-verifier-key")),
            sessions: Arc::new(SessionStore::new(
                b"harness-session-key",
                self.session_policy,
            )),
            oidc: Arc::new(oidc::TransactionStore::new(b"harness-oidc-key")),
            oidc_config: self.oidc_config,
            verifier: self.verifier,
            health,
            store: Arc::new(store),
            telemetry: Arc::new(telemetry),
            clock: shared_clock,
            cors: self.cors,
            decisions: Arc::new(DecisionCache::default()),
            usage: Arc::new(UsageAggregate::default()),
            traffic: Arc::clone(&traffic),
            // The harness carries a real controller so the capacity panel is
            // exercised against the type the router shares, not against a stub.
            // `without_admission()` is the deployment that has none.
            admission: admission.clone(),
            audit: Arc::new(AuditIndex::default()),
            drafts: DraftStore::new(),
            next_version: AtomicU64::new(version + 1),
            break_glass: self.break_glass,
            credentials: sink,
            fleet: self.fleet.clone(),
        });

        Harness {
            api: AdminApi::new(Arc::clone(&state)),
            state,
            clock,
            credentials,
            logs,
            traffic,
            admission,
            dir,
            request_counter: AtomicU64::new(1),
        }
    }
}
