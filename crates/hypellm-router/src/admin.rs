//! Mounting the management API on its own listener.
//!
//! Specification 3: the management listener is a separate trust boundary —
//! "Admin network and stronger authorization" — with its own listener
//! configuration, its own limits, and its own authentication scopes.
//!
//! Keeping it a distinct [`Handler`] on a distinct socket is what makes that
//! real. A management endpoint reachable from the inference listener would put
//! the control plane behind an API key rather than behind a session, and
//! specification 3 separates them for a reason.

use hypellm_admin_api::{AdminApi, AdminRequest, ApiError, ApiErrorCode, ApiResponse, security_headers};
use hypellm_crypto::random;
use std::io;
use std::sync::Arc;
use wire_http1::{Method, RequestHead, ResponseBuilder};

use crate::server::{ClientWriter, Disposition, Handler};

/// The management listener.
#[derive(Debug)]
pub struct AdminHandler {
    api: AdminApi,
    /// Whether to serve the static application from this listener.
    ///
    /// Specification 15 allows the application to be served from a different
    /// origin entirely; serving it here is a convenience for the single-node
    /// profile, not a requirement.
    static_root: Option<std::path::PathBuf>,
    /// Shared state, for the metrics exposition.
    ///
    /// Specification 17's exposition is operational detail — target names,
    /// queue depths, breaker states, auth failure counts — so it belongs on
    /// the management path, not beside the inference endpoints.
    router: Option<Arc<crate::state::RouterState>>,
}

impl AdminHandler {
    /// Mount the API.
    #[must_use]
    pub const fn new(api: AdminApi) -> Self {
        Self {
            api,
            static_root: None,
            router: None,
        }
    }

    /// Also serve the metrics exposition from this listener.
    #[must_use]
    pub fn with_metrics(mut self, router: Arc<crate::state::RouterState>) -> Self {
        self.router = Some(router);
        self
    }

    /// Also serve the static application from `root`.
    #[must_use]
    pub fn with_static_root(mut self, root: std::path::PathBuf) -> Self {
        self.static_root = Some(root);
        self
    }

    fn serve_static(&self, path: &str, writer: &mut ClientWriter) -> io::Result<Disposition> {
        let Some(root) = &self.static_root else {
            return write_error(
                writer,
                &ApiError::new(ApiErrorCode::NotFound, "no such endpoint"),
                "",
            );
        };

        // The path is matched against a fixed set rather than joined onto the
        // root. Joining a request path to a filesystem path is a traversal bug
        // waiting for the first `%2e%2e%2f`, and the application has few enough
        // files to enumerate.
        let (relative, content_type) = match path {
            "/" | "/index.html" => ("index.html", "text/html; charset=utf-8"),
            "/app.js" => ("app.js", "text/javascript; charset=utf-8"),
            "/styles/main.css" => ("styles/main.css", "text/css; charset=utf-8"),
            other => {
                let allowed = [
                    "/views/overview.js",
                    "/views/targets.js",
                    "/views/policies.js",
                    "/views/access.js",
                    "/views/keys.js",
                    "/views/credentials.js",
                    "/views/usage.js",
                    "/views/decisions.js",
                    "/views/audit.js",
                    "/views/settings.js",
                    "/components/dom.js",
                    "/components/table.js",
                    "/components/layout.js",
                    "/api.js",
                ];
                if allowed.contains(&other) {
                    (other.trim_start_matches('/'), "text/javascript; charset=utf-8")
                } else {
                    return write_error(
                        writer,
                        &ApiError::new(ApiErrorCode::NotFound, "no such file"),
                        "",
                    );
                }
            }
        };

        let Ok(bytes) = std::fs::read(root.join(relative)) else {
            return write_error(
                writer,
                &ApiError::new(ApiErrorCode::NotFound, "no such file"),
                "",
            );
        };

        let mut builder = ResponseBuilder::new(200)
            .header("Content-Type", content_type)
            .map_err(|_| io::Error::other("response head"))?;
        for (name, value) in static_security_headers() {
            builder = builder
                .header(name, value)
                .map_err(|_| io::Error::other("response head"))?;
        }
        let head = builder
            .finish_with_length(bytes.len())
            .map_err(|_| io::Error::other("response head"))?;
        writer.write(&head)?;
        writer.write(&bytes)?;
        writer.flush()?;
        Ok(Disposition::KeepAlive)
    }
}

impl Handler for AdminHandler {
    fn handle(
        &self,
        head: &RequestHead,
        body: &[u8],
        writer: &mut ClientWriter,
    ) -> io::Result<Disposition> {
        // Fails closed rather than assigning every management request the same
        // all-zero identifier. Specification 17 keys the audit record and the
        // response on it, and an audit trail in which every entry shares an id
        // is worse than one that is missing entries: it looks complete.
        let Ok(value) = random::u128_value() else {
            if let Some(router) = &self.router {
                router.telemetry.log(
                    &hypellm_telemetry::Event::critical("router.entropy_unavailable").str_field(
                        hypellm_telemetry::Field::Detail,
                        "no request identifier could be generated on the management listener",
                    ),
                );
                router.telemetry.count(
                    hypellm_telemetry::names::ENTROPY_FAILURES,
                    "Requests refused because no entropy was available.",
                    &hypellm_telemetry::Labels::one(
                        hypellm_telemetry::LabelName::Listener,
                        "management",
                    ),
                );
            }
            return write_error(
                writer,
                &hypellm_admin_api::ApiError::new(
                    hypellm_admin_api::ApiErrorCode::InternalFault,
                    "the router cannot generate a request identifier",
                ),
                "",
            );
        };
        let request_id = format!("{value:032x}");

        // The exposition is served here rather than on the data plane. It is
        // unauthenticated on this listener by design: the management address is
        // operator-chosen and expected to sit on a trusted network, and a
        // scrape agent cannot present an interactive session credential. What
        // matters is that an inference caller cannot reach it.
        if head.method == Method::Get && head.path == "/metrics" {
            if let Some(router) = &self.router {
                return crate::routes::metrics(router, writer);
            }
        }

        if !head.path.starts_with("/admin/v1") {
            return self.serve_static(&head.path, writer);
        }

        let request = AdminRequest {
            method: &head.method,
            path: &head.path,
            query: head.query.as_deref(),
            headers: &head.headers,
            body,
            peer: writer.peer().ip(),
            request_id: request_id.clone(),
        };

        match self.api.handle(&request) {
            Ok(response) => write_response(writer, &response, &request_id, head.method == Method::Head),
            Err(error) => write_error(writer, &error, &request_id),
        }
    }
}

fn write_response(
    writer: &mut ClientWriter,
    response: &ApiResponse,
    request_id: &str,
    head_only: bool,
) -> io::Result<Disposition> {
    let mut builder = ResponseBuilder::new(response.status);
    if !response.body.is_empty() {
        builder = builder
            .header("Content-Type", "application/json")
            .map_err(|_| io::Error::other("response head"))?;
    }
    builder = builder
        .header("X-Request-Id", request_id)
        .map_err(|_| io::Error::other("response head"))?;
    if let Some(etag) = &response.etag {
        builder = builder
            .header("ETag", etag)
            .map_err(|_| io::Error::other("response head"))?;
    }
    for (name, value) in &response.headers {
        // `Set-Cookie` may legitimately appear twice, so headers are appended
        // rather than set.
        builder = builder
            .header(name, value)
            .map_err(|_| io::Error::other("response head"))?;
    }
    for (name, value) in security_headers() {
        builder = builder
            .header(name, value)
            .map_err(|_| io::Error::other("response head"))?;
    }

    let head = builder
        .finish_with_length(response.body.len())
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    if !head_only && !response.body.is_empty() {
        writer.write(response.body.as_bytes())?;
    }
    writer.flush()?;
    Ok(Disposition::KeepAlive)
}

fn write_error(
    writer: &mut ClientWriter,
    error: &ApiError,
    request_id: &str,
) -> io::Result<Disposition> {
    let body = error.to_json(request_id);
    let mut builder = ResponseBuilder::new(error.status())
        .header("Content-Type", "application/json")
        .map_err(|_| io::Error::other("response head"))?
        .header("X-Request-Id", request_id)
        .map_err(|_| io::Error::other("response head"))?;
    for (name, value) in security_headers() {
        builder = builder
            .header(name, value)
            .map_err(|_| io::Error::other("response head"))?;
    }
    // Headers the API attached to the error itself — the cross-origin grant,
    // without which a browser cannot read this body and the operator sees an
    // opaque failure rather than the reason.
    for (name, value) in &error.headers {
        builder = builder
            .header(name, value)
            .map_err(|_| io::Error::other("response head"))?;
    }
    let head = builder
        .finish_with_length(body.len())
        .map_err(|_| io::Error::other("response head"))?;
    writer.write(&head)?;
    writer.write(body.as_bytes())?;
    writer.flush()?;
    Ok(Disposition::KeepAlive)
}

/// The headers the static application is served with.
///
/// Specification 15.2 recommends exactly this shape. `script-src 'self'` with
/// no `'unsafe-inline'` is the load-bearing part: the application has no inline
/// script and no inline event handlers, so a content injection has nothing to
/// execute.
#[must_use]
pub fn static_security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; \
             img-src 'self' data:; font-src 'self'; connect-src 'self'; \
             base-uri 'none'; frame-ancestors 'none'; form-action 'self'; \
             object-src 'none'",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
             magnetometer=(), microphone=(), payment=(), usb=()",
        ),
        ("X-Frame-Options", "DENY"),
    ]
}

/// Build the management state from the router's own, sharing every component.
#[must_use]
pub fn admin_state_from(
    router: &Arc<crate::state::RouterState>,
    cors: hypellm_admin_api::CorsPolicy,
    oidc_config: Option<hypellm_auth::oidc::OidcConfig>,
    verifier: Option<Arc<dyn hypellm_auth::oidc::TokenVerifier>>,
    oidc_key: &[u8],
    break_glass_verifier: &[u8],
) -> hypellm_admin_api::AdminState {
    let version = router.config().snapshot.version;
    // Unsizing to the sink trait object as a typed binding rather than an `as`
    // cast, so the conversion is one the compiler names.
    // The adapter rather than the bare store: rotating a credential must also
    // drain the connections opened under it (specification 22.2 step 17), and
    // the pool is not reachable from `hypellm-admin-api` by design.
    let credentials: Arc<dyn hypellm_admin_api::CredentialSink> =
        Arc::new(crate::state::CredentialSinkAdapter::new(Arc::clone(router)));
    hypellm_admin_api::AdminState {
        config: Arc::clone(&router.config),
        keys: Arc::clone(&router.keys),
        sessions: Arc::clone(&router.sessions),
        oidc: Arc::new(hypellm_auth::oidc::TransactionStore::new(oidc_key)),
        oidc_config,
        verifier,
        health: Arc::clone(&router.health),
        store: Arc::clone(&router.store),
        telemetry: Arc::clone(&router.telemetry),
        clock: Arc::clone(&router.clock),
        cors,
        decisions: Arc::clone(&router.decisions),
        usage: Arc::clone(&router.usage),
        audit: Arc::new(hypellm_admin_api::AuditIndex::default()),
        // Restored from the durable log, so a draft awaiting a second approver
        // survives a restart (`DI-013`).
        drafts: restore_drafts(&router.store),
        next_version: std::sync::atomic::AtomicU64::new(version + 1),
        break_glass: break_glass_policy(&router.config(), break_glass_verifier),
        credentials: Some(credentials),
    }
}

/// Rebuild the draft store from the durable log.
///
/// Drafts that were published or discarded are removed as their closing records
/// replay, so a spent draft does not come back looking as though it were still
/// awaiting approval. Order matters and is the log's: a `PolicyDraftClosed`
/// always follows the `PolicyDraft` it closes.
///
/// A record that does not decode is skipped rather than aborting startup. A
/// draft is proposed work, not authority: losing one costs an operator a
/// retype, while refusing to boot over it costs the deployment. That is the
/// opposite of the trade for a key record or the audit chain, and the
/// difference is deliberate.
fn restore_drafts(store: &hypellm_store::Store) -> hypellm_admin_api::DraftStore {
    let drafts = hypellm_admin_api::DraftStore::new();
    let Ok(records) = store.records_of_kinds(&[
        hypellm_store::RecordKind::PolicyDraft,
        hypellm_store::RecordKind::PolicyDraftClosed,
    ]) else {
        return drafts;
    };
    for (kind, payload) in records {
        match kind {
            hypellm_store::RecordKind::PolicyDraft => {
                if let Some(draft) = hypellm_admin_api::Draft::from_payload(&payload) {
                    drafts.restore(draft);
                }
            }
            hypellm_store::RecordKind::PolicyDraftClosed => {
                if let Ok(id) = core::str::from_utf8(&payload) {
                    drafts.close(id);
                }
            }
            _ => {}
        }
    }
    drafts
}

/// A listener that serves only the metrics exposition.
///
/// Specification 17 makes metrics "local first: a dependency-free text
/// exposition endpoint … A platform collector may scrape/forward them", and
/// `settings metrics_listen` exists to put that endpoint on its own address.
/// The field was parsed and read by nothing (`DI-011`), so the exposition was
/// only ever reachable on the management listener — which means a scrape agent
/// had to be allowed onto the control plane.
///
/// Serving *only* `/metrics` is the point. This address is reachable by a
/// scraper, and a scraper should not be one path away from `/admin/v1`.
/// Everything else, including any `/admin/v1` path, gets 404: not 403, because
/// a 403 would confirm the management API is behind this address too.
#[derive(Debug)]
pub struct MetricsHandler {
    router: Arc<crate::state::RouterState>,
}

impl MetricsHandler {
    /// Serve the exposition for `router`.
    #[must_use]
    pub const fn new(router: Arc<crate::state::RouterState>) -> Self {
        Self { router }
    }
}

impl Handler for MetricsHandler {
    fn handle(
        &self,
        head: &RequestHead,
        _body: &[u8],
        writer: &mut ClientWriter,
    ) -> io::Result<Disposition> {
        if head.method == Method::Get && head.path == "/metrics" {
            return crate::routes::metrics(&self.router, writer);
        }
        // Also answers `/health/live`, so a supervisor can check the process
        // without reaching either plane. It discloses nothing.
        if head.method == Method::Get && head.path == "/health/live" {
            return crate::routes::liveness(writer);
        }
        let body = br#"{"error":{"message":"not found","type":"invalid_request_error","code":"not_found"}}"#;
        let response = ResponseBuilder::new(404)
            .header("Content-Type", "application/json")
            .and_then(|b| b.finish_with_length(body.len()))
            .map_err(|_| io::Error::other("response head"))?;
        writer.write(&response)?;
        writer.write(body)?;
        writer.flush()?;
        Ok(Disposition::KeepAlive)
    }
}

/// The break-glass policy, when the configuration declares one.
///
/// Both the principal and the tenant must be present and valid. A partially
/// configured break-glass is disabled rather than half-enabled: specification
/// 22.4 makes this the path that works when the identity provider does not, and
/// an endpoint that exists but cannot succeed is an oracle for whoever is
/// probing it.
fn break_glass_policy(
    config: &hypellm_config::ValidatedConfig,
    verifier: &[u8],
) -> Option<hypellm_admin_api::BreakGlassPolicy> {
    let principal = config.settings.break_glass_principal.as_deref()?;
    let tenant = config.settings.break_glass_tenant.as_deref()?;
    Some(hypellm_admin_api::BreakGlassPolicy {
        verifier: verifier.to_vec(),
        principal: hypellm_core::ids::PrincipalId::new(principal).ok()?,
        tenant: hypellm_core::ids::TenantId::new(tenant).ok()?,
        ttl_millis: config
            .settings
            .break_glass_ttl_secs
            .saturating_mul(1000),
    })
}

#[cfg(test)]
// The crate-root `deny` in `lib.rs` guards production code. A test module
// indexes its own fixtures and reports failure by panicking; holding it to the
// data-plane rules would only push the panics behind `unwrap_or_else`.
#[allow(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::panic,
    clippy::expect_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    #[test]
    fn the_metrics_listener_serves_the_exposition_and_nothing_else() {
        // Specification 17 puts the exposition on `settings metrics_listen` so
        // a platform collector can scrape it. The field was parsed and read by
        // nothing (`DI-011`), so the only way to scrape was to let the agent
        // onto the management listener — which is the control plane.
        //
        // Serving *only* `/metrics` is the point: this address is reachable by
        // a scraper, and a scraper must not be one path away from `/admin/v1`.
        use std::io::{Read as _, Write as _};

        let upstream =
            crate::testing::FakeUpstream::start(crate::testing::CannedResponse::json(200, "{}"));
        let router = crate::testing::router_for(&upstream);
        let state = std::sync::Arc::clone(&router.state);

        let clock: std::sync::Arc<dyn hypellm_core::time::Clock> =
            std::sync::Arc::clone(&state.clock);
        let server = crate::server::Server::bind(
            "127.0.0.1:0",
            crate::server::ServerConfig::management(),
            clock,
        )
        .expect("bind");
        let address = server.local_addr().expect("address");
        let shutdown = server.shutdown_handle();
        let handler: std::sync::Arc<dyn crate::server::Handler> =
            std::sync::Arc::new(MetricsHandler::new(std::sync::Arc::clone(&state)));
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });

        let get = |path: &str| -> String {
            let mut stream = std::net::TcpStream::connect(address).expect("connect");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let raw = format!(
                "GET {path} HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(raw.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
            out
        };

        // A fresh router has recorded nothing, so its exposition is legitimately
        // empty. Record one metric, or this asserts only that the endpoint
        // answers — which is the weaker half of what matters.
        state.telemetry.count(
            hypellm_telemetry::names::REQUESTS_TOTAL,
            "Requests.",
            &hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Operation, "chat"),
        );

        let served = get("/metrics");
        assert!(served.starts_with("HTTP/1.1 200"), "{served}");
        assert!(
            served.contains("hypellm_requests_total"),
            "the exposition was not served: {served}"
        );

        // Everything else is 404 — not 403, which would confirm the management
        // API is behind this address too.
        for path in ["/admin/v1/keys", "/admin/v1/audit", "/admin/v1/session", "/"] {
            let response = get(path);
            assert!(
                response.starts_with("HTTP/1.1 404"),
                "{path} answered: {response}"
            );
            assert!(
                !response.contains("hypellmk_") && !response.contains("csrf"),
                "{path} disclosed something: {response}"
            );
        }

        // Liveness is allowed, so a supervisor can check the process without
        // reaching either plane. It discloses nothing.
        assert!(get("/health/live").starts_with("HTTP/1.1 200"));

        shutdown.shutdown();
        let _ = thread.join();
    }


    use super::*;

    #[test]
    fn the_static_content_security_policy_forbids_inline_script() {
        // Specification 15.1: "no inline event handlers"; 15.2: `script-src
        // 'self'`. Without this, an injected string could execute.
        let headers = static_security_headers();
        let csp = headers
            .iter()
            .find(|(name, _)| *name == "Content-Security-Policy")
            .map(|(_, value)| *value)
            .expect("a policy");

        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("base-uri 'none'"));
    }

    #[test]
    fn the_policy_permits_no_third_party_origin() {
        // Specification 15: "no build-time or runtime package dependencies,
        // CDN assets, remote fonts, telemetry SDKs".
        let headers = static_security_headers();
        let csp = headers
            .iter()
            .find(|(name, _)| *name == "Content-Security-Policy")
            .map(|(_, value)| *value)
            .expect("a policy");
        assert!(!csp.contains("http://"));
        assert!(!csp.contains("https://"));
        assert!(!csp.contains('*'));
    }

    #[test]
    fn static_responses_carry_nosniff_and_deny_framing() {
        let headers = static_security_headers();
        let map: Vec<(&str, &str)> = headers.clone();
        assert!(map.contains(&("X-Content-Type-Options", "nosniff")));
        assert!(map.contains(&("X-Frame-Options", "DENY")));
        assert!(map.contains(&("Referrer-Policy", "no-referrer")));
        assert!(
            map.iter().any(|(name, _)| *name == "Permissions-Policy"),
            "unused browser features should be disabled"
        );
    }
}
