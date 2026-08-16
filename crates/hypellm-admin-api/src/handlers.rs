//! The `/admin/v1` handlers (specification 16).
//!
//! Every mutating handler goes through the same gate, in this order:
//!
//! 1. **Origin** — on the exact allowlist, or the request is refused
//!    (specification 15.4).
//! 2. **Session** — a valid, unexpired server-side session.
//! 3. **CSRF** — a session-bound token, for anything state-changing
//!    (specification 9.1).
//! 4. **Permission** — the role must carry it (specification 9.3).
//! 5. **Freshness** — sensitive actions need a recent authentication
//!    (specification 9.1).
//! 6. **`If-Match`** — optimistic concurrency on mutation (specification 15.4).
//!
//! The order matters: an unauthenticated caller must not learn whether a
//! resource exists, and a caller from a hostile origin must be stopped before
//! their session cookie is consulted at all.

use hypellm_auth::session::{self, Session};
use hypellm_auth::{SessionRejection, oidc};
use hypellm_config::ValidatedConfig;
use hypellm_core::canonical::Operation;
use hypellm_core::ids::{CredentialRef, PrincipalId, RequestId, TargetId, TenantId};
use hypellm_core::policy::RoutingContext;
use hypellm_core::rbac::Permission;
use hypellm_core::target::AdminState as TargetAdminState;
use hypellm_core::time::Clock;
use hypellm_store::{AuditAction, AuditEvent, AuditOutcome, Store};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use wire_http1::{Headers, Method};
use wire_json::{Limits, Object, Value, parse};

use crate::audit_index::AuditIndex;
use crate::cors::{CorsPolicy, PreflightOutcome};
use crate::decisions::DecisionCache;
use crate::drafts::{DraftStore, PublishRefusal};
use crate::response::{
    ApiError, ApiErrorCode, ApiErrorDetail, ApiResponse, Pagination, etag_for, if_match_satisfied,
    list_envelope,
};
use crate::usage::UsageAggregate;

/// Whether a caller-supplied value may be written into a configuration record.
///
/// The configuration grammar is line-oriented and space-separated
/// (specification 11.1), so a value carrying a space, a newline, or a `#` would
/// not add one field to one record — it would add fields, records, or a comment
/// that swallowed the rest of the line. That is configuration injection, and
/// the fact that the caller needs `EditPolicy` to get here does not make it
/// acceptable: a draft is reviewed by a *second* person, who reads what they
/// were shown and approves what is there.
///
/// The alphabet is the intersection of what the grammar's identifiers, target
/// ids (`provider:model`), and model names actually use. Anything outside it is
/// refused rather than escaped, because a quoted string would still parse and
/// the point is to reject the input, not to make it safe to embed.
fn is_configuration_token(raw: &str) -> bool {
    // A cap, because this becomes a line in a document every future reader of
    // the configuration has to scroll past. Generous next to any real model
    // name, which is the longest of the three fields.
    const MAX: usize = 128;
    !raw.is_empty()
        && raw.chars().count() <= MAX
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/'))
}

/// Render a caller-supplied token safely into an error message.
///
/// An error naming the value it rejected is worth a great deal — "unknown scope
/// 'inferance'" tells an operator exactly what to fix, and "unknown scope"
/// does not. But the value is caller-controlled and unbounded, and a malformed
/// management body is very often a mis-pasted secret: without narrowing, the
/// whole of it comes back in the response and into whatever reads it.
///
/// So the value is echoed at typo scale and no further: 32 characters, narrowed
/// to an identifier alphabet so it cannot carry a quote, a newline, or JSON
/// structure into the message. A typo survives intact; a pasted key does not.
fn echo(raw: &str) -> String {
    const MAX: usize = 32;
    let mut out: String = raw
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if raw.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// How many source networks one key may name.
///
/// Specification 3.2 bounds every input, and a restriction list is walked on
/// every request the key makes.
const MAX_SOURCE_NETWORKS: usize = 32;

/// Parse `source_networks` into a [`SourceRestriction`].
///
/// Absent means [`SourceRestriction::Any`], which is what a key gets when the
/// caller does not ask — the same default as before this existed, so an
/// existing client is unaffected.
///
/// Present but *empty* is an error rather than `Any`. An empty list reads as
/// "restrict to nothing", and quietly turning that into "restrict to nothing at
/// all" is the shape of fail-open this codebase has already been bitten by once
/// (`DI-002`: an explicitly empty `model=` widening a grant to every alias).
///
/// Each entry is `address/prefix`. A bare address without a prefix is refused
/// rather than assumed to be a /32: an operator who meant a single host and
/// typed one can say so, and an operator who forgot the prefix on a network
/// gets an error instead of a restriction one address wide.
fn parse_source_restriction(body: &Value) -> Result<hypellm_auth::SourceRestriction, ApiError> {
    let Some(entries) = body.opt_field_array("source_networks").ok().flatten() else {
        return Ok(hypellm_auth::SourceRestriction::Any);
    };
    if entries.is_empty() {
        return Err(ApiError::new(
            ApiErrorCode::InvalidRequest,
            "'source_networks' was present but empty; omit it for an unrestricted key",
        ));
    }
    if entries.len() > MAX_SOURCE_NETWORKS {
        return Err(ApiError::new(
            ApiErrorCode::InvalidRequest,
            "'source_networks' names more networks than a key may carry",
        ));
    }

    let mut networks = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = entry.as_str().unwrap_or_default();
        let (address, prefix) = text.split_once('/').ok_or_else(|| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!(
                    "'{}' is not a CIDR block; write a prefix length, such as \
                     '10.0.0.0/8' or '203.0.113.7/32'",
                    echo(text)
                ),
            )
        })?;
        let address: IpAddr = address.parse().map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!("'{}' is not a valid IP address", echo(address)),
            )
        })?;
        let bits: u8 = prefix.parse().map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!("'{}' is not a valid prefix length", echo(prefix)),
            )
        })?;
        let max_bits = if address.is_ipv4() { 32 } else { 128 };
        if bits > max_bits {
            return Err(ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!("a prefix length of {bits} is too long for this address family"),
            ));
        }
        networks.push((address, bits));
    }
    Ok(hypellm_auth::SourceRestriction::Networks(networks))
}

/// Render a source restriction for a listing.
fn render_source_restriction(source: &hypellm_auth::SourceRestriction) -> Value {
    match source {
        hypellm_auth::SourceRestriction::Any => Value::Null,
        hypellm_auth::SourceRestriction::Addresses(list) => Value::Array(
            list.iter()
                .map(|a| Value::from(a.to_string().as_str()))
                .collect(),
        ),
        hypellm_auth::SourceRestriction::Networks(nets) => Value::Array(
            nets.iter()
                .map(|(a, bits)| Value::from(format!("{a}/{bits}").as_str()))
                .collect(),
        ),
    }
}

/// What a credential probe found.
///
/// Deliberately narrow. A probe result crosses from the data path into a
/// management response, so it carries a verdict, the target it reached, and a
/// *sanitised* provider code — never the provider's message, which
/// specification 10 keeps out of any client-visible surface and which is the
/// field most likely to echo a prompt or an internal hostname.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// Whether the credential was accepted.
    pub ok: bool,
    /// The target the probe was issued against.
    pub target: String,
    /// The upstream error class, when it failed.
    pub class: Option<String>,
    /// The narrowed provider error code, when the provider supplied one.
    pub provider_code: Option<String>,
    /// How long the exchange took.
    pub millis: u64,
}

/// Whether a credential is past its declared rotation interval.
///
/// A credential with **no** recorded rotation is not reported overdue. The
/// audit chain is bounded and starts from whenever this deployment began
/// recording, so "never rotated" and "rotated before the window this router can
/// see" are indistinguishable — and reporting every credential overdue on the
/// first read would train an operator to ignore the field, which is worse than
/// not having it.
///
/// An interval of zero means "no rotation policy" and is never overdue.
#[must_use]
fn is_rotation_overdue(rotated_at: Option<u64>, after_days: u32, now_millis: u64) -> bool {
    if after_days == 0 {
        return false;
    }
    let Some(rotated_at) = rotated_at else {
        return false;
    };
    let interval = u64::from(after_days).saturating_mul(24 * 60 * 60 * 1000);
    now_millis.saturating_sub(rotated_at) > interval
}

/// How many durable pages one export may materialise.
///
/// Specification 3.2 bounds every input, and an export builds its whole answer
/// in memory. At `MAX_AUDIT_PAGE` (500) per page this is 100 000 records, which
/// is a large export and a bounded one. Past it the response says `truncated`
/// rather than stopping quietly.
const MAX_EXPORT_PAGES: usize = 200;

/// How many durable pages one filtered audit query may scan.
///
/// A filter can match nothing for a long stretch of the chain, and without a
/// bound the query would walk the whole log looking. Specification 3.2 bounds
/// every input; this is the bound on how much work one search may cause. When
/// it runs out, the response carries a cursor, so the caller continues rather
/// than being told the history ended.
const MAX_AUDIT_SCAN_PAGES: usize = 20;

/// Specification 22.3 step 20's audit search.
///
/// Every field narrows. There is deliberately no parameter that widens — a
/// query string must not be able to reach another tenant's records, and the
/// tenant filter is applied before any of these.
#[derive(Debug, Default)]
struct AuditFilter {
    actor: Option<String>,
    action: Option<String>,
    since_millis: Option<u64>,
    until_millis: Option<u64>,
    /// Read the durable chain even with no filter, for looking further back
    /// than the in-memory ring holds.
    durable: bool,
}

impl AuditFilter {
    fn from_query(query: Option<&str>) -> Result<Self, ApiError> {
        let params = query_params(query);
        let get = |key: &str| {
            param(&params, key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let millis = |key: &str| -> Result<Option<u64>, ApiError> {
            match get(key) {
                None => Ok(None),
                Some(raw) => raw.parse::<u64>().map(Some).map_err(|_| {
                    ApiError::new(
                        ApiErrorCode::InvalidRequest,
                        format!(
                            "'{key}' must be milliseconds since the epoch, not '{}'",
                            echo(&raw)
                        ),
                    )
                }),
            }
        };

        let filter = Self {
            actor: get("actor"),
            action: get("action"),
            since_millis: millis("since")?,
            until_millis: millis("until")?,
            durable: get("durable").is_some_and(|v| v == "true"),
        };

        if let (Some(since), Some(until)) = (filter.since_millis, filter.until_millis) {
            if since > until {
                return Err(ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    "'since' is after 'until', which can never match",
                ));
            }
        }
        Ok(filter)
    }

    const fn is_empty(&self) -> bool {
        self.actor.is_none()
            && self.action.is_none()
            && self.since_millis.is_none()
            && self.until_millis.is_none()
    }

    fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(actor) = &self.actor {
            if event.actor != *actor {
                return false;
            }
        }
        if let Some(action) = &self.action {
            if event.action.as_str() != action {
                return false;
            }
        }
        if let Some(since) = self.since_millis {
            if event.timestamp_millis < since {
                return false;
            }
        }
        if let Some(until) = self.until_millis {
            if event.timestamp_millis > until {
                return false;
            }
        }
        true
    }
}

/// One audit row, rendered identically whether it came from the ring or the
/// durable chain — so a caller cannot tell which answered, and the two cannot
/// drift into different shapes.
fn render_audit_row(sequence: u64, event: &AuditEvent, link_short: &str) -> Value {
    let mut object = Object::new();
    object.push("sequence", Value::from(sequence));
    object.push(
        "timestamp",
        Value::from(hypellm_core::time::format_rfc3339(event.timestamp_millis)),
    );
    object.push("actor", Value::from(event.actor.as_str()));
    object.push("action", Value::from(event.action.as_str()));
    object.push("outcome", Value::from(event.outcome.as_str()));
    object.push_opt("object", event.object.as_deref().map(Value::from));
    object.push_opt("tenant", event.tenant.as_deref().map(Value::from));
    object.push_opt(
        "reason",
        event.reason.as_ref().map(|r| Value::from(r.as_str())),
    );
    object.push("link", Value::from(link_short));
    Value::Object(object)
}

/// The shortest rollback reason accepted, for the same reason as break-glass:
/// this is the record a post-incident review reads.
const MIN_ROLLBACK_REASON: usize = 8;

/// The shortest break-glass reason accepted.
///
/// Long enough that "x" and "test" do not pass. Specification 22.4 makes
/// break-glass "reason-bound … and reviewed"; a reason nobody can read during a
/// review is the same as no reason.
const MIN_BREAK_GLASS_REASON: usize = 8;
/// The longest, so an audit record stays bounded (specification 3.2).
const MAX_BREAK_GLASS_REASON: usize = 256;

/// What a break-glass sign-in establishes, and for how long.
///
/// Specification 22.4: "Authorized operators use a preprovisioned local
/// break-glass method stored offline. Break-glass access is time-limited,
/// reason-bound, alerting, and reviewed."
#[derive(Debug, Clone)]
pub struct BreakGlassPolicy {
    /// SHA-256 of the domain-separated token. The token is never stored.
    pub verifier: Vec<u8>,
    /// The principal the session authenticates as.
    pub principal: PrincipalId,
    /// The tenant it belongs to.
    pub tenant: TenantId,
    /// The session's absolute lifetime, in milliseconds.
    pub ttl_millis: u64,
}

/// Everything the management API needs.
///
/// Deliberately a distinct type from the router's own state: specification 3
/// separates the management path from the data path, and this crate has no
/// access to the inference pipeline. The shared components arrive as `Arc`s so
/// both planes observe the same configuration and the same audit chain.
#[derive(Debug)]
pub struct AdminState {
    /// The active configuration.
    pub config: Arc<hypellm_store::Activatable<ValidatedConfig>>,
    /// API keys.
    pub keys: Arc<hypellm_auth::KeyStore>,
    /// Management sessions.
    pub sessions: Arc<hypellm_auth::SessionStore>,
    /// Open OIDC transactions.
    pub oidc: Arc<oidc::TransactionStore>,
    /// The OIDC configuration, when sign-in is enabled.
    pub oidc_config: Option<oidc::OidcConfig>,
    /// The identity verifier boundary.
    pub verifier: Option<Arc<dyn oidc::TokenVerifier>>,
    /// Target health, for the overview and for quarantine.
    pub health: Arc<hypellm_core::health::HealthRegistry>,
    /// The durable store, for audit.
    pub store: Arc<Store>,
    /// Metrics and logs.
    pub telemetry: Arc<hypellm_telemetry::Telemetry>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The cross-origin policy.
    pub cors: CorsPolicy,
    /// Recent decision traces.
    pub decisions: Arc<DecisionCache>,
    /// Usage aggregates, for the usage screen.
    pub usage: Arc<UsageAggregate>,
    /// Recent audit events, for the audit view.
    pub audit: Arc<AuditIndex>,
    /// Policy drafts.
    pub drafts: DraftStore,
    /// The next configuration version to assign.
    pub next_version: AtomicU64,
    /// Verifies a break-glass token: the digest, never the token itself.
    ///
    /// `None` disables break-glass entirely, which is what a deployment that
    /// has not preprovisioned one should get — an endpoint that exists but
    /// cannot succeed is an oracle, and one that invents an identity is worse.
    pub break_glass: Option<BreakGlassPolicy>,
    /// Where a rotated provider credential is written.
    ///
    /// `None` in a deployment with no credential store, in which case the
    /// credential endpoints refuse rather than reporting a rotation that did
    /// not happen.
    pub credentials: Option<Arc<dyn CredentialSink>>,
}

/// Somewhere a provider credential can be put.
///
/// Deliberately write-only. Specification 15.3 requires credential values to be
/// "write-only" and specification 5 says the secret is "never returned through
/// management API" — a trait with no read method makes that structural rather
/// than a rule someone has to remember.
///
/// The implementation lives in the router, which owns the secrets directory;
/// the management API only needs to know that storing can succeed or fail.
pub trait CredentialSink: Send + Sync + std::fmt::Debug {
    /// Persist `secret` under `reference`, replacing any previous value.
    ///
    /// Must be durable before returning: a rotation reported as stored but
    /// lost on restart is worse than one that visibly failed.
    fn store(&self, reference: &CredentialRef, secret: Vec<u8>) -> Result<(), String>;

    /// Whether a reference currently resolves.
    fn contains(&self, reference: &CredentialRef) -> bool;

    /// Issue a low-cost probe using `reference` and report what happened.
    ///
    /// Specification 22.2 step 15: "Validate with a low-cost target-safe
    /// probe." Returns `None` when no probe is possible — no target uses the
    /// credential, or the deployment has no data path — which the handler
    /// reports as such rather than as a pass.
    ///
    /// Same boundary as `store` and `drain_connections`, for the same reason:
    /// this crate has no network access, and specification 3 keeps it that way.
    fn probe(&self, _reference: &CredentialRef) -> Option<ProbeOutcome> {
        None
    }

    /// Whether a rotation is still relying on the superseded secret.
    ///
    /// `false` by default, which is the honest answer for a deployment with no
    /// data path: there are no upstream requests, so nothing can be falling
    /// back.
    fn rotation_unaccepted(&self, _reference: &CredentialRef, _now_millis: u64) -> bool {
        false
    }

    /// Close idle pooled connections that were opened under `reference`.
    ///
    /// Specification 22.2 step 17: "Drain/recycle connections whose
    /// authentication is connection-bound." Returns how many were closed.
    ///
    /// This crate cannot do it itself — specification 3 keeps the management
    /// path free of the data path, and `hypellm-admin-api` has no network access
    /// at all — so it travels through the same boundary the secret does.
    ///
    /// Provider authentication in this router is per-request today, so a pooled
    /// socket carries no stale credential and the default is correctly a no-op.
    /// It becomes load-bearing the moment a provider with connection-bound
    /// authentication is added, and the point of wiring it now is that whoever
    /// adds that provider will not have to notice this.
    fn drain_connections(&self, _reference: &CredentialRef) -> usize {
        0
    }
}

impl AdminState {
    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> Arc<ValidatedConfig> {
        self.config.load()
    }
}

/// A management request.
#[derive(Debug)]
pub struct AdminRequest<'a> {
    /// The method.
    pub method: &'a Method,
    /// The exact, undecoded path.
    pub path: &'a str,
    /// The query string, if any.
    pub query: Option<&'a str>,
    /// The headers.
    pub headers: &'a Headers,
    /// The body.
    pub body: &'a [u8],
    /// The peer address.
    pub peer: Option<IpAddr>,
    /// The identifier for this management request.
    pub request_id: String,
}

impl AdminRequest<'_> {
    fn origin(&self) -> Option<&str> {
        self.headers.get("origin")
    }

    fn session_token(&self) -> Option<&str> {
        self.headers
            .get("cookie")
            .and_then(|cookie| session::cookie_value(cookie, session::COOKIE_NAME))
    }

    fn oidc_handle(&self) -> Option<&str> {
        self.headers
            .get("cookie")
            .and_then(|cookie| session::cookie_value(cookie, oidc::TRANSACTION_COOKIE))
    }

    fn csrf(&self) -> Option<&str> {
        self.headers.get(session::CSRF_HEADER)
    }

    fn if_match(&self) -> Option<&str> {
        self.headers.get("if-match")
    }

    fn is_mutating(&self) -> bool {
        !matches!(self.method, Method::Get | Method::Head | Method::Options)
    }

    fn json(&self, limits: &Limits) -> Result<Value, ApiError> {
        parse(self.body, limits).map_err(|e| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!("the request body is not valid JSON ({})", e.kind.code()),
            )
        })
    }
}

/// How many sign-in failures an unauthenticated caller may make durable per
/// window before the rest are aggregated.
///
/// Ten is enough that an operator debugging their own sign-in sees their
/// attempts individually, and small enough that a flood cannot fill the log.
const MAX_ANONYMOUS_AUDITS_PER_WINDOW: u32 = 10;

/// The window those failures are counted over.
const ANONYMOUS_AUDIT_WINDOW_MILLIS: u64 = 60_000;

/// Bounds the durable records an unauthenticated caller can cause.
///
/// The sign-in endpoints run before any session by definition, so an
/// unauthenticated caller who can reach the management listener decides how
/// often they run. Each failure appended a `LoginFailed` audit record, which is
/// an `fsync` under the global store log mutex and a frame that never goes
/// away — specification 3.2 forbids exactly this: "No request may create an
/// unbounded thread, task, buffer, channel, retry loop, **or log entry**."
///
/// The consequence was worse than the write cost. `Log::replay` refuses a log
/// larger than `MAX_LOG_BYTES`, so filling it makes the router unbootable, and
/// the remedy — compaction — discards API keys, the audit chain, and
/// configuration activations (`DI-044`). An unauthenticated flood became a
/// denial of service that survived restart.
///
/// So the *records* are bounded and the *signal* is not: every failure still
/// increments `hypellm_auth_failures_total`, which is O(1) memory, and a window
/// in which anything was suppressed ends with one record saying how many. An
/// operator sees the flood in the metric immediately and in the audit trail
/// exactly once per window, instead of one frame per attacker request.
#[derive(Debug)]
struct AnonymousAuditBudget {
    /// Start of the current window, in wall milliseconds.
    window_start: AtomicU64,
    /// Failures made durable in the current window.
    recorded: AtomicU32,
    /// Failures suppressed in the current window.
    suppressed: AtomicU32,
}

impl AnonymousAuditBudget {
    const fn new() -> Self {
        Self {
            window_start: AtomicU64::new(0),
            recorded: AtomicU32::new(0),
            suppressed: AtomicU32::new(0),
        }
    }

    /// Decide whether this failure becomes a durable record.
    ///
    /// Returns `(record_it, suppressed_in_the_window_just_ended)`. A non-`None`
    /// second element means the caller should write one aggregate record — it
    /// is returned rather than written here so that this type does no I/O and
    /// stays testable without a store.
    fn admit(&self, now_millis: u64) -> (bool, Option<u32>) {
        let start = self.window_start.load(Ordering::SeqCst);
        let mut rolled = None;

        if now_millis.saturating_sub(start) >= ANONYMOUS_AUDIT_WINDOW_MILLIS {
            // `compare_exchange` so that exactly one thread rolls the window
            // and emits its summary. Two threads rolling concurrently would
            // report the same suppressed count twice, which is an audit trail
            // that overstates what happened.
            if self
                .window_start
                .compare_exchange(start, now_millis, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let suppressed = self.suppressed.swap(0, Ordering::SeqCst);
                self.recorded.store(0, Ordering::SeqCst);
                if suppressed > 0 {
                    rolled = Some(suppressed);
                }
            }
        }

        if self.recorded.fetch_add(1, Ordering::SeqCst) < MAX_ANONYMOUS_AUDITS_PER_WINDOW {
            (true, rolled)
        } else {
            // Saturating: a long flood must not wrap the count back to a small
            // number and report a handful of suppressed attempts.
            let _ = self
                .suppressed
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_add(1))
                });
            (false, rolled)
        }
    }
}

/// The management API.
#[derive(Debug)]
pub struct AdminApi {
    state: Arc<AdminState>,
    /// Bounds durable records from unauthenticated OIDC sign-in failures.
    anonymous_audits: AnonymousAuditBudget,
    /// The same bound for break-glass, kept **separate** on purpose.
    ///
    /// A shared budget would let a flood of OIDC callbacks exhaust it and
    /// suppress the break-glass records that followed — an attacker could hide
    /// an attack on the emergency path behind noise on the ordinary one. Two
    /// budgets cost one more record per window and remove that.
    break_glass_audits: AnonymousAuditBudget,
}

impl AdminApi {
    /// Create an API over shared state.
    #[must_use]
    pub const fn new(state: Arc<AdminState>) -> Self {
        Self {
            state,
            anonymous_audits: AnonymousAuditBudget::new(),
            break_glass_audits: AnonymousAuditBudget::new(),
        }
    }

    /// The shared state.
    #[must_use]
    pub fn state(&self) -> &Arc<AdminState> {
        &self.state
    }

    /// Serve a management request.
    ///
    /// The cross-origin grant is applied here, on the way out, rather than at
    /// each handler: a preflight that admits an origin and an actual response
    /// that carries no `Access-Control-Allow-Origin` is a deployment the
    /// browser breaks after the router has already authorized and executed the
    /// request (specification 15.4).
    pub fn handle(&self, request: &AdminRequest<'_>) -> Result<ApiResponse, ApiError> {
        // A preflight already carries the grant, with the method and header
        // lists beside it; adding it twice would emit a duplicate header.
        let grant = if *request.method == Method::Options {
            Vec::new()
        } else {
            self.state.cors.response_headers(request.origin())
        };

        match self.serve(request) {
            Ok(mut response) => {
                response.headers.extend(grant);
                Ok(response)
            }
            // The grant goes on the error too. A browser cannot read a body it
            // was not granted access to, so without this an allowlisted admin
            // origin receives every 401, 403, 412 and 428 as an opaque failure
            // and can only tell the operator that something went wrong.
            //
            // A refused origin is unaffected: `response_headers` returns
            // nothing for an origin the policy does not permit, so this cannot
            // hand a grant to the caller it just turned away.
            Err(mut error) => {
                error.headers.extend(grant);
                Err(error)
            }
        }
    }

    fn serve(&self, request: &AdminRequest<'_>) -> Result<ApiResponse, ApiError> {
        // 1. Origin, before anything else looks at a cookie.
        if *request.method == Method::Options {
            return match self.state.cors.preflight(request.origin()) {
                PreflightOutcome::Allowed(headers) => {
                    let mut response = ApiResponse::no_content();
                    response.headers = headers;
                    Ok(response)
                }
                PreflightOutcome::NotCors => Ok(ApiResponse::no_content()),
                PreflightOutcome::Refused => Err(ApiError::new(
                    ApiErrorCode::OriginNotPermitted,
                    "this origin is not permitted to call the management API",
                )),
            };
        }

        if let Some(origin) = request.origin() {
            if !self.state.cors.permits(origin) {
                return Err(ApiError::new(
                    ApiErrorCode::OriginNotPermitted,
                    "this origin is not permitted to call the management API",
                ));
            }
        }

        // Sign-in endpoints run without a session, by definition.
        match (request.method, request.path) {
            (Method::Post, "/admin/v1/auth/google/start") => return self.oidc_start(request),
            (Method::Get, "/admin/v1/auth/google/callback") => {
                return self.oidc_callback(request);
            }
            // Specification 22.4's recovery path, and the only endpoint that
            // must keep working when the identity provider does not.
            (Method::Post, "/admin/v1/auth/break-glass") => {
                return self.break_glass(request);
            }
            _ => {}
        }

        // 2. Session.
        let token = request
            .session_token()
            .ok_or_else(|| session_error(SessionRejection::Missing))?;
        let session = self
            .state
            .sessions
            .validate(token, self.state.clock.now_millis())
            .map_err(session_error)?;

        // 3. CSRF, for anything state-changing.
        if request.is_mutating() {
            self.state
                .sessions
                .verify_csrf(&session, request.csrf())
                .map_err(session_error)?;
        }

        self.dispatch(request, &session, token)
    }

    fn dispatch(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        token: &str,
    ) -> Result<ApiResponse, ApiError> {
        let path = request.path;

        match (request.method, path) {
            (Method::Get, "/admin/v1/session") => self.session_info(session),
            (Method::Post, "/admin/v1/logout") => self.logout(session, token),

            (Method::Get, "/admin/v1/targets") => self.list_targets(request, session),
            (Method::Get, "/admin/v1/providers") => self.list_providers(session),
            (Method::Get, "/admin/v1/aliases") => self.list_aliases(session),
            (Method::Get, "/admin/v1/overview") => self.overview(session),

            (Method::Get, "/admin/v1/policies") => self.list_drafts(session),
            (Method::Post, "/admin/v1/policies") => self.create_draft(request, session),
            (Method::Post, "/admin/v1/policies:rollback") => self.rollback_policy(request, session),
            (Method::Post, "/admin/v1/policies/active:simulate") => {
                self.simulate_active(request, session)
            }

            (Method::Get, "/admin/v1/keys") => self.list_keys(session),
            (Method::Post, "/admin/v1/keys") => self.create_key(request, session),

            (Method::Get, "/admin/v1/credentials") => self.list_credentials(session),

            (Method::Get, "/admin/v1/access") => self.list_access(session),
            (Method::Get, "/admin/v1/settings") => self.settings_view(session),

            (Method::Get, "/admin/v1/usage") => self.list_usage(session),

            (Method::Get, "/admin/v1/audit") => self.list_audit(request, session),
            (Method::Get, "/admin/v1/audit/export") => self.export_audit(request, session),

            (Method::Post, "/admin/v1/targets") => self.propose_target(request, session),
            (Method::Patch, _) if path.starts_with("/admin/v1/targets/") => {
                let id = suffix(path, "/admin/v1/targets/")?;
                self.patch_target(request, session, &id)
            }
            (Method::Delete, _) if path.starts_with("/admin/v1/keys/") => {
                let id = suffix(path, "/admin/v1/keys/")?;
                self.revoke_key(session, &id)
            }
            (Method::Get, _) if path.starts_with("/admin/v1/decisions/") => {
                let id = suffix(path, "/admin/v1/decisions/")?;
                self.decision(session, &id)
            }
            (Method::Post, _) if path.starts_with("/admin/v1/policies/") => {
                let rest = suffix(path, "/admin/v1/policies/")?;
                let (draft_id, action) = rest.split_once(':').ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCode::NotFound,
                        "no such policy action; expected :validate, :simulate, or :publish",
                    )
                })?;
                match action {
                    "validate" => self.validate_draft(session, draft_id),
                    "simulate" => self.simulate_draft(request, session, draft_id),
                    "publish" => self.publish_draft(request, session, draft_id),
                    _ => Err(ApiError::new(
                        ApiErrorCode::NotFound,
                        "no such policy action",
                    )),
                }
            }
            (Method::Post, _) if path.starts_with("/admin/v1/credentials/") => {
                let rest = suffix(path, "/admin/v1/credentials/")?;
                match rest.split_once(':') {
                    Some((id, "rotate")) => self.rotate_credential(request, session, id),
                    Some((id, "probe")) => self.probe_credential(session, id),
                    _ => Err(ApiError::new(
                        ApiErrorCode::NotFound,
                        "no such credential action",
                    )),
                }
            }
            (Method::Post, "/admin/v1/credentials") => self.create_credential(request, session),

            _ => Err(ApiError::new(ApiErrorCode::NotFound, "no such endpoint")),
        }
    }

    // -- Session ----------------------------------------------------------

    fn session_info(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        let config = self.state.config();
        let permissions: Vec<Value> = session
            .permissions()
            .as_slice()
            .iter()
            .map(|p| Value::from(p.as_str()))
            .collect();

        let mut root = Object::new();
        root.push("principal", Value::from(session.principal.as_str()));
        root.push("tenant", Value::from(session.tenant.as_str()));
        root.push_opt("email", session.email.as_deref().map(Value::from));
        root.push("auth_method", Value::from(session.method.as_str()));
        root.push("permissions", Value::Array(permissions));
        root.push(
            "roles",
            Value::Array(
                session
                    .roles
                    .iter()
                    .map(|r| Value::from(r.as_str()))
                    .collect(),
            ),
        );
        // The CSRF token is delivered here rather than in a cookie, so a page
        // that cannot read it cannot forge a request with it.
        root.push(
            "csrf_token",
            Value::from(self.state.sessions.csrf_for(&session.digest)),
        );
        root.push("config_version", Value::from(config.snapshot.version));
        root.push("config_digest", Value::from(config.digest_short()));
        root.push("break_glass", Value::from(session.is_break_glass()));
        root.push(
            "authenticated_at",
            Value::from(session.authenticated_at_millis),
        );
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    fn logout(&self, session: &Session, token: &str) -> Result<ApiResponse, ApiError> {
        // Specification 22.4 pairs `BreakGlassOpened` with `BreakGlassClosed`,
        // so a review can see the window rather than only its start. An
        // expiring session leaves no record here; the opening record carries
        // the lifetime, which is what bounds the window in that case.
        if session.method == hypellm_auth::AuthMethod::BreakGlass {
            // Not fail-closed: refusing the sign-out because the record could
            // not be written would leave the break-glass session live, which is
            // the worse of the two outcomes.
            let _ = self.record_audit(
                AuditEvent::new(
                    self.state.clock.wall_millis(),
                    session.principal.as_str(),
                    AuditAction::BreakGlassClosed,
                )
                .with_tenant(session.tenant.as_str()),
            );
            self.state.telemetry.log(
                &hypellm_telemetry::Event::critical("auth.break_glass_closed").str_field(
                    hypellm_telemetry::Field::Detail,
                    "a break-glass session was ended",
                ),
            );
        }
        self.state.sessions.invalidate(token);
        Ok(ApiResponse::no_content().with_header(
            "Set-Cookie",
            format!(
                "{}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
                session::COOKIE_NAME
            ),
        ))
    }

    // -- Sign-in ------------------------------------------------------------

    fn oidc_start(&self, request: &AdminRequest<'_>) -> Result<ApiResponse, ApiError> {
        let Some(config) = &self.state.oidc_config else {
            return Err(ApiError::new(
                ApiErrorCode::NotFound,
                "sign-in is not configured",
            ));
        };
        let return_path = request
            .json(&Limits::SMALL)
            .ok()
            .and_then(|v| v.opt_field_str("return_path").ok().flatten().map(str::to_owned))
            .unwrap_or_else(|| "/".to_owned());

        let authorization = self
            .state
            .oidc
            .begin(config, &return_path, self.state.clock.now_millis())
            .map_err(|e| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    format!("cannot start sign-in ({})", e.code()),
                )
            })?;

        let mut root = Object::new();
        root.push("authorization_url", Value::from(authorization.url.as_str()));
        Ok(ApiResponse::ok(&Value::Object(root))
            .with_header("Set-Cookie", authorization.set_cookie_header()))
    }

    fn oidc_callback(&self, request: &AdminRequest<'_>) -> Result<ApiResponse, ApiError> {
        let Some(config) = &self.state.oidc_config else {
            return Err(ApiError::new(
                ApiErrorCode::NotFound,
                "sign-in is not configured",
            ));
        };
        let Some(verifier) = &self.state.verifier else {
            return Err(ApiError::new(
                ApiErrorCode::InternalFault,
                "the identity verifier is not configured",
            ));
        };

        let params = query_params(request.query);
        // A provider error arrives as a parameter rather than a token.
        if params.iter().any(|(k, _)| k == "error") {
            self.audit_login_failure(request, "provider_error");
            return Err(ApiError::new(
                ApiErrorCode::Unauthenticated,
                "the identity provider refused the sign-in",
            ));
        }

        let state_param = param(&params, "state").unwrap_or_default();
        let code = param(&params, "code").unwrap_or_default();

        let transaction = self
            .state
            .oidc
            .take(
                request.oidc_handle(),
                &state_param,
                self.state.clock.now_millis(),
            )
            .map_err(|e| {
                self.audit_login_failure(request, e.code());
                ApiError::new(ApiErrorCode::Unauthenticated, "the sign-in could not be completed")
            })?;

        // The authorization code is redeemed through the platform boundary,
        // which performs the token request and returns the verified claims.
        // This crate never speaks HTTPS (specification 4).
        if code.is_empty() {
            self.audit_login_failure(request, "missing_code");
            return Err(ApiError::new(
                ApiErrorCode::Unauthenticated,
                "the sign-in could not be completed",
            ));
        }

        // The PKCE verifier travels with the code. It was generated when the
        // transaction opened and held server-side ever since; sending it here
        // is what makes an intercepted code useless to anyone who does not
        // also hold the transaction. Passing the raw code to `verify` — as
        // this once did — treated an authorization code as though it were an
        // identity token, so no exchange happened, the verifier was never
        // transmitted, and sign-in could not complete at all.
        let claims = verifier
            .exchange_code(&oidc::CodeExchange {
                code: &code,
                code_verifier: &transaction.code_verifier,
                redirect_uri: &config.redirect_uri,
                client_id: &config.client_id,
                token_endpoint: &config.token_endpoint,
            })
            .map_err(|e| {
                self.audit_login_failure(request, e.code());
                ApiError::new(
                    ApiErrorCode::Unauthenticated,
                    "the sign-in could not be completed",
                )
            })?;

        oidc::validate_claims(
            &claims,
            config,
            &transaction.nonce,
            self.state.clock.wall_millis(),
        )
        .map_err(|e| {
            self.audit_login_failure(request, e.code());
            ApiError::new(ApiErrorCode::Unauthenticated, "the sign-in could not be completed")
        })?;

        // The stable identity is (iss, sub); the local principal is looked up
        // from configuration by that key, never by email.
        let identity = claims.identity_key();
        let config_snapshot = self.state.config();
        let (principal, tenant, roles) = resolve_identity(&config_snapshot, &claims.iss, &claims.sub)
            .ok_or_else(|| {
                self.audit_login_failure(request, "unknown_identity");
                ApiError::new(
                    ApiErrorCode::Forbidden,
                    "this identity is not bound to a principal in this deployment",
                )
            })?;

        let tenant_for_audit = tenant.clone();
        let issued = self
            .state
            .sessions
            .issue(
                principal.clone(),
                tenant,
                Some(identity),
                claims.email.clone(),
                roles,
                hypellm_auth::AuthMethod::Oidc,
                self.state.clock.now_millis(),
            )
            .map_err(|_| {
                ApiError::new(ApiErrorCode::InternalFault, "cannot establish a session")
            })?;

        // Also through `record_audit`, and also carrying the tenant. Appended
        // directly and without one, a successful sign-in was durable but
        // invisible in the audit view — the same defect as DI-051, in the one
        // record a reviewer looks for first.
        let _ = self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                principal.as_str(),
                AuditAction::Login,
            )
            .with_tenant(tenant_for_audit.as_str())
            .with_source(peer_text(request.peer)),
        );

        let mut root = Object::new();
        root.push("return_path", Value::from(transaction.return_path.as_str()));
        root.push("csrf_token", Value::from(issued.csrf_token.as_str()));

        Ok(ApiResponse::ok(&Value::Object(root))
            .with_header(
                "Set-Cookie",
                issued.set_cookie_header(
                    Duration::from_millis(self.state.sessions.policy().absolute_millis).as_secs(),
                ),
            )
            .with_header("Set-Cookie", oidc::AuthorizationRequest::clear_cookie_header()))
    }

    /// Specification 22.4's break-glass sign-in.
    ///
    /// Four properties, each of which the specification names:
    ///
    /// - **Preprovisioned and offline.** The router holds a verifier, not the
    ///   token, so reading the secrets directory does not yield a way in.
    /// - **Time-limited.** The session's absolute lifetime is
    ///   `break_glass_ttl_secs`, independent of the ordinary session lifetime
    ///   and clamped to it.
    /// - **Reason-bound.** A reason is required and recorded. It is not a
    ///   formality: this is the record a review reads afterwards, and an
    ///   optional field would be empty exactly when it mattered.
    /// - **Alerting.** A `critical` log event and an audit record on success,
    ///   and on every failure.
    ///
    /// It is deliberately not tied to the identity provider in any way. The
    /// case this exists for is the provider being unreachable.
    fn break_glass(&self, request: &AdminRequest<'_>) -> Result<ApiResponse, ApiError> {
        let Some(policy) = &self.state.break_glass else {
            // Not "wrong token": a deployment that has not preprovisioned one
            // should not advertise that the endpoint is live.
            return Err(ApiError::new(
                ApiErrorCode::NotFound,
                "break-glass access is not configured",
            ));
        };

        let body = request.json(&Limits::SMALL).map_err(|_| {
            ApiError::new(ApiErrorCode::InvalidRequest, "the request body is not valid JSON")
        })?;
        let token = body
            .opt_field_str("token")
            .ok()
            .flatten()
            .unwrap_or_default();
        let reason = body
            .opt_field_str("reason")
            .ok()
            .flatten()
            .unwrap_or_default()
            .trim()
            .to_owned();

        // Checked before the token, so a caller cannot use a malformed reason
        // to learn whether a token was right.
        if reason.len() < MIN_BREAK_GLASS_REASON || reason.len() > MAX_BREAK_GLASS_REASON {
            self.audit_break_glass_failure(request, policy, "break_glass_reason_missing");
            return Err(ApiError::new(
                ApiErrorCode::InvalidRequest,
                "break-glass access requires a reason of 8 to 256 characters",
            ));
        }

        let presented = hypellm_crypto::sha256::sha256_parts(&[
            b"hypellm/break-glass/v1\0",
            token.as_bytes(),
        ]);
        if !hypellm_crypto::ct::eq(&presented, &policy.verifier) {
            self.audit_break_glass_failure(request, policy, "break_glass_token_invalid");
            // Loud on failure as well as on success: a wrong token here is
            // either an operator with the wrong copy or someone trying the
            // recovery path, and both are worth waking somebody for.
            self.state.telemetry.log(
                &hypellm_telemetry::Event::critical("auth.break_glass_refused")
                    .str_field(hypellm_telemetry::Field::Detail, "a break-glass token was refused"),
            );
            return Err(ApiError::new(
                ApiErrorCode::Unauthenticated,
                "break-glass authentication failed",
            ));
        }

        let config = self.state.config();
        let roles = management_roles_for(&config, &policy.principal);
        if roles.is_empty() {
            // Holding the token proves who you are, not what you may do. A
            // break-glass principal with no `role_binding` gets a session that
            // can do nothing, which is a confusing way to fail during an
            // incident — so say it instead.
            self.audit_break_glass_failure(request, policy, "break_glass_principal_unbound");
            return Err(ApiError::new(
                ApiErrorCode::Forbidden,
                "the break-glass principal has no role binding in this configuration",
            ));
        }

        let issued = self
            .state
            .sessions
            .issue_for(
                policy.principal.clone(),
                policy.tenant.clone(),
                None,
                None,
                roles,
                hypellm_auth::AuthMethod::BreakGlass,
                self.state.clock.now_millis(),
                policy.ttl_millis,
            )
            .map_err(|_| {
                ApiError::new(ApiErrorCode::InternalFault, "cannot establish a session")
            })?;

        // Through `record_audit`, not `append_audit`: the wrapper is what also
        // puts the record in the index the audit view reads. Appending directly
        // leaves the durable chain correct and the screen an operator watches
        // during the incident blank — the DI-051 defect, in a new place.
        //
        // Fails closed (specification 18.3, "security changes fail closed"): a
        // break-glass session that could not be recorded must not be issued,
        // because an unrecorded one is exactly what this mechanism exists to
        // make impossible.
        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                policy.principal.as_str(),
                AuditAction::BreakGlassOpened,
            )
            .with_reason(&reason)
            .with_tenant(policy.tenant.as_str())
            .with_source(peer_text(request.peer)),
        )?;
        self.state.telemetry.log(
            &hypellm_telemetry::Event::critical("auth.break_glass_opened")
                .str_field(hypellm_telemetry::Field::Detail, &reason),
        );

        // Truncating rather than rounding: a cookie that outlives the session
        // it names leaves the browser presenting a token the router has already
        // forgotten, which reads to an operator as a random sign-out.
        let seconds = Duration::from_millis(policy.ttl_millis).as_secs();
        let mut root = Object::new();
        root.push("csrf_token", Value::from(issued.csrf_token.as_str()));
        root.push("expires_in_seconds", Value::from(seconds));
        Ok(ApiResponse::ok(&Value::Object(root))
            .with_header("Set-Cookie", issued.set_cookie_header(seconds)))
    }

    /// A refused break-glass attempt.
    ///
    /// Distinct from `audit_login_failure` for one reason: the tenant is known
    /// here and unknown there. The audit view filters by tenant (Appendix B:
    /// "Management visibility never exceeds the caller's tenant"), so a record
    /// written without one is invisible to every reviewer — and an attempt on
    /// the emergency access path is exactly the record that must not be.
    fn audit_break_glass_failure(
        &self,
        request: &AdminRequest<'_>,
        policy: &BreakGlassPolicy,
        reason: &str,
    ) {
        // Bounded for the same reason as the sign-in path, and more sharply
        // motivated: `POST /admin/v1/auth/break-glass` runs before any session,
        // so an unauthenticated caller decides how often it runs. Filling the
        // durable log through it would make the router unbootable
        // (`Log::replay` refuses past `MAX_LOG_BYTES`) — disabling the
        // emergency recovery path exactly when it is needed. Specification
        // 22.4 calls this "the only endpoint that must keep working when the
        // identity provider does not".
        let now = self.state.clock.wall_millis();
        let (record, suppressed) = self.break_glass_audits.admit(now);

        if let Some(count) = suppressed {
            let _ = self.record_audit(
                AuditEvent::new(now, "anonymous", AuditAction::LoginFailed)
                    .with_outcome(AuditOutcome::Denied)
                    .with_reason("further_failures_suppressed")
                    .with_tenant(policy.tenant.as_str())
                    .with_source(&format!(
                        "{count} further break-glass failures in the last window"
                    )),
            );
        }

        if record {
            let _ = self.record_audit(
                AuditEvent::new(now, "anonymous", AuditAction::LoginFailed)
                    .with_outcome(AuditOutcome::Denied)
                    .with_reason(reason)
                    .with_tenant(policy.tenant.as_str())
                    .with_source(peer_text(request.peer)),
            );
        }
        self.state.telemetry.count(
            hypellm_telemetry::names::AUTH_FAILURES,
            "Authentication failures.",
            &hypellm_telemetry::Labels::new()
                .with(hypellm_telemetry::LabelName::Listener, "admin")
                .with(hypellm_telemetry::LabelName::Reason, reason),
        );
    }

    fn audit_login_failure(&self, request: &AdminRequest<'_>, reason: &str) {
        let now = self.state.clock.wall_millis();
        // Bounded, because an unauthenticated caller decides how often this
        // runs (specification 3.2: no request may create an unbounded log
        // entry). The metric below is incremented unconditionally, so
        // suppressing the record never suppresses the signal.
        let (record, suppressed) = self.anonymous_audits.admit(now);

        if let Some(count) = suppressed {
            let _ = self.state.store.append_audit(
                AuditEvent::new(now, "anonymous", AuditAction::LoginFailed)
                    .with_outcome(AuditOutcome::Denied)
                    .with_reason("further_failures_suppressed")
                    .with_source(&format!("{count} further sign-in failures in the last window")),
            );
        }

        if record {
            let _ = self.state.store.append_audit(
                AuditEvent::new(now, "anonymous", AuditAction::LoginFailed)
                    .with_outcome(AuditOutcome::Denied)
                    .with_reason(reason)
                    .with_source(peer_text(request.peer)),
            );
        }
        self.state.telemetry.count(
            hypellm_telemetry::names::AUTH_FAILURES,
            "Authentication failures.",
            &hypellm_telemetry::Labels::new()
                .with(hypellm_telemetry::LabelName::Listener, "admin")
                .with(hypellm_telemetry::LabelName::Reason, reason),
        );
    }

    // -- Read endpoints -----------------------------------------------------

    fn list_targets(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadSummary)?;
        let config = self.state.config();
        let page = Pagination::from_query(request.query);

        // Appendix B: "Management visibility never exceeds the caller's tenant
        // and permissions." A target is reachable by this caller only through
        // an alias their tenant is authorized for, so the listing is filtered by
        // exactly the authorization the data plane applies to `GET /v1/models`.
        let visible = visible_targets(&config, session);
        let targets: Vec<&hypellm_core::target::Target> = config
            .snapshot
            .targets
            .values()
            .filter(|target| visible.contains(&target.id))
            .collect();
        let (window, cursor) = page.apply(&targets, |t| t.id.as_str());

        let items: Vec<Value> = window
            .iter()
            .map(|target| self.render_target(target))
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, cursor)))
    }

    /// The part of a target that `If-Match` is compared against.
    ///
    /// Its configuration and its administrative state, and nothing else. The
    /// live counters belong in the listing but not in the tag: a precondition
    /// that goes stale because the target served a request would refuse the
    /// drain issued to relieve the load that made it stale.
    fn target_representation(&self, target: &hypellm_core::target::Target) -> Value {
        let mut object = Object::new();
        object.push("id", Value::from(target.id.as_str()));
        object.push("provider", Value::from(target.provider_id.as_str()));
        object.push("model", Value::from(target.native_model.as_str()));
        object.push("state", Value::from(self.effective_state(target).as_str()));
        object.push("local", Value::from(target.is_local));
        object.push("cost_class", Value::from(u64::from(target.cost_class.0)));
        object.push_opt(
            "residency",
            target.residency.as_ref().map(|r| Value::from(r.as_str())),
        );
        object.push(
            "quarantined",
            Value::from(self.state.health.is_quarantined(&target.id)),
        );
        object.push("capabilities", capabilities_value(&target.capabilities));
        Value::Object(object)
    }

    /// The entity tag a target's update will demand.
    fn target_etag(&self, target: &hypellm_core::target::Target) -> String {
        etag_for(&self.target_representation(target))
    }

    /// The administrative state now in force.
    ///
    /// The operator override lives in the health registry, not in the immutable
    /// policy snapshot, so a listing that reported `Target::admin_state` would
    /// show a target an operator had just drained as `enabled`.
    fn effective_state(&self, target: &hypellm_core::target::Target) -> TargetAdminState {
        self.state
            .health
            .admin_state(&target.id)
            .unwrap_or(target.admin_state)
    }

    /// A target's breaker state per operation, and the worst of them.
    ///
    /// "Worst" is `Open` over `HalfOpen` over `Closed`: an operator asking
    /// whether a target is healthy is asking whether *anything* about it is
    /// broken, and the safe direction to be wrong in is to say degraded when
    /// one operation is degraded. `targets_healthy` counts on the same rule, so
    /// the overview and the target list cannot disagree.
    fn breaker_states(
        &self,
        target: &TargetId,
        now: u64,
    ) -> (hypellm_core::health::BreakerState, Object) {
        use hypellm_core::health::BreakerState;

        let mut worst = BreakerState::Closed;
        let mut map = Object::new();
        for operation in Operation::all() {
            let state = self
                .state
                .health
                .entry(target, *operation)
                .breaker
                .state(now);
            map.push(operation.as_str(), Value::from(state.as_str()));
            worst = match (worst, state) {
                (BreakerState::Open, _) | (_, BreakerState::Open) => BreakerState::Open,
                (BreakerState::HalfOpen, _) | (_, BreakerState::HalfOpen) => {
                    BreakerState::HalfOpen
                }
                _ => BreakerState::Closed,
            };
        }
        (worst, map)
    }

    fn render_target(&self, target: &hypellm_core::target::Target) -> Value {
        let now = self.state.clock.now_millis();
        let health = self.state.health.entry(&target.id, Operation::Chat);
        let (worst_state, per_operation) = self.breaker_states(&target.id, now);

        let mut object = Object::new();
        object.push("id", Value::from(target.id.as_str()));
        object.push("provider", Value::from(target.provider_id.as_str()));
        object.push("model", Value::from(target.native_model.as_str()));
        object.push("state", Value::from(self.effective_state(target).as_str()));
        object.push("local", Value::from(target.is_local));
        object.push("cost_class", Value::from(u64::from(target.cost_class.0)));
        object.push_opt(
            "residency",
            target.residency.as_ref().map(|r| Value::from(r.as_str())),
        );
        // The *worst* state across operations, not the chat one. Health is
        // tracked per `(target, operation)`, and reading only chat reported a
        // target failing on embeddings or tokenize as `closed` — "the target is
        // fine" during exactly the outage this screen exists for. The
        // per-operation map is alongside it, so the summary is never the only
        // answer available.
        object.push("breaker_state", Value::from(worst_state.as_str()));
        object.push("breaker_state_by_operation", Value::Object(per_operation));
        object.push("in_flight", Value::from(u64::from(health.in_flight())));
        object.push("total_requests", Value::from(health.total_requests()));
        object.push("total_failures", Value::from(health.total_failures()));
        object.push(
            "quarantined",
            Value::from(self.state.health.is_quarantined(&target.id)),
        );
        // Disclosed so a client can satisfy `If-Match` from a read, rather than
        // reimplementing the server's canonical-JSON digest or falling back to
        // `*` — which would defeat the concurrency control of 15.4.
        object.push("etag", Value::from(self.target_etag(target)));

        object.push("capabilities", capabilities_value(&target.capabilities));
        Value::Object(object)
    }

    fn list_providers(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadSummary)?;
        let config = self.state.config();

        // Appendix B: "Management visibility never exceeds the caller's tenant
        // and permissions." A provider is visible only if it backs a target the
        // caller's tenant can actually reach — the same derivation
        // `list_targets` uses and the same one `GET /v1/models` applies on the
        // data plane.
        //
        // This listing carries endpoint hostnames and credential *references*,
        // so an unscoped one told every tenant which providers the deployment
        // uses, where they live, and what their credentials are called. An
        // operator whose tenant is granted the alias still sees all of it; only
        // providers their tenant cannot reach at all are hidden, and an
        // operator who cannot reach a provider has nothing to operate on it
        // with.
        let visible = visible_targets(&config, session);
        let reachable: std::collections::BTreeSet<&hypellm_core::ids::ProviderId> = config
            .snapshot
            .targets
            .values()
            .filter(|target| visible.contains(&target.id))
            .map(|target| &target.provider_id)
            .collect();

        let items: Vec<Value> = config
            .snapshot
            .providers
            .values()
            .filter(|provider| reachable.contains(&provider.id))
            .map(|provider| {
                let mut object = Object::new();
                object.push("id", Value::from(provider.id.as_str()));
                object.push("family", Value::from(provider.family.as_str()));
                object.push("enabled", Value::from(provider.enabled));
                object.push("egress_profile", Value::from(provider.egress_profile.as_str()));
                // The credential *reference* is shown; the secret is not
                // reachable through any endpoint (specification 9.3).
                object.push_opt(
                    "credential_ref",
                    provider
                        .credential_ref
                        .as_ref()
                        .map(|c| Value::from(c.as_str())),
                );
                let endpoints: Vec<Value> = provider
                    .endpoints
                    .iter()
                    .map(|endpoint| {
                        let mut e = Object::new();
                        e.push("scheme", Value::from(endpoint.scheme.as_str()));
                        e.push("host", Value::from(endpoint.host.as_str()));
                        e.push("port", Value::from(u64::from(endpoint.port)));
                        e.push("base_path", Value::from(endpoint.base_path.as_str()));
                        Value::Object(e)
                    })
                    .collect();
                object.push("endpoints", Value::Array(endpoints));
                Value::Object(object)
            })
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, None)))
    }

    fn list_aliases(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadSummary)?;
        let config = self.state.config();

        // Scoped like the targets it names. An alias the caller's tenant holds
        // no grant for is not theirs to see, and listing it would also disclose
        // the target set behind it.
        let visible = visible_targets(&config, session);
        let items: Vec<Value> = config
            .snapshot
            .aliases
            .values()
            .filter(|alias| {
                alias
                    .permitted_targets
                    .iter()
                    .any(|target| visible.contains(target))
            })
            .map(|alias| {
                let mut object = Object::new();
                object.push("id", Value::from(alias.id.as_str()));
                object.push_opt(
                    "description",
                    alias.description.as_deref().map(Value::from),
                );
                object.push(
                    "family_failover",
                    Value::from(alias.allow_family_failover),
                );
                object.push(
                    "targets",
                    Value::Array(
                        alias
                            .permitted_targets
                            .iter()
                            .map(|t| Value::from(t.as_str()))
                            .collect(),
                    ),
                );
                Value::Object(object)
            })
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, None)))
    }

    fn overview(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadSummary)?;
        let config = self.state.config();
        let now = self.state.clock.now_millis();

        // Counted over what this caller can see, so the overview and the target
        // list agree. An unscoped count told a viewer in one tenant how large
        // the deployment is and how much of it is broken — neither of which is
        // theirs to know (Appendix B), and the `tenants` field below was
        // already narrowed for exactly that reason.
        let visible = visible_targets(&config, session);
        let reachable_providers: std::collections::BTreeSet<&hypellm_core::ids::ProviderId> = config
            .snapshot
            .targets
            .values()
            .filter(|target| visible.contains(&target.id))
            .map(|target| &target.provider_id)
            .collect();
        let visible_aliases = config
            .snapshot
            .aliases
            .values()
            .filter(|alias| {
                alias
                    .permitted_targets
                    .iter()
                    .any(|target| visible.contains(target))
            })
            .count();

        let mut healthy = 0u64;
        let mut degraded = 0u64;
        for id in config.snapshot.targets.keys().filter(|id| visible.contains(id)) {
            let (worst, _) = self.breaker_states(id, now);
            if worst == hypellm_core::health::BreakerState::Closed
                && !self.state.health.is_quarantined(id)
            {
                healthy += 1;
            } else {
                degraded += 1;
            }
        }

        let mut root = Object::new();
        root.push("config_version", Value::from(config.snapshot.version));
        root.push("config_digest", Value::from(config.digest_short()));
        root.push("targets_total", Value::from(visible.len()));
        root.push("targets_healthy", Value::from(healthy));
        root.push("targets_degraded", Value::from(degraded));
        root.push("aliases", Value::from(visible_aliases));
        root.push("providers", Value::from(reachable_providers.len()));
        // A session is scoped to exactly one tenant, so the router-wide count is
        // not the caller's to know: reporting it told a viewer in one tenant how
        // many others the router serves (Appendix B). When a platform-scope role
        // exists, that is where the true count belongs.
        root.push(
            "tenants",
            Value::from(u64::from(
                config.tenants.contains_key(&session.tenant),
            )),
        );
        root.push(
            "audit_head",
            Value::from(
                hypellm_crypto::Digest::from_bytes(self.state.store.audit_head()).short(),
            ),
        );
        root.push("audit_records", Value::from(self.state.store.audit_count()));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    fn decision(&self, session: &Session, raw_id: &str) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadDecisionTraces)?;
        let request_id = RequestId::parse(raw_id).map_err(|_| {
            ApiError::new(ApiErrorCode::InvalidRequest, "malformed request identifier")
        })?;

        let stored = self
            .state
            .decisions
            .get(request_id, &session.tenant)
            .ok_or_else(|| ApiError::not_found("decision trace"))?;

        let trace = &stored.trace;
        let mut root = Object::new();
        root.push("request_id", Value::from(trace.request_id.to_string()));
        root.push("policy_digest", Value::from(trace.policy_digest.short()));
        root.push("pinned", Value::from(trace.pinned));
        root.push("routing_micros", Value::from(trace.routing_micros));
        root.push_opt(
            "chosen",
            trace.chosen.as_ref().map(|t| Value::from(t.as_str())),
        );
        root.push("explanation", Value::from(trace.explain()));

        root.push(
            "candidates",
            Value::Array(
                trace
                    .candidates
                    .iter()
                    .map(|candidate| {
                        let mut object = Object::new();
                        object.push("target", Value::from(candidate.target.as_str()));
                        object.push("rank", Value::from(u64::from(candidate.rank)));
                        object.push("score", Value::from(candidate.score()));
                        let terms = &candidate.terms;
                        let mut breakdown = Object::new();
                        breakdown.push("priority_rank", Value::from(terms.priority_rank));
                        breakdown.push("policy_weight", Value::from(terms.policy_weight));
                        breakdown.push("health", Value::from(terms.health));
                        breakdown.push("latency", Value::from(terms.latency));
                        breakdown.push("queue", Value::from(terms.queue));
                        breakdown.push("cost", Value::from(terms.cost));
                        breakdown.push("locality", Value::from(terms.locality));
                        breakdown.push("affinity", Value::from(terms.affinity));
                        breakdown.push("jitter", Value::from(terms.jitter));
                        object.push("terms", Value::Object(breakdown));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );

        root.push(
            "exclusions",
            Value::Array(
                trace
                    .exclusions
                    .iter()
                    .map(|exclusion| {
                        let mut object = Object::new();
                        object.push("target", Value::from(exclusion.target.as_str()));
                        object.push("reason", Value::from(exclusion.reason.code()));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );

        root.push(
            "attempts",
            Value::Array(
                trace
                    .attempts
                    .iter()
                    .map(|attempt| {
                        let mut object = Object::new();
                        object.push("target", Value::from(attempt.target.as_str()));
                        object.push("sequence", Value::from(u64::from(attempt.sequence)));
                        object.push("outcome", Value::from(attempt.outcome.code()));
                        object.push_opt(
                            "error_class",
                            attempt
                                .outcome
                                .error_class()
                                .map(|c| Value::from(c.as_str())),
                        );
                        object.push_opt(
                            "first_byte_millis",
                            attempt.first_byte_millis.map(Value::from),
                        );
                        object.push("total_millis", Value::from(attempt.total_millis));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );

        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    /// Usage totals visible to this caller.
    ///
    /// Specification 15.3: "Per **authorized scope**, model/alias, operation,
    /// status, cost class; no prompt bodies by default." The authorized scope
    /// is the whole distinction between the two usage permissions:
    /// `ReadTenantUsage` returns every principal in the tenant, `ReadOwnUsage`
    /// returns only the caller's own rows, and neither ever crosses a tenant
    /// boundary. The scope actually applied is reported in the response, so a
    /// viewer cannot mistake their own totals for the tenant's.
    fn list_usage(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        let tenant_wide = self.require(session, Permission::ReadTenantUsage).is_ok();
        if !tenant_wide {
            self.require(session, Permission::ReadOwnUsage)?;
        }
        let filter = if tenant_wide {
            None
        } else {
            Some(&session.principal)
        };

        let config = self.state.config();
        let now = self.state.clock.wall_millis();
        let rows = self.state.usage.rows(&session.tenant, filter);
        let items: Vec<Value> = rows
            .iter()
            .map(|row| {
                let mut object = Object::new();
                object.push_opt(
                    "principal",
                    row.key.principal.as_ref().map(|p| Value::from(p.as_str())),
                );
                object.push_opt(
                    "alias",
                    row.key.alias.as_ref().map(|a| Value::from(a.as_str())),
                );
                object.push_opt(
                    "target",
                    row.key.target.as_ref().map(|t| Value::from(t.as_str())),
                );
                object.push("operation", Value::from(row.key.operation.as_str()));
                object.push("status", Value::from(row.key.status.as_str()));
                object.push("cost_class", Value::from(u64::from(row.key.cost_class)));
                object.push("requests", Value::from(row.totals.requests));
                object.push("input_tokens", Value::from(row.totals.input_tokens));
                object.push("output_tokens", Value::from(row.totals.output_tokens));
                object.push(
                    "cached_input_tokens",
                    Value::from(row.totals.cached_input_tokens),
                );
                object.push(
                    "reasoning_tokens",
                    Value::from(row.totals.reasoning_tokens),
                );
                // Specification 14 requires provider-reported and
                // router-estimated numbers to be distinguishable; a screen that
                // hid the difference would let an estimate read as a bill.
                object.push(
                    "estimated_requests",
                    Value::from(row.totals.estimated_requests),
                );
                object.push("aggregated", Value::from(row.key.is_overflow()));
                // Specification 25's price schedule, reported as an *estimate*
                // and never as an amount owed — a billing system is among the
                // things the specification says this router is not, and the
                // token counts feeding this are themselves sometimes router
                // estimates (`estimated_requests` above says how many). An
                // estimate multiplied by a price is
                // doubly an estimate, and a screen that presented it as a bill
                // would be the wrong artefact entirely.
                if let Some(price) = row.key.target.as_ref().and_then(|target| {
                    hypellm_config::price_in_effect(&config.prices, target, now)
                }) {
                    let mut cost = Object::new();
                    cost.push(
                        "estimated_minor_units",
                        Value::from(price.cost_minor_units(
                            row.totals.input_tokens,
                            row.totals.output_tokens,
                            row.totals.cached_input_tokens,
                        )),
                    );
                    cost.push("currency", Value::from(price.currency.as_str()));
                    object.push("estimated_cost", Value::Object(cost));
                }
                Value::Object(object)
            })
            .collect();

        let summary = self.state.usage.summary(&session.tenant, filter);
        let mut totals = Object::new();
        totals.push("requests", Value::from(summary.requests));
        totals.push("input_tokens", Value::from(summary.input_tokens));
        totals.push("output_tokens", Value::from(summary.output_tokens));
        totals.push(
            "cached_input_tokens",
            Value::from(summary.cached_input_tokens),
        );
        totals.push("reasoning_tokens", Value::from(summary.reasoning_tokens));
        totals.push(
            "estimated_requests",
            Value::from(summary.estimated_requests),
        );

        // Specification 22.3 step 20's usage-by-key. Only for a caller who may
        // read the whole tenant's usage: a per-key breakdown of a tenant is not
        // something a principal-scoped reader is entitled to, and would let one
        // service account enumerate the others' keys.
        let by_key: Vec<Value> = if tenant_wide {
            self.state
                .usage
                .keys(&session.tenant)
                .iter()
                .map(|(key, totals)| {
                    let mut object = Object::new();
                    object.push("key_id", Value::from(key.as_str()));
                    object.push("requests", Value::from(totals.requests));
                    object.push("input_tokens", Value::from(totals.input_tokens));
                    object.push("output_tokens", Value::from(totals.output_tokens));
                    object.push(
                        "estimated_requests",
                        Value::from(totals.estimated_requests),
                    );
                    Value::Object(object)
                })
                .collect()
        } else {
            Vec::new()
        };

        let mut envelope = Object::new();
        envelope.push("object", Value::from("list"));
        envelope.push("data", Value::Array(items));
        envelope.push("by_key", Value::Array(by_key));
        envelope.push(
            "scope",
            Value::from(if tenant_wide { "tenant" } else { "principal" }),
        );
        envelope.push("tenant", Value::from(session.tenant.as_str()));
        envelope.push("since", Value::from(self.state.usage.since_millis()));
        // When the series bound is reached some rows are folded into an
        // unattributed remainder. Saying so is the difference between an
        // incomplete breakdown and a wrong one.
        envelope.push("truncated", Value::from(self.state.usage.is_saturated()));
        envelope.push("totals", Value::Object(totals));
        Ok(ApiResponse::ok(&Value::Object(envelope)))
    }

    /// Specification 16's cursor-paginated authorized audit records, with
    /// specification 22.3 step 20's search.
    ///
    /// Reads the **durable chain** when the caller asks for a filter or a
    /// deeper page, and the in-memory ring otherwise. The ring is a bounded
    /// 2 048-record cache that starts empty on every restart: right for a
    /// screen showing recent activity, wrong for an investigation, which is
    /// exactly the case that needs to look further back than the ring holds and
    /// across the restart that may have been part of the incident.
    ///
    /// Filters are `actor`, `action`, `since`, and `until`. They are applied
    /// *after* the tenant filter, never instead of it — Appendix B:
    /// "Management visibility never exceeds the caller's tenant and
    /// permissions", and a search parameter that could widen that would be a
    /// cross-tenant read with a query string.
    fn list_audit(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ReadAudit)?;
        let page = Pagination::from_query(request.query);
        let filter = AuditFilter::from_query(request.query)?;

        // A filtered or explicitly deep read goes to the durable chain; the
        // default view stays on the hot ring.
        if filter.is_empty() && !filter.durable {
            let records = self
                .state
                .audit
                .recent_for_tenant(session.tenant.as_str(), usize::MAX);
            let keyed: Vec<(String, &crate::audit_index::IndexedAudit)> = records
                .iter()
                .map(|record| (record.sequence.to_string(), record))
                .collect();
            let (window, cursor) = page.apply(&keyed, |(key, _)| key.as_str());
            let items = window
                .iter()
                .map(|(_, record)| {
                    render_audit_row(
                        record.sequence,
                        &record.event,
                        record.link_short.as_str(),
                    )
                })
                .collect();
            return Ok(ApiResponse::ok(&self.audit_envelope(items, cursor)));
        }

        {
            let before = page
                .after
                .as_deref()
                .and_then(|cursor| cursor.parse::<u64>().ok());
            let mut collected: Vec<Value> = Vec::new();
            let mut cursor = before;
            // The durable read pages backwards through the chain; a page whose
            // records are mostly another tenant's would otherwise come back
            // nearly empty and look like the end of the history.
            for _ in 0..MAX_AUDIT_SCAN_PAGES {
                let batch = self
                    .state
                    .store
                    .audit_records(cursor, hypellm_store::MAX_AUDIT_PAGE)
                    .map_err(|_| {
                        ApiError::new(
                            ApiErrorCode::InternalFault,
                            "the durable audit chain could not be read",
                        )
                    })?;
                if batch.is_empty() {
                    break;
                }
                cursor = batch.last().map(|(sequence, _)| *sequence);
                for (sequence, record) in &batch {
                    if record.event.tenant.as_deref() != Some(session.tenant.as_str()) {
                        continue;
                    }
                    if !filter.matches(&record.event) {
                        continue;
                    }
                    collected.push(render_audit_row(
                        *sequence,
                        &record.event,
                        &hypellm_crypto::Digest::from_bytes(record.link()).short(),
                    ));
                    if collected.len() >= page.limit {
                        break;
                    }
                }
                if collected.len() >= page.limit {
                    break;
                }
            }
            let next = (collected.len() >= page.limit)
                .then(|| cursor.map(|c| c.to_string()))
                .flatten();
            Ok(ApiResponse::ok(&self.audit_envelope(collected, next)))
        }
    }

    /// Specification 11.2's export to immutable storage.
    ///
    /// Emits the durable chain — not the in-memory ring, which starts empty on
    /// every restart — together with every checkpoint that verifies under the
    /// store MAC key. The checkpoints are the point: `AuditRecord::link` is
    /// unkeyed SHA-256, so the chain proves *ordering and continuity* and the
    /// checkpoints are what prove authorship. An export of records without them
    /// would be a document anyone could produce.
    ///
    /// Tenant-scoped like every other management read (Appendix B). An operator
    /// exporting "the audit trail" gets their tenant's, and the envelope says
    /// so, because an export that silently omits records is worse evidence than
    /// one that states its scope.
    ///
    /// The export itself is audited. Specification 17 lists it as an audited
    /// action, and `AuditAction::AuditExported` has existed without a producer
    /// since the vocabulary was written.
    fn export_audit(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ExportAudit)?;
        let filter = AuditFilter::from_query(request.query)?;

        let mut records: Vec<Value> = Vec::new();
        let mut cursor: Option<u64> = None;
        let mut truncated = false;
        for page in 0.. {
            if page >= MAX_EXPORT_PAGES {
                truncated = true;
                break;
            }
            let batch = self
                .state
                .store
                .audit_records(cursor, hypellm_store::MAX_AUDIT_PAGE)
                .map_err(|_| {
                    ApiError::new(
                        ApiErrorCode::InternalFault,
                        "the durable audit chain could not be read",
                    )
                })?;
            if batch.is_empty() {
                break;
            }
            cursor = batch.last().map(|(sequence, _)| *sequence);
            for (sequence, record) in &batch {
                if record.event.tenant.as_deref() != Some(session.tenant.as_str()) {
                    continue;
                }
                if !filter.matches(&record.event) {
                    continue;
                }
                records.push(render_audit_row(
                    *sequence,
                    &record.event,
                    &hypellm_crypto::Digest::from_bytes(record.link()).short(),
                ));
            }
        }
        // Oldest first: an export is read as a history, not as a screen.
        records.reverse();

        let checkpoints: Vec<Value> = self
            .state
            .store
            .checkpoints()
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the audit checkpoints could not be read",
                )
            })?
            .iter()
            .map(|checkpoint| {
                let mut object = Object::new();
                object.push("sequence", Value::from(checkpoint.sequence));
                object.push(
                    "link",
                    Value::from(
                        hypellm_crypto::Digest::from_bytes(checkpoint.link).to_hex(),
                    ),
                );
                object.push(
                    "timestamp",
                    Value::from(hypellm_core::time::format_rfc3339(
                        checkpoint.timestamp_millis,
                    )),
                );
                object.push(
                    "mac",
                    Value::from(hypellm_crypto::Digest::from_bytes(checkpoint.mac).to_hex()),
                );
                Value::Object(object)
            })
            .collect();

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::AuditExported,
            )
            .with_tenant(session.tenant.as_str())
            .with_reason(&format!("{} record(s)", records.len()))
            .with_source(peer_text(request.peer)),
        )?;

        let mut root = Object::new();
        root.push("object", Value::from("audit_export"));
        root.push("tenant", Value::from(session.tenant.as_str()));
        root.push("records", Value::Array(records));
        // Without these the export proves ordering and nothing else: the chain
        // link is unkeyed, so only a checkpoint carries a MAC.
        root.push("checkpoints", Value::Array(checkpoints));
        root.push(
            "chain_head",
            Value::from(
                hypellm_crypto::Digest::from_bytes(self.state.store.audit_head()).to_hex(),
            ),
        );
        root.push("chain_length", Value::from(self.state.store.audit_count()));
        // Stated rather than implied. An export that quietly stopped early is
        // evidence of the wrong thing.
        root.push("truncated", Value::from(truncated));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    fn audit_envelope(&self, items: Vec<Value>, cursor: Option<String>) -> Value {
        let mut envelope = Object::new();
        envelope.push("object", Value::from("list"));
        envelope.push("data", Value::Array(items));
        envelope.push("has_more", Value::from(cursor.is_some()));
        envelope.push_opt("next_cursor", cursor.map(|c| Value::from(c.as_str())));
        envelope.push(
            "chain_head",
            Value::from(
                hypellm_crypto::Digest::from_bytes(self.state.store.audit_head()).to_hex(),
            ),
        );
        envelope.push("chain_length", Value::from(self.state.store.audit_count()));
        Value::Object(envelope)
    }

    // -- Targets ------------------------------------------------------------

    fn patch_target(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        raw_id: &str,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::OperateTargets)?;
        let target_id = TargetId::new(raw_id).map_err(|_| ApiError::not_found("target"))?;

        let config = self.state.config();
        let target = config
            .snapshot
            .targets
            .get(&target_id)
            .ok_or_else(|| ApiError::not_found("target"))?;

        if_match_satisfied(request.if_match(), &self.target_etag(target))?;

        let body = request.json(&Limits::SMALL)?;
        let desired = body.field_str("state").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a target update requires a 'state'",
            )
        })?;
        let reason = body.opt_field_str("reason").ok().flatten();

        let (action, audit_action) = match desired {
            "enabled" => (TargetAdminState::Enabled, AuditAction::TargetStateChanged),
            "draining" => (TargetAdminState::Draining, AuditAction::TargetStateChanged),
            "maintenance" => (
                TargetAdminState::Maintenance,
                AuditAction::TargetStateChanged,
            ),
            "quarantined" => (
                TargetAdminState::Quarantined,
                AuditAction::TargetQuarantined,
            ),
            "disabled" => (TargetAdminState::Disabled, AuditAction::TargetStateChanged),
            other => {
                return Err(ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    format!("unknown target state '{}'", echo(other)),
                ));
            }
        };

        // Quarantine is a stronger action with its own permission and a
        // mandatory reason (specification 13).
        let quarantining = action == TargetAdminState::Quarantined;
        let until = if quarantining {
            self.require(session, Permission::QuarantineTargets)?;
            if reason.is_none_or(|r| r.trim().is_empty()) {
                return Err(ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    "quarantining a target requires a reason",
                ));
            }
            // Bounded and saturating. The release profile sets
            // `overflow-checks = true` with `panic = "abort"`, so
            // `now + duration * 1000` on an unbounded `duration_seconds` is not
            // a wrong answer — it is a management request that kills the
            // process. Specification 3.2 also forbids any unbounded value
            // originating from a request.
            //
            // The ceiling is a quarter and not `u64::MAX`, because a
            // quarantine is an incident action with a "reason, actor,
            // expiry/review time" (specification 13). One that expires after
            // the heat death of the universe is an indefinite disable wearing
            // a quarantine's clothes, and it should be spelled `disabled`.
            const MAX_QUARANTINE_SECONDS: u64 = 90 * 24 * 60 * 60;

            let requested = body
                .opt_field_i64("duration_seconds")
                .ok()
                .flatten()
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(3600);

            if requested > MAX_QUARANTINE_SECONDS {
                return Err(ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    format!(
                        "duration_seconds must be at most {MAX_QUARANTINE_SECONDS}; \
                         use state=disabled for an indefinite removal"
                    ),
                ));
            }

            Some(
                self.state
                    .clock
                    .wall_millis()
                    .saturating_add(requested.saturating_mul(1000)),
            )
        } else {
            if target.admin_state == TargetAdminState::Quarantined
                || self.state.health.is_quarantined(&target_id)
            {
                // Lifting a quarantine is itself a quarantine-level action.
                self.require(session, Permission::QuarantineTargets)?;
            }
            None
        };

        // The durable record first, then the change. Specification 18.3 makes
        // security changes fail closed, and this handler answers a failed append
        // with "the action could not be recorded durably and was not applied" —
        // which was untrue while the override was applied first, leaving a
        // target out of rotation with no audit trail behind it.
        let mut event = AuditEvent::new(
            self.state.clock.wall_millis(),
            session.principal.as_str(),
            audit_action,
        )
        .with_object(target_id.as_str())
        .with_tenant(session.tenant.as_str());
        if let Some(reason) = reason {
            event = event.with_reason(reason);
        }
        self.record_audit(event)?;

        if let Some(until) = until {
            self.state.health.quarantine(&target_id, until);
        } else {
            if self.state.health.is_quarantined(&target_id) {
                self.state.health.release_quarantine(&target_id);
            }
            // Apply the state. This handler previously wrote an audit record
            // and returned `{"state": desired}` without changing anything for
            // drain, maintenance, and disable: the configured state lives in
            // the immutable policy snapshot, so an operator draining a target
            // was told it had worked while traffic kept arriving.
            self.state
                .health
                .set_admin_state(&target_id, Some(action));
        }

        let mut root = Object::new();
        root.push("id", Value::from(target_id.as_str()));
        // The state now in force, read back rather than echoed. If quarantine
        // outranked the requested state, the caller sees that.
        root.push("state", Value::from(self.effective_state(target).as_str()));
        root.push("requested", Value::from(desired));
        root.push(
            "quarantined",
            Value::from(self.state.health.is_quarantined(&target_id)),
        );
        // An operator override is runtime state, not configuration, and this
        // router keeps it in memory. Saying so beats letting a restart quietly
        // return a drained target to service.
        root.push("persists_across_restart", Value::from(false));
        // RFC 9110: the tag on a 200 to a PATCH is the tag of the resource's new
        // representation, so a read-modify-write loop can continue without
        // re-reading. Tagging the reply body instead handed the caller something
        // the server itself would refuse on the next update.
        let mut response = ApiResponse::ok(&Value::Object(root));
        response.etag = Some(self.target_etag(target));
        Ok(response)
    }

    // -- Policies -----------------------------------------------------------

    fn list_drafts(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::SimulatePolicy)
            .or_else(|_| self.require(session, Permission::EditPolicy))?;

        let items: Vec<Value> = self
            .state
            .drafts
            .list(&session.tenant)
            .iter()
            .map(|draft| {
                let mut object = Object::new();
                object.push("id", Value::from(draft.id.as_str()));
                object.push("author", Value::from(draft.author.as_str()));
                object.push("created_at", Value::from(draft.created_at_millis));
                object.push("validated", Value::from(draft.validated));
                object.push("valid", Value::from(draft.is_valid()));
                object.push_opt("digest", draft.digest.map(|d| Value::from(d.short())));
                object.push("error_count", Value::from(draft.errors.len()));
                Value::Object(object)
            })
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, None)))
    }

    /// Propose a new target, as a policy draft.
    ///
    /// Specification 16 lists `POST /admin/v1/targets`, and for a long time this
    /// was simply absent (`DI-047`) because the obvious reading — create the
    /// target — would put a second mutation path next to the draft → validate →
    /// approve → activate discipline of specification 15.4, outside the
    /// separation-of-duties check. That would make routing changeable with one
    /// signature, which is the property that discipline exists to prevent.
    ///
    /// So this endpoint does not create a target. It renders the requested
    /// target as one `target` record, appends it to the **active**
    /// configuration text, and creates a draft of the result — returning the
    /// draft, not a target. Every downstream step is unchanged: the draft still
    /// has to validate, still needs a second approver, and still activates
    /// atomically. The convenience is in not hand-authoring a whole document to
    /// add one line; the control is untouched.
    ///
    /// It deliberately requires `EditPolicy` rather than `OperateTargets`. The
    /// permission has to match what the call actually does — author a policy
    /// change — or the endpoint becomes a way for an operator with only
    /// day-to-day target permissions to enter the policy workflow.
    fn propose_target(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::EditPolicy)?;
        let body = request.json(&Limits::SMALL)?;

        let id = body.field_str("id").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a target proposal requires an 'id'",
            )
        })?;
        let provider = body.field_str("provider").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a target proposal requires a 'provider'",
            )
        })?;
        let model = body.field_str("model").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a target proposal requires a 'model'",
            )
        })?;

        // Rejected here rather than left to the draft validator, so the caller
        // gets the field name back. The identifier alphabet is also what stops
        // a value carrying a newline or a quote into the configuration text
        // below — a proposal must add one record, never several.
        for (field, value) in [("id", id), ("provider", provider), ("model", model)] {
            if !is_configuration_token(value) {
                return Err(ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    format!(
                        "'{field}' is not a valid configuration token: '{}'",
                        echo(value)
                    ),
                ));
            }
        }

        let config = self.state.config();
        if config.snapshot.targets.contains_key(
            &TargetId::new(id).map_err(|_| {
                ApiError::new(ApiErrorCode::InvalidRequest, "'id' is not a target id")
            })?,
        ) {
            return Err(ApiError::new(
                ApiErrorCode::Conflict,
                "a target with that id already exists; edit it through a policy draft",
            ));
        }

        // Only the three required fields are rendered. Everything else a target
        // can declare — capabilities, limits, cost class — is deliberately left
        // to the draft the operator then edits: guessing a context window or a
        // capability set on their behalf would put a wrong number into routing
        // policy with their name on it.
        let mut text = config.canonical.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "target id={id} provider={provider} model={model}\n"
        ));

        let draft = self.state.drafts.create(
            text,
            session.principal.clone(),
            session.tenant.clone(),
            self.state.clock.wall_millis(),
        );

        self.state
            .store
            .append(hypellm_store::RecordKind::PolicyDraft, &draft.to_payload())
            .map_err(|_| {
                self.state.drafts.close(&draft.id);
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the draft could not be recorded durably and was not created",
                )
            })?;

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::PolicyDrafted,
            )
            .with_object(draft.id.as_str())
            .with_tenant(session.tenant.as_str()),
        )?;

        let mut root = Object::new();
        root.push("draft_id", Value::from(draft.id.as_str()));
        root.push("author", Value::from(draft.author.as_str()));
        root.push("validated", Value::from(false));
        // Named explicitly so a client cannot mistake this for target creation:
        // nothing routes to the proposed target until the draft is approved and
        // activated.
        root.push("target_created", Value::from(false));
        Ok(ApiResponse::created(&Value::Object(root)))
    }

    fn create_draft(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::EditPolicy)?;
        let body = request.json(&Limits::DEFAULT)?;
        let text = body.field_str("configuration").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a draft requires a 'configuration' field",
            )
        })?;

        let draft = self.state.drafts.create(
            text.to_owned(),
            session.principal.clone(),
            session.tenant.clone(),
            self.state.clock.wall_millis(),
        );

        // Durable, so a restart does not lose a draft awaiting a second
        // approver — which during an incident means re-authoring a whole
        // configuration under pressure (specification 15.3's workflow only
        // works if its state survives).
        //
        // Fails closed: a draft reported as created but lost on restart is
        // worse than one that visibly failed to create, because the operator
        // walks away believing it exists.
        self.state
            .store
            .append(hypellm_store::RecordKind::PolicyDraft, &draft.to_payload())
            .map_err(|_| {
                self.state.drafts.close(&draft.id);
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the draft could not be recorded durably and was not created",
                )
            })?;

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::PolicyDrafted,
            )
            .with_object(draft.id.as_str())
            .with_tenant(session.tenant.as_str()),
        )?;

        let mut root = Object::new();
        root.push("id", Value::from(draft.id.as_str()));
        root.push("author", Value::from(draft.author.as_str()));
        root.push("validated", Value::from(false));
        Ok(ApiResponse::created(&Value::Object(root)))
    }

    fn validate_draft(&self, session: &Session, draft_id: &str) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::EditPolicy)
            .or_else(|_| self.require(session, Permission::SimulatePolicy))?;

        let version = self.state.next_version.load(Ordering::SeqCst);
        let draft = self
            .state
            .drafts
            .validate(draft_id, &session.tenant, version)
            .ok_or_else(|| ApiError::not_found("draft"))?;

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::PolicyValidated,
            )
            .with_object(draft_id)
            .with_tenant(session.tenant.as_str())
            .with_outcome(if draft.is_valid() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failed
            }),
        )?;

        let mut root = Object::new();
        root.push("id", Value::from(draft.id.as_str()));
        root.push("valid", Value::from(draft.is_valid()));
        root.push_opt("digest", draft.digest.map(|d| Value::from(d.to_hex())));
        root.push(
            "errors",
            Value::Array(
                draft
                    .errors
                    .iter()
                    .map(|error| {
                        let mut object = Object::new();
                        object.push("code", Value::from(error.code));
                        object.push("message", Value::from(error.message.as_str()));
                        object.push("line", Value::from(u64::from(error.position.line)));
                        object.push("column", Value::from(u64::from(error.position.column)));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    /// Simulate a draft against a scenario.
    ///
    /// Specification 15.4: "Draft policy simulation accepts a sanitized request
    /// descriptor and principal selector, returning exclusions and scores
    /// **without provider invocation**." The simulation runs the production
    /// routing function over ideal live state, so what it reports is what the
    /// router would decide — not a reimplementation that can drift.
    fn simulate_draft(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        draft_id: &str,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::SimulatePolicy)?;
        let draft = self
            .state
            .drafts
            .get(draft_id, &session.tenant)
            .ok_or_else(|| ApiError::not_found("draft"))?;

        let version = self.state.next_version.load(Ordering::SeqCst);
        let config = hypellm_config::load(&draft.text, version).map_err(|errors| {
            ApiError::new(ApiErrorCode::ValidationFailed, "the draft did not validate").with_details(
                errors
                    .iter()
                    .map(|e| ApiErrorDetail {
                        code: e.code.to_owned(),
                        location: e.position.to_string(),
                        message: e.message.clone(),
                    })
                    .collect(),
            )
        })?;

        let mut root = self.simulate(request, session, &config)?;
        root.push("draft", Value::from(draft.id.as_str()));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    /// Simulate against the **active** configuration.
    ///
    /// Specification 22.1 step 11 asks an operator to "simulate critical aliases
    /// to confirm permitted fallback and capacity" — during an incident, about
    /// what is running. Requiring a draft made that impossible: an operator
    /// would have had to author a draft of the configuration already live to ask
    /// a question about it.
    fn simulate_active(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::SimulatePolicy)?;
        let config = self.state.config();
        let mut root = self.simulate(request, session, &config)?;
        root.push("active_version", Value::from(config.snapshot.version));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    /// One routing simulation, against `config`.
    ///
    /// `live=true` routes against the real `HealthRegistry` — breakers,
    /// quarantines, operator overrides, observed failure rates, and remaining
    /// capacity — instead of `IdealLiveState`, which reports everything healthy.
    ///
    /// The distinction is the whole point of specification 22.1 step 11. Ideal
    /// answers "does policy permit this", which is what you want when reviewing
    /// a draft: a target that happens to be breaking right now should not make a
    /// policy look wrong. Live answers "would this work at this moment", which is
    /// what you want during an incident, and which the ideal answer cannot give.
    ///
    /// Neither reserves capacity or contacts a provider (specification 15.4:
    /// "without provider invocation"). A live simulation *reads* admission and
    /// health state; it does not consume any, so simulating cannot itself cause
    /// the rejection it is investigating.
    ///
    /// The response says which mode ran. An operator reading "no eligible
    /// target" needs to know whether that was policy or weather.
    fn simulate(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        config: &ValidatedConfig,
    ) -> Result<Object, ApiError> {
        let body = request.json(&Limits::SMALL)?;
        let scenario = build_scenario(&body, session, &config.snapshot)?;
        let live_mode = query_params(request.query)
            .iter()
            .any(|(k, v)| k == "live" && v == "true");

        let groups: Vec<hypellm_core::ids::GroupId> = body
            .opt_field_array("groups")
            .ok()
            .flatten()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| hypellm_core::ids::GroupId::new(s).ok())
                    .collect()
            })
            .unwrap_or_default();

        let attempted = Vec::new();
        let context = RoutingContext {
            principal: &scenario.principal,
            groups: &groups,
            tenant: &scenario.tenant,
            attempted: &attempted,
        };

        let ideal = hypellm_core::policy::IdealLiveState;
        let live: &dyn hypellm_core::policy::LiveState = if live_mode {
            self.state.health.as_ref()
        } else {
            &ideal
        };
        let outcome = config.snapshot.route(&context, &scenario.request, live);

        let mut root = Object::new();
        root.push("policy_digest", Value::from(config.digest.to_hex()));
        // Stated, not implied: "no eligible target" means something different
        // in each mode, and an operator has to know which they asked for.
        root.push(
            "live_state",
            Value::from(if live_mode { "live" } else { "ideal" }),
        );
        root.push("pinned", Value::from(outcome.pinned));
        root.push(
            "chosen",
            outcome
                .candidates
                .first()
                .map_or(Value::Null, |c| Value::from(c.target.as_str())),
        );
        root.push(
            "candidates",
            Value::Array(
                outcome
                    .candidates
                    .iter()
                    .map(|candidate| {
                        let mut object = Object::new();
                        object.push("target", Value::from(candidate.target.as_str()));
                        object.push("rank", Value::from(u64::from(candidate.rank)));
                        object.push("score", Value::from(candidate.score()));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );
        root.push(
            "exclusions",
            Value::Array(
                outcome
                    .exclusions
                    .iter()
                    .map(|exclusion| {
                        let mut object = Object::new();
                        object.push("target", Value::from(exclusion.target.as_str()));
                        object.push("reason", Value::from(exclusion.reason.code()));
                        Value::Object(object)
                    })
                    .collect(),
            ),
        );
        Ok(root)
    }

    /// Restore the previously active configuration.
    ///
    /// Specification 15.3 requires the routing-policy screen to offer rollback,
    /// and specification 17 lists it as an audited action —
    /// `AuditAction::PolicyRolledBack` has existed since the audit vocabulary
    /// was written and had no producer. `Activatable::rollback` retains eight
    /// versions and was likewise implemented and uncalled.
    ///
    /// **It requires only `PublishPolicy`, not a second approver**, and that is
    /// the deliberate decision this entry asked for. Publication needs two
    /// people because it changes policy to something nobody has reviewed;
    /// rollback restores a configuration that was *already* published under
    /// that rule, so the second signature has already been given. Requiring one
    /// again would mean the recovery path is unavailable precisely when an
    /// incident has one operator awake — which is how a bad publication stays
    /// live.
    ///
    /// A rollback is itself an activation: durable frame first, then the
    /// pointer swap, in that order, for the same reason `publish_draft` does
    /// it.
    ///
    /// The previous configuration's *text* is re-loaded under a new version
    /// number rather than its object being swapped back in. Two different
    /// configurations must never share a version: `If-Match` ETags are derived
    /// from it, `/health/ready` and the overview report it, and an operator
    /// watching that number through an incident needs a change to be visible.
    /// Reinstating the old object would make the counter go backwards and give
    /// the restored configuration a version an auditor has already seen
    /// attached to different content.
    fn rollback_policy(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::PublishPolicy)?;

        let active = self.state.config();
        if_match_satisfied(request.if_match(), &active_etag(&active))?;

        let reason = request
            .json(&Limits::SMALL)
            .ok()
            .and_then(|body| {
                body.opt_field_str("reason")
                    .ok()
                    .flatten()
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let reason = reason.trim();
        if reason.len() < MIN_ROLLBACK_REASON || reason.len() > MAX_BREAK_GLASS_REASON {
            return Err(ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a rollback requires a reason of 8 to 256 characters",
            ));
        }

        // Peek before committing: rolling back with no retained version must be
        // a refusal, not a silent no-op that reports success.
        let Some(previous) = self.state.config.previous() else {
            return Err(ApiError::new(
                ApiErrorCode::ValidationFailed,
                "there is no previous configuration to roll back to",
            ));
        };
        if previous.snapshot.version == active.snapshot.version {
            return Err(ApiError::new(
                ApiErrorCode::ValidationFailed,
                "the previous configuration is the active one",
            ));
        }

        let version = self.state.next_version.fetch_add(1, Ordering::SeqCst);
        let restored_from = previous.snapshot.version;

        // Re-loaded rather than swapped back in, so the restored configuration
        // carries a new version. It built once; if it does not build now, the
        // configuration grammar changed underneath a retained version and
        // refusing is the only safe answer.
        let restored = hypellm_config::load(&previous.canonical, version).map_err(|_| {
            ApiError::new(
                ApiErrorCode::InternalFault,
                "the previous configuration no longer builds and cannot be restored",
            )
        })?;
        let digest = restored.digest;

        self.state
            .store
            .append(
                hypellm_store::RecordKind::ConfigActivation,
                restored.canonical.as_bytes(),
            )
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the rollback could not be recorded durably",
                )
            })?;

        self.state.config.activate(restored);
        let activated = active_etag(&self.state.config());

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::PolicyRolledBack,
            )
            .with_object(digest.short())
            .with_tenant(session.tenant.as_str())
            .with_reason(reason),
        )?;
        // Loud, because a rollback is an incident action by definition.
        self.state.telemetry.log(
            &hypellm_telemetry::Event::critical("policy.rolled_back")
                .str_field(hypellm_telemetry::Field::Detail, reason)
                .str_field(hypellm_telemetry::Field::ConfigDigest, &digest.short()),
        );

        let mut root = Object::new();
        root.push("version", Value::from(version));
        root.push("digest", Value::from(digest.to_hex()));
        root.push("restored_from_version", Value::from(restored_from));
        let mut response = ApiResponse::ok(&Value::Object(root));
        response.etag = Some(activated);
        Ok(response)
    }

    fn publish_draft(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        draft_id: &str,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::PublishPolicy)?;

        let active = self.state.config();
        let current = active_etag(&active);
        if_match_satisfied(request.if_match(), &current)?;

        // The version is *reserved*, not consumed, until the draft is known to
        // build. Incrementing first meant a publish refused for self-approval or
        // a draft that does not validate still burned a number, leaving the
        // `ConfigActivation` frames on disk with gaps an auditor cannot account
        // for — and any approver able to widen the gap at will.
        let version = self.state.next_version.load(Ordering::SeqCst);
        let config = self
            .state
            .drafts
            .prepare_publish(draft_id, &session.principal, &session.tenant, version)
            .map_err(|refusal| match refusal {
                PublishRefusal::NoSuchDraft => ApiError::not_found("draft"),
                PublishRefusal::SelfApproval => {
                    ApiError::new(ApiErrorCode::Forbidden, refusal.message())
                }
                other => ApiError::new(ApiErrorCode::ValidationFailed, other.message()),
            })?;
        // Claim the number now that it will be used. A concurrent publish that
        // got there first invalidates this attempt's version, so it is refused
        // rather than activated under a number somebody else is already using.
        self.state
            .next_version
            .compare_exchange(version, version + 1, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::PreconditionFailed,
                    "another publication completed while this one was being prepared; \
                     re-read the active configuration and retry",
                )
            })?;

        let digest = config.digest;

        // Durable first, then the pointer swap. A crash between the two leaves
        // the record of an activation that did not take effect, which an
        // operator can see; the reverse would leave a running configuration
        // with no record of who published it.
        self.state
            .store
            .append(
                hypellm_store::RecordKind::ConfigActivation,
                config.canonical.as_bytes(),
            )
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the activation could not be recorded durably",
                )
            })?;

        // The draft is spent. Recording that keeps replay from restoring a
        // draft that has already been published — which would present a
        // reviewed-and-activated configuration as though it were still awaiting
        // approval.
        let _ = self.state.store.append(
            hypellm_store::RecordKind::PolicyDraftClosed,
            draft_id.as_bytes(),
        );
        self.state.drafts.close(draft_id);

        self.state.config.activate(config);
        // The tag of what is now active — which is what the next publish will be
        // compared against. Tagging the reply body instead handed the approver
        // something the server would refuse with 412, forcing every real client
        // back to `If-Match: *` and silently defeating the concurrency control.
        let activated = active_etag(&self.state.config());

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::PolicyPublished,
            )
            .with_object(draft_id)
            .with_tenant(session.tenant.as_str())
            .with_reason(&format!("digest {}", digest.short())),
        )?;

        let mut root = Object::new();
        root.push("version", Value::from(version));
        root.push("digest", Value::from(digest.to_hex()));
        root.push("draft", Value::from(draft_id));
        let mut response = ApiResponse::ok(&Value::Object(root));
        response.etag = Some(activated);
        Ok(response)
    }

    // -- Keys ---------------------------------------------------------------

    fn list_keys(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageKeys)?;
        let items: Vec<Value> = self
            .state
            .keys
            .list()
            .iter()
            .filter(|record| record.tenant == session.tenant)
            .map(|record| {
                let mut object = Object::new();
                object.push("id", Value::from(record.id.as_str()));
                object.push("principal", Value::from(record.principal.as_str()));
                object.push("tenant", Value::from(record.tenant.as_str()));
                object.push("revoked", Value::from(record.revoked));
                object.push("created_at", Value::from(record.created_at_millis));
                object.push_opt("expires_at", record.expires_at_millis.map(Value::from));
                object.push_opt(
                    "description",
                    record.description.as_deref().map(Value::from),
                );
                object.push(
                    "scopes",
                    Value::Array(
                        record
                            .scopes
                            .iter()
                            .map(|s| Value::from(s.as_str()))
                            .collect(),
                    ),
                );
                // Null when the key is unrestricted, so a listing distinguishes
                // "usable from anywhere" from "restricted to nothing" — which
                // an empty array would not.
                object.push(
                    "source_networks",
                    render_source_restriction(&record.source),
                );
                // The verifier is never returned: it is not the secret, but it
                // is key-derived material with no reason to leave the process.
                Value::Object(object)
            })
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, None)))
    }

    fn create_key(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageKeys)?;
        let body = request.json(&Limits::SMALL)?;

        let principal_text = body.field_str("principal").map_err(|_| {
            ApiError::new(ApiErrorCode::InvalidRequest, "a key requires a 'principal'")
        })?;
        let principal = PrincipalId::new(principal_text).map_err(|_| {
            ApiError::new(ApiErrorCode::InvalidRequest, "the principal is not a valid identifier")
        })?;

        let mut scopes = Vec::new();
        for raw in body.opt_field_array("scopes").ok().flatten().unwrap_or(&[]) {
            let text = raw.as_str().unwrap_or("");
            let scope = hypellm_auth::Scope::parse(text).ok_or_else(|| {
                ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    format!("unknown scope '{}'", echo(text)),
                )
            })?;
            scopes.push(scope);
        }
        if scopes.is_empty() {
            return Err(ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a key requires at least one scope",
            ));
        }

        let expires_at = body
            .opt_field_i64("expires_at")
            .ok()
            .flatten()
            .and_then(|v| u64::try_from(v).ok());

        // Specification 9.2's source-constrained keys. `KeyStore` has enforced
        // this since it existed — `verify` checks it, and a restricted key with
        // an unknown peer address fails closed — but `create_key` always passed
        // `Any`, so there was no way to create one through the API and
        // specification 22.3's least-privilege replacement could not be built.
        let source = parse_source_restriction(&body)?;

        let new_key = self
            .state
            .keys
            .create(
                session.tenant.clone(),
                principal.clone(),
                scopes,
                Vec::new(),
                expires_at,
                source,
                body.opt_field_str("description")
                    .ok()
                    .flatten()
                    .map(str::to_owned),
                self.state.clock.wall_millis(),
            )
            .map_err(|_| ApiError::new(ApiErrorCode::InternalFault, "cannot create a key"))?;

        let key_id = new_key.id().clone();

        // Durable before the secret is handed out. A key returned to a caller
        // but absent from the log would stop working at the next restart, and
        // the caller would have no way to know until it did.
        self.state
            .store
            .append(
                hypellm_store::RecordKind::ApiKey,
                &new_key.record.to_payload(),
            )
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the key could not be recorded durably and was not created",
                )
            })?;

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::KeyCreated,
            )
            .with_object(key_id.as_str())
            .with_tenant(session.tenant.as_str()),
        )?;

        // Specification 9.2 and 15.3: displayed once, never retrievable again.
        let secret = new_key.into_secret();
        let mut root = Object::new();
        root.push("id", Value::from(key_id.as_str()));
        root.push("principal", Value::from(principal.as_str()));
        root.push("secret", Value::from(secret.as_str()));
        root.push(
            "notice",
            Value::from("this secret is shown once and cannot be retrieved again"),
        );
        Ok(ApiResponse::created(&Value::Object(root)))
    }

    /// Revoke a key.
    ///
    /// # Why this mutation carries no `If-Match`
    ///
    /// Specification 15.4 requires "If-Match on mutation", and this is a
    /// mutation of an existing resource, so the exemption is deliberate rather
    /// than an oversight.
    ///
    /// `If-Match` exists to prevent a lost update: two writers each read a
    /// resource, each modify it, and the second silently discards the first's
    /// change. Revocation has no such failure mode. It is monotonic — there is
    /// no un-revoke — and idempotent, so two concurrent revocations converge on
    /// the state both callers wanted. There is nothing to lose.
    ///
    /// What a precondition *would* cost is real. Specification 22.3 says
    /// "revoke key id immediately; revocation bypasses configuration
    /// publication delay": this runs during a credential compromise. Demanding
    /// a fresh `ETag` first adds a round trip to an incident, and a `412` from
    /// a concurrent revoke would refuse the one operation that should never be
    /// refused — leaving a leaked key live because two responders reached for
    /// it at once.
    fn revoke_key(&self, session: &Session, raw_id: &str) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageKeys)?;
        let key_id = hypellm_core::ids::KeyId::new(raw_id)
            .map_err(|_| ApiError::not_found("key"))?;

        let record = self
            .state
            .keys
            .get(&key_id)
            .filter(|record| record.tenant == session.tenant)
            .ok_or_else(|| ApiError::not_found("key"))?;

        // Specification 22.3: "Revoke key id immediately; revocation bypasses
        // configuration publication delay."
        //
        // Durable first. The in-memory revocation is instant either way, but a
        // revocation that never reached the log would be undone by a restart —
        // resurrecting a key that was revoked precisely because it leaked.
        self.state
            .store
            .append(
                hypellm_store::RecordKind::ApiKeyRevocation,
                key_id.as_str().as_bytes(),
            )
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    "the revocation could not be recorded durably and was not applied",
                )
            })?;

        self.state.keys.revoke(&key_id);

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::KeyRevoked,
            )
            .with_object(key_id.as_str())
            .with_tenant(record.tenant.as_str()),
        )?;

        Ok(ApiResponse::no_content())
    }

    // -- Credentials --------------------------------------------------------

    /// The users-and-access view.
    ///
    /// Specification 15.3: "Google-linked identities, service principals,
    /// roles, status, sessions." Everything is scoped to the caller's tenant
    /// (Appendix B), and nothing here is a credential: an identity shows its
    /// issuer and subject, a service principal shows its key identifier — which
    /// is the key's public prefix — and a session shows its digest, never the
    /// cookie token, which is not stored at all.
    fn list_access(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManagePrincipals)?;
        let config = self.state.config();

        // Google-linked identities bound to a principal in this tenant.
        let identities: Vec<Value> = config
            .identities
            .iter()
            .filter(|identity| identity.tenant == session.tenant)
            .map(|identity| {
                let mut object = Object::new();
                object.push("issuer", Value::from(identity.issuer.as_str()));
                object.push("subject", Value::from(identity.subject.as_str()));
                object.push("principal", Value::from(identity.principal.as_str()));
                object.push_opt(
                    "description",
                    identity.description.as_deref().map(Value::from),
                );
                object.push(
                    "roles",
                    Value::Array(roles_for(&config, &identity.principal)),
                );
                Value::Object(object)
            })
            .collect();

        // Service principals: the API keys this tenant holds. The secret is
        // never here — only the identifier, which is the key's prefix.
        let mut service_principals: Vec<Value> = self
            .state
            .keys
            .list()
            .iter()
            .filter(|record| record.tenant == session.tenant)
            .map(|record| {
                let mut object = Object::new();
                object.push("key_id", Value::from(record.id.as_str()));
                object.push("principal", Value::from(record.principal.as_str()));
                object.push(
                    "scopes",
                    Value::Array(
                        record
                            .scopes
                            .iter()
                            .map(|s| Value::from(s.as_str()))
                            .collect(),
                    ),
                );
                object.push(
                    "status",
                    Value::from(if record.revoked { "revoked" } else { "active" }),
                );
                object.push("created_at", Value::from(record.created_at_millis));
                object.push_opt("expires_at", record.expires_at_millis.map(Value::from));
                object.push_opt("description", record.description.as_deref().map(Value::from));
                Value::Object(object)
            })
            .collect();
        service_principals.sort_by(|a, b| {
            a.get("key_id")
                .and_then(Value::as_str)
                .cmp(&b.get("key_id").and_then(Value::as_str))
        });

        // Groups, so an operator can see what a group binding will match.
        let groups: Vec<Value> = config
            .groups
            .iter()
            .filter(|group| group.tenant == session.tenant)
            .map(|group| {
                let mut object = Object::new();
                object.push("id", Value::from(group.id.as_str()));
                object.push(
                    "members",
                    Value::Array(
                        group
                            .members
                            .iter()
                            .map(|m| Value::from(m.as_str()))
                            .collect(),
                    ),
                );
                object.push_opt("description", group.description.as_deref().map(Value::from));
                Value::Object(object)
            })
            .collect();

        // Live sessions. The digest identifies a session for revocation
        // without being usable as one.
        let sessions: Vec<Value> = self
            .state
            .sessions
            .sessions_for_tenant(&session.tenant, self.state.clock.now_millis())
            .iter()
            .map(|live| {
                let mut object = Object::new();
                object.push("id", Value::from(live.digest.short()));
                object.push("principal", Value::from(live.principal.as_str()));
                object.push("auth_method", Value::from(live.method.as_str()));
                // An attribute, shown for recognition. Not the identity key.
                object.push_opt("email", live.email.as_deref().map(Value::from));
                object.push(
                    "roles",
                    Value::Array(live.roles.iter().map(|r| Value::from(r.as_str())).collect()),
                );
                object.push("created_at", Value::from(live.created_at_millis));
                object.push("last_seen", Value::from(live.last_seen_millis));
                object.push("expires_at", Value::from(live.absolute_expiry_millis));
                object.push("is_current", Value::from(live.digest == session.digest));
                Value::Object(object)
            })
            .collect();

        let mut root = Object::new();
        root.push("object", Value::from("access"));
        root.push("tenant", Value::from(session.tenant.as_str()));
        root.push("identities", Value::Array(identities));
        root.push("service_principals", Value::Array(service_principals));
        root.push("groups", Value::Array(groups));
        root.push("sessions", Value::Array(sessions));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    /// The settings view.
    ///
    /// Specification 15.3: "OIDC, retention, CORS/origins, break-glass, safe
    /// deployment parameters."
    ///
    /// Read-only, and deliberately partial. Settings are configuration, and
    /// configuration changes through a policy draft and a publish — there is no
    /// write path here, and offering one would bypass the review specification
    /// 15.4 requires for activation.
    ///
    /// **What is deliberately absent**: `oidc_verifier_socket`,
    /// `tls_helper_socket`, `control_socket`, and `state_dir`. None is a
    /// secret, but each names a local attack surface, and the screen exists to
    /// answer "is sign-in configured", not "where do I find the socket that
    /// stops the router".
    fn settings_view(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageSettings)?;
        let config = self.state.config();
        let settings = &config.settings;

        let mut oidc = Object::new();
        oidc.push("configured", Value::from(self.state.oidc_config.is_some()));
        oidc.push_opt("issuer", settings.oidc_issuer.as_deref().map(Value::from));
        oidc.push_opt(
            "client_id",
            settings.oidc_client_id.as_deref().map(Value::from),
        );
        oidc.push_opt(
            "redirect_uri",
            settings.oidc_redirect_uri.as_deref().map(Value::from),
        );
        oidc.push(
            "hosted_domains",
            Value::Array(
                settings
                    .oidc_hosted_domains
                    .iter()
                    .map(|d| Value::from(d.as_str()))
                    .collect(),
            ),
        );
        // Whether a verifier is wired, not where it lives.
        oidc.push(
            "verifier_configured",
            Value::from(settings.oidc_verifier_socket.is_some()),
        );

        let mut sessions = Object::new();
        sessions.push("idle_seconds", Value::from(settings.session_idle_secs));
        sessions.push(
            "absolute_seconds",
            Value::from(settings.session_absolute_secs),
        );

        let mut deployment = Object::new();
        deployment.push("max_body_bytes", Value::from(settings.max_body_bytes));
        deployment.push(
            "max_head_bytes",
            Value::from(u64::from(settings.max_head_bytes)),
        );
        deployment.push(
            "default_deadline_ms",
            Value::from(settings.default_deadline_ms),
        );
        deployment.push("max_attempts", Value::from(u64::from(settings.max_attempts)));
        deployment.push("retry_budget_ms", Value::from(settings.retry_budget_ms));
        deployment.push(
            "slow_client_timeout_ms",
            Value::from(settings.slow_client_timeout_ms),
        );
        deployment.push(
            "keepalive_interval_ms",
            Value::from(settings.keepalive_interval_ms),
        );
        deployment.push(
            "weighted_tie_break",
            Value::from(settings.weighted_tie_break),
        );
        deployment.push(
            "max_failure_percent",
            Value::from(u64::from(settings.max_failure_percent)),
        );
        deployment.push(
            "allow_generic_adapter",
            Value::from(settings.allow_generic_adapter),
        );
        deployment.push(
            "outbound_tls_configured",
            Value::from(settings.tls_helper_socket.is_some()),
        );

        // Retention is per-tenant, so the caller sees its own.
        let mut retention = Object::new();
        if let Some(tenant) = config.tenants.get(&session.tenant) {
            retention.push("days", Value::from(u64::from(tenant.retention_days)));
            retention.push_opt(
                "residency",
                tenant.residency.as_ref().map(|r| Value::from(r.as_str())),
            );
            retention.push_opt(
                "max_cost_class",
                tenant.max_cost_class.map(|c| Value::from(u64::from(c.0))),
            );
        }
        retention.push(
            "prompt_capture_enabled",
            Value::from(settings.capture_bodies),
        );

        let mut break_glass = Object::new();
        // Honest rather than encouraging: the role exists and grants the
        // permissions, but no local break-glass *authentication* method is
        // implemented, so specification 22.4's recovery path needs a session
        // that already exists.
        break_glass.push(
            "role_available",
            Value::from(true),
        );
        break_glass.push("local_authentication_implemented", Value::from(false));
        break_glass.push(
            "note",
            Value::from(
                "the break-glass role can be bound, but this router has no local \
                 break-glass sign-in; recovery during an identity outage needs a \
                 session established beforehand",
            ),
        );

        let mut root = Object::new();
        root.push("object", Value::from("settings"));
        root.push("tenant", Value::from(session.tenant.as_str()));
        root.push("read_only", Value::from(true));
        root.push(
            "note",
            Value::from(
                "settings are configuration; change them through a policy draft and \
                 publish so the change is reviewed and recorded",
            ),
        );
        root.push("oidc", Value::Object(oidc));
        root.push(
            "cors_origins",
            Value::Array(
                settings
                    .cors_origins
                    .iter()
                    .map(|o| Value::from(o.as_str()))
                    .collect(),
            ),
        );
        root.push("sessions", Value::Object(sessions));
        root.push("retention", Value::Object(retention));
        root.push("break_glass", Value::Object(break_glass));
        root.push("deployment", Value::Object(deployment));
        root.push("config_version", Value::from(config.snapshot.version));
        root.push("config_digest", Value::from(config.digest_short()));
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    fn list_credentials(&self, session: &Session) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageCredentials)?;
        let config = self.state.config();
        // Read once for the whole listing rather than per credential: this
        // replays the log.
        let rotations = self.last_rotations();
        let now = self.state.clock.wall_millis();

        let items: Vec<Value> = config
            .credentials
            .iter()
            .map(|credential| {
                let Value::Object(mut object) = self.credential_representation(credential)
                else {
                    return Value::Null;
                };
                // `rotates_after_days` was declared, displayed, and enforced by
                // nothing — an operator could set 30 and never learn that a
                // credential was two years old (`DI-011`). The router does not
                // *force* a rotation, because cutting off a working credential
                // on a timer would turn a policy into an outage; it reports the
                // fact and lets an operator act on it.
                let rotated = rotations.get(credential.id.as_str()).copied();
                object.push_opt(
                    "last_rotated",
                    rotated.map(|at| Value::from(hypellm_core::time::format_rfc3339(at))),
                );
                object.push(
                    "overdue",
                    Value::from(is_rotation_overdue(
                        rotated,
                        credential.rotates_after_days,
                        now,
                    )),
                );
                // Specification 22.2 step 16's overlap window, reported. True
                // only once the superseded secret has actually served a
                // request, which means the provider is refusing the rotated
                // one — a different and far more urgent fact than "a rotation
                // happened recently".
                object.push(
                    "rotation_unaccepted",
                    Value::from(
                        self.state
                            .credentials
                            .as_ref()
                            .is_some_and(|sink| sink.rotation_unaccepted(&credential.id, now)),
                    ),
                );
                // Disclosed so a rotation's `If-Match` can be satisfied from a
                // read rather than from `*`.
                object.push("etag", Value::from(self.credential_etag(credential)));
                Value::Object(object)
            })
            .collect();
        Ok(ApiResponse::ok(&list_envelope(items, None)))
    }

    /// When each credential was last created or rotated, from the audit chain.
    ///
    /// Derived rather than stored, because the audit chain already records it
    /// and a second copy could disagree with the first — and the chain is the
    /// one that has integrity protection.
    fn last_rotations(&self) -> std::collections::BTreeMap<String, u64> {
        let mut newest: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        let Ok(records) = self.state.store.audit_records(None, hypellm_store::MAX_AUDIT_PAGE)
        else {
            return newest;
        };
        for (_, record) in records {
            if !matches!(
                record.event.action,
                AuditAction::CredentialRotated | AuditAction::CredentialCreated
            ) {
                continue;
            }
            let Some(object) = record.event.object.as_deref() else {
                continue;
            };
            let at = record.event.timestamp_millis;
            newest
                .entry(object.to_owned())
                .and_modify(|existing| *existing = (*existing).max(at))
                .or_insert(at);
        }
        newest
    }

    /// What a credential's `If-Match` is compared against.
    ///
    /// Its declared metadata plus whether a secret is held. The secret itself is
    /// write-only (specification 9.3), so no read can observe its value and no
    /// tag can cover it: the precondition therefore catches a credential whose
    /// *declaration* moved under the caller, and the first store of a secret,
    /// but two rotations racing in the same window still both hold a tag that
    /// matches. Recorded here rather than papered over.
    fn credential_representation(
        &self,
        credential: &hypellm_config::CredentialMeta,
    ) -> Value {
        let mut object = Object::new();
        object.push("id", Value::from(credential.id.as_str()));
        object.push_opt(
            "description",
            credential.description.as_deref().map(Value::from),
        );
        object.push(
            "rotates_after_days",
            Value::from(u64::from(credential.rotates_after_days)),
        );
        object.push(
            "scope",
            Value::Array(
                credential
                    .scope
                    .iter()
                    .map(|s| Value::from(s.as_str()))
                    .collect(),
            ),
        );
        object.push(
            "has_secret",
            Value::from(
                self.state
                    .credentials
                    .as_ref()
                    .is_some_and(|sink| sink.contains(&credential.id)),
            ),
        );
        // There is no `secret` field, here or anywhere: specification 9.3 says a
        // credential manager "cannot read secret back", and no permission exists
        // that would authorize it.
        Value::Object(object)
    }

    fn credential_etag(&self, credential: &hypellm_config::CredentialMeta) -> String {
        etag_for(&self.credential_representation(credential))
    }

    fn create_credential(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageCredentials)?;
        let body = request.json(&Limits::SMALL)?;
        let id = body.field_str("id").map_err(|_| {
            ApiError::new(ApiErrorCode::InvalidRequest, "a credential requires an 'id'")
        })?;
        // The secret is accepted write-only and handed to the platform secret
        // facility; it is never echoed back and never stored in configuration.
        let secret = body.field_str("secret").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a credential requires a 'secret'",
            )
        })?;

        // Creation must not be a rotation in disguise. Without this, a typo in
        // an `id` silently overwrote the live secret of an existing credential
        // and answered 201: the rotation path's not-found guard was skipped, and
        // the overwrite was recorded as `CredentialCreated`, so an auditor
        // reviewing rotations never saw it.
        let reference = CredentialRef::new(id).map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "the credential reference is not a valid identifier",
            )
        })?;
        let declared = self
            .state
            .config()
            .credentials
            .iter()
            .any(|credential| credential.id == reference);
        let stored = self
            .state
            .credentials
            .as_ref()
            .is_some_and(|sink| sink.contains(&reference));
        if declared || stored {
            return Err(ApiError::new(
                ApiErrorCode::Conflict,
                "a credential with this reference already exists; \
                 rotate it if you meant to replace its secret",
            ));
        }

        // Stored before the audit record and before the response. This handler
        // previously validated the secret's presence, discarded it, and replied
        // `stored: true` — an operator following the rotation runbook would
        // have been told the credential was in place while the router still
        // held the old one.
        let reference = self.store_credential(id, secret)?;

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::CredentialCreated,
            )
            .with_object(reference.as_str())
            .with_tenant(session.tenant.as_str()),
        )?;

        let mut root = Object::new();
        root.push("id", Value::from(reference.as_str()));
        root.push("stored", Value::from(true));
        Ok(ApiResponse::created(&Value::Object(root)))
    }

    /// Validate a credential reference and persist its secret.
    ///
    /// Shared by create and rotate: both must fail closed when the deployment
    /// has nowhere to put a secret, rather than reporting success.
    fn store_credential(&self, id: &str, secret: &str) -> Result<CredentialRef, ApiError> {
        let reference = CredentialRef::new(id).map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "the credential reference is not a valid identifier",
            )
        })?;

        if secret.is_empty() {
            return Err(ApiError::new(
                ApiErrorCode::InvalidRequest,
                "the credential secret must not be empty",
            ));
        }

        let Some(sink) = &self.state.credentials else {
            return Err(ApiError::new(
                ApiErrorCode::InternalFault,
                "this router has no credential store configured, so the secret was not stored",
            ));
        };

        sink.store(&reference, secret.as_bytes().to_vec())
            .map_err(|detail| {
                ApiError::new(
                    ApiErrorCode::InternalFault,
                    format!("the credential could not be stored durably: {detail}"),
                )
            })?;

        Ok(reference)
    }

    /// Specification 22.2 step 15's low-cost probe.
    ///
    /// The gap this closes is not that a rotation might fail — it is *how* a
    /// failed one presents. An upstream authentication failure reaches the
    /// client as `internal_fault` and does not trip a breaker, so a bad
    /// rotation looks like a quiet per-request 500 and is discovered by users
    /// rather than by the operator who caused it. There is also no dual-accept
    /// window (`DI-021`), so there is no fallback to the old secret.
    ///
    /// Gated on `ManageCredentials`: a probe issues a real upstream request
    /// with the tenant's credential, and being able to make the router spend a
    /// provider call is the same authority as being able to change what it
    /// spends.
    fn probe_credential(
        &self,
        session: &Session,
        id: &str,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageCredentials)?;

        let reference = CredentialRef::new(id).map_err(|_| ApiError::not_found("credential"))?;
        let config = self.state.config();
        if !config
            .credentials
            .iter()
            .any(|declared| declared.id == reference)
        {
            return Err(ApiError::not_found("credential"));
        }

        let Some(sink) = self.state.credentials.as_ref() else {
            return Err(ApiError::new(
                ApiErrorCode::NotFound,
                "this deployment has no data path to probe with",
            ));
        };
        let Some(outcome) = sink.probe(&reference) else {
            // Not a pass. A credential no target uses cannot be validated, and
            // reporting success would be the most misleading answer available.
            return Err(ApiError::new(
                ApiErrorCode::ValidationFailed,
                "no enabled target uses this credential, so it cannot be probed",
            ));
        };

        let _ = self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::CredentialProbed,
            )
            .with_object(reference.as_str())
            .with_tenant(session.tenant.as_str())
            .with_outcome(if outcome.ok {
                AuditOutcome::Success
            } else {
                AuditOutcome::Denied
            }),
        );

        let mut root = Object::new();
        root.push("id", Value::from(reference.as_str()));
        root.push("ok", Value::from(outcome.ok));
        root.push("target", Value::from(outcome.target.as_str()));
        root.push("elapsed_ms", Value::from(outcome.millis));
        root.push_opt("class", outcome.class.as_deref().map(Value::from));
        root.push_opt(
            "provider_code",
            outcome.provider_code.as_deref().map(Value::from),
        );
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    fn rotate_credential(
        &self,
        request: &AdminRequest<'_>,
        session: &Session,
        id: &str,
    ) -> Result<ApiResponse, ApiError> {
        self.require(session, Permission::ManageCredentials)?;
        let body = request.json(&Limits::SMALL)?;
        let secret = body.field_str("secret").map_err(|_| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                "a rotation requires the new 'secret'",
            )
        })?;

        // Rotating something that was never configured is almost always a typo
        // in the reference, and silently creating it would leave the operator
        // believing they had rotated a credential the router still holds under
        // another name.
        let reference = CredentialRef::new(id).map_err(|_| ApiError::not_found("credential"))?;
        let config = self.state.config();
        let declared = config
            .credentials
            .iter()
            .find(|declared| declared.id == reference)
            .ok_or_else(|| ApiError::not_found("credential"))?;

        // Specification 15.4 requires `If-Match` on mutation, and this is the
        // mutation where losing the race is worst: two operators rotating in the
        // same window both got 200, and the loser had no way to learn that the
        // provider account they cut over to is not the one the router holds.
        if_match_satisfied(request.if_match(), &self.credential_etag(declared))?;

        let reference = self.store_credential(id, secret)?;

        // Specification 22.2 step 17. Done after the store and before the audit
        // record, so a drained connection always corresponds to a rotation that
        // actually happened.
        let drained = self
            .state
            .credentials
            .as_ref()
            .map_or(0, |sink| sink.drain_connections(&reference));

        self.record_audit(
            AuditEvent::new(
                self.state.clock.wall_millis(),
                session.principal.as_str(),
                AuditAction::CredentialRotated,
            )
            .with_object(reference.as_str())
            .with_tenant(session.tenant.as_str()),
        )?;

        let mut root = Object::new();
        root.push("id", Value::from(reference.as_str()));
        root.push("rotated", Value::from(true));
        root.push(
            "connections_drained",
            Value::from(u64::try_from(drained).unwrap_or(u64::MAX)),
        );
        // Specification 22.2 step 16's bounded overlap. The new secret is live
        // immediately; the superseded one stays usable for this long *only* if
        // the provider refuses the new one, and any such use is reported.
        root.push(
            "overlap_seconds",
            Value::from(
                Duration::from_millis(hypellm_core::OVERLAP_HINT_MILLIS).as_secs(),
            ),
        );
        root.push(
            "note",
            Value::from(
                "the new secret is live immediately. If the provider refuses it, the \
                 superseded one carries requests for the overlap window and the \
                 credential is flagged `rotation_unaccepted` — probe now rather than \
                 waiting for the window to close",
            ),
        );
        Ok(ApiResponse::ok(&Value::Object(root)))
    }

    // -- Helpers ------------------------------------------------------------

    fn require(&self, session: &Session, permission: Permission) -> Result<(), ApiError> {
        self.state
            .sessions
            .authorize(session, permission, self.state.clock.now_millis())
            .map_err(session_error)
    }

    fn record_audit(&self, event: AuditEvent) -> Result<(), ApiError> {
        // Specification 18.3: "security changes fail closed". An action whose
        // audit record did not reach disk must not be reported as having
        // succeeded.
        let appended = self.state.store.append_audit(event.clone()).map_err(|_| {
            ApiError::new(
                ApiErrorCode::InternalFault,
                "the action could not be recorded durably and was not applied",
            )
        })?;
        // The event that was appended, not a reconstruction of it. Indexing a
        // synthesized placeholder left the durable chain correct and the screen
        // an operator watches blank: the placeholder carried no tenant, and the
        // audit view filters on exactly that.
        self.state
            .audit
            .push_event(appended.sequence, event, appended.link);
        Ok(())
    }
}

/// A parsed simulation scenario.
struct Scenario {
    principal: PrincipalId,
    tenant: TenantId,
    request: hypellm_core::canonical::CanonicalRequest,
}

fn build_scenario(
    body: &Value,
    session: &Session,
    snapshot: &hypellm_core::policy::PolicySnapshot,
) -> Result<Scenario, ApiError> {
    use hypellm_core::canonical::{
        CanonicalRequest, ClientProtocol, Message, RequestLimits, Role, RoutingHints, Sampling,
        StreamOptions,
    };

    let principal = body
        .opt_field_str("principal")
        .ok()
        .flatten()
        .map_or_else(
            || Ok(session.principal.clone()),
            |text| {
                PrincipalId::new(text).map_err(|_| {
                    ApiError::new(
                        ApiErrorCode::InvalidRequest,
                        "the principal selector is not a valid identifier",
                    )
                })
            },
        )?;

    // The tenant is the caller's own: specification 15.4 keeps management
    // visibility within the caller's tenant, and simulating another tenant's
    // policy would disclose it.
    let tenant = session.tenant.clone();

    let alias_text = body.field_str("model").map_err(|_| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            "a simulation requires a 'model'",
        )
    })?;
    let alias = hypellm_core::ids::AliasId::new(alias_text).map_err(|_| {
        ApiError::new(ApiErrorCode::InvalidRequest, "the model is not a valid alias")
    })?;

    let operation = body
        .opt_field_str("operation")
        .ok()
        .flatten()
        .and_then(Operation::parse)
        .unwrap_or(Operation::Chat);

    // The descriptor is sanitized: a size, not a prompt. Specification 15.4
    // says "sanitized request descriptor", and a simulation endpoint that
    // accepted prompt text would be a way to get prompts into the management
    // plane's logs.
    //
    // The size is bounded by what any target in this policy could actually
    // serve. Specification 3.2 forbids an unbounded buffer originating from a
    // request, and this one was `input_tokens * 2` bytes with no ceiling: a
    // sixty-byte body could ask the management plane for eight gigabytes.
    let ceiling = simulation_token_ceiling(snapshot);
    let input_tokens = body
        .opt_field_i64("input_tokens")
        .ok()
        .flatten()
        .map_or(Ok(1000), |value| {
            u32::try_from(value)
                .ok()
                .filter(|tokens| *tokens <= ceiling)
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCode::InvalidRequest,
                        format!(
                            "'input_tokens' must be between 0 and {ceiling},                              which is twice the largest context window this policy declares"
                        ),
                    )
                })
        })?;
    let filler = "x".repeat(usize::try_from(input_tokens).unwrap_or(1000).saturating_mul(2));

    Ok(Scenario {
        principal: principal.clone(),
        tenant: tenant.clone(),
        request: CanonicalRequest {
            request_id: RequestId::from_u128(0),
            tenant,
            principal,
            protocol: ClientProtocol::Native,
            operation,
            requested_model: alias,
            messages: vec![Message::text(Role::User, filler)],
            inputs: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            response_format: None,
            sampling: Sampling::default(),
            limits: RequestLimits {
                max_output_tokens: body
                    .opt_field_i64("max_output_tokens")
                    .ok()
                    .flatten()
                    .and_then(|v| u32::try_from(v).ok()),
                deadline: hypellm_core::time::Deadline::at(u64::MAX),
                max_cost_class: None,
                residency: body
                    .opt_field_str("residency")
                    .ok()
                    .flatten()
                    .map(hypellm_core::canonical::Residency::new),
            },
            stream: StreamOptions {
                enabled: body
                    .opt_field_bool("stream")
                    .ok()
                    .flatten()
                    .unwrap_or(false),
                include_usage: false,
            },
            hints: RoutingHints {
                require_local: body
                    .opt_field_bool("require_local")
                    .ok()
                    .flatten()
                    .unwrap_or(false),
                ..RoutingHints::default()
            },
        },
    })
}

/// The targets this caller's tenant can reach.
///
/// A target is reachable only through an alias, and an alias only through a
/// grant, so the set is exactly the union of the permitted targets of the
/// aliases [`PolicySnapshot::visible_aliases`] returns — the same authorization
/// the data plane applies to `GET /v1/models`. Every operation is considered,
/// because an alias authorized for embeddings alone is still an alias this
/// tenant uses.
fn visible_targets(
    config: &ValidatedConfig,
    session: &Session,
) -> std::collections::BTreeSet<TargetId> {
    let groups: Vec<hypellm_core::ids::GroupId> = Vec::new();
    let attempted: Vec<TargetId> = Vec::new();
    let context = RoutingContext {
        principal: &session.principal,
        groups: &groups,
        tenant: &session.tenant,
        attempted: &attempted,
    };

    let mut visible = std::collections::BTreeSet::new();
    for operation in Operation::all() {
        for alias in config.snapshot.visible_aliases(&context, *operation) {
            visible.extend(alias.permitted_targets.iter().cloned());
        }
    }
    visible
}

/// A target's declared capabilities, as the API spells them.
fn capabilities_value(capabilities: &hypellm_core::target::Capabilities) -> Value {
    let mut caps = Object::new();
    caps.push("streaming", Value::from(capabilities.streaming));
    caps.push("tools", Value::from(capabilities.tools));
    caps.push("json_mode", Value::from(capabilities.json_mode));
    caps.push(
        "structured_output",
        Value::from(capabilities.structured_output),
    );
    caps.push(
        "max_context_tokens",
        Value::from(u64::from(capabilities.max_context_tokens)),
    );
    caps.push(
        "max_output_tokens",
        Value::from(u64::from(capabilities.max_output_tokens)),
    );
    caps.push(
        "operations",
        Value::Array(
            capabilities
                .operations
                .iter()
                .map(|o| Value::from(o.as_str()))
                .collect(),
        ),
    );
    Value::Object(caps)
}

/// The largest descriptor size a simulation may ask for.
///
/// Twice the largest context window the policy declares: enough headroom to
/// simulate a request that no target can serve — which is a routing outcome an
/// approver needs to be able to reproduce — and nothing beyond it. The floor
/// keeps a policy with no targets from clamping every simulation to zero.
fn simulation_token_ceiling(snapshot: &hypellm_core::policy::PolicySnapshot) -> u32 {
    snapshot
        .targets
        .values()
        .map(|target| target.capabilities.max_context_tokens)
        .max()
        .unwrap_or(0)
        .saturating_mul(2)
        .max(4096)
}

/// Resolve a verified external identity to a local principal.
///
/// Specification 9.1: the stable identity is the `(iss, sub)` pair, and
/// authorization is "by local role binding, never by email domain".
///
/// The lookup is an explicit `identity` configuration record. Two earlier
/// attempts at this were wrong in ways worth recording, because both looked
/// reasonable:
///
/// - Treating the identity key as the principal identifier. `"{iss}|{sub}"`
///   contains `|` and `/`, which `PrincipalId` rejects, so *every* sign-in
///   failed with "this identity is not bound to a principal" — the router
///   could not be signed into at all.
/// - Taking the tenant from `config.tenants.keys().next()`. That is the first
///   tenant in map order, so in any multi-tenant deployment every operator
///   landed in whichever tenant sorted first, holding their real roles against
///   somebody else's data.
///
/// Roles still come from `role_binding` records naming the resolved principal.
/// An identity bound to a principal with no roles signs in with no permissions
/// rather than being refused: that is a legible state an administrator can see
/// and fix, where a refusal looks like a broken integration.
/// The roles bound to a principal, as JSON.
fn roles_for(config: &ValidatedConfig, principal: &PrincipalId) -> Vec<Value> {
    config
        .roles
        .iter()
        .filter_map(|role| match &role.subject {
            hypellm_config::RoleSubject::Principal(p) if p == principal => {
                Some(Value::from(role.role.as_str()))
            }
            _ => None,
        })
        .collect()
}

/// The management roles bound to a principal.
///
/// Shared by identity resolution and break-glass, so the two cannot drift into
/// disagreeing about what a `role_binding` means.
fn management_roles_for(
    config: &ValidatedConfig,
    principal: &PrincipalId,
) -> Vec<hypellm_core::rbac::Role> {
    config
        .roles
        .iter()
        .filter_map(|role| match &role.subject {
            hypellm_config::RoleSubject::Principal(p) if p == principal => Some(role.role),
            _ => None,
        })
        .collect()
}

fn resolve_identity(
    config: &ValidatedConfig,
    issuer: &str,
    subject: &str,
) -> Option<(PrincipalId, TenantId, Vec<hypellm_core::rbac::Role>)> {
    let binding = config
        .identities
        .iter()
        .find(|identity| identity.issuer == issuer && identity.subject == subject)?;

    let roles = management_roles_for(config, &binding.principal);

    Some((
        binding.principal.clone(),
        binding.tenant.clone(),
        roles,
    ))
}

fn active_etag(config: &ValidatedConfig) -> String {
    let mut object = Object::new();
    object.push("version", Value::from(config.snapshot.version));
    object.push("digest", Value::from(config.digest.to_hex()));
    etag_for(&Value::Object(object))
}

fn session_error(rejection: SessionRejection) -> ApiError {
    let code = match rejection {
        SessionRejection::PermissionDenied => ApiErrorCode::Forbidden,
        SessionRejection::ReauthenticationRequired => ApiErrorCode::ReauthenticationRequired,
        SessionRejection::CsrfMismatch => ApiErrorCode::CsrfRequired,
        SessionRejection::OriginNotPermitted => ApiErrorCode::OriginNotPermitted,
        _ => ApiErrorCode::Unauthenticated,
    };
    let message = match code {
        ApiErrorCode::Forbidden => "the session does not hold the permission this action requires",
        ApiErrorCode::ReauthenticationRequired => {
            "this action requires a recent authentication; sign in again"
        }
        ApiErrorCode::CsrfRequired => "a valid CSRF token is required for this request",
        ApiErrorCode::OriginNotPermitted => {
            "this origin is not permitted to call the management API"
        }
        _ => "a valid session is required",
    };
    ApiError::new(code, message)
}

fn suffix(path: &str, prefix: &str) -> Result<String, ApiError> {
    let rest = path
        .strip_prefix(prefix)
        .ok_or_else(|| ApiError::new(ApiErrorCode::NotFound, "no such endpoint"))?;
    if rest.is_empty() || rest.contains('/') || rest.len() > 256 {
        return Err(ApiError::new(ApiErrorCode::NotFound, "no such endpoint"));
    }
    Ok(rest.to_owned())
}

fn query_params(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), percent_decode(v)))
        .collect()
}

fn param(params: &[(String, String)], name: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// Decode one `%XX` escape.
///
/// The pair is decoded from bytes rather than from a `str` sub-slice: a
/// two-byte window of a UTF-8 string is not necessarily a character boundary
/// (`%€` puts one in the middle of a three-byte character), and slicing a
/// `str` there panics. Any window that is not two valid hexadecimal ASCII
/// digits — including one that is not valid UTF-8 at all — yields `None`, and
/// the caller then treats the `%` as a literal byte.
fn percent_pair(pair: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(pair).ok()?;
    u8::from_str_radix(text, 16).ok()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'%' => match bytes.get(i + 1..i + 3).and_then(percent_pair) {
                Some(decoded) => {
                    out.push(decoded);
                    i += 3;
                }
                None => {
                    out.push(byte);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn peer_text(peer: Option<IpAddr>) -> String {
    peer.map_or_else(|| "unknown".to_owned(), |addr| addr.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_anonymous_audit_budget_bounds_records_and_reports_what_it_dropped() {
        use super::{
            ANONYMOUS_AUDIT_WINDOW_MILLIS, AnonymousAuditBudget,
            MAX_ANONYMOUS_AUDITS_PER_WINDOW,
        };

        let budget = AnonymousAuditBudget::new();

        // The first failures in a window are recorded individually, so an
        // operator debugging their own sign-in sees their own attempts.
        for n in 0..MAX_ANONYMOUS_AUDITS_PER_WINDOW {
            let (record, rolled) = budget.admit(1_000);
            assert!(record, "attempt {n} in the first window was suppressed");
            assert_eq!(rolled, None);
        }

        // Past the budget, nothing more becomes durable.
        for _ in 0..10_000 {
            let (record, rolled) = budget.admit(1_000);
            assert!(!record, "the budget did not bound the window");
            assert_eq!(rolled, None);
        }

        // The next window reports what the last one dropped, exactly once.
        let later = 1_000 + ANONYMOUS_AUDIT_WINDOW_MILLIS;
        let (record, rolled) = budget.admit(later);
        assert!(record, "the new window must start recording again");
        assert_eq!(
            rolled,
            Some(10_000),
            "the summary must say how many were suppressed"
        );

        // And only once: a second call in the same window must not repeat it,
        // or the audit trail overstates what happened.
        let (_, rolled_again) = budget.admit(later);
        assert_eq!(rolled_again, None);
    }

    #[test]
    fn a_window_with_nothing_suppressed_writes_no_summary() {
        use super::{ANONYMOUS_AUDIT_WINDOW_MILLIS, AnonymousAuditBudget};

        // The ordinary case — a few failed sign-ins over a quiet week — must
        // not add a record saying nothing happened. An audit trail padded with
        // empty summaries is one people stop reading.
        let budget = AnonymousAuditBudget::new();
        assert_eq!(budget.admit(1_000), (true, None));
        assert_eq!(
            budget.admit(1_000 + ANONYMOUS_AUDIT_WINDOW_MILLIS),
            (true, None)
        );
    }

    #[test]
    fn a_sustained_flood_cannot_wrap_the_suppressed_count() {
        use super::{
            ANONYMOUS_AUDIT_WINDOW_MILLIS, AnonymousAuditBudget,
            MAX_ANONYMOUS_AUDITS_PER_WINDOW,
        };

        // Saturating rather than wrapping: a count that wrapped would report a
        // handful of suppressed attempts during the largest flood, which is
        // worse than no number at all.
        let budget = AnonymousAuditBudget::new();
        for _ in 0..MAX_ANONYMOUS_AUDITS_PER_WINDOW {
            let _ = budget.admit(1_000);
        }
        budget
            .suppressed
            .store(u32::MAX - 1, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..100 {
            let _ = budget.admit(1_000);
        }
        let (_, rolled) = budget.admit(1_000 + ANONYMOUS_AUDIT_WINDOW_MILLIS);
        assert_eq!(rolled, Some(u32::MAX));
    }

    #[test]
    fn a_rotation_interval_is_only_overdue_once_a_rotation_is_known() {
        use super::is_rotation_overdue;
        const DAY: u64 = 24 * 60 * 60 * 1000;

        // Inside the window.
        assert!(!is_rotation_overdue(Some(0), 30, 29 * DAY));
        // Past it.
        assert!(is_rotation_overdue(Some(0), 30, 31 * DAY));

        // Zero means "no rotation policy", not "overdue immediately".
        assert!(!is_rotation_overdue(Some(0), 0, 10_000 * DAY));

        // No recorded rotation is *not* overdue. The audit chain is bounded and
        // starts whenever this deployment began recording, so "never rotated"
        // and "rotated before the window this router can see" are
        // indistinguishable — and marking every credential overdue on the first
        // read would train an operator to ignore the field.
        assert!(!is_rotation_overdue(None, 30, 10_000 * DAY));
    }


    use super::{echo, percent_decode, query_params};

    #[test]
    fn an_echoed_value_keeps_a_typo_and_loses_a_secret() {
        // The point of echoing at all: a genuine mistake comes back readable.
        assert_eq!(echo("inferance"), "inferance");
        assert_eq!(echo("draning"), "draning");

        // The point of bounding it: a mis-pasted key does not. Found by the
        // management-API fuzz target, which planted a secret in the body and
        // read it back out of a 400 response verbatim.
        let secret = "sk-live-0123456789abcdef0123456789abcdef0123456789";
        let echoed = echo(secret);
        assert!(!echoed.contains("0123456789abcdef0123456789abcdef"));
        assert!(echoed.ends_with('…'), "truncation must be visible: {echoed}");
        assert!(echoed.chars().count() <= 33);

        // And it cannot carry structure into the message it lands in.
        for hostile in ["a\"b", "a\nb", "a\u{7}b", "{\"x\":1}"] {
            let echoed = echo(hostile);
            assert!(!echoed.contains('"'));
            assert!(!echoed.contains('\n'));
            assert!(!echoed.contains('{'));
        }
    }

    #[test]
    fn percent_decode_handles_a_multi_byte_char_after_the_escape() {
        // The regression this locks in: the decoder used to slice the `str`
        // over a two-byte window after only checking the byte length, so a
        // multi-byte character straight after `%` put the slice end inside a
        // character and panicked. Decoding the window as bytes cannot.
        assert_eq!(percent_decode("%\u{20ac}"), "%\u{20ac}");
        assert_eq!(percent_decode("a%\u{20ac}b"), "a%\u{20ac}b");
        assert_eq!(percent_decode("%\u{e9}"), "%\u{e9}");
        // A truncated escape at the very end of the input.
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn percent_decode_still_decodes_ordinary_escapes() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a%2fb"), "a/b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode(""), "");
        // Not hexadecimal: the `%` stays literal and decoding resumes after it.
        assert_eq!(percent_decode("%zz"), "%zz");
        // `u8::from_str_radix` accepts a leading `+`, so this pair decodes to
        // 0x01 rather than staying literal. Pinned because it is surprising.
        assert_eq!(percent_decode("%+1"), "\u{1}");
    }

    #[test]
    fn query_params_decodes_values_only() {
        let params = query_params(Some("a=1%2F2&b=x+y&c=%\u{20ac}"));
        assert_eq!(
            params,
            vec![
                ("a".to_owned(), "1/2".to_owned()),
                ("b".to_owned(), "x y".to_owned()),
                ("c".to_owned(), "%\u{20ac}".to_owned()),
            ]
        );
        assert!(query_params(None).is_empty());
    }
}
