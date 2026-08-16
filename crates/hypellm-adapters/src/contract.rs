//! The adapter contract (specification 7.1).
//!
//! ```text
//! fn validate(canonical_request, target_caps) -> ValidationResult
//! fn encode_headers(credential_handle, request_meta) -> SensitiveHeaders
//! fn encode_request(canonical_request) -> BoundedBytes/stream
//! fn decode_response(status, headers, body_stream) -> CanonicalEvent stream
//! fn classify_error(...) -> ErrorClass with retryability and safe client detail
//! fn usage_from_events(...) -> CanonicalUsage with provider-reported and
//!                              router-estimated flags
//! ```
//!
//! Specification 7 constrains what an adapter may do, and the trait is shaped
//! to make the constraints structural rather than advisory:
//!
//! > They contain only typed conversion, strict parsing, endpoint paths,
//! > authentication header construction, stream decoding, and error mapping.
//! > **They cannot make routing decisions, read arbitrary files, resolve
//! > arbitrary hosts, or expose credentials in errors.**
//!
//! - No method receives a [`PolicySnapshot`](hypellm_core::PolicySnapshot) or a
//!   candidate list, so an adapter cannot influence routing.
//! - No method receives a filesystem path or a resolver.
//! - The credential arrives as a [`CredentialHandle`] and leaves as
//!   [`SensitiveHeaders`], which redacts its values in `Debug` and is not
//!   `Clone`. An adapter cannot put a credential into an error, because the
//!   error types have no field that can hold one.

use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::event::{CanonicalEvent, CanonicalUsage, UpstreamErrorClass};
use hypellm_core::ids::CredentialRef;
use hypellm_core::sensitive::Capped;
use hypellm_core::target::{Capabilities, Endpoint, Target};
use core::fmt;

/// Maximum bytes an adapter may produce for one request body.
pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// An opaque handle to a provider credential.
///
/// Specification 10: "Provider credentials are scoped to the narrowest
/// provider/tenant/target set and retrieved by opaque handle only inside the
/// adapter boundary."
///
/// The secret is borrowed for exactly as long as it takes to build the headers.
/// Not `Clone`, so a handle cannot be squirrelled away.
pub struct CredentialHandle<'a> {
    reference: &'a CredentialRef,
    secret: &'a [u8],
}

impl<'a> CredentialHandle<'a> {
    /// Create a handle. Called only by the credential store.
    #[must_use]
    pub const fn new(reference: &'a CredentialRef, secret: &'a [u8]) -> Self {
        Self { reference, secret }
    }

    /// The opaque reference, safe to log.
    #[must_use]
    pub const fn reference(&self) -> &CredentialRef {
        self.reference
    }

    /// The secret bytes.
    ///
    /// Named `expose` so that every use is greppable; the only legitimate use
    /// is constructing an authentication header.
    #[must_use]
    pub const fn expose(&self) -> &[u8] {
        self.secret
    }

    /// The secret as a string, when it is textual.
    ///
    /// Callers construct an authentication header from this and, historically,
    /// skipped the header entirely when it returned `None` — dispatching an
    /// unauthenticated request to a third party. That cannot happen now,
    /// because [`is_usable_credential`] rejects such a value where the
    /// credential is loaded, long before an adapter sees it.
    #[must_use]
    pub fn expose_str(&self) -> Option<&str> {
        core::str::from_utf8(self.secret).ok()
    }
}

/// Whether a byte string can be carried in an authentication header.
///
/// Two distinct failures are prevented, and the second is the serious one:
///
/// - **A silent fail-open.** An adapter builds its header from
///   [`CredentialHandle::expose_str`]; a value that is not UTF-8 yields `None`,
///   and the natural `if let Some(...)` around it omits the header and sends
///   the request anyway. The provider rejects it, the failure reads as a
///   provider outage, and the prompt has already been transmitted.
/// - **Header injection.** HTTP field values admit visible ASCII, space and
///   horizontal tab (RFC 9110 §5.5). A credential containing CR or LF would
///   terminate the header and let whatever follows be read as more headers —
///   from a file in the state directory, which is exactly the position
///   specification 10.1's hostile-state-directory boundary assumes an attacker
///   may reach.
///
/// Checked where a credential is *loaded* rather than where it is used, so
/// there is one place to get right and a bad value is refused while an operator
/// is still looking at it.
#[must_use]
pub fn is_usable_credential(secret: &[u8]) -> bool {
    !secret.is_empty()
        && secret
            .iter()
            .all(|b| matches!(b, 0x20..=0x7e) || *b == b'\t')
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn an_ordinary_provider_key_is_usable() {
        assert!(is_usable_credential(b"sk-proj-AbCdEf0123456789"));
        assert!(is_usable_credential(b"sk-ant-api03-x_y-z"));
    }

    #[test]
    fn an_empty_credential_is_not_usable() {
        assert!(!is_usable_credential(b""));
    }

    #[test]
    fn a_credential_carrying_crlf_is_refused() {
        // Header injection: whatever follows the CRLF would be read as another
        // header by the provider — from a file in the state directory.
        assert!(!is_usable_credential(b"sk-live\r\nX-Injected: yes"));
        assert!(!is_usable_credential(b"sk-live\nX-Injected: yes"));
        assert!(!is_usable_credential(b"sk-live\r"));
    }

    #[test]
    fn a_credential_that_is_not_utf8_is_refused() {
        // This is the fail-open case: `expose_str` returns `None`, and an
        // adapter's `if let Some(...)` omits the header and dispatches the
        // request unauthenticated.
        assert!(!is_usable_credential(&[0xff, 0xfe, 0x00]));
        assert!(!is_usable_credential("sk-café".as_bytes()));
    }

    #[test]
    fn control_bytes_are_refused_even_where_utf8_permits_them() {
        assert!(!is_usable_credential(b"sk-live\0trailing"));
        assert!(!is_usable_credential(b"sk-live\x1b[0m"));
    }

    #[test]
    fn a_usable_credential_always_survives_expose_str() {
        // The property that makes checking at load sufficient: anything this
        // accepts is guaranteed to produce a header, so no adapter can silently
        // skip one.
        let name = hypellm_core::ids::CredentialRef::new("cred").expect("reference");
        let handle = crate::CredentialHandle::new(&name, b"sk-live-value");
        assert!(is_usable_credential(handle.expose()));
        assert!(handle.expose_str().is_some());
    }
}

impl fmt::Debug for CredentialHandle<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialHandle({}, [redacted])", self.reference)
    }
}

/// Headers carrying credentials.
///
/// Specification 7.1: "`SensitiveHeaders` is a non-cloneable redacting type.
/// Debug formatting prints only header names."
pub struct SensitiveHeaders {
    entries: Vec<(String, String)>,
    /// Names whose values are secret. Non-secret headers such as
    /// `content-type` render normally, which keeps a debug dump useful.
    secret: Vec<String>,
}

impl SensitiveHeaders {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            secret: Vec::new(),
        }
    }

    /// Add a header whose value is not secret.
    pub fn push(&mut self, name: &str, value: impl Into<String>) {
        self.entries
            .push((name.to_ascii_lowercase(), value.into()));
    }

    /// Add a header whose value is a credential.
    pub fn push_secret(&mut self, name: &str, value: impl Into<String>) {
        let lower = name.to_ascii_lowercase();
        self.secret.push(lower.clone());
        self.entries.push((lower, value.into()));
    }

    /// Iterate over `(name, value)`.
    ///
    /// The only way to read a secret value, and it exists so the HTTP client
    /// can serialize the request.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Header names only, for traces.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    /// How many headers are set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no headers are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a header's value is secret.
    #[must_use]
    pub fn is_secret(&self, name: &str) -> bool {
        self.secret.iter().any(|s| s == name)
    }
}

impl Default for SensitiveHeaders {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SensitiveHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveHeaders {")?;
        for (i, (name, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if self.is_secret(name) {
                write!(f, " {name}: [redacted]")?;
            } else {
                write!(f, " {name}: {value:?}")?;
            }
        }
        f.write_str(" }")
    }
}

/// Why an adapter refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    /// A stable code.
    pub code: &'static str,
    /// A safe, bounded explanation.
    pub detail: Capped,
    /// The request parameter at fault, when there is one.
    pub param: Option<&'static str>,
}

impl ValidationFailure {
    /// Construct.
    #[must_use]
    pub fn new(code: &'static str, detail: &str) -> Self {
        Self {
            code,
            detail: Capped::new(detail, 200),
            param: None,
        }
    }

    /// Name the offending parameter.
    #[must_use]
    pub const fn with_param(mut self, param: &'static str) -> Self {
        self.param = Some(param);
        self
    }

    /// The client-facing error.
    #[must_use]
    pub fn to_router_error(&self) -> hypellm_core::error::RouterError {
        let mut error = hypellm_core::error::RouterError::invalid_request(self.detail.as_str());
        if let Some(param) = self.param {
            error = error.with_param(param);
        }
        error
    }
}

impl fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// The result of validating a request against a target.
pub type ValidationResult = Result<(), ValidationFailure>;

/// What the adapter needs to know about the exchange, beyond the request.
#[derive(Debug, Clone)]
pub struct RequestMeta<'a> {
    /// The target being called.
    pub target: &'a Target,
    /// The endpoint being called.
    pub endpoint: &'a Endpoint,
    /// The router's request identifier, for provider-side correlation.
    pub request_id: String,
    /// Whether the client asked for a stream.
    pub streaming: bool,
    /// An idempotency key, when the client supplied one.
    pub idempotency_key: Option<String>,
}

/// A decoded provider error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorClassification {
    /// How the router classifies it.
    pub class: UpstreamErrorClass,
    /// The provider's own error type token, bounded and sanitised.
    pub provider_code: Option<Capped>,
    /// A safe detail for the client.
    ///
    /// Adapters must not forward a provider's message verbatim: it can contain
    /// an internal hostname, a quota identifier, or an echo of the prompt.
    pub safe_detail: Capped,
    /// Seconds the provider asked the caller to wait.
    pub retry_after_secs: Option<u32>,
}

impl ErrorClassification {
    /// Whether the router may retry on another target.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        self.class.is_retriable()
    }
}

/// The provider-family adapter.
///
/// Every method is pure: given the same inputs it produces the same output, and
/// none of them performs I/O. The transport is the caller's job, which is what
/// lets the whole adapter surface be tested against recorded fixtures
/// (specification 21, "Integration — Each provider adapter against recorded
/// golden server").
pub trait Adapter: Send + Sync + fmt::Debug {
    /// The family this adapter serves.
    fn family(&self) -> hypellm_core::target::ProviderFamily;

    /// The request path for an operation, relative to the endpoint base path.
    fn path_for(&self, request: &CanonicalRequest) -> Result<&'static str, ValidationFailure>;

    /// Check the request against the target's declared capabilities.
    fn validate(&self, request: &CanonicalRequest, capabilities: &Capabilities)
    -> ValidationResult;

    /// Build the request headers, including authentication.
    fn encode_headers(
        &self,
        credential: Option<&CredentialHandle<'_>>,
        meta: &RequestMeta<'_>,
    ) -> SensitiveHeaders;

    /// Serialize the request body.
    fn encode_request(
        &self,
        request: &CanonicalRequest,
        meta: &RequestMeta<'_>,
    ) -> Result<Vec<u8>, ValidationFailure>;

    /// Decode a complete, non-streaming response body into canonical events.
    fn decode_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification>;

    /// Decode one streaming event's payload into canonical events.
    ///
    /// Returns an empty vector for an event that carries no canonical meaning,
    /// such as a provider keepalive or a frame the router does not model.
    fn decode_stream_event(
        &self,
        event_name: Option<&str>,
        data: &str,
    ) -> Result<Vec<CanonicalEvent>, ErrorClassification>;

    /// Whether a streaming payload is the terminal marker.
    fn is_stream_terminator(&self, data: &str) -> bool;

    /// Classify an error response.
    fn classify_error(&self, status: u16, body: &[u8]) -> ErrorClassification;

    /// Extract usage from a decoded event sequence.
    ///
    /// Returns a router-estimated value when the provider reported none, so
    /// that metering always has a number and always knows its provenance
    /// (specification 7.1, 14).
    fn usage_from_events(&self, events: &[CanonicalEvent]) -> CanonicalUsage {
        for event in events.iter().rev() {
            if let CanonicalEvent::Usage(usage) = event {
                return *usage;
            }
        }
        CanonicalUsage::estimated(0, 0)
    }
}

/// Map an HTTP status to an error class, the shape every provider shares.
#[must_use]
pub fn class_for_status(status: u16) -> UpstreamErrorClass {
    match status {
        400 | 422 => UpstreamErrorClass::InvalidRequest,
        401 | 403 => UpstreamErrorClass::Authentication,
        404 => UpstreamErrorClass::InvalidRequest,
        408 => UpstreamErrorClass::Timeout,
        413 => UpstreamErrorClass::ContextOverflow,
        429 => UpstreamErrorClass::RateLimited,
        500..=599 => UpstreamErrorClass::ServerError,
        _ => UpstreamErrorClass::ProtocolViolation,
    }
}

/// Reduce a provider-supplied token to something safe to record.
///
/// A provider error type is attacker-influenced in the sense that the router
/// does not control it; narrowing it to an identifier alphabet keeps it out of
/// log-injection territory.
#[must_use]
pub fn sanitize_provider_code(raw: &str) -> Capped {
    let narrowed: String = raw
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Capped::new(&narrowed, 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::ids::CredentialRef;

    #[test]
    fn a_credential_handle_redacts_its_secret() {
        let reference = CredentialRef::new("cred_openai").unwrap();
        let handle = CredentialHandle::new(&reference, b"sk-live-abcdef123456");
        let rendered = format!("{handle:?}");
        assert!(!rendered.contains("sk-live"));
        assert!(rendered.contains("cred_openai"));
        assert_eq!(handle.expose_str(), Some("sk-live-abcdef123456"));
    }

    #[test]
    fn sensitive_headers_redact_only_secret_values() {
        let mut headers = SensitiveHeaders::new();
        headers.push("content-type", "application/json");
        headers.push_secret("authorization", "Bearer sk-live-abcdef123456");
        headers.push_secret("x-api-key", "secret-key-value");
        headers.push("accept", "text/event-stream");

        let rendered = format!("{headers:?}");
        assert!(!rendered.contains("sk-live"));
        assert!(!rendered.contains("secret-key-value"));
        // Names stay visible, which is what makes a debug dump useful.
        assert!(rendered.contains("authorization"));
        assert!(rendered.contains("x-api-key"));
        // Non-secret values stay visible too.
        assert!(rendered.contains("application/json"));
        assert!(rendered.contains("text/event-stream"));
    }

    #[test]
    fn header_names_are_lowercased_and_iterable() {
        let mut headers = SensitiveHeaders::new();
        headers.push("Content-Type", "application/json");
        headers.push_secret("Authorization", "Bearer x");
        let names: Vec<&str> = headers.names().collect();
        assert_eq!(names, vec!["content-type", "authorization"]);
        assert!(headers.is_secret("authorization"));
        assert!(!headers.is_secret("content-type"));
        assert_eq!(headers.len(), 2);
        assert!(!headers.is_empty());
    }

    #[test]
    fn the_values_are_still_reachable_for_serialization() {
        let mut headers = SensitiveHeaders::new();
        headers.push_secret("authorization", "Bearer secret");
        let pairs: Vec<(&str, &str)> = headers.iter().collect();
        assert_eq!(pairs, vec![("authorization", "Bearer secret")]);
    }

    #[test]
    fn status_classification_matches_the_failover_rules() {
        // Retriable, per specification 6.5.
        for status in [429u16, 500, 502, 503, 504] {
            assert!(
                class_for_status(status).is_retriable(),
                "status {status} should be retriable"
            );
        }
        // Not retriable: the same request to another target fails the same way.
        for status in [400u16, 401, 403, 404, 413, 422] {
            assert!(
                !class_for_status(status).is_retriable(),
                "status {status} must not be retriable"
            );
        }
        assert_eq!(class_for_status(401), UpstreamErrorClass::Authentication);
        assert_eq!(class_for_status(413), UpstreamErrorClass::ContextOverflow);
        assert_eq!(class_for_status(429), UpstreamErrorClass::RateLimited);
    }

    #[test]
    fn a_provider_credential_failure_is_not_a_health_signal() {
        // The router's own key expiring says nothing about the target's health,
        // and counting it would open a circuit for a configuration problem.
        assert!(!UpstreamErrorClass::Authentication.affects_health());
        assert!(UpstreamErrorClass::ServerError.affects_health());
    }

    #[test]
    fn provider_codes_are_narrowed() {
        let hostile = "rate_limit\n{\"forged\":true}\x1b[31m";
        let safe = sanitize_provider_code(hostile);
        assert!(!safe.as_str().contains('\n'));
        assert!(!safe.as_str().contains('{'));
        assert!(!safe.as_str().contains('\x1b'));
        assert!(safe.as_str().starts_with("rate_limit"));
        assert_eq!(sanitize_provider_code(&"x".repeat(500)).as_str().len(), 64);
    }

    #[test]
    fn validation_failures_become_client_errors_with_a_parameter() {
        let failure = ValidationFailure::new("tools_unsupported", "this model does not support tools")
            .with_param("tools");
        let error = failure.to_router_error();
        assert_eq!(error.code, hypellm_core::error::ErrorCode::InvalidRequest);
        assert_eq!(error.param.expect("param").as_str(), "tools");
        assert!(error.detail.as_str().contains("does not support tools"));
    }
}
