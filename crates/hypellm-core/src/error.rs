//! The client-facing error contract of specification 8.2.
//!
//! Every failure the router reports to a caller is one of these codes. The
//! rules that make the contract usable:
//!
//! - The code is stable. Clients and harness compatibility profiles depend on
//!   it, so it is part of the API surface, not a log string.
//! - The detail is *safe*: it never contains a prompt, a credential, an
//!   upstream URL, an internal hostname, or a provider error body
//!   (specification 10).
//! - Retryability is a property of the error, not a guess by the caller.

use crate::sensitive::Capped;
use core::fmt;

/// A stable router error code (specification 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// 400 — malformed or unsupported request.
    InvalidRequest,
    /// 401 — missing or invalid client authentication.
    Unauthenticated,
    /// 403 — authenticated but denied by policy.
    Forbidden,
    /// 404 — alias absent or hidden from this caller.
    ModelNotFound,
    /// 409 — same idempotency key with a different request digest.
    IdempotencyConflict,
    /// 429 — principal quota exceeded.
    RateLimited,
    /// 429 — finite queue or capacity reached.
    CapacityExhausted,
    /// 502 — the provider violated the adapter contract.
    UpstreamInvalidResponse,
    /// 503 — no target meets policy, health, or capability requirements.
    NoEligibleTarget,
    /// 504 — the end-to-end deadline expired.
    DeadlineExceeded,
    /// 500 — an internal fault. Never carries detail.
    InternalFault,
}

impl ErrorCode {
    /// The wire code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::ModelNotFound => "model_not_found",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::RateLimited => "rate_limited",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::UpstreamInvalidResponse => "upstream_invalid_response",
            Self::NoEligibleTarget => "no_eligible_target",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InternalFault => "internal_fault",
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::ModelNotFound => 404,
            Self::IdempotencyConflict => 409,
            Self::RateLimited | Self::CapacityExhausted => 429,
            Self::UpstreamInvalidResponse => 502,
            Self::NoEligibleTarget => 503,
            Self::DeadlineExceeded => 504,
            Self::InternalFault => 500,
        }
    }

    /// Whether the router may retry this on another target.
    ///
    /// Specification 6.5: "Context overflow, unsupported feature, policy
    /// denial, invalid request, and authentication errors are not retriable."
    #[must_use]
    pub const fn is_retriable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::CapacityExhausted | Self::UpstreamInvalidResponse
        )
    }

    /// The OpenAI-compatible error `type` for the client error envelope.
    #[must_use]
    pub const fn openai_type(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::ModelNotFound | Self::IdempotencyConflict => {
                "invalid_request_error"
            }
            Self::Unauthenticated => "authentication_error",
            Self::Forbidden => "permission_error",
            Self::RateLimited | Self::CapacityExhausted => "rate_limit_error",
            Self::UpstreamInvalidResponse
            | Self::NoEligibleTarget
            | Self::DeadlineExceeded
            | Self::InternalFault => "api_error",
        }
    }

    /// The Anthropic-compatible error `type`.
    #[must_use]
    pub const fn anthropic_type(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::IdempotencyConflict => "invalid_request_error",
            Self::Unauthenticated => "authentication_error",
            Self::Forbidden => "permission_error",
            Self::ModelNotFound => "not_found_error",
            Self::RateLimited | Self::CapacityExhausted => "rate_limit_error",
            Self::UpstreamInvalidResponse | Self::NoEligibleTarget => "api_error",
            Self::DeadlineExceeded => "timeout_error",
            Self::InternalFault => "api_error",
        }
    }

    /// Every code, for exhaustiveness tests and documentation generation.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::InvalidRequest,
            Self::Unauthenticated,
            Self::Forbidden,
            Self::ModelNotFound,
            Self::IdempotencyConflict,
            Self::RateLimited,
            Self::CapacityExhausted,
            Self::UpstreamInvalidResponse,
            Self::NoEligibleTarget,
            Self::DeadlineExceeded,
            Self::InternalFault,
        ]
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A router error: a stable code plus a bounded, safe detail string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterError {
    /// The stable code.
    pub code: ErrorCode,
    /// A message safe to return to the caller.
    pub detail: Capped,
    /// Seconds to wait before retrying, when the router can say.
    pub retry_after_secs: Option<u32>,
    /// The parameter at fault, for `invalid_request` only.
    pub param: Option<Capped>,
}

impl RouterError {
    /// Construct with a safe detail string.
    ///
    /// The detail is capped at 256 bytes. Callers must pass a message they
    /// authored, never an upstream body or a caller-supplied value.
    #[must_use]
    pub fn new(code: ErrorCode, detail: &str) -> Self {
        Self {
            code,
            detail: Capped::log_field(detail),
            retry_after_secs: None,
            param: None,
        }
    }

    /// Attach a `Retry-After` hint.
    #[must_use]
    pub const fn with_retry_after(mut self, secs: u32) -> Self {
        self.retry_after_secs = Some(secs);
        self
    }

    /// Name the offending request parameter.
    #[must_use]
    pub fn with_param(mut self, param: &str) -> Self {
        self.param = Some(Capped::new(param, 64));
        self
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.code.status()
    }

    /// Whether the router may try another target.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        self.code.is_retriable()
    }

    /// A 400 for a malformed request.
    #[must_use]
    pub fn invalid_request(detail: &str) -> Self {
        Self::new(ErrorCode::InvalidRequest, detail)
    }

    /// A 403 for a policy denial.
    #[must_use]
    pub fn forbidden(detail: &str) -> Self {
        Self::new(ErrorCode::Forbidden, detail)
    }

    /// A 500 that never carries detail.
    ///
    /// Specification 18.2: "Public errors are stable codes with safe detail;
    /// internal causes are chained only in redacted logs." An internal fault
    /// reveals nothing at all to the caller — the request id is the only
    /// correlation handle they get.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(ErrorCode::InternalFault, "internal error")
    }
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RouterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_statuses_match_specification_8_2() {
        let expected: &[(ErrorCode, u16, &str)] = &[
            (ErrorCode::InvalidRequest, 400, "invalid_request"),
            (ErrorCode::Unauthenticated, 401, "unauthenticated"),
            (ErrorCode::Forbidden, 403, "forbidden"),
            (ErrorCode::ModelNotFound, 404, "model_not_found"),
            (ErrorCode::IdempotencyConflict, 409, "idempotency_conflict"),
            (ErrorCode::RateLimited, 429, "rate_limited"),
            (ErrorCode::CapacityExhausted, 429, "capacity_exhausted"),
            (
                ErrorCode::UpstreamInvalidResponse,
                502,
                "upstream_invalid_response",
            ),
            (ErrorCode::NoEligibleTarget, 503, "no_eligible_target"),
            (ErrorCode::DeadlineExceeded, 504, "deadline_exceeded"),
        ];
        for (code, status, text) in expected {
            assert_eq!(code.status(), *status, "{code}");
            assert_eq!(code.as_str(), *text);
        }
    }

    #[test]
    fn code_strings_are_distinct() {
        let mut names: Vec<&str> = ErrorCode::all().iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn retriability_matches_specification_6_5() {
        // Not retriable: policy, authentication, validity, and capability
        // failures. Retrying those on another target changes nothing.
        for code in [
            ErrorCode::InvalidRequest,
            ErrorCode::Unauthenticated,
            ErrorCode::Forbidden,
            ErrorCode::ModelNotFound,
            ErrorCode::IdempotencyConflict,
            ErrorCode::DeadlineExceeded,
            ErrorCode::NoEligibleTarget,
            ErrorCode::InternalFault,
        ] {
            assert!(!code.is_retriable(), "{code} must not be retriable");
        }
        for code in [
            ErrorCode::RateLimited,
            ErrorCode::CapacityExhausted,
            ErrorCode::UpstreamInvalidResponse,
        ] {
            assert!(code.is_retriable(), "{code} should be retriable");
        }
    }

    #[test]
    fn deadline_exceeded_is_never_retried() {
        // Specification 6.5 caps Retry-After by the remaining deadline; once
        // the deadline has passed there is nothing left to retry into.
        assert!(!ErrorCode::DeadlineExceeded.is_retriable());
    }

    #[test]
    fn detail_is_capped() {
        let e = RouterError::invalid_request(&"x".repeat(1000));
        assert_eq!(e.detail.as_str().len(), 256);
        assert!(e.detail.is_truncated());
    }

    #[test]
    fn internal_fault_reveals_nothing() {
        let e = RouterError::internal();
        assert_eq!(e.code, ErrorCode::InternalFault);
        assert_eq!(e.detail.as_str(), "internal error");
        assert_eq!(e.param, None);
    }

    #[test]
    fn protocol_type_mappings_are_populated() {
        for code in ErrorCode::all() {
            assert!(!code.openai_type().is_empty(), "{code}");
            assert!(!code.anthropic_type().is_empty(), "{code}");
        }
        assert_eq!(ErrorCode::Unauthenticated.openai_type(), "authentication_error");
        assert_eq!(ErrorCode::ModelNotFound.anthropic_type(), "not_found_error");
        assert_eq!(ErrorCode::DeadlineExceeded.anthropic_type(), "timeout_error");
    }

    #[test]
    fn retry_after_and_param_are_optional() {
        let e = RouterError::new(ErrorCode::RateLimited, "quota exceeded").with_retry_after(30);
        assert_eq!(e.retry_after_secs, Some(30));
        let e = RouterError::invalid_request("bad field").with_param("max_tokens");
        assert_eq!(e.param.unwrap().as_str(), "max_tokens");
    }
}
