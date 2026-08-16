//! The versioned management API.
//!
//! Specification 18.1: "admin-api — Versioned management handlers and
//! schemas." Specification 16 fixes the surface and 15.4 the behaviour:
//!
//! > All management resources live under `/admin/v1` and use explicit JSON
//! > schemas, ETags, If-Match on mutation, pagination cursors, stable error
//! > codes, and request IDs.
//!
//! # Separation from the data plane
//!
//! Specification 3 separates the management path from the hot path "in code,
//! scheduling, rate limits, authentication scopes, and listener
//! configuration". This crate is that separation in code: it has no access to
//! the inference pipeline, and the inference listener never routes to
//! `/admin/v1`.
//!
//! # What the API cannot do
//!
//! - **Read a credential secret.** There is no handler for it and no
//!   permission that would authorize one (specification 9.3).
//! - **Publish a draft the caller wrote**, unless a deployment deliberately
//!   enables self-approval (specification 9.3).
//! - **Act on a state-changing request without a CSRF token and a permitted
//!   origin** (specification 9.1).

#![forbid(unsafe_code)]
// Specification 18.2: "no panics on data-plane input" and "all integer
// conversions checked". The management surface parses attacker-shaped request
// targets, headers, and bodies, so the workspace warnings are escalated to
// errors here: a new unchecked index or a new truncating division in this
// crate is a build failure, not one more line of clippy output. Only the lints
// this crate has had to resolve are listed; the rest stay at the workspace
// warn level so that a first occurrence is still visible.
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::integer_division))]

pub mod audit_index;
pub mod cors;
pub mod decisions;
pub mod drafts;
pub mod handlers;
pub mod response;
pub mod usage;

pub use audit_index::AuditIndex;
pub use cors::{CorsPolicy, PreflightOutcome, security_headers};
pub use decisions::DecisionCache;
pub use drafts::{Draft, DraftStore, PublishRefusal};
pub use handlers::{
    AdminApi, AdminRequest, AdminState, BreakGlassPolicy, CredentialSink, ProbeOutcome,
};
pub use response::{ApiError, ApiErrorCode, ApiResponse, Pagination};
pub use usage::{UsageAggregate, UsageSample, UsageStatus, UsageTotals};
