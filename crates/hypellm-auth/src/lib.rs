//! Authentication and authorization.
//!
//! Specification 18.1: "auth — API keys, sessions, OIDC verifier boundary
//! client, RBAC."
//!
//! # The four ways a principal is established
//!
//! Specification 9.2 lists them, and each has its own module or type here:
//!
//! | Method | Used by | Where |
//! |---|---|---|
//! | Router API key | coding harnesses, services | [`apikey`] |
//! | Google OIDC session | humans in the admin UI | [`oidc`], [`session`] |
//! | Local password | humans, before OIDC is set up | [`session::AuthMethod::Password`] |
//! | Local peer credentials | same-host tools | [`peer`] |
//! | Break-glass | offline recovery | [`session::AuthMethod::BreakGlass`] |
//!
//! mTLS identity is the fifth; specification 9.2 says the identity is "supplied
//! only by trusted edge", so it arrives as a header the edge sets and is
//! handled by [`peer::TrustedEdge`].
//!
//! The password row is a **deviation**, not a fifth method the specification
//! names: specification 9.2 lists four, and a local account is none of them. It
//! is recorded in `docs/deferred-issues.md`, it exists so that a deployment can
//! be operated before an identity provider is configured, and it is the weakest
//! way into the management plane. The hashing it needs is
//! `hypellm_crypto::pbkdf2`; the sign-in handler is in `hypellm-admin-api`.
//!
//! # What is deliberately absent
//!
//! No JWT signature verification and no TLS. Specification 9.1 delegates both
//! to a platform verifier.

#![forbid(unsafe_code)]
// Specification 18.2: no panics on data-plane input, all integer conversions
// checked. This crate sits on the request path — every request that carries a
// key, a cookie, or an identity token is parsed here — so the workspace's
// warn-level lints are escalated to `deny` at its root. Only the lints this
// crate actually has to satisfy are listed; a new unchecked conversion or
// unguarded index is a compile error, not another warning in a long list.
#![cfg_attr(not(test), deny(clippy::as_conversions, clippy::integer_division))]

pub mod apikey;
pub mod oidc;
pub mod peer;
pub mod session;

pub use apikey::{KeyRecord, KeyRejection, KeyStore, NewKey, Scope, SourceRestriction};
pub use oidc::{IdTokenClaims, OidcConfig, OidcError, TokenVerifier, TransactionStore};
pub use peer::{PeerIdentity, TrustedEdge};
pub use session::{
    AuthMethod, IssuedSession, Session, SessionPolicy, SessionRejection, SessionStore,
};

use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::ids::{PrincipalId, TenantId};
use hypellm_core::rbac::{PermissionSet, Role};

/// An authenticated caller.
///
/// Specification 5.1: "principal — Resolved server-side; client cannot
/// override." Every field here is derived from a verified credential; nothing
/// is copied from a request body or a caller-supplied header.
#[derive(Debug, Clone)]
pub struct Principal {
    /// The principal identifier.
    pub id: PrincipalId,
    /// The tenant.
    pub tenant: TenantId,
    /// How the caller authenticated.
    pub method: AuthMethod,
    /// Inference scopes held, for a key-authenticated caller.
    pub scopes: Vec<Scope>,
    /// Management roles held.
    pub roles: Vec<Role>,
    /// The key record identifier, when authenticated by key.
    pub key_id: Option<hypellm_core::ids::KeyId>,
    /// The groups the principal belongs to.
    ///
    /// Specification 25: from local role bindings or a provisioned directory
    /// sync — never inferred from an email domain.
    pub groups: Vec<hypellm_core::ids::GroupId>,
}

impl Principal {
    /// The permissions this principal holds.
    #[must_use]
    pub fn permissions(&self) -> PermissionSet {
        PermissionSet::from_roles(&self.roles)
    }

    /// Whether an inference scope is held.
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Build from a verified API key record.
    #[must_use]
    pub fn from_key(record: &KeyRecord, groups: Vec<hypellm_core::ids::GroupId>) -> Self {
        Self {
            id: record.principal.clone(),
            tenant: record.tenant.clone(),
            method: AuthMethod::ApiKey,
            scopes: record.scopes.clone(),
            roles: record.roles.clone(),
            key_id: Some(record.id.clone()),
            groups,
        }
    }

    /// Build the principal an uncredentialed inference request is served as.
    ///
    /// Only reachable when `anonymous_enabled` is configured, which
    /// `hypellm-config` refuses unless a principal, a tenant, and a
    /// management-free scope list are all present. Nothing here invents an
    /// identity: every field comes from configuration, and `key_id` is `None`
    /// because no key was presented — an audit reader asking "which key" gets
    /// no answer rather than a wrong one.
    #[must_use]
    pub fn anonymous(
        id: hypellm_core::ids::PrincipalId,
        tenant: hypellm_core::ids::TenantId,
        scopes: Vec<Scope>,
        groups: Vec<hypellm_core::ids::GroupId>,
    ) -> Self {
        Self {
            id,
            tenant,
            method: AuthMethod::Anonymous,
            scopes,
            // No management roles, ever. The scope list is validated at
            // startup and the role list is simply not offered: an anonymous
            // caller reaches the inference listener, and the management
            // listener authenticates sessions by a path this never touches.
            roles: Vec::new(),
            key_id: None,
            groups,
        }
    }

    /// Build from a validated session.
    #[must_use]
    pub fn from_session(session: &Session, groups: Vec<hypellm_core::ids::GroupId>) -> Self {
        Self {
            id: session.principal.clone(),
            tenant: session.tenant.clone(),
            method: session.method,
            scopes: Vec::new(),
            roles: session.roles.clone(),
            key_id: None,
            groups,
        }
    }
}

/// Why authentication failed, across all methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No credential was presented.
    NoCredential,
    /// An API key was rejected.
    Key(KeyRejection),
    /// A session was rejected.
    Session(SessionRejection),
    /// A sign-in failed.
    Oidc(OidcError),
    /// Peer credentials were not usable.
    Peer,
}

impl AuthFailure {
    /// Stable code for audit and metrics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoCredential => "no_credential",
            Self::Key(k) => k.code(),
            Self::Session(s) => s.code(),
            Self::Oidc(o) => o.code(),
            Self::Peer => "peer_credentials_unavailable",
        }
    }

    /// The client-facing error.
    ///
    /// The detail is always generic. Specification 8.2 gives `unauthenticated`
    /// and `forbidden` no sub-codes for a reason: telling a caller *why* their
    /// credential failed is an oracle.
    #[must_use]
    pub fn to_router_error(self) -> RouterError {
        let code = match self {
            Self::NoCredential | Self::Peer => ErrorCode::Unauthenticated,
            Self::Key(k) => k.client_code(),
            Self::Session(s) => s.client_code(),
            Self::Oidc(_) => ErrorCode::Unauthenticated,
        };
        let detail = match code {
            ErrorCode::Forbidden => "the credential is not permitted to perform this action",
            _ => "a valid credential is required",
        };
        RouterError::new(code, detail)
    }
}

impl core::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_key_authenticated_principal_records_that_it_used_a_key() {
        // Specification 17 requires the audit record to identify how a
        // principal authenticated. Every key-authenticated caller used to be
        // recorded as `local_peer` — Unix socket peer credentials — because
        // `AuthMethod` had no `ApiKey` variant. Not a bypass: scopes, roles,
        // tenant, and key id were all correct. But specification 22.3's
        // investigation starts from *how* someone got in, and that field
        // answered wrongly for every request on the inference listener.
        let key = crate::apikey::KeyRecord {
            id: hypellm_core::ids::KeyId::new("key_test").expect("key id"),
            verifier: hypellm_crypto::Digest::from_bytes([0u8; 32]),
            tenant: hypellm_core::ids::TenantId::new("acme").expect("tenant"),
            principal: hypellm_core::ids::PrincipalId::new("svc:a").expect("principal"),
            scopes: vec![Scope::Inference],
            roles: Vec::new(),
            expires_at_millis: None,
            source: SourceRestriction::Any,
            created_at_millis: 0,
            description: None,
            revoked: false,
        };
        let principal = Principal::from_key(&key, Vec::new());
        assert_eq!(principal.method, AuthMethod::ApiKey);
        assert_eq!(principal.method.as_str(), "api_key");
        assert_ne!(
            principal.method,
            AuthMethod::LocalPeer,
            "a key is not a peer credential"
        );
    }

    use super::*;
    use hypellm_core::rbac::Permission;

    #[test]
    fn failures_do_not_disclose_which_check_failed() {
        // Every unauthenticated failure produces the same client-visible
        // message, whatever the internal reason.
        let failures = [
            AuthFailure::NoCredential,
            AuthFailure::Key(KeyRejection::UnknownKey),
            AuthFailure::Key(KeyRejection::BadSecret),
            AuthFailure::Key(KeyRejection::Expired),
            AuthFailure::Session(SessionRejection::Unknown),
            AuthFailure::Session(SessionRejection::IdleExpired),
            AuthFailure::Oidc(OidcError::NonceMismatch),
            AuthFailure::Peer,
        ];
        let details: Vec<String> = failures
            .iter()
            .map(|f| f.to_router_error().detail.as_str().to_owned())
            .collect();
        assert!(
            details.windows(2).all(|w| w[0] == w[1]),
            "client-visible details differ between failure modes: {details:?}"
        );

        // The internal codes remain distinct, for audit and metrics.
        let mut codes: Vec<&str> = failures.iter().map(|f| f.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);
    }

    #[test]
    fn scope_failures_report_forbidden_not_unauthenticated() {
        let e = AuthFailure::Key(KeyRejection::ScopeNotPermitted).to_router_error();
        assert_eq!(e.code, ErrorCode::Forbidden);
        assert_eq!(e.status(), 403);

        let e = AuthFailure::Key(KeyRejection::BadSecret).to_router_error();
        assert_eq!(e.code, ErrorCode::Unauthenticated);
        assert_eq!(e.status(), 401);
    }

    #[test]
    fn a_principal_from_a_key_carries_its_scopes_and_roles() {
        let store = KeyStore::new(b"verifier-key");
        let new_key = store
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:ci").unwrap(),
                vec![Scope::Inference],
                vec![Role::Viewer],
                None,
                SourceRestriction::Any,
                None,
                0,
            )
            .unwrap();

        let principal = Principal::from_key(&new_key.record, Vec::new());
        assert_eq!(principal.id.as_str(), "svc:ci");
        assert_eq!(principal.tenant.as_str(), "acme");
        assert!(principal.has_scope(Scope::Inference));
        assert!(!principal.has_scope(Scope::Embeddings));
        assert!(principal.permissions().has(Permission::ReadSummary));
        assert!(principal.key_id.is_some());
    }

    #[test]
    fn a_principal_from_a_session_carries_no_inference_scopes() {
        // A browser session authorises management actions, not inference. A
        // session that could also drive the inference API would let a CSRF on
        // the admin UI spend a tenant's token budget.
        let store = SessionStore::new(b"session-key", SessionPolicy::DEFAULT);
        let issued = store
            .issue(
                PrincipalId::new("user:alice").unwrap(),
                TenantId::new("acme").unwrap(),
                None,
                None,
                vec![Role::Operator],
                AuthMethod::Oidc,
                0,
            )
            .unwrap();

        let principal = Principal::from_session(&issued.session, Vec::new());
        assert!(principal.scopes.is_empty());
        assert!(!principal.has_scope(Scope::Inference));
        assert!(principal.permissions().has(Permission::OperateTargets));
        assert!(principal.key_id.is_none());
    }
}
