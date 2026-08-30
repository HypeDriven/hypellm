//! Management sessions and CSRF binding.
//!
//! Specification 9.1:
//!
//! - "Issue a router session identifier in a Secure, HttpOnly, SameSite=Lax
//!   cookie. Store only a digest server-side. Rotate on authentication and
//!   privilege change; short idle and absolute lifetimes."
//! - "Protect all state-changing management requests with same-origin
//!   enforcement and a session-bound CSRF token; set a strict CORS allowlist."
//! - "Logout invalidates the server session."
//!
//! # Why only a digest is stored
//!
//! The cookie value is a 256-bit random token. The server keeps
//! `HMAC(server_key, token)`. Someone who reads the session table — a backup, a
//! memory dump, a log that should not have contained it — gets verifiers, not
//! session cookies. This mirrors the API key design for the same reason.
//!
//! # Why the CSRF token is derived, not stored
//!
//! The CSRF token is `HMAC(server_key, "csrf" || session_digest)`. It is
//! reproducible from the session, so it needs no separate storage and cannot
//! drift out of sync; and because it is keyed, a page that can *read* the
//! session cookie cannot compute it — which is what makes the double-submit
//! pattern meaningful here.

use hypellm_core::ids::{PrincipalId, TenantId};
use hypellm_core::rbac::{Permission, PermissionSet, Role};
use hypellm_crypto::{Digest, base64, ct, hmac_sha256_parts, random};
use core::fmt;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// The session cookie name.
///
/// The `__Host-` prefix is enforced by browsers: the cookie must be Secure,
/// have no Domain attribute, and have Path=/. That makes it impossible for a
/// subdomain to set or overwrite it, which closes session fixation from a
/// neighbouring host.
pub const COOKIE_NAME: &str = "__Host-hypellm_session";

/// The header carrying the CSRF token.
pub const CSRF_HEADER: &str = "x-hypellm-csrf";

/// Bytes of session token material.
pub const TOKEN_BYTES: usize = 32;

/// How a session was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Google OIDC sign-in.
    Oidc,
    /// A local break-glass credential.
    ///
    /// Specification 22.4: "Authorized operators use a preprovisioned local
    /// break-glass method stored offline."
    BreakGlass,
    /// A local username and password.
    ///
    /// Not one of specification 9.2's four methods — see `LocalUser` in
    /// `hypellm-config` and `docs/deferred-issues.md` for why it exists anyway.
    /// It is recorded distinctly because an investigation's first question is
    /// how a principal authenticated, and a password session answered as
    /// `oidc` would say the identity provider vouched for someone it has never
    /// seen.
    Password,
    /// A router API key on the inference listener.
    ///
    /// Specification 17 requires an audit record to identify how a principal
    /// authenticated, and specification 22.3's investigation workflow reads
    /// that field. Key-authenticated callers were previously recorded as
    /// `LocalPeer` — not an authentication bypass, since scopes, roles, tenant,
    /// and key id were all correct, but every one of them was exported as
    /// having presented Unix socket peer credentials, which is a false answer
    /// to the question an investigation asks first.
    ApiKey,
    /// Unix socket peer credentials.
    LocalPeer,
    /// No credential was presented, and the deployment configured an anonymous
    /// principal for the inference listener to fall back to.
    ///
    /// Recorded as its own method for the reason [`Self::ApiKey`] was added:
    /// specification 22.3's investigation starts from *how* a principal
    /// authenticated, and the honest answer here is "it did not". Reusing
    /// `ApiKey` would export every open request as having presented a
    /// credential that was never issued, which is precisely the false answer
    /// that field exists to prevent.
    ///
    /// This is a deviation from specification 9.2, recorded in
    /// `docs/deferred-issues.md`. It is off unless configured.
    Anonymous,
}

impl AuthMethod {
    /// Stable name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::BreakGlass => "break_glass",
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::LocalPeer => "local_peer",
            Self::Anonymous => "anonymous",
        }
    }
}

/// A server-side session record.
#[derive(Debug, Clone)]
pub struct Session {
    /// The keyed digest of the cookie token. The token itself is not stored.
    pub digest: Digest,
    /// Who the session belongs to.
    pub principal: PrincipalId,
    /// The tenant.
    pub tenant: TenantId,
    /// The immutable subject the identity provider asserted, as `iss|sub`.
    ///
    /// Specification 9.1: "Map immutable subject (iss, sub) to a local
    /// principal. Email is an attribute, not the stable identity key."
    pub subject: Option<String>,
    /// The email attribute, for display only.
    pub email: Option<String>,
    /// Management roles held.
    pub roles: Vec<Role>,
    /// How the session was established.
    pub method: AuthMethod,
    /// When the session was created.
    pub created_at_millis: u64,
    /// When the session was last used.
    pub last_seen_millis: u64,
    /// When the session expires regardless of activity.
    pub absolute_expiry_millis: u64,
    /// When the most recent authentication happened.
    ///
    /// Sensitive actions require a recent one (specification 9.1).
    pub authenticated_at_millis: u64,
}

impl Session {
    /// The permissions this session holds.
    #[must_use]
    pub fn permissions(&self) -> PermissionSet {
        PermissionSet::from_roles(&self.roles)
    }

    /// Whether the session holds a permission.
    #[must_use]
    pub fn can(&self, permission: Permission) -> bool {
        self.permissions().has(permission)
    }

    /// Whether the session is a break-glass session.
    #[must_use]
    pub fn is_break_glass(&self) -> bool {
        self.method == AuthMethod::BreakGlass || self.roles.contains(&Role::BreakGlassAdmin)
    }
}

/// Session lifetime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Maximum time between requests before the session expires.
    pub idle_millis: u64,
    /// Maximum session lifetime regardless of activity.
    pub absolute_millis: u64,
    /// How recently a sensitive action must have been authenticated.
    pub reauthentication_millis: u64,
    /// Maximum concurrent sessions held, a memory backstop.
    pub max_sessions: usize,
}

impl SessionPolicy {
    /// Defaults matching specification 9.1's "short idle and absolute
    /// lifetimes".
    pub const DEFAULT: Self = Self {
        idle_millis: 30 * 60 * 1000,
        absolute_millis: 12 * 60 * 60 * 1000,
        reauthentication_millis: 5 * 60 * 1000,
        max_sessions: 10_000,
    };
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a session was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRejection {
    /// No session cookie was present.
    Missing,
    /// The cookie value was malformed.
    Malformed,
    /// No session matches.
    Unknown,
    /// The session exceeded its idle timeout.
    IdleExpired,
    /// The session exceeded its absolute lifetime.
    AbsoluteExpired,
    /// The CSRF token was absent or did not match.
    CsrfMismatch,
    /// The request origin is not permitted.
    OriginNotPermitted,
    /// The action requires a more recent authentication.
    ReauthenticationRequired,
    /// The session lacks the permission the action requires.
    PermissionDenied,
}

impl SessionRejection {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "session_missing",
            Self::Malformed => "session_malformed",
            Self::Unknown => "session_unknown",
            Self::IdleExpired => "session_idle_expired",
            Self::AbsoluteExpired => "session_absolute_expired",
            Self::CsrfMismatch => "csrf_mismatch",
            Self::OriginNotPermitted => "origin_not_permitted",
            Self::ReauthenticationRequired => "reauthentication_required",
            Self::PermissionDenied => "permission_denied",
        }
    }

    /// What the caller is told.
    #[must_use]
    pub const fn client_code(self) -> hypellm_core::error::ErrorCode {
        match self {
            Self::PermissionDenied
            | Self::CsrfMismatch
            | Self::OriginNotPermitted
            | Self::ReauthenticationRequired => hypellm_core::error::ErrorCode::Forbidden,
            _ => hypellm_core::error::ErrorCode::Unauthenticated,
        }
    }
}

impl fmt::Display for SessionRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A newly issued session: the record plus the one-time cookie value.
pub struct IssuedSession {
    /// The stored record.
    pub session: Session,
    /// The cookie value to send to the browser.
    pub token: String,
    /// The CSRF token for this session.
    pub csrf_token: String,
}

impl fmt::Debug for IssuedSession {
    /// Redacted. Both fields are bearer values: the cookie authenticates every
    /// subsequent management request, and the CSRF token defeats the
    /// cross-site check. Specification 17 keeps them out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedSession")
            .field("session", &self.session)
            .field("token", &"[redacted session token]")
            .field("csrf_token", &"[redacted csrf token]")
            .finish()
    }
}

impl IssuedSession {
    /// The `Set-Cookie` header value.
    ///
    /// `HttpOnly` keeps script from reading it; `Secure` keeps it off cleartext;
    /// `SameSite=Lax` stops it riding along on a cross-site form post; `Path=/`
    /// and no `Domain` are required by the `__Host-` prefix.
    #[must_use]
    pub fn set_cookie_header(&self, max_age_secs: u64) -> String {
        format!(
            "{COOKIE_NAME}={}; Max-Age={max_age_secs}; Path=/; Secure; HttpOnly; SameSite=Lax",
            self.token
        )
    }
}

/// The session store.
pub struct SessionStore {
    digest_key: Vec<u8>,
    policy: SessionPolicy,
    sessions: RwLock<BTreeMap<Digest, Session>>,
}

impl fmt::Debug for SessionStore {
    /// Redacted. The digest key lets any session token be forged.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStore")
            .field("digest_key", &"[redacted key material]")
            .field("policy", &self.policy)
            .field("sessions", &self.sessions.read().map(|s| s.len()).unwrap_or(0))
            .finish()
    }
}

impl SessionStore {
    /// Create a store.
    #[must_use]
    pub fn new(digest_key: &[u8], policy: SessionPolicy) -> Self {
        Self {
            digest_key: digest_key.to_vec(),
            policy,
            sessions: RwLock::new(BTreeMap::new()),
        }
    }

    /// The lifetime policy.
    #[must_use]
    pub const fn policy(&self) -> SessionPolicy {
        self.policy
    }

    /// The digest stored for a cookie token.
    #[must_use]
    pub fn digest_for(&self, token: &str) -> Digest {
        Digest::from_bytes(hmac_sha256_parts(
            &self.digest_key,
            &[b"hypellm.session.v1", token.as_bytes()],
        ))
    }

    /// The CSRF token bound to a session digest.
    #[must_use]
    pub fn csrf_for(&self, digest: &Digest) -> String {
        let tag = hmac_sha256_parts(
            &self.digest_key,
            &[b"hypellm.csrf.v1", digest.as_bytes()],
        );
        base64::encode_url_nopad(&tag)
    }

    /// How many sessions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.read().map_or(0, |s| s.len())
    }

    /// Whether no sessions are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Issue a session.
    #[allow(clippy::too_many_arguments, reason = "a session record has this many attributes")]
    pub fn issue(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        subject: Option<String>,
        email: Option<String>,
        roles: Vec<Role>,
        method: AuthMethod,
        now_millis: u64,
    ) -> Result<IssuedSession, random::RandomError> {
        let lifetime = self.policy.absolute_millis;
        self.issue_for(
            principal, tenant, subject, email, roles, method, now_millis, lifetime,
        )
    }

    /// Issue a session with an explicit absolute lifetime.
    ///
    /// Specification 22.4 requires break-glass access to be "time-limited", and
    /// the ordinary twelve-hour session lifetime is not that. The lifetime is a
    /// parameter rather than a second policy field because it is a property of
    /// *how* the session was established, not of the store.
    ///
    /// The lifetime is only ever shortened, never extended: passing something
    /// longer than the configured absolute lifetime is clamped, so a
    /// misconfigured break-glass TTL cannot mint a session that outlives the
    /// policy every other session obeys.
    #[allow(clippy::too_many_arguments, reason = "one session's full identity")]
    pub fn issue_for(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        subject: Option<String>,
        email: Option<String>,
        roles: Vec<Role>,
        method: AuthMethod,
        now_millis: u64,
        absolute_millis: u64,
    ) -> Result<IssuedSession, random::RandomError> {
        let absolute_millis = absolute_millis.min(self.policy.absolute_millis);
        let token_bytes = random::bytes::<TOKEN_BYTES>()?;
        let token = base64::encode_url_nopad(&token_bytes);
        let digest = self.digest_for(&token);

        let session = Session {
            digest,
            principal,
            tenant,
            subject,
            email,
            roles,
            method,
            created_at_millis: now_millis,
            last_seen_millis: now_millis,
            absolute_expiry_millis: now_millis.saturating_add(absolute_millis),
            authenticated_at_millis: now_millis,
        };

        if let Ok(mut map) = self.sessions.write() {
            if map.len() >= self.policy.max_sessions {
                // Evict the oldest by last activity rather than refusing to
                // sign anyone in.
                if let Some(oldest) = map
                    .values()
                    .min_by_key(|s| s.last_seen_millis)
                    .map(|s| s.digest)
                {
                    map.remove(&oldest);
                }
            }
            map.insert(digest, session.clone());
        }

        Ok(IssuedSession {
            csrf_token: self.csrf_for(&digest),
            session,
            token,
        })
    }

    /// Look up and validate a session by cookie token, updating activity.
    pub fn validate(&self, token: &str, now_millis: u64) -> Result<Session, SessionRejection> {
        if token.is_empty() || token.len() > 128 {
            return Err(SessionRejection::Malformed);
        }
        let digest = self.digest_for(token);

        let mut map = self
            .sessions
            .write()
            .map_err(|_| SessionRejection::Unknown)?;
        let Some(session) = map.get_mut(&digest) else {
            return Err(SessionRejection::Unknown);
        };

        if now_millis >= session.absolute_expiry_millis {
            let expired = session.digest;
            map.remove(&expired);
            return Err(SessionRejection::AbsoluteExpired);
        }
        if now_millis.saturating_sub(session.last_seen_millis) >= self.policy.idle_millis {
            let expired = session.digest;
            map.remove(&expired);
            return Err(SessionRejection::IdleExpired);
        }

        session.last_seen_millis = now_millis;
        Ok(session.clone())
    }

    /// Verify a CSRF token against a session.
    pub fn verify_csrf(
        &self,
        session: &Session,
        presented: Option<&str>,
    ) -> Result<(), SessionRejection> {
        let expected = self.csrf_for(&session.digest);
        let presented = presented.ok_or(SessionRejection::CsrfMismatch)?;
        if ct::eq(expected.as_bytes(), presented.as_bytes()) {
            Ok(())
        } else {
            Err(SessionRejection::CsrfMismatch)
        }
    }

    /// Rotate a session's token, keeping its identity.
    ///
    /// Specification 9.1: "Rotate on authentication and privilege change."
    /// Rotation is what makes a session fixed before sign-in useless after it.
    pub fn rotate(
        &self,
        old_token: &str,
        now_millis: u64,
    ) -> Result<IssuedSession, SessionRejection> {
        let old_digest = self.digest_for(old_token);
        let existing = {
            let map = self
                .sessions
                .read()
                .map_err(|_| SessionRejection::Unknown)?;
            map.get(&old_digest).cloned()
        };
        let Some(mut session) = existing else {
            return Err(SessionRejection::Unknown);
        };

        let token_bytes = random::bytes::<TOKEN_BYTES>().map_err(|_| SessionRejection::Unknown)?;
        let token = base64::encode_url_nopad(&token_bytes);
        let digest = self.digest_for(&token);

        session.digest = digest;
        session.last_seen_millis = now_millis;
        session.authenticated_at_millis = now_millis;

        if let Ok(mut map) = self.sessions.write() {
            map.remove(&old_digest);
            map.insert(digest, session.clone());
        }

        Ok(IssuedSession {
            csrf_token: self.csrf_for(&digest),
            session,
            token,
        })
    }

    /// Invalidate a session.
    pub fn invalidate(&self, token: &str) -> bool {
        let digest = self.digest_for(token);
        self.sessions
            .write()
            .map(|mut m| m.remove(&digest).is_some())
            .unwrap_or(false)
    }

    /// Invalidate every session for a principal.
    ///
    /// Used when a role binding changes: the old session's cached roles must
    /// not outlive the grant.
    pub fn invalidate_principal(&self, principal: &PrincipalId) -> usize {
        match self.sessions.write() {
            Ok(mut map) => {
                let doomed: Vec<Digest> = map
                    .values()
                    .filter(|s| s.principal == *principal)
                    .map(|s| s.digest)
                    .collect();
                for d in &doomed {
                    map.remove(d);
                }
                doomed.len()
            }
            Err(_) => 0,
        }
    }

    /// Remove expired sessions.
    pub fn sweep(&self, now_millis: u64) -> usize {
        match self.sessions.write() {
            Ok(mut map) => {
                let before = map.len();
                map.retain(|_, s| {
                    now_millis < s.absolute_expiry_millis
                        && now_millis.saturating_sub(s.last_seen_millis) < self.policy.idle_millis
                });
                before - map.len()
            }
            Err(_) => 0,
        }
    }

    /// Check that a sensitive action has a recent enough authentication.
    pub fn require_fresh_authentication(
        &self,
        session: &Session,
        now_millis: u64,
    ) -> Result<(), SessionRejection> {
        if now_millis.saturating_sub(session.authenticated_at_millis)
            <= self.policy.reauthentication_millis
        {
            Ok(())
        } else {
            Err(SessionRejection::ReauthenticationRequired)
        }
    }

    /// Authorize a management action end to end.
    ///
    /// Combines the permission check with the reauthentication rule, so a call
    /// site cannot do one and forget the other.
    pub fn authorize(
        &self,
        session: &Session,
        permission: Permission,
        now_millis: u64,
    ) -> Result<(), SessionRejection> {
        if !session.can(permission) {
            return Err(SessionRejection::PermissionDenied);
        }
        if permission.requires_reauthentication() {
            self.require_fresh_authentication(session, now_millis)?;
        }
        Ok(())
    }

    /// Sessions belonging to a principal, for the management view.
    #[must_use]
    pub fn sessions_for(&self, principal: &PrincipalId) -> Vec<Session> {
        self.sessions
            .read()
            .map(|m| {
                m.values()
                    .filter(|s| s.principal == *principal)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether a session has expired under either lifetime.
    ///
    /// The same two rules `validate` applies, so a listing cannot disagree with
    /// what a request would decide.
    #[must_use]
    fn is_expired(&self, session: &Session, now_millis: u64) -> bool {
        now_millis >= session.absolute_expiry_millis
            || now_millis.saturating_sub(session.last_seen_millis) >= self.policy.idle_millis
    }

    /// Live sessions belonging to a tenant, for the users-and-access screen.
    ///
    /// Specification 15.3 lists "sessions" among what that screen shows, and
    /// Appendix B bounds it: "management visibility never exceeds the caller's
    /// tenant and permissions". Expired sessions are excluded — a screen that
    /// lists a session an operator can no longer use invites them to revoke
    /// something that is already gone, and hides the ones that matter.
    ///
    /// The cookie token is not stored anywhere, so nothing this returns can be
    /// replayed; a [`Session`] carries only the digest.
    #[must_use]
    pub fn sessions_for_tenant(&self, tenant: &TenantId, now_millis: u64) -> Vec<Session> {
        self.sessions
            .read()
            .map(|m| {
                let mut live: Vec<Session> = m
                    .values()
                    .filter(|s| s.tenant == *tenant && !self.is_expired(s, now_millis))
                    .cloned()
                    .collect();
                // Newest first, then by principal, so the order is total and a
                // page does not shuffle between reads.
                live.sort_by(|a, b| {
                    b.created_at_millis
                        .cmp(&a.created_at_millis)
                        .then_with(|| a.principal.cmp(&b.principal))
                        .then_with(|| a.digest.to_hex().cmp(&b.digest.to_hex()))
                });
                live
            })
            .unwrap_or_default()
    }
}

/// Extract a named cookie from a `Cookie` header value.
///
/// Deliberately strict: names are compared exactly, values must not contain a
/// separator, and only the first occurrence is returned. A lenient cookie
/// parser is how a `__Host-` cookie set by an attacker on a sibling name gets
/// picked up instead of the real one.
#[must_use]
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key == name {
            if value.is_empty() || value.contains(|c: char| c.is_whitespace() || c == ';') {
                return None;
            }
            return Some(value);
        }
    }
    None
}

/// Whether a request's `Origin` is permitted.
///
/// Specification 15.4: "Cross-origin deployment uses an exact origin allowlist,
/// credentials mode, preflight validation, and no wildcard with cookies."
/// Matching is exact — no suffix matching, which is how `evil-example.com`
/// passes a check for `example.com`.
#[must_use]
pub fn origin_permitted(origin: Option<&str>, allowlist: &[String]) -> bool {
    match origin {
        // A same-origin request from a browser omits Origin on safe methods.
        // State-changing requests are additionally gated by the CSRF token, so
        // an absent Origin is not sufficient on its own to act.
        None => true,
        Some(o) => allowlist.iter().any(|allowed| allowed == o),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"session-digest-key-for-tests";
    const NOW: u64 = 1_767_225_600_000;

    fn store() -> SessionStore {
        SessionStore::new(KEY, SessionPolicy::DEFAULT)
    }

    fn issue(store: &SessionStore, roles: Vec<Role>) -> IssuedSession {
        store
            .issue(
                PrincipalId::new("user:alice").unwrap(),
                TenantId::new("acme").unwrap(),
                Some("https://accounts.google.com|1234567890".to_owned()),
                Some("alice@example.com".to_owned()),
                roles,
                AuthMethod::Oidc,
                NOW,
            )
            .expect("entropy")
    }

    #[test]
    fn debug_output_never_contains_the_session_token_csrf_token_or_digest_key() {
        let store = store();
        let issued = issue(&store, vec![Role::Viewer]);

        let rendered = format!("{issued:?}");
        assert!(!rendered.contains(&issued.token), "IssuedSession leaked the session token");
        assert!(
            !rendered.contains(&issued.csrf_token),
            "IssuedSession leaked the CSRF token"
        );
        assert!(rendered.contains("[redacted"));

        let store_rendered = format!("{store:?}");
        assert!(
            !store_rendered.contains(&String::from_utf8_lossy(KEY).to_string()),
            "SessionStore leaked the digest key"
        );
        assert!(store_rendered.contains("[redacted"));
    }

    #[test]
    fn an_issued_session_validates() {
        let store = store();
        let issued = issue(&store, vec![Role::Viewer]);
        let session = store.validate(&issued.token, NOW).expect("validates");
        assert_eq!(session.principal.as_str(), "user:alice");
        assert_eq!(session.method, AuthMethod::Oidc);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn the_store_holds_a_digest_not_the_token() {
        let store = store();
        let issued = issue(&store, vec![Role::Viewer]);
        let stored = issued.session.digest.to_hex();
        assert!(!stored.contains(&issued.token));
        // And the digest is not usable as a token.
        assert!(store.validate(&stored, NOW).is_err());
    }

    #[test]
    fn tokens_are_unique() {
        use std::collections::BTreeSet;
        let store = store();
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            assert!(seen.insert(issue(&store, Vec::new()).token));
        }
    }

    #[test]
    fn an_unknown_or_malformed_token_is_rejected() {
        let store = store();
        assert_eq!(store.validate("", NOW).unwrap_err(), SessionRejection::Malformed);
        assert_eq!(
            store.validate(&"x".repeat(500), NOW).unwrap_err(),
            SessionRejection::Malformed
        );
        assert_eq!(
            store.validate("not-a-real-token", NOW).unwrap_err(),
            SessionRejection::Unknown
        );
    }

    #[test]
    fn idle_timeout_expires_a_session() {
        let store = store();
        let issued = issue(&store, Vec::new());
        let idle = SessionPolicy::DEFAULT.idle_millis;

        assert!(store.validate(&issued.token, NOW + idle - 1).is_ok());
        // Activity resets the idle window.
        assert!(store.validate(&issued.token, NOW + idle + idle - 2).is_ok());
        assert_eq!(
            store
                .validate(&issued.token, NOW + idle * 3)
                .unwrap_err(),
            SessionRejection::IdleExpired
        );
        assert_eq!(store.len(), 0, "an expired session is removed");
    }

    #[test]
    fn absolute_lifetime_expires_a_busy_session() {
        // The point of an absolute lifetime: continuous activity must not keep
        // a session alive forever.
        let store = store();
        let issued = issue(&store, Vec::new());
        let absolute = SessionPolicy::DEFAULT.absolute_millis;

        // Step forward in increments smaller than the idle window, so the
        // session stays continuously active right up to the absolute limit.
        let mut now = NOW;
        while now + 60_000 < NOW + absolute {
            now += 60_000;
            assert!(store.validate(&issued.token, now).is_ok(), "at {now}");
        }
        assert_eq!(
            store.validate(&issued.token, NOW + absolute).unwrap_err(),
            SessionRejection::AbsoluteExpired
        );
    }

    #[test]
    fn logout_invalidates_the_session() {
        let store = store();
        let issued = issue(&store, Vec::new());
        assert!(store.invalidate(&issued.token));
        assert_eq!(
            store.validate(&issued.token, NOW).unwrap_err(),
            SessionRejection::Unknown
        );
        assert!(!store.invalidate(&issued.token), "already gone");
    }

    #[test]
    fn rotation_replaces_the_token_and_keeps_the_identity() {
        // Specification 9.1: rotate on authentication. A token fixed before
        // sign-in must not survive it.
        let store = store();
        let issued = issue(&store, vec![Role::Viewer]);
        let old_token = issued.token.clone();

        let rotated = store.rotate(&old_token, NOW + 1000).expect("rotates");
        assert_ne!(rotated.token, old_token);
        assert_eq!(rotated.session.principal, issued.session.principal);
        assert_eq!(rotated.session.created_at_millis, NOW);
        assert_eq!(rotated.session.authenticated_at_millis, NOW + 1000);

        assert_eq!(
            store.validate(&old_token, NOW + 1000).unwrap_err(),
            SessionRejection::Unknown,
            "the pre-rotation token must be dead"
        );
        assert!(store.validate(&rotated.token, NOW + 1000).is_ok());
        assert_eq!(store.len(), 1, "rotation must not leave the old entry");
    }

    #[test]
    fn rotation_changes_the_csrf_token() {
        let store = store();
        let issued = issue(&store, Vec::new());
        let rotated = store.rotate(&issued.token, NOW + 1).expect("rotates");
        assert_ne!(rotated.csrf_token, issued.csrf_token);
        assert!(store.verify_csrf(&issued.session, Some(&issued.csrf_token)).is_ok());
        assert!(
            store
                .verify_csrf(&rotated.session, Some(&issued.csrf_token))
                .is_err(),
            "the old CSRF token must not work against the new session"
        );
    }

    #[test]
    fn csrf_tokens_are_session_bound() {
        let store = store();
        let a = issue(&store, Vec::new());
        let b = issue(&store, Vec::new());

        assert!(store.verify_csrf(&a.session, Some(&a.csrf_token)).is_ok());
        assert_eq!(
            store
                .verify_csrf(&a.session, Some(&b.csrf_token))
                .unwrap_err(),
            SessionRejection::CsrfMismatch,
            "another session's token must not work"
        );
        assert_eq!(
            store.verify_csrf(&a.session, None).unwrap_err(),
            SessionRejection::CsrfMismatch
        );
        assert_eq!(
            store.verify_csrf(&a.session, Some("")).unwrap_err(),
            SessionRejection::CsrfMismatch
        );
    }

    #[test]
    fn the_csrf_token_is_not_derivable_from_the_cookie_alone() {
        // A script that can read the cookie still cannot compute the token,
        // because the derivation is keyed with a server-held key.
        let store = store();
        let issued = issue(&store, Vec::new());
        let other_store = SessionStore::new(b"a-different-key", SessionPolicy::DEFAULT);
        let guessed = other_store.csrf_for(&issued.session.digest);
        assert_ne!(guessed, issued.csrf_token);
    }

    #[test]
    fn invalidating_a_principal_kills_every_session() {
        let store = store();
        let a = issue(&store, Vec::new());
        let b = issue(&store, Vec::new());
        let other = store
            .issue(
                PrincipalId::new("user:bob").unwrap(),
                TenantId::new("acme").unwrap(),
                None,
                None,
                Vec::new(),
                AuthMethod::Oidc,
                NOW,
            )
            .unwrap();

        let killed = store.invalidate_principal(&PrincipalId::new("user:alice").unwrap());
        assert_eq!(killed, 2);
        assert!(store.validate(&a.token, NOW).is_err());
        assert!(store.validate(&b.token, NOW).is_err());
        assert!(store.validate(&other.token, NOW).is_ok(), "bob is unaffected");
    }

    #[test]
    fn sweeping_removes_expired_sessions() {
        let store = store();
        for _ in 0..5 {
            issue(&store, Vec::new());
        }
        assert_eq!(store.len(), 5);
        assert_eq!(store.sweep(NOW), 0, "nothing has expired yet");
        assert_eq!(store.sweep(NOW + SessionPolicy::DEFAULT.absolute_millis), 5);
        assert!(store.is_empty());
    }

    #[test]
    fn the_session_table_is_bounded() {
        let policy = SessionPolicy {
            max_sessions: 4,
            ..SessionPolicy::DEFAULT
        };
        let store = SessionStore::new(KEY, policy);
        for i in 0..20u64 {
            store
                .issue(
                    PrincipalId::new(format!("user:{i}")).unwrap(),
                    TenantId::new("acme").unwrap(),
                    None,
                    None,
                    Vec::new(),
                    AuthMethod::Oidc,
                    NOW + i,
                )
                .unwrap();
        }
        assert!(store.len() <= 4, "session table grew to {}", store.len());
    }

    #[test]
    fn authorization_combines_permission_and_freshness() {
        let store = store();
        let issued = issue(&store, vec![Role::PolicyApprover]);
        let session = &issued.session;

        // Holds the permission and just authenticated.
        assert!(store.authorize(session, Permission::PublishPolicy, NOW).is_ok());

        // Same permission, stale authentication.
        assert_eq!(
            store
                .authorize(session, Permission::PublishPolicy, NOW + 3_600_000)
                .unwrap_err(),
            SessionRejection::ReauthenticationRequired
        );

        // A non-sensitive permission does not need freshness.
        assert!(
            store
                .authorize(session, Permission::ReadSummary, NOW + 3_600_000)
                .is_ok()
        );

        // A permission the role does not hold.
        assert_eq!(
            store
                .authorize(session, Permission::EditPolicy, NOW)
                .unwrap_err(),
            SessionRejection::PermissionDenied
        );
    }

    #[test]
    fn a_viewer_cannot_perform_management_actions() {
        let store = store();
        let issued = issue(&store, vec![Role::Viewer]);
        for permission in [
            Permission::PublishPolicy,
            Permission::ManageCredentials,
            Permission::ManageKeys,
            Permission::BreakGlass,
            Permission::OperateTargets,
        ] {
            assert_eq!(
                store
                    .authorize(&issued.session, permission, NOW)
                    .unwrap_err(),
                SessionRejection::PermissionDenied,
                "{permission}"
            );
        }
    }

    #[test]
    fn break_glass_sessions_are_identifiable() {
        let store = store();
        let normal = issue(&store, vec![Role::Operator]);
        assert!(!normal.session.is_break_glass());

        let bg = store
            .issue(
                PrincipalId::new("user:oncall").unwrap(),
                TenantId::new("acme").unwrap(),
                None,
                None,
                vec![Role::BreakGlassAdmin],
                AuthMethod::BreakGlass,
                NOW,
            )
            .unwrap();
        assert!(bg.session.is_break_glass());
    }

    #[test]
    fn the_cookie_carries_the_required_attributes() {
        let store = store();
        let issued = issue(&store, Vec::new());
        let header = issued.set_cookie_header(1800);

        assert!(header.starts_with("__Host-hypellm_session="));
        assert!(header.contains("; Secure"));
        assert!(header.contains("; HttpOnly"));
        assert!(header.contains("; SameSite=Lax"));
        assert!(header.contains("; Path=/"));
        assert!(
            !header.contains("Domain="),
            "the __Host- prefix forbids a Domain attribute"
        );
    }

    #[test]
    fn cookie_parsing_is_exact() {
        let header = "other=1; __Host-hypellm_session=abc123; another=2";
        assert_eq!(cookie_value(header, COOKIE_NAME), Some("abc123"));
        assert_eq!(cookie_value(header, "other"), Some("1"));
        assert_eq!(cookie_value(header, "absent"), None);

        // A near-miss name must not match.
        let hostile = "hypellm_session=attacker; __Host-hypellm_session_x=no";
        assert_eq!(cookie_value(hostile, COOKIE_NAME), None);

        // The first occurrence wins, and an empty value is not a value.
        assert_eq!(cookie_value("a=1; a=2", "a"), Some("1"));
        assert_eq!(cookie_value("a=", "a"), None);
        assert_eq!(cookie_value("", COOKIE_NAME), None);
        assert_eq!(cookie_value("novalue", "novalue"), None);
    }

    #[test]
    fn origin_matching_is_exact() {
        let allowlist = vec!["https://admin.example".to_owned()];
        assert!(origin_permitted(Some("https://admin.example"), &allowlist));
        assert!(!origin_permitted(Some("https://admin.example.evil.com"), &allowlist));
        assert!(!origin_permitted(Some("https://evil.com/admin.example"), &allowlist));
        assert!(!origin_permitted(Some("http://admin.example"), &allowlist));
        assert!(!origin_permitted(Some("https://ADMIN.example"), &allowlist));
        assert!(!origin_permitted(Some("null"), &allowlist));
        assert!(origin_permitted(None, &allowlist));

        // An empty allowlist permits no cross-origin request at all.
        assert!(!origin_permitted(Some("https://admin.example"), &[]));
    }

    #[test]
    fn rejections_map_to_the_error_contract() {
        for r in [
            SessionRejection::Missing,
            SessionRejection::Malformed,
            SessionRejection::Unknown,
            SessionRejection::IdleExpired,
            SessionRejection::AbsoluteExpired,
        ] {
            assert_eq!(
                r.client_code(),
                hypellm_core::error::ErrorCode::Unauthenticated,
                "{r}"
            );
        }
        for r in [
            SessionRejection::CsrfMismatch,
            SessionRejection::OriginNotPermitted,
            SessionRejection::ReauthenticationRequired,
            SessionRejection::PermissionDenied,
        ] {
            assert_eq!(r.client_code(), hypellm_core::error::ErrorCode::Forbidden, "{r}");
        }
    }
}
