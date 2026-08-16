//! Google OIDC sign-in: authorization code with PKCE S256.
//!
//! Specification 9.1 sets every rule this module implements. The two that shape
//! the design most:
//!
//! > Use exact preconfigured issuer, authorization endpoint, token endpoint,
//! > client_id, redirect URI, and allowed hosted domains. **No discovery URL or
//! > redirect is supplied by the browser.**
//!
//! So [`OidcConfig`] holds fixed strings from configuration and there is no
//! code path that reads an endpoint from a request. A `redirect_uri` parameter
//! arriving on the callback is ignored, not honoured.
//!
//! > **OIDC dependency boundary:** JWT signature verification and HTTPS are
//! > cryptographic security functions. Strict profile delegates them to an
//! > approved local identity/TLS verifier service… Never write novel signature
//! > or TLS code merely to satisfy "no dependencies".
//!
//! So this module contains **no signature verification**. It builds the
//! authorization URL, manages the transaction, and validates the *claims* of an
//! already-verified token — which is ordinary comparison logic, exhaustively
//! testable, and where the interesting bugs actually live. The signature is
//! checked by whatever implements [`TokenVerifier`], which in the strict
//! profile is a client of the platform verifier socket.

use hypellm_crypto::{Digest, base64, ct, hmac_sha256_parts, random, sha256};
use core::fmt;
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// The transaction cookie name.
///
/// Separate from the session cookie: it exists only between the redirect to the
/// provider and the callback, and is cleared immediately afterwards.
pub const TRANSACTION_COOKIE: &str = "__Host-hypellm_oidc";

/// How long a sign-in transaction may remain open.
pub const TRANSACTION_TTL_MILLIS: u64 = 10 * 60 * 1000;

/// Maximum concurrent open transactions.
pub const MAX_TRANSACTIONS: usize = 4096;

/// Fixed OIDC configuration.
///
/// Every field comes from the router's own configuration. Nothing here is ever
/// read from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The expected `iss` claim, for example `https://accounts.google.com`.
    pub issuer: String,
    /// The client identifier, which is also the expected `aud`.
    pub client_id: String,
    /// The fixed authorization endpoint.
    pub authorization_endpoint: String,
    /// The fixed token endpoint.
    pub token_endpoint: String,
    /// The fixed redirect URI the router owns.
    pub redirect_uri: String,
    /// Hosted domains permitted to sign in. Empty means any.
    ///
    /// Specification 9.1: "Optional hd/domain rules are authorization inputs but
    /// not proof of group membership."
    pub hosted_domains: Vec<String>,
    /// Permitted clock skew when checking `exp` and `iat`.
    pub clock_skew_millis: u64,
}

impl OidcConfig {
    /// Whether the configuration is complete enough to attempt a sign-in.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.issuer.is_empty()
            && !self.client_id.is_empty()
            && self.authorization_endpoint.starts_with("https://")
            && self.token_endpoint.starts_with("https://")
            && !self.redirect_uri.is_empty()
    }
}

/// An open sign-in transaction.
///
/// Held server-side. The browser gets only an opaque handle, so none of these
/// values can be chosen by the caller.
#[derive(Clone)]
pub struct Transaction {
    /// The `state` parameter.
    pub state: String,
    /// The `nonce` claim the identity token must carry.
    pub nonce: String,
    /// The PKCE code verifier.
    pub code_verifier: String,
    /// When the transaction was opened.
    pub created_at_millis: u64,
    /// Where to send the browser after a successful sign-in.
    ///
    /// A path within the admin application, never an absolute URL — an open
    /// redirect here would turn the router's own domain into a phishing hop.
    pub return_path: String,
}

impl fmt::Debug for Transaction {
    /// Redacted. The nonce and the PKCE code verifier are the two values that
    /// bind this transaction to the browser that started it: an attacker
    /// holding them can complete someone else's sign-in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("state", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("code_verifier", &"[redacted pkce verifier]")
            .field("created_at_millis", &self.created_at_millis)
            .field("return_path", &self.return_path)
            .finish()
    }
}

impl Transaction {
    /// Whether the transaction has expired.
    #[must_use]
    pub fn is_expired(&self, now_millis: u64) -> bool {
        now_millis.saturating_sub(self.created_at_millis) > TRANSACTION_TTL_MILLIS
    }
}

/// The start of a sign-in.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// The URL to redirect the browser to.
    pub url: String,
    /// The opaque transaction handle to set as a cookie.
    pub transaction_handle: String,
}

impl AuthorizationRequest {
    /// The `Set-Cookie` header for the transaction.
    ///
    /// `Max-Age` is expressed in whole seconds (RFC 6265), so the millisecond
    /// TTL is converted through [`Duration`] rather than by a bare division.
    #[must_use]
    pub fn set_cookie_header(&self) -> String {
        format!(
            "{TRANSACTION_COOKIE}={}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
            self.transaction_handle,
            Duration::from_millis(TRANSACTION_TTL_MILLIS).as_secs()
        )
    }

    /// The header that clears the transaction cookie.
    #[must_use]
    pub fn clear_cookie_header() -> String {
        format!("{TRANSACTION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")
    }
}

/// Why a sign-in failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcError {
    /// Sign-in is not configured.
    NotConfigured,
    /// The transaction cookie was absent.
    MissingTransaction,
    /// No transaction matches the handle.
    UnknownTransaction,
    /// The transaction expired.
    TransactionExpired,
    /// The `state` parameter did not match the transaction.
    StateMismatch,
    /// The provider returned an error instead of a code.
    ProviderError,
    /// The `iss` claim did not match the configured issuer.
    IssuerMismatch,
    /// The `aud` claim did not include the configured client.
    AudienceMismatch,
    /// The `azp` claim was present and did not match.
    AuthorizedPartyMismatch,
    /// The token has expired.
    TokenExpired,
    /// The token was issued in the future beyond the permitted skew.
    TokenNotYetValid,
    /// The `nonce` claim did not match the transaction.
    NonceMismatch,
    /// The subject was absent.
    MissingSubject,
    /// The email address was not verified.
    EmailNotVerified,
    /// The hosted domain is not permitted.
    HostedDomainNotPermitted,
    /// The identity token failed signature verification.
    SignatureInvalid,
    /// The verifier service was unreachable.
    VerifierUnavailable,
    /// Entropy was unavailable, so no transaction could be opened.
    EntropyUnavailable,
}

impl OidcError {
    /// Stable code for audit records and metrics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotConfigured => "oidc_not_configured",
            Self::MissingTransaction => "oidc_missing_transaction",
            Self::UnknownTransaction => "oidc_unknown_transaction",
            Self::TransactionExpired => "oidc_transaction_expired",
            Self::StateMismatch => "oidc_state_mismatch",
            Self::ProviderError => "oidc_provider_error",
            Self::IssuerMismatch => "oidc_issuer_mismatch",
            Self::AudienceMismatch => "oidc_audience_mismatch",
            Self::AuthorizedPartyMismatch => "oidc_azp_mismatch",
            Self::TokenExpired => "oidc_token_expired",
            Self::TokenNotYetValid => "oidc_token_not_yet_valid",
            Self::NonceMismatch => "oidc_nonce_mismatch",
            Self::MissingSubject => "oidc_missing_subject",
            Self::EmailNotVerified => "oidc_email_not_verified",
            Self::HostedDomainNotPermitted => "oidc_hosted_domain_not_permitted",
            Self::SignatureInvalid => "oidc_signature_invalid",
            Self::VerifierUnavailable => "oidc_verifier_unavailable",
            Self::EntropyUnavailable => "oidc_entropy_unavailable",
        }
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OidcError {}

/// Claims from an identity token whose signature has already been verified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// The issuer.
    pub iss: String,
    /// The subject: the immutable identifier within the issuer.
    pub sub: String,
    /// The audiences.
    pub aud: Vec<String>,
    /// The authorized party, when present.
    pub azp: Option<String>,
    /// Expiry, in seconds since the epoch.
    pub exp: u64,
    /// Issued-at, in seconds since the epoch.
    pub iat: u64,
    /// The nonce echoed from the authorization request.
    pub nonce: Option<String>,
    /// The email address, an attribute rather than an identifier.
    pub email: Option<String>,
    /// Whether the provider asserts the email is verified.
    pub email_verified: bool,
    /// The Google Workspace hosted domain, when present.
    pub hd: Option<String>,
    /// The display name.
    pub name: Option<String>,
}

impl IdTokenClaims {
    /// The stable identity key: issuer and subject together.
    ///
    /// Specification 9.1: "Map immutable subject (iss, sub) to a local
    /// principal. Email is an attribute, not the stable identity key." An email
    /// address can be reassigned within a domain; a subject cannot.
    #[must_use]
    pub fn identity_key(&self) -> String {
        format!("{}|{}", self.iss, self.sub)
    }
}

/// The boundary to signature verification.
///
/// Implemented in `hypellm-net` by a client of the platform verifier socket. The
/// trait exists so that this crate contains no cryptographic verification and
/// so that claim validation is testable without one.
pub trait TokenVerifier: Send + Sync + fmt::Debug {
    /// Verify an identity token's signature against pinned issuer keys and
    /// return its claims.
    ///
    /// An implementation must **not** validate `iss`, `aud`, `exp`, or `nonce`
    /// — those are checked by [`validate_claims`], in one place, with tests.
    /// Splitting the checks across two components is how one of them ends up
    /// being skipped.
    fn verify(&self, id_token: &str) -> Result<IdTokenClaims, OidcError>;

    /// Redeem an authorization code for an identity token, then verify it.
    ///
    /// The router cannot do this itself: the token endpoint is HTTPS, and
    /// specification 4 forbids the router from speaking it. The exchange
    /// therefore happens at the same platform boundary that already holds the
    /// issuer keys.
    ///
    /// The **`code_verifier` is the point**. Specification 9.1 requires PKCE,
    /// and PKCE only protects anything if the verifier reaches the token
    /// request: the authorization request sent a challenge, and redeeming the
    /// code has to prove possession of the secret behind it. A router that
    /// generates a verifier and never transmits it has the ceremony and none
    /// of the protection — an intercepted code is still redeemable.
    fn exchange_code(&self, request: &CodeExchange<'_>) -> Result<IdTokenClaims, OidcError>;
}

/// Everything the platform boundary needs to redeem an authorization code.
///
/// Every field comes from configuration or from the server-side transaction.
/// Nothing here is taken from the callback's query string except the code
/// itself, which is why an attacker who replays a callback cannot redirect the
/// exchange somewhere else.
#[derive(Debug, Clone, Copy)]
pub struct CodeExchange<'a> {
    /// The authorization code from the callback.
    pub code: &'a str,
    /// The PKCE verifier held server-side for this transaction.
    pub code_verifier: &'a str,
    /// The redirect URI, which the token endpoint re-checks.
    pub redirect_uri: &'a str,
    /// The client identifier.
    pub client_id: &'a str,
    /// The token endpoint, fixed in configuration and never discovered.
    pub token_endpoint: &'a str,
}

/// Validate the claims of a verified identity token.
///
/// Every check specification 9.1 lists: `iss`, `aud`, `azp` when required,
/// `exp`, `iat` skew, `nonce`, and `email_verified`.
pub fn validate_claims(
    claims: &IdTokenClaims,
    config: &OidcConfig,
    expected_nonce: &str,
    now_wall_millis: u64,
) -> Result<(), OidcError> {
    if claims.iss != config.issuer {
        return Err(OidcError::IssuerMismatch);
    }
    if !claims.aud.iter().any(|a| a == &config.client_id) {
        return Err(OidcError::AudienceMismatch);
    }
    // `azp` matters when the token has multiple audiences: it names which
    // client the token was actually minted for.
    if let Some(azp) = &claims.azp {
        if azp != &config.client_id {
            return Err(OidcError::AuthorizedPartyMismatch);
        }
    }

    // `exp` and `iat` are whole seconds since the epoch (RFC 7519 NumericDate),
    // so both operands are brought down to seconds. `Duration` performs the
    // truncating millis-to-seconds conversion without a bare integer division.
    let now_secs = Duration::from_millis(now_wall_millis).as_secs();
    let skew_secs = Duration::from_millis(config.clock_skew_millis).as_secs();

    if claims.exp.saturating_add(skew_secs) <= now_secs {
        return Err(OidcError::TokenExpired);
    }
    if claims.iat > now_secs.saturating_add(skew_secs) {
        return Err(OidcError::TokenNotYetValid);
    }

    // Constant-time: the nonce is a secret the router generated, and a timing
    // oracle on it would let an attacker confirm a guess.
    let nonce = claims.nonce.as_deref().unwrap_or("");
    if !ct::eq(nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err(OidcError::NonceMismatch);
    }

    if claims.sub.is_empty() {
        return Err(OidcError::MissingSubject);
    }
    if claims.email.is_some() && !claims.email_verified {
        return Err(OidcError::EmailNotVerified);
    }

    if !config.hosted_domains.is_empty() {
        let hd = claims.hd.as_deref().unwrap_or("");
        if !config.hosted_domains.iter().any(|d| d == hd) {
            return Err(OidcError::HostedDomainNotPermitted);
        }
    }

    Ok(())
}

/// Open sign-in transactions.
pub struct TransactionStore {
    handle_key: Vec<u8>,
    transactions: RwLock<BTreeMap<Digest, Transaction>>,
}

impl fmt::Debug for TransactionStore {
    /// Redacted. The handle key derives every transaction lookup digest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionStore")
            .field("handle_key", &"[redacted key material]")
            .field("transactions", &self.transactions.read().map(|t| t.len()).unwrap_or(0))
            .finish()
    }
}

impl TransactionStore {
    /// Create a store.
    #[must_use]
    pub fn new(handle_key: &[u8]) -> Self {
        Self {
            handle_key: handle_key.to_vec(),
            transactions: RwLock::new(BTreeMap::new()),
        }
    }

    fn digest_for(&self, handle: &str) -> Digest {
        Digest::from_bytes(hmac_sha256_parts(
            &self.handle_key,
            &[b"hypellm.oidc.transaction.v1", handle.as_bytes()],
        ))
    }

    /// How many transactions are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.read().map_or(0, |t| t.len())
    }

    /// Whether no transactions are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Begin a sign-in, producing the authorization URL and a handle.
    pub fn begin(
        &self,
        config: &OidcConfig,
        return_path: &str,
        now_millis: u64,
    ) -> Result<AuthorizationRequest, OidcError> {
        if !config.is_usable() {
            return Err(OidcError::NotConfigured);
        }

        let state = random_token::<32>()?;
        let nonce = random_token::<32>()?;
        let code_verifier = random_token::<32>()?;
        let handle = random_token::<32>()?;

        // A return path must be a path within the application. Accepting an
        // absolute URL would make the router an open redirect, and an open
        // redirect on an OIDC redirect URI is a token-theft primitive.
        let return_path = sanitize_return_path(return_path);

        let transaction = Transaction {
            state: state.clone(),
            nonce: nonce.clone(),
            code_verifier: code_verifier.clone(),
            created_at_millis: now_millis,
            return_path,
        };

        let digest = self.digest_for(&handle);
        if let Ok(mut map) = self.transactions.write() {
            if map.len() >= MAX_TRANSACTIONS {
                // Evict the oldest rather than refusing to start a sign-in. An
                // open transaction is worth little on its own: completing one
                // still requires the handle cookie and the matching state.
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, t)| t.created_at_millis)
                    .map(|(digest, _)| *digest)
                {
                    map.remove(&oldest);
                }
            }
            map.insert(digest, transaction);
        }

        let challenge = code_challenge_s256(&code_verifier);
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
             &code_challenge={}&code_challenge_method=S256&prompt=select_account",
            config.authorization_endpoint,
            percent_encode(&config.client_id),
            percent_encode(&config.redirect_uri),
            percent_encode("openid email profile"),
            percent_encode(&state),
            percent_encode(&nonce),
            percent_encode(&challenge),
        );

        Ok(AuthorizationRequest {
            url,
            transaction_handle: handle,
        })
    }

    /// Take a transaction, validating the state parameter.
    ///
    /// Read an open transaction without consuming it.
    ///
    /// Exists so the sign-in flow can be tested end to end. Verifying that the
    /// PKCE verifier actually reaches the token exchange means comparing what
    /// crossed the boundary against what the store holds, and every other route
    /// to that value consumes the transaction the callback still needs.
    ///
    /// Not used on any request path — [`TransactionStore::take`] is, and it
    /// removes the transaction, which is what keeps a sign-in single-use. A
    /// caller holding the handle already possesses everything this returns.
    #[must_use]
    pub fn peek(&self, handle: &str) -> Option<Transaction> {
        let digest = self.digest_for(handle);
        self.transactions.read().ok()?.get(&digest).cloned()
    }

    /// The transaction is removed whether or not validation succeeds: a
    /// sign-in attempt is single-use, so a replayed callback finds nothing.
    pub fn take(
        &self,
        handle: Option<&str>,
        state: &str,
        now_millis: u64,
    ) -> Result<Transaction, OidcError> {
        let handle = handle.ok_or(OidcError::MissingTransaction)?;
        if handle.is_empty() || handle.len() > 128 {
            return Err(OidcError::MissingTransaction);
        }
        let digest = self.digest_for(handle);

        let transaction = match self.transactions.write() {
            Ok(mut map) => map.remove(&digest),
            Err(_) => None,
        };
        let transaction = transaction.ok_or(OidcError::UnknownTransaction)?;

        if transaction.is_expired(now_millis) {
            return Err(OidcError::TransactionExpired);
        }
        if !ct::eq(transaction.state.as_bytes(), state.as_bytes()) {
            return Err(OidcError::StateMismatch);
        }
        Ok(transaction)
    }

    /// Remove expired transactions.
    pub fn sweep(&self, now_millis: u64) -> usize {
        match self.transactions.write() {
            Ok(mut map) => {
                let before = map.len();
                map.retain(|_, t| !t.is_expired(now_millis));
                before - map.len()
            }
            Err(_) => 0,
        }
    }
}

fn random_token<const N: usize>() -> Result<String, OidcError> {
    let bytes = random::bytes::<N>().map_err(|_| OidcError::EntropyUnavailable)?;
    Ok(base64::encode_url_nopad(&bytes))
}

/// The PKCE S256 code challenge for a verifier (RFC 7636).
#[must_use]
pub fn code_challenge_s256(verifier: &str) -> String {
    base64::encode_url_nopad(&sha256(verifier.as_bytes()))
}

/// Reduce a return path to something safe to redirect to.
///
/// Must be a single absolute path within the application. Anything else — an
/// absolute URL, a protocol-relative `//host` reference, a backslash form some
/// browsers normalise to a slash — becomes `/`.
#[must_use]
pub fn sanitize_return_path(raw: &str) -> String {
    let candidate = raw.trim();
    if candidate.is_empty()
        || !candidate.starts_with('/')
        || candidate.starts_with("//")
        || candidate.starts_with("/\\")
        || candidate.contains('\\')
        || candidate.contains("://")
        || candidate.len() > 512
        || candidate.contains(|c: char| c.is_control())
    {
        return "/".to_owned();
    }
    candidate.to_owned()
}

/// Percent-encode a query parameter value.
///
/// Unreserved characters per RFC 3986 pass through; everything else is encoded.
/// Conservative by design: over-encoding is harmless, under-encoding lets a
/// value break out of its parameter.
#[must_use]
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"oidc-transaction-key";
    const NOW: u64 = 1_767_225_600_000;
    /// `NOW` as whole seconds, the unit `exp` and `iat` are expressed in.
    const NOW_SECS: u64 = Duration::from_millis(NOW).as_secs();

    fn config() -> OidcConfig {
        OidcConfig {
            issuer: "https://accounts.google.com".to_owned(),
            client_id: "1234.apps.googleusercontent.com".to_owned(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_owned(),
            redirect_uri: "https://router.example/admin/v1/auth/google/callback".to_owned(),
            hosted_domains: Vec::new(),
            clock_skew_millis: 60_000,
        }
    }

    fn claims(nonce: &str) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://accounts.google.com".to_owned(),
            sub: "1234567890".to_owned(),
            aud: vec!["1234.apps.googleusercontent.com".to_owned()],
            azp: Some("1234.apps.googleusercontent.com".to_owned()),
            exp: NOW_SECS + 3600,
            iat: NOW_SECS,
            nonce: Some(nonce.to_owned()),
            email: Some("alice@example.com".to_owned()),
            email_verified: true,
            hd: Some("example.com".to_owned()),
            name: Some("Alice".to_owned()),
        }
    }

    #[test]
    fn debug_output_never_contains_the_pkce_verifier_nonce_or_handle_key() {
        let store = TransactionStore::new(KEY);
        let config = config();
        let _ = store.begin(&config, "/targets", NOW).expect("begins");

        let transaction = Transaction {
            state: "state-value".to_owned(),
            nonce: "nonce-value".to_owned(),
            code_verifier: "pkce-code-verifier-value".to_owned(),
            created_at_millis: NOW,
            return_path: "/targets".to_owned(),
        };

        let rendered = format!("{transaction:?}");
        assert!(
            !rendered.contains(&transaction.code_verifier),
            "Transaction leaked the PKCE code verifier"
        );
        assert!(!rendered.contains(&transaction.nonce), "Transaction leaked the nonce");
        assert!(rendered.contains("[redacted"));

        let store_rendered = format!("{store:?}");
        assert!(
            !store_rendered.contains(&String::from_utf8_lossy(KEY).to_string()),
            "TransactionStore leaked the handle key"
        );
        assert!(store_rendered.contains("[redacted"));
    }

    // -- Authorization request ----------------------------------------------

    #[test]
    fn the_authorization_url_uses_only_configured_values() {
        let store = TransactionStore::new(KEY);
        let config = config();
        let request = store.begin(&config, "/targets", NOW).expect("begins");

        assert!(request.url.starts_with(&config.authorization_endpoint));
        assert!(request.url.contains("response_type=code"));
        assert!(request.url.contains("code_challenge_method=S256"));
        assert!(request.url.contains(&percent_encode(&config.client_id)));
        assert!(request.url.contains(&percent_encode(&config.redirect_uri)));
        assert!(request.url.contains("state="));
        assert!(request.url.contains("nonce="));
        assert!(request.url.contains("code_challenge="));
        // No secret is in the URL: PKCE sends the challenge, not the verifier.
        assert!(!request.url.contains("code_verifier"));
        assert!(!request.url.contains("client_secret"));
    }

    #[test]
    fn the_transaction_cookie_is_host_scoped_and_short_lived() {
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/", NOW).unwrap();
        let header = request.set_cookie_header();
        assert!(header.starts_with("__Host-hypellm_oidc="));
        assert!(header.contains("Secure"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Max-Age=600"));
        assert!(!header.contains("Domain="));

        let clear = AuthorizationRequest::clear_cookie_header();
        assert!(clear.contains("Max-Age=0"));
    }

    #[test]
    fn an_unconfigured_provider_cannot_start_a_sign_in() {
        let store = TransactionStore::new(KEY);
        let mut config = config();
        config.issuer = String::new();
        assert_eq!(
            store.begin(&config, "/", NOW).unwrap_err(),
            OidcError::NotConfigured
        );

        let mut config = self::config();
        // A cleartext endpoint is not usable: the code exchange must go through
        // the approved HTTPS boundary.
        config.token_endpoint = "http://oauth2.googleapis.com/token".to_owned();
        assert_eq!(
            store.begin(&config, "/", NOW).unwrap_err(),
            OidcError::NotConfigured
        );
    }

    #[test]
    fn each_transaction_gets_fresh_secrets() {
        use std::collections::BTreeSet;
        let store = TransactionStore::new(KEY);
        let mut handles = BTreeSet::new();
        for _ in 0..32 {
            let r = store.begin(&config(), "/", NOW).unwrap();
            assert!(handles.insert(r.transaction_handle));
        }
    }

    // -- Callback -----------------------------------------------------------

    #[test]
    fn a_matching_state_completes_the_transaction() {
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/policies", NOW).unwrap();
        let state = extract_param(&request.url, "state");

        let transaction = store
            .take(Some(&request.transaction_handle), &state, NOW)
            .expect("takes");
        assert_eq!(transaction.return_path, "/policies");
        assert!(!transaction.nonce.is_empty());
        assert!(!transaction.code_verifier.is_empty());
    }

    #[test]
    fn a_transaction_is_single_use() {
        // A replayed callback must find nothing.
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/", NOW).unwrap();
        let state = extract_param(&request.url, "state");

        assert!(store.take(Some(&request.transaction_handle), &state, NOW).is_ok());
        assert_eq!(
            store
                .take(Some(&request.transaction_handle), &state, NOW)
                .unwrap_err(),
            OidcError::UnknownTransaction
        );
    }

    #[test]
    fn a_wrong_state_is_rejected_and_consumes_the_transaction() {
        // CSRF on the callback: an attacker who can make the browser hit the
        // callback with their own code cannot supply the right state.
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/", NOW).unwrap();

        assert_eq!(
            store
                .take(Some(&request.transaction_handle), "attacker-state", NOW)
                .unwrap_err(),
            OidcError::StateMismatch
        );
        // Consumed, so the real callback cannot complete either — failing
        // closed rather than leaving a transaction an attacker has probed.
        let state = extract_param(&request.url, "state");
        assert_eq!(
            store
                .take(Some(&request.transaction_handle), &state, NOW)
                .unwrap_err(),
            OidcError::UnknownTransaction
        );
    }

    #[test]
    fn a_missing_or_unknown_handle_is_rejected() {
        let store = TransactionStore::new(KEY);
        assert_eq!(
            store.take(None, "state", NOW).unwrap_err(),
            OidcError::MissingTransaction
        );
        assert_eq!(
            store.take(Some(""), "state", NOW).unwrap_err(),
            OidcError::MissingTransaction
        );
        assert_eq!(
            store.take(Some("no-such-handle"), "state", NOW).unwrap_err(),
            OidcError::UnknownTransaction
        );
    }

    #[test]
    fn transactions_expire() {
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/", NOW).unwrap();
        let state = extract_param(&request.url, "state");
        assert_eq!(
            store
                .take(
                    Some(&request.transaction_handle),
                    &state,
                    NOW + TRANSACTION_TTL_MILLIS + 1
                )
                .unwrap_err(),
            OidcError::TransactionExpired
        );
    }

    #[test]
    fn sweeping_removes_expired_transactions() {
        let store = TransactionStore::new(KEY);
        for _ in 0..5 {
            store.begin(&config(), "/", NOW).unwrap();
        }
        assert_eq!(store.len(), 5);
        assert_eq!(store.sweep(NOW), 0);
        assert_eq!(store.sweep(NOW + TRANSACTION_TTL_MILLIS + 1), 5);
        assert!(store.is_empty());
    }

    // -- PKCE ---------------------------------------------------------------

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // The worked example from RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_challenge_does_not_reveal_the_verifier() {
        let store = TransactionStore::new(KEY);
        let request = store.begin(&config(), "/", NOW).unwrap();
        let state = extract_param(&request.url, "state");
        let challenge = extract_param(&request.url, "code_challenge");
        let transaction = store
            .take(Some(&request.transaction_handle), &state, NOW)
            .unwrap();

        assert_ne!(challenge, transaction.code_verifier);
        assert_eq!(code_challenge_s256(&transaction.code_verifier), challenge);
    }

    // -- Claim validation ---------------------------------------------------

    #[test]
    fn valid_claims_pass() {
        assert!(validate_claims(&claims("n1"), &config(), "n1", NOW).is_ok());
    }

    #[test]
    fn a_wrong_issuer_is_rejected() {
        let mut c = claims("n1");
        c.iss = "https://accounts.evil.example".to_owned();
        assert_eq!(
            validate_claims(&c, &config(), "n1", NOW).unwrap_err(),
            OidcError::IssuerMismatch
        );
    }

    #[test]
    fn a_wrong_audience_is_rejected() {
        let mut c = claims("n1");
        c.aud = vec!["9999.apps.googleusercontent.com".to_owned()];
        c.azp = None;
        assert_eq!(
            validate_claims(&c, &config(), "n1", NOW).unwrap_err(),
            OidcError::AudienceMismatch
        );

        // A token minted for another client but listing ours among several
        // audiences is caught by `azp`.
        let mut c = claims("n1");
        c.aud = vec![
            "1234.apps.googleusercontent.com".to_owned(),
            "other.apps.googleusercontent.com".to_owned(),
        ];
        c.azp = Some("other.apps.googleusercontent.com".to_owned());
        assert_eq!(
            validate_claims(&c, &config(), "n1", NOW).unwrap_err(),
            OidcError::AuthorizedPartyMismatch
        );
    }

    #[test]
    fn expiry_and_issued_at_are_checked_with_skew() {
        let config = config();
        let mut c = claims("n1");
        c.exp = NOW_SECS - 3600;
        assert_eq!(
            validate_claims(&c, &config, "n1", NOW).unwrap_err(),
            OidcError::TokenExpired
        );

        // Just expired, but within the permitted skew.
        let mut c = claims("n1");
        c.exp = NOW_SECS - 30;
        assert!(validate_claims(&c, &config, "n1", NOW).is_ok());

        // Issued far in the future.
        let mut c = claims("n1");
        c.iat = NOW_SECS + 3600;
        assert_eq!(
            validate_claims(&c, &config, "n1", NOW).unwrap_err(),
            OidcError::TokenNotYetValid
        );

        // Slightly in the future, within skew.
        let mut c = claims("n1");
        c.iat = NOW_SECS + 30;
        assert!(validate_claims(&c, &config, "n1", NOW).is_ok());
    }

    #[test]
    fn a_wrong_or_absent_nonce_is_rejected() {
        // Replay protection: a token minted for a different sign-in attempt
        // carries a different nonce.
        let config = config();
        assert_eq!(
            validate_claims(&claims("n1"), &config, "n2", NOW).unwrap_err(),
            OidcError::NonceMismatch
        );

        let mut c = claims("n1");
        c.nonce = None;
        assert_eq!(
            validate_claims(&c, &config, "n1", NOW).unwrap_err(),
            OidcError::NonceMismatch
        );
    }

    #[test]
    fn an_unverified_email_is_rejected() {
        let mut c = claims("n1");
        c.email_verified = false;
        assert_eq!(
            validate_claims(&c, &config(), "n1", NOW).unwrap_err(),
            OidcError::EmailNotVerified
        );
    }

    #[test]
    fn a_missing_subject_is_rejected() {
        let mut c = claims("n1");
        c.sub = String::new();
        assert_eq!(
            validate_claims(&c, &config(), "n1", NOW).unwrap_err(),
            OidcError::MissingSubject
        );
    }

    #[test]
    fn hosted_domain_rules_are_enforced_when_configured() {
        let mut config = config();
        config.hosted_domains = vec!["example.com".to_owned()];

        assert!(validate_claims(&claims("n1"), &config, "n1", NOW).is_ok());

        let mut c = claims("n1");
        c.hd = Some("other.com".to_owned());
        assert_eq!(
            validate_claims(&c, &config, "n1", NOW).unwrap_err(),
            OidcError::HostedDomainNotPermitted
        );

        // A personal account has no hd at all.
        let mut c = claims("n1");
        c.hd = None;
        assert_eq!(
            validate_claims(&c, &config, "n1", NOW).unwrap_err(),
            OidcError::HostedDomainNotPermitted
        );
    }

    #[test]
    fn identity_is_keyed_on_issuer_and_subject_not_email() {
        // Specification 9.1: email is an attribute, not the identity key. Two
        // tokens with the same email but different subjects are different
        // identities; the same subject with a changed email is one identity.
        let a = claims("n");
        let mut b = claims("n");
        b.sub = "9999999999".to_owned();
        assert_ne!(a.identity_key(), b.identity_key());

        let mut c = claims("n");
        c.email = Some("alice.renamed@example.com".to_owned());
        assert_eq!(a.identity_key(), c.identity_key());

        assert_eq!(a.identity_key(), "https://accounts.google.com|1234567890");
    }

    // -- Return path --------------------------------------------------------

    #[test]
    fn return_paths_cannot_become_open_redirects() {
        for hostile in [
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example",
            "http://evil.example",
            "javascript:alert(1)",
            "\\\\evil.example",
            "",
            "   ",
            "relative/path",
            "/path\nInjected: header",
        ] {
            assert_eq!(
                sanitize_return_path(hostile),
                "/",
                "hostile return path {hostile:?} was not neutralised"
            );
        }

        for safe in ["/", "/targets", "/policies?draft=7", "/a/b/c"] {
            assert_eq!(sanitize_return_path(safe), safe);
        }

        assert_eq!(sanitize_return_path(&format!("/{}", "a".repeat(1000))), "/");
    }

    #[test]
    fn percent_encoding_covers_delimiters() {
        assert_eq!(percent_encode("abc-._~"), "abc-._~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("https://x/y"), "https%3A%2F%2Fx%2Fy");
        assert_eq!(percent_encode("a#b"), "a%23b");
        assert_eq!(percent_encode("a\nb"), "a%0Ab");
    }

    #[test]
    fn a_hostile_client_id_cannot_break_out_of_its_parameter() {
        let store = TransactionStore::new(KEY);
        let mut config = config();
        config.client_id = "id&redirect_uri=https://evil.example".to_owned();
        let request = store.begin(&config, "/", NOW).unwrap();
        // The injected parameter is encoded, so the URL still has exactly one
        // redirect_uri.
        assert_eq!(request.url.matches("redirect_uri=").count(), 1);
    }

    #[test]
    fn error_codes_are_distinct() {
        let all = [
            OidcError::NotConfigured,
            OidcError::MissingTransaction,
            OidcError::UnknownTransaction,
            OidcError::TransactionExpired,
            OidcError::StateMismatch,
            OidcError::ProviderError,
            OidcError::IssuerMismatch,
            OidcError::AudienceMismatch,
            OidcError::AuthorizedPartyMismatch,
            OidcError::TokenExpired,
            OidcError::TokenNotYetValid,
            OidcError::NonceMismatch,
            OidcError::MissingSubject,
            OidcError::EmailNotVerified,
            OidcError::HostedDomainNotPermitted,
            OidcError::SignatureInvalid,
            OidcError::VerifierUnavailable,
            OidcError::EntropyUnavailable,
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);
    }

    fn extract_param(url: &str, name: &str) -> String {
        let needle = format!("{name}=");
        let start = url
            .match_indices(&needle)
            .find(|(i, _)| {
                *i == 0 || url.as_bytes().get(i.saturating_sub(1)) == Some(&b'&')
            })
            .map(|(i, _)| i + needle.len())
            .unwrap_or_else(|| panic!("parameter {name} not found in {url}"));
        let rest = &url[start..];
        let end = rest.find('&').unwrap_or(rest.len());
        percent_decode(&rest[..end])
    }

    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).expect("valid UTF-8")
    }
}
