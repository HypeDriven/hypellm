//! Cross-origin policy for the management API.
//!
//! Specification 15.4: "Cross-origin deployment uses an **exact origin
//! allowlist**, credentials mode, preflight validation, and **no wildcard with
//! cookies**."
//!
//! The last clause is the one that matters most and the one browsers already
//! enforce: `Access-Control-Allow-Origin: *` with
//! `Access-Control-Allow-Credentials: true` is rejected by every browser, so a
//! router that emitted it would simply break. Emitting the *reflected* origin
//! without checking it is the dangerous version — that works in the browser and
//! hands any site the operator visits an authenticated cross-origin channel to
//! the management API.
//!
//! This module therefore reflects an origin only when it is on the configured
//! allowlist, and never emits a wildcard at all.

use core::fmt;

/// The configured cross-origin policy.
#[derive(Debug, Clone, Default)]
pub struct CorsPolicy {
    /// Exact origins permitted, for example `https://admin.example`.
    ///
    /// Empty means no cross-origin request is permitted, which is the correct
    /// setting when the admin application is served from the same origin.
    pub allowed_origins: Vec<String>,
    /// How long a browser may cache a preflight result, in seconds.
    pub max_age_secs: u32,
}

impl CorsPolicy {
    /// A policy permitting nothing cross-origin.
    #[must_use]
    pub fn none() -> Self {
        Self {
            allowed_origins: Vec::new(),
            max_age_secs: 600,
        }
    }

    /// A policy permitting a fixed list of origins.
    #[must_use]
    pub fn with_origins(origins: Vec<String>) -> Self {
        Self {
            allowed_origins: origins,
            max_age_secs: 600,
        }
    }

    /// Whether an origin is permitted.
    ///
    /// Exact comparison. No suffix matching, no scheme coercion, no case
    /// folding: `https://admin.example.evil.com` must not match
    /// `https://admin.example`, and `http://` must not match `https://`.
    #[must_use]
    pub fn permits(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|allowed| allowed == origin)
    }

    /// The headers to add to an actual (non-preflight) response.
    ///
    /// Returns nothing when the request carried no `Origin` — a same-origin
    /// request needs no CORS headers — or when the origin is not permitted, in
    /// which case the browser blocks the response for want of them.
    #[must_use]
    pub fn response_headers(&self, origin: Option<&str>) -> Vec<(String, String)> {
        let Some(origin) = origin else {
            return Vec::new();
        };
        if !self.permits(origin) {
            return Vec::new();
        }
        vec![
            (
                "Access-Control-Allow-Origin".to_owned(),
                origin.to_owned(),
            ),
            (
                "Access-Control-Allow-Credentials".to_owned(),
                "true".to_owned(),
            ),
            // Tells caches that the response varies by origin, so a response
            // for one origin is not served to another.
            ("Vary".to_owned(), "Origin".to_owned()),
        ]
    }

    /// The response to a preflight request.
    ///
    /// A refused origin gets a 403 with no CORS headers, which the browser
    /// surfaces as a blocked request.
    #[must_use]
    pub fn preflight(&self, origin: Option<&str>) -> PreflightOutcome {
        let Some(origin) = origin else {
            return PreflightOutcome::NotCors;
        };
        if !self.permits(origin) {
            return PreflightOutcome::Refused;
        }

        let mut headers = self.response_headers(Some(origin));
        headers.push((
            "Access-Control-Allow-Methods".to_owned(),
            "GET, POST, PATCH, DELETE, OPTIONS".to_owned(),
        ));
        headers.push((
            "Access-Control-Allow-Headers".to_owned(),
            format!(
                "Content-Type, If-Match, {}",
                hypellm_auth::session::CSRF_HEADER
            ),
        ));
        headers.push((
            "Access-Control-Expose-Headers".to_owned(),
            "ETag, X-Request-Id".to_owned(),
        ));
        headers.push((
            "Access-Control-Max-Age".to_owned(),
            self.max_age_secs.to_string(),
        ));
        PreflightOutcome::Allowed(headers)
    }
}

/// What to do with a preflight request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// The request carried no `Origin`; treat it as an ordinary request.
    NotCors,
    /// The origin is permitted; answer 204 with these headers.
    Allowed(Vec<(String, String)>),
    /// The origin is not permitted; answer 403 with no CORS headers.
    Refused,
}

impl fmt::Display for PreflightOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCors => f.write_str("not_cors"),
            Self::Allowed(_) => f.write_str("allowed"),
            Self::Refused => f.write_str("refused"),
        }
    }
}

/// Security headers for every management response.
///
/// Specification 15.2 recommends these for the static application; the API
/// sends the subset that makes sense for a JSON endpoint. `nosniff` matters
/// most: without it a browser may sniff a JSON body as HTML and execute it.
#[must_use]
pub fn security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        // An API response is never a document, so it should never be framed.
        ("X-Frame-Options", "DENY"),
        (
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CorsPolicy {
        CorsPolicy::with_origins(vec!["https://admin.example".to_owned()])
    }

    #[test]
    fn origin_matching_is_exact() {
        let policy = policy();
        assert!(policy.permits("https://admin.example"));

        // Every near-miss that a sloppy matcher would accept.
        for hostile in [
            "https://admin.example.evil.com",
            "https://evil.com/https://admin.example",
            "http://admin.example",
            "https://admin.example:8443",
            "https://ADMIN.example",
            "https://admin.example/",
            "null",
            "",
        ] {
            assert!(!policy.permits(hostile), "{hostile} must not be permitted");
        }
    }

    #[test]
    fn a_permitted_origin_is_reflected_with_credentials() {
        let headers = policy().response_headers(Some("https://admin.example"));
        let map: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(map.contains(&(
            "Access-Control-Allow-Origin",
            "https://admin.example"
        )));
        assert!(map.contains(&("Access-Control-Allow-Credentials", "true")));
        assert!(map.contains(&("Vary", "Origin")));
    }

    #[test]
    fn a_wildcard_is_never_emitted() {
        // Specification 15.4: "no wildcard with cookies". The router emits no
        // wildcard at all, for any origin.
        for origin in [Some("https://admin.example"), Some("https://other"), None] {
            for (name, value) in policy().response_headers(origin) {
                assert_ne!(value, "*", "{name} must never be a wildcard");
            }
        }
    }

    #[test]
    fn an_unpermitted_origin_gets_no_cors_headers() {
        // Reflecting an unchecked origin is the dangerous mistake: it works in
        // the browser and hands any site an authenticated channel.
        let headers = policy().response_headers(Some("https://evil.example"));
        assert!(headers.is_empty());
    }

    #[test]
    fn a_same_origin_request_needs_no_cors_headers() {
        assert!(policy().response_headers(None).is_empty());
        assert_eq!(policy().preflight(None), PreflightOutcome::NotCors);
    }

    #[test]
    fn an_empty_allowlist_permits_nothing() {
        let policy = CorsPolicy::none();
        assert!(!policy.permits("https://admin.example"));
        assert!(
            policy
                .response_headers(Some("https://admin.example"))
                .is_empty()
        );
        assert_eq!(
            policy.preflight(Some("https://admin.example")),
            PreflightOutcome::Refused
        );
    }

    #[test]
    fn a_preflight_advertises_the_csrf_header() {
        // Without it the browser blocks the actual request, and the CSRF
        // protection would look like a bug rather than a control.
        match policy().preflight(Some("https://admin.example")) {
            PreflightOutcome::Allowed(headers) => {
                let allow_headers = headers
                    .iter()
                    .find(|(name, _)| name == "Access-Control-Allow-Headers")
                    .map(|(_, value)| value.clone())
                    .expect("allow-headers");
                assert!(allow_headers.contains(hypellm_auth::session::CSRF_HEADER));
                assert!(allow_headers.contains("If-Match"));

                let expose = headers
                    .iter()
                    .find(|(name, _)| name == "Access-Control-Expose-Headers")
                    .map(|(_, value)| value.clone())
                    .expect("expose-headers");
                assert!(expose.contains("ETag"), "ETag must be readable for If-Match");
            }
            other => panic!("expected an allowed preflight, got {other}"),
        }
    }

    #[test]
    fn a_refused_preflight_carries_nothing() {
        assert_eq!(
            policy().preflight(Some("https://evil.example")),
            PreflightOutcome::Refused
        );
    }

    #[test]
    fn security_headers_include_nosniff_and_a_locked_down_policy() {
        let headers = security_headers();
        let map: Vec<(&str, &str)> = headers.clone();
        assert!(map.contains(&("X-Content-Type-Options", "nosniff")));
        assert!(map.contains(&("Referrer-Policy", "no-referrer")));
        assert!(map.contains(&("Cache-Control", "no-store")));
        assert!(map.contains(&("X-Frame-Options", "DENY")));

        let csp = map
            .iter()
            .find(|(name, _)| *name == "Content-Security-Policy")
            .map(|(_, value)| *value)
            .expect("a CSP");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }
}
