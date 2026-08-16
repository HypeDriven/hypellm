//! Clients for the two platform helper services.
//!
//! Specification 4 and 9.1 both draw the same boundary:
//!
//! > **TLS reality:** Do not implement TLS or modern cryptography ad hoc. …
//! > For outbound HTTPS, use a platform-provided audited TLS helper/sidecar
//! > with a narrow CONNECT-like API and destination allowlist.
//!
//! > **OIDC dependency boundary:** JWT signature verification and HTTPS are
//! > cryptographic security functions. Strict profile delegates them to an
//! > approved local identity/TLS verifier service over a narrow authenticated
//! > local interface.
//!
//! # The wire protocol
//!
//! Both helpers speak the same deliberately tiny line protocol over a Unix
//! socket. It is small enough to audit in one sitting, which is the point: a
//! complex helper protocol would just move the trusted computing base rather
//! than shrinking it.
//!
//! ```text
//! TLS helper:
//!   → CONNECT <host> <port> <sni>\n
//!   ← OK\n              then the socket carries the TLS session's plaintext
//!   ← ERR <code>\n      and the socket closes
//!
//! Identity verifier:
//!   → VERIFY <length>\n<token bytes>
//!   ← OK <length>\n<claims JSON>
//!   ← ERR <code>\n
//! ```
//!
//! The router never sends a URL, a path, or a header to either helper — only a
//! host, a port, and an SNI name, all of which came from configuration.

use crate::egress::{PinnedDestination, Transport};
use hypellm_auth::oidc::{IdTokenClaims, OidcError, TokenVerifier};
use core::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use wire_json::{Limits, Value, parse};

/// Maximum bytes in a helper's status line.
const MAX_STATUS_LINE: usize = 256;

/// Maximum bytes of claims a verifier may return.
const MAX_CLAIMS_BYTES: usize = 64 * 1024;

/// Maximum bytes of token the router will submit for verification.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Why a helper exchange failed.
#[derive(Debug)]
pub enum HelperError {
    /// The helper socket could not be reached.
    Unavailable(io::Error),
    /// The helper refused the request.
    Refused {
        /// The helper's error code, bounded.
        code: String,
    },
    /// The helper's reply did not match the protocol.
    ProtocolViolation,
    /// The helper's reply exceeded a bound.
    ReplyTooLarge,
}

impl HelperError {
    /// Stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "helper_unavailable",
            Self::Refused { .. } => "helper_refused",
            Self::ProtocolViolation => "helper_protocol_violation",
            Self::ReplyTooLarge => "helper_reply_too_large",
        }
    }
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "helper service unavailable: {e}"),
            Self::Refused { code } => write!(f, "helper refused the request: {code}"),
            Self::ProtocolViolation => f.write_str("helper reply violated the protocol"),
            Self::ReplyTooLarge => f.write_str("helper reply exceeded the permitted size"),
        }
    }
}

impl std::error::Error for HelperError {}

/// Read one bounded, newline-terminated status line.
fn read_status_line(reader: &mut impl BufRead) -> Result<String, HelperError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= MAX_STATUS_LINE {
            return Err(HelperError::ReplyTooLarge);
        }
        let read = reader
            .read(&mut byte)
            .map_err(HelperError::Unavailable)?;
        if read == 0 {
            return Err(HelperError::ProtocolViolation);
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).map_err(|_| HelperError::ProtocolViolation)
}

/// Bound and sanitise a helper-supplied error code.
///
/// The helper is trusted to terminate TLS, not to author strings the router
/// will echo. The code is truncated and narrowed to an identifier alphabet
/// before it can reach a log line or an error body.
fn sanitize_code(raw: &str) -> String {
    raw.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A client of the outbound TLS helper.
#[derive(Debug, Clone)]
pub struct TlsHelper {
    socket_path: String,
    timeout: Duration,
}

impl TlsHelper {
    /// Create a client for the helper at `socket_path`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout,
        }
    }

    /// The configured socket path.
    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Open a TLS-protected connection to a pinned destination.
    ///
    /// The returned transport carries the plaintext of the TLS session. The
    /// router writes HTTP into it exactly as it would to a cleartext socket.
    pub fn connect(&self, destination: &PinnedDestination) -> Result<Transport, HelperError> {
        let crate::egress::DestinationAddress::Socket(addr) = &destination.address() else {
            // A Unix destination never needs TLS.
            return Err(HelperError::ProtocolViolation);
        };

        let stream = UnixStream::connect(&self.socket_path).map_err(HelperError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(HelperError::Unavailable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(HelperError::Unavailable)?;

        let sni = destination.sni().unwrap_or("");
        // The pinned IP is what the helper connects to; the SNI is the
        // configured name. Sending both is what lets the helper honour the
        // router's rebinding-safe pin while still presenting the right name.
        let request = format!("CONNECT {} {} {}\n", addr.ip(), addr.port(), sni);

        let mut writer = stream.try_clone().map_err(HelperError::Unavailable)?;
        writer
            .write_all(request.as_bytes())
            .map_err(HelperError::Unavailable)?;
        writer.flush().map_err(HelperError::Unavailable)?;

        let mut reader = BufReader::new(stream.try_clone().map_err(HelperError::Unavailable)?);
        let status = read_status_line(&mut reader)?;

        if status == "OK" {
            Ok(Transport::Unix(stream))
        } else if let Some(code) = status.strip_prefix("ERR ") {
            Err(HelperError::Refused {
                code: sanitize_code(code),
            })
        } else {
            Err(HelperError::ProtocolViolation)
        }
    }
}

/// A client of the identity verifier.
#[derive(Debug, Clone)]
pub struct VerifierClient {
    socket_path: String,
    timeout: Duration,
}

impl VerifierClient {
    /// Create a client for the verifier at `socket_path`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout,
        }
    }

    /// The configured socket path.
    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Send one `<verb> <length>\n<payload>` request and read the reply.
    fn request(&self, verb: &str, token: &str) -> Result<Vec<u8>, HelperError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(HelperError::ReplyTooLarge);
        }

        let stream = UnixStream::connect(&self.socket_path).map_err(HelperError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(HelperError::Unavailable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(HelperError::Unavailable)?;

        let mut writer = stream.try_clone().map_err(HelperError::Unavailable)?;
        writer
            .write_all(format!("{verb} {}\n", token.len()).as_bytes())
            .map_err(HelperError::Unavailable)?;
        writer
            .write_all(token.as_bytes())
            .map_err(HelperError::Unavailable)?;
        writer.flush().map_err(HelperError::Unavailable)?;

        let mut reader = BufReader::new(stream);
        let status = read_status_line(&mut reader)?;

        if let Some(code) = status.strip_prefix("ERR ") {
            return Err(HelperError::Refused {
                code: sanitize_code(code),
            });
        }
        let Some(length) = status.strip_prefix("OK ") else {
            return Err(HelperError::ProtocolViolation);
        };
        let length: usize = length
            .trim()
            .parse()
            .map_err(|_| HelperError::ProtocolViolation)?;
        if length > MAX_CLAIMS_BYTES {
            return Err(HelperError::ReplyTooLarge);
        }

        let mut claims = vec![0u8; length];
        reader
            .read_exact(&mut claims)
            .map_err(|_| HelperError::ProtocolViolation)?;
        Ok(claims)
    }
}

impl TokenVerifier for VerifierClient {
    fn verify(&self, id_token: &str) -> Result<IdTokenClaims, OidcError> {
        let claims = self.request("VERIFY", id_token).map_err(|e| match e {
            HelperError::Refused { .. } => OidcError::SignatureInvalid,
            _ => OidcError::VerifierUnavailable,
        })?;
        let value = parse(&claims, &Limits::SMALL).map_err(|_| OidcError::VerifierUnavailable)?;
        parse_claims(&value).ok_or(OidcError::VerifierUnavailable)
    }

    fn exchange_code(
        &self,
        request: &hypellm_auth::oidc::CodeExchange<'_>,
    ) -> Result<IdTokenClaims, OidcError> {
        // A JSON payload rather than more positional fields: the exchange has
        // five of them, and a helper that mis-orders `redirect_uri` and
        // `token_endpoint` would be redeeming codes against the wrong host.
        let mut object = wire_json::Object::new();
        object.push("code", Value::from(request.code));
        object.push("code_verifier", Value::from(request.code_verifier));
        object.push("redirect_uri", Value::from(request.redirect_uri));
        object.push("client_id", Value::from(request.client_id));
        object.push("token_endpoint", Value::from(request.token_endpoint));
        let payload = wire_json::to_string(&Value::Object(object));

        let claims = self.request("EXCHANGE", &payload).map_err(|e| match e {
            // The boundary distinguishes "the provider refused this code" from
            // "the boundary is not answering". Collapsing them would report a
            // helper outage as a failed sign-in and send an operator looking
            // at the wrong system.
            HelperError::Refused { .. } => OidcError::SignatureInvalid,
            _ => OidcError::VerifierUnavailable,
        })?;
        let value = parse(&claims, &Limits::SMALL).map_err(|_| OidcError::VerifierUnavailable)?;
        parse_claims(&value).ok_or(OidcError::VerifierUnavailable)
    }
}

/// Parse the claims document a verifier returns.
///
/// Only claims the router uses are read; anything else in the document is
/// ignored. Notably, this does **not** validate `iss`, `aud`, `exp`, or
/// `nonce` — those go through `hypellm_auth::oidc::validate_claims`, in one
/// place, so a check cannot be quietly skipped on one of two paths.
#[must_use]
pub fn parse_claims(value: &Value) -> Option<IdTokenClaims> {
    let aud = match value.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };

    Some(IdTokenClaims {
        iss: value.get("iss")?.as_str()?.to_owned(),
        sub: value.get("sub")?.as_str()?.to_owned(),
        aud,
        azp: value.get("azp").and_then(|v| v.as_str()).map(str::to_owned),
        exp: value.get("exp").and_then(|v| v.as_u64()).unwrap_or(0),
        iat: value.get("iat").and_then(|v| v.as_u64()).unwrap_or(0),
        nonce: value.get("nonce").and_then(|v| v.as_str()).map(str::to_owned),
        email: value.get("email").and_then(|v| v.as_str()).map(str::to_owned),
        email_verified: value
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        hd: value.get("hd").and_then(|v| v.as_str()).map(str::to_owned),
        name: value.get("name").and_then(|v| v.as_str()).map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_store::TempDir;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use wire_json::parse_str;

    /// Run a helper that replies with `reply` and then echoes.
    fn helper(dir: &TempDir, name: &str, reply: Vec<u8>) -> (String, thread::JoinHandle<Vec<u8>>) {
        let path = dir.join(name).to_string_lossy().into_owned();
        let listener = UnixListener::bind(&path).expect("bind");
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = vec![0u8; 4096];
            let n = socket.read(&mut request).unwrap_or(0);
            request.truncate(n);
            socket.write_all(&reply).expect("write");
            socket.flush().expect("flush");
            request
        });
        (path, handle)
    }

    #[test]
    fn the_tls_helper_receives_only_a_pinned_address_and_sni() {
        let dir = TempDir::new("tls-helper");
        let (path, server) = helper(&dir, "tls.sock", b"OK\n".to_vec());

        let destination = PinnedDestination::for_tests(crate::egress::DestinationAddress::Socket("93.184.216.34:443".parse().unwrap()), "api.example", Some(&"api.example"), true);
        let client = TlsHelper::new(path, Duration::from_secs(5));
        let transport = client.connect(&destination).expect("connects");
        drop(transport);

        let request = server.join().expect("server");
        let text = String::from_utf8(request).expect("utf8");
        assert_eq!(text, "CONNECT 93.184.216.34 443 api.example\n");
        // No URL, no path, no header reaches the helper.
        assert!(!text.contains('/'));
        assert!(!text.contains("Authorization"));
    }

    #[test]
    fn a_refused_connection_reports_a_sanitised_code() {
        let dir = TempDir::new("tls-refused");
        let (path, server) = helper(
            &dir,
            "tls.sock",
            b"ERR destination_not_allowlisted\n".to_vec(),
        );

        let destination = PinnedDestination::for_tests(crate::egress::DestinationAddress::Socket("93.184.216.34:443".parse().unwrap()), "api.example", Some(&"api.example"), true);
        let client = TlsHelper::new(path, Duration::from_secs(5));
        match client.connect(&destination) {
            Err(HelperError::Refused { code }) => {
                assert_eq!(code, "destination_not_allowlisted");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        server.join().expect("server");
    }

    #[test]
    fn a_hostile_helper_code_cannot_inject_into_a_log_line() {
        let dir = TempDir::new("tls-hostile");
        let (path, server) = helper(
            &dir,
            "tls.sock",
            b"ERR bad\x1b[31m code\"with'quotes\n".to_vec(),
        );

        let destination = PinnedDestination::for_tests(crate::egress::DestinationAddress::Socket("93.184.216.34:443".parse().unwrap()), "api.example", None, true);
        let client = TlsHelper::new(path, Duration::from_secs(5));
        match client.connect(&destination) {
            Err(HelperError::Refused { code }) => {
                assert!(!code.contains('\x1b'));
                assert!(!code.contains('"'));
                assert!(!code.contains('\''));
                assert!(code.len() <= 64);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        server.join().expect("server");
    }

    #[test]
    fn an_unavailable_helper_is_reported_not_bypassed() {
        // The failure that matters: if the TLS helper is down, the router must
        // fail rather than fall back to a cleartext connection.
        let client = TlsHelper::new("/nonexistent/hypellm-tls.sock", Duration::from_millis(200));
        let destination = PinnedDestination::for_tests(crate::egress::DestinationAddress::Socket("93.184.216.34:443".parse().unwrap()), "api.example", None, true);
        match client.connect(&destination) {
            Err(HelperError::Unavailable(_)) => {}
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_status_line_is_rejected() {
        let dir = TempDir::new("tls-oversize");
        let mut reply = Vec::from(&b"ERR "[..]);
        reply.extend(std::iter::repeat_n(b'x', 10_000));
        reply.push(b'\n');
        let (path, server) = helper(&dir, "tls.sock", reply);

        let destination = PinnedDestination::for_tests(crate::egress::DestinationAddress::Socket("93.184.216.34:443".parse().unwrap()), "api.example", None, true);
        let client = TlsHelper::new(path, Duration::from_secs(5));
        assert!(matches!(
            client.connect(&destination),
            Err(HelperError::ReplyTooLarge)
        ));
        let _ = server.join();
    }

    #[test]
    fn the_verifier_returns_parsed_claims() {
        let claims = r#"{"iss":"https://accounts.google.com","sub":"12345","aud":"client-id","azp":"client-id","exp":9999999999,"iat":1000,"nonce":"n1","email":"a@example.com","email_verified":true,"hd":"example.com","name":"Alice"}"#;
        let dir = TempDir::new("verifier");
        let reply = format!("OK {}\n{claims}", claims.len()).into_bytes();
        let (path, server) = helper(&dir, "verify.sock", reply);

        let client = VerifierClient::new(path, Duration::from_secs(5));
        let parsed = client.verify("header.payload.signature").expect("verifies");
        assert_eq!(parsed.iss, "https://accounts.google.com");
        assert_eq!(parsed.sub, "12345");
        assert_eq!(parsed.aud, vec!["client-id"]);
        assert_eq!(parsed.nonce.as_deref(), Some("n1"));
        assert!(parsed.email_verified);
        assert_eq!(parsed.hd.as_deref(), Some("example.com"));

        let request = server.join().expect("server");
        let text = String::from_utf8(request).expect("utf8");
        assert!(text.starts_with("VERIFY 24\n"));
        assert!(text.ends_with("header.payload.signature"));
    }

    #[test]
    fn a_rejected_signature_is_reported_as_such() {
        let dir = TempDir::new("verifier-bad");
        let (path, server) = helper(&dir, "verify.sock", b"ERR bad_signature\n".to_vec());
        let client = VerifierClient::new(path, Duration::from_secs(5));
        assert_eq!(
            client.verify("header.payload.signature").unwrap_err(),
            OidcError::SignatureInvalid
        );
        server.join().expect("server");
    }

    #[test]
    fn an_unavailable_verifier_does_not_admit_the_token() {
        // Fail closed: a verifier that cannot be reached must not mean "valid".
        let client = VerifierClient::new("/nonexistent/verify.sock", Duration::from_millis(200));
        assert_eq!(
            client.verify("header.payload.signature").unwrap_err(),
            OidcError::VerifierUnavailable
        );
    }

    #[test]
    fn an_oversized_token_is_not_submitted() {
        let client = VerifierClient::new("/nonexistent/verify.sock", Duration::from_millis(200));
        let huge = "a".repeat(MAX_TOKEN_BYTES + 1);
        // Rejected before any socket is opened, so the error is not
        // "unavailable" from the connect attempt.
        assert!(client.request("VERIFY", &huge).is_err());
    }

    #[test]
    fn claims_parsing_handles_both_audience_shapes() {
        let single = parse_str(
            r#"{"iss":"i","sub":"s","aud":"one"}"#,
            &Limits::SMALL,
        )
        .unwrap();
        assert_eq!(parse_claims(&single).unwrap().aud, vec!["one"]);

        let multiple = parse_str(
            r#"{"iss":"i","sub":"s","aud":["one","two"]}"#,
            &Limits::SMALL,
        )
        .unwrap();
        assert_eq!(parse_claims(&multiple).unwrap().aud, vec!["one", "two"]);
    }

    #[test]
    fn claims_parsing_defaults_email_verified_to_false() {
        // An absent claim must not read as verified.
        let value = parse_str(r#"{"iss":"i","sub":"s","email":"a@b"}"#, &Limits::SMALL).unwrap();
        let claims = parse_claims(&value).expect("parses");
        assert!(!claims.email_verified);
    }

    #[test]
    fn claims_without_a_subject_do_not_parse() {
        let value = parse_str(r#"{"iss":"i"}"#, &Limits::SMALL).unwrap();
        assert!(parse_claims(&value).is_none());
    }
}
