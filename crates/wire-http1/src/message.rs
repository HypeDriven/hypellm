//! Message types shared by the server and client state machines.

use crate::error::{HttpError, HttpErrorKind};
use crate::header::Headers;

/// The HTTP version on the wire.
///
/// Only 1.0 and 1.1 exist here. Specification 25 records the decision:
/// "HTTP/1.1 inside normalized boundary for v1; edge provides HTTP/2/3."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// `HTTP/1.0`
    Http10,
    /// `HTTP/1.1`
    Http11,
}

impl Version {
    /// Parse a version token from a request or status line.
    pub fn parse(bytes: &[u8]) -> Result<Self, HttpError> {
        match bytes {
            b"HTTP/1.1" => Ok(Self::Http11),
            b"HTTP/1.0" => Ok(Self::Http10),
            _ => Err(HttpErrorKind::UnsupportedVersion.into()),
        }
    }

    /// Wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }

    /// Whether connections default to persistent.
    #[must_use]
    pub const fn default_keep_alive(self) -> bool {
        matches!(self, Self::Http11)
    }
}

/// A request method.
///
/// The common methods are named so that routing matches on an enum rather than
/// a string. Anything else is carried as `Other` and answered with 405 by the
/// listener; the parser's job is to bound and validate it, not to decide policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
    /// A syntactically valid method the router does not implement.
    Other(String),
}

impl Method {
    /// Classify a validated method token.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        match token {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Whether a response to this method carries a body.
    ///
    /// A `HEAD` response has the headers of the equivalent `GET` — including
    /// `Content-Length` — but no body. Reading one as though it had a body is a
    /// response-splitting bug on the client side.
    #[must_use]
    pub const fn response_has_body(&self) -> bool {
        !matches!(self, Self::Head)
    }

    /// Whether the method is idempotent per RFC 9110.
    ///
    /// Specification 6.5 permits retrying after upstream acceptance only for
    /// idempotent requests or those carrying an idempotency key. Inference
    /// requests are `POST`, so this returns false for them and the failover
    /// rules take the conservative branch.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Put | Self::Delete | Self::Options
        )
    }
}

impl core::fmt::Display for Method {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body at all.
    None,
    /// Exactly this many bytes.
    Fixed(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Delimited by connection close.
    ///
    /// Only ever valid for a *response*. A request framed this way is
    /// unparseable without guessing, so the server parser never produces it.
    UntilClose,
}

impl BodyFraming {
    /// True when a body of some length is expected.
    #[must_use]
    pub const fn has_body(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A parsed request head.
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// The method.
    pub method: Method,
    /// The raw request target, exactly as received, in origin form.
    ///
    /// Kept undecoded: routing compares the path literally, and percent-decoding
    /// before comparison is how `/v1/..%2f..%2fadmin` becomes a path-traversal.
    pub target: String,
    /// The path portion of the target, before any `?`.
    pub path: String,
    /// The query portion, after the first `?`, without the `?`.
    pub query: Option<String>,
    /// The version.
    pub version: Version,
    /// The header fields.
    pub headers: Headers,
    /// How the body is delimited.
    pub body: BodyFraming,
    /// Whether the client sent `Expect: 100-continue`.
    pub expect_continue: bool,
    /// Whether the connection must close after this exchange.
    pub connection_close: bool,
    /// Total bytes consumed by the head, including the terminating CRLF CRLF.
    pub head_len: usize,
}

impl RequestHead {
    /// The `Host` value, which the parser has already validated as present on
    /// HTTP/1.1.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host")
    }

    /// The declared content type, without parameters and lowercased.
    #[must_use]
    pub fn content_type(&self) -> Option<String> {
        self.headers.get("content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
    }

    /// True when the client asked for an event stream.
    #[must_use]
    pub fn accepts_event_stream(&self) -> bool {
        self.headers
            .get_all("accept")
            .any(|v| v.split(',').any(|p| p.trim().starts_with("text/event-stream")))
    }
}

/// A parsed response head.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    /// The version.
    pub version: Version,
    /// The three-digit status code.
    pub status: u16,
    /// The reason phrase, which carries no meaning and may be empty.
    pub reason: String,
    /// The header fields.
    pub headers: Headers,
    /// How the body is delimited.
    pub body: BodyFraming,
    /// Whether the upstream signalled connection close.
    pub connection_close: bool,
    /// Total bytes consumed by the head.
    pub head_len: usize,
}

impl ResponseHead {
    /// True for 1xx.
    #[must_use]
    pub const fn is_informational(&self) -> bool {
        self.status >= 100 && self.status < 200
    }

    /// True for 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The declared content type, without parameters and lowercased.
    #[must_use]
    pub fn content_type(&self) -> Option<String> {
        self.headers.get("content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
    }

    /// True when the upstream is sending an SSE stream.
    #[must_use]
    pub fn is_event_stream(&self) -> bool {
        self.content_type().as_deref() == Some("text/event-stream")
    }

    /// Statuses that never carry a body regardless of headers (RFC 9112 6.3).
    #[must_use]
    pub const fn status_forbids_body(status: u16) -> bool {
        matches!(status, 100..=199 | 204 | 304)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(Version::parse(b"HTTP/1.1").unwrap(), Version::Http11);
        assert_eq!(Version::parse(b"HTTP/1.0").unwrap(), Version::Http10);
        for bad in [
            &b"HTTP/0.9"[..],
            b"HTTP/2",
            b"HTTP/2.0",
            b"HTTP/3",
            b"HTTP/1.2",
            b"HTTP/1.10",
            b"http/1.1",
            b"HTTP/1.1 ",
            b"",
            b"ICE/1.0",
        ] {
            assert_eq!(
                Version::parse(bad).unwrap_err().kind,
                HttpErrorKind::UnsupportedVersion,
                "{:?} must be rejected",
                core::str::from_utf8(bad)
            );
        }
    }

    #[test]
    fn version_roundtrips() {
        for v in [Version::Http10, Version::Http11] {
            assert_eq!(Version::parse(v.as_str().as_bytes()).unwrap(), v);
        }
        assert!(Version::Http11.default_keep_alive());
        assert!(!Version::Http10.default_keep_alive());
    }

    #[test]
    fn method_classification() {
        assert_eq!(Method::from_token("GET"), Method::Get);
        assert_eq!(Method::from_token("POST"), Method::Post);
        assert_eq!(
            Method::from_token("PROPFIND"),
            Method::Other("PROPFIND".to_owned())
        );
        // Case matters: methods are case-sensitive, so `get` is not `GET`.
        assert_eq!(Method::from_token("get"), Method::Other("get".to_owned()));
        assert_eq!(Method::from_token("GET").as_str(), "GET");
    }

    #[test]
    fn head_response_has_no_body() {
        assert!(!Method::Head.response_has_body());
        assert!(Method::Get.response_has_body());
        assert!(Method::Post.response_has_body());
    }

    #[test]
    fn idempotence_matches_rfc_9110() {
        assert!(Method::Get.is_idempotent());
        assert!(Method::Put.is_idempotent());
        assert!(Method::Delete.is_idempotent());
        assert!(!Method::Post.is_idempotent(), "inference requests are POST");
        assert!(!Method::Patch.is_idempotent());
        assert!(!Method::Other("LOCK".to_owned()).is_idempotent());
    }

    #[test]
    fn bodyless_statuses() {
        for s in [100, 101, 199, 204, 304] {
            assert!(ResponseHead::status_forbids_body(s), "{s}");
        }
        for s in [200, 201, 400, 404, 500, 503] {
            assert!(!ResponseHead::status_forbids_body(s), "{s}");
        }
    }

    #[test]
    fn framing_predicate() {
        assert!(!BodyFraming::None.has_body());
        assert!(BodyFraming::Fixed(0).has_body());
        assert!(BodyFraming::Chunked.has_body());
        assert!(BodyFraming::UntilClose.has_body());
    }
}
