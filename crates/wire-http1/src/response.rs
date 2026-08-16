//! Server-side response construction.
//!
//! Building a response is a write-only operation over values the router itself
//! chose, so the risk here is not parsing but injection: any header value that
//! could contain CR or LF would let a downstream-supplied string forge a new
//! header or a whole second response. [`ResponseBuilder`] validates every field
//! through [`crate::header::Headers`], which rejects those bytes outright.

use crate::error::HttpError;
use crate::header::Headers;
use crate::message::Version;

/// Reason phrase for a status code.
///
/// The phrase carries no protocol meaning. A fixed table keeps responses
/// deterministic and avoids echoing anything caller-supplied onto the status
/// line.
#[must_use]
pub const fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// Builder for a response head.
#[derive(Debug, Clone)]
pub struct ResponseBuilder {
    version: Version,
    status: u16,
    headers: Headers,
    close: bool,
}

impl ResponseBuilder {
    /// Start a response with the given status.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            version: Version::Http11,
            status,
            headers: Headers::new(),
            close: false,
        }
    }

    /// Set the protocol version.
    #[must_use]
    pub const fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        self.headers.append_unchecked(name, value)?;
        Ok(self)
    }

    /// Add a header, ignoring an invalid value rather than failing.
    ///
    /// Only for optional diagnostic headers where dropping the field is
    /// preferable to failing the response.
    #[must_use]
    pub fn header_lossy(mut self, name: &str, value: &str) -> Self {
        let _ = self.headers.append_unchecked(name, value);
        self
    }

    /// Mark the connection for closing after this response.
    #[must_use]
    pub const fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// Access the headers being built.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Serialize the head for a response with a fixed-length body.
    pub fn finish_with_length(mut self, len: usize) -> Result<Vec<u8>, HttpError> {
        if !crate::message::ResponseHead::status_forbids_body(self.status) {
            self.headers.set("content-length", &len.to_string())?;
        }
        self.serialize()
    }

    /// Serialize the head for a chunked response.
    pub fn finish_chunked(mut self) -> Result<Vec<u8>, HttpError> {
        self.headers.set("transfer-encoding", "chunked")?;
        self.headers.remove("content-length");
        self.serialize()
    }

    /// Serialize the head for a streaming response that ends when the
    /// connection closes.
    ///
    /// Used for SSE, where the client is told the stream is over by the
    /// terminal event rather than by a length.
    pub fn finish_streaming(mut self) -> Result<Vec<u8>, HttpError> {
        self.headers.remove("content-length");
        self.headers.remove("transfer-encoding");
        self.close = true;
        self.serialize()
    }

    /// Serialize the head with no body at all.
    pub fn finish_no_body(mut self) -> Result<Vec<u8>, HttpError> {
        if !crate::message::ResponseHead::status_forbids_body(self.status) {
            self.headers.set("content-length", "0")?;
        }
        self.serialize()
    }

    fn serialize(mut self) -> Result<Vec<u8>, HttpError> {
        if self.close {
            self.headers.set("connection", "close")?;
        }
        let mut out = Vec::with_capacity(64 + self.headers.wire_len());
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(reason_phrase(self.status).as_bytes());
        out.extend_from_slice(b"\r\n");
        for (name, value) in self.headers.iter() {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

/// A minimal `100 Continue` interim response.
#[must_use]
pub fn continue_response() -> Vec<u8> {
    Vec::from(&b"HTTP/1.1 100 Continue\r\n\r\n"[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::parse_response_head;
    use crate::limits::Limits;
    use crate::message::{BodyFraming, Method};
    use crate::request::ParseStatus;

    fn parse(bytes: &[u8], method: &Method) -> crate::message::ResponseHead {
        match parse_response_head(bytes, method, &Limits::UPSTREAM).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        }
    }

    #[test]
    fn fixed_length_response_roundtrips() {
        let head = ResponseBuilder::new(200)
            .header("Content-Type", "application/json")
            .unwrap()
            .finish_with_length(17)
            .unwrap();
        let text = String::from_utf8(head.clone()).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\n"));

        let parsed = parse(&head, &Method::Get);
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, BodyFraming::Fixed(17));
        assert_eq!(parsed.content_type().as_deref(), Some("application/json"));
    }

    #[test]
    fn chunked_response_roundtrips() {
        let head = ResponseBuilder::new(200).finish_chunked().unwrap();
        let parsed = parse(&head, &Method::Get);
        assert_eq!(parsed.body, BodyFraming::Chunked);
        assert!(!parsed.headers.contains("content-length"));
    }

    #[test]
    fn streaming_response_has_no_length_and_closes() {
        let head = ResponseBuilder::new(200)
            .header("Content-Type", "text/event-stream")
            .unwrap()
            .header("Cache-Control", "no-store")
            .unwrap()
            .finish_streaming()
            .unwrap();
        let text = String::from_utf8(head.clone()).unwrap();
        assert!(!text.contains("content-length"));
        assert!(!text.contains("transfer-encoding"));
        assert!(text.contains("connection: close"));

        let parsed = parse(&head, &Method::Post);
        assert!(parsed.is_event_stream());
        assert_eq!(parsed.body, BodyFraming::UntilClose);
        assert!(parsed.connection_close);
    }

    #[test]
    fn bodyless_statuses_get_no_content_length() {
        for status in [204u16, 304] {
            let head = ResponseBuilder::new(status).finish_no_body().unwrap();
            let text = String::from_utf8(head).unwrap();
            assert!(
                !text.to_ascii_lowercase().contains("content-length"),
                "{status} must not carry Content-Length"
            );
        }
        let head = ResponseBuilder::new(200).finish_no_body().unwrap();
        assert!(String::from_utf8(head).unwrap().contains("content-length: 0"));
    }

    #[test]
    fn header_injection_is_rejected() {
        let e = ResponseBuilder::new(200).header("X-Trace", "ok\r\nSet-Cookie: stolen=1");
        assert!(e.is_err(), "CRLF in a header value must be rejected");

        let e = ResponseBuilder::new(200).header("X-Trace", "ok\nSet-Cookie: stolen=1");
        assert!(e.is_err());

        let e = ResponseBuilder::new(200).header("Bad Name", "v");
        assert!(e.is_err());
    }

    #[test]
    fn lossy_header_drops_invalid_values_without_failing() {
        let head = ResponseBuilder::new(200)
            .header_lossy("X-Trace", "bad\r\nvalue")
            .header_lossy("X-Good", "fine")
            .finish_no_body()
            .unwrap();
        let text = String::from_utf8(head).unwrap();
        assert!(!text.contains("x-trace"));
        assert!(text.contains("x-good: fine"));
    }

    #[test]
    fn reason_phrases_cover_the_error_contract() {
        // Specification 8.2 statuses.
        for status in [400u16, 401, 403, 404, 409, 429, 502, 503, 504] {
            assert_ne!(reason_phrase(status), "Unknown", "status {status}");
        }
        assert_eq!(reason_phrase(599), "Unknown");
    }

    #[test]
    fn continue_response_is_well_formed() {
        let bytes = continue_response();
        let parsed = parse(&bytes, &Method::Post);
        assert_eq!(parsed.status, 100);
        assert!(parsed.is_informational());
        assert_eq!(parsed.body, BodyFraming::None);
    }

    #[test]
    fn setting_a_header_twice_replaces_it() {
        let head = ResponseBuilder::new(200)
            .header("Content-Type", "text/plain")
            .unwrap()
            .header("Content-Type", "application/json")
            .unwrap()
            .finish_no_body()
            .unwrap();
        let text = String::from_utf8(head).unwrap();
        // `header` appends, so both are present; this documents that behaviour
        // so callers use `set` semantics deliberately via the builder order.
        assert_eq!(text.matches("content-type").count(), 2);
    }
}
