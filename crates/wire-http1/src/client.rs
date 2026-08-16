//! Client-side request encoding and response head parsing.
//!
//! Used by provider adapters. A provider is outside the trust boundary:
//! specification 8.2 reserves `upstream_invalid_response` for one that violates
//! its contract, and specification 7 requires adapters to do "strict parsing".
//! So the response parser is as strict as the request parser — an upstream can
//! smuggle into a shared connection pool just as a client can.

use crate::error::{HttpError, HttpErrorKind};
use crate::header::{Headers, is_field_value, is_token, split_field, trim_ows};
use crate::limits::Limits;
use crate::message::{BodyFraming, Method, ResponseHead, Version};
use crate::request::ParseStatus;

/// Builder for an outbound request.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    method: Method,
    target: String,
    host: String,
    headers: Headers,
}

impl RequestBuilder {
    /// Start a request. `target` must be in origin form and `host` is the
    /// authority the adapter was configured with — never a client-supplied
    /// value (specification 10).
    pub fn new(method: Method, target: &str, host: &str) -> Result<Self, HttpError> {
        if !target.starts_with('/') || target.starts_with("//") {
            return Err(HttpErrorKind::NonOriginFormTarget.into());
        }
        if !target.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(HttpErrorKind::InvalidTarget.into());
        }
        if host.is_empty()
            || !host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
            })
        {
            return Err(HttpErrorKind::InvalidHost.into());
        }
        Ok(Self {
            method,
            target: target.to_owned(),
            host: host.to_owned(),
            headers: Headers::new(),
        })
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        self.headers.append_unchecked(name, value)?;
        Ok(self)
    }

    /// Serialize head and body for a request with a fixed-length body.
    pub fn finish_with_body(mut self, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        self.headers.set("host", &self.host.clone())?;
        if !body.is_empty() || matches!(self.method, Method::Post | Method::Put | Method::Patch) {
            self.headers.set("content-length", &body.len().to_string())?;
        }
        let mut out = self.serialize_head()?;
        out.extend_from_slice(body);
        Ok(out)
    }

    /// Serialize the head for a request whose body will be sent chunked.
    pub fn finish_chunked(mut self) -> Result<Vec<u8>, HttpError> {
        self.headers.set("host", &self.host.clone())?;
        self.headers.set("transfer-encoding", "chunked")?;
        self.headers.remove("content-length");
        self.serialize_head()
    }

    fn serialize_head(self) -> Result<Vec<u8>, HttpError> {
        let mut out = Vec::with_capacity(64 + self.headers.wire_len());
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.push(b' ');
        out.extend_from_slice(Version::Http11.as_str().as_bytes());
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

/// Attempt to parse a response head from `buf`.
///
/// `request_method` is required because framing depends on it: a `HEAD`
/// response carries the `Content-Length` of the equivalent `GET` but no body.
pub fn parse_response_head(
    buf: &[u8],
    request_method: &Method,
    limits: &Limits,
) -> Result<ParseStatus<ResponseHead>, HttpError> {
    let limits = limits.clamped();

    let head_end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p + 4,
        None => {
            if buf.len() > limits.max_head_bytes {
                return Err(HttpErrorKind::HeadTooLarge.into());
            }
            return Ok(ParseStatus::Incomplete);
        }
    };
    if head_end > limits.max_head_bytes {
        return Err(HttpErrorKind::HeadTooLarge.into());
    }

    // `head_end` is the offset just past a CRLF CRLF found in `buf`, so it is
    // at least 4 and at most `buf.len()`; the fallback is unreachable.
    let head = match head_end.checked_sub(4).and_then(|end| buf.get(..end)) {
        Some(head) => head,
        None => return Err(HttpErrorKind::MalformedStatusLine.into()),
    };
    if head.contains(&0u8) {
        return Err(HttpErrorKind::NulInHead.into());
    }

    let mut lines = split_crlf_strict(head)?;
    if lines.is_empty() {
        return Err(HttpErrorKind::MalformedStatusLine.into());
    }

    let status_line = lines.remove(0);
    let (version, status, reason) = parse_status_line(status_line)?;

    if lines.len() > limits.max_header_count {
        return Err(HttpErrorKind::TooManyHeaders.into());
    }

    let mut headers = Headers::with_capacity(lines.len());
    for line in lines {
        parse_header_line(line, &mut headers)?;
    }

    let body = response_body_framing(&headers, status, request_method, &limits)?;
    let connection_close = headers.list_contains("connection", "close")
        || (version == Version::Http10 && !headers.list_contains("connection", "keep-alive"))
        || body == BodyFraming::UntilClose;

    Ok(ParseStatus::Complete(ResponseHead {
        version,
        status,
        reason,
        headers,
        body,
        connection_close,
        head_len: head_end,
    }))
}

fn split_crlf_strict(head: &[u8]) -> Result<Vec<&[u8]>, HttpError> {
    let mut out = Vec::new();
    let mut rest = head;
    loop {
        let Some(term) = rest.iter().position(|b| matches!(*b, b'\r' | b'\n')) else {
            if !rest.is_empty() {
                out.push(rest);
            }
            return Ok(out);
        };
        // `term` came from `position` on `rest`, so the split always succeeds.
        let Some((line, tail)) = rest.split_at_checked(term) else {
            return Err(HttpErrorKind::MalformedStatusLine.into());
        };
        match tail {
            [b'\r', b'\n', remainder @ ..] => {
                out.push(line);
                rest = remainder;
            }
            _ => return Err(HttpErrorKind::MalformedStatusLine.into()),
        }
    }
}

fn parse_status_line(line: &[u8]) -> Result<(Version, u16, String), HttpError> {
    // Exactly one space separates the version from the code; `splitn` gives the
    // two halves without any index arithmetic.
    let mut parts = line.splitn(2, |b| *b == b' ');
    let version_bytes = parts.next().unwrap_or(&[]);
    let rest = parts
        .next()
        .ok_or_else(|| HttpError::from(HttpErrorKind::MalformedStatusLine))?;
    let version = Version::parse(version_bytes)?;

    let [d0, d1, d2, tail @ ..] = rest else {
        return Err(HttpErrorKind::InvalidStatusCode.into());
    };
    if !d0.is_ascii_digit() || !d1.is_ascii_digit() || !d2.is_ascii_digit() {
        return Err(HttpErrorKind::InvalidStatusCode.into());
    }
    let status = u16::from(d0 - b'0') * 100 + u16::from(d1 - b'0') * 10 + u16::from(d2 - b'0');
    if !(100..=599).contains(&status) {
        return Err(HttpErrorKind::InvalidStatusCode.into());
    }

    // The reason phrase is optional, but if anything follows the code it must
    // begin with a single space.
    let reason = match tail {
        [] => String::new(),
        [b' ', phrase @ ..] => {
            if !is_field_value(phrase) {
                return Err(HttpErrorKind::MalformedStatusLine.into());
            }
            String::from_utf8_lossy(phrase).into_owned()
        }
        _ => return Err(HttpErrorKind::MalformedStatusLine.into()),
    };

    Ok((version, status, reason))
}

fn parse_header_line(line: &[u8], headers: &mut Headers) -> Result<(), HttpError> {
    if line.is_empty() {
        return Err(HttpErrorKind::InvalidHeaderName.into());
    }
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(HttpErrorKind::ObsoleteLineFolding.into());
    }
    let Some((name, value)) = split_field(line, b':') else {
        return Err(HttpErrorKind::InvalidHeaderName.into());
    };
    if matches!(name.last(), Some(b' ' | b'\t')) {
        return Err(HttpErrorKind::WhitespaceBeforeColon.into());
    }
    if !is_token(name) {
        return Err(HttpErrorKind::InvalidHeaderName.into());
    }
    if !is_field_value(value) {
        return Err(HttpErrorKind::InvalidHeaderValue.into());
    }
    let name = core::str::from_utf8(name)
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidHeaderName))?;
    let value = core::str::from_utf8(value)
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidHeaderValue))?;
    headers.append(name, trim_ows(value))
}

fn response_body_framing(
    headers: &Headers,
    status: u16,
    request_method: &Method,
    limits: &Limits,
) -> Result<BodyFraming, HttpError> {
    // RFC 9112 6.3: these never have a body, whatever the headers say.
    if ResponseHead::status_forbids_body(status) || !request_method.response_has_body() {
        return Ok(BodyFraming::None);
    }

    let te = headers.get("transfer-encoding");
    let cl = headers.get("content-length");

    // An upstream sending both is as dangerous as a client sending both: the
    // connection is pooled and reused, so a disagreement about where this
    // response ends becomes a prefix on the next one.
    if te.is_some() && cl.is_some() {
        return Err(HttpErrorKind::ConflictingFraming.into());
    }

    if let Some(te) = te {
        if !te.eq_ignore_ascii_case("chunked") {
            return Err(HttpErrorKind::UnsupportedTransferEncoding.into());
        }
        return Ok(BodyFraming::Chunked);
    }

    if let Some(cl) = cl {
        let n = crate::request::parse_content_length(cl)?;
        if n > limits.max_body_bytes {
            return Err(HttpErrorKind::BodyTooLarge.into());
        }
        return Ok(if n == 0 {
            BodyFraming::None
        } else {
            BodyFraming::Fixed(n)
        });
    }

    // No length and no chunking: the body runs until close. This is how SSE
    // streams arrive from several providers.
    Ok(BodyFraming::UntilClose)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str, method: &Method) -> Result<ResponseHead, HttpError> {
        match parse_response_head(raw.as_bytes(), method, &Limits::UPSTREAM)? {
            ParseStatus::Complete(h) => Ok(h),
            ParseStatus::Incomplete => panic!("expected complete head"),
        }
    }

    fn err(raw: &str) -> HttpErrorKind {
        parse(raw, &Method::Get).expect_err("expected rejection").kind
    }

    // -- Request encoding ---------------------------------------------------

    #[test]
    fn encodes_a_post_with_body() {
        let bytes = RequestBuilder::new(Method::Post, "/v1/chat/completions", "api.example")
            .unwrap()
            .header("Content-Type", "application/json")
            .unwrap()
            .header("Authorization", "Bearer secret")
            .unwrap()
            .finish_with_body(br#"{"a":1}"#)
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(text.contains("host: api.example\r\n"));
        assert!(text.contains("content-length: 7\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"a\":1}"));
    }

    #[test]
    fn encodes_a_get_without_content_length() {
        let bytes = RequestBuilder::new(Method::Get, "/v1/models", "api.example")
            .unwrap()
            .finish_with_body(b"")
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("content-length"));
    }

    #[test]
    fn encodes_a_chunked_request() {
        let bytes = RequestBuilder::new(Method::Post, "/v1/messages", "api.example")
            .unwrap()
            .finish_chunked()
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("transfer-encoding: chunked"));
        assert!(!text.contains("content-length"));
    }

    #[test]
    fn rejects_non_origin_targets_and_bad_hosts() {
        assert_eq!(
            RequestBuilder::new(Method::Get, "http://x/y", "a").unwrap_err().kind,
            HttpErrorKind::NonOriginFormTarget
        );
        assert_eq!(
            RequestBuilder::new(Method::Get, "//x/y", "a").unwrap_err().kind,
            HttpErrorKind::NonOriginFormTarget
        );
        assert_eq!(
            RequestBuilder::new(Method::Get, "/a b", "a").unwrap_err().kind,
            HttpErrorKind::InvalidTarget
        );
        assert_eq!(
            RequestBuilder::new(Method::Get, "/a", "bad host").unwrap_err().kind,
            HttpErrorKind::InvalidHost
        );
        assert_eq!(
            RequestBuilder::new(Method::Get, "/a", "").unwrap_err().kind,
            HttpErrorKind::InvalidHost
        );
    }

    #[test]
    fn credential_headers_cannot_inject_a_request() {
        let e = RequestBuilder::new(Method::Post, "/v1/x", "api.example")
            .unwrap()
            .header("Authorization", "Bearer x\r\nX-Injected: 1");
        assert!(e.is_err());
    }

    // -- Response parsing ---------------------------------------------------

    #[test]
    fn parses_a_fixed_length_response() {
        let h = parse(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n",
            &Method::Post,
        )
        .unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.reason, "OK");
        assert_eq!(h.body, BodyFraming::Fixed(12));
        assert!(h.is_success());
        assert!(!h.connection_close);
    }

    #[test]
    fn parses_an_sse_response() {
        let h = parse(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
            &Method::Post,
        )
        .unwrap();
        assert!(h.is_event_stream());
        assert_eq!(h.body, BodyFraming::UntilClose);
        assert!(h.connection_close, "close-delimited implies no reuse");
    }

    #[test]
    fn parses_a_chunked_response() {
        let h = parse(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            &Method::Post,
        )
        .unwrap();
        assert_eq!(h.body, BodyFraming::Chunked);
        assert!(!h.connection_close);
    }

    #[test]
    fn empty_reason_phrase_is_accepted() {
        let h = parse("HTTP/1.1 204 \r\n\r\n", &Method::Get).unwrap();
        assert_eq!(h.status, 204);
        assert_eq!(h.reason, "");
        let h = parse("HTTP/1.1 204\r\n\r\n", &Method::Get).unwrap();
        assert_eq!(h.status, 204);
    }

    #[test]
    fn reason_phrase_may_contain_spaces() {
        let h = parse("HTTP/1.1 503 Service Unavailable\r\n\r\n", &Method::Get).unwrap();
        assert_eq!(h.reason, "Service Unavailable");
    }

    #[test]
    fn head_response_never_has_a_body() {
        let h = parse(
            "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n",
            &Method::Head,
        )
        .unwrap();
        assert_eq!(
            h.body,
            BodyFraming::None,
            "a HEAD response advertises a length but sends no bytes"
        );
    }

    #[test]
    fn bodyless_statuses_ignore_content_length() {
        for status in [100u16, 101, 204, 304] {
            let raw = format!("HTTP/1.1 {status} X\r\nContent-Length: 99\r\n\r\n");
            let h = parse(&raw, &Method::Get).unwrap();
            assert_eq!(h.body, BodyFraming::None, "status {status}");
        }
    }

    #[test]
    fn upstream_framing_conflict_is_rejected() {
        assert_eq!(
            err("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"),
            HttpErrorKind::ConflictingFraming
        );
    }

    #[test]
    fn upstream_duplicate_headers_are_rejected() {
        assert_eq!(
            err("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"),
            HttpErrorKind::DuplicateHeader
        );
    }

    #[test]
    fn malformed_status_lines_are_rejected() {
        assert_eq!(err("HTTP/1.1\r\n\r\n"), HttpErrorKind::MalformedStatusLine);
        assert_eq!(err("HTTP/1.1 20 OK\r\n\r\n"), HttpErrorKind::InvalidStatusCode);
        assert_eq!(err("HTTP/1.1 2000 OK\r\n\r\n"), HttpErrorKind::MalformedStatusLine);
        assert_eq!(err("HTTP/1.1 abc OK\r\n\r\n"), HttpErrorKind::InvalidStatusCode);
        assert_eq!(err("HTTP/1.1 099 OK\r\n\r\n"), HttpErrorKind::InvalidStatusCode);
        assert_eq!(err("HTTP/9.9 200 OK\r\n\r\n"), HttpErrorKind::UnsupportedVersion);
        assert_eq!(err("200 OK\r\n\r\n"), HttpErrorKind::UnsupportedVersion);
    }

    #[test]
    fn bare_lf_from_upstream_is_rejected() {
        assert_eq!(
            err("HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n"),
            HttpErrorKind::MalformedStatusLine
        );
    }

    #[test]
    fn folded_upstream_headers_are_rejected() {
        assert_eq!(
            err("HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\n\r\n"),
            HttpErrorKind::ObsoleteLineFolding
        );
    }

    #[test]
    fn incomplete_upstream_head_reports_incomplete() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";
        assert!(matches!(
            parse_response_head(partial, &Method::Get, &Limits::UPSTREAM).unwrap(),
            ParseStatus::Incomplete
        ));
    }

    #[test]
    fn byte_at_a_time_upstream_delivery() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
        for split in 0..raw.len() {
            match parse_response_head(&raw.as_bytes()[..split], &Method::Get, &Limits::UPSTREAM) {
                Ok(ParseStatus::Incomplete) => {}
                other => panic!("prefix {split} gave {other:?}"),
            }
        }
    }

    #[test]
    fn oversize_upstream_head_is_rejected() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(40_000)
        );
        assert_eq!(
            parse_response_head(raw.as_bytes(), &Method::Get, &Limits::UPSTREAM)
                .unwrap_err()
                .kind,
            HttpErrorKind::HeadTooLarge
        );
    }

    #[test]
    fn http_1_0_upstream_defaults_to_close() {
        let h = parse("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", &Method::Get).unwrap();
        assert!(h.connection_close);
        let h = parse(
            "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
            &Method::Get,
        )
        .unwrap();
        assert!(!h.connection_close);
    }
}
