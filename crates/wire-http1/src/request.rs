//! Server-side request head parsing.
//!
//! This is the router's outermost trust boundary. Specification 10.1 names
//! request smuggling as a threat and prescribes "single strict parser; edge
//! normalization; reject TE/CL ambiguity and invalid duplicate headers".
//!
//! The parser therefore refuses everything ambiguous rather than normalising
//! it:
//!
//! - CRLF is the only line terminator. A bare LF or bare CR in the head is an
//!   error, because a front end that accepts one and a back end that accepts
//!   the other can be made to disagree about where a request ends.
//! - Exactly one space separates the three request-line tokens.
//! - Obsolete line folding is rejected.
//! - Whitespace before a header colon is rejected.
//! - `Content-Length` and `Transfer-Encoding` together are rejected.
//! - `Transfer-Encoding` must be exactly `chunked`.
//! - Single-valued headers may not repeat.
//! - The request target must be in origin form.

use crate::error::{HttpError, HttpErrorKind};
use crate::header::{Headers, is_field_value, is_token, split_field, trim_ows};
use crate::limits::Limits;
use crate::message::{BodyFraming, Method, RequestHead, Version};

/// Outcome of attempting to parse a head from a buffer.
#[derive(Debug)]
pub enum ParseStatus<T> {
    /// A complete head was parsed.
    Complete(T),
    /// More bytes are required. The buffer has been checked against the size
    /// limits, so a caller may safely read more.
    Incomplete,
}

/// Attempt to parse a request head from `buf`.
///
/// Returns [`ParseStatus::Incomplete`] when the terminating CRLF CRLF has not
/// arrived yet. `head_len` on the returned value tells the caller how many
/// bytes to consume before reading the body.
pub fn parse_request_head(
    buf: &[u8],
    limits: &Limits,
) -> Result<ParseStatus<RequestHead>, HttpError> {
    let limits = limits.clamped();

    let head_end = match find_head_end(buf) {
        Some(end) => end,
        None => {
            if buf.len() > limits.max_head_bytes {
                return Err(HttpErrorKind::HeadTooLarge.into());
            }
            // A bare LF before any CRLF CRLF is still a framing violation, and
            // detecting it now avoids buffering to the limit first.
            if let Some(err) = scan_for_bare_terminators(buf) {
                return Err(err);
            }
            return Ok(ParseStatus::Incomplete);
        }
    };

    if head_end > limits.max_head_bytes {
        return Err(HttpErrorKind::HeadTooLarge.into());
    }

    // `find_head_end` returns the offset just past a CRLF CRLF, so `head_end`
    // is at least 4 and at most `buf.len()`; the fallback is unreachable.
    let head = match head_end.checked_sub(4).and_then(|end| buf.get(..end)) {
        Some(head) => head,
        None => return Err(HttpErrorKind::MalformedRequestLine.into()),
    };
    if head.contains(&0u8) {
        return Err(HttpErrorKind::NulInHead.into());
    }

    let mut lines = split_crlf(head)?;
    if lines.is_empty() {
        return Err(HttpErrorKind::MalformedRequestLine.into());
    }

    let request_line = lines.remove(0);
    let (method, target, version) = parse_request_line(request_line, &limits)?;

    if lines.len() > limits.max_header_count {
        return Err(HttpErrorKind::TooManyHeaders.into());
    }

    let mut headers = Headers::with_capacity(lines.len());
    for line in lines {
        parse_header_line(line, &mut headers)?;
    }

    let body = request_body_framing(&headers, version, &limits)?;
    validate_host(&headers, version)?;

    let expect_continue = headers.list_contains("expect", "100-continue");
    let connection_close = headers.list_contains("connection", "close")
        || (version == Version::Http10 && !headers.list_contains("connection", "keep-alive"));

    let (path, query) = split_target(&target);

    Ok(ParseStatus::Complete(RequestHead {
        method,
        target: target.clone(),
        path,
        query,
        version,
        headers,
        body,
        expect_continue,
        connection_close,
        head_len: head_end,
    }))
}

/// Locate the end of the head, returning the offset just past `CRLF CRLF`.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Detect a bare LF or bare CR in a partial head.
fn scan_for_bare_terminators(buf: &[u8]) -> Option<HttpError> {
    let mut rest = buf;
    loop {
        match rest {
            [b'\n', ..] => return Some(HttpErrorKind::MalformedRequestLine.into()),
            // A trailing CR may simply be the first half of a CRLF that has not
            // arrived yet, so it ends the scan without an error.
            [b'\r'] | [] => return None,
            [b'\r', b'\n', tail @ ..] => rest = tail,
            [b'\r', ..] => return Some(HttpErrorKind::MalformedRequestLine.into()),
            [_, tail @ ..] => rest = tail,
        }
    }
}

/// Split a head into lines on CRLF, rejecting any bare CR or bare LF.
fn split_crlf(head: &[u8]) -> Result<Vec<&[u8]>, HttpError> {
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
            return Err(HttpErrorKind::MalformedRequestLine.into());
        };
        match tail {
            [b'\r', b'\n', remainder @ ..] => {
                out.push(line);
                rest = remainder;
            }
            _ => return Err(HttpErrorKind::MalformedRequestLine.into()),
        }
    }
}

fn parse_request_line(
    line: &[u8],
    limits: &Limits,
) -> Result<(Method, String, Version), HttpError> {
    // Exactly two spaces, and no leading or trailing whitespace. RFC 9112
    // allows a recipient to be liberal here; a router must not be, because
    // "GET  /a HTTP/1.1" is read differently by different parsers.
    let mut parts = line.split(|b| *b == b' ');
    let method_bytes = parts
        .next()
        .ok_or_else(|| HttpError::from(HttpErrorKind::MalformedRequestLine))?;
    let target_bytes = parts
        .next()
        .ok_or_else(|| HttpError::from(HttpErrorKind::MalformedRequestLine))?;
    let version_bytes = parts
        .next()
        .ok_or_else(|| HttpError::from(HttpErrorKind::MalformedRequestLine))?;
    if parts.next().is_some() {
        return Err(HttpErrorKind::MalformedRequestLine.into());
    }

    if method_bytes.len() > limits.max_method_bytes {
        return Err(HttpErrorKind::InvalidMethod.into());
    }
    if !is_token(method_bytes) {
        return Err(HttpErrorKind::InvalidMethod.into());
    }
    let method_str = core::str::from_utf8(method_bytes)
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidMethod))?;
    let method = Method::from_token(method_str);

    let target = parse_target(target_bytes, &method, limits)?;
    let version = Version::parse(version_bytes)?;

    Ok((method, target, version))
}

fn parse_target(bytes: &[u8], method: &Method, limits: &Limits) -> Result<String, HttpError> {
    if bytes.is_empty() {
        return Err(HttpErrorKind::InvalidTarget.into());
    }
    if bytes.len() > limits.max_target_bytes {
        return Err(HttpErrorKind::InvalidTarget.into());
    }
    // Only visible ASCII. Space is already excluded by the split; this also
    // rejects DEL, control characters, and raw non-ASCII, which clients are
    // required to percent-encode.
    if !bytes.iter().all(|b| (0x21..=0x7E).contains(b)) {
        return Err(HttpErrorKind::InvalidTarget.into());
    }

    let text = core::str::from_utf8(bytes)
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidTarget))?;

    if text == "*" {
        // Asterisk-form is only meaningful for a server-wide OPTIONS.
        return if matches!(method, Method::Options) {
            Ok(text.to_owned())
        } else {
            Err(HttpErrorKind::InvalidTarget.into())
        };
    }

    // Absolute-form and authority-form belong to a forward proxy. Accepting
    // them would let a caller name an upstream, which specification 10 forbids
    // outright.
    if !text.starts_with('/') {
        return Err(HttpErrorKind::NonOriginFormTarget.into());
    }
    // A target beginning `//` is read as an authority by some intermediaries
    // and as a path by others.
    if text.starts_with("//") {
        return Err(HttpErrorKind::NonOriginFormTarget.into());
    }

    Ok(text.to_owned())
}

fn split_target(target: &str) -> (String, Option<String>) {
    match target.find('?') {
        Some(i) => (target[..i].to_owned(), Some(target[i + 1..].to_owned())),
        None => (target.to_owned(), None),
    }
}

fn parse_header_line(line: &[u8], headers: &mut Headers) -> Result<(), HttpError> {
    if line.is_empty() {
        return Err(HttpErrorKind::InvalidHeaderName.into());
    }
    // Obsolete folding: a continuation line begins with SP or HTAB.
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(HttpErrorKind::ObsoleteLineFolding.into());
    }

    // `split_field` requires a colon and returns the halves either side of it.
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
    // `obs-text` bytes are permitted on the wire but are not valid UTF-8. They
    // never appear in a header the router interprets, so rejecting them keeps
    // every stored value a `str`.
    let value = core::str::from_utf8(value)
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidHeaderValue))?;

    headers.append(name, trim_ows(value))
}

/// Decide how a request body is framed.
pub(crate) fn request_body_framing(
    headers: &Headers,
    version: Version,
    limits: &Limits,
) -> Result<BodyFraming, HttpError> {
    let te = headers.get("transfer-encoding");
    let cl = headers.get("content-length");

    if te.is_some() && cl.is_some() {
        return Err(HttpErrorKind::ConflictingFraming.into());
    }

    if let Some(te) = te {
        if version == Version::Http10 {
            // Chunked transfer coding did not exist in HTTP/1.0.
            return Err(HttpErrorKind::UnsupportedTransferEncoding.into());
        }
        // Only a bare `chunked` is accepted. A coding list such as
        // `gzip, chunked` would require the router to decompress attacker-
        // controlled data before authentication, which it will not do.
        if !te.eq_ignore_ascii_case("chunked") {
            return Err(HttpErrorKind::UnsupportedTransferEncoding.into());
        }
        return Ok(BodyFraming::Chunked);
    }

    if let Some(cl) = cl {
        let n = parse_content_length(cl)?;
        if n > limits.max_body_bytes {
            return Err(HttpErrorKind::BodyTooLarge.into());
        }
        return Ok(if n == 0 {
            BodyFraming::None
        } else {
            BodyFraming::Fixed(n)
        });
    }

    Ok(BodyFraming::None)
}

/// Parse a `Content-Length` value strictly.
///
/// Only a non-empty run of ASCII digits. This rejects `+5`, `-5`, `0x5`,
/// `5, 5`, `5 5`, and leading-whitespace forms that different parsers read
/// differently.
pub(crate) fn parse_content_length(value: &str) -> Result<u64, HttpError> {
    if value.is_empty() || value.len() > 19 {
        return Err(HttpErrorKind::InvalidContentLength.into());
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpErrorKind::InvalidContentLength.into());
    }
    value
        .parse::<u64>()
        .map_err(|_| HttpError::from(HttpErrorKind::InvalidContentLength))
}

fn validate_host(headers: &Headers, version: Version) -> Result<(), HttpError> {
    let host = headers.get("host");
    match host {
        None => {
            if version == Version::Http11 {
                Err(HttpErrorKind::MissingHost.into())
            } else {
                Ok(())
            }
        }
        Some(h) => {
            if h.is_empty() || h.len() > 255 {
                return Err(HttpErrorKind::InvalidHost.into());
            }
            // Reject anything that could smuggle a userinfo, a path, or a
            // second authority into a value the router may later use to build
            // a URL or a routing decision.
            let ok = h.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
            });
            if !ok {
                return Err(HttpErrorKind::InvalidHost.into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<RequestHead, HttpError> {
        match parse_request_head(raw.as_bytes(), &Limits::DEFAULT)? {
            ParseStatus::Complete(h) => Ok(h),
            ParseStatus::Incomplete => panic!("expected a complete head for {raw:?}"),
        }
    }

    fn err(raw: &str) -> HttpErrorKind {
        parse(raw).expect_err("expected rejection").kind
    }

    const OK: &str = "POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 2\r\n\r\n";

    #[test]
    fn parses_a_well_formed_request() {
        let h = parse(OK).unwrap();
        assert_eq!(h.method, Method::Post);
        assert_eq!(h.target, "/v1/chat/completions");
        assert_eq!(h.path, "/v1/chat/completions");
        assert_eq!(h.query, None);
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.host(), Some("router.example"));
        assert_eq!(h.body, BodyFraming::Fixed(2));
        assert!(!h.connection_close);
        assert!(!h.expect_continue);
        assert_eq!(h.head_len, OK.len());
    }

    #[test]
    fn incomplete_head_reports_incomplete() {
        let partial = "POST /v1/chat HTTP/1.1\r\nHost: a\r\n";
        assert!(matches!(
            parse_request_head(partial.as_bytes(), &Limits::DEFAULT).unwrap(),
            ParseStatus::Incomplete
        ));
        assert!(matches!(
            parse_request_head(b"", &Limits::DEFAULT).unwrap(),
            ParseStatus::Incomplete
        ));
        assert!(matches!(
            parse_request_head(b"GET / HTTP/1.1\r", &Limits::DEFAULT).unwrap(),
            ParseStatus::Incomplete
        ));
    }

    #[test]
    fn byte_at_a_time_delivery_parses_identically() {
        let expected = parse(OK).unwrap();
        for split in 0..OK.len() {
            let head = &OK.as_bytes()[..split];
            match parse_request_head(head, &Limits::DEFAULT) {
                Ok(ParseStatus::Incomplete) => {}
                Ok(ParseStatus::Complete(_)) => {
                    panic!("prefix of length {split} parsed as complete")
                }
                Err(e) => panic!("prefix of length {split} errored: {e}"),
            }
        }
        assert_eq!(expected.head_len, OK.len());
    }

    #[test]
    fn query_string_is_split_but_not_decoded() {
        let h = parse("GET /v1/models?limit=10&after=x%2Fy HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(h.path, "/v1/models");
        assert_eq!(h.query.as_deref(), Some("limit=10&after=x%2Fy"));
        // The raw target keeps its encoding: decoding before routing is how
        // `%2f` becomes a path separator the router did not intend.
        assert_eq!(h.target, "/v1/models?limit=10&after=x%2Fy");
    }

    #[test]
    fn path_traversal_encoding_is_not_normalised() {
        let h = parse("GET /v1/..%2f..%2fadmin/v1/keys HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(h.path, "/v1/..%2f..%2fadmin/v1/keys");
        assert!(!h.path.contains("/admin/v1/keys"));
    }

    // -- Framing ambiguity ------------------------------------------------

    #[test]
    fn content_length_with_transfer_encoding_is_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"),
            HttpErrorKind::ConflictingFraming
        );
        // Order must not matter.
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"),
            HttpErrorKind::ConflictingFraming
        );
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
            HttpErrorKind::DuplicateHeader
        );
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"),
            HttpErrorKind::DuplicateHeader
        );
    }

    #[test]
    fn duplicate_host_and_transfer_encoding_are_rejected() {
        assert_eq!(
            err("GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
            HttpErrorKind::DuplicateHeader
        );
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"),
            HttpErrorKind::DuplicateHeader
        );
    }

    #[test]
    fn malformed_content_length_values_are_rejected() {
        for value in ["", " ", "+5", "-5", "0x5", "5, 5", "5 5", "five", "5.0", "٥"] {
            let raw =
                format!("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {value}\r\n\r\n");
            let e = parse(&raw).expect_err("must reject").kind;
            assert!(
                matches!(
                    e,
                    HttpErrorKind::InvalidContentLength | HttpErrorKind::InvalidHeaderValue
                ),
                "Content-Length {value:?} produced {e:?}"
            );
        }
    }

    #[test]
    fn non_chunked_transfer_encodings_are_rejected() {
        for te in ["gzip", "gzip, chunked", "chunked, gzip", "identity", "chunked;q=1"] {
            let raw = format!("POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {te}\r\n\r\n");
            let e = parse(&raw).expect_err("must reject").kind;
            assert_eq!(
                e,
                HttpErrorKind::UnsupportedTransferEncoding,
                "Transfer-Encoding {te:?}"
            );
        }
        // A bare `chunked` is accepted, case-insensitively and after the
        // optional whitespace that RFC 9112 requires be stripped.
        for te in ["chunked", "CHUNKED", "Chunked", "chunked ", "  chunked"] {
            let raw = format!("POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {te}\r\n\r\n");
            assert_eq!(parse(&raw).unwrap().body, BodyFraming::Chunked);
        }
    }

    #[test]
    fn transfer_encoding_on_http_1_0_is_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"),
            HttpErrorKind::UnsupportedTransferEncoding
        );
    }

    #[test]
    fn zero_content_length_means_no_body() {
        assert_eq!(
            parse("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
                .unwrap()
                .body,
            BodyFraming::None
        );
    }

    #[test]
    fn oversize_content_length_is_rejected() {
        let limits = Limits::DEFAULT.with_max_body_bytes(10);
        let raw = "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\n";
        let e = match parse_request_head(raw.as_bytes(), &limits) {
            Err(e) => e.kind,
            Ok(_) => panic!("must reject"),
        };
        assert_eq!(e, HttpErrorKind::BodyTooLarge);
    }

    // -- Line-ending and folding strictness --------------------------------

    #[test]
    fn bare_lf_line_endings_are_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.1\nHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine
        );
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\nContent-Length: 0\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine
        );
    }

    #[test]
    fn bare_cr_in_head_is_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.1\rHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine
        );
    }

    #[test]
    fn obsolete_line_folding_is_rejected() {
        assert_eq!(
            err("GET /a HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n  two\r\n\r\n"),
            HttpErrorKind::ObsoleteLineFolding
        );
        assert_eq!(
            err("GET /a HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n\ttwo\r\n\r\n"),
            HttpErrorKind::ObsoleteLineFolding
        );
    }

    #[test]
    fn whitespace_before_colon_is_rejected() {
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n"),
            HttpErrorKind::WhitespaceBeforeColon
        );
        assert_eq!(
            err("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length\t: 5\r\n\r\n"),
            HttpErrorKind::WhitespaceBeforeColon
        );
    }

    #[test]
    fn nul_in_head_is_rejected() {
        let mut raw = Vec::from(&b"GET /a HTTP/1.1\r\nHost: a\r\nX: "[..]);
        raw.push(0);
        raw.extend_from_slice(b"\r\n\r\n");
        let e = parse_request_head(&raw, &Limits::DEFAULT).unwrap_err().kind;
        assert_eq!(e, HttpErrorKind::NulInHead);
    }

    // -- Request line strictness -------------------------------------------

    #[test]
    fn request_line_requires_exactly_three_tokens() {
        assert_eq!(err("GET /a\r\nHost: a\r\n\r\n"), HttpErrorKind::MalformedRequestLine);
        assert_eq!(
            err("GET /a HTTP/1.1 extra\r\nHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine
        );
        assert_eq!(
            err("GET  /a HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine,
            "double space must not be collapsed"
        );
        // A leading space makes the line four space-separated tokens, so it is
        // rejected as a malformed request line rather than reaching the method
        // check. What matters is that it is not silently trimmed.
        assert_eq!(
            err(" GET /a HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine
        );
        assert_eq!(
            err("GET /a HTTP/1.1 \r\nHost: a\r\n\r\n"),
            HttpErrorKind::MalformedRequestLine,
            "a trailing space is a fourth, empty token"
        );
    }

    #[test]
    fn invalid_methods_are_rejected() {
        assert_eq!(
            err("G\u{1}T /a HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::InvalidMethod
        );
        let long = "A".repeat(64);
        assert_eq!(
            err(&format!("{long} /a HTTP/1.1\r\nHost: a\r\n\r\n")),
            HttpErrorKind::InvalidMethod
        );
    }

    #[test]
    fn unknown_but_valid_methods_are_carried_through() {
        let h = parse("PROPFIND /a HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(h.method, Method::Other("PROPFIND".to_owned()));
    }

    #[test]
    fn absolute_and_authority_form_targets_are_rejected() {
        assert_eq!(
            err("GET http://evil.example/a HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::NonOriginFormTarget
        );
        assert_eq!(
            err("GET https://169.254.169.254/latest/meta-data HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::NonOriginFormTarget
        );
        assert_eq!(
            err("CONNECT evil.example:443 HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::NonOriginFormTarget
        );
        assert_eq!(
            err("GET //evil.example/a HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::NonOriginFormTarget
        );
    }

    #[test]
    fn asterisk_target_only_for_options() {
        assert!(parse("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").is_ok());
        assert_eq!(
            err("GET * HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::InvalidTarget
        );
    }

    #[test]
    fn control_and_non_ascii_targets_are_rejected() {
        assert_eq!(
            err("GET /a\u{7f}b HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::InvalidTarget
        );
        assert_eq!(
            err("GET /café HTTP/1.1\r\nHost: a\r\n\r\n"),
            HttpErrorKind::InvalidTarget
        );
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        assert_eq!(
            err("GET /a HTTP/2.0\r\nHost: a\r\n\r\n"),
            HttpErrorKind::UnsupportedVersion
        );
        assert_eq!(
            err("GET /a HTTP/0.9\r\nHost: a\r\n\r\n"),
            HttpErrorKind::UnsupportedVersion
        );
    }

    // -- Host --------------------------------------------------------------

    #[test]
    fn http_1_1_requires_host() {
        assert_eq!(err("GET /a HTTP/1.1\r\n\r\n"), HttpErrorKind::MissingHost);
        // HTTP/1.0 may omit it.
        assert!(parse("GET /a HTTP/1.0\r\n\r\n").is_ok());
    }

    #[test]
    fn suspicious_host_values_are_rejected() {
        for host in [
            "a/b",
            "user@host",
            "host\\path",
            "",
            "a b",
            "host#frag",
            "host?q",
        ] {
            let raw = format!("GET /a HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let e = parse(&raw).expect_err("must reject").kind;
            assert!(
                matches!(e, HttpErrorKind::InvalidHost | HttpErrorKind::MissingHost),
                "host {host:?} produced {e:?}"
            );
        }
        // Legitimate forms are accepted.
        for host in ["router.example", "router.example:8443", "127.0.0.1:9000", "[::1]:9000"] {
            let raw = format!("GET /a HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert!(parse(&raw).is_ok(), "host {host:?} should be accepted");
        }
    }

    // -- Size limits --------------------------------------------------------

    #[test]
    fn head_size_is_bounded() {
        let filler = "X-Pad: ".to_owned() + &"a".repeat(40_000) + "\r\n";
        let raw = format!("GET /a HTTP/1.1\r\nHost: a\r\n{filler}\r\n");
        let e = parse_request_head(raw.as_bytes(), &Limits::DEFAULT)
            .unwrap_err()
            .kind;
        assert_eq!(e, HttpErrorKind::HeadTooLarge);
        assert_eq!(e.status(), 431);
    }

    #[test]
    fn header_count_is_bounded() {
        let mut raw = String::from("GET /a HTTP/1.1\r\nHost: a\r\n");
        for i in 0..200 {
            raw.push_str(&format!("X-H{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(
            parse_request_head(raw.as_bytes(), &Limits::DEFAULT)
                .unwrap_err()
                .kind,
            HttpErrorKind::TooManyHeaders
        );
    }

    #[test]
    fn incomplete_oversize_head_is_rejected_without_waiting() {
        let raw = "GET /a HTTP/1.1\r\nHost: a\r\nX: ".to_owned() + &"a".repeat(40_000);
        assert_eq!(
            parse_request_head(raw.as_bytes(), &Limits::DEFAULT)
                .unwrap_err()
                .kind,
            HttpErrorKind::HeadTooLarge
        );
    }

    // -- Connection semantics ----------------------------------------------

    #[test]
    fn connection_close_is_detected() {
        let h = parse("GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
        assert!(h.connection_close);
        let h = parse("GET /a HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n").unwrap();
        assert!(h.connection_close);
    }

    #[test]
    fn http_1_0_defaults_to_close() {
        assert!(parse("GET /a HTTP/1.0\r\n\r\n").unwrap().connection_close);
        assert!(
            !parse("GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
                .unwrap()
                .connection_close
        );
    }

    #[test]
    fn expect_continue_is_detected() {
        let h = parse("POST /a HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n")
            .unwrap();
        assert!(h.expect_continue);
        let h = parse("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n").unwrap();
        assert!(!h.expect_continue);
    }

    #[test]
    fn accept_and_content_type_helpers() {
        let h = parse(
            "POST /a HTTP/1.1\r\nHost: a\r\nContent-Type: application/json; charset=utf-8\r\nAccept: text/event-stream\r\n\r\n",
        )
        .unwrap();
        assert_eq!(h.content_type().as_deref(), Some("application/json"));
        assert!(h.accepts_event_stream());

        let h = parse("POST /a HTTP/1.1\r\nHost: a\r\nAccept: application/json\r\n\r\n").unwrap();
        assert!(!h.accepts_event_stream());
    }

    #[test]
    fn header_values_are_ows_trimmed() {
        let h = parse("GET /a HTTP/1.1\r\nHost: a\r\nX-Pad:   value  \r\n\r\n").unwrap();
        assert_eq!(h.headers.get("x-pad"), Some("value"));
    }

    #[test]
    fn empty_header_value_is_allowed() {
        let h = parse("GET /a HTTP/1.1\r\nHost: a\r\nX-Empty:\r\n\r\n").unwrap();
        assert_eq!(h.headers.get("x-empty"), Some(""));
    }
}
