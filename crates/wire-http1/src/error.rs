//! Parse failures, each carrying the status the router should answer with.
//!
//! Specification 8.2 fixes the client error contract. A transport-level failure
//! happens before authentication and before routing, so it must answer with a
//! status and a stable code and nothing else — no echo of the offending bytes,
//! no hint about what the router does or does not support beyond the category.

/// What went wrong while parsing an HTTP/1.1 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorKind {
    /// The request line was malformed.
    MalformedRequestLine,
    /// The status line of an upstream response was malformed.
    MalformedStatusLine,
    /// The HTTP version was absent, malformed, or unsupported.
    UnsupportedVersion,
    /// The method contained a character outside the token grammar, or was
    /// longer than permitted.
    InvalidMethod,
    /// The request target was empty, over-long, or contained a forbidden byte.
    InvalidTarget,
    /// The request target was in absolute or authority form.
    ///
    /// Specification 2.2 makes general-purpose proxying a non-goal, and
    /// specification 10 forbids user input selecting an upstream. Accepting a
    /// proxy-form target would be the first half of exactly that.
    NonOriginFormTarget,
    /// A header name was not a valid token.
    InvalidHeaderName,
    /// A header value contained a forbidden byte.
    InvalidHeaderValue,
    /// Whitespace appeared between a header name and its colon.
    ///
    /// RFC 9112 requires rejecting this: intermediaries disagree about whether
    /// `Content-Length : 5` is a `Content-Length` header, which is a smuggling
    /// primitive.
    WhitespaceBeforeColon,
    /// A header used obsolete line folding.
    ObsoleteLineFolding,
    /// A header that must appear at most once appeared more than once.
    DuplicateHeader,
    /// The head exceeded the permitted byte count.
    HeadTooLarge,
    /// The head contained more headers than permitted.
    TooManyHeaders,
    /// `Content-Length` was not a single decimal value.
    InvalidContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` were present.
    ///
    /// The canonical request-smuggling setup.
    ConflictingFraming,
    /// A `Transfer-Encoding` other than a single `chunked` was requested.
    UnsupportedTransferEncoding,
    /// `Host` was missing on an HTTP/1.1 request.
    MissingHost,
    /// `Host` was not a valid host or contained a forbidden byte.
    InvalidHost,
    /// A chunk size line was malformed or over-long.
    InvalidChunkSize,
    /// A chunk was not followed by CRLF.
    InvalidChunkTerminator,
    /// The body exceeded the permitted length.
    BodyTooLarge,
    /// The trailer section was over-long or contained a forbidden field.
    InvalidTrailer,
    /// A NUL byte appeared in the message head.
    NulInHead,
    /// The upstream closed before the message was complete.
    UnexpectedEof,
    /// The status code was not three digits.
    InvalidStatusCode,
    /// The message did not arrive within its absolute deadline.
    ///
    /// Distinct from [`HttpErrorKind::HeadTooLarge`] and
    /// [`HttpErrorKind::BodyTooLarge`]: nothing exceeded a size limit, the
    /// bytes simply arrived too slowly. Reporting a size error for a slow
    /// client sends an operator hunting for a payload problem that does not
    /// exist.
    RequestTimeout,
}

impl HttpErrorKind {
    /// Stable machine-readable code, surfaced in the error body.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedRequestLine => "malformed_request_line",
            Self::MalformedStatusLine => "malformed_status_line",
            Self::UnsupportedVersion => "unsupported_http_version",
            Self::InvalidMethod => "invalid_method",
            Self::InvalidTarget => "invalid_request_target",
            Self::NonOriginFormTarget => "non_origin_form_target",
            Self::InvalidHeaderName => "invalid_header_name",
            Self::InvalidHeaderValue => "invalid_header_value",
            Self::WhitespaceBeforeColon => "whitespace_before_colon",
            Self::ObsoleteLineFolding => "obsolete_line_folding",
            Self::DuplicateHeader => "duplicate_header",
            Self::HeadTooLarge => "head_too_large",
            Self::TooManyHeaders => "too_many_headers",
            Self::InvalidContentLength => "invalid_content_length",
            Self::ConflictingFraming => "conflicting_framing",
            Self::UnsupportedTransferEncoding => "unsupported_transfer_encoding",
            Self::MissingHost => "missing_host",
            Self::InvalidHost => "invalid_host",
            Self::InvalidChunkSize => "invalid_chunk_size",
            Self::InvalidChunkTerminator => "invalid_chunk_terminator",
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidTrailer => "invalid_trailer",
            Self::NulInHead => "nul_in_head",
            Self::UnexpectedEof => "unexpected_eof",
            Self::InvalidStatusCode => "invalid_status_code",
            Self::RequestTimeout => "request_timeout",
        }
    }

    /// The HTTP status the router answers a client with.
    ///
    /// Anything ambiguous is a 400: the router must not guess which
    /// interpretation the caller meant.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::HeadTooLarge | Self::TooManyHeaders => 431,
            Self::BodyTooLarge => 413,
            Self::RequestTimeout => 408,
            Self::UnsupportedVersion => 505,
            Self::UnsupportedTransferEncoding => 501,
            _ => 400,
        }
    }

    /// Whether the connection must be closed rather than reused.
    ///
    /// Once framing is in doubt, the bytes remaining on the connection cannot
    /// be attributed to a request. Reusing it is how a smuggled prefix becomes
    /// the next caller's request line.
    #[must_use]
    pub const fn must_close(self) -> bool {
        !matches!(self, Self::UnsupportedVersion)
    }

    const fn message(self) -> &'static str {
        match self {
            Self::MalformedRequestLine => "malformed request line",
            Self::MalformedStatusLine => "malformed status line",
            Self::UnsupportedVersion => "unsupported HTTP version",
            Self::InvalidMethod => "invalid method",
            Self::InvalidTarget => "invalid request target",
            Self::NonOriginFormTarget => "request target must be in origin form",
            Self::InvalidHeaderName => "invalid header name",
            Self::InvalidHeaderValue => "invalid header value",
            Self::WhitespaceBeforeColon => "whitespace between header name and colon",
            Self::ObsoleteLineFolding => "obsolete header line folding",
            Self::DuplicateHeader => "duplicate single-valued header",
            Self::HeadTooLarge => "message head exceeds the permitted size",
            Self::TooManyHeaders => "message head contains too many headers",
            Self::InvalidContentLength => "invalid Content-Length",
            Self::ConflictingFraming => "Content-Length and Transfer-Encoding both present",
            Self::UnsupportedTransferEncoding => "unsupported Transfer-Encoding",
            Self::MissingHost => "missing Host header",
            Self::InvalidHost => "invalid Host header",
            Self::InvalidChunkSize => "invalid chunk size",
            Self::InvalidChunkTerminator => "invalid chunk terminator",
            Self::BodyTooLarge => "body exceeds the permitted size",
            Self::InvalidTrailer => "invalid trailer section",
            Self::NulInHead => "NUL byte in message head",
            Self::UnexpectedEof => "connection closed before the message was complete",
            Self::InvalidStatusCode => "invalid status code",
            Self::RequestTimeout => "the request did not arrive within its deadline",
        }
    }
}

/// A parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpError {
    /// What went wrong.
    pub kind: HttpErrorKind,
}

impl HttpError {
    /// Construct from a kind.
    #[must_use]
    pub const fn new(kind: HttpErrorKind) -> Self {
        Self { kind }
    }

    /// The status to answer with.
    #[must_use]
    pub const fn status(self) -> u16 {
        self.kind.status()
    }

    /// The stable code to report.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl From<HttpErrorKind> for HttpError {
    fn from(kind: HttpErrorKind) -> Self {
        Self::new(kind)
    }
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for HttpError {}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[HttpErrorKind] = &[
        HttpErrorKind::MalformedRequestLine,
        HttpErrorKind::MalformedStatusLine,
        HttpErrorKind::UnsupportedVersion,
        HttpErrorKind::InvalidMethod,
        HttpErrorKind::InvalidTarget,
        HttpErrorKind::NonOriginFormTarget,
        HttpErrorKind::InvalidHeaderName,
        HttpErrorKind::InvalidHeaderValue,
        HttpErrorKind::WhitespaceBeforeColon,
        HttpErrorKind::ObsoleteLineFolding,
        HttpErrorKind::DuplicateHeader,
        HttpErrorKind::HeadTooLarge,
        HttpErrorKind::TooManyHeaders,
        HttpErrorKind::InvalidContentLength,
        HttpErrorKind::ConflictingFraming,
        HttpErrorKind::UnsupportedTransferEncoding,
        HttpErrorKind::MissingHost,
        HttpErrorKind::InvalidHost,
        HttpErrorKind::InvalidChunkSize,
        HttpErrorKind::InvalidChunkTerminator,
        HttpErrorKind::BodyTooLarge,
        HttpErrorKind::InvalidTrailer,
        HttpErrorKind::NulInHead,
        HttpErrorKind::UnexpectedEof,
        HttpErrorKind::InvalidStatusCode,
        HttpErrorKind::RequestTimeout,
    ];

    #[test]
    fn codes_are_distinct() {
        let mut codes: Vec<&str> = ALL.iter().map(|k| k.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);
    }

    #[test]
    fn statuses_are_client_errors_or_501_505() {
        for k in ALL {
            let s = k.status();
            assert!(
                (400..=431).contains(&s) || s == 501 || s == 505,
                "{k:?} maps to unexpected status {s}"
            );
        }
    }

    #[test]
    fn framing_ambiguity_closes_the_connection() {
        // The security-relevant cases must all force a close, so that leftover
        // bytes cannot be read as the next request.
        for k in [
            HttpErrorKind::ConflictingFraming,
            HttpErrorKind::InvalidContentLength,
            HttpErrorKind::InvalidChunkSize,
            HttpErrorKind::InvalidChunkTerminator,
            HttpErrorKind::WhitespaceBeforeColon,
            HttpErrorKind::ObsoleteLineFolding,
            HttpErrorKind::DuplicateHeader,
        ] {
            assert!(k.must_close(), "{k:?} must close the connection");
        }
    }

    #[test]
    fn oversize_maps_to_431_and_413() {
        assert_eq!(HttpErrorKind::HeadTooLarge.status(), 431);
        assert_eq!(HttpErrorKind::TooManyHeaders.status(), 431);
        assert_eq!(HttpErrorKind::BodyTooLarge.status(), 413);
    }

    #[test]
    fn display_does_not_echo_input() {
        for k in ALL {
            let msg = HttpError::new(*k).to_string();
            assert!(!msg.is_empty());
            assert!(!msg.contains('\r') && !msg.contains('\n'));
        }
    }
}
