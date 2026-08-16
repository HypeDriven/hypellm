//! Strict, bounded HTTP/1.1 for HypeLLM Router.
//!
//! Specification 18.1: "Strict bounded HTTP/1.1 server/client state machines
//! where platform edge does not supply normalized transport."
//!
//! # Why a parser rather than a library
//!
//! Specification 4 admits no registry dependencies, so this is written in
//! repository. That constraint turns out to be aligned with the threat model:
//! specification 10.1 lists request smuggling, and every smuggling technique is
//! a *disagreement* between two parsers about where a message ends. A parser
//! whose only job is to refuse ambiguity is smaller and more auditable than one
//! that aims for maximum interoperability.
//!
//! # What is refused
//!
//! | Input | Result |
//! |---|---|
//! | Bare LF or bare CR in a head | rejected |
//! | Obsolete line folding | rejected |
//! | Whitespace before a header colon | rejected |
//! | `Content-Length` with `Transfer-Encoding` | rejected |
//! | Repeated `Content-Length`, `Host`, `Authorization`, … | rejected |
//! | `Transfer-Encoding` other than exactly `chunked` | rejected |
//! | Non-decimal `Content-Length` | rejected |
//! | Absolute-form, authority-form, or `//`-prefixed target | rejected |
//! | Non-ASCII or control bytes in a target | rejected |
//! | Framing or auth fields in a chunked trailer | rejected |
//! | Head over 32 KiB (64 KiB hard maximum) | rejected |
//!
//! # Shape of the API
//!
//! Parsing is a pure function over a buffer that returns
//! [`ParseStatus::Incomplete`] rather than blocking, so the same code serves a
//! blocking socket, a test vector, and a fuzz driver.
//!
//! ```
//! use wire_http1::{Limits, ParseStatus, parse_request_head};
//!
//! let raw = b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\n\r\n";
//! match parse_request_head(raw, &Limits::DEFAULT)? {
//!     ParseStatus::Complete(head) => {
//!         assert_eq!(head.path, "/v1/models");
//!         assert_eq!(head.host(), Some("router.example"));
//!     }
//!     ParseStatus::Incomplete => unreachable!("the head is complete"),
//! }
//! # Ok::<(), wire_http1::HttpError>(())
//! ```

#![forbid(unsafe_code)]
// Specification 18.2: "no panics on data-plane input; all integer conversions
// checked". This crate *is* the data plane's outer edge — every byte a hostile
// client sends is parsed here — so the workspace-level warnings are escalated
// to errors for the whole crate rather than for selected modules. An
// out-of-range index or a silent truncating `as` in this code is a remote
// crash or a framing disagreement, which is what specification 10.1 calls
// request smuggling. Test code may still index and panic freely.
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::as_conversions))]
#![cfg_attr(not(test), deny(clippy::panic))]

pub mod body;
pub mod client;
pub mod error;
pub mod header;
pub mod limits;
pub mod message;
pub mod request;
pub mod response;

pub use body::{BodyDecoder, encode_chunk, encode_last_chunk};
pub use client::{RequestBuilder, parse_response_head};
pub use error::{HttpError, HttpErrorKind};
pub use header::{Headers, trim_ows};
pub use limits::Limits;
pub use message::{BodyFraming, Method, RequestHead, ResponseHead, Version};
pub use request::{ParseStatus, parse_request_head};
pub use response::{ResponseBuilder, continue_response, reason_phrase};

#[cfg(test)]
mod smuggling_tests {
    //! Specification 21 requires a security test layer covering request
    //! smuggling. Each case here is a published technique; the assertion is
    //! always that the router refuses to guess.

    use super::*;

    fn reject(raw: &[u8]) -> HttpErrorKind {
        parse_request_head(raw, &Limits::DEFAULT)
            .expect_err("this request must be rejected")
            .kind
    }

    #[test]
    fn cl_te_desync() {
        // Front end honours Content-Length, back end honours Transfer-Encoding.
        let raw = b"POST /v1/chat HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/v1/keys HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::ConflictingFraming);
    }

    #[test]
    fn te_cl_desync() {
        let raw = b"POST /v1/chat HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGET /admin/v1/keys HTTP/1.1\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::ConflictingFraming);
    }

    #[test]
    fn te_te_obfuscation() {
        // A second, differently-spelled Transfer-Encoding that one hop ignores.
        for raw in [
            &b"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"[..],
            b"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n",
        ] {
            assert_eq!(reject(raw), HttpErrorKind::DuplicateHeader);
        }
    }

    #[test]
    fn te_with_space_before_colon() {
        let raw = b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::WhitespaceBeforeColon);
    }

    #[test]
    fn te_hidden_by_line_folding() {
        let raw =
            b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nX-Ignore: x\r\n Transfer-Encoding: chunked\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::ObsoleteLineFolding);
    }

    #[test]
    fn lf_only_request_line_desync() {
        // A hop that accepts bare LF sees a different message boundary than one
        // that requires CRLF.
        let raw = b"POST /a HTTP/1.1\nHost: a\nContent-Length: 0\n\n";
        assert_eq!(reject(raw), HttpErrorKind::MalformedRequestLine);
    }

    #[test]
    fn lf_terminated_header_inside_crlf_head() {
        let raw = b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\nX-Smuggled: 1\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::MalformedRequestLine);
    }

    #[test]
    fn duplicate_host_for_routing_confusion() {
        let raw = b"GET /a HTTP/1.1\r\nHost: trusted.internal\r\nHost: evil.example\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::DuplicateHeader);
    }

    #[test]
    fn absolute_uri_naming_an_upstream() {
        // Specification 10: no client-controlled value may select a destination.
        let raw = b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: router.example\r\n\r\n";
        assert_eq!(reject(raw), HttpErrorKind::NonOriginFormTarget);
    }

    #[test]
    fn chunk_size_obfuscation_is_rejected_by_the_body_decoder() {
        use crate::body::BodyDecoder;
        let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
        let mut out = Vec::new();
        // A leading `0x`, a sign, or padding would be read differently by
        // different implementations.
        for input in [&b"0x5\r\nhello\r\n"[..], b" 5\r\nhello\r\n", b"05 \r\nhello\r\n"] {
            let mut d2 = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
            assert!(d2.decode(input, &mut Vec::new()).is_err(), "{input:?}");
        }
        assert!(d.decode(b"5\r\nhello\r\n0\r\n\r\n", &mut out).is_ok());
    }

    #[test]
    fn trailer_cannot_reintroduce_framing() {
        use crate::body::BodyDecoder;
        let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
        let raw = b"0\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            d.decode(raw, &mut Vec::new()).unwrap_err().kind,
            HttpErrorKind::InvalidTrailer
        );
    }

    #[test]
    fn every_rejection_closes_the_connection() {
        // A rejected message leaves unattributable bytes on the wire. Reusing
        // that connection is how a smuggled prefix becomes the next caller's
        // request line.
        for raw in [
            &b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST /a HTTP/1.1\nHost: a\r\n\r\n",
            b"GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET /a HTTP/1.1\r\nHost: a\r\nX : 1\r\n\r\n",
        ] {
            let kind = reject(raw);
            assert!(kind.must_close(), "{kind:?} must force a connection close");
        }
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    /// A full exchange: encode a request, parse it as a server, build a
    /// response, parse it as a client.
    #[test]
    fn full_exchange() {
        let request = RequestBuilder::new(Method::Post, "/v1/chat/completions", "api.example")
            .unwrap()
            .header("Content-Type", "application/json")
            .unwrap()
            .finish_with_body(br#"{"model":"x"}"#)
            .unwrap();

        let head = match parse_request_head(&request, &Limits::DEFAULT).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        };
        assert_eq!(head.method, Method::Post);
        assert_eq!(head.body, BodyFraming::Fixed(13));

        let mut decoder = BodyDecoder::new(head.body, Limits::DEFAULT);
        let mut body = Vec::new();
        decoder
            .decode(&request[head.head_len..], &mut body)
            .unwrap();
        assert!(decoder.is_complete());
        assert_eq!(body, br#"{"model":"x"}"#);

        let payload = br#"{"id":"resp_1"}"#;
        let response = ResponseBuilder::new(200)
            .header("Content-Type", "application/json")
            .unwrap()
            .finish_with_length(payload.len())
            .unwrap();

        let rhead = match parse_response_head(&response, &Method::Post, &Limits::UPSTREAM).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        };
        assert_eq!(rhead.status, 200);
        assert_eq!(rhead.body, BodyFraming::Fixed(payload.len() as u64));
    }

    /// A chunked exchange in both directions.
    #[test]
    fn chunked_exchange() {
        let mut wire = RequestBuilder::new(Method::Post, "/v1/messages", "api.example")
            .unwrap()
            .finish_chunked()
            .unwrap();
        encode_chunk(&mut wire, br#"{"partial":"#);
        encode_chunk(&mut wire, br#"true}"#);
        encode_last_chunk(&mut wire);

        let head = match parse_request_head(&wire, &Limits::DEFAULT).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        };
        assert_eq!(head.body, BodyFraming::Chunked);

        let mut decoder = BodyDecoder::new(head.body, Limits::DEFAULT);
        let mut body = Vec::new();
        let consumed = decoder.decode(&wire[head.head_len..], &mut body).unwrap();
        assert!(decoder.is_complete());
        assert_eq!(consumed, wire.len() - head.head_len);
        assert_eq!(body, br#"{"partial":true}"#);
    }

    /// Pipelined requests: the parser must report exactly the first head's
    /// length so the caller can find the second request.
    #[test]
    fn head_len_locates_the_next_message() {
        let first = "GET /v1/models HTTP/1.1\r\nHost: a\r\n\r\n";
        let second = "GET /health/live HTTP/1.1\r\nHost: a\r\n\r\n";
        let joined = format!("{first}{second}");

        let head = match parse_request_head(joined.as_bytes(), &Limits::DEFAULT).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        };
        assert_eq!(head.head_len, first.len());
        assert_eq!(head.path, "/v1/models");

        let rest = &joined.as_bytes()[head.head_len..];
        let head2 = match parse_request_head(rest, &Limits::DEFAULT).unwrap() {
            ParseStatus::Complete(h) => h,
            ParseStatus::Incomplete => panic!("incomplete"),
        };
        assert_eq!(head2.path, "/health/live");
    }
}
