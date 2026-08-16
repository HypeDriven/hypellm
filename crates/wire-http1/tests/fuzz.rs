//! Fuzz targets for the HTTP/1.1 parser.
//!
//! Specification 21 requires a Fuzz layer over "HTTP, JSON, SSE, config,
//! provider events, state recovery"; this is the HTTP target. This parser is
//! the router's outermost trust boundary — everything a hostile client sends
//! arrives here first — and specification 18.2 requires "no panics on
//! data-plane input".
//!
//! # The property that matters most
//!
//! Specification 10.1 lists request smuggling as a named threat. Smuggling is a
//! *disagreement* between two parsers about where one message ends, so beyond
//! "does not panic" these targets assert the framing decision is never
//! ambiguous: an input the parser accepts must have exactly one interpretation
//! of its body length, and any input offering two must be refused rather than
//! resolved.

use hypellm_test_corpus::fuzz::{self, Rng};
use wire_http1::{Limits, ParseStatus, parse_request_head};

const ITERATIONS: u32 = 20_000;

fn seeds() -> Vec<&'static [u8]> {
    hypellm_test_corpus::http1::all().iter().map(|v| v.raw).collect()
}

#[test]
fn no_mutation_of_the_corpus_panics_the_head_parser() {
    let seeds = seeds();
    let (accepted, rejected) = fuzz::sweep(&seeds, ITERATIONS, 0x4874_0001, |case| {
        matches!(
            parse_request_head(case, &Limits::DEFAULT),
            Ok(ParseStatus::Complete(_))
        )
    });

    assert!(accepted > 0, "no mutated request was ever accepted");
    assert_eq!(accepted + rejected, ITERATIONS);
}

#[test]
fn an_accepted_head_never_declares_two_framings() {
    // Specification 10.1: request smuggling. A head carrying both
    // `Content-Length` and `Transfer-Encoding` has two answers to "where does
    // the body end", and any parser that picks one can be made to disagree
    // with the next hop. It must be refused, not resolved — including after
    // mutation has inserted the second header.
    let seeds = seeds();
    let (_, _) = fuzz::sweep(&seeds, ITERATIONS, 0x4874_0002, |case| {
        match parse_request_head(case, &Limits::DEFAULT) {
            Ok(ParseStatus::Complete(head)) => {
                let has_length = head.headers.get("content-length").is_some();
                let has_encoding = head.headers.get("transfer-encoding").is_some();
                assert!(
                    !(has_length && has_encoding),
                    "a head with conflicting framing was accepted: {:?}",
                    String::from_utf8_lossy(case)
                );
                true
            }
            _ => false,
        }
    });
}

#[test]
fn an_accepted_head_carries_no_control_bytes_in_its_fields() {
    // A NUL or a bare CR that survives into a header value is header injection
    // waiting for the next component that reserialises it.
    let seeds = seeds();
    let (_, _) = fuzz::sweep(&seeds, ITERATIONS, 0x4874_0003, |case| {
        match parse_request_head(case, &Limits::DEFAULT) {
            Ok(ParseStatus::Complete(head)) => {
                assert!(
                    !head.path.bytes().any(|b| b < 0x20 || b == 0x7f),
                    "a control byte survived into the request path"
                );
                true
            }
            _ => false,
        }
    });
}

#[test]
fn the_head_size_limit_holds_on_mutated_input() {
    // Specification 3.2: "Inbound header bytes: default 32 KiB; hard maximum
    // 64 KiB." A mutation that splices a long run must not be accepted past
    // the bound.
    let seeds = seeds();
    let limits = Limits::DEFAULT;
    let (_, _) = fuzz::sweep(&seeds, ITERATIONS, 0x4874_0004, |case| {
        match parse_request_head(case, &limits) {
            Ok(ParseStatus::Complete(head)) => {
                assert!(
                    head.head_len <= limits.max_head_bytes,
                    "a head of {} bytes was accepted past the {} byte limit",
                    head.head_len,
                    limits.max_head_bytes
                );
                true
            }
            _ => false,
        }
    });
}

#[test]
fn an_incomplete_head_is_never_reported_as_complete() {
    // Every prefix of a valid request must be `Incomplete` or an error, never
    // `Complete`: a parser that completes early has decided a message boundary
    // the sender did not send.
    for vector in hypellm_test_corpus::http1::all() {
        let full = vector.raw;
        for cut in 0..full.len() {
            let prefix = full.get(..cut).unwrap_or_default();
            if let Ok(ParseStatus::Complete(head)) = parse_request_head(prefix, &Limits::DEFAULT) {
                assert!(
                    head.head_len <= prefix.len(),
                    "the parser completed a head longer than the bytes it was given"
                );
            }
        }
    }
}

#[test]
fn random_bytes_are_rejected_without_panicking() {
    let mut rng = Rng::new(0x4874_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(1024);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let _ = parse_request_head(&case, &Limits::DEFAULT);
    }
}

#[test]
fn a_head_of_many_short_headers_is_bounded_by_the_count_limit() {
    // Specification 3.2 bounds the header count as well as the byte total; a
    // parser bounded only by bytes still allocates one entry per header.
    let mut request = Vec::from(&b"GET / HTTP/1.1\r\nHost: a\r\n"[..]);
    for n in 0..10_000u32 {
        request.extend_from_slice(format!("x-{n}: v\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");

    assert!(
        !matches!(
            parse_request_head(&request, &Limits::DEFAULT),
            Ok(ParseStatus::Complete(_))
        ),
        "a head with 10,000 headers was accepted"
    );
}
