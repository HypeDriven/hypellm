//! The shared protocol corpus, run against this parser.
//!
//! Specification 21 requires the security suite to work from a shared corpus so
//! that the smuggling vectors, the fuzz seeds, and the parser's own tests agree
//! on what "correct" means. `hypellm-test-corpus` holds the vectors and their
//! expected outcomes; the comparison lives here, in the crate under test.
//!
//! The inline vectors in `src/request.rs` and `src/lib.rs` are unaffected and
//! stay where they are — migrating them onto the corpus is separate work under
//! specification 21.1's two-person review rule for parser changes.

use hypellm_test_corpus::http1::{self, HttpVector};
use hypellm_test_corpus::limits as boundary;
use hypellm_test_corpus::outcome::Outcome;
use wire_http1::{HttpError, Limits, ParseStatus, parse_request_head};

/// Feed one input to the parser and report what it did in corpus terms.
fn observe(raw: &[u8]) -> Result<ParseStatus<wire_http1::RequestHead>, HttpError> {
    parse_request_head(raw, &Limits::DEFAULT)
}

/// Check one input against one expectation, naming the vector on failure.
fn check(name: &str, why: &str, raw: &[u8], outcome: Outcome) {
    match (observe(raw), outcome) {
        (Ok(ParseStatus::Complete(_)), Outcome::Accept)
        | (Ok(ParseStatus::Incomplete), Outcome::Incomplete) => {}
        (Err(error), Outcome::Reject(_)) => {
            assert!(
                outcome.permits_code(error.code()),
                "{name}: rejected with {:?}, but the corpus requires {}\n  why: {why}",
                error.code(),
                outcome.describe()
            );
        }
        (observed, expected) => {
            let described = match observed {
                Ok(ParseStatus::Complete(_)) => "accepted".to_owned(),
                Ok(ParseStatus::Incomplete) => "reported incomplete".to_owned(),
                Err(error) => format!("rejected with {:?}", error.code()),
            };
            panic!(
                "{name}: parser {described}, but the corpus requires {}\n  why: {why}",
                expected.describe()
            );
        }
    }
}

#[test]
fn every_corpus_vector_matches_its_expectation() {
    assert!(!http1::all().is_empty(), "the corpus is empty");
    for HttpVector {
        name,
        raw,
        outcome,
        why,
        ..
    } in http1::all()
    {
        check(name, why, raw, *outcome);
    }
}

#[test]
fn the_smuggling_selection_is_refused_without_exception() {
    // Kept separate from the sweep above so that a corpus reorganisation that
    // dropped a smuggling vector from the general list still fails here.
    let mut checked = 0usize;
    for vector in http1::smuggling() {
        check(vector.name, vector.why, vector.raw, vector.outcome);
        checked += 1;

        // Specification 10.1: once framing is in doubt, the bytes left on the
        // connection cannot be attributed to a request. A rejection that leaves
        // the connection reusable is how a smuggled prefix becomes the next
        // caller's request line, so refusing the message is only half the
        // control.
        if vector.outcome.is_reject() {
            let error = observe(vector.raw).expect_err("the corpus says reject");
            assert!(
                error.kind.must_close(),
                "{}: rejected with {:?}, which permits connection reuse",
                vector.name,
                error.code()
            );
        }
    }
    assert!(checked >= 10, "only {checked} smuggling vectors were run");
}

#[test]
fn boundary_cases_land_exactly_on_the_documented_limits() {
    // Specification 3.2 fixes these bounds. The corpus generates the largest
    // input that must be accepted and the smallest that must not; an off-by-one
    // in either direction is a real client's largest request being refused, or
    // a budget that is not the budget.
    assert_eq!(
        boundary::HTTP_DEFAULT_MAX_HEAD_BYTES,
        Limits::DEFAULT.max_head_bytes,
        "the corpus was written against a different head budget than this parser enforces"
    );
    assert_eq!(
        boundary::HTTP_DEFAULT_MAX_HEADER_COUNT,
        Limits::DEFAULT.max_header_count,
        "the corpus was written against a different header count than this parser enforces"
    );

    for case in boundary::http_head_size_cases()
        .into_iter()
        .chain(boundary::http_header_count_cases())
    {
        check(case.name, case.why, &case.input, case.outcome);
    }
}

#[test]
fn accepted_vectors_report_the_head_length_they_actually_consumed() {
    // `head_len` is what a caller uses to find the body, and on a pipelined
    // connection to find the next request. A wrong value there is a framing
    // fault of the same kind the smuggling vectors are about.
    for vector in http1::all().iter().filter(|v| v.outcome.is_accept()) {
        let ParseStatus::Complete(head) = observe(vector.raw).expect("the corpus says accept")
        else {
            panic!("{}: expected a complete head", vector.name);
        };
        let terminator = vector
            .raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("an accepted vector is terminated");
        assert_eq!(
            head.head_len,
            terminator + 4,
            "{}: head_len does not point just past the first terminator",
            vector.name
        );
    }
}

#[test]
fn every_prefix_of_an_accepted_vector_is_incomplete_rather_than_wrong() {
    // Delivery timing must not change the verdict: a parser that accepts or
    // rejects a prefix behaves differently for a slow client than for a fast
    // one, and that difference is exploitable.
    for vector in http1::all().iter().filter(|v| v.outcome.is_accept()) {
        for split in 0..vector.raw.len() {
            let prefix = vector.raw.get(..split).expect("split is in range");
            match parse_request_head(prefix, &Limits::DEFAULT) {
                Ok(ParseStatus::Incomplete) => {}
                Ok(ParseStatus::Complete(_)) => {
                    panic!("{}: prefix of {split} bytes parsed as complete", vector.name)
                }
                Err(error) => panic!(
                    "{}: prefix of {split} bytes was rejected with {:?}",
                    vector.name,
                    error.code()
                ),
            }
        }
    }
}
