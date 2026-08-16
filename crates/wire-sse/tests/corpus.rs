//! The shared SSE corpus, run against this parser.
//!
//! Specification 21 requires shared corpora; `hypellm-test-corpus` holds the
//! vectors and the events each must dispatch, and this file is the comparison.
//! The inline tests in `src/parse.rs` are unaffected.

use hypellm_test_corpus::limits as boundary;
use hypellm_test_corpus::outcome::Outcome;
use hypellm_test_corpus::sse::{self, ExpectedEvent, SseVector};
use wire_sse::{SseEvent, SseLimits, SseParser};

/// Feed a whole stream in one push and drain whatever it produced.
fn parse_whole(raw: &[u8]) -> Result<(Vec<SseEvent>, bool), wire_sse::SseError> {
    let mut parser = SseParser::with_default_limits();
    parser.push(raw)?;
    let events = parser.drain()?;
    Ok((events, parser.has_incomplete_tail()))
}

fn matches(observed: &SseEvent, expected: &ExpectedEvent) -> bool {
    observed.event.as_deref() == expected.event
        && observed.data == expected.data
        && observed.id.as_deref() == expected.id
        && observed.retry == expected.retry
}

/// Check one stream against one expectation, naming the vector on failure.
fn check(name: &str, why: &str, raw: &[u8], outcome: Outcome, expected: &[ExpectedEvent]) {
    match (parse_whole(raw), outcome) {
        (Ok((events, incomplete)), Outcome::Accept) => {
            assert!(
                !incomplete,
                "{name}: accepted but left a partial line buffered\n  why: {why}"
            );
            assert_eq!(
                events.len(),
                expected.len(),
                "{name}: dispatched {} events, the corpus expects {}\n  why: {why}\n  got: {events:?}",
                events.len(),
                expected.len()
            );
            for (index, (observed, want)) in events.iter().zip(expected).enumerate() {
                assert!(
                    matches(observed, want),
                    "{name}: event {index} is {observed:?}, the corpus expects {want:?}\n  why: {why}"
                );
            }
        }
        (Ok((events, incomplete)), Outcome::Incomplete) => {
            assert!(
                events.is_empty(),
                "{name}: dispatched {events:?} from an unterminated stream\n  why: {why}"
            );
            assert!(
                incomplete,
                "{name}: reported no partial line, but the corpus says the stream is cut short\n  why: {why}"
            );
        }
        (Err(error), Outcome::Reject(_)) => {
            assert!(
                outcome.permits_code(error.code()),
                "{name}: failed with {:?}, but the corpus requires {}\n  why: {why}",
                error.code(),
                outcome.describe()
            );
        }
        (observed, expected_outcome) => {
            let described = match observed {
                Ok((events, _)) => format!("dispatched {} events", events.len()),
                Err(error) => format!("failed with {:?}", error.code()),
            };
            panic!(
                "{name}: parser {described}, but the corpus requires {}\n  why: {why}",
                expected_outcome.describe()
            );
        }
    }
}

#[test]
fn every_corpus_vector_matches_its_expectation() {
    assert!(!sse::all().is_empty(), "the corpus is empty");
    for SseVector {
        name,
        raw,
        outcome,
        expected,
        why,
        ..
    } in sse::all()
    {
        check(name, why, raw, *outcome, expected);
    }
}

#[test]
fn byte_at_a_time_delivery_produces_the_same_events() {
    // The framing bug that matters: a CR ending one read and an LF beginning
    // the next must not look like two terminators. A provider's chunk
    // boundaries are outside the router's control, so an event count that
    // depends on them is an event count that depends on the network.
    for vector in sse::all().iter().filter(|v| v.outcome.is_accept()) {
        let (whole, _) = parse_whole(vector.raw).expect("the corpus says accept");

        let mut parser = SseParser::with_default_limits();
        let mut incremental = Vec::new();
        for byte in vector.raw {
            parser.push(&[*byte]).expect("the corpus says accept");
            incremental.extend(parser.drain().expect("the corpus says accept"));
        }
        assert_eq!(
            whole, incremental,
            "{}: chunking changed the events dispatched",
            vector.name
        );
    }
}

#[test]
fn boundary_cases_land_exactly_on_the_documented_buffer_limit() {
    assert_eq!(
        boundary::SSE_DEFAULT_MAX_BUFFER_BYTES,
        SseLimits::DEFAULT.max_buffer_bytes,
        "the corpus was written against a different buffer ceiling than this parser enforces"
    );
    for case in boundary::sse_line_length_cases() {
        let observed = parse_whole(&case.input);
        match (observed, case.outcome) {
            (Ok((events, _)), Outcome::Accept) => {
                assert_eq!(events.len(), 1, "{}: expected one event", case.name);
            }
            (Err(error), Outcome::Reject(_)) => assert!(
                case.outcome.permits_code(error.code()),
                "{}: failed with {:?}, the corpus requires {}",
                case.name,
                error.code(),
                case.outcome.describe()
            ),
            (other, expected) => panic!(
                "{}: got {other:?}, the corpus requires {}\n  why: {}",
                case.name,
                expected.describe(),
                case.why
            ),
        }
    }
}

#[test]
fn a_failure_is_sticky_across_the_rest_of_the_stream() {
    // Once framing is lost the parser can no longer place event boundaries, so
    // continuing would hand an adapter fragments attributed to the wrong event.
    for vector in sse::all().iter().filter(|v| v.outcome.is_reject()) {
        let mut parser = SseParser::with_default_limits();
        let first = parser.push(vector.raw).expect_err("the corpus says reject");
        assert_eq!(
            parser.push(b"data: recovered\n\n"),
            Err(first),
            "{}: the parser accepted data after a framing failure",
            vector.name
        );
        assert_eq!(parser.next_event(), Err(first));
    }
}
