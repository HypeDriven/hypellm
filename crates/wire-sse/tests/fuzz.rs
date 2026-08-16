//! Fuzz targets for the server-sent events parser.
//!
//! Specification 21 requires a Fuzz layer covering "provider events"; this is
//! that target. The bytes reaching this parser come from a *provider*, which
//! specification 10.1's threat model treats as hostile: a compromised or
//! merely buggy upstream can send anything, and the router must not crash,
//! stall, or grow without bound because of it.
//!
//! # Incremental delivery is the point
//!
//! Specification 14: "The router parses upstream streaming incrementally and
//! emits complete client-protocol events. It MUST NOT buffer an entire
//! completion." A stream arrives in arbitrary chunks, so these targets feed
//! the same bytes split at every boundary the fuzzer picks — the split itself
//! is part of the input, and a parser that only works when a frame arrives
//! whole is broken.

use hypellm_test_corpus::fuzz::{self, Rng};
use wire_sse::{SseLimits, SseParser};

const ITERATIONS: u32 = 20_000;

fn seeds() -> Vec<&'static [u8]> {
    hypellm_test_corpus::sse::all().iter().map(|v| v.raw).collect()
}

/// Feed `case` to a parser in one piece.
fn feed_whole(case: &[u8]) -> bool {
    let mut parser = SseParser::with_default_limits();
    if parser.push(case).is_err() {
        return false;
    }
    parser.drain().is_ok()
}

#[test]
fn no_mutation_of_the_corpus_panics_the_parser() {
    let seeds = seeds();
    let (accepted, rejected) = fuzz::sweep(&seeds, ITERATIONS, 0x5353_0001, feed_whole);

    assert!(accepted > 0, "no mutated stream was ever accepted");
    assert_eq!(accepted + rejected, ITERATIONS);
}

#[test]
fn an_arbitrary_chunk_split_produces_the_same_decision_as_the_whole() {
    // The split is chosen by the network, not the sender. A parser whose answer
    // depends on where a TCP segment happened to land will dispatch a partial
    // frame under load and look correct in every test that pushes whole
    // buffers.
    let seeds = seeds();
    let mut rng = Rng::new(0x5353_0002);

    for _ in 0..ITERATIONS {
        let Some(base) = rng.pick(&seeds).copied() else {
            break;
        };
        let case = fuzz::mutate(base, &mut rng);

        let whole = feed_whole(&case);

        // Same bytes, delivered in random slices.
        let mut parser = SseParser::with_default_limits();
        let mut offset = 0usize;
        let mut split_ok = true;
        while offset < case.len() {
            let take = 1 + rng.below(case.len() - offset);
            let chunk = case.get(offset..offset + take).unwrap_or_default();
            if parser.push(chunk).is_err() {
                split_ok = false;
                break;
            }
            if parser.drain().is_err() {
                split_ok = false;
                break;
            }
            offset += take;
        }

        assert_eq!(
            whole, split_ok,
            "the parser's decision depended on where the stream was cut: {:?}",
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn an_event_that_is_never_terminated_is_refused_at_its_bound() {
    // Specification 3.2 bounds per-stream buffered data. An upstream that
    // sends `data:` lines forever and never the blank line that completes the
    // frame must hit a ceiling, not grow until the router dies.
    //
    // Explicit small limits rather than the defaults: the property is that the
    // bound is enforced, and asserting it against a 1 MiB default would mean
    // pushing a megabyte through the test to learn the same thing.
    let mut parser = SseParser::new(SseLimits {
        max_buffer_bytes: 4096,
        max_event_bytes: 1024,
        max_field_name_bytes: 64,
    });

    let mut refused = false;
    for _ in 0..100_000 {
        if parser.push(b"data: x\n").is_err() || parser.drain().is_err() {
            refused = true;
            break;
        }
    }

    assert!(
        refused,
        "an unterminated event was buffered past its declared ceiling"
    );
}

#[test]
fn the_default_limits_also_bound_an_unterminated_event() {
    // The same property at the shipped defaults, so a change to
    // `SseLimits::DEFAULT` that removed the ceiling would still be caught.
    // 1 MiB of payload at roughly two bytes per line.
    let mut parser = SseParser::with_default_limits();
    let mut refused = false;

    for _ in 0..1_200_000 {
        if parser.push(b"data: x\n").is_err() || parser.drain().is_err() {
            refused = true;
            break;
        }
    }

    assert!(refused, "the default limits did not bound an unterminated event");
}

#[test]
fn a_single_line_that_never_ends_is_refused_by_the_buffer_bound() {
    // The other unbounded shape: one line, no newline, forever. This is the
    // `max_buffer_bytes` ceiling rather than `max_event_bytes`.
    let mut parser = SseParser::with_default_limits();
    let mut refused = false;

    for _ in 0..100_000 {
        if parser.push(b"aaaaaaaaaaaaaaaa").is_err() || parser.drain().is_err() {
            refused = true;
            break;
        }
    }

    assert!(refused, "a line with no terminator was buffered without bound");
}

#[test]
fn a_single_oversize_event_is_refused() {
    let mut parser = SseParser::with_default_limits();
    let payload = vec![b'a'; 4 * 1024 * 1024];
    let mut chunk = Vec::from(&b"data: "[..]);
    chunk.extend_from_slice(&payload);
    chunk.extend_from_slice(b"\n\n");

    assert!(
        parser.push(&chunk).is_err() || parser.drain().is_err(),
        "a 4 MiB event was accepted"
    );
}

#[test]
fn random_bytes_are_handled_without_panicking() {
    let mut rng = Rng::new(0x5353_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(512);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let mut parser = SseParser::with_default_limits();
        if parser.push(&case).is_ok() {
            let _ = parser.drain();
        }
    }
}

#[test]
fn truncation_at_every_offset_is_handled() {
    for vector in hypellm_test_corpus::sse::all() {
        for cut in 0..vector.raw.len().min(512) {
            let prefix = vector.raw.get(..cut).unwrap_or_default();
            let mut parser = SseParser::with_default_limits();
            if parser.push(prefix).is_ok() {
                let _ = parser.drain();
            }
        }
    }
}
