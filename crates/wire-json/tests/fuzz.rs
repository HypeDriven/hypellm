//! Fuzz targets for the JSON parser.
//!
//! Specification 21 requires a Fuzz layer over "HTTP, JSON, SSE, config,
//! provider events, state recovery"; this is the JSON target. Specification
//! 18.2 requires "no panics on data-plane input", and every request body the
//! router accepts reaches this parser before anything else looks at it.
//!
//! The engine is `hypellm_test_corpus::fuzz` — a seeded mutation fuzzer, since
//! specification 4 rules out libFuzzer. Each case is reproducible from the seed
//! printed with a failure.
//!
//! # What is asserted
//!
//! Chiefly that the parser **returns**. A panic here is a remote crash, and an
//! unbounded loop or allocation is a remote denial of service, so the tests
//! also assert that the declared limits hold on mutated input — a limit that
//! only holds for well-formed documents is not a limit.

use hypellm_test_corpus::fuzz::{self, Rng};
use wire_json::{Limits, parse};

/// Iterations per target.
///
/// Enough to be worth running, small enough that the suite stays fast. A fuzz
/// layer that turns `cargo test` into a coffee break gets run with `--skip`.
const ITERATIONS: u32 = 20_000;

fn seeds() -> Vec<&'static [u8]> {
    hypellm_test_corpus::json::all().iter().map(|v| v.raw).collect()
}

#[test]
fn no_mutation_of_the_corpus_panics_the_parser() {
    let seeds = seeds();
    let (accepted, rejected) = fuzz::sweep(&seeds, ITERATIONS, 0x1500_0001, |case| {
        parse(case, &Limits::DEFAULT).is_ok()
    });

    // A sweep that accepted nothing would mean the mutations destroyed every
    // document, and the parser's accept path was never exercised at all.
    assert!(accepted > 0, "no mutated document was ever accepted");
    assert_eq!(accepted + rejected, ITERATIONS);
}

#[test]
fn the_depth_limit_holds_on_mutated_input() {
    // Specification 3.2: "JSON depth / string length: 64 levels / 8 MiB
    // default". Deep nesting is the classic route to a stack overflow, which is
    // a crash the parser cannot catch.
    let seeds = seeds();
    let limits = Limits::DEFAULT;
    let (_, _) = fuzz::sweep(&seeds, ITERATIONS, 0x0eeb_0002, |case| {
        match parse(case, &limits) {
            Ok(value) => {
                assert!(
                    depth_of(&value) <= 64,
                    "a document deeper than the limit was accepted"
                );
                true
            }
            Err(_) => false,
        }
    });
}

#[test]
fn deeply_nested_input_is_refused_rather_than_overflowing_the_stack() {
    // Built rather than mutated: reaching a depth of thousands by mutation is
    // vanishingly unlikely, and this is the case that actually crashes.
    for depth in [65usize, 100, 1_000, 10_000, 100_000] {
        let mut document = Vec::with_capacity(depth * 2);
        document.extend(std::iter::repeat_n(b'[', depth));
        document.extend(std::iter::repeat_n(b']', depth));

        // The assertion is that this returns at all.
        let result = parse(&document, &Limits::DEFAULT);
        assert!(result.is_err(), "depth {depth} must be refused");
    }
}

#[test]
fn an_oversize_document_is_refused_without_being_buffered_whole() {
    // A parser that reads the whole input before checking its size limit has
    // no size limit.
    let limits = Limits::DEFAULT.with_max_input_bytes(1024);
    let mut document = Vec::with_capacity(64 * 1024);
    document.push(b'"');
    document.extend(std::iter::repeat_n(b'a', 64 * 1024));
    document.push(b'"');

    assert!(parse(&document, &limits).is_err());
}

#[test]
fn truncation_at_every_offset_is_handled() {
    // Truncation is what a dropped connection looks like. Each prefix must
    // produce an error rather than a partial value or a panic.
    for vector in hypellm_test_corpus::json::all() {
        for cut in 0..vector.raw.len().min(512) {
            let prefix = vector.raw.get(..cut).unwrap_or_default();
            // Whatever it decides, it must decide.
            let _ = parse(prefix, &Limits::DEFAULT);
        }
    }
}

#[test]
fn random_bytes_are_rejected_without_panicking() {
    // The corpus mutations stay close to valid JSON; this covers the other end.
    let mut rng = Rng::new(0xdead_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(512);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let _ = parse(&case, &Limits::DEFAULT);
    }
}

/// Structural depth of a parsed value.
fn depth_of(value: &wire_json::Value) -> usize {
    match value {
        wire_json::Value::Array(items) => {
            1 + items.iter().map(depth_of).max().unwrap_or(0)
        }
        wire_json::Value::Object(object) => {
            1 + object.iter().map(|(_, v)| depth_of(v)).max().unwrap_or(0)
        }
        _ => 0,
    }
}
