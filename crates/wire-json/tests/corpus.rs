//! The shared JSON corpus, run against this parser.
//!
//! Specification 21 requires the corpora to be shared rather than re-derived
//! per crate; `hypellm-test-corpus` holds the vectors and their expected
//! outcomes, and this file is the comparison. The inline grammar tests in
//! `src/parse.rs` are unaffected and stay where they are.

use hypellm_test_corpus::json::{self, JsonCategory};
use hypellm_test_corpus::limits as boundary;
use hypellm_test_corpus::outcome::Outcome;
use wire_json::{Limits, parse};

/// Check one document against one expectation, naming the vector on failure.
fn check(name: &str, why: &str, raw: &[u8], outcome: Outcome) {
    match (parse(raw, &Limits::DEFAULT), outcome) {
        (Ok(_), Outcome::Accept) => {}
        (Err(error), Outcome::Reject(_)) => {
            assert!(
                outcome.permits_code(error.kind.code()),
                "{name}: rejected with {:?}, but the corpus requires {}\n  why: {why}",
                error.kind.code(),
                outcome.describe()
            );
            // Specification 10 makes request bodies sensitive by default, so an
            // error may carry a category and an offset and nothing else. A
            // corpus run is where a message that started echoing input shows up
            // across every vector at once rather than one test at a time.
            let rendered = error.to_string();
            assert!(
                !rendered.contains("prompt") && !rendered.contains('"'),
                "{name}: the error message looks like it echoes the document: {rendered:?}"
            );
        }
        (observed, expected) => {
            let described = match observed {
                Ok(_) => "accepted".to_owned(),
                Err(error) => format!("rejected with {:?}", error.kind.code()),
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
    assert!(!json::all().is_empty(), "the corpus is empty");
    for vector in json::all() {
        check(vector.name, vector.why, vector.raw, vector.outcome);
    }
}

#[test]
fn every_duplicate_key_vector_is_refused_by_default() {
    // Separated from the sweep so that a corpus reorganisation dropping these
    // from the general list still fails here. Duplicate keys are the router's
    // sharpest JSON differential: first-wins and last-wins are both defensible,
    // which is exactly why the router must not choose.
    let mut checked = 0usize;
    for vector in json::in_category(JsonCategory::DuplicateKey) {
        check(vector.name, vector.why, vector.raw, vector.outcome);
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} duplicate-key vectors were run");
}

#[test]
fn boundary_cases_land_exactly_on_the_documented_depth_limit() {
    assert_eq!(
        u32::try_from(boundary::JSON_DEFAULT_MAX_DEPTH).expect("the bound fits in u32"),
        Limits::DEFAULT.max_depth,
        "the corpus was written against a different depth bound than this parser enforces"
    );
    for case in boundary::json_depth_cases() {
        check(case.name, case.why, &case.input, case.outcome);
    }
}

#[test]
fn the_escaped_and_raw_spellings_of_one_string_decode_alike() {
    // Two vectors, one text. If they decoded differently the router and an
    // upstream would hold different prompts from the same client input, and
    // nothing downstream would notice.
    let escaped = json::by_name("json/well_formed_surrogate_pair_escape").expect("present");
    let raw = json::by_name("json/well_formed_raw_multibyte_utf8").expect("present");

    let escaped = parse(escaped.raw, &Limits::DEFAULT).expect("accepted");
    let raw = parse(raw.raw, &Limits::DEFAULT).expect("accepted");

    let escaped = escaped.as_str().expect("a string");
    let raw = raw.as_str().expect("a string");
    assert!(
        raw.ends_with(escaped),
        "the escaped spelling {escaped:?} is not the tail of the raw one {raw:?}"
    );
}
