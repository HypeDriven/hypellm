//! Shared test corpora, golden provider fixtures, and harness profiles.
//!
//! Specification 18.1 lists this crate as the home of "golden
//! requests/responses, malformed input, provider stream fixtures".
//! Specification 21 requires integration tests to run "against recorded golden
//! servers" with "versioned harness-compatibility profiles". This crate holds
//! the data those tests compare against; it holds no assertions of its own.
//!
//! # What is here
//!
//! | Module | Contents | Specification |
//! |---|---|---|
//! | [`http1`] | Request-head vectors, including the request-smuggling corpus | 10.1, 21 |
//! | [`json`] | Strict RFC 8259 acceptance and the extensions that must fail | 3.1, 21 |
//! | [`sse`] | Event framing, field semantics, and provider stream shapes | 14, 21 |
//! | [`limits`] | Boundary inputs generated at the documented bounds | 3.2 |
//! | [`golden`] | Recorded provider responses, streams, and error shapes | 7, 21 |
//! | [`harness`] | Versioned coding-harness compatibility profiles | 8.1 |
//! | [`outcome`] | The expectation type every vector carries | 21 |
//!
//! # Three rules this crate follows
//!
//! **Every vector says what must happen.** A corpus of raw byte strings with no
//! recorded expectation can only find panics, never a parser that accepts
//! something it must refuse. Expectations are spelled as the stable error code
//! strings the parser crates publish, which pins the client-visible contract of
//! specification 8.2 at the same time.
//!
//! **It supplies inputs and expectations; it does not assert.** The comparison
//! lives in the crate under test. A corpus that owned the assertion could
//! silently redefine "correct" for every consumer at once.
//!
//! **It does no I/O and takes no dependencies.** No sockets, no host
//! resolution, no file reads, no `[dependencies]` and no `[dev-dependencies]`.
//! Being dependency-free is not decoration: it is what lets every crate in the
//! workspace take this one as a dev-dependency without a cycle, `wire-json` and
//! `wire-http1` included.
//!
//! # Honest gaps
//!
//! These are stated here as well as in `MODULE.md` because a reader who trusts
//! this corpus needs them before they trust a passing suite:
//!
//! - **Nothing was recorded from a live provider.** Every golden fixture is
//!   synthetic, hand-written against the shapes `hypellm-adapters` decodes. There
//!   are no real credentials, identifiers, prompts, or completions in this
//!   crate — and correspondingly, no evidence that a provider's current wire
//!   format still matches. See [`golden`].
//! - **No coding harness has been run against the router.** The profiles in
//!   [`harness`] are the specification 8.1 classes written out as data, not
//!   measurements of any named tool.
//! - **No fuzz target exists anywhere in the repository.** This crate is their
//!   declared corpus home; the seven targets specification 21 requires are
//!   listed in `MODULE.md` and none is implemented.
//! - **The parser crates still carry their own inline copies** of most of these
//!   vectors. They are deliberately left in place — deleting working coverage
//!   in exchange for a refactor is not an improvement — so migrating those
//!   suites onto this corpus is follow-up work that has not been done.
//! - **The limits in [`limits`] are restated, not linked.** This crate cannot
//!   read `wire_http1::Limits::DEFAULT` without depending on it, so a bound
//!   changed in the parser and not here produces a boundary case that no longer
//!   sits on the boundary.

#![forbid(unsafe_code)]
// Specification 18.2: all integer conversions are checked. The corpus feeds the
// data-plane parsers, so its own width conversions are held to the same rule as
// the code under test: `try_from` with an explicit fallback, never `as`.
#![cfg_attr(not(test), deny(clippy::as_conversions))]

pub mod fuzz;
pub mod golden;
pub mod harness;
pub mod http1;
pub mod json;
pub mod limits;
pub mod outcome;
pub mod sse;

pub use outcome::Outcome;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name the corpus exposes, across all four vector kinds.
    fn all_names() -> Vec<&'static str> {
        let mut names: Vec<&'static str> = http1::all().iter().map(|v| v.name).collect();
        names.extend(json::all().iter().map(|v| v.name));
        names.extend(sse::all().iter().map(|v| v.name));
        names.extend(golden::responses().iter().map(|v| v.name));
        names.extend(golden::streams().iter().map(|v| v.name));
        names.extend(golden::embeddings().iter().map(|v| v.name));
        names.extend(golden::failures().iter().map(|v| v.name));
        names
    }

    #[test]
    fn names_are_unique_across_the_whole_corpus() {
        // A suite records a failure by name. Two vectors sharing one makes a
        // recorded failure ambiguous, and makes a "known failure" allowlist
        // silently cover both.
        let mut names = all_names();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "corpus names must be globally unique");
    }

    #[test]
    fn names_are_prefixed_by_their_corpus() {
        for name in http1::all().iter().map(|v| v.name) {
            assert!(name.starts_with("http/"), "{name}");
        }
        for name in json::all().iter().map(|v| v.name) {
            assert!(name.starts_with("json/"), "{name}");
        }
        for name in sse::all().iter().map(|v| v.name) {
            assert!(name.starts_with("sse/"), "{name}");
        }
        for case in limits::all() {
            assert!(case.name.starts_with("limits/"), "{}", case.name);
        }
    }

    #[test]
    fn the_corpus_is_not_empty_anywhere() {
        // A module that silently emptied would make its consumer's loop pass
        // over nothing while still reporting success.
        assert!(!http1::all().is_empty());
        assert!(!json::all().is_empty());
        assert!(!sse::all().is_empty());
        assert!(!limits::all().is_empty());
        assert!(!golden::responses().is_empty());
        assert!(!golden::streams().is_empty());
        assert!(!golden::embeddings().is_empty());
        assert!(!golden::failures().is_empty());
        assert!(!harness::all().is_empty());
    }

    #[test]
    fn no_vector_is_both_accepted_and_rejected_under_one_name() {
        // Cheap invariant, but the one that catches a copy-paste that changed
        // the bytes and not the expectation.
        for vector in http1::all() {
            let same: Vec<&http1::HttpVector> = http1::all()
                .iter()
                .filter(|v| v.raw == vector.raw)
                .collect();
            for other in same {
                assert_eq!(
                    other.outcome, vector.outcome,
                    "{} and {} share bytes but not an expectation",
                    vector.name, other.name
                );
            }
        }
    }

    #[test]
    fn the_corpus_covers_every_family_the_router_supports() {
        // Specification 7 names five provider families across two wire formats.
        // The corpus is organised by wire format, so both must be present.
        let families: Vec<golden::GoldenFamily> =
            golden::responses().iter().map(|r| r.family).collect();
        assert!(families.contains(&golden::GoldenFamily::OpenAiCompatible));
        assert!(families.contains(&golden::GoldenFamily::Anthropic));
    }

    #[test]
    fn provider_family_tokens_match_the_configuration_spelling() {
        // These are the tokens `hypellm_core::target::ProviderFamily::as_str`
        // produces. They are restated rather than imported, so this test is the
        // only thing holding them together.
        assert_eq!(
            golden::GoldenFamily::OpenAiCompatible.provider_family_token(),
            "openai"
        );
        assert_eq!(
            golden::GoldenFamily::Anthropic.provider_family_token(),
            "anthropic"
        );
    }
}
