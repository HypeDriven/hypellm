//! What a parser under test must do with a vector.
//!
//! Specification 21 requires a fuzz and security test layer whose corpora are
//! shared rather than re-derived per crate. A corpus of raw byte strings with no
//! recorded expectation is not a test oracle: it can only find panics, never a
//! parser that accepts something it must refuse. Every vector in this crate
//! therefore carries an [`Outcome`].
//!
//! Expectations are expressed as the *stable error code strings* the parser
//! crates already publish (`wire_http1::HttpErrorKind::code`,
//! `wire_json::ErrorKind::code`, `wire_sse::SseError::code`) rather than as
//! their enum values. Two reasons, in order of importance:
//!
//! 1. Specification 8.2 makes those codes part of the client contract. Pinning
//!    the code, not the variant, means a rename that changes what a client sees
//!    fails the corpus — which is the failure worth catching.
//! 2. It keeps this crate free of dependencies, so any crate may take it as a
//!    dev-dependency without a cycle.

/// The required result of feeding one vector to the parser under test.
///
/// [`Outcome::Reject`] carries a list rather than a single code because a few
/// inputs are legitimately refused at more than one point in a strict parser —
/// a `Content-Length` of `٥` is both an unusable field value and an unusable
/// length, and either rejection is correct. The list is the set of *acceptable*
/// codes; anything outside it is a finding. A list is never empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The parser must accept the input and produce a value.
    Accept,
    /// The parser must report that it needs more bytes, without either
    /// accepting or failing.
    ///
    /// For `wire-http1` this is `ParseStatus::Incomplete`. For `wire-sse` it
    /// means the bytes are consumed without error and no event is dispatched,
    /// because a partial line remains buffered. `wire-json` has no such state:
    /// a truncated document is an error there, so no JSON vector uses this.
    Incomplete,
    /// The parser must reject the input, reporting one of these stable codes.
    Reject(&'static [&'static str]),
}

impl Outcome {
    /// True when the input must be accepted.
    #[must_use]
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }

    /// True when the parser must ask for more bytes.
    #[must_use]
    pub const fn is_incomplete(self) -> bool {
        matches!(self, Self::Incomplete)
    }

    /// True when the input must be rejected.
    #[must_use]
    pub const fn is_reject(self) -> bool {
        matches!(self, Self::Reject(_))
    }

    /// The acceptable rejection codes; empty for the non-rejecting outcomes.
    #[must_use]
    pub const fn codes(self) -> &'static [&'static str] {
        match self {
            Self::Accept | Self::Incomplete => &[],
            Self::Reject(codes) => codes,
        }
    }

    /// Whether `code` is an acceptable rejection code for this outcome.
    ///
    /// Always false for [`Outcome::Accept`] and [`Outcome::Incomplete`], so a
    /// consumer that reports a rejection where none was expected fails without
    /// needing a separate branch.
    #[must_use]
    pub fn permits_code(self, code: &str) -> bool {
        self.codes().contains(&code)
    }

    /// A short human-readable form, for assertion messages.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Accept => "accept".to_owned(),
            Self::Incomplete => "incomplete".to_owned(),
            Self::Reject(codes) => format!("reject with one of {codes:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_permits_no_code() {
        assert!(Outcome::Accept.is_accept());
        assert!(Outcome::Accept.codes().is_empty());
        assert!(!Outcome::Accept.permits_code("conflicting_framing"));
        assert!(!Outcome::Incomplete.permits_code("conflicting_framing"));
    }

    #[test]
    fn reject_matches_only_listed_codes() {
        let outcome = Outcome::Reject(&["invalid_content_length", "invalid_header_value"]);
        assert!(outcome.is_reject());
        assert!(outcome.permits_code("invalid_content_length"));
        assert!(outcome.permits_code("invalid_header_value"));
        assert!(!outcome.permits_code("conflicting_framing"));
        // A near-miss must not pass: the code is a contract string, not a hint.
        assert!(!outcome.permits_code("invalid_content_length "));
        assert!(!outcome.permits_code("INVALID_CONTENT_LENGTH"));
    }

    #[test]
    fn descriptions_name_the_expectation() {
        assert_eq!(Outcome::Accept.describe(), "accept");
        assert!(
            Outcome::Reject(&["nul_in_head"])
                .describe()
                .contains("nul_in_head")
        );
    }
}
