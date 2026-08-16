//! JSON vectors: strict RFC 8259 acceptance and the extensions that must fail.
//!
//! Specification 3.1 requires ambiguous input to be rejected rather than
//! normalised, and specification 3.2 bounds the work a document may cause.
//! Every extension refused here — comments, trailing commas, `NaN`, leading
//! zeros, duplicate keys — is a real parser differential: a lenient router and a
//! strict upstream can be made to disagree about the same bytes, and for a
//! router that disagreement is about which model, which tool schema, or whether
//! streaming was requested.
//!
//! Rejection codes are the values `wire_json::ErrorKind::code` returns, and
//! expected outcomes assume `wire_json::Limits::DEFAULT`. Depth and size
//! boundaries are generated in [`crate::limits`] rather than committed as
//! literals, so the corpus does not carry megabyte fixtures.
//!
//! # Migration status
//!
//! `wire-json` keeps its own inline copies of the grammar cases in
//! `src/parse.rs`. They are left in place on purpose; consolidating onto this
//! corpus is follow-up work and is not claimed to be done.

use crate::outcome::Outcome;

/// What a JSON vector is exercising.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonCategory {
    /// A document that must parse.
    WellFormed,
    /// Number grammar: leading zeros, signs, exponents, range.
    Number,
    /// Syntax extensions no conforming document contains.
    SyntaxExtension,
    /// String escapes and control characters.
    String,
    /// Encoding-level framing: UTF-8 validity, byte-order marks.
    Encoding,
    /// Duplicate object keys.
    DuplicateKey,
    /// Truncated documents.
    Truncated,
}

/// One JSON document vector.
#[derive(Debug, Clone, Copy)]
pub struct JsonVector {
    /// Stable identifier.
    pub name: &'static str,
    /// The raw document bytes. Bytes rather than `str` so the corpus can carry
    /// inputs that are not valid UTF-8 — which is itself a case under test.
    pub raw: &'static [u8],
    /// What the parser must do.
    pub outcome: Outcome,
    /// What this vector is exercising.
    pub category: JsonCategory,
    /// Why the wrong answer matters.
    pub why: &'static str,
    /// The specification clause the expectation derives from.
    pub spec: &'static str,
}

/// Every JSON vector.
#[must_use]
pub const fn all() -> &'static [JsonVector] {
    VECTORS
}

/// Only the vectors in one category.
pub fn in_category(category: JsonCategory) -> impl Iterator<Item = &'static JsonVector> {
    VECTORS.iter().filter(move |v| v.category == category)
}

/// Look one vector up by name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static JsonVector> {
    VECTORS.iter().find(|v| v.name == name)
}

const UNEXPECTED_BYTE: Outcome = Outcome::Reject(&["unexpected_byte"]);
const TRAILING: Outcome = Outcome::Reject(&["trailing_content"]);
const BAD_NUMBER: Outcome = Outcome::Reject(&["invalid_number"]);
const BAD_UNICODE: Outcome = Outcome::Reject(&["invalid_unicode_escape"]);
const CONTROL_IN_STRING: Outcome = Outcome::Reject(&["control_character_in_string"]);
const DUPLICATE_KEY: Outcome = Outcome::Reject(&["duplicate_key"]);

const VECTORS: &[JsonVector] = &[
    // -- Well-formed --------------------------------------------------------
    JsonVector {
        name: "json/well_formed_chat_request",
        raw: br#"{"model":"code-premium","messages":[{"role":"user","content":"hi"}],"stream":true}"#,
        outcome: Outcome::Accept,
        category: JsonCategory::WellFormed,
        why: "The shape the router actually receives; a corpus without it can be passed by refusing everything.",
        spec: "8",
    },
    JsonVector {
        name: "json/well_formed_empty_containers",
        raw: br#"{"a":{},"b":[]}"#,
        outcome: Outcome::Accept,
        category: JsonCategory::WellFormed,
        why: "Empty containers are the boundary between the container and the trailing-comma paths.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/well_formed_max_i64",
        raw: b"9223372036854775807",
        outcome: Outcome::Accept,
        category: JsonCategory::Number,
        why: "Token counts and quota values sit near this bound; degrading them to f64 silently loses exactness.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/well_formed_surrogate_pair_escape",
        // A raw byte-string literal, so the two escapes reach the parser as the
        // six-character sequences a client would send rather than as the code
        // point they denote.
        raw: br#""\ud83d\ude00""#,
        outcome: Outcome::Accept,
        category: JsonCategory::String,
        why: "A correctly paired surrogate escape is one code point; rejecting it would break any prompt containing a non-BMP character.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/well_formed_raw_multibyte_utf8",
        raw: "\"h\u{e9}llo \u{1f600}\"".as_bytes(),
        outcome: Outcome::Accept,
        category: JsonCategory::String,
        why: "The unescaped spelling of the same text must decode to the same string as the escaped one, or the router and the upstream hold different prompts.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/well_formed_del_in_string",
        raw: b"\"a\x7fb\"",
        outcome: Outcome::Accept,
        category: JsonCategory::String,
        why: "DEL is not a C0 control and RFC 8259 permits it raw; refusing it would be stricter than the grammar and would reject conforming documents.",
        spec: "3.1",
    },
    // -- Number grammar -----------------------------------------------------
    JsonVector {
        name: "json/number_leading_zero",
        raw: b"01",
        outcome: BAD_NUMBER,
        category: JsonCategory::Number,
        why: "A leading zero is octal to some readers and decimal to others, so `010` is 8 to one hop and 10 to the next; a limit expressed that way is not the limit that is enforced.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_leading_plus",
        raw: b"+1",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::Number,
        why: "A leading plus is not in the grammar; accepting it widens the number path for no client benefit.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_bare_fraction",
        raw: b".5",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::Number,
        why: "A value with no integer part is a JavaScript literal, not a JSON one.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_trailing_dot",
        raw: b"1.",
        outcome: BAD_NUMBER,
        category: JsonCategory::Number,
        why: "The fraction must have digits; a permissive parser reads 1.0 where a strict one reads nothing.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_exponent_without_digits",
        raw: b"1e",
        outcome: BAD_NUMBER,
        category: JsonCategory::Number,
        why: "An exponent marker with no digits truncates differently in every implementation.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_hex_literal",
        raw: b"0x10",
        outcome: TRAILING,
        category: JsonCategory::Number,
        why: "`0x10` is 0 followed by garbage to a strict parser and 16 to a permissive one — a sixteen-fold difference in any limit expressed this way.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/number_infinity_literal",
        raw: b"Infinity",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::Number,
        why: "A non-finite value has no JSON spelling; admitting one puts an infinity into arithmetic that specification 6.3 requires be saturating and finite.",
        spec: "3.1, 6.3",
    },
    JsonVector {
        name: "json/number_nan_literal",
        raw: b"NaN",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::Number,
        why: "NaN compares false against everything, including itself, which silently disables any comparison-based limit check.",
        spec: "3.1, 6.3",
    },
    JsonVector {
        name: "json/number_negative_infinity_literal",
        raw: b"-Infinity",
        outcome: BAD_NUMBER,
        category: JsonCategory::Number,
        why: "Same hazard as `Infinity`, reached through the number path rather than the literal path.",
        spec: "3.1, 6.3",
    },
    JsonVector {
        name: "json/number_overflowing_exponent",
        raw: b"1e999",
        outcome: Outcome::Reject(&["number_out_of_range"]),
        category: JsonCategory::Number,
        why: "Syntactically valid and numerically infinite; the parser must refuse rather than store an infinity.",
        spec: "3.1, 6.3",
    },
    // -- Syntax extensions --------------------------------------------------
    JsonVector {
        name: "json/extension_trailing_comma_array",
        raw: b"[1,]",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "A trailing comma means one element to some parsers and two to others, so an array length check disagrees between hops.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_trailing_comma_object",
        raw: br#"{"a":1,}"#,
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "The object form of the same differential.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_single_quoted_string",
        raw: b"'a'",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "Single quotes are a JavaScript affordance; accepting them means the escape rules differ from the ones the grammar defines.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_unquoted_key",
        raw: br#"{model:"x"}"#,
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "An unquoted key has no delimiter, so where it ends depends on the implementation.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_line_comment",
        raw: b"// c\n1",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "A comment is content one hop ignores and another does not, which is exactly where a hidden field lives.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_block_comment_after_value",
        raw: b"1 /* c */",
        outcome: TRAILING,
        category: JsonCategory::SyntaxExtension,
        why: "Trailing content after the top-level value must end the parse, comment-shaped or not.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_two_documents",
        raw: b"{} {}",
        outcome: TRAILING,
        category: JsonCategory::SyntaxExtension,
        why: "Two documents in one body is the JSON analogue of request smuggling: the second is invisible to whichever hop stops at the first.",
        spec: "3.1, 10.1",
    },
    JsonVector {
        name: "json/extension_empty_input",
        raw: b"",
        outcome: Outcome::Reject(&["empty_input"]),
        category: JsonCategory::SyntaxExtension,
        why: "An empty body is not an empty object; defaulting it would let a request with no fields inherit whatever the router assumes.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_whitespace_only",
        raw: b"   \t\r\n",
        outcome: Outcome::Reject(&["empty_input"]),
        category: JsonCategory::SyntaxExtension,
        why: "Whitespace is not a value, and it is what a truncated upload leaves behind.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_form_feed_whitespace",
        raw: b"\x0c1",
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "Form feed is whitespace in several languages but not in RFC 8259; skipping it is a differential against a conforming upstream.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/extension_nbsp_whitespace",
        raw: "\u{a0}1".as_bytes(),
        outcome: UNEXPECTED_BYTE,
        category: JsonCategory::SyntaxExtension,
        why: "A non-breaking space is a Unicode space separator, not JSON whitespace.",
        spec: "3.1",
    },
    // -- Strings and escapes ------------------------------------------------
    JsonVector {
        name: "json/string_unknown_escape",
        raw: br#""\x41""#,
        outcome: Outcome::Reject(&["invalid_escape"]),
        category: JsonCategory::String,
        why: "`\\x` is not a JSON escape; a parser that decodes it produces a different string than one that does not, from identical bytes.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_short_unicode_escape",
        raw: br#""\u00""#,
        outcome: BAD_UNICODE,
        category: JsonCategory::String,
        why: "Fewer than four hex digits leaves the parser to guess how far the escape runs.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_lone_high_surrogate",
        raw: br#""\ud83d""#,
        outcome: BAD_UNICODE,
        category: JsonCategory::String,
        why: "A lone surrogate cannot be encoded as UTF-8; substituting U+FFFD would make the router and the upstream hold different strings.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_lone_low_surrogate",
        raw: br#""\ude00""#,
        outcome: BAD_UNICODE,
        category: JsonCategory::String,
        why: "The other half of the same hazard.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_high_surrogate_then_raw_char",
        raw: br#""\ud83dA""#,
        outcome: BAD_UNICODE,
        category: JsonCategory::String,
        why: "A high surrogate must be followed by a low-surrogate escape, not by ordinary text.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_raw_newline",
        raw: b"\"a\nb\"",
        outcome: CONTROL_IN_STRING,
        category: JsonCategory::String,
        why: "A raw newline inside a string ends the value for a line-oriented consumer; refusing it keeps one framing.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_raw_tab",
        raw: b"\"a\tb\"",
        outcome: CONTROL_IN_STRING,
        category: JsonCategory::String,
        why: "The grammar requires C0 controls to be escaped; accepting one raw accepts them all.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/string_raw_nul",
        raw: b"\"a\x00b\"",
        outcome: CONTROL_IN_STRING,
        category: JsonCategory::String,
        why: "A NUL truncates the value for any C-string consumer downstream.",
        spec: "3.1",
    },
    // -- Encoding -----------------------------------------------------------
    JsonVector {
        name: "json/encoding_byte_order_mark",
        raw: b"\xef\xbb\xbf{}",
        outcome: Outcome::Reject(&["byte_order_mark"]),
        category: JsonCategory::Encoding,
        why: "A BOM is skipped by some parsers and is a syntax error to others; silently skipping it means the byte offsets in an error no longer point at the input the client sent.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/encoding_invalid_utf8_in_string",
        raw: b"\"\xff\"",
        outcome: Outcome::Reject(&["invalid_utf8"]),
        category: JsonCategory::Encoding,
        why: "Lossy decoding replaces the byte and hands the upstream a different string than the client sent.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/encoding_overlong_utf8_sequence",
        raw: b"\"\xc0\xaf\"",
        outcome: Outcome::Reject(&["invalid_utf8"]),
        category: JsonCategory::Encoding,
        why: "An overlong encoding of `/` passes an ASCII-comparison filter and then decodes to a separator; UTF-8 validation is the control that stops it.",
        spec: "3.1, 10.1",
    },
    // -- Duplicate keys -----------------------------------------------------
    JsonVector {
        name: "json/duplicate_key_plain",
        raw: br#"{"a":1,"a":2}"#,
        outcome: DUPLICATE_KEY,
        category: JsonCategory::DuplicateKey,
        why: "First-wins and last-wins are both defensible readings, which is precisely why the router must not pick one.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/duplicate_key_model",
        raw: br#"{"model":"cheap-alias","model":"expensive-alias","messages":[]}"#,
        outcome: DUPLICATE_KEY,
        category: JsonCategory::DuplicateKey,
        why: "The routing-relevant case: the router authorises one model and the upstream serves the other.",
        spec: "3.1, 6.1",
    },
    JsonVector {
        name: "json/duplicate_key_stream_flag",
        raw: br#"{"model":"a","stream":true,"stream":false}"#,
        outcome: DUPLICATE_KEY,
        category: JsonCategory::DuplicateKey,
        why: "The router and the upstream disagreeing about streaming produces a response the client cannot parse, and a failover decision made on the wrong contract.",
        spec: "3.1, 6.5",
    },
    // -- Truncation ---------------------------------------------------------
    JsonVector {
        name: "json/truncated_open_array",
        raw: b"[",
        outcome: Outcome::Reject(&["unexpected_end"]),
        category: JsonCategory::Truncated,
        why: "A truncated document is an error, not a request for more bytes: the JSON parser is handed a complete body by the framing layer, so short input means the body was wrong.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/truncated_after_key",
        raw: br#"{"model""#,
        outcome: Outcome::Reject(&["unexpected_end"]),
        category: JsonCategory::Truncated,
        why: "A key with no value must not default; defaulting is how a missing field becomes a permissive one.",
        spec: "3.1",
    },
    JsonVector {
        name: "json/truncated_literal",
        raw: b"tru",
        outcome: Outcome::Reject(&["unexpected_end"]),
        category: JsonCategory::Truncated,
        why: "A prefix of `true` must not be completed by the parser.",
        spec: "3.1",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_namespaced() {
        let mut names: Vec<&str> = VECTORS.iter().map(|v| v.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        assert!(VECTORS.iter().all(|v| v.name.starts_with("json/")));
    }

    #[test]
    fn every_vector_carries_a_reason_and_a_clause() {
        for vector in VECTORS {
            assert!(!vector.why.is_empty(), "{} has no rationale", vector.name);
            assert!(!vector.spec.is_empty(), "{} cites no clause", vector.name);
        }
    }

    #[test]
    fn no_json_vector_expects_incompleteness() {
        // `wire-json` has no incomplete state: the framing layer hands it a
        // whole body. A vector claiming otherwise would be unsatisfiable.
        assert!(VECTORS.iter().all(|v| !v.outcome.is_incomplete()));
    }

    #[test]
    fn the_corpus_contains_documents_that_must_parse() {
        assert!(VECTORS.iter().filter(|v| v.outcome.is_accept()).count() >= 4);
    }

    #[test]
    fn duplicate_key_vectors_cover_router_relevant_fields() {
        let names: Vec<&str> = in_category(JsonCategory::DuplicateKey)
            .map(|v| v.name)
            .collect();
        assert!(names.contains(&"json/duplicate_key_model"));
        assert!(names.contains(&"json/duplicate_key_stream_flag"));
    }

    #[test]
    fn vectors_that_must_parse_are_valid_utf8() {
        // The parser validates UTF-8 up front, so an accepting vector that is
        // not valid UTF-8 would be unsatisfiable.
        for vector in VECTORS.iter().filter(|v| v.outcome.is_accept()) {
            assert!(
                core::str::from_utf8(vector.raw).is_ok(),
                "{} is marked accept but is not UTF-8",
                vector.name
            );
        }
    }

    #[test]
    fn lookup_by_name_finds_vectors() {
        assert_eq!(
            by_name("json/duplicate_key_stream_flag").expect("present").outcome,
            DUPLICATE_KEY
        );
        assert!(by_name("json/nope").is_none());
    }
}
