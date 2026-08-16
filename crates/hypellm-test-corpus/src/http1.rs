//! HTTP/1.1 request-head vectors, including the request-smuggling corpus.
//!
//! Specification 10.1 names request smuggling as a threat and prescribes a
//! "single strict parser; edge normalization; reject TE/CL ambiguity and
//! invalid duplicate headers". Specification 21 requires those vectors to live
//! in a shared corpus so the security suite, the fuzz seeds, and the parser's
//! own tests agree on what "correct" means.
//!
//! Every rejection code below is the value `wire_http1::HttpErrorKind::code`
//! returns. Expected outcomes assume `wire_http1::Limits::DEFAULT`; vectors that
//! depend on a *different* limit live in [`crate::limits`] instead, because a
//! vector whose outcome silently depends on the caller's configuration is not a
//! fixed expectation.
//!
//! # Migration status
//!
//! `wire-http1` still carries its own inline copies of most of these vectors in
//! `src/request.rs` and the `smuggling_tests` module of `src/lib.rs`. Those
//! copies are deliberately left in place: deleting them would remove working
//! coverage in exchange for a refactor, and specification 21.1 requires
//! two-person review for parser changes. Consolidating onto this corpus is
//! follow-up work, tracked as a gap rather than claimed as done.

use crate::outcome::Outcome;

/// What a vector is exercising, so a suite can select a subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCategory {
    /// A request that must parse, included so the corpus cannot pass by
    /// rejecting everything.
    WellFormed,
    /// Body-framing ambiguity: `Content-Length` versus `Transfer-Encoding`.
    Framing,
    /// A published request-smuggling technique.
    Smuggling,
    /// Line-terminator and folding strictness.
    LineEnding,
    /// Request-line token structure, method, and version.
    RequestLine,
    /// Request-target form and encoding.
    Target,
    /// `Host` presence and shape.
    Host,
    /// Header name/value grammar and duplication.
    Header,
    /// A prefix of a well-formed request.
    Partial,
}

/// One HTTP request-head vector.
#[derive(Debug, Clone, Copy)]
pub struct HttpVector {
    /// Stable identifier. Never reused for different bytes: a suite that
    /// records a failure by name must keep meaning the same input.
    pub name: &'static str,
    /// The raw bytes to feed to the parser.
    pub raw: &'static [u8],
    /// What the parser must do with them.
    pub outcome: Outcome,
    /// What this vector is exercising.
    pub category: HttpCategory,
    /// Why refusing (or accepting) this input matters. Not a restatement of the
    /// bytes — the reason the wrong answer is exploitable.
    pub why: &'static str,
    /// The specification clause the expectation derives from.
    pub spec: &'static str,
}

/// Every HTTP request-head vector.
#[must_use]
pub const fn all() -> &'static [HttpVector] {
    VECTORS
}

/// Only the vectors in one category.
pub fn in_category(category: HttpCategory) -> impl Iterator<Item = &'static HttpVector> {
    VECTORS.iter().filter(move |v| v.category == category)
}

/// The request-smuggling corpus: the framing and line-ending vectors together.
///
/// These are the ones specification 21.1 puts under two-person review — a
/// commit that turns one of these expectations from a rejection into an
/// acceptance disables a security control while leaving the suite green.
pub fn smuggling() -> impl Iterator<Item = &'static HttpVector> {
    VECTORS.iter().filter(|v| {
        matches!(
            v.category,
            HttpCategory::Smuggling | HttpCategory::Framing | HttpCategory::LineEnding
        )
    })
}

/// Look one vector up by name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static HttpVector> {
    VECTORS.iter().find(|v| v.name == name)
}

const CONFLICTING: Outcome = Outcome::Reject(&["conflicting_framing"]);
const DUPLICATE: Outcome = Outcome::Reject(&["duplicate_header"]);
const MALFORMED_LINE: Outcome = Outcome::Reject(&["malformed_request_line"]);
const NON_ORIGIN: Outcome = Outcome::Reject(&["non_origin_form_target"]);
const BAD_LENGTH: Outcome = Outcome::Reject(&["invalid_content_length"]);
const BAD_TARGET: Outcome = Outcome::Reject(&["invalid_request_target"]);

const VECTORS: &[HttpVector] = &[
    // -- Well-formed --------------------------------------------------------
    HttpVector {
        name: "http/well_formed_chat_post",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::WellFormed,
        why: "The corpus must contain inputs that pass, or a parser that rejects everything scores perfectly.",
        spec: "8",
    },
    HttpVector {
        name: "http/well_formed_models_get_with_query",
        raw: b"GET /v1/models?limit=10&after=x%2Fy HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::WellFormed,
        why: "The query string is split off but must not be percent-decoded; decoding before routing is how %2f becomes a path separator the router did not intend.",
        spec: "8",
    },
    HttpVector {
        name: "http/well_formed_encoded_traversal_is_not_normalised",
        raw: b"GET /v1/..%2f..%2fadmin/v1/keys HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::Target,
        why: "Accepted as an opaque path. The finding would be a parser that normalises it into /admin/v1/keys, crossing the data-plane/management-plane split of specification 3.",
        spec: "3, 10.1",
    },
    HttpVector {
        name: "http/well_formed_chunked_request",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nTransfer-Encoding: chunked\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::Framing,
        why: "A bare `chunked` is the one transfer coding the router accepts; refusing it would break every streaming client.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/well_formed_options_asterisk",
        raw: b"OPTIONS * HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::Target,
        why: "Asterisk-form is legal for a server-wide OPTIONS and only for that.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/well_formed_http_1_0_without_host",
        raw: b"GET /health/live HTTP/1.0\r\n\r\n",
        outcome: Outcome::Accept,
        category: HttpCategory::Host,
        why: "HTTP/1.0 predates the mandatory Host header; requiring it would reject conforming clients.",
        spec: "10.1",
    },
    // -- Framing ambiguity: the canonical smuggling primitive ----------------
    HttpVector {
        name: "http/smuggle_cl_te_desync",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/v1/keys HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: CONFLICTING,
        category: HttpCategory::Smuggling,
        why: "A front end honouring Content-Length and a back end honouring Transfer-Encoding disagree about where the request ends; the tail becomes the next caller's request line.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_te_cl_desync",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGET /admin/v1/keys HTTP/1.1\r\n\r\n",
        outcome: CONFLICTING,
        category: HttpCategory::Smuggling,
        why: "The same desync with the headers reversed. Header order must not change the verdict, or the ordering itself becomes the bypass.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_te_te_identity",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Smuggling,
        why: "Two Transfer-Encoding headers let one hop pick the first and another the last.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_te_te_case_variant",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Smuggling,
        why: "A case-varied duplicate is the same attack against a parser that compares names case-sensitively.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_te_space_before_colon",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n",
        outcome: Outcome::Reject(&["whitespace_before_colon"]),
        category: HttpCategory::Smuggling,
        why: "Intermediaries disagree about whether `Name : value` is a header at all; a hop that reads it sees chunked framing while a hop that ignores it sees Content-Length.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_te_hidden_by_line_folding",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 4\r\nX-Ignore: x\r\n Transfer-Encoding: chunked\r\n\r\n",
        outcome: Outcome::Reject(&["obsolete_line_folding"]),
        category: HttpCategory::Smuggling,
        why: "Obsolete folding hides a framing header inside another header's value for any hop that still unfolds.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_lf_only_request_line",
        raw: b"POST /v1/chat/completions HTTP/1.1\nHost: router.example\nContent-Length: 0\n\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::LineEnding,
        why: "A hop that accepts bare LF and one that requires CRLF see different message boundaries in the same bytes.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_lf_header_inside_crlf_head",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 0\nX-Smuggled: 1\r\n\r\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::LineEnding,
        why: "One LF among CRLFs makes the header count differ between hops; the smuggled header is invisible to the strict one.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_bare_cr_in_request_line",
        raw: b"POST /v1/chat/completions HTTP/1.1\rHost: router.example\r\n\r\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::LineEnding,
        why: "A bare CR terminates a line for some parsers and is data for others.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/smuggle_duplicate_host",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: trusted.internal\r\nHost: evil.example\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Smuggling,
        why: "Two Host values let a caller pick which one a routing or virtual-host decision sees.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_duplicate_content_length_equal",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Framing,
        why: "Rejected even when the two values agree: accepting the agreeing case is how a parser grows the code path that later accepts the disagreeing one.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_duplicate_content_length_conflicting",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Framing,
        why: "Two lengths, two message boundaries.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_content_length_leading_plus",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: +5\r\n\r\n",
        outcome: BAD_LENGTH,
        category: HttpCategory::Framing,
        why: "Some parsers accept a signed length, others reject it; the disagreement is a framing disagreement.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_content_length_hex",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 0x5\r\n\r\n",
        outcome: BAD_LENGTH,
        category: HttpCategory::Framing,
        why: "A hex-looking length reads as 0 to a decimal parser and 5 to a permissive one.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_content_length_list",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: 5, 5\r\n\r\n",
        outcome: BAD_LENGTH,
        category: HttpCategory::Framing,
        why: "A comma-joined duplicate is the duplicate-header attack after a normalising hop has merged the fields.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_content_length_non_ascii_digits",
        raw: "POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nContent-Length: \u{664}\r\n\r\n".as_bytes(),
        outcome: Outcome::Reject(&["invalid_content_length", "invalid_header_value"]),
        category: HttpCategory::Framing,
        why: "Arabic-Indic digit four. A parser using a Unicode-aware digit test reads 4 where an ASCII parser reads nothing. Either rejection code is correct; acceptance is not.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/framing_transfer_encoding_gzip_chunked",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        outcome: Outcome::Reject(&["unsupported_transfer_encoding"]),
        category: HttpCategory::Framing,
        why: "Honouring a coding list would make the router decompress attacker-controlled bytes before authentication.",
        spec: "10.1, 3.2",
    },
    HttpVector {
        name: "http/framing_transfer_encoding_on_http_1_0",
        raw: b"POST /v1/chat/completions HTTP/1.0\r\nHost: router.example\r\nTransfer-Encoding: chunked\r\n\r\n",
        outcome: Outcome::Reject(&["unsupported_transfer_encoding"]),
        category: HttpCategory::Framing,
        why: "Chunked coding did not exist in HTTP/1.0, so a 1.0 hop reads the chunk sizes as body content.",
        spec: "10.1",
    },
    // -- Request line -------------------------------------------------------
    HttpVector {
        name: "http/request_line_double_space",
        raw: b"GET  /v1/models HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::RequestLine,
        why: "Collapsing runs of spaces makes the target ambiguous between hops.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/request_line_trailing_space",
        raw: b"GET /v1/models HTTP/1.1 \r\nHost: router.example\r\n\r\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::RequestLine,
        why: "A trailing space is a fourth, empty token; trimming it is the same leniency as collapsing an inner one.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/request_line_two_tokens",
        raw: b"GET /v1/models\r\nHost: router.example\r\n\r\n",
        outcome: MALFORMED_LINE,
        category: HttpCategory::RequestLine,
        why: "A version-less request line is HTTP/0.9, which has no headers and therefore no way to authenticate.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/request_line_control_in_method",
        raw: b"G\x01T /v1/models HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: Outcome::Reject(&["invalid_method"]),
        category: HttpCategory::RequestLine,
        why: "A control byte in the method is outside the token grammar and is how a method is smuggled past a name-based filter.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/request_line_http_2_version",
        raw: b"GET /v1/models HTTP/2.0\r\nHost: router.example\r\n\r\n",
        outcome: Outcome::Reject(&["unsupported_http_version"]),
        category: HttpCategory::RequestLine,
        why: "Specification 25 leaves HTTP/2 support an open decision; claiming a version the parser does not implement is worse than refusing it.",
        spec: "25",
    },
    // -- Target -------------------------------------------------------------
    HttpVector {
        name: "http/target_absolute_form_metadata_service",
        raw: b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: NON_ORIGIN,
        category: HttpCategory::Target,
        why: "Specification 10 forbids any client-controlled value selecting a destination. Absolute-form is that value, aimed at the cloud metadata service.",
        spec: "10, 2.2",
    },
    HttpVector {
        name: "http/target_absolute_form_http_scheme",
        raw: b"GET http://evil.example/v1/chat/completions HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: NON_ORIGIN,
        category: HttpCategory::Target,
        why: "General-purpose proxying is an explicit non-goal (specification 2.2); accepting absolute-form is the first half of becoming one.",
        spec: "2.2, 10",
    },
    HttpVector {
        name: "http/target_connect_authority_form",
        raw: b"CONNECT evil.example:443 HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: NON_ORIGIN,
        category: HttpCategory::Target,
        why: "CONNECT would turn the router into a tunnel to an address the caller chose.",
        spec: "2.2, 10",
    },
    HttpVector {
        name: "http/target_protocol_relative",
        raw: b"GET //evil.example/v1/models HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: NON_ORIGIN,
        category: HttpCategory::Target,
        why: "A leading `//` is an authority to some intermediaries and a path to others.",
        spec: "10",
    },
    HttpVector {
        name: "http/target_asterisk_on_get",
        raw: b"GET * HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: BAD_TARGET,
        category: HttpCategory::Target,
        why: "Asterisk-form is meaningful only for a server-wide OPTIONS; elsewhere it is a target no route can match.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/target_del_byte",
        raw: b"GET /v1/mod\x7fels HTTP/1.1\r\nHost: router.example\r\n\r\n",
        outcome: BAD_TARGET,
        category: HttpCategory::Target,
        why: "DEL is invisible in a log line, so a target carrying it can be made to look like one that was routed.",
        spec: "10.1, 17",
    },
    HttpVector {
        name: "http/target_raw_non_ascii",
        raw: "GET /v1/caf\u{e9} HTTP/1.1\r\nHost: router.example\r\n\r\n".as_bytes(),
        outcome: BAD_TARGET,
        category: HttpCategory::Target,
        why: "Raw non-ASCII must be percent-encoded by the client; accepting it means two hops may transcode it differently.",
        spec: "10.1",
    },
    // -- Host ---------------------------------------------------------------
    HttpVector {
        name: "http/host_missing_on_http_1_1",
        raw: b"GET /v1/models HTTP/1.1\r\n\r\n",
        outcome: Outcome::Reject(&["missing_host"]),
        category: HttpCategory::Host,
        why: "HTTP/1.1 requires it; a request without one cannot be attributed to a virtual host.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/host_with_userinfo",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: user@evil.example\r\n\r\n",
        outcome: Outcome::Reject(&["invalid_host"]),
        category: HttpCategory::Host,
        why: "Userinfo in an authority is how a URL built from the Host header is made to point somewhere else.",
        spec: "10",
    },
    HttpVector {
        name: "http/host_with_path",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: router.example/evil\r\n\r\n",
        outcome: Outcome::Reject(&["invalid_host"]),
        category: HttpCategory::Host,
        why: "A path smuggled into the authority survives naive URL concatenation.",
        spec: "10",
    },
    // -- Headers ------------------------------------------------------------
    HttpVector {
        name: "http/header_nul_in_value",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\nX-Trace: a\x00b\r\n\r\n",
        outcome: Outcome::Reject(&["nul_in_head"]),
        category: HttpCategory::Header,
        why: "A NUL truncates the value for any C-string consumer downstream, so the two ends disagree about what was sent.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/header_empty_name",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\n: value\r\n\r\n",
        outcome: Outcome::Reject(&["invalid_header_name"]),
        category: HttpCategory::Header,
        why: "An empty name is not a token; parsers differ on whether the line is a header or garbage to skip.",
        spec: "10.1",
    },
    HttpVector {
        name: "http/header_duplicate_authorization",
        raw: b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\nAuthorization: Bearer aaa\r\nAuthorization: Bearer bbb\r\n\r\n",
        outcome: DUPLICATE,
        category: HttpCategory::Header,
        why: "Two credentials let the authenticating hop and the auditing hop disagree about who the caller is.",
        spec: "9.2, 10.1",
    },
    // -- Partial ------------------------------------------------------------
    HttpVector {
        name: "http/partial_head_without_terminator",
        raw: b"POST /v1/chat/completions HTTP/1.1\r\nHost: router.example\r\n",
        outcome: Outcome::Incomplete,
        category: HttpCategory::Partial,
        why: "A prefix must be reported as needing more bytes, not as a parse failure; treating a slow client as malformed is a self-inflicted denial of service.",
        spec: "3.2",
    },
    HttpVector {
        name: "http/partial_trailing_cr",
        raw: b"GET /v1/models HTTP/1.1\r",
        outcome: Outcome::Incomplete,
        category: HttpCategory::Partial,
        why: "A CR at the buffer edge may be the first half of a CRLF that has not arrived; rejecting it makes delivery timing change the verdict.",
        spec: "3.2",
    },
    HttpVector {
        name: "http/partial_empty_buffer",
        raw: b"",
        outcome: Outcome::Incomplete,
        category: HttpCategory::Partial,
        why: "Zero bytes is the state every connection starts in.",
        spec: "3.2",
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
        assert_eq!(names.len(), before, "vector names must be unique");
        assert!(VECTORS.iter().all(|v| v.name.starts_with("http/")));
    }

    #[test]
    fn every_vector_carries_a_reason_and_a_clause() {
        for vector in VECTORS {
            assert!(!vector.why.is_empty(), "{} has no rationale", vector.name);
            assert!(!vector.spec.is_empty(), "{} cites no clause", vector.name);
            assert!(!vector.raw.is_empty() || vector.outcome.is_incomplete());
        }
    }

    #[test]
    fn rejection_codes_are_non_empty_and_lowercase() {
        for vector in VECTORS {
            if let Outcome::Reject(codes) = vector.outcome {
                assert!(!codes.is_empty(), "{} lists no code", vector.name);
                for code in codes {
                    assert!(
                        code.bytes()
                            .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                        "{} lists a non-contract code {code:?}",
                        vector.name
                    );
                }
            }
        }
    }

    #[test]
    fn the_corpus_contains_inputs_that_must_be_accepted() {
        // A corpus of nothing but rejections is passed by a parser that refuses
        // every request, which is not the property under test.
        assert!(VECTORS.iter().filter(|v| v.outcome.is_accept()).count() >= 5);
        assert!(VECTORS.iter().any(|v| v.outcome.is_incomplete()));
    }

    #[test]
    fn the_smuggling_selection_covers_the_named_techniques() {
        let names: Vec<&str> = smuggling().map(|v| v.name).collect();
        for required in [
            "http/smuggle_cl_te_desync",
            "http/smuggle_te_cl_desync",
            "http/smuggle_te_te_identity",
            "http/smuggle_te_space_before_colon",
            "http/smuggle_te_hidden_by_line_folding",
            "http/smuggle_lf_only_request_line",
        ] {
            assert!(names.contains(&required), "{required} is not selected");
        }
        // Every selected vector must be a rejection: a smuggling corpus with an
        // accepting entry is a contradiction.
        assert!(smuggling().all(|v| v.outcome.is_reject() || v.outcome.is_accept()));
        assert!(
            smuggling()
                .filter(|v| v.category == HttpCategory::Smuggling)
                .all(|v| v.outcome.is_reject())
        );
    }

    #[test]
    fn lookup_by_name_finds_vectors() {
        let vector = by_name("http/smuggle_cl_te_desync").expect("present");
        assert_eq!(vector.outcome, CONFLICTING);
        assert!(by_name("http/does_not_exist").is_none());
    }

    #[test]
    fn category_selection_is_a_partition() {
        let categories = [
            HttpCategory::WellFormed,
            HttpCategory::Framing,
            HttpCategory::Smuggling,
            HttpCategory::LineEnding,
            HttpCategory::RequestLine,
            HttpCategory::Target,
            HttpCategory::Host,
            HttpCategory::Header,
            HttpCategory::Partial,
        ];
        let counted: usize = categories.iter().map(|c| in_category(*c).count()).sum();
        assert_eq!(counted, all().len(), "every vector has exactly one category");
    }

    #[test]
    fn heads_that_must_parse_are_terminated() {
        // A vector marked `Accept` whose head is not terminated would report
        // Incomplete instead, and the expectation would be unreachable.
        for vector in VECTORS.iter().filter(|v| v.outcome.is_accept()) {
            assert!(
                vector.raw.windows(4).any(|w| w == b"\r\n\r\n"),
                "{} is marked accept but has no head terminator",
                vector.name
            );
        }
    }
}
