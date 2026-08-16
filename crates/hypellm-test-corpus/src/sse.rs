//! Server-Sent Events vectors: framing, field semantics, and bounds.
//!
//! Specification 14 requires SSE parsing to handle "CRLF/LF, multiple data
//! lines, comments, bounded event size, and terminal markers", and requires that
//! "JSON fragments are assembled only within declared provider event
//! boundaries; incomplete or excessive events fail safely".
//!
//! The framing cases matter more here than they look. An SSE parser that
//! dispatches one event early hands an adapter half a JSON object, and the
//! adapter reports a protocol violation for a stream the provider sent
//! correctly — which specification 6.5 then turns into a failover decision made
//! on a fault the router invented.
//!
//! Rejection codes are the values `wire_sse::SseError::code` returns, and
//! expected outcomes assume `wire_sse::SseLimits::DEFAULT`. Buffer-boundary
//! vectors are generated in [`crate::limits`] rather than committed, because a
//! 256 KiB fixture in version control is a permanent cost for one assertion.
//!
//! # Migration status
//!
//! `wire-sse` keeps its own inline copies in `src/parse.rs`. They stay; moving
//! the suite onto this corpus is follow-up work.

use crate::outcome::Outcome;

/// One event the parser must dispatch, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedEvent {
    /// The `event:` field, or `None` when the stream did not name one.
    pub event: Option<&'static str>,
    /// The accumulated `data:` payload, with continuation lines joined by `\n`.
    pub data: &'static str,
    /// The `id:` field, when one was accepted.
    pub id: Option<&'static str>,
    /// The `retry:` field, when one parsed as an unsigned integer.
    pub retry: Option<u64>,
}

impl ExpectedEvent {
    /// An unnamed event carrying only data, which is the common case.
    #[must_use]
    pub const fn data(data: &'static str) -> Self {
        Self {
            event: None,
            data,
            id: None,
            retry: None,
        }
    }

    /// A named event carrying data, which is the Anthropic stream shape.
    #[must_use]
    pub const fn named(event: &'static str, data: &'static str) -> Self {
        Self {
            event: Some(event),
            data,
            id: None,
            retry: None,
        }
    }
}

/// What an SSE vector is exercising.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseCategory {
    /// Line terminators and event boundaries.
    Framing,
    /// Field parsing: names, the optional leading space, unknown fields.
    Fields,
    /// A recorded provider stream shape.
    ProviderShape,
    /// A bound the parser must enforce.
    Bounds,
}

/// One SSE stream vector.
#[derive(Debug, Clone, Copy)]
pub struct SseVector {
    /// Stable identifier.
    pub name: &'static str,
    /// The raw stream bytes.
    pub raw: &'static [u8],
    /// What the parser must do with them.
    ///
    /// [`Outcome::Accept`] means the bytes are consumed without error and
    /// exactly [`SseVector::expected`] is dispatched. [`Outcome::Incomplete`]
    /// means they are consumed without error and *nothing* is dispatched,
    /// because a partial line remains buffered.
    pub outcome: Outcome,
    /// The events that must be dispatched, in order. Empty unless the outcome
    /// is [`Outcome::Accept`].
    pub expected: &'static [ExpectedEvent],
    /// What this vector is exercising.
    pub category: SseCategory,
    /// Why the wrong answer matters.
    pub why: &'static str,
    /// The specification clause the expectation derives from.
    pub spec: &'static str,
}

/// Every SSE vector.
#[must_use]
pub const fn all() -> &'static [SseVector] {
    VECTORS
}

/// Only the vectors in one category.
pub fn in_category(category: SseCategory) -> impl Iterator<Item = &'static SseVector> {
    VECTORS.iter().filter(move |v| v.category == category)
}

/// Look one vector up by name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static SseVector> {
    VECTORS.iter().find(|v| v.name == name)
}

const VECTORS: &[SseVector] = &[
    // -- Framing ------------------------------------------------------------
    SseVector {
        name: "sse/framing_single_event_lf",
        raw: b"data: hello\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("hello")],
        category: SseCategory::Framing,
        why: "The minimal stream. A corpus without it can be passed by a parser that dispatches nothing.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_single_event_crlf",
        raw: b"data: hello\r\n\r\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("hello")],
        category: SseCategory::Framing,
        why: "CRLF must produce the identical event; a parser that treats CR as data appends a stray character to every payload.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_single_event_bare_cr",
        raw: b"data: hello\r\r",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("hello")],
        category: SseCategory::Framing,
        why: "Bare CR is a legal terminator in the EventSource grammar; refusing it would drop a conforming provider's stream mid-response.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_mixed_terminators",
        raw: b"data: a\r\n\r\ndata: b\n\ndata: c\r\r",
        outcome: Outcome::Accept,
        expected: &[
            ExpectedEvent::data("a"),
            ExpectedEvent::data("b"),
            ExpectedEvent::data("c"),
        ],
        category: SseCategory::Framing,
        why: "One stream may mix terminators; the event count must not depend on which one a frame happened to use.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_multiple_data_lines_join",
        raw: b"data: line one\ndata: line two\ndata: line three\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("line one\nline two\nline three")],
        category: SseCategory::Framing,
        why: "Continuation lines join with a newline and dispatch once; splitting them hands the adapter three JSON fragments instead of one document.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_empty_data_line_is_a_blank_line",
        raw: b"data: a\ndata:\ndata: b\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("a\n\nb")],
        category: SseCategory::Framing,
        why: "An empty `data:` field contributes an empty line, not a dispatch; treating it as a dispatch cuts the event in half.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_blank_line_resets_event_name",
        raw: b"event: a\ndata: 1\n\ndata: 2\n\n",
        outcome: Outcome::Accept,
        expected: &[
            ExpectedEvent::named("a", "1"),
            ExpectedEvent::data("2"),
        ],
        category: SseCategory::Framing,
        why: "A name carried into the next event would make an adapter decode a `message_delta` payload as a `message_start`.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_event_without_data_is_not_dispatched",
        raw: b"event: ping\nid: 7\n\ndata: real\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("real")],
        category: SseCategory::Framing,
        why: "A data-less event must be discarded whole, fields included; dispatching it hands the adapter an empty string to parse as JSON, and leaking its `event`/`id` forward mislabels the next one.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_incomplete_trailing_line",
        raw: b"data: partial",
        outcome: Outcome::Incomplete,
        expected: &[],
        category: SseCategory::Framing,
        why: "An unterminated line must not dispatch. Dispatching it hands the adapter a truncated JSON fragment that looks like a provider protocol violation.",
        spec: "14",
    },
    SseVector {
        name: "sse/framing_comment_only_stream",
        raw: b": keepalive\n\n: keepalive\n\n",
        outcome: Outcome::Accept,
        expected: &[],
        category: SseCategory::Framing,
        why: "Keepalive comments carry no data and must not dispatch an empty event; a stream of them is silence, not a sequence of malformed frames.",
        spec: "14",
    },
    // -- Fields -------------------------------------------------------------
    SseVector {
        name: "sse/fields_one_leading_space_stripped",
        raw: b"data:  two spaces\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data(" two spaces")],
        category: SseCategory::Fields,
        why: "Exactly one space after the colon is removed. Stripping all of them silently edits payload text, which for a code assistant is the difference between valid and invalid indentation.",
        spec: "14",
    },
    SseVector {
        name: "sse/fields_no_space_after_colon",
        raw: b"data:no space\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("no space")],
        category: SseCategory::Fields,
        why: "The space is optional; requiring it would drop the first character of every payload from a provider that omits it.",
        spec: "14",
    },
    SseVector {
        name: "sse/fields_named_with_id_and_retry",
        raw: b"event: message_start\nid: 42\nretry: 3000\ndata: {}\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent {
            event: Some("message_start"),
            data: "{}",
            id: Some("42"),
            retry: Some(3000),
        }],
        category: SseCategory::Fields,
        why: "All four fields on one event, which is the Anthropic frame shape.",
        spec: "14, 7",
    },
    SseVector {
        name: "sse/fields_unknown_fields_ignored",
        raw: b"unknown: x\nnocolon\ndata: y\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("y")],
        category: SseCategory::Fields,
        why: "Unknown fields and colon-less lines are ignored rather than fatal, so a provider adding a field does not break the stream.",
        spec: "14",
    },
    SseVector {
        name: "sse/fields_id_containing_nul_is_ignored",
        raw: b"id: a\x00b\ndata: x\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("x")],
        category: SseCategory::Fields,
        why: "The EventSource grammar requires ignoring an id containing NUL rather than truncating at it; truncating would make two distinct ids compare equal.",
        spec: "14",
    },
    SseVector {
        name: "sse/fields_negative_retry_ignored",
        raw: b"retry: -5\ndata: x\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("x")],
        category: SseCategory::Fields,
        why: "A negative reconnection delay is not representable and must be dropped, not wrapped into an enormous unsigned value.",
        spec: "14",
    },
    SseVector {
        name: "sse/fields_non_numeric_retry_ignored",
        raw: b"retry: soon\ndata: x\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("x")],
        category: SseCategory::Fields,
        why: "An unparseable retry is ignored; the event around it is still valid and must still be delivered.",
        spec: "14",
    },
    // -- Provider shapes ----------------------------------------------------
    SseVector {
        name: "sse/provider_openai_done_marker",
        raw: b"data: [DONE]\n\n",
        outcome: Outcome::Accept,
        expected: &[ExpectedEvent::data("[DONE]")],
        category: SseCategory::ProviderShape,
        why: "The terminal marker is an ordinary event to the SSE layer; recognising it is the adapter's job, and a parser that swallows it hides the end of stream from the adapter.",
        spec: "14, 7",
    },
    SseVector {
        name: "sse/provider_openai_chunk_sequence",
        raw: b"data: {\"choices\":[{\"delta\":{\"content\":\"Back\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"pressure.\"}}]}\n\ndata: [DONE]\n\n",
        outcome: Outcome::Accept,
        expected: &[
            ExpectedEvent::data("{\"choices\":[{\"delta\":{\"content\":\"Back\"}}]}"),
            ExpectedEvent::data("{\"choices\":[{\"delta\":{\"content\":\"pressure.\"}}]}"),
            ExpectedEvent::data("[DONE]"),
        ],
        category: SseCategory::ProviderShape,
        why: "JSON payloads contain colons and braces; the field split must happen at the first colon of the line and nowhere else.",
        spec: "14, 7",
    },
    SseVector {
        name: "sse/provider_anthropic_named_sequence",
        raw: b"event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        outcome: Outcome::Accept,
        expected: &[
            ExpectedEvent::named("message_start", "{\"type\":\"message_start\"}"),
            ExpectedEvent::named("ping", "{\"type\":\"ping\"}"),
            ExpectedEvent::named(
                "content_block_delta",
                "{\"type\":\"content_block_delta\",\"index\":0}",
            ),
            ExpectedEvent::named("message_stop", "{\"type\":\"message_stop\"}"),
        ],
        category: SseCategory::ProviderShape,
        why: "The Anthropic profile names every event, and the adapter treats the name as authoritative; losing it makes every frame fall back to the payload's own `type`.",
        spec: "14, 7",
    },
    // -- Bounds -------------------------------------------------------------
    SseVector {
        name: "sse/bounds_invalid_utf8_line",
        raw: b"data: \xff\n\n",
        outcome: Outcome::Reject(&["sse_invalid_utf8"]),
        expected: &[],
        category: SseCategory::Bounds,
        why: "Lossy decoding would hand the client a payload the provider did not send, and would do it silently.",
        spec: "14",
    },
    SseVector {
        name: "sse/bounds_oversized_field_name",
        raw: b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: x\n",
        outcome: Outcome::Reject(&["sse_field_name_too_long"]),
        expected: &[],
        category: SseCategory::Bounds,
        why: "A stream that never emits a colon would otherwise buffer without bound; the field-name ceiling is what makes a garbage stream terminate.",
        spec: "3.2, 14",
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
        assert!(VECTORS.iter().all(|v| v.name.starts_with("sse/")));
    }

    #[test]
    fn every_vector_carries_a_reason_and_a_clause() {
        for vector in VECTORS {
            assert!(!vector.why.is_empty(), "{} has no rationale", vector.name);
            assert!(!vector.spec.is_empty(), "{} cites no clause", vector.name);
        }
    }

    #[test]
    fn only_accepting_vectors_expect_events() {
        for vector in VECTORS {
            if !vector.outcome.is_accept() {
                assert!(
                    vector.expected.is_empty(),
                    "{} expects events but is not marked accept",
                    vector.name
                );
            }
        }
    }

    #[test]
    fn the_field_name_bound_vector_actually_exceeds_the_default() {
        // 64 bytes is `SseLimits::DEFAULT.max_field_name_bytes`. A vector at or
        // below it would be accepted and the expectation would be unreachable.
        let vector = by_name("sse/bounds_oversized_field_name").expect("present");
        let name_len = vector
            .raw
            .iter()
            .position(|b| *b == b':')
            .expect("the vector has a colon");
        assert!(name_len > 64, "field name is only {name_len} bytes");
    }

    #[test]
    fn accepting_vectors_are_terminated_or_expect_nothing() {
        // An accepting vector must end in a terminator, or the events it claims
        // would still be buffered when the stream ends.
        for vector in VECTORS.iter().filter(|v| v.outcome.is_accept()) {
            if vector.expected.is_empty() {
                continue;
            }
            let last = vector.raw.last().copied();
            assert!(
                matches!(last, Some(b'\n' | b'\r')),
                "{} claims events but does not end on a terminator",
                vector.name
            );
        }
    }

    #[test]
    fn the_corpus_covers_all_three_terminator_spellings() {
        assert!(by_name("sse/framing_single_event_lf").is_some());
        assert!(by_name("sse/framing_single_event_crlf").is_some());
        assert!(by_name("sse/framing_single_event_bare_cr").is_some());
        assert!(by_name("sse/framing_mixed_terminators").is_some());
    }

    #[test]
    fn provider_shapes_cover_both_families() {
        let names: Vec<&str> = in_category(SseCategory::ProviderShape)
            .map(|v| v.name)
            .collect();
        assert!(names.iter().any(|n| n.contains("openai")));
        assert!(names.iter().any(|n| n.contains("anthropic")));
    }
}
