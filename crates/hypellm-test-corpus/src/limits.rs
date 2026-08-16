//! Boundary cases generated at call time rather than committed as fixtures.
//!
//! Specification 3.2 fixes the bounds — 32 KiB inbound header budget with a
//! 64 KiB hard maximum, 16 MiB body, 64 levels of JSON nesting, 256 KiB of
//! per-stream buffered SSE data. Testing a bound means testing *at* it: the
//! largest input that must be accepted and the smallest that must be refused.
//! An input one byte inside the limit that is rejected is a working parser with
//! an off-by-one that only shows up under a real client's largest request.
//!
//! These cases are generated because committing them would not be. A 64 KiB
//! header fixture and a 256 KiB stream fixture cost every checkout, every
//! build, and every CI run for one assertion each, and the bounded-work
//! discipline of specification 3.2 applies to the repository as much as to the
//! data plane. The generators below allocate only while the test that asked for
//! them is running.
//!
//! Each generator states the limit it was written against. When a limit changes
//! in the parser crate, the corresponding constant here must change with it —
//! there is no compile-time link between the two, and that is a known weakness
//! recorded in `MODULE.md` rather than papered over.

use crate::outcome::Outcome;

/// One generated boundary input.
#[derive(Debug, Clone)]
pub struct BoundaryCase {
    /// Stable identifier.
    pub name: &'static str,
    /// The generated input.
    pub input: Vec<u8>,
    /// What the parser must do with it.
    pub outcome: Outcome,
    /// Why this exact size is the interesting one.
    pub why: &'static str,
    /// The specification clause the bound derives from.
    pub spec: &'static str,
}

/// `wire_http1::Limits::DEFAULT.max_head_bytes`, restated here because this
/// crate takes no dependencies.
pub const HTTP_DEFAULT_MAX_HEAD_BYTES: usize = 32 * 1024;

/// `wire_http1::Limits::DEFAULT.max_header_count`.
pub const HTTP_DEFAULT_MAX_HEADER_COUNT: usize = 100;

/// `wire_json::Limits::DEFAULT.max_depth`.
pub const JSON_DEFAULT_MAX_DEPTH: usize = 64;

/// `wire_sse::SseLimits::DEFAULT.max_buffer_bytes`.
pub const SSE_DEFAULT_MAX_BUFFER_BYTES: usize = 256 * 1024;

/// Head-size boundary: exactly at the limit, and one byte past it.
///
/// The head is padded with a single long header value, so the boundary is the
/// total head length and not an artefact of the header count.
#[must_use]
pub fn http_head_size_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "limits/http_head_at_maximum",
            input: head_of_length(HTTP_DEFAULT_MAX_HEAD_BYTES),
            outcome: Outcome::Accept,
            why: "The largest head a conforming client may send. Rejecting it turns a documented limit into a smaller undocumented one.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/http_head_one_byte_over",
            input: head_of_length(HTTP_DEFAULT_MAX_HEAD_BYTES + 1),
            outcome: Outcome::Reject(&["head_too_large"]),
            why: "One byte past the budget. The rejection must arrive at the limit, not at whatever size the buffer happens to grow to.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/http_partial_head_over_maximum",
            input: {
                // No terminator: the parser must refuse on size before it has
                // seen a complete head, or a slow attacker can pin memory by
                // never finishing one.
                let mut raw = Vec::from(&b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\nX-Pad: "[..]);
                raw.resize(HTTP_DEFAULT_MAX_HEAD_BYTES + 1024, b'a');
                raw
            },
            outcome: Outcome::Reject(&["head_too_large"]),
            why: "An unterminated oversize head must fail immediately rather than being reported incomplete and buffered further.",
            spec: "3.2",
        },
    ]
}

/// Header-count boundary: exactly the permitted number of header fields, and
/// one more.
#[must_use]
pub fn http_header_count_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "limits/http_header_count_at_maximum",
            input: head_with_header_count(HTTP_DEFAULT_MAX_HEADER_COUNT),
            outcome: Outcome::Accept,
            why: "`Host` counts toward the budget, so the largest conforming request has exactly this many fields.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/http_header_count_one_over",
            input: head_with_header_count(HTTP_DEFAULT_MAX_HEADER_COUNT + 1),
            outcome: Outcome::Reject(&["too_many_headers"]),
            why: "The count limit bounds per-request allocation independently of the byte limit: many tiny headers stay well inside 32 KiB.",
            spec: "3.2",
        },
    ]
}

/// JSON nesting boundary: the deepest document that must parse, and one level
/// deeper. Both array and object nesting, because they are separate code paths.
#[must_use]
pub fn json_depth_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "limits/json_array_depth_at_maximum",
            input: nested_arrays(JSON_DEFAULT_MAX_DEPTH),
            outcome: Outcome::Accept,
            why: "Tool schemas nest, and a limit enforced one level early rejects a schema the client is entitled to send.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/json_array_depth_one_over",
            input: nested_arrays(JSON_DEFAULT_MAX_DEPTH + 1),
            outcome: Outcome::Reject(&["depth_exceeded"]),
            why: "Unbounded nesting is a stack-exhaustion primitive reachable before authentication.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/json_object_depth_at_maximum",
            input: nested_objects(JSON_DEFAULT_MAX_DEPTH),
            outcome: Outcome::Accept,
            why: "Object nesting must count the same as array nesting; a parser that counts only one is bounded only in one direction.",
            spec: "3.2",
        },
        BoundaryCase {
            name: "limits/json_object_depth_one_over",
            input: nested_objects(JSON_DEFAULT_MAX_DEPTH + 1),
            outcome: Outcome::Reject(&["depth_exceeded"]),
            why: "The object spelling of the same exhaustion primitive.",
            spec: "3.2",
        },
    ]
}

/// SSE line-buffer boundary: the longest single line that must be buffered, and
/// one byte more.
#[must_use]
pub fn sse_line_length_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "limits/sse_line_at_maximum",
            input: sse_line_of_length(SSE_DEFAULT_MAX_BUFFER_BYTES),
            outcome: Outcome::Accept,
            why: "A provider may legitimately send one large frame; refusing at the documented ceiling would drop a valid response as if the provider had violated its contract.",
            spec: "3.2, 14",
        },
        BoundaryCase {
            name: "limits/sse_line_one_byte_over",
            input: sse_line_of_length(SSE_DEFAULT_MAX_BUFFER_BYTES + 1),
            outcome: Outcome::Reject(&["sse_line_too_long"]),
            why: "A line that never ends is how an upstream makes the router buffer without bound; the ceiling is the only thing that stops it.",
            spec: "3.2, 14",
        },
    ]
}

/// Every generated boundary case.
#[must_use]
pub fn all() -> Vec<BoundaryCase> {
    let mut cases = http_head_size_cases();
    cases.extend(http_header_count_cases());
    cases.extend(json_depth_cases());
    cases.extend(sse_line_length_cases());
    cases
}

/// A syntactically valid request head padded to exactly `total` bytes.
///
/// # Panics
///
/// Panics when `total` is too small to hold the fixed part of the head. This is
/// a fixture-construction error, not a data-plane path.
fn head_of_length(total: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"GET /v1/models HTTP/1.1\r\nHost: router.example\r\nX-Pad: ";
    const SUFFIX: &[u8] = b"\r\n\r\n";
    let fixed = PREFIX.len() + SUFFIX.len();
    assert!(
        total >= fixed,
        "a head of {total} bytes cannot hold the {fixed}-byte fixed part"
    );
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PREFIX);
    out.resize(total - SUFFIX.len(), b'a');
    out.extend_from_slice(SUFFIX);
    out
}

/// A request head carrying exactly `count` header fields, `Host` included.
///
/// # Panics
///
/// Panics when `count` is zero, since `Host` is mandatory on HTTP/1.1.
fn head_with_header_count(count: usize) -> Vec<u8> {
    assert!(count >= 1, "HTTP/1.1 requires at least the Host header");
    let mut out = String::from("GET /v1/models HTTP/1.1\r\nHost: router.example\r\n");
    for i in 1..count {
        out.push_str(&format!("X-Pad-{i}: v\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// `depth` nested arrays around a single integer.
fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut out = String::with_capacity(depth * 2 + 1);
    for _ in 0..depth {
        out.push('[');
    }
    out.push('1');
    for _ in 0..depth {
        out.push(']');
    }
    out.into_bytes()
}

/// `depth` nested objects around a single integer.
fn nested_objects(depth: usize) -> Vec<u8> {
    let mut out = String::with_capacity(depth * 6 + 1);
    for _ in 0..depth {
        out.push_str("{\"a\":");
    }
    out.push('1');
    for _ in 0..depth {
        out.push('}');
    }
    out.into_bytes()
}

/// An SSE stream whose single `data:` line is exactly `line_len` bytes,
/// followed by a blank line.
///
/// # Panics
///
/// Panics when `line_len` is shorter than the `data: ` field prefix.
fn sse_line_of_length(line_len: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"data: ";
    assert!(
        line_len >= PREFIX.len(),
        "a data line of {line_len} bytes cannot hold its own field name"
    );
    let mut out = Vec::with_capacity(line_len + 2);
    out.extend_from_slice(PREFIX);
    out.resize(line_len, b'x');
    out.extend_from_slice(b"\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_heads_are_exactly_the_requested_length() {
        for total in [64, 1024, HTTP_DEFAULT_MAX_HEAD_BYTES, HTTP_DEFAULT_MAX_HEAD_BYTES + 1] {
            let head = head_of_length(total);
            assert_eq!(head.len(), total);
            assert!(head.ends_with(b"\r\n\r\n"), "head of {total} is unterminated");
            // Exactly one head terminator, so the length under test is the
            // length of one head rather than of a pipelined pair.
            assert_eq!(
                head.windows(4).filter(|w| *w == b"\r\n\r\n").count(),
                1,
                "head of {total} contains more than one terminator"
            );
        }
    }

    #[test]
    fn generated_heads_carry_the_requested_field_count() {
        for count in [1, 10, HTTP_DEFAULT_MAX_HEADER_COUNT, HTTP_DEFAULT_MAX_HEADER_COUNT + 1] {
            let head = head_with_header_count(count);
            let text = String::from_utf8(head).expect("ascii");
            // The head holds count + 2 CRLFs: one after the request line, one
            // after each header, and one for the terminating blank line. A
            // split on CRLF therefore yields count + 3 pieces, the last two
            // empty.
            let lines: Vec<&str> = text.split("\r\n").collect();
            assert_eq!(lines.len(), count + 3, "count {count} produced {lines:?}");
            assert_eq!(lines.last(), Some(&""));
        }
    }

    #[test]
    fn generated_json_nests_to_the_requested_depth() {
        let arrays = nested_arrays(3);
        assert_eq!(arrays, b"[[[1]]]");
        let objects = nested_objects(2);
        assert_eq!(objects, br#"{"a":{"a":1}}"#);
        assert_eq!(
            nested_arrays(JSON_DEFAULT_MAX_DEPTH).iter().filter(|b| **b == b'[').count(),
            JSON_DEFAULT_MAX_DEPTH
        );
    }

    #[test]
    fn generated_sse_lines_are_exactly_the_requested_length() {
        let stream = sse_line_of_length(SSE_DEFAULT_MAX_BUFFER_BYTES);
        let line_end = stream.iter().position(|b| *b == b'\n').expect("terminated");
        assert_eq!(line_end, SSE_DEFAULT_MAX_BUFFER_BYTES);
        assert!(stream.ends_with(b"\n\n"), "the event is not dispatched");
    }

    #[test]
    fn the_case_set_pairs_every_limit_with_an_accept_and_a_reject() {
        for cases in [
            http_head_size_cases(),
            http_header_count_cases(),
            json_depth_cases(),
            sse_line_length_cases(),
        ] {
            assert!(
                cases.iter().any(|c| c.outcome.is_accept()),
                "a boundary set with no accepting case tests only that the parser refuses things"
            );
            assert!(cases.iter().any(|c| c.outcome.is_reject()));
        }
    }

    #[test]
    fn names_are_unique_across_the_generated_set() {
        let cases = all();
        let mut names: Vec<&str> = cases.iter().map(|c| c.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        assert!(cases.iter().all(|c| c.name.starts_with("limits/")));
    }
}
