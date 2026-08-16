//! Incremental Server-Sent Events parsing and encoding.
//!
//! Specification 14: "SSE parsing handles CRLF/LF, multiple data lines,
//! comments, bounded event size, and terminal markers. JSON fragments are
//! assembled only within declared provider event boundaries; incomplete or
//! excessive events fail safely."
//!
//! The parser is a byte-at-a-time state machine over an internal buffer with a
//! hard ceiling. It never waits for a complete response, never grows without
//! bound, and reports a typed error instead of truncating silently — an upstream
//! that stops sending mid-event must not look like a clean end of stream.
//!
//! Field semantics follow the WHATWG `EventSource` specification, including the
//! rule that a `data`-less event is not dispatched and the rule that exactly one
//! leading space after the field colon is removed.

#![forbid(unsafe_code)]

pub mod encode;
pub mod parse;

pub use encode::{
    DONE_MARKER, encode_comment, encode_data, encode_done, encode_event, encode_keepalive,
    encode_retry,
};
pub use parse::{SseError, SseEvent, SseLimits, SseParser};
