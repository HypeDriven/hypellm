//! Incremental SSE parser.

/// Bounds on a single stream's parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    /// Maximum bytes held in the line-assembly buffer at once.
    ///
    /// This is the "per-stream buffered data" ceiling of specification 3.2.
    /// Exceeding it means the upstream sent a single line longer than the
    /// router is willing to hold, which is a protocol violation rather than
    /// backpressure.
    pub max_buffer_bytes: usize,
    /// Maximum accumulated `data` payload for one event.
    pub max_event_bytes: usize,
    /// Maximum length of a field name, to bound a garbage stream that never
    /// emits a colon.
    pub max_field_name_bytes: usize,
}

impl SseLimits {
    /// Defaults derived from specification 3.2's 256 KiB per-stream ceiling.
    pub const DEFAULT: Self = Self {
        max_buffer_bytes: 256 * 1024,
        max_event_bytes: 1024 * 1024,
        max_field_name_bytes: 64,
    };
}

impl Default for SseLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A dispatched event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SseEvent {
    /// The `event:` field, when present.
    pub event: Option<String>,
    /// The accumulated `data:` payload, with lines joined by `\n`.
    pub data: String,
    /// The `id:` field, when present and free of NUL.
    pub id: Option<String>,
    /// The `retry:` field, when present and a valid integer.
    pub retry: Option<u64>,
}

impl SseEvent {
    /// True when the payload is the OpenAI-style terminal marker.
    #[must_use]
    pub fn is_done_marker(&self) -> bool {
        self.data.trim() == crate::encode::DONE_MARKER
    }
}

/// Parse failures. All are fatal for the stream: a malformed SSE frame means
/// the router can no longer trust event boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseError {
    /// A single line exceeded [`SseLimits::max_buffer_bytes`].
    LineTooLong,
    /// One event's accumulated data exceeded [`SseLimits::max_event_bytes`].
    EventTooLarge,
    /// A field name exceeded [`SseLimits::max_field_name_bytes`].
    FieldNameTooLong,
    /// A line was not valid UTF-8.
    InvalidUtf8,
}

impl SseError {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LineTooLong => "sse_line_too_long",
            Self::EventTooLarge => "sse_event_too_large",
            Self::FieldNameTooLong => "sse_field_name_too_long",
            Self::InvalidUtf8 => "sse_invalid_utf8",
        }
    }
}

impl core::fmt::Display for SseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::LineTooLong => "server-sent events line exceeds the permitted length",
            Self::EventTooLarge => "server-sent event exceeds the permitted size",
            Self::FieldNameTooLong => "server-sent events field name exceeds the permitted length",
            Self::InvalidUtf8 => "server-sent events line is not valid UTF-8",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SseError {}

/// Incremental parser.
///
/// Feed bytes with [`SseParser::push`], then drain with
/// [`SseParser::next_event`] until it returns `None`.
#[derive(Debug)]
pub struct SseParser {
    limits: SseLimits,
    /// Bytes received but not yet formed into a complete line.
    line_buf: Vec<u8>,
    /// Completed lines not yet consumed by `next_event`.
    pending: std::collections::VecDeque<Line>,
    /// Accumulator for the event currently being assembled.
    current: SseEvent,
    /// True when at least one `data:` field has been seen for `current`.
    saw_data: bool,
    /// Set when the previous chunk ended with a bare CR, so that a following LF
    /// is treated as the second half of one CRLF rather than a blank line.
    pending_cr: bool,
    /// Sticky failure. Once set, every call reports it.
    failed: Option<SseError>,
}

#[derive(Debug)]
enum Line {
    Blank,
    Comment,
    Field { name: String, value: String },
}

impl SseParser {
    /// Create a parser with the given limits.
    #[must_use]
    pub fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            line_buf: Vec::new(),
            pending: std::collections::VecDeque::new(),
            current: SseEvent::default(),
            saw_data: false,
            pending_cr: false,
            failed: None,
        }
    }

    /// Create a parser with default limits.
    #[must_use]
    pub fn with_default_limits() -> Self {
        Self::new(SseLimits::DEFAULT)
    }

    /// Bytes currently buffered but not yet formed into a line.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.line_buf.len()
    }

    /// Feed received bytes.
    ///
    /// Line splitting accepts LF, CRLF, and bare CR. A CR at the very end of a
    /// chunk is remembered so that a CRLF split across two reads is not
    /// mistaken for a line terminator followed by a blank line — that mistake
    /// would dispatch an event early and split a JSON payload in half.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), SseError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        for &byte in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    // Second half of a CRLF whose CR already ended a line.
                    continue;
                }
            }
            match byte {
                b'\n' => self.finish_line()?,
                b'\r' => {
                    self.finish_line()?;
                    self.pending_cr = true;
                }
                _ => {
                    if self.line_buf.len() >= self.limits.max_buffer_bytes {
                        return Err(self.fail(SseError::LineTooLong));
                    }
                    self.line_buf.push(byte);
                }
            }
        }
        Ok(())
    }

    /// Signal that the upstream closed.
    ///
    /// A trailing line with no terminator is discarded, per the `EventSource`
    /// specification. Returning the partial line would hand a truncated JSON
    /// fragment to an adapter.
    pub fn finish(&mut self) {
        self.line_buf.clear();
        self.pending_cr = false;
    }

    /// True when a partial line is buffered at end of stream, meaning the
    /// upstream stopped mid-event.
    #[must_use]
    pub fn has_incomplete_tail(&self) -> bool {
        !self.line_buf.is_empty()
    }

    fn fail(&mut self, e: SseError) -> SseError {
        self.failed = Some(e);
        e
    }

    fn finish_line(&mut self) -> Result<(), SseError> {
        let raw = core::mem::take(&mut self.line_buf);
        let text = match String::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return Err(self.fail(SseError::InvalidUtf8)),
        };

        if text.is_empty() {
            self.pending.push_back(Line::Blank);
            return Ok(());
        }
        if text.starts_with(':') {
            // A comment. Used for keepalive; carries no event data.
            self.pending.push_back(Line::Comment);
            return Ok(());
        }

        let (name, value) = match text.find(':') {
            Some(idx) => {
                let (n, rest) = text.split_at(idx);
                // Skip the colon, then exactly one optional leading space.
                let v = &rest[1..];
                let v = v.strip_prefix(' ').unwrap_or(v);
                (n.to_owned(), v.to_owned())
            }
            // A line with no colon is a field name with an empty value.
            None => (text, String::new()),
        };

        if name.len() > self.limits.max_field_name_bytes {
            return Err(self.fail(SseError::FieldNameTooLong));
        }
        self.pending.push_back(Line::Field { name, value });
        Ok(())
    }

    /// Take the next complete event, if one has been assembled.
    pub fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        while let Some(line) = self.pending.pop_front() {
            match line {
                Line::Comment => {}
                Line::Blank => {
                    // Dispatch. An event with no `data` field is not dispatched;
                    // its `event`/`id` fields are discarded with it.
                    if self.saw_data {
                        let event = core::mem::take(&mut self.current);
                        self.saw_data = false;
                        return Ok(Some(event));
                    }
                    self.current = SseEvent::default();
                }
                Line::Field { name, value } => match name.as_str() {
                    "data" => {
                        let addition = if self.saw_data {
                            value.len() + 1
                        } else {
                            value.len()
                        };
                        if self.current.data.len() + addition > self.limits.max_event_bytes {
                            return Err(self.fail(SseError::EventTooLarge));
                        }
                        if self.saw_data {
                            self.current.data.push('\n');
                        }
                        self.current.data.push_str(&value);
                        self.saw_data = true;
                    }
                    "event" => self.current.event = Some(value),
                    // The specification requires ignoring an id containing NUL
                    // rather than truncating at it. Failing the guard falls
                    // through to the catch-all arm below, which ignores the
                    // field — exactly the required behaviour.
                    "id" if !value.contains('\u{0}') => self.current.id = Some(value),
                    "retry" => {
                        if let Ok(ms) = value.parse::<u64>() {
                            self.current.retry = Some(ms);
                        }
                    }
                    // Unknown fields are ignored, as the specification requires.
                    _ => {}
                },
            }
        }
        Ok(None)
    }

    /// Drain every event currently available.
    pub fn drain(&mut self) -> Result<Vec<SseEvent>, SseError> {
        let mut out = Vec::new();
        while let Some(e) = self.next_event()? {
            out.push(e);
        }
        Ok(out)
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::with_default_limits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(input: &[u8]) -> Vec<SseEvent> {
        let mut p = SseParser::with_default_limits();
        p.push(input).expect("push");
        p.drain().expect("drain")
    }

    #[test]
    fn single_event() {
        let events = parse_all(b"data: hello\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[0].event, None);
    }

    #[test]
    fn named_event_with_id_and_retry() {
        let events = parse_all(b"event: message_start\nid: 42\nretry: 3000\ndata: {}\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.as_deref(), Some("message_start"));
        assert_eq!(events[0].id.as_deref(), Some("42"));
        assert_eq!(events[0].retry, Some(3000));
        assert_eq!(events[0].data, "{}");
    }

    #[test]
    fn multiple_data_lines_join_with_newline() {
        let events = parse_all(b"data: line one\ndata: line two\ndata: line three\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line one\nline two\nline three");
    }

    #[test]
    fn empty_data_line_contributes_an_empty_line() {
        let events = parse_all(b"data: a\ndata:\ndata: b\n\n");
        assert_eq!(events[0].data, "a\n\nb");
    }

    #[test]
    fn exactly_one_leading_space_is_stripped() {
        let events = parse_all(b"data:  two spaces\n\n");
        assert_eq!(events[0].data, " two spaces");
        let events = parse_all(b"data:no space\n\n");
        assert_eq!(events[0].data, "no space");
    }

    #[test]
    fn comments_are_ignored_but_do_not_dispatch() {
        let events = parse_all(b": keepalive\ndata: x\n: another\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "x");
        // A comment-only stream produces nothing at all.
        assert!(parse_all(b": ping\n\n: ping\n\n").is_empty());
    }

    #[test]
    fn crlf_and_bare_cr_are_accepted() {
        assert_eq!(parse_all(b"data: a\r\n\r\n")[0].data, "a");
        assert_eq!(parse_all(b"data: a\r\r")[0].data, "a");
        assert_eq!(parse_all(b"data: a\n\n")[0].data, "a");
        // Mixed within one stream.
        let events = parse_all(b"data: a\r\n\r\ndata: b\n\ndata: c\r\r");
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].data, "c");
    }

    #[test]
    fn crlf_split_across_chunks_is_one_terminator() {
        // The classic incremental-parsing bug: a CR ending one read and an LF
        // beginning the next must not look like two line endings, which would
        // dispatch the event a frame early.
        let mut p = SseParser::with_default_limits();
        p.push(b"data: a\r").unwrap();
        p.push(b"\ndata: b\r\n\r\n").unwrap();
        let events = p.drain().unwrap();
        assert_eq!(events.len(), 1, "expected one event, got {events:?}");
        assert_eq!(events[0].data, "a\nb");
    }

    #[test]
    fn byte_at_a_time_matches_whole_input() {
        let input: &[u8] =
            b"event: delta\ndata: {\"a\":1}\ndata: {\"b\":2}\n\n: c\n\ndata: [DONE]\n\n";
        let whole = parse_all(input);

        let mut p = SseParser::with_default_limits();
        let mut incremental = Vec::new();
        for byte in input {
            p.push(&[*byte]).unwrap();
            incremental.extend(p.drain().unwrap());
        }
        assert_eq!(whole, incremental);
        assert_eq!(incremental.len(), 2);
        assert!(incremental[1].is_done_marker());
    }

    #[test]
    fn event_without_data_is_not_dispatched() {
        // `event:` and `id:` without any `data:` must be discarded, not emitted
        // as an empty event that an adapter would try to decode as JSON.
        let events = parse_all(b"event: ping\nid: 7\n\ndata: real\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "real");
        assert_eq!(events[0].event, None, "discarded fields must not leak forward");
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let events = parse_all(b"unknown: x\nfoo\ndata: y\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "y");
    }

    #[test]
    fn id_containing_nul_is_ignored() {
        let mut input = Vec::from(&b"id: a"[..]);
        input.push(0);
        input.extend_from_slice(b"b\ndata: x\n\n");
        let events = parse_all(&input);
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn incomplete_event_is_not_dispatched() {
        let mut p = SseParser::with_default_limits();
        p.push(b"data: partial").unwrap();
        assert_eq!(p.drain().unwrap(), vec![]);
        assert!(p.has_incomplete_tail());
        p.finish();
        assert_eq!(p.drain().unwrap(), vec![]);
    }

    #[test]
    fn line_length_is_bounded() {
        let limits = SseLimits {
            max_buffer_bytes: 32,
            ..SseLimits::DEFAULT
        };
        let mut p = SseParser::new(limits);
        let long = vec![b'x'; 64];
        assert_eq!(p.push(&long), Err(SseError::LineTooLong));
        // The failure is sticky: no further data is trusted.
        assert_eq!(p.push(b"data: ok\n\n"), Err(SseError::LineTooLong));
        assert_eq!(p.next_event(), Err(SseError::LineTooLong));
    }

    #[test]
    fn event_size_is_bounded() {
        let limits = SseLimits {
            max_event_bytes: 16,
            ..SseLimits::DEFAULT
        };
        let mut p = SseParser::new(limits);
        p.push(b"data: 0123456789\ndata: 0123456789\n\n").unwrap();
        assert_eq!(p.next_event(), Err(SseError::EventTooLarge));
    }

    #[test]
    fn field_name_is_bounded() {
        let limits = SseLimits {
            max_field_name_bytes: 8,
            ..SseLimits::DEFAULT
        };
        let mut p = SseParser::new(limits);
        assert_eq!(
            p.push(b"averyverylongfieldname: x\n"),
            Err(SseError::FieldNameTooLong)
        );
    }

    #[test]
    fn invalid_utf8_line_is_rejected() {
        let mut p = SseParser::with_default_limits();
        assert_eq!(p.push(&[b'd', b'a', b't', b'a', b':', 0xFF, b'\n']), Err(SseError::InvalidUtf8));
    }

    #[test]
    fn multibyte_utf8_survives_chunk_splits() {
        let mut p = SseParser::with_default_limits();
        let payload = "data: héllo 😀\n\n".as_bytes();
        for byte in payload {
            p.push(&[*byte]).unwrap();
        }
        let events = p.drain().unwrap();
        assert_eq!(events[0].data, "héllo 😀");
    }

    #[test]
    fn blank_line_between_events_resets_state() {
        let events = parse_all(b"event: a\ndata: 1\n\ndata: 2\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("a"));
        assert_eq!(events[1].event, None, "event name must not carry over");
    }

    #[test]
    fn invalid_retry_is_ignored() {
        let events = parse_all(b"retry: not-a-number\ndata: x\n\n");
        assert_eq!(events[0].retry, None);
        let events = parse_all(b"retry: -5\ndata: x\n\n");
        assert_eq!(events[0].retry, None);
    }
}
