//! SSE encoding for the client-facing stream.
//!
//! Specification 14 requires that keepalives use protocol comments or pings and
//! "never synthetic content tokens": a router must not invent assistant text to
//! keep a connection warm, because the client cannot distinguish it from model
//! output.

/// The terminal marker used by the OpenAI streaming profile.
pub const DONE_MARKER: &str = "[DONE]";

/// Append a `data:`-only event.
///
/// Embedded newlines are split across multiple `data:` lines, which is what the
/// protocol requires; a raw newline inside one `data:` line would terminate the
/// event early and let a payload containing `\n\n` inject a frame boundary.
pub fn encode_data(out: &mut String, data: &str) {
    write_data_lines(out, data);
    out.push('\n');
}

/// Append a named event with a payload.
pub fn encode_event(out: &mut String, event: &str, data: &str) {
    // A field value must not contain a line terminator. Event names come from
    // adapters, never from client input, but sanitising here means a future
    // caller cannot open a frame-injection hole by passing one through.
    out.push_str("event: ");
    push_single_line(out, event);
    out.push('\n');
    write_data_lines(out, data);
    out.push('\n');
}

/// Append the OpenAI-style terminal marker event.
pub fn encode_done(out: &mut String) {
    out.push_str("data: ");
    out.push_str(DONE_MARKER);
    out.push_str("\n\n");
}

/// Append a comment line. Comments carry no event data and are the correct
/// keepalive mechanism.
pub fn encode_comment(out: &mut String, text: &str) {
    out.push(':');
    push_single_line(out, text);
    out.push('\n');
}

/// Append a bare keepalive comment.
pub fn encode_keepalive(out: &mut String) {
    out.push_str(": keepalive\n");
}

/// Append a `retry:` directive telling the client how long to wait before
/// reconnecting.
pub fn encode_retry(out: &mut String, millis: u64) {
    out.push_str("retry: ");
    out.push_str(&millis.to_string());
    out.push('\n');
}

fn write_data_lines(out: &mut String, data: &str) {
    if data.is_empty() {
        out.push_str("data: \n");
        return;
    }
    // `split('\n')` after normalising CR keeps a trailing empty segment, which
    // correctly reproduces a payload that ends in a newline.
    let normalised = data.replace("\r\n", "\n");
    for line in normalised.split(['\n', '\r']) {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
}

fn push_single_line(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::SseParser;

    fn roundtrip(s: &str) -> Vec<crate::parse::SseEvent> {
        let mut p = SseParser::with_default_limits();
        p.push(s.as_bytes()).unwrap();
        p.drain().unwrap()
    }

    #[test]
    fn data_event_roundtrips() {
        let mut out = String::new();
        encode_data(&mut out, r#"{"delta":"hi"}"#);
        assert_eq!(out, "data: {\"delta\":\"hi\"}\n\n");
        let events = roundtrip(&out);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, r#"{"delta":"hi"}"#);
    }

    #[test]
    fn named_event_roundtrips() {
        let mut out = String::new();
        encode_event(&mut out, "content_block_delta", r#"{"i":0}"#);
        let events = roundtrip(&out);
        assert_eq!(events[0].event.as_deref(), Some("content_block_delta"));
        assert_eq!(events[0].data, r#"{"i":0}"#);
    }

    #[test]
    fn embedded_newlines_survive_the_roundtrip() {
        // The property that matters: a payload containing a blank line must not
        // be able to forge a frame boundary.
        for payload in [
            "line1\nline2",
            "a\n\nb",
            "trailing\n",
            "\nleading",
            "crlf\r\nstyle",
            "bare\rcr",
            "",
        ] {
            let mut out = String::new();
            encode_data(&mut out, payload);
            let events = roundtrip(&out);
            assert_eq!(events.len(), 1, "payload {payload:?} produced {events:?}");
            let expected = payload.replace("\r\n", "\n").replace('\r', "\n");
            assert_eq!(events[0].data, expected, "payload {payload:?}");
        }
    }

    #[test]
    fn done_marker_is_recognised() {
        let mut out = String::new();
        encode_done(&mut out);
        assert_eq!(out, "data: [DONE]\n\n");
        let events = roundtrip(&out);
        assert!(events[0].is_done_marker());
    }

    #[test]
    fn comments_do_not_dispatch_events() {
        let mut out = String::new();
        encode_comment(&mut out, "still here");
        encode_keepalive(&mut out);
        assert!(roundtrip(&out).is_empty());
        assert!(out.starts_with(':'));
    }

    #[test]
    fn event_name_cannot_inject_a_frame() {
        let mut out = String::new();
        encode_event(&mut out, "evil\n\ndata: injected", "real");
        let events = roundtrip(&out);
        assert_eq!(events.len(), 1, "injection produced extra frames: {events:?}");
        assert_eq!(events[0].data, "real");
        assert_eq!(events[0].event.as_deref(), Some("evil  data: injected"));
    }

    #[test]
    fn comment_cannot_inject_a_frame() {
        let mut out = String::new();
        encode_comment(&mut out, "x\n\ndata: injected");
        encode_data(&mut out, "real");
        let events = roundtrip(&out);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "real");
    }

    #[test]
    fn retry_directive_roundtrips() {
        let mut out = String::new();
        encode_retry(&mut out, 2500);
        encode_data(&mut out, "x");
        let events = roundtrip(&out);
        assert_eq!(events[0].retry, Some(2500));
    }

    #[test]
    fn several_events_stream_in_order() {
        let mut out = String::new();
        for i in 0..5 {
            encode_data(&mut out, &format!("{{\"i\":{i}}}"));
        }
        encode_done(&mut out);
        let events = roundtrip(&out);
        assert_eq!(events.len(), 6);
        for (i, e) in events.iter().take(5).enumerate() {
            assert_eq!(e.data, format!("{{\"i\":{i}}}"));
        }
        assert!(events[5].is_done_marker());
    }
}
