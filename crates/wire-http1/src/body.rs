//! Body framing: fixed-length, chunked, and close-delimited decoding.
//!
//! The decoder is incremental and never buffers a whole body. Specification 14
//! forbids buffering an entire completion, and specification 3.2 caps
//! per-stream buffered data — so the decoder holds at most one partial chunk
//! header, never a partial body.

use crate::error::{HttpError, HttpErrorKind};
use crate::header::{FORBIDDEN_TRAILERS, Headers, is_field_value, is_token, split_field, trim_ows};
use crate::limits::Limits;
use crate::message::BodyFraming;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Fixed-length body with this many bytes still expected.
    Fixed(u64),
    /// Reading a chunk-size line.
    ChunkSize,
    /// Reading chunk data, this many bytes remaining.
    ChunkData(u64),
    /// Expecting the CRLF that follows chunk data.
    ChunkDataCrlf,
    /// Reading the trailer section after the terminal chunk.
    Trailer,
    /// Reading until the connection closes.
    UntilClose,
    /// The body is complete.
    Done,
}

/// Incremental body decoder.
#[derive(Debug)]
pub struct BodyDecoder {
    state: State,
    limits: Limits,
    /// Partial chunk-size or trailer line carried across reads.
    line_buf: Vec<u8>,
    /// Bytes of decoded payload produced so far.
    decoded: u64,
    /// Bytes consumed by the trailer section so far.
    trailer_bytes: usize,
    trailers: Headers,
}

impl BodyDecoder {
    /// Create a decoder for the given framing.
    #[must_use]
    pub fn new(framing: BodyFraming, limits: Limits) -> Self {
        let state = match framing {
            BodyFraming::None => State::Done,
            BodyFraming::Fixed(n) => State::Fixed(n),
            BodyFraming::Chunked => State::ChunkSize,
            BodyFraming::UntilClose => State::UntilClose,
        };
        Self {
            state,
            limits,
            line_buf: Vec::new(),
            decoded: 0,
            trailer_bytes: 0,
            trailers: Headers::new(),
        }
    }

    /// True when the body has been fully decoded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// True when completion is signalled by the connection closing rather than
    /// by a length.
    #[must_use]
    pub fn is_close_delimited(&self) -> bool {
        matches!(self.state, State::UntilClose)
    }

    /// Payload bytes decoded so far.
    #[must_use]
    pub fn decoded_len(&self) -> u64 {
        self.decoded
    }

    /// Trailer fields, populated once a chunked body completes.
    #[must_use]
    pub fn trailers(&self) -> &Headers {
        &self.trailers
    }

    /// Decode from `input`, appending payload to `out`.
    ///
    /// Returns the number of bytes of `input` consumed. The caller re-offers
    /// anything unconsumed together with the next read.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, HttpError> {
        let mut pos = 0usize;

        loop {
            match self.state {
                State::Done => return Ok(pos),

                State::Fixed(remaining) => {
                    if remaining == 0 {
                        self.state = State::Done;
                        continue;
                    }
                    let unread = input.get(pos..).unwrap_or(&[]);
                    if unread.is_empty() {
                        return Ok(pos);
                    }
                    let (chunk, _) = take_at_most(unread, usize_min_u64(unread.len(), remaining));
                    self.emit(chunk, out)?;
                    pos += chunk.len();
                    let left = remaining.saturating_sub(u64_from_usize(chunk.len()));
                    self.state = if left == 0 {
                        State::Done
                    } else {
                        State::Fixed(left)
                    };
                }

                State::UntilClose => {
                    let unread = input.get(pos..).unwrap_or(&[]);
                    if unread.is_empty() {
                        return Ok(pos);
                    }
                    self.emit(unread, out)?;
                    pos += unread.len();
                    return Ok(pos);
                }

                State::ChunkSize => {
                    let line = match self.take_line(input, &mut pos, self.limits.max_chunk_line_bytes)? {
                        Some(l) => l,
                        None => return Ok(pos),
                    };
                    let size = parse_chunk_size(&line)?;
                    self.state = if size == 0 {
                        State::Trailer
                    } else {
                        State::ChunkData(size)
                    };
                }

                State::ChunkData(remaining) => {
                    let unread = input.get(pos..).unwrap_or(&[]);
                    if unread.is_empty() {
                        return Ok(pos);
                    }
                    let (chunk, _) = take_at_most(unread, usize_min_u64(unread.len(), remaining));
                    self.emit(chunk, out)?;
                    pos += chunk.len();
                    let left = remaining.saturating_sub(u64_from_usize(chunk.len()));
                    self.state = if left == 0 {
                        State::ChunkDataCrlf
                    } else {
                        State::ChunkData(left)
                    };
                }

                State::ChunkDataCrlf => {
                    // Exactly CRLF. A chunk that is not terminated where its
                    // declared size says it ends means the sender and the
                    // router disagree about the byte stream.
                    let line = match self.take_line(input, &mut pos, 2)? {
                        Some(l) => l,
                        None => return Ok(pos),
                    };
                    if !line.is_empty() {
                        return Err(HttpErrorKind::InvalidChunkTerminator.into());
                    }
                    self.state = State::ChunkSize;
                }

                State::Trailer => {
                    let line = match self.take_line(input, &mut pos, self.limits.max_trailer_bytes)? {
                        Some(l) => l,
                        None => return Ok(pos),
                    };
                    self.trailer_bytes += line.len() + 2;
                    if self.trailer_bytes > self.limits.max_trailer_bytes {
                        return Err(HttpErrorKind::InvalidTrailer.into());
                    }
                    if line.is_empty() {
                        self.state = State::Done;
                        return Ok(pos);
                    }
                    self.push_trailer(&line)?;
                }
            }
        }
    }

    /// Signal that the upstream closed the connection.
    ///
    /// A close-delimited body completes. Anything else is truncated, which the
    /// caller must treat as a failed exchange rather than a short answer.
    pub fn finish(&mut self) -> Result<(), HttpError> {
        match self.state {
            State::Done => Ok(()),
            State::UntilClose => {
                self.state = State::Done;
                Ok(())
            }
            _ => Err(HttpErrorKind::UnexpectedEof.into()),
        }
    }

    fn emit(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), HttpError> {
        let next = self.decoded.saturating_add(u64_from_usize(data.len()));
        if next > self.limits.max_body_bytes {
            return Err(HttpErrorKind::BodyTooLarge.into());
        }
        self.decoded = next;
        out.extend_from_slice(data);
        Ok(())
    }

    /// Read one CRLF-terminated line, buffering across calls.
    ///
    /// Returns `None` when the line is incomplete. A bare LF is rejected here
    /// for the same reason as in the head: two parsers must not be able to
    /// disagree about where a chunk boundary is.
    fn take_line(
        &mut self,
        input: &[u8],
        pos: &mut usize,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, HttpError> {
        while let Some(&byte) = input.get(*pos) {
            *pos += 1;
            match byte {
                b'\n' => {
                    // Valid only as the second half of CRLF.
                    if self.line_buf.last() == Some(&b'\r') {
                        self.line_buf.pop();
                        let line = core::mem::take(&mut self.line_buf);
                        return Ok(Some(line));
                    }
                    return Err(self.line_error(max_len));
                }
                _ => {
                    if self.line_buf.len() >= max_len.max(2) + 2 {
                        return Err(self.line_error(max_len));
                    }
                    self.line_buf.push(byte);
                }
            }
        }
        Ok(None)
    }

    fn line_error(&self, max_len: usize) -> HttpError {
        // A short cap means this is the post-chunk CRLF, not a size line.
        if max_len <= 2 {
            HttpErrorKind::InvalidChunkTerminator.into()
        } else if matches!(self.state, State::Trailer) {
            HttpErrorKind::InvalidTrailer.into()
        } else {
            HttpErrorKind::InvalidChunkSize.into()
        }
    }

    fn push_trailer(&mut self, line: &[u8]) -> Result<(), HttpError> {
        let Some((name, value)) = split_field(line, b':') else {
            return Err(HttpErrorKind::InvalidTrailer.into());
        };
        if !is_token(name) || !is_field_value(value) {
            return Err(HttpErrorKind::InvalidTrailer.into());
        }
        let name = core::str::from_utf8(name)
            .map_err(|_| HttpError::from(HttpErrorKind::InvalidTrailer))?
            .to_ascii_lowercase();

        // A trailer that redeclares framing or authentication is a smuggling
        // attempt: those decisions were already made from the head.
        if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
            return Err(HttpErrorKind::InvalidTrailer.into());
        }
        let value = core::str::from_utf8(value)
            .map_err(|_| HttpError::from(HttpErrorKind::InvalidTrailer))?;
        self.trailers
            .append_unchecked(&name, trim_ows(value))
            .map_err(|_| HttpError::from(HttpErrorKind::InvalidTrailer))
    }
}

/// The smaller of a byte count and a remaining-length counter, as a `usize`.
///
/// A `u64` remaining count larger than `usize::MAX` can only be larger than
/// any in-memory slice length, so it clamps to `usize::MAX` and `a` wins.
fn usize_min_u64(a: usize, b: u64) -> usize {
    usize::try_from(b).unwrap_or(usize::MAX).min(a)
}

/// Widen a length to `u64`, saturating on a hypothetical platform where
/// `usize` is wider than `u64`.
fn u64_from_usize(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Split off at most `n` leading bytes, returning `(head, tail)`.
///
/// Total by construction: when `n` exceeds the length the whole slice is the
/// head, so no caller can produce an out-of-range range expression.
fn take_at_most(data: &[u8], n: usize) -> (&[u8], &[u8]) {
    match data.split_at_checked(n) {
        Some(parts) => parts,
        None => (data, &[]),
    }
}

/// Parse a chunk-size line: hex digits, then optional `;`-prefixed extensions.
fn parse_chunk_size(line: &[u8]) -> Result<u64, HttpError> {
    // Everything before the first `;` is the size; the rest, including the
    // `;`, is the extension list.
    let (digits, extensions) = match line.iter().position(|b| *b == b';') {
        Some(at) => take_at_most(line, at),
        None => (line, &[][..]),
    };
    if digits.is_empty() || digits.len() > 16 {
        return Err(HttpErrorKind::InvalidChunkSize.into());
    }
    let mut value: u64 = 0;
    for b in digits {
        let d = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' => u64::from(b - b'a') + 10,
            b'A'..=b'F' => u64::from(b - b'A') + 10,
            // No leading `+`, no `0x`, no whitespace padding: each of those is
            // read differently by different implementations.
            _ => return Err(HttpErrorKind::InvalidChunkSize.into()),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(d))
            .ok_or_else(|| HttpError::from(HttpErrorKind::InvalidChunkSize))?;
    }
    // Extensions are permitted by the grammar but carry no meaning here. They
    // are bounded by the caller's line limit and otherwise ignored; they must
    // still be free of control characters.
    if !extensions.is_empty() && !is_field_value(extensions) {
        return Err(HttpErrorKind::InvalidChunkSize.into());
    }
    Ok(value)
}

/// Append one chunk in `chunked` transfer coding.
pub fn encode_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        // A zero-length chunk is the terminal chunk; emitting one here by
        // accident would truncate the stream.
        return;
    }
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Append the terminal chunk and the empty trailer section.
pub fn encode_last_chunk(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(framing: BodyFraming, input: &[u8]) -> Result<(Vec<u8>, usize), HttpError> {
        let mut d = BodyDecoder::new(framing, Limits::DEFAULT);
        let mut out = Vec::new();
        let n = d.decode(input, &mut out)?;
        Ok((out, n))
    }

    #[test]
    fn fixed_length_body() {
        let (out, n) = decode_all(BodyFraming::Fixed(5), b"hello world").unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(n, 5, "trailing bytes belong to the next message");
    }

    #[test]
    fn fixed_length_across_reads() {
        let mut d = BodyDecoder::new(BodyFraming::Fixed(11), Limits::DEFAULT);
        let mut out = Vec::new();
        d.decode(b"hello", &mut out).unwrap();
        assert!(!d.is_complete());
        d.decode(b" world", &mut out).unwrap();
        assert!(d.is_complete());
        assert_eq!(out, b"hello world");
        assert_eq!(d.decoded_len(), 11);
    }

    #[test]
    fn no_body_is_immediately_complete() {
        let mut d = BodyDecoder::new(BodyFraming::None, Limits::DEFAULT);
        assert!(d.is_complete());
        let mut out = Vec::new();
        assert_eq!(d.decode(b"leftover", &mut out).unwrap(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn chunked_body() {
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (out, n) = decode_all(BodyFraming::Chunked, input).unwrap();
        assert_eq!(out, b"hello world");
        assert_eq!(n, input.len());
    }

    #[test]
    fn chunked_byte_at_a_time_matches_whole_input() {
        let input: &[u8] = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (whole, _) = decode_all(BodyFraming::Chunked, input).unwrap();

        let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
        let mut out = Vec::new();
        for byte in input {
            let consumed = d.decode(&[*byte], &mut out).unwrap();
            assert_eq!(consumed, 1);
        }
        assert!(d.is_complete());
        assert_eq!(out, whole);
    }

    #[test]
    fn chunk_extensions_are_ignored() {
        let input = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let (out, _) = decode_all(BodyFraming::Chunked, input).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn uppercase_and_lowercase_hex_sizes() {
        for input in [
            &b"A\r\n0123456789\r\n0\r\n\r\n"[..],
            b"a\r\n0123456789\r\n0\r\n\r\n",
        ] {
            let (out, _) = decode_all(BodyFraming::Chunked, input).unwrap();
            assert_eq!(out, b"0123456789");
        }
    }

    #[test]
    fn malformed_chunk_sizes_are_rejected() {
        for input in [
            &b"0x5\r\nhello\r\n0\r\n\r\n"[..],
            b"+5\r\nhello\r\n0\r\n\r\n",
            b"-5\r\nhello\r\n0\r\n\r\n",
            b" 5\r\nhello\r\n0\r\n\r\n",
            b"5 \r\nhello\r\n0\r\n\r\n",
            b"\r\nhello\r\n0\r\n\r\n",
            b"zz\r\nhello\r\n0\r\n\r\n",
            b"ffffffffffffffffff\r\n",
        ] {
            let e = decode_all(BodyFraming::Chunked, input)
                .expect_err("must reject")
                .kind;
            assert_eq!(
                e,
                HttpErrorKind::InvalidChunkSize,
                "input {:?}",
                core::str::from_utf8(input)
            );
        }
    }

    #[test]
    fn chunk_must_end_with_crlf() {
        // The declared size says the chunk ends at "hello"; anything other than
        // CRLF there means the stream is not what it claims.
        let e = decode_all(BodyFraming::Chunked, b"5\r\nhelloX\r\n0\r\n\r\n")
            .expect_err("must reject")
            .kind;
        assert_eq!(e, HttpErrorKind::InvalidChunkTerminator);
    }

    #[test]
    fn bare_lf_in_chunk_framing_is_rejected() {
        let e = decode_all(BodyFraming::Chunked, b"5\nhello\r\n0\r\n\r\n")
            .expect_err("must reject")
            .kind;
        assert_eq!(e, HttpErrorKind::InvalidChunkSize);
    }

    #[test]
    fn trailers_are_captured() {
        let input = b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Note: n\r\n\r\n";
        let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
        let mut out = Vec::new();
        d.decode(input, &mut out).unwrap();
        assert!(d.is_complete());
        assert_eq!(out, b"hello");
        assert_eq!(d.trailers().get("x-checksum"), Some("abc"));
        assert_eq!(d.trailers().get("x-note"), Some("n"));
    }

    #[test]
    fn framing_trailers_are_rejected() {
        for name in [
            "Transfer-Encoding",
            "Content-Length",
            "Host",
            "Authorization",
            "Set-Cookie",
        ] {
            let input = format!("5\r\nhello\r\n0\r\n{name}: x\r\n\r\n");
            let e = decode_all(BodyFraming::Chunked, input.as_bytes())
                .expect_err("must reject")
                .kind;
            assert_eq!(e, HttpErrorKind::InvalidTrailer, "trailer {name}");
        }
    }

    #[test]
    fn oversize_body_is_rejected() {
        let limits = Limits::DEFAULT.with_max_body_bytes(4);
        let mut d = BodyDecoder::new(BodyFraming::Chunked, limits);
        let mut out = Vec::new();
        let e = d
            .decode(b"5\r\nhello\r\n0\r\n\r\n", &mut out)
            .expect_err("must reject")
            .kind;
        assert_eq!(e, HttpErrorKind::BodyTooLarge);

        let mut d = BodyDecoder::new(BodyFraming::Fixed(5), limits);
        let mut out = Vec::new();
        assert_eq!(
            d.decode(b"hello", &mut out).expect_err("must reject").kind,
            HttpErrorKind::BodyTooLarge
        );
    }

    #[test]
    fn oversize_chunk_line_is_rejected() {
        let limits = Limits {
            max_chunk_line_bytes: 8,
            ..Limits::DEFAULT
        };
        let mut d = BodyDecoder::new(BodyFraming::Chunked, limits);
        let mut out = Vec::new();
        let long = format!("5;{}\r\nhello\r\n0\r\n\r\n", "x".repeat(64));
        assert_eq!(
            d.decode(long.as_bytes(), &mut out)
                .expect_err("must reject")
                .kind,
            HttpErrorKind::InvalidChunkSize
        );
    }

    #[test]
    fn oversize_trailer_section_is_rejected() {
        let limits = Limits {
            max_trailer_bytes: 16,
            ..Limits::DEFAULT
        };
        let mut d = BodyDecoder::new(BodyFraming::Chunked, limits);
        let mut out = Vec::new();
        let long = format!("0\r\nX-Pad: {}\r\n\r\n", "a".repeat(200));
        assert_eq!(
            d.decode(long.as_bytes(), &mut out)
                .expect_err("must reject")
                .kind,
            HttpErrorKind::InvalidTrailer
        );
    }

    #[test]
    fn close_delimited_body() {
        let mut d = BodyDecoder::new(BodyFraming::UntilClose, Limits::UPSTREAM);
        let mut out = Vec::new();
        d.decode(b"partial ", &mut out).unwrap();
        d.decode(b"answer", &mut out).unwrap();
        assert!(!d.is_complete());
        assert!(d.is_close_delimited());
        d.finish().unwrap();
        assert!(d.is_complete());
        assert_eq!(out, b"partial answer");
    }

    #[test]
    fn truncation_is_an_error_not_a_short_body() {
        let mut d = BodyDecoder::new(BodyFraming::Fixed(10), Limits::DEFAULT);
        let mut out = Vec::new();
        d.decode(b"short", &mut out).unwrap();
        assert_eq!(
            d.finish().expect_err("truncation must fail").kind,
            HttpErrorKind::UnexpectedEof
        );

        let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
        let mut out = Vec::new();
        d.decode(b"5\r\nhel", &mut out).unwrap();
        assert_eq!(
            d.finish().expect_err("truncation must fail").kind,
            HttpErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn encoder_roundtrips_through_the_decoder() {
        let mut wire = Vec::new();
        encode_chunk(&mut wire, b"hello");
        encode_chunk(&mut wire, b" ");
        encode_chunk(&mut wire, b"world");
        encode_chunk(&mut wire, b""); // must be a no-op, not a terminal chunk
        encode_last_chunk(&mut wire);

        let (out, n) = decode_all(BodyFraming::Chunked, &wire).unwrap();
        assert_eq!(out, b"hello world");
        assert_eq!(n, wire.len());
    }

    #[test]
    fn encoder_handles_large_and_binary_payloads() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        let mut wire = Vec::new();
        encode_chunk(&mut wire, &payload);
        encode_last_chunk(&mut wire);
        let (out, _) = decode_all(BodyFraming::Chunked, &wire).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn split_reads_never_lose_or_duplicate_bytes() {
        let input: &[u8] = b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n";
        for split in 0..input.len() {
            let mut d = BodyDecoder::new(BodyFraming::Chunked, Limits::DEFAULT);
            let mut out = Vec::new();
            let mut pos = 0usize;
            pos += d.decode(&input[..split], &mut out).unwrap();
            pos += d.decode(&input[pos..], &mut out).unwrap();
            assert!(d.is_complete(), "split {split} did not complete");
            assert_eq!(out, b"abcdefgh", "split {split}");
            assert_eq!(pos, input.len(), "split {split} consumed {pos}");
        }
    }
}
