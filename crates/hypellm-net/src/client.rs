//! The upstream HTTP exchange.
//!
//! One connection, one request, an incrementally-read response. Specification
//! 14 forbids buffering an entire completion, so the body is delivered in
//! chunks as they arrive and the caller decides what to do with each.
//!
//! Deadlines are enforced at every read and write: specification 18.2 requires
//! that "every I/O operation has a deadline and cancellation path". A read that
//! would outlive the request's deadline is not attempted.

use crate::egress::{Dialer, EgressError, PinnedDestination, Transport};
use hypellm_core::time::{Clock, Deadline};
use core::fmt;
use std::io::{self, Read, Write};
use std::time::Duration;
use wire_http1::{
    BodyDecoder, HttpError, Limits, Method, ParseStatus, ResponseHead, parse_response_head,
};

/// The read buffer's growth increment.
const READ_CHUNK: usize = 16 * 1024;

/// Maximum bytes buffered while waiting for a response head.
///
/// The head limit plus a margin. An upstream that sends an enormous head is
/// misbehaving, and holding it would be a memory amplification.
const MAX_HEAD_BUFFER: usize = 128 * 1024;

/// Why an upstream exchange failed.
#[derive(Debug)]
pub enum UpstreamError {
    /// The connection could not be established.
    Egress(EgressError),
    /// The response violated the HTTP contract.
    Protocol(HttpError),
    /// The connection closed before the response was complete.
    Truncated,
    /// The deadline expired.
    Timeout,
    /// An I/O failure.
    Io(io::Error),
    /// The upstream sent more head bytes than permitted.
    HeadTooLarge,
}

impl UpstreamError {
    /// Stable code for traces and metrics.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Egress(e) => e.code(),
            Self::Protocol(e) => e.code(),
            Self::Truncated => "upstream_truncated",
            Self::Timeout => "upstream_timeout",
            Self::Io(_) => "upstream_io_error",
            Self::HeadTooLarge => "upstream_head_too_large",
        }
    }

    /// How the router classifies this for failover.
    #[must_use]
    pub const fn class(&self) -> hypellm_core::event::UpstreamErrorClass {
        use hypellm_core::event::UpstreamErrorClass as C;
        match self {
            Self::Egress(_) | Self::Io(_) => C::Connection,
            Self::Timeout => C::Timeout,
            Self::Protocol(_) | Self::HeadTooLarge => C::ProtocolViolation,
            Self::Truncated => C::Connection,
        }
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Egress(e) => write!(f, "{e}"),
            Self::Protocol(e) => write!(f, "upstream protocol violation: {e}"),
            Self::Truncated => f.write_str("upstream closed before the response was complete"),
            Self::Timeout => f.write_str("upstream deadline expired"),
            Self::Io(e) => write!(f, "upstream I/O error: {e}"),
            Self::HeadTooLarge => f.write_str("upstream response head exceeds the permitted size"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<io::Error> for UpstreamError {
    fn from(e: io::Error) -> Self {
        if matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::Timeout
        } else {
            Self::Io(e)
        }
    }
}

impl From<HttpError> for UpstreamError {
    fn from(e: HttpError) -> Self {
        Self::Protocol(e)
    }
}

impl From<EgressError> for UpstreamError {
    fn from(e: EgressError) -> Self {
        match e {
            EgressError::Timeout => Self::Timeout,
            other => Self::Egress(other),
        }
    }
}

/// A connection to one upstream, carrying one exchange at a time.
#[derive(Debug)]
pub struct UpstreamConnection {
    transport: Transport,
    /// Bytes read from the socket but not yet consumed.
    buffer: Vec<u8>,
    /// How many bytes of `buffer` have been consumed.
    consumed: usize,
    /// Whether the peer has closed.
    eof: bool,
    /// The pool key this connection belongs to.
    pool_key: String,
    /// Whether the connection may be reused after this exchange.
    reusable: bool,
    /// Whether this connection was taken from the pool rather than dialed for
    /// this exchange.
    ///
    /// A pooled connection may have been closed by the peer at any moment since
    /// it went idle, and the close is only observable by trying to use it. A
    /// caller that fails on a pooled connection before the upstream produced
    /// any response therefore learns nothing about the upstream, and must be
    /// able to tell that case apart from a genuine failure on a fresh socket.
    pooled: bool,
}

impl UpstreamConnection {
    /// Open a connection to a pinned destination.
    pub fn connect(
        destination: &PinnedDestination,
        pool_key: String,
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        let transport = Dialer::connect(destination, timeout)?;
        Ok(Self {
            transport,
            buffer: Vec::with_capacity(READ_CHUNK),
            consumed: 0,
            eof: false,
            pool_key,
            reusable: true,
            pooled: false,
        })
    }

    /// Wrap an already-connected transport, such as one from the TLS helper.
    #[must_use]
    pub fn from_transport(transport: Transport, pool_key: String) -> Self {
        Self {
            transport,
            buffer: Vec::with_capacity(READ_CHUNK),
            consumed: 0,
            eof: false,
            pool_key,
            reusable: true,
            pooled: false,
        }
    }

    /// The pool key.
    #[must_use]
    pub fn pool_key(&self) -> &str {
        &self.pool_key
    }

    /// Whether this connection was reused from the pool.
    #[must_use]
    pub const fn is_pooled(&self) -> bool {
        self.pooled
    }

    /// Record that this connection came out of the pool.
    pub const fn mark_pooled(&mut self) {
        self.pooled = true;
    }

    /// Whether the connection may be returned to the pool.
    #[must_use]
    /// Whether any byte has ever arrived from the peer on this connection.
    ///
    /// The signal a caller needs to tell a socket the peer closed while it was
    /// idle from one that answered and then failed. The first says the request
    /// was never processed and may be replayed; the second says nothing of the
    /// kind, and replaying a non-idempotent request on it would run the
    /// exchange twice (specification 6.5).
    pub fn has_received_any(&self) -> bool {
        !self.buffer.is_empty()
    }

    pub const fn is_reusable(&self) -> bool {
        self.reusable && !self.eof
    }

    /// Mark the connection unusable, so it is closed rather than pooled.
    pub const fn poison(&mut self) {
        self.reusable = false;
    }

    /// Send a request head and body.
    pub fn send(
        &mut self,
        head: &[u8],
        body: &[u8],
        clock: &dyn Clock,
        deadline: Deadline,
    ) -> Result<(), UpstreamError> {
        self.apply_deadline(clock, deadline)?;
        self.transport.write_all(head)?;
        if !body.is_empty() {
            self.transport.write_all(body)?;
        }
        self.transport.flush()?;
        Ok(())
    }

    /// Write raw bytes, for a chunked request body.
    pub fn write_chunk(
        &mut self,
        bytes: &[u8],
        clock: &dyn Clock,
        deadline: Deadline,
    ) -> Result<(), UpstreamError> {
        self.apply_deadline(clock, deadline)?;
        self.transport.write_all(bytes)?;
        self.transport.flush()?;
        Ok(())
    }

    fn apply_deadline(&self, clock: &dyn Clock, deadline: Deadline) -> Result<(), UpstreamError> {
        if deadline.is_expired(clock) {
            return Err(UpstreamError::Timeout);
        }
        self.transport
            .set_timeouts(Some(deadline.remaining(clock)))?;
        Ok(())
    }

    /// Unconsumed bytes currently buffered.
    fn pending(&self) -> &[u8] {
        // `consumed` never exceeds `buffer.len()`: it only advances by a count
        // the parser or decoder derived from this same slice. Expressing that
        // with `get` means a future violation degrades to "no bytes pending"
        // (the callers then treat the stream as short) instead of panicking.
        self.buffer.get(self.consumed..).unwrap_or(&[])
    }

    /// Read more bytes from the socket into the buffer.
    fn fill(&mut self, clock: &dyn Clock, deadline: Deadline) -> Result<usize, UpstreamError> {
        if self.eof {
            return Ok(0);
        }
        self.apply_deadline(clock, deadline)?;

        // Reclaim the consumed prefix rather than growing without bound.
        if self.consumed > 0 && self.consumed == self.buffer.len() {
            self.buffer.clear();
            self.consumed = 0;
        } else if self.consumed > READ_CHUNK {
            self.buffer.drain(..self.consumed);
            self.consumed = 0;
        }

        let start = self.buffer.len();
        self.buffer.resize(start + READ_CHUNK, 0);
        let Some(dst) = self.buffer.get_mut(start..) else {
            // Unreachable: the `resize` above leaves `buffer.len()` equal to
            // `start + READ_CHUNK`, so the tail always exists. Fail closed as
            // a short read rather than panicking on the data path.
            self.buffer.truncate(start);
            self.eof = true;
            return Ok(0);
        };
        let read = match self.transport.read(dst) {
            Ok(n) => n,
            Err(e) => {
                self.buffer.truncate(start);
                return Err(e.into());
            }
        };
        self.buffer.truncate(start + read);
        if read == 0 {
            self.eof = true;
        }
        Ok(read)
    }

    /// Read the response head.
    pub fn read_head(
        &mut self,
        request_method: &Method,
        limits: &Limits,
        clock: &dyn Clock,
        deadline: Deadline,
    ) -> Result<ResponseHead, UpstreamError> {
        loop {
            match parse_response_head(self.pending(), request_method, limits)? {
                ParseStatus::Complete(head) => {
                    self.consumed += head.head_len;
                    if head.connection_close {
                        self.reusable = false;
                    }
                    return Ok(head);
                }
                ParseStatus::Incomplete => {
                    if self.pending().len() > MAX_HEAD_BUFFER {
                        self.poison();
                        return Err(UpstreamError::HeadTooLarge);
                    }
                    if self.fill(clock, deadline)? == 0 {
                        self.poison();
                        return Err(UpstreamError::Truncated);
                    }
                }
            }
        }
    }

    /// Read the next piece of the body, appending decoded payload to `out`.
    ///
    /// Returns the number of payload bytes produced. A return of zero with the
    /// decoder complete means the body has ended.
    pub fn read_body(
        &mut self,
        decoder: &mut BodyDecoder,
        out: &mut Vec<u8>,
        clock: &dyn Clock,
        deadline: Deadline,
    ) -> Result<usize, UpstreamError> {
        let before = out.len();

        loop {
            if decoder.is_complete() {
                return Ok(out.len() - before);
            }

            if !self.pending().is_empty() {
                let taken = decoder.decode(self.pending(), out)?;
                self.consumed += taken;
                if out.len() > before {
                    return Ok(out.len() - before);
                }
                if taken == 0 && decoder.is_complete() {
                    return Ok(out.len() - before);
                }
                if taken == 0 {
                    // The decoder needs more bytes than are buffered.
                    if self.fill(clock, deadline)? == 0 {
                        return self.finish_body(decoder, out, before);
                    }
                }
                continue;
            }

            if self.fill(clock, deadline)? == 0 {
                return self.finish_body(decoder, out, before);
            }
        }
    }

    fn finish_body(
        &mut self,
        decoder: &mut BodyDecoder,
        out: &[u8],
        before: usize,
    ) -> Result<usize, UpstreamError> {
        self.reusable = false;
        match decoder.finish() {
            Ok(()) => Ok(out.len() - before),
            Err(_) => Err(UpstreamError::Truncated),
        }
    }

    /// Read the whole body, bounded by the decoder's own limit.
    ///
    /// For non-streaming responses only. A streaming response must go through
    /// [`UpstreamConnection::read_body`] so that no completion is buffered
    /// whole (specification 14).
    pub fn read_body_to_end(
        &mut self,
        decoder: &mut BodyDecoder,
        clock: &dyn Clock,
        deadline: Deadline,
    ) -> Result<Vec<u8>, UpstreamError> {
        let mut out = Vec::new();
        loop {
            let produced = self.read_body(decoder, &mut out, clock, deadline)?;
            if decoder.is_complete() {
                return Ok(out);
            }
            if produced == 0 && self.eof {
                return Err(UpstreamError::Truncated);
            }
        }
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.reusable = false;
        let _ = self.transport.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::DestinationAddress;
    use hypellm_core::time::SystemClock;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use wire_http1::BodyFraming;

    /// Serve one canned response and return the request bytes received.
    fn serve(response: Vec<u8>) -> (PinnedDestination, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            // A single `read` is not enough: `send` writes the head and the
            // body as separate syscalls, and TCP preserves no message
            // boundary, so one read usually returns the head alone. Read until
            // the head is complete and the declared body has arrived.
            //
            // The timeout is a backstop: without it a client that never sends
            // the body would hang this thread, and with it the test fails
            // rather than blocking the suite.
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set read timeout");

            let mut request: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                if let Some(end) = find_head_end(&request) {
                    let expected = end.saturating_add(content_length(&request));
                    if request.len() >= expected {
                        break;
                    }
                }
                match socket.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                }
            }

            socket.write_all(&response).expect("write");
            let _ = socket.shutdown(std::net::Shutdown::Write);
            request
        });
        (
            PinnedDestination::for_tests(DestinationAddress::Socket(addr), "127.0.0.1", None, false),
            handle,
        )
    }

    /// Offset just past the blank line that ends the request head.
    fn find_head_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i.saturating_add(4))
    }

    /// The declared `Content-Length`, or zero when absent.
    fn content_length(buffer: &[u8]) -> usize {
        let text = String::from_utf8_lossy(buffer);
        text.lines()
            .take_while(|line| !line.is_empty())
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_owned())
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
    }

    fn clock() -> Arc<SystemClock> {
        Arc::new(SystemClock::new())
    }

    fn deadline(clock: &SystemClock) -> Deadline {
        Deadline::after(clock, Duration::from_secs(10))
    }

    #[test]
    fn a_fixed_length_exchange_round_trips() {
        let body = br#"{"id":"resp_1","object":"chat.completion"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut wire = response.into_bytes();
        wire.extend_from_slice(body);
        let (destination, server) = serve(wire);

        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");

        conn.send(
            b"POST /v1/chat/completions HTTP/1.1\r\nhost: api\r\ncontent-length: 2\r\n\r\n",
            b"{}",
            clock.as_ref(),
            deadline,
        )
        .expect("send");

        let head = conn
            .read_head(&Method::Post, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");
        assert_eq!(head.status, 200);
        assert_eq!(head.body, BodyFraming::Fixed(body.len() as u64));

        let mut decoder = BodyDecoder::new(head.body, Limits::UPSTREAM);
        let received = conn
            .read_body_to_end(&mut decoder, clock.as_ref(), deadline)
            .expect("body");
        assert_eq!(received, body);

        let request = server.join().expect("server");
        assert!(request.starts_with(b"POST /v1/chat/completions"));
        assert!(request.ends_with(b"{}"));
    }

    #[test]
    fn a_chunked_response_is_decoded() {
        let mut wire = Vec::from(
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        );
        wire_http1::encode_chunk(&mut wire, b"hello ");
        wire_http1::encode_chunk(&mut wire, b"world");
        wire_http1::encode_last_chunk(&mut wire);
        let (destination, server) = serve(wire);

        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");

        let head = conn
            .read_head(&Method::Get, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");
        assert_eq!(head.body, BodyFraming::Chunked);

        let mut decoder = BodyDecoder::new(head.body, Limits::UPSTREAM);
        let body = conn
            .read_body_to_end(&mut decoder, clock.as_ref(), deadline)
            .expect("body");
        assert_eq!(body, b"hello world");
        server.join().expect("server");
    }

    #[test]
    fn a_streaming_response_arrives_incrementally() {
        // The property specification 14 requires: events are delivered as they
        // arrive, not after the whole completion is buffered.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut scratch = [0u8; 1024];
            let _ = socket.read(&mut scratch);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                .expect("head");
            socket.flush().expect("flush");
            for i in 0..5 {
                socket
                    .write_all(format!("data: {{\"i\":{i}}}\n\n").as_bytes())
                    .expect("event");
                socket.flush().expect("flush");
            }
            let _ = socket.shutdown(std::net::Shutdown::Write);
        });

        let destination = PinnedDestination::for_tests(DestinationAddress::Socket(addr), "127.0.0.1", None, false);
        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"POST / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");

        let head = conn
            .read_head(&Method::Post, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");
        assert!(head.is_event_stream());
        assert_eq!(head.body, BodyFraming::UntilClose);

        let mut decoder = BodyDecoder::new(head.body, Limits::UPSTREAM);
        let mut parser = wire_sse::SseParser::with_default_limits();
        let mut events = Vec::new();
        let mut chunk = Vec::new();

        while !decoder.is_complete() {
            chunk.clear();
            let produced = conn
                .read_body(&mut decoder, &mut chunk, clock.as_ref(), deadline)
                .expect("read");
            if produced > 0 {
                parser.push(&chunk).expect("sse");
                events.extend(parser.drain().expect("drain"));
            }
            if produced == 0 && decoder.is_complete() {
                break;
            }
        }

        assert_eq!(events.len(), 5);
        assert_eq!(events.first().expect("first event").data, r#"{"i":0}"#);
        assert_eq!(events.get(4).expect("fifth event").data, r#"{"i":4}"#);
        server.join().expect("server");
    }

    #[test]
    fn a_truncated_response_is_an_error_not_a_short_body() {
        // Declaring 100 bytes and sending 5 must not look like a 5 byte answer.
        let mut wire = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..]);
        wire.extend_from_slice(b"short");
        let (destination, server) = serve(wire);

        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");
        let head = conn
            .read_head(&Method::Get, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");

        let mut decoder = BodyDecoder::new(head.body, Limits::UPSTREAM);
        let err = conn
            .read_body_to_end(&mut decoder, clock.as_ref(), deadline)
            .expect_err("must fail");
        assert!(matches!(err, UpstreamError::Truncated));
        assert_eq!(err.class(), hypellm_core::event::UpstreamErrorClass::Connection);
        server.join().expect("server");
    }

    #[test]
    fn a_closed_connection_before_the_head_is_truncation() {
        let (destination, server) = serve(Vec::new());
        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");
        let err = conn
            .read_head(&Method::Get, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect_err("must fail");
        assert!(matches!(err, UpstreamError::Truncated));
        assert!(!conn.is_reusable());
        server.join().expect("server");
    }

    #[test]
    fn a_malformed_response_is_a_protocol_violation() {
        let (destination, server) = serve(Vec::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        ));
        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");
        let err = conn
            .read_head(&Method::Get, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect_err("must fail");
        assert_eq!(
            err.class(),
            hypellm_core::event::UpstreamErrorClass::ProtocolViolation
        );
        server.join().expect("server");
    }

    #[test]
    fn an_expired_deadline_prevents_any_io() {
        let (destination, server) = serve(Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..]));
        let clock = clock();
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");

        let expired = Deadline::at(0);
        let err = conn
            .send(b"GET / HTTP/1.1\r\n\r\n", b"", clock.as_ref(), expired)
            .expect_err("must refuse");
        assert!(matches!(err, UpstreamError::Timeout));

        // The server may or may not have accepted; either way the join must
        // not hang, so close first.
        conn.close();
        drop(server);
    }

    #[test]
    fn connection_close_marks_the_connection_unreusable() {
        let (destination, server) = serve(Vec::from(
            &b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"[..],
        ));
        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");
        let head = conn
            .read_head(&Method::Get, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");
        assert!(head.connection_close);
        assert!(!conn.is_reusable());
        server.join().expect("server");
    }

    #[test]
    fn a_head_response_has_no_body_to_read() {
        let (destination, server) = serve(Vec::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"[..],
        ));
        let clock = clock();
        let deadline = deadline(&clock);
        let mut conn =
            UpstreamConnection::connect(&destination, "k".to_owned(), Duration::from_secs(5))
                .expect("connect");
        conn.send(b"HEAD / HTTP/1.1\r\nhost: a\r\n\r\n", b"", clock.as_ref(), deadline)
            .expect("send");
        let head = conn
            .read_head(&Method::Head, &Limits::UPSTREAM, clock.as_ref(), deadline)
            .expect("head");
        assert_eq!(head.body, BodyFraming::None);

        let mut decoder = BodyDecoder::new(head.body, Limits::UPSTREAM);
        let body = conn
            .read_body_to_end(&mut decoder, clock.as_ref(), deadline)
            .expect("body");
        assert!(body.is_empty());
        server.join().expect("server");
    }
}
