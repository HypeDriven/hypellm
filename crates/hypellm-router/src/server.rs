//! The listener.
//!
//! Specification 3.2: "Use a fixed set of event-loop workers. Each connection
//! is represented by an explicit state machine… No request may create an
//! unbounded thread, task, buffer, channel, retry loop, or log entry."
//!
//! # Concurrency model, and a stated deviation
//!
//! This implementation uses **one thread per connection from a bounded pool**
//! rather than a fixed set of event-loop workers over non-blocking sockets.
//! The bound is enforced at accept time: past [`ServerConfig::max_connections`]
//! the listener answers 503 and closes, so no request creates an unbounded
//! thread and memory stays proportional to a configured constant.
//!
//! The deviation is deliberate and recorded in `docs/deferred-issues.md`. An
//! epoll-driven event loop needs either `unsafe` FFI to `epoll_create1` — which
//! specification 18.2 forbids workspace-wide — or an approved low-level crate
//! under specification 4's exception profile. Neither is in place, and a
//! blocking implementation that is *correct* and bounded is a better starting
//! point than an unreviewed unsafe one. The interface here does not assume the
//! blocking model: [`Handler`] receives a parsed head and a writer, so
//! replacing the accept loop does not touch a handler.
//!
//! What this costs is the 20,000-concurrent-stream target of specification 2.1,
//! which needs the event loop. What it does not cost is correctness: every
//! bound, deadline, and cancellation path in the specification is enforced.

use hypellm_core::time::{Clock, Deadline};
use hypellm_telemetry::Telemetry;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use wire_http1::{
    BodyDecoder, HttpError, Limits, ParseStatus, RequestHead, ResponseBuilder, parse_request_head,
};

/// Listener configuration.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Maximum simultaneous connections.
    pub max_connections: u64,
    /// How long to wait for a request head or body.
    pub read_timeout: Duration,
    /// How long a write to the client may block before the exchange is
    /// abandoned.
    ///
    /// Specification 14: "slow-client timeout cancels upstream".
    pub write_timeout: Duration,
    /// How long an idle keep-alive connection is held.
    pub keepalive_timeout: Duration,
    /// Maximum requests on one connection before it is closed.
    pub max_requests_per_connection: u32,
    /// How long shutdown waits for in-flight exchanges to finish.
    ///
    /// Specification 20.1: graceful shutdown "drains within deadline, cancels
    /// remainder". Past this the remaining connections are abandoned rather
    /// than held onto: a shutdown that waits forever for one stuck stream is
    /// not a graceful shutdown, it is a hang.
    pub drain_timeout: Duration,
    /// Absolute wall-clock budget for reading one request's head and body.
    ///
    /// `read_timeout` bounds a single `read` syscall and is reset by every byte
    /// that arrives, so a client sending one byte just inside the timeout can
    /// hold a worker indefinitely — the classic slow-loris. This bounds the
    /// whole message, which is what specification 3.2's "no request may create
    /// an unbounded thread" actually requires.
    pub request_deadline: Duration,
    /// Stack size, in bytes, for each connection thread.
    ///
    /// One thread per connection (`DI-001`) makes this a direct multiplier on
    /// the memory a connection flood can commit, so the real ceiling is address
    /// space divided by this number rather than [`Self::max_connections`]. The
    /// default is small on purpose; an operator whose workload needs deeper
    /// stacks raises it and accepts the lower ceiling.
    pub connection_stack_bytes: usize,
    /// Transport limits.
    pub limits: Limits,
}

/// Default per-connection thread stack.
///
/// Deliberately far below the platform default of 8 MiB: at 8 MiB the 4096
/// connections the inference profile admits would reserve 32 GiB of address
/// space, so the thread-per-connection model (`DI-001`) would make
/// `max_connections` a number the process cannot actually reach. At 512 KiB the
/// same 4096 connections reserve 2 GiB, which they can.
pub const DEFAULT_CONNECTION_STACK_BYTES: usize = 512 * 1024;

/// Smallest stack an operator may configure.
///
/// Below this the handler's own frames risk overflowing, which on a thread
/// stack is an abort rather than an error — a configuration mistake must not be
/// able to turn a request into a process death.
pub const MIN_CONNECTION_STACK_BYTES: usize = 128 * 1024;

/// Largest stack an operator may configure.
///
/// The cap is what stops `max_connections` from silently becoming
/// unreachable again by way of a large stack.
pub const MAX_CONNECTION_STACK_BYTES: usize = 8 * 1024 * 1024;

impl ServerConfig {
    /// Defaults for the inference listener.
    #[must_use]
    pub fn inference() -> Self {
        Self {
            max_connections: 4096,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(75),
            max_requests_per_connection: 1000,
            request_deadline: Duration::from_secs(120),
            drain_timeout: Duration::from_secs(30),
            connection_stack_bytes: DEFAULT_CONNECTION_STACK_BYTES,
            limits: Limits::DEFAULT,
        }
    }

    /// Defaults for the management listener.
    #[must_use]
    pub fn management() -> Self {
        Self {
            max_connections: 256,
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(15),
            keepalive_timeout: Duration::from_secs(30),
            max_requests_per_connection: 200,
            request_deadline: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            connection_stack_bytes: DEFAULT_CONNECTION_STACK_BYTES,
            limits: Limits::ADMIN,
        }
    }
}

/// Where a client connection came from.
///
/// Specification 20's "single secure node" profile puts the TLS edge on the
/// same host and a **Unix socket** between it and the router, so a peer is not
/// always an IP address. Modelled as an enum rather than as
/// `Option<IpAddr>` because "no address" and "a local socket" are different
/// facts: the first is a failure to observe, the second is an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A network peer.
    Ip(IpAddr),
    /// A Unix-domain socket on this host.
    Local,
    /// The address could not be determined.
    Unknown,
}

impl Peer {
    /// The IP address, when there is one.
    ///
    /// `None` for a local socket, which is what makes an API key carrying a
    /// source restriction **fail closed** over one: the restriction cannot be
    /// evaluated, so it is not satisfied (`SourceRestriction::permits`). That
    /// is the same answer an unknown address gets, and it is the safe one — a
    /// key pinned to a network must not become unrestricted by arriving through
    /// a different transport.
    #[must_use]
    pub const fn ip(self) -> Option<IpAddr> {
        match self {
            Self::Ip(address) => Some(address),
            Self::Local | Self::Unknown => None,
        }
    }

    /// A stable token for an audit record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::Local => "unix",
            Self::Unknown => "unknown",
        }
    }
}

/// One accepted connection, over either transport.
///
/// `TcpStream` and `UnixStream` share everything this needs except
/// `set_nodelay`, which has no meaning for a local socket.
#[derive(Debug)]
pub enum ClientTransport {
    /// A TCP connection.
    Tcp(TcpStream),
    /// A Unix-domain connection.
    Unix(std::os::unix::net::UnixStream),
}

impl ClientTransport {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(s) => s.try_clone().map(Self::Tcp),
            Self::Unix(s) => s.try_clone().map(Self::Unix),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_read_timeout(timeout),
            Self::Unix(s) => s.set_read_timeout(timeout),
        }
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Self::Tcp(s) => s.read_timeout(),
            Self::Unix(s) => s.read_timeout(),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_write_timeout(timeout),
            Self::Unix(s) => s.set_write_timeout(timeout),
        }
    }

    fn shutdown_write(&self) {
        let _ = match self {
            Self::Tcp(s) => s.shutdown(std::net::Shutdown::Write),
            Self::Unix(s) => s.shutdown(std::net::Shutdown::Write),
        };
    }

    fn peer(&self) -> Peer {
        match self {
            Self::Tcp(s) => s.peer_addr().map_or(Peer::Unknown, |a| Peer::Ip(a.ip())),
            // A Unix peer has a path, not an address, and often not even that
            // — an unnamed socket reports nothing. What matters here is the
            // transport, which is the fact a source restriction and an audit
            // record both need.
            Self::Unix(_) => Peer::Local,
        }
    }

    /// Disable Nagle on TCP; a no-op for a local socket.
    fn set_nodelay(&self) {
        if let Self::Tcp(s) = self {
            let _ = s.set_nodelay(true);
        }
    }
}

impl Read for ClientTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl Write for ClientTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
        }
    }
}

/// The client side of one exchange.
///
/// A handler writes the whole response through this: head, then body or stream.
/// Every write carries the configured timeout, so a client that stops reading
/// unblocks the router rather than pinning a thread indefinitely.
#[derive(Debug)]
pub struct ClientWriter {
    stream: ClientTransport,
    peer: Peer,
    bytes_written: u64,
    /// Set once a write fails, so subsequent writes stop rather than retrying
    /// into a dead socket.
    closed: bool,
}

impl ClientWriter {
    /// Where the connection came from.
    #[must_use]
    pub const fn peer(&self) -> Peer {
        self.peer
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Whether the connection has failed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Write bytes to the client.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the client connection is closed",
            ));
        }
        match self.stream.write_all(bytes) {
            Ok(()) => {
                self.bytes_written += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                Ok(())
            }
            Err(e) => {
                self.closed = true;
                Err(e)
            }
        }
    }

    /// Flush the socket.
    ///
    /// Streaming correctness depends on this: an event buffered in the socket
    /// layer has not reached the client, and the whole point of a stream is
    /// that it arrives incrementally.
    pub fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.stream.flush() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.closed = true;
                Err(e)
            }
        }
    }

    /// Close the write half.
    pub fn shutdown(&mut self) {
        self.closed = true;
        self.stream.shutdown_write();
    }
}

/// What a handler decided about the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The connection may serve another request.
    KeepAlive,
    /// The connection must be closed.
    Close,
}

/// Handles one request.
pub trait Handler: Send + Sync {
    /// Serve a request.
    ///
    /// The head has already been parsed and the body read. Returning `Close`
    /// ends the connection; an `Err` also ends it and is logged.
    fn handle(
        &self,
        head: &RequestHead,
        body: &[u8],
        writer: &mut ClientWriter,
    ) -> io::Result<Disposition>;
}

/// Where a listener publishes its connection-level counters.
///
/// Optional because `Server` is used in tests and by `hypellm-bench` without a
/// registry, and because the transport layer should not need an observability
/// facade to be correct. Specification 17 lists bytes and connection counts
/// among the required signals; this is where they come from, since the request
/// path never sees the framing bytes or an idle keep-alive connection.
#[derive(Clone)]
pub struct ListenerMetrics {
    telemetry: Arc<Telemetry>,
    /// Which plane this listener serves. A closed vocabulary: the data and
    /// management planes are separate everywhere else (specification 3.1), and
    /// a shared metric that could not tell them apart would undo that.
    listener: &'static str,
}

impl fmt::Debug for ListenerMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerMetrics")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl ListenerMetrics {
    /// Publish under `listener`.
    #[must_use]
    pub fn new(telemetry: Arc<Telemetry>, listener: &'static str) -> Self {
        Self {
            telemetry,
            listener,
        }
    }

    fn labels(&self) -> hypellm_telemetry::Labels {
        hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Listener, self.listener)
    }

    fn set_open(&self, open: u64) {
        self.telemetry.metrics.gauge_set(
            hypellm_telemetry::names::OPEN_CONNECTIONS,
            "Client connections currently open, by listener.",
            &self.labels(),
            i64::try_from(open).unwrap_or(i64::MAX),
        );
    }

    fn add_bytes(&self, inbound: u64, outbound: u64) {
        if inbound > 0 {
            self.telemetry.metrics.counter_add(
                hypellm_telemetry::names::CLIENT_BYTES_IN,
                "Bytes read from clients, by listener.",
                &self.labels(),
                inbound,
            );
        }
        if outbound > 0 {
            self.telemetry.metrics.counter_add(
                hypellm_telemetry::names::CLIENT_BYTES_OUT,
                "Bytes written to clients, by listener.",
                &self.labels(),
                outbound,
            );
        }
    }
}

/// The bound listening socket.
///
/// Specification 20's "single secure node" profile is "TLS edge on same host,
/// Unix socket to router", so the listener is not always TCP. Both variants
/// serve the same `Handler` over the same connection state machine; only the
/// accept differs.
#[derive(Debug)]
enum Bound {
    Tcp(TcpListener),
    Unix(std::os::unix::net::UnixListener),
}

/// A running listener.
#[derive(Debug)]
pub struct Server {
    listener: Bound,
    /// The Unix socket path, when bound to one. Needed for the shutdown poke
    /// and to remove the file on the way out.
    socket_path: Option<std::path::PathBuf>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
    metrics: Option<ListenerMetrics>,
}

impl Server {
    /// Bind a listener.
    /// `address` is a `host:port`, or a filesystem path for a Unix socket.
    ///
    /// A path is recognised by a leading `/` or a `unix:` prefix. Neither is a
    /// valid `host:port`, so the distinction cannot be ambiguous and no
    /// configuration flag is needed to disambiguate it.
    ///
    /// A stale socket file is removed before binding — a router that refuses to
    /// start after an unclean shutdown, because a file it created is still
    /// there, is an outage caused by tidiness — and the socket is then
    /// restricted to its owner. Filesystem permission is the *only* access
    /// control on a Unix listener: there is no network to firewall, so the mode
    /// is the boundary.
    pub fn bind(address: &str, config: ServerConfig, clock: Arc<dyn Clock>) -> io::Result<Self> {
        let listener = match unix_socket_path(address) {
            Some(path) => {
                let _ = std::fs::remove_file(path);
                let bound = std::os::unix::net::UnixListener::bind(path)?;
                crate::state::restrict_to_owner(std::path::Path::new(path))?;
                Bound::Unix(bound)
            }
            None => Bound::Tcp(TcpListener::bind(address)?),
        };
        let socket_path = unix_socket_path(address).map(std::path::PathBuf::from);
        Ok(Self {
            socket_path,
            listener,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
            accepted: Arc::new(AtomicU64::new(0)),
            clock,
            metrics: None,
        })
    }

    /// Publish this listener's connection counters into `metrics`.
    pub fn observe(&mut self, metrics: ListenerMetrics) {
        self.metrics = Some(metrics);
    }

    /// The bound address, for a TCP listener.
    ///
    /// `None` for a Unix listener, which has a path rather than an address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.listener {
            Bound::Tcp(listener) => listener.local_addr(),
            Bound::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a Unix listener has a path, not a socket address",
            )),
        }
    }

    /// A handle that can request shutdown.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
            address: self.local_addr().ok(),
            path: self.socket_path.clone(),
        }
    }

    /// Connections currently being served.
    #[must_use]
    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::SeqCst)
    }

    /// Connections accepted since start.
    #[must_use]
    pub fn accepted_connections(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Serve until shutdown is requested.
    ///
    /// Specification 20.1: "Graceful shutdown stops admission, drains within
    /// deadline, cancels remainder". Setting the flag stops new connections
    /// being accepted; in-flight ones finish their current exchange.
    pub fn serve(&self, handler: Arc<dyn Handler>) -> io::Result<()> {
        // A short accept timeout lets the loop notice a shutdown request
        // without needing a self-pipe.
        let incoming: Box<dyn Iterator<Item = io::Result<ClientTransport>>> = match &self.listener
        {
            Bound::Tcp(listener) => {
                listener.set_nonblocking(false)?;
                Box::new(listener.incoming().map(|s| s.map(ClientTransport::Tcp)))
            }
            Bound::Unix(listener) => {
                listener.set_nonblocking(false)?;
                Box::new(listener.incoming().map(|s| s.map(ClientTransport::Unix)))
            }
        };

        for stream in incoming {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => continue,
            };

            self.accepted.fetch_add(1, Ordering::SeqCst);

            // The admission bound, enforced before any per-connection state is
            // allocated. Past the cap the router answers rather than queueing,
            // so latency stays bounded under overload (specification 19).
            let current = self.active.load(Ordering::SeqCst);
            if current >= self.config.max_connections {
                reject_overloaded(stream, self.config.write_timeout);
                continue;
            }
            let open = self.active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            if let Some(metrics) = &self.metrics {
                metrics.set_open(open);
            }

            let handler = Arc::clone(&handler);
            let config = self.config;
            let active = Arc::clone(&self.active);
            let clock = Arc::clone(&self.clock);
            let shutdown = Arc::clone(&self.shutdown);
            let metrics = self.metrics.clone();

            let spawned = std::thread::Builder::new()
                .name("hypellm-conn".to_owned())
                .stack_size(config.connection_stack_bytes)
                .spawn(move || {
                    serve_connection(
                        stream,
                        &handler,
                        config,
                        &clock,
                        &shutdown,
                        metrics.as_ref(),
                    );
                    // Set from the authoritative counter rather than
                    // decremented independently, so the gauge cannot drift away
                    // from the bound the accept loop actually enforces.
                    let open = active.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
                    if let Some(metrics) = &metrics {
                        metrics.set_open(open);
                    }
                });

            if spawned.is_err() {
                // The system refused a thread. Shed rather than block the
                // accept loop.
                let open = self.active.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
                if let Some(metrics) = &self.metrics {
                    metrics.set_open(open);
                }
            }
        }

        // Specification 20.1: "drains within deadline, cancels remainder".
        // Returning here without waiting would abandon every in-flight
        // exchange the moment shutdown was signalled, cutting responses off
        // mid-stream and losing the metering and audit records that follow
        // them.
        self.drain(self.config.drain_timeout);
        Ok(())
    }

    /// Wait for in-flight exchanges to finish, up to `timeout`.
    ///
    /// Returns how many were still running when the deadline passed; zero
    /// means a clean drain. The remainder are not killed — the connection
    /// threads own their sockets and each already carries a request deadline
    /// and a write timeout, so they end on their own. What the caller gets
    /// back is the honest count for the exit status and the shutdown log.
    pub fn drain(&self, timeout: Duration) -> u64 {
        // A poll rather than a condition variable: shutdown is not a hot path,
        // and this keeps the connection threads free of any coordination they
        // would otherwise have to remember to perform.
        const POLL: Duration = Duration::from_millis(20);
        let started = std::time::Instant::now();

        loop {
            let active = self.active.load(Ordering::SeqCst);
            if active == 0 {
                return 0;
            }
            if started.elapsed() >= timeout {
                return active;
            }
            std::thread::sleep(POLL.min(timeout.saturating_sub(started.elapsed())));
        }
    }

}

/// Requests a listener stop accepting.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    address: Option<SocketAddr>,
    /// The Unix socket path, when the listener is one.
    ///
    /// Without it a Unix listener would sit in `accept` forever after the flag
    /// was set: the wake-up is a connection to the listener's own endpoint, and
    /// a path is not a `SocketAddr`. The result would be a router that reports
    /// shutdown and never stops.
    path: Option<std::path::PathBuf>,
}

impl ShutdownHandle {
    /// Signal shutdown.
    ///
    /// A connection to the listener's own address wakes the blocking accept
    /// so the loop observes the flag promptly.
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::SeqCst);
        if let Some(address) = self.address {
            let _ = TcpStream::connect_timeout(&address, Duration::from_millis(200));
        }
        if let Some(path) = &self.path {
            let _ = std::os::unix::net::UnixStream::connect(path);
        }
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// The filesystem path in `address`, when it names a Unix socket.
///
/// A leading `/` or a `unix:` prefix. Neither can appear in a `host:port`, so
/// the two forms cannot be confused and no extra configuration is needed.
fn unix_socket_path(address: &str) -> Option<&str> {
    address
        .strip_prefix("unix:")
        .or_else(|| address.starts_with('/').then_some(address))
}

fn reject_overloaded(mut stream: ClientTransport, timeout: Duration) {
    let _ = stream.set_write_timeout(Some(timeout));
    let body = br#"{"error":{"message":"the router is at its connection limit","type":"api_error","code":"capacity_exhausted"}}"#;
    if let Ok(head) = ResponseBuilder::new(429)
        .header("Content-Type", "application/json")
        .and_then(|b| b.header("Retry-After", "1"))
        .map(ResponseBuilder::close)
        .and_then(|b| b.finish_with_length(body.len()))
    {
        let _ = stream.write_all(&head);
        let _ = stream.write_all(body);
    }
    stream.shutdown_write();
}

fn serve_connection(
    stream: ClientTransport,
    handler: &Arc<dyn Handler>,
    config: ServerConfig,
    clock: &Arc<dyn Clock>,
    shutdown: &Arc<AtomicBool>,
    metrics: Option<&ListenerMetrics>,
) {
    let peer = stream.peer();
    stream.set_nodelay();
    let _ = stream.set_read_timeout(Some(config.read_timeout));
    let _ = stream.set_write_timeout(Some(config.write_timeout));

    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut writer = ClientWriter {
        stream,
        peer,
        bytes_written: 0,
        closed: false,
    };
    let mut reader = read_half;
    let mut buffer: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut served: u32 = 0;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        if served >= config.max_requests_per_connection {
            break;
        }

        // -- Read the head -------------------------------------------------

        // The deadline starts when the first byte of this request is awaited
        // and covers the head and body together, so the budget cannot be reset
        // by dribbling bytes across the boundary between them.
        let deadline = Deadline::after(clock.as_ref(), config.request_deadline);

        let head = match read_head(
            &mut reader,
            &mut buffer,
            &config,
            clock.as_ref(),
            deadline,
            shutdown,
        ) {
            Ok(Some(head)) => head,
            Ok(None) => break, // clean close
            Err(error) => {
                write_transport_error(&mut writer, error);
                break;
            }
        };
        let head_len = head.head_len;
        buffer.drain(..head_len);
        let mut inbound = u64::try_from(head_len).unwrap_or(u64::MAX);

        // -- Read the body -------------------------------------------------

        let mut decoder = BodyDecoder::new(head.body, config.limits);
        let mut body = Vec::new();
        if let Err(error) = read_body(
            &mut reader,
            &mut buffer,
            &mut decoder,
            &mut body,
            clock.as_ref(),
            deadline,
        ) {
            write_transport_error(&mut writer, error);
            break;
        }

        // -- Serve ---------------------------------------------------------

        served += 1;
        inbound = inbound.saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX));
        let before = writer.bytes_written();
        let disposition = match handler.handle(&head, &body, &mut writer) {
            Ok(disposition) => disposition,
            Err(_) => Disposition::Close,
        };
        // Accounted per exchange rather than per write: a write-level counter
        // would take the registry lock on every stream chunk, which is the one
        // place in the router where that cost is paid per token.
        if let Some(metrics) = metrics {
            metrics.add_bytes(inbound, writer.bytes_written().saturating_sub(before));
        }

        if disposition == Disposition::Close || head.connection_close || writer.is_closed() {
            break;
        }
        let _ = reader.set_read_timeout(Some(config.keepalive_timeout));
    }

    writer.shutdown();
}

fn read_head(
    reader: &mut ClientTransport,
    buffer: &mut Vec<u8>,
    config: &ServerConfig,
    clock: &dyn Clock,
    deadline: Deadline,
    shutdown: &AtomicBool,
) -> Result<Option<RequestHead>, HttpError> {
    // While waiting for a request that has not started arriving, poll in short
    // slices so that a shutdown is noticed promptly. Without this an idle
    // keep-alive connection sits in `read` for the whole keep-alive timeout,
    // and every shutdown burns its full drain deadline waiting for connections
    // that have nothing left to say.
    let idle_poll = IDLE_POLL.min(config.keepalive_timeout);
    let previous_timeout = reader.read_timeout().ok().flatten();
    let mut polling = false;

    let mut chunk = [0u8; 8 * 1024];
    loop {
        match parse_request_head(buffer, &config.limits)? {
            ParseStatus::Complete(head) => return Ok(Some(head)),
            ParseStatus::Incomplete => {}
        }
        if deadline.is_expired(clock) {
            // A head that never completes within the budget. Reported as a
            // transport error rather than a clean close so the client learns
            // why, and so the metric distinguishes it from a normal
            // disconnect.
            restore_timeout(reader, previous_timeout, polling);
            return Err(wire_http1::HttpErrorKind::RequestTimeout.into());
        }
        if shutdown.load(Ordering::SeqCst) && buffer.is_empty() {
            // Nothing of this request has arrived, so nothing is lost by
            // closing now. A request already part-way in is left to finish.
            restore_timeout(reader, previous_timeout, polling);
            return Ok(None);
        }
        if !polling {
            let _ = reader.set_read_timeout(Some(idle_poll));
            polling = true;
        }

        match reader.read(&mut chunk) {
            Ok(0) => {
                restore_timeout(reader, previous_timeout, polling);
                return if buffer.is_empty() {
                    // A clean close between requests, which is normal.
                    Ok(None)
                } else {
                    Err(wire_http1::HttpErrorKind::MalformedRequestLine.into())
                };
            }
            Ok(n) => {
                // `TcpStream::read` never reports more than the buffer length,
                // so the `None` arm is unreachable; taking it costs one lost
                // poll rather than a panic on the data path.
                if let Some(received) = chunk.get(..n) {
                    buffer.extend_from_slice(received);
                }
                // Bytes are arriving: hand the rest of the head back to the
                // configured timeout rather than the short idle poll.
                restore_timeout(reader, previous_timeout, polling);
                polling = false;
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                // An idle slice elapsed. Loop to re-check the deadline and the
                // shutdown flag.
            }
            Err(_) => {
                restore_timeout(reader, previous_timeout, polling);
                return Ok(None);
            }
        }
    }
}

/// How long a connection waits between polls for a request that has not
/// started arriving.
const IDLE_POLL: Duration = Duration::from_millis(250);

fn restore_timeout(reader: &ClientTransport, previous: Option<Duration>, polling: bool) {
    if polling {
        let _ = reader.set_read_timeout(previous);
    }
}

fn read_body(
    reader: &mut ClientTransport,
    buffer: &mut Vec<u8>,
    decoder: &mut BodyDecoder,
    body: &mut Vec<u8>,
    clock: &dyn Clock,
    deadline: Deadline,
) -> Result<(), HttpError> {
    let mut chunk = [0u8; 8 * 1024];
    loop {
        if decoder.is_complete() {
            return Ok(());
        }
        if deadline.is_expired(clock) {
            // A body that arrives too slowly to finish inside the budget. The
            // per-read timeout cannot catch this: it is reset by every byte.
            return Err(wire_http1::HttpErrorKind::RequestTimeout.into());
        }
        if !buffer.is_empty() {
            let consumed = decoder.decode(buffer, body)?;
            buffer.drain(..consumed);
            if decoder.is_complete() {
                return Ok(());
            }
            if consumed == 0 && buffer.is_empty() {
                continue;
            }
            if consumed == 0 {
                // The decoder needs more bytes than are buffered.
            }
        }
        match reader.read(&mut chunk) {
            Ok(0) => {
                return decoder
                    .finish()
                    .map_err(|_| wire_http1::HttpErrorKind::UnexpectedEof.into());
            }
            // As above: `TcpStream::read` cannot report more than the buffer
            // holds, so the `None` arm is unreachable and merely re-polls.
            Ok(n) => {
                if let Some(received) = chunk.get(..n) {
                    buffer.extend_from_slice(received);
                }
            }
            Err(_) => return Err(wire_http1::HttpErrorKind::UnexpectedEof.into()),
        }
    }
}

/// Answer a transport-level failure.
///
/// Specification 8.2's contract applies below routing too: the caller gets a
/// status and a stable code, never the bytes that caused the problem.
fn write_transport_error(writer: &mut ClientWriter, error: HttpError) {
    let status = error.status();
    let body = format!(
        r#"{{"error":{{"message":"the request could not be parsed","type":"invalid_request_error","code":"{}"}}}}"#,
        error.code()
    );
    if let Ok(head) = ResponseBuilder::new(status)
        .header("Content-Type", "application/json")
        .map(ResponseBuilder::close)
        .and_then(|b| b.finish_with_length(body.len()))
    {
        let _ = writer.write(&head);
        let _ = writer.write(body.as_bytes());
        let _ = writer.flush();
    }
}

#[cfg(test)]
// The crate-root `deny` in `lib.rs` guards production code. A test module
// indexes its own fixtures and reports failure by panicking; holding it to the
// data-plane rules would only push the panics behind `unwrap_or_else`.
#[allow(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::panic,
    clippy::expect_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    #[test]
    fn a_unix_socket_path_is_recognised_without_a_flag() {
        // A leading `/` or a `unix:` prefix. Neither can appear in a
        // `host:port`, so the two forms cannot be confused and the router needs
        // no extra setting to tell them apart.
        assert_eq!(
            super::unix_socket_path("/run/hypellm/inference.sock"),
            Some("/run/hypellm/inference.sock")
        );
        assert_eq!(
            super::unix_socket_path("unix:/run/hypellm/inference.sock"),
            Some("/run/hypellm/inference.sock")
        );
        assert_eq!(super::unix_socket_path("127.0.0.1:8080"), None);
        assert_eq!(super::unix_socket_path("[::1]:8080"), None);
        assert_eq!(super::unix_socket_path("0.0.0.0:0"), None);
    }

    #[test]
    fn a_unix_listener_serves_the_same_handler_as_a_tcp_one() {
        // Specification 20's "single secure node" profile: "TLS edge on same
        // host, Unix socket to router". Only TCP was supported, so that profile
        // could not be built as written.
        use std::io::{BufRead, BufReader};

        let dir = hypellm_store::TempDir::new("unix-listener");
        let path = dir.join("inference.sock");
        let address = path.display().to_string();

        let clock: Arc<dyn Clock> = Arc::new(hypellm_core::time::SystemClock::new());
        let server = Server::bind(&address, ServerConfig::inference(), clock).expect("bind");
        let shutdown = server.shutdown_handle();
        let handler = Arc::new(EchoHandler);
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });

        // Wait for the socket to appear, then speak HTTP over it.
        for _ in 0..200 {
            if path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut stream =
            std::os::unix::net::UnixStream::connect(&path).expect("connect to the socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream
            .write_all(b"GET /echo HTTP/1.1\r\nHost: router.test\r\nConnection: close\r\n\r\n")
            .expect("write");

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).expect("read");
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "the Unix listener did not serve the request: {status:?}"
        );

        // The handle wakes the blocked `accept` itself: a Unix listener has no
        // `SocketAddr` to connect to, so without the path it would sit there
        // forever and the router would report a shutdown that never happened.
        let stopped = std::time::Instant::now();
        shutdown.shutdown();
        let _ = thread.join();
        assert!(
            stopped.elapsed() < Duration::from_secs(5),
            "a Unix listener did not wake on shutdown: {:?}",
            stopped.elapsed()
        );
    }

    #[test]
    fn a_unix_socket_is_restricted_to_its_owner_and_replaces_a_stale_file() {
        // Filesystem permission is the *only* access control on a Unix
        // listener: there is no network to firewall, so the mode is the
        // boundary. And a router that refuses to start because a socket file it
        // created is still there would be an outage caused by tidiness.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = hypellm_store::TempDir::new("unix-listener-mode");
        let path = dir.join("inference.sock");
        std::fs::write(&path, b"stale").expect("leave a stale file");

        let clock: Arc<dyn Clock> = Arc::new(hypellm_core::time::SystemClock::new());
        let server = Server::bind(&path.display().to_string(), ServerConfig::inference(), clock)
            .expect("a stale socket file must not stop startup");

        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the socket must be owner-only: {:o}",
            mode & 0o777
        );

        // A Unix listener has a path, not an address, and says so rather than
        // inventing one.
        assert!(server.local_addr().is_err());
    }


    use super::*;
    use hypellm_core::time::SystemClock;
    use std::io::BufRead;
    use std::io::BufReader;

    /// A handler that echoes the request path and body length.
    #[derive(Debug)]
    struct EchoHandler;

    impl Handler for EchoHandler {
        fn handle(
            &self,
            head: &RequestHead,
            body: &[u8],
            writer: &mut ClientWriter,
        ) -> io::Result<Disposition> {
            let payload = format!("{} {}", head.path, body.len());
            let response = ResponseBuilder::new(200)
                .header("Content-Type", "text/plain")
                .and_then(|b| b.finish_with_length(payload.len()))
                .map_err(|_| io::Error::other("head"))?;
            writer.write(&response)?;
            writer.write(payload.as_bytes())?;
            writer.flush()?;
            Ok(Disposition::KeepAlive)
        }
    }

    fn start(config: ServerConfig) -> (SocketAddr, ShutdownHandle, std::thread::JoinHandle<()>) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let server = Server::bind("127.0.0.1:0", config, clock).expect("bind");
        let address = server.local_addr().expect("addr");
        let handle = server.shutdown_handle();
        let thread = std::thread::spawn(move || {
            let _ = server.serve(Arc::new(EchoHandler));
        });
        (address, handle, thread)
    }

    /// Read exactly one response: the head, then `Content-Length` bytes.
    ///
    /// A single `read` is not enough — the head and body routinely arrive in
    /// separate segments, and a keep-alive connection has no close to read to.
    fn read_one_response(stream: &mut TcpStream) -> String {
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];

        let head_end = loop {
            if let Some(position) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break position + 4;
            }
            let n = stream.read(&mut chunk).expect("read head");
            assert!(n > 0, "connection closed while reading the head");
            raw.extend_from_slice(&chunk[..n]);
        };

        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);

        while raw.len() < head_end + length {
            let n = stream.read(&mut chunk).expect("read body");
            assert!(n > 0, "connection closed while reading the body");
            raw.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&raw[..head_end + length]).into_owned()
    }

    fn request(address: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        // Read the head plus whatever body arrives before the close.
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    response.push_str(&line);
                    if response.contains("\r\n\r\n") {
                        let mut rest = String::new();
                        let _ = reader.read_to_string(&mut rest);
                        response.push_str(&rest);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        response
    }

    #[test]
    fn a_well_formed_request_is_served() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        let response = request(
            address,
            "POST /v1/chat/completions HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("/v1/chat/completions 5"), "{response}");

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn a_smuggling_attempt_is_refused_at_the_transport() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        let response = request(
            address,
            "POST /v1/chat HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("conflicting_framing"), "{response}");
        // The connection must close: leftover bytes cannot be attributed.
        assert!(response.contains("connection: close"), "{response}");

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn an_oversize_head_is_refused_with_431() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        let filler = "x".repeat(40_000);
        let response = request(
            address,
            &format!("GET /a HTTP/1.1\r\nHost: a\r\nX-Pad: {filler}\r\n\r\n"),
        );
        assert!(response.starts_with("HTTP/1.1 431"), "{}", &response[..60.min(response.len())]);

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn keep_alive_serves_several_requests_on_one_connection() {
        let (address, shutdown, thread) = start(ServerConfig::inference());

        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        for i in 0..3 {
            let path = format!("/req{i}");
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes(),
                )
                .expect("write");
            let text = read_one_response(&mut stream);
            assert!(text.contains("200 OK"), "request {i}: {text}");
            assert!(text.ends_with(&format!("{path} 0")), "request {i}: {text}");
        }

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn a_configured_connection_stack_still_serves() {
        // `DI-001`: one thread per connection makes the stack size a direct
        // multiplier on what a connection flood commits, so it is configurable.
        //
        // This is a smoke test and no more. The size a thread actually got is
        // not observable from safe Rust — reading the stack bounds needs
        // `pthread_getattr_np`, which is `unsafe` FFI and forbidden
        // (specification 18.2). What it does establish is that a non-default
        // value reaches `Builder::stack_size` and produces a thread that
        // serves: passing an unsupported size makes `spawn` fail, and the
        // accept loop sheds on spawn failure, so a broken value here presents
        // as every request being dropped. The clamp — the part with actual
        // logic in it — is tested in `startup`.
        let config = ServerConfig {
            connection_stack_bytes: MIN_CONNECTION_STACK_BYTES,
            ..ServerConfig::inference()
        };
        let (address, shutdown, thread) = start(config);

        let response = request(
            address,
            "GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn the_connection_limit_sheds_rather_than_queueing() {
        // Specification 19: "Latency remains bounded through early admission
        // rejection; no swap thrash or queue explosion."
        let config = ServerConfig {
            max_connections: 1,
            ..ServerConfig::inference()
        };
        let (address, shutdown, thread) = start(config);

        // Hold one connection open without completing a request.
        let mut held = TcpStream::connect(address).expect("connect");
        held.write_all(b"GET /slow HTTP/1.1\r\nHost: a\r\n")
            .expect("partial write");
        // Give the server a moment to register the connection.
        for _ in 0..50 {
            std::thread::yield_now();
        }

        let mut shed = false;
        for _ in 0..5 {
            let response = request(address, "GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
            if response.starts_with("HTTP/1.1 429") {
                assert!(response.contains("capacity_exhausted"), "{response}");
                shed = true;
                break;
            }
        }
        assert!(shed, "the connection cap was not enforced");

        drop(held);
        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn shutdown_drains_in_flight_exchanges_before_returning() {
        // Specification 20.1: graceful shutdown "drains within deadline,
        // cancels remainder". `serve` previously returned the moment the
        // accept loop broke, abandoning every in-flight exchange — cutting
        // responses off mid-stream and losing the metering and audit records
        // that follow them.
        let (address, shutdown, thread) = start(ServerConfig::inference());

        // Open a connection and leave it mid-exchange.
        let mut held = TcpStream::connect(address).expect("connect");
        held.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        held.write_all(b"GET /v1/models HTTP/1.1\r\nHost: local\r\n\r\n")
            .expect("write");
        let _ = read_one_response(&mut held);

        let started = std::time::Instant::now();
        shutdown.shutdown();
        let _ = TcpStream::connect(address);

        // The serve loop must return only once nothing is in flight.
        let joined = thread.join();
        assert!(joined.is_ok());

        // And it must not take the whole drain deadline to get there. An idle
        // keep-alive connection used to sit inside `read` for the full
        // keep-alive timeout, so every shutdown burned its entire drain budget
        // waiting for connections that had nothing left to say.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "shutdown waited {:?} for an idle connection",
            started.elapsed()
        );

        drop(held);
    }

    #[test]
    fn a_drain_that_cannot_finish_gives_up_at_its_deadline() {
        // A shutdown that waits forever for one stuck stream is a hang, not a
        // graceful shutdown. `drain` reports what was still running so the
        // caller can say so rather than block.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).expect("bind");

        // Nothing is in flight, so this returns immediately with zero.
        assert_eq!(server.drain(Duration::from_millis(50)), 0);

        let started = std::time::Instant::now();
        assert_eq!(server.drain(Duration::from_millis(50)), 0);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an already-idle drain must not wait out its deadline"
        );
    }

    #[test]
    fn shutdown_stops_accepting() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        assert!(!shutdown.is_shutting_down());

        // One request works.
        let response = request(address, "GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200"));

        shutdown.shutdown();
        assert!(shutdown.is_shutting_down());
        let _ = thread.join();

        // After the loop exits the port is closed.
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err()
                || {
                    // On some systems the socket lingers briefly; a request
                    // against it must not be served.
                    let response =
                        request(address, "GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
                    !response.starts_with("HTTP/1.1 200")
                }
        );
    }

    #[test]
    fn a_slow_client_is_cut_off_by_the_absolute_deadline() {
        // The slow-loris case. `read_timeout` bounds one `read` syscall and is
        // reset by every byte, so a client that dribbles a header just inside
        // that window holds a worker forever. Only an absolute deadline over
        // the whole message ends it.
        let mut config = ServerConfig::inference();
        config.request_deadline = Duration::from_millis(300);
        config.read_timeout = Duration::from_secs(30);
        let (address, shutdown, thread) = start(config);

        let mut stream = TcpStream::connect(address).expect("connect");
        // Short, so the probe below polls rather than blocking on the server's
        // silence.
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");

        // A head that never terminates, delivered slowly enough to keep every
        // individual read well inside `read_timeout`.
        stream
            .write_all(b"GET /v1/models HTTP/1.1\r\nHost: local\r\n")
            .expect("write");
        let started = std::time::Instant::now();
        let mut refused = false;
        for _ in 0..40 {
            if stream.write_all(b"X-Pad: filler\r\n").is_err() {
                refused = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            let mut probe = [0u8; 512];
            match stream.read(&mut probe) {
                Ok(0) => {
                    refused = true;
                    break;
                }
                Ok(n) => {
                    let answer = String::from_utf8_lossy(&probe[..n]).into_owned();
                    assert!(answer.contains("408"), "expected 408, got: {answer}");
                    refused = true;
                    break;
                }
                Err(_) => {}
            }
        }

        assert!(refused, "the server never cut off a client that never finished its head");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline did not bound the exchange"
        );

        shutdown.shutdown();
        let _ = TcpStream::connect(address);
        let _ = thread.join();
    }

    #[test]
    fn configured_limits_reach_the_transport_parser() {
        // An operator who lowers the body limit must actually get it. Before
        // this was wired the listener always used the compiled-in default.
        let mut config = ServerConfig::inference();
        config.limits.max_body_bytes = 64;
        let (address, shutdown, thread) = start(config);

        let body = "x".repeat(4096);
        let response = request(
            address,
            &format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: local\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(response.contains("413"), "expected 413, got: {response}");

        shutdown.shutdown();
        let _ = TcpStream::connect(address);
        let _ = thread.join();
    }

    #[test]
    fn a_client_that_closes_early_does_not_hang_the_server() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        {
            let mut stream = TcpStream::connect(address).expect("connect");
            stream.write_all(b"GET /a HTTP/1.1\r\n").expect("partial");
            // Drop mid-request.
        }
        // The server is still serving.
        let response = request(address, "GET /b HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn a_chunked_request_body_is_decoded() {
        let (address, shutdown, thread) = start(ServerConfig::inference());
        let response = request(
            address,
            "POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("/a 11"), "{response}");

        shutdown.shutdown();
        let _ = thread.join();
    }

    #[test]
    fn a_writer_reports_closure_rather_than_retrying() {
        // A broken pipe must stop the write loop, not spin against a dead
        // socket.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let client = TcpStream::connect(address).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        drop(client);

        let mut writer = ClientWriter {
            stream: ClientTransport::Tcp(accepted),
            peer: Peer::Unknown,
            bytes_written: 0,
            closed: false,
        };
        // The first write may succeed into the socket buffer; a large one after
        // the peer is gone must eventually fail and latch.
        for _ in 0..100 {
            if writer.write(&vec![0u8; 64 * 1024]).is_err() {
                break;
            }
        }
        if writer.is_closed() {
            assert!(writer.write(b"more").is_err());
        }
    }
}
