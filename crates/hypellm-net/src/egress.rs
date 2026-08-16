//! The egress guard: resolve, validate, pin.
//!
//! Specification 10:
//!
//! > Upstream destinations are administrator-defined scheme/host/port tuples.
//! > Resolve DNS through a controlled resolver, reject private/link-local/
//! > metadata ranges unless the target is explicitly local, **pin the validated
//! > address for the connection**, and revalidate on refresh.
//! >
//! > Redirects are disabled. Proxy environment variables are ignored. User
//! > input never selects base URL, Host, SNI, CONNECT target, file path, or
//! > Unix socket.
//!
//! # Why pinning is the load-bearing part
//!
//! Validating a resolved address and then connecting *by name* is the DNS
//! rebinding bug: the second lookup can return a different address, and the
//! check ran against the first. [`PinnedDestination`] carries the exact
//! `SocketAddr` that passed validation, and [`Dialer::connect`] takes only a
//! pinned destination — there is no code path that connects to a name.
//!
//! # Proxy environment variables
//!
//! Nothing here reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, or `NO_PROXY`.
//! An environment variable that silently redirects every upstream connection
//! through a third party is exactly the destination-selection channel
//! specification 10 closes.

use hypellm_core::netaddr::{self, AddressClass, EgressProfile};
use hypellm_core::target::{Endpoint, EndpointScheme};
use core::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// A destination that has been resolved and validated.
///
/// The only thing [`Dialer::connect`] accepts. Constructing one requires going
/// through [`Resolver::resolve`], so an unvalidated destination cannot reach a
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDestination {
    /// The exact address to connect to.
    address: DestinationAddress,
    /// The authority for the `Host` header, from configuration.
    authority: String,
    /// The name to present for TLS, from configuration.
    sni: Option<String>,
    /// Whether the connection needs the TLS boundary.
    needs_tls: bool,
    /// The class the address was validated as, for the audit record.
    class: Option<AddressClass>,
}

impl PinnedDestination {
    /// The exact address a connection will be made to.
    #[must_use]
    pub const fn address(&self) -> &DestinationAddress {
        &self.address
    }

    /// The `Host` authority, which comes from configuration and never from a
    /// resolved name.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The name to present for TLS.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Whether this connection needs the TLS boundary.
    #[must_use]
    pub const fn needs_tls(&self) -> bool {
        self.needs_tls
    }

    /// The class the address was validated as, for the audit record.
    #[must_use]
    pub const fn class(&self) -> Option<AddressClass> {
        self.class
    }

    /// A destination for a Unix socket path from configuration.
    ///
    /// No classification, because a path names no network destination — which
    /// is also why this is a separate constructor rather than a parameter:
    /// there is no argument that could make a socket address skip
    /// classification by accident.
    fn unix(path: String, authority: String) -> Self {
        Self {
            address: DestinationAddress::Unix(path),
            authority,
            sni: None,
            needs_tls: false,
            class: None,
        }
    }

    /// Construct one directly, for tests only.
    ///
    /// `#[cfg(test)]`, so it does not exist in a built router. A test needs to
    /// reach a listener on a port it just bound, without standing up a resolver
    /// and an egress profile to say so — but the whole value of this type is
    /// that production code cannot do the same, so the escape hatch is compiled
    /// out rather than merely discouraged.
    #[cfg(test)]
    pub(crate) fn for_tests(
        address: DestinationAddress,
        authority: &str,
        sni: Option<&str>,
        needs_tls: bool,
    ) -> Self {
        Self {
            address,
            authority: authority.to_owned(),
            sni: sni.map(ToOwned::to_owned),
            needs_tls,
            class: None,
        }
    }

    /// A destination for an address that [`Resolver::resolve`] has classified
    /// and the egress profile has permitted.
    ///
    /// Private to this module, and that is the point of the type. Specification
    /// 10 requires "the validated address is pinned for the connection", and
    /// `Dialer::connect` accepts nothing else — but while the fields were
    /// public, a struct literal anywhere in the workspace could produce one
    /// that had never been near the classifier. The invariant was a discipline
    /// that held because everybody kept it, which is the kind that stops
    /// holding quietly.
    ///
    /// Now it is a property of the type: outside this module the only way to
    /// obtain a `PinnedDestination` is to call `resolve`, and `resolve` cannot
    /// return one it has not classified.
    fn validated(
        address: SocketAddr,
        authority: String,
        sni: Option<String>,
        needs_tls: bool,
        class: AddressClass,
    ) -> Self {
        Self {
            address: DestinationAddress::Socket(address),
            authority,
            sni,
            needs_tls,
            class: Some(class),
        }
    }
}

/// Where a connection actually goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationAddress {
    /// A pinned IP address and port.
    Socket(SocketAddr),
    /// A Unix domain socket path from configuration.
    Unix(String),
}

impl fmt::Display for DestinationAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "unix:{path}"),
        }
    }
}

/// Why a destination was refused or unreachable.
#[derive(Debug)]
pub enum EgressError {
    /// The host did not resolve.
    ResolutionFailed {
        /// The configured host. Administrator-supplied, so safe to report.
        host: String,
    },
    /// Every resolved address was refused by the egress profile.
    AllAddressesRefused {
        /// The configured host.
        host: String,
        /// The classes that were refused.
        classes: Vec<AddressClass>,
    },
    /// The host is not syntactically valid.
    InvalidHost {
        /// The configured host.
        host: String,
    },
    /// Connecting failed.
    ConnectFailed(io::Error),
    /// The connection deadline expired.
    Timeout,
}

impl EgressError {
    /// Stable code for traces and metrics.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResolutionFailed { .. } => "resolution_failed",
            Self::AllAddressesRefused { .. } => "destination_refused",
            Self::InvalidHost { .. } => "invalid_host",
            Self::ConnectFailed(_) => "connect_failed",
            Self::Timeout => "connect_timeout",
        }
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolutionFailed { host } => write!(f, "cannot resolve '{host}'"),
            Self::AllAddressesRefused { host, classes } => {
                let names: Vec<&str> = classes.iter().map(|c| c.as_str()).collect();
                write!(
                    f,
                    "every address for '{host}' was refused by the egress profile ({})",
                    names.join(", ")
                )
            }
            Self::InvalidHost { host } => write!(f, "'{host}' is not a valid destination host"),
            Self::ConnectFailed(e) => write!(f, "connection failed: {e}"),
            Self::Timeout => f.write_str("connection deadline expired"),
        }
    }
}

impl std::error::Error for EgressError {}

/// Resolves and validates destinations.
pub trait Resolve: Send + Sync + fmt::Debug {
    /// Resolve a host to candidate addresses.
    ///
    /// Implementations must not consult proxy environment variables and must
    /// not follow any redirection.
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The platform resolver.
///
/// Uses the operating system resolver, which specification 4 admits as a
/// platform facility. The "controlled" part of specification 10's "controlled
/// resolver" is the validation that follows, not a bespoke DNS implementation —
/// writing one would add a parser to the trusted computing base for no security
/// gain.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}

/// A resolver returning fixed answers, for tests.
#[derive(Debug, Default)]
pub struct StaticResolver {
    answers: std::collections::BTreeMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an answer.
    #[must_use]
    pub fn with(mut self, host: &str, addresses: Vec<IpAddr>) -> Self {
        self.answers.insert(host.to_owned(), addresses);
        self
    }
}

impl Resolve for StaticResolver {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self.answers.get(host) {
            Some(addrs) => Ok(addrs.iter().map(|a| SocketAddr::new(*a, port)).collect()),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no answer configured",
            )),
        }
    }
}

/// The egress guard.
#[derive(Debug)]
pub struct Resolver {
    inner: Box<dyn Resolve>,
}

impl Resolver {
    /// Wrap a resolution strategy.
    #[must_use]
    pub fn new(inner: Box<dyn Resolve>) -> Self {
        Self { inner }
    }

    /// The platform resolver.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Box::new(SystemResolver))
    }

    /// Resolve and validate an endpoint, producing a pinned destination.
    ///
    /// Every candidate address is classified; the first permitted one is
    /// pinned. If none is permitted, the error names the classes that were
    /// refused, so an operator can see *why* rather than only that it failed.
    pub fn resolve(
        &self,
        endpoint: &Endpoint,
        profile: EgressProfile,
    ) -> Result<PinnedDestination, EgressError> {
        if endpoint.scheme == EndpointScheme::Unix {
            // A Unix path comes from configuration and names no network
            // destination, so there is nothing to classify.
            return Ok(PinnedDestination::unix(
                endpoint.host.clone(),
                endpoint.authority(),
            ));
        }

        if !netaddr::is_valid_host(&endpoint.host) {
            return Err(EgressError::InvalidHost {
                host: endpoint.host.clone(),
            });
        }

        // An IP literal needs no lookup; a name goes to the resolver.
        let bare = endpoint
            .host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&endpoint.host);

        let candidates: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
            Ok(addr) => vec![SocketAddr::new(addr, endpoint.port)],
            Err(_) => self
                .inner
                .lookup(bare, endpoint.port)
                .map_err(|_| EgressError::ResolutionFailed {
                    host: endpoint.host.clone(),
                })?,
        };

        if candidates.is_empty() {
            return Err(EgressError::ResolutionFailed {
                host: endpoint.host.clone(),
            });
        }

        let mut refused = Vec::new();
        for candidate in candidates {
            let class = netaddr::classify(candidate.ip());
            if profile.permits(class) {
                return Ok(PinnedDestination::validated(
                    candidate,
                    endpoint.authority(),
                    match endpoint.scheme {
                        // SNI is the configured host, never anything from a
                        // request.
                        EndpointScheme::Https => Some(endpoint.host.clone()),
                        _ => None,
                    },
                    endpoint.scheme.needs_tls(),
                    class,
                ));
            }
            if !refused.contains(&class) {
                refused.push(class);
            }
        }

        Err(EgressError::AllAddressesRefused {
            host: endpoint.host.clone(),
            classes: refused,
        })
    }
}

/// A connected transport.
#[derive(Debug)]
pub enum Transport {
    /// A TCP connection.
    Tcp(TcpStream),
    /// A Unix domain socket connection.
    Unix(UnixStream),
}

impl Transport {
    /// Set read and write timeouts.
    pub fn set_timeouts(&self, timeout: Option<Duration>) -> io::Result<()> {
        // A zero timeout means "block forever" to the kernel, which is the
        // opposite of what an expired deadline should mean. Clamp to a
        // millisecond so an exhausted budget fails fast instead of hanging.
        let timeout = timeout.map(|t| t.max(Duration::from_millis(1)));
        match self {
            Self::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
            Self::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
        }
    }

    /// Disable Nagle's algorithm on TCP.
    ///
    /// A streaming gateway sends many small frames; buffering them to fill a
    /// segment adds latency to every token.
    pub fn set_nodelay(&self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_nodelay(true),
            Self::Unix(_) => Ok(()),
        }
    }

    /// Shut down the connection.
    pub fn shutdown(&self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.shutdown(std::net::Shutdown::Both),
            Self::Unix(s) => s.shutdown(std::net::Shutdown::Both),
        }
    }

    /// Duplicate the handle, so reading and writing can proceed independently.
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(s) => s.try_clone().map(Self::Tcp),
            Self::Unix(s) => s.try_clone().map(Self::Unix),
        }
    }
}

impl io::Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl io::Write for Transport {
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

/// Opens connections to pinned destinations.
#[derive(Debug, Default)]
pub struct Dialer;

impl Dialer {
    /// Connect to a pinned destination.
    ///
    /// Takes a [`PinnedDestination`] rather than a host and port, so there is
    /// no way to reach this function with an unvalidated name.
    pub fn connect(
        destination: &PinnedDestination,
        timeout: Duration,
    ) -> Result<Transport, EgressError> {
        let timeout = timeout.max(Duration::from_millis(1));
        let transport = match &destination.address() {
            DestinationAddress::Socket(addr) => TcpStream::connect_timeout(addr, timeout)
                .map(Transport::Tcp)
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::TimedOut {
                        EgressError::Timeout
                    } else {
                        EgressError::ConnectFailed(e)
                    }
                })?,
            DestinationAddress::Unix(path) => UnixStream::connect(path)
                .map(Transport::Unix)
                .map_err(EgressError::ConnectFailed)?,
        };
        transport
            .set_timeouts(Some(timeout))
            .map_err(EgressError::ConnectFailed)?;
        transport.set_nodelay().map_err(EgressError::ConnectFailed)?;
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(scheme: EndpointScheme, host: &str, port: u16) -> Endpoint {
        Endpoint {
            scheme,
            host: host.to_owned(),
            port,
            base_path: "/v1".to_owned(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid address")
    }

    #[test]
    fn an_ip_literal_needs_no_lookup() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "1.1.1.1", 443),
                EgressProfile::REMOTE,
            )
            .expect("resolves");
        assert_eq!(
            pinned.address,
            DestinationAddress::Socket("1.1.1.1:443".parse().unwrap())
        );
        assert_eq!(pinned.class, Some(AddressClass::Global));
        assert!(pinned.needs_tls);
        assert_eq!(pinned.sni.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn a_name_is_resolved_and_pinned() {
        let resolver = Resolver::new(Box::new(
            StaticResolver::new().with("api.example", vec![ip("93.184.216.34")]),
        ));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "api.example", 443),
                EgressProfile::REMOTE,
            )
            .expect("resolves");
        assert_eq!(
            pinned.address,
            DestinationAddress::Socket("93.184.216.34:443".parse().unwrap())
        );
        // The Host header and SNI come from configuration, not from the answer.
        assert_eq!(pinned.authority, "api.example");
        assert_eq!(pinned.sni.as_deref(), Some("api.example"));
    }

    #[test]
    fn a_metadata_answer_is_refused() {
        // The SSRF case: a name under attacker influence resolving to the
        // instance metadata service.
        let resolver = Resolver::new(Box::new(
            StaticResolver::new().with("evil.example", vec![ip("169.254.169.254")]),
        ));
        let err = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "evil.example", 443),
                EgressProfile::REMOTE,
            )
            .expect_err("must refuse");
        match err {
            EgressError::AllAddressesRefused { classes, .. } => {
                assert_eq!(classes, vec![AddressClass::Metadata]);
            }
            other => panic!("expected refusal, got {other}"),
        }
    }

    #[test]
    fn no_profile_permits_a_metadata_answer() {
        for profile in [
            EgressProfile::REMOTE,
            EgressProfile::LOCAL,
            EgressProfile::PRIVATE_NETWORK,
            EgressProfile::NONE,
        ] {
            let resolver = Resolver::new(Box::new(
                StaticResolver::new().with("meta.example", vec![ip("169.254.169.254")]),
            ));
            assert!(
                resolver
                    .resolve(
                        &endpoint(EndpointScheme::Https, "meta.example", 443),
                        profile
                    )
                    .is_err(),
                "{profile:?} admitted the metadata address"
            );
        }
    }

    #[test]
    fn a_mixed_answer_pins_the_permitted_address() {
        // A name resolving to both a refused and a permitted address must pin
        // the permitted one — and must pin it, not re-resolve later.
        let resolver = Resolver::new(Box::new(StaticResolver::new().with(
            "mixed.example",
            vec![ip("169.254.169.254"), ip("10.0.0.1"), ip("93.184.216.34")],
        )));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "mixed.example", 443),
                EgressProfile::REMOTE,
            )
            .expect("resolves");
        assert_eq!(
            pinned.address,
            DestinationAddress::Socket("93.184.216.34:443".parse().unwrap())
        );
    }

    #[test]
    fn an_all_refused_answer_reports_every_class() {
        let resolver = Resolver::new(Box::new(StaticResolver::new().with(
            "internal.example",
            vec![ip("10.0.0.1"), ip("192.168.1.1"), ip("127.0.0.1")],
        )));
        let err = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "internal.example", 443),
                EgressProfile::REMOTE,
            )
            .expect_err("must refuse");
        match err {
            EgressError::AllAddressesRefused { classes, .. } => {
                assert!(classes.contains(&AddressClass::Private));
                assert!(classes.contains(&AddressClass::Loopback));
            }
            other => panic!("expected refusal, got {other}"),
        }
    }

    #[test]
    fn rebinding_cannot_change_a_pinned_destination() {
        // The property that closes DNS rebinding: the pinned value is a
        // SocketAddr, so a second answer has nothing to attach to.
        let resolver = Resolver::new(Box::new(
            StaticResolver::new().with("flip.example", vec![ip("93.184.216.34")]),
        ));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "flip.example", 443),
                EgressProfile::REMOTE,
            )
            .unwrap();

        // The zone now answers with the metadata address.
        let rebound = Resolver::new(Box::new(
            StaticResolver::new().with("flip.example", vec![ip("169.254.169.254")]),
        ));
        assert!(
            rebound
                .resolve(
                    &endpoint(EndpointScheme::Https, "flip.example", 443),
                    EgressProfile::REMOTE
                )
                .is_err(),
            "the second resolution must be refused"
        );
        // And the already-pinned destination is unchanged.
        assert_eq!(
            pinned.address,
            DestinationAddress::Socket("93.184.216.34:443".parse().unwrap())
        );
    }

    #[test]
    fn documentation_ranges_are_refused() {
        // RFC 5737 reserves 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24
        // for documentation. A configuration that still points at an example
        // address from a tutorial should fail loudly rather than dial it.
        for host in ["203.0.113.9", "192.0.2.1", "198.51.100.1"] {
            let resolver = Resolver::new(Box::new(StaticResolver::new()));
            let err = resolver
                .resolve(
                    &endpoint(EndpointScheme::Https, host, 443),
                    EgressProfile::REMOTE,
                )
                .expect_err("must refuse");
            assert_eq!(err.code(), "destination_refused", "host {host}");
        }
    }

    #[test]
    fn a_local_profile_permits_loopback_only() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        assert!(
            resolver
                .resolve(
                    &endpoint(EndpointScheme::Http, "127.0.0.1", 8080),
                    EgressProfile::LOCAL
                )
                .is_ok()
        );
        assert!(
            resolver
                .resolve(
                    &endpoint(EndpointScheme::Http, "93.184.216.34", 8080),
                    EgressProfile::LOCAL
                )
                .is_err()
        );
    }

    #[test]
    fn a_unix_endpoint_bypasses_classification() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Unix, "/run/llama.sock", 0),
                EgressProfile::NONE,
            )
            .expect("unix endpoints need no address class");
        assert_eq!(
            pinned.address,
            DestinationAddress::Unix("/run/llama.sock".to_owned())
        );
        assert!(!pinned.needs_tls);
        assert_eq!(pinned.sni, None);
        assert_eq!(pinned.class, None);
    }

    #[test]
    fn an_invalid_host_is_refused_before_resolution() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        for host in ["user@host", "host/path", "", "has space"] {
            let err = resolver
                .resolve(
                    &endpoint(EndpointScheme::Https, host, 443),
                    EgressProfile::REMOTE,
                )
                .expect_err("must refuse");
            assert_eq!(err.code(), "invalid_host", "host {host:?}");
        }
    }

    #[test]
    fn an_unresolvable_name_is_reported() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        let err = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "nowhere.example", 443),
                EgressProfile::REMOTE,
            )
            .expect_err("must fail");
        assert_eq!(err.code(), "resolution_failed");
    }

    #[test]
    fn an_empty_answer_is_a_resolution_failure() {
        let resolver = Resolver::new(Box::new(
            StaticResolver::new().with("empty.example", Vec::new()),
        ));
        let err = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "empty.example", 443),
                EgressProfile::REMOTE,
            )
            .expect_err("must fail");
        assert_eq!(err.code(), "resolution_failed");
    }

    #[test]
    fn ipv6_literals_resolve_and_classify() {
        let resolver = Resolver::new(Box::new(StaticResolver::new()));
        let pinned = resolver
            .resolve(
                &endpoint(EndpointScheme::Https, "[2606:4700::1111]", 443),
                EgressProfile::REMOTE,
            )
            .expect("resolves");
        assert_eq!(pinned.class, Some(AddressClass::Global));

        // An IPv4-mapped metadata address written in IPv6 syntax is refused.
        let err = resolver.resolve(
            &endpoint(EndpointScheme::Https, "[::ffff:169.254.169.254]", 443),
            EgressProfile::REMOTE,
        );
        assert!(err.is_err(), "IPv4-mapped metadata must be refused");
    }

    #[test]
    fn a_dialer_can_reach_a_local_listener() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).expect("read");
            socket.write_all(b"pong").expect("write");
        });

        let pinned = PinnedDestination {
            address: DestinationAddress::Socket(addr),
            authority: "127.0.0.1".to_owned(),
            sni: None,
            needs_tls: false,
            class: Some(AddressClass::Loopback),
        };
        let mut transport =
            Dialer::connect(&pinned, Duration::from_secs(5)).expect("connect");
        transport.write_all(b"ping!").expect("write");
        let mut reply = [0u8; 4];
        transport.read_exact(&mut reply).expect("read");
        assert_eq!(&reply, b"pong");

        server.join().expect("server thread");
    }

    #[test]
    fn a_connection_to_a_closed_port_fails_promptly() {
        // Bind then drop, so the port is almost certainly unused.
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr")
        };
        let pinned = PinnedDestination {
            address: DestinationAddress::Socket(addr),
            authority: "127.0.0.1".to_owned(),
            sni: None,
            needs_tls: false,
            class: Some(AddressClass::Loopback),
        };
        let err = Dialer::connect(&pinned, Duration::from_secs(2)).expect_err("must fail");
        assert!(matches!(
            err,
            EgressError::ConnectFailed(_) | EgressError::Timeout
        ));
    }

    #[test]
    fn a_zero_timeout_does_not_block_forever() {
        // A zero timeout means "no timeout" to the kernel; the dialer clamps it.
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr")
        };
        let pinned = PinnedDestination {
            address: DestinationAddress::Socket(addr),
            authority: "127.0.0.1".to_owned(),
            sni: None,
            needs_tls: false,
            class: Some(AddressClass::Loopback),
        };
        assert!(Dialer::connect(&pinned, Duration::ZERO).is_err());
    }
}
