//! Address classification for the egress guard.
//!
//! Specification 10: "Resolve DNS through a controlled resolver, reject
//! private/link-local/metadata ranges unless the target is explicitly local,
//! pin the validated address for the connection, and revalidate on refresh."
//!
//! Specification 10.1 names SSRF and DNS rebinding as threats. The defence has
//! three parts, and this module is the first:
//!
//! 1. **Classification** (here): decide whether an address is permitted by a
//!    given egress profile. Pure arithmetic over the address, no I/O, so it is
//!    exhaustively testable.
//! 2. **Resolution and pinning** (`hypellm-net`): resolve once, validate, then
//!    connect to the *validated address*, never re-resolving the name. This is
//!    what closes DNS rebinding — a second lookup returning `169.254.169.254`
//!    has nothing to attach to.
//! 3. **Configuration-time validation** (`hypellm-config`): reject an endpoint at
//!    load time rather than at first use, so a bad destination cannot reach
//!    production behind a rarely-taken code path.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The class an address falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// A well-known cloud instance-metadata address.
    ///
    /// Called out separately from link-local because it is the single most
    /// valuable SSRF destination and deserves its own reason code in a trace.
    Metadata,
    /// RFC 1918, RFC 4193 unique-local.
    Private,
    /// `100.64.0.0/10` carrier-grade NAT.
    SharedAddressSpace,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Documentation and benchmarking ranges.
    Reserved,
    /// Publicly routable.
    Global,
}

impl AddressClass {
    /// Stable name for traces and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified",
            Self::LinkLocal => "link_local",
            Self::Metadata => "metadata",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared_address_space",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
            Self::Global => "global",
        }
    }

    /// Whether this class is publicly routable.
    #[must_use]
    pub const fn is_global(self) -> bool {
        matches!(self, Self::Global)
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Well-known cloud instance-metadata addresses.
///
/// These are inside link-local or private ranges already; naming them makes the
/// rejection reason unambiguous in an audit record, and guards against a future
/// profile that permits link-local for a legitimate reason.
const METADATA_V4: &[Ipv4Addr] = &[
    // AWS, Azure, GCP, DigitalOcean, OpenStack.
    Ipv4Addr::new(169, 254, 169, 254),
    // Alibaba Cloud.
    Ipv4Addr::new(100, 100, 100, 200),
    // Oracle Cloud.
    Ipv4Addr::new(192, 0, 0, 192),
    // GCP metadata alias.
    Ipv4Addr::new(169, 254, 169, 253),
];

/// Classify an IPv4 address.
#[must_use]
pub fn classify_ipv4(addr: Ipv4Addr) -> AddressClass {
    if METADATA_V4.contains(&addr) {
        return AddressClass::Metadata;
    }
    let o = addr.octets();
    if addr.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if addr.is_loopback() {
        return AddressClass::Loopback;
    }
    if addr.is_link_local() {
        return AddressClass::LinkLocal;
    }
    if addr.is_broadcast() {
        return AddressClass::Broadcast;
    }
    if addr.is_multicast() {
        return AddressClass::Multicast;
    }
    if addr.is_private() {
        return AddressClass::Private;
    }
    // 100.64.0.0/10, carrier-grade NAT (RFC 6598).
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return AddressClass::SharedAddressSpace;
    }
    if addr.is_documentation() {
        return AddressClass::Reserved;
    }
    // 198.18.0.0/15 benchmarking (RFC 2544), 240.0.0.0/4 reserved,
    // 192.0.0.0/24 IETF protocol assignments.
    if (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
    {
        return AddressClass::Reserved;
    }
    AddressClass::Global
}

/// Classify an IPv6 address.
#[must_use]
pub fn classify_ipv6(addr: Ipv6Addr) -> AddressClass {
    // An IPv4-mapped or IPv4-compatible address must be classified as the IPv4
    // address it carries. Otherwise `::ffff:169.254.169.254` would be treated
    // as an ordinary global IPv6 address and reach the metadata service.
    if let Some(v4) = to_ipv4_equivalent(addr) {
        return classify_ipv4(v4);
    }
    // AWS IPv6 instance metadata.
    if addr == Ipv6Addr::new(0xfd00, 0x00ec, 0x0002, 0, 0, 0, 0, 0x0254) {
        return AddressClass::Metadata;
    }
    if addr.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if addr.is_loopback() {
        return AddressClass::Loopback;
    }
    if addr.is_multicast() {
        return AddressClass::Multicast;
    }
    let segments = addr.segments();
    // fe80::/10 link-local.
    if segments[0] & 0xffc0 == 0xfe80 {
        return AddressClass::LinkLocal;
    }
    // fc00::/7 unique local.
    if segments[0] & 0xfe00 == 0xfc00 {
        return AddressClass::Private;
    }
    // 2001:db8::/32 documentation, 100::/64 discard-only.
    if (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
    {
        return AddressClass::Reserved;
    }
    AddressClass::Global
}

/// The IPv4 address an IPv6 address is equivalent to, if any.
///
/// Covers IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), and
/// NAT64 (`64:ff9b::a.b.c.d`) forms. Each is a way to write an IPv4 destination
/// in IPv6 syntax, and each has been used to slip past a classifier that only
/// looked at the outer family.
#[must_use]
pub fn to_ipv4_equivalent(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = addr.segments();
    // The last two segments are the four IPv4 octets in network order.
    let [a, b] = s[6].to_be_bytes();
    let [c, d] = s[7].to_be_bytes();
    let tail = Ipv4Addr::new(a, b, c, d);

    // ::ffff:a.b.c.d
    if s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return Some(tail);
    }
    // ::a.b.c.d, excluding :: and ::1 which are their own classes.
    if s[0..6] == [0, 0, 0, 0, 0, 0] && !(s[6] == 0 && (s[7] == 0 || s[7] == 1)) {
        return Some(tail);
    }
    // 64:ff9b::/96 NAT64.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail);
    }
    None
}

/// Classify any address.
#[must_use]
pub fn classify(addr: IpAddr) -> AddressClass {
    match addr {
        IpAddr::V4(a) => classify_ipv4(a),
        IpAddr::V6(a) => classify_ipv6(a),
    }
}

/// What an egress profile permits.
///
/// Specification 20 defines deployment profiles ranging from "Developer local"
/// to "Air-gapped/local-only"; a profile here is the address-level expression
/// of one of those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressProfile {
    /// Permit loopback destinations.
    pub allow_loopback: bool,
    /// Permit RFC 1918 and unique-local destinations.
    pub allow_private: bool,
    /// Permit link-local destinations.
    ///
    /// Almost never correct. Metadata addresses are refused even when this is
    /// set, since they are classified separately.
    pub allow_link_local: bool,
    /// Permit publicly routable destinations.
    pub allow_global: bool,
}

impl EgressProfile {
    /// A short, stable token identifying exactly which address classes this
    /// profile permits.
    ///
    /// Used to key the connection pool: a socket opened under one profile must
    /// not be reused under another, or the second request skips the
    /// address-class check that specification 10 requires. Derived from the
    /// fields rather than from a profile *name*, so a new named profile with
    /// the same permissions correctly shares connections, and two profiles that
    /// differ in any bit never do.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        match (
            self.allow_loopback,
            self.allow_private,
            self.allow_link_local,
            self.allow_global,
        ) {
            (false, false, false, false) => "e0000",
            (false, false, false, true) => "e0001",
            (false, false, true, false) => "e0010",
            (false, false, true, true) => "e0011",
            (false, true, false, false) => "e0100",
            (false, true, false, true) => "e0101",
            (false, true, true, false) => "e0110",
            (false, true, true, true) => "e0111",
            (true, false, false, false) => "e1000",
            (true, false, false, true) => "e1001",
            (true, false, true, false) => "e1010",
            (true, false, true, true) => "e1011",
            (true, true, false, false) => "e1100",
            (true, true, false, true) => "e1101",
            (true, true, true, false) => "e1110",
            (true, true, true, true) => "e1111",
        }
    }

    /// Remote providers over the public internet, no internal reachability.
    pub const REMOTE: Self = Self {
        allow_loopback: false,
        allow_private: false,
        allow_link_local: false,
        allow_global: true,
    };

    /// A local inference server on loopback or a Unix socket.
    pub const LOCAL: Self = Self {
        allow_loopback: true,
        allow_private: false,
        allow_link_local: false,
        allow_global: false,
    };

    /// A provider inside a private network, such as a self-hosted endpoint.
    pub const PRIVATE_NETWORK: Self = Self {
        allow_loopback: false,
        allow_private: true,
        allow_link_local: false,
        allow_global: false,
    };

    /// Nothing at all. The air-gapped profile's default.
    pub const NONE: Self = Self {
        allow_loopback: false,
        allow_private: false,
        allow_link_local: false,
        allow_global: false,
    };

    /// Parse a profile name from configuration.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "remote" => Self::REMOTE,
            "local" => Self::LOCAL,
            "private_network" => Self::PRIVATE_NETWORK,
            "none" => Self::NONE,
            _ => return None,
        })
    }

    /// Whether this profile permits an address class.
    ///
    /// Metadata, multicast, broadcast, unspecified, reserved, and shared
    /// address space are refused by *every* profile. There is no configuration
    /// that makes the instance-metadata service reachable, because there is no
    /// legitimate reason for an LLM gateway to talk to it.
    #[must_use]
    pub const fn permits(self, class: AddressClass) -> bool {
        match class {
            AddressClass::Loopback => self.allow_loopback,
            AddressClass::Private => self.allow_private,
            AddressClass::LinkLocal => self.allow_link_local,
            AddressClass::Global => self.allow_global,
            AddressClass::Metadata
            | AddressClass::Multicast
            | AddressClass::Broadcast
            | AddressClass::Unspecified
            | AddressClass::Reserved
            | AddressClass::SharedAddressSpace => false,
        }
    }

    /// Whether this profile permits an address.
    #[must_use]
    pub fn permits_address(self, addr: IpAddr) -> bool {
        self.permits(classify(addr))
    }
}

/// Why a destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenial {
    /// The address class is not permitted by the profile.
    ClassNotPermitted(AddressClass),
    /// The port is not on the permitted list.
    PortNotPermitted(u16),
    /// The host was syntactically invalid.
    InvalidHost,
}

impl fmt::Display for EgressDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassNotPermitted(c) => {
                write!(f, "destination address class '{c}' is not permitted")
            }
            Self::PortNotPermitted(p) => write!(f, "destination port {p} is not permitted"),
            Self::InvalidHost => f.write_str("destination host is not valid"),
        }
    }
}

impl std::error::Error for EgressDenial {}

/// Check a resolved destination against a profile.
pub fn check_destination(
    addr: IpAddr,
    port: u16,
    profile: EgressProfile,
    permitted_ports: &[u16],
) -> Result<(), EgressDenial> {
    let class = classify(addr);
    if !profile.permits(class) {
        return Err(EgressDenial::ClassNotPermitted(class));
    }
    if !permitted_ports.is_empty() && !permitted_ports.contains(&port) {
        return Err(EgressDenial::PortNotPermitted(port));
    }
    Ok(())
}

/// Whether a host string is syntactically acceptable as a destination.
///
/// Rejects userinfo, paths, query strings, and anything that is not a DNS name
/// or an IP literal. A destination is administrator-configured, so this is a
/// typo check rather than a security boundary — but it is the check that stops
/// `host=evil.example@internal.example` from resolving to the wrong place.
#[must_use]
pub fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // An IPv6 literal in brackets.
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().is_ok();
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    // A DNS name: labels of alphanumerics and hyphens, separated by dots.
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().expect("valid IPv4"))
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().expect("valid IPv6"))
    }

    #[test]
    fn metadata_addresses_are_classified_specifically() {
        for s in [
            "169.254.169.254",
            "169.254.169.253",
            "100.100.100.200",
            "192.0.0.192",
        ] {
            assert_eq!(classify(v4(s)), AddressClass::Metadata, "{s}");
        }
        assert_eq!(
            classify(v6("fd00:ec:2::254")),
            AddressClass::Metadata,
            "AWS IPv6 metadata"
        );
    }

    #[test]
    fn no_profile_permits_metadata() {
        // The central SSRF property: there is no configuration that reaches the
        // instance metadata service.
        for profile in [
            EgressProfile::REMOTE,
            EgressProfile::LOCAL,
            EgressProfile::PRIVATE_NETWORK,
            EgressProfile::NONE,
            EgressProfile {
                allow_loopback: true,
                allow_private: true,
                allow_link_local: true,
                allow_global: true,
            },
        ] {
            assert!(
                !profile.permits(AddressClass::Metadata),
                "{profile:?} must not permit metadata"
            );
            assert!(!profile.permits_address(v4("169.254.169.254")));
        }
    }

    #[test]
    fn ipv4_classification() {
        assert_eq!(classify(v4("127.0.0.1")), AddressClass::Loopback);
        assert_eq!(classify(v4("127.255.255.254")), AddressClass::Loopback);
        assert_eq!(classify(v4("0.0.0.0")), AddressClass::Unspecified);
        assert_eq!(classify(v4("169.254.1.1")), AddressClass::LinkLocal);
        assert_eq!(classify(v4("10.0.0.1")), AddressClass::Private);
        assert_eq!(classify(v4("172.16.0.1")), AddressClass::Private);
        assert_eq!(classify(v4("172.31.255.255")), AddressClass::Private);
        assert_eq!(classify(v4("192.168.1.1")), AddressClass::Private);
        assert_eq!(classify(v4("100.64.0.1")), AddressClass::SharedAddressSpace);
        assert_eq!(classify(v4("100.127.255.255")), AddressClass::SharedAddressSpace);
        assert_eq!(classify(v4("224.0.0.1")), AddressClass::Multicast);
        assert_eq!(classify(v4("255.255.255.255")), AddressClass::Broadcast);
        assert_eq!(classify(v4("192.0.2.1")), AddressClass::Reserved);
        assert_eq!(classify(v4("198.18.0.1")), AddressClass::Reserved);
        assert_eq!(classify(v4("240.0.0.1")), AddressClass::Reserved);

        // Genuinely routable addresses.
        assert_eq!(classify(v4("1.1.1.1")), AddressClass::Global);
        assert_eq!(classify(v4("172.15.0.1")), AddressClass::Global);
        assert_eq!(classify(v4("172.32.0.1")), AddressClass::Global);
        assert_eq!(classify(v4("100.63.255.255")), AddressClass::Global);
        assert_eq!(classify(v4("100.128.0.0")), AddressClass::Global);
    }

    #[test]
    fn ipv6_classification() {
        assert_eq!(classify(v6("::1")), AddressClass::Loopback);
        assert_eq!(classify(v6("::")), AddressClass::Unspecified);
        assert_eq!(classify(v6("fe80::1")), AddressClass::LinkLocal);
        assert_eq!(classify(v6("febf::1")), AddressClass::LinkLocal);
        assert_eq!(classify(v6("fc00::1")), AddressClass::Private);
        assert_eq!(classify(v6("fd12:3456::1")), AddressClass::Private);
        assert_eq!(classify(v6("ff02::1")), AddressClass::Multicast);
        assert_eq!(classify(v6("2001:db8::1")), AddressClass::Reserved);
        assert_eq!(classify(v6("2606:4700::1111")), AddressClass::Global);
    }

    #[test]
    fn ipv4_in_ipv6_forms_are_unmasked() {
        // Each of these is a way to write an IPv4 destination in IPv6 syntax.
        // A classifier that only looked at the outer family would call them
        // global and route straight to the metadata service.
        for s in [
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::169.254.169.254",
        ] {
            assert_eq!(classify(v6(s)), AddressClass::Metadata, "{s}");
        }
        for s in ["::ffff:127.0.0.1", "::ffff:7f00:1"] {
            assert_eq!(classify(v6(s)), AddressClass::Loopback, "{s}");
        }
        for s in ["::ffff:10.0.0.1", "::ffff:192.168.1.1"] {
            assert_eq!(classify(v6(s)), AddressClass::Private, "{s}");
        }
        assert_eq!(classify(v6("::ffff:1.1.1.1")), AddressClass::Global);

        // `::` and `::1` keep their own classes rather than decoding to
        // 0.0.0.0 and 0.0.0.1.
        assert_eq!(classify(v6("::")), AddressClass::Unspecified);
        assert_eq!(classify(v6("::1")), AddressClass::Loopback);
    }

    #[test]
    fn profiles_permit_what_they_say() {
        assert!(EgressProfile::REMOTE.permits_address(v4("1.1.1.1")));
        assert!(!EgressProfile::REMOTE.permits_address(v4("127.0.0.1")));
        assert!(!EgressProfile::REMOTE.permits_address(v4("10.0.0.1")));

        assert!(EgressProfile::LOCAL.permits_address(v4("127.0.0.1")));
        assert!(EgressProfile::LOCAL.permits_address(v6("::1")));
        assert!(!EgressProfile::LOCAL.permits_address(v4("1.1.1.1")));

        assert!(EgressProfile::PRIVATE_NETWORK.permits_address(v4("10.0.0.1")));
        assert!(!EgressProfile::PRIVATE_NETWORK.permits_address(v4("1.1.1.1")));

        for addr in ["1.1.1.1", "127.0.0.1", "10.0.0.1"] {
            assert!(
                !EgressProfile::NONE.permits_address(v4(addr)),
                "air-gapped profile must permit nothing"
            );
        }
    }

    #[test]
    fn profile_parsing() {
        assert_eq!(EgressProfile::parse("remote"), Some(EgressProfile::REMOTE));
        assert_eq!(EgressProfile::parse("local"), Some(EgressProfile::LOCAL));
        assert_eq!(
            EgressProfile::parse("private_network"),
            Some(EgressProfile::PRIVATE_NETWORK)
        );
        assert_eq!(EgressProfile::parse("none"), Some(EgressProfile::NONE));
        assert_eq!(EgressProfile::parse("anything"), None);
    }

    #[test]
    fn destination_check_reports_the_class() {
        assert_eq!(
            check_destination(v4("10.0.0.1"), 443, EgressProfile::REMOTE, &[]),
            Err(EgressDenial::ClassNotPermitted(AddressClass::Private))
        );
        assert_eq!(
            check_destination(v4("169.254.169.254"), 80, EgressProfile::LOCAL, &[]),
            Err(EgressDenial::ClassNotPermitted(AddressClass::Metadata))
        );
        assert!(check_destination(v4("1.1.1.1"), 443, EgressProfile::REMOTE, &[]).is_ok());
    }

    #[test]
    fn port_allowlist_is_enforced_when_present() {
        assert!(check_destination(v4("1.1.1.1"), 443, EgressProfile::REMOTE, &[443]).is_ok());
        assert_eq!(
            check_destination(v4("1.1.1.1"), 22, EgressProfile::REMOTE, &[443]),
            Err(EgressDenial::PortNotPermitted(22))
        );
        // An empty list means no port restriction.
        assert!(check_destination(v4("1.1.1.1"), 22, EgressProfile::REMOTE, &[]).is_ok());
    }

    #[test]
    fn host_syntax_validation() {
        for host in [
            "api.openai.com",
            "localhost",
            "a",
            "127.0.0.1",
            "[::1]",
            "sub-domain.example.co.uk",
            "host_with_underscore",
        ] {
            assert!(is_valid_host(host), "{host} should be valid");
        }
        for host in [
            "",
            "user@host",
            "host/path",
            "host:8080",
            "host?query",
            "host#frag",
            ".leading",
            "trailing.",
            "double..dot",
            "-leading-hyphen.example",
            "trailing-hyphen-.example",
            "has space",
            "[not-ipv6]",
            "héllo.example",
        ] {
            assert!(!is_valid_host(host), "{host} should be invalid");
        }
        assert!(!is_valid_host(&"a".repeat(254)));
        assert!(!is_valid_host(&format!("{}.example", "a".repeat(64))));
    }

    #[test]
    fn class_names_are_distinct() {
        let classes = [
            AddressClass::Loopback,
            AddressClass::Unspecified,
            AddressClass::LinkLocal,
            AddressClass::Metadata,
            AddressClass::Private,
            AddressClass::SharedAddressSpace,
            AddressClass::Multicast,
            AddressClass::Broadcast,
            AddressClass::Reserved,
            AddressClass::Global,
        ];
        let mut names: Vec<&str> = classes.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }
}
