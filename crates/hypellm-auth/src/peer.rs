//! Local peer credentials and trusted-edge identity.
//!
//! Specification 9.2:
//!
//! | Method | Rules |
//! |---|---|
//! | mTLS identity | "Identity from verified certificate/SPIFFE-like URI supplied only by trusted edge." |
//! | Local peer credentials | "Unix socket peer UID/GID mapped to principal." |
//!
//! # Why forwarded identity headers are dangerous by default
//!
//! Specification 3 says the edge boundary "never trusts inbound forwarding
//! headers except from configured peers". An `X-Forwarded-Client-Cert` header
//! is authentication if and only if it came from the edge and could not have
//! come from anywhere else. [`TrustedEdge`] makes that explicit: the header is
//! read only when the connection arrived on a listener marked as edge-facing
//! *and* from a configured peer address. On any other listener the header is
//! ignored entirely rather than being treated as a hint.

use hypellm_core::ids::{PrincipalId, TenantId};
use core::fmt;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// An identity established by the transport rather than by a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The principal.
    pub principal: PrincipalId,
    /// The tenant.
    pub tenant: TenantId,
    /// How the identity was established, for the audit record.
    pub source: PeerSource,
}

/// Where a peer identity came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSource {
    /// A Unix socket peer's numeric user identifier.
    UnixUid(u32),
    /// A workload identity forwarded by the trusted edge.
    EdgeWorkload(String),
}

impl fmt::Display for PeerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnixUid(uid) => write!(f, "unix:{uid}"),
            Self::EdgeWorkload(id) => write!(f, "edge:{id}"),
        }
    }
}

/// Maps Unix peer identifiers to principals.
///
/// The mapping is explicit configuration. There is no rule like "uid 0 is
/// admin": a numeric identifier means nothing until an administrator says what
/// it means.
#[derive(Debug, Default)]
pub struct PeerMap {
    by_uid: BTreeMap<u32, PeerIdentity>,
}

impl PeerMap {
    /// An empty map. With no entries, no peer authenticates.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a user identifier to a principal.
    pub fn insert(&mut self, uid: u32, principal: PrincipalId, tenant: TenantId) {
        self.by_uid.insert(
            uid,
            PeerIdentity {
                principal,
                tenant,
                source: PeerSource::UnixUid(uid),
            },
        );
    }

    /// Resolve a user identifier.
    #[must_use]
    pub fn resolve(&self, uid: u32) -> Option<PeerIdentity> {
        self.by_uid.get(&uid).cloned()
    }

    /// How many mappings exist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_uid.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_uid.is_empty()
    }
}

/// The policy governing identity headers forwarded by an edge.
#[derive(Debug, Clone, Default)]
pub struct TrustedEdge {
    /// Peer addresses whose forwarded headers are believed.
    ///
    /// Empty means no forwarded identity is ever accepted, which is the
    /// default and the correct setting for a router not behind an
    /// identity-aware edge.
    pub trusted_peers: Vec<IpAddr>,
    /// The header carrying the workload identity.
    pub identity_header: String,
    /// Workload identities that may be accepted, and what they map to.
    pub workloads: BTreeMap<String, (PrincipalId, TenantId)>,
}

impl TrustedEdge {
    /// A policy that trusts nothing.
    #[must_use]
    pub fn none() -> Self {
        Self {
            trusted_peers: Vec::new(),
            identity_header: String::new(),
            workloads: BTreeMap::new(),
        }
    }

    /// Whether a peer's forwarded headers are trusted.
    #[must_use]
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        match peer {
            None => false,
            Some(addr) => self.trusted_peers.contains(&addr),
        }
    }

    /// Resolve a forwarded workload identity.
    ///
    /// Returns `None` unless *both* the peer is trusted and the identity is one
    /// the administrator declared. An unknown identity from a trusted edge is
    /// still refused: the edge authenticates the workload, but the router
    /// decides which workloads exist.
    #[must_use]
    pub fn resolve(&self, peer: Option<IpAddr>, header_value: Option<&str>) -> Option<PeerIdentity> {
        if !self.trusts(peer) {
            return None;
        }
        let value = header_value?;
        if value.is_empty() || value.len() > 256 {
            return None;
        }
        let (principal, tenant) = self.workloads.get(value)?;
        Some(PeerIdentity {
            principal: principal.clone(),
            tenant: tenant.clone(),
            source: PeerSource::EdgeWorkload(value.to_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(s: &str) -> PrincipalId {
        PrincipalId::new(s).unwrap()
    }
    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    #[test]
    fn an_empty_peer_map_authenticates_nobody() {
        let map = PeerMap::new();
        assert!(map.is_empty());
        assert_eq!(map.resolve(0), None);
        assert_eq!(map.resolve(1000), None);
    }

    #[test]
    fn peer_identifiers_resolve_only_when_mapped() {
        let mut map = PeerMap::new();
        map.insert(1000, principal("user:local"), tenant());

        let identity = map.resolve(1000).expect("mapped");
        assert_eq!(identity.principal.as_str(), "user:local");
        assert_eq!(identity.source, PeerSource::UnixUid(1000));
        assert_eq!(identity.source.to_string(), "unix:1000");

        // Root is not special.
        assert_eq!(map.resolve(0), None);
        assert_eq!(map.resolve(1001), None);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn no_forwarded_identity_is_trusted_by_default() {
        // The default policy is the safe one: a forwarded header means nothing.
        let edge = TrustedEdge::none();
        assert!(!edge.trusts(Some("10.0.0.1".parse().unwrap())));
        assert_eq!(
            edge.resolve(Some("10.0.0.1".parse().unwrap()), Some("workload-a")),
            None
        );
    }

    #[test]
    fn a_forwarded_identity_needs_a_trusted_peer_and_a_declared_workload() {
        let trusted: IpAddr = "10.0.0.1".parse().unwrap();
        let untrusted: IpAddr = "10.0.0.2".parse().unwrap();
        let mut edge = TrustedEdge {
            trusted_peers: vec![trusted],
            identity_header: "x-forwarded-workload".to_owned(),
            workloads: BTreeMap::new(),
        };
        edge.workloads.insert(
            "spiffe://cluster/ns/default/sa/ci".to_owned(),
            (principal("svc:ci"), tenant()),
        );

        // Trusted peer, declared workload.
        let identity = edge
            .resolve(Some(trusted), Some("spiffe://cluster/ns/default/sa/ci"))
            .expect("resolves");
        assert_eq!(identity.principal.as_str(), "svc:ci");

        // Same header from an untrusted peer: refused. This is the header
        // spoofing case — a client sending it directly.
        assert_eq!(
            edge.resolve(Some(untrusted), Some("spiffe://cluster/ns/default/sa/ci")),
            None
        );
        assert_eq!(
            edge.resolve(None, Some("spiffe://cluster/ns/default/sa/ci")),
            None
        );

        // Trusted peer, undeclared workload: still refused.
        assert_eq!(edge.resolve(Some(trusted), Some("spiffe://cluster/ns/x/sa/y")), None);

        // Trusted peer, no header.
        assert_eq!(edge.resolve(Some(trusted), None), None);
    }

    #[test]
    fn forwarded_identity_values_are_bounded() {
        let trusted: IpAddr = "10.0.0.1".parse().unwrap();
        let edge = TrustedEdge {
            trusted_peers: vec![trusted],
            identity_header: "x-workload".to_owned(),
            workloads: BTreeMap::new(),
        };
        assert_eq!(edge.resolve(Some(trusted), Some("")), None);
        assert_eq!(edge.resolve(Some(trusted), Some(&"a".repeat(1000))), None);
    }
}
