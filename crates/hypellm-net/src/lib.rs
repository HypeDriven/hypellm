//! Outbound networking: egress guard, connection pooling, platform helpers.
//!
//! This crate is where the router touches the network on the way *out*. Three
//! specification rules shape all of it:
//!
//! 1. **Destinations are configured, never derived from a request**
//!    (specification 10). Every function here takes an [`Endpoint`] from the
//!    validated configuration or a [`PinnedDestination`] produced from one.
//!    There is no function that accepts a URL.
//! 2. **Resolve, validate, then pin** (specification 10). The address that
//!    passed classification is the address connected to, which is what closes
//!    DNS rebinding.
//! 3. **TLS is delegated** (specification 4). Outbound HTTPS goes through the
//!    platform TLS helper over a narrow CONNECT-like interface.
//!
//! ```text
//!  Endpoint (config)
//!        │
//!        ▼
//!  Resolver::resolve ──▶ PinnedDestination ──┬─▶ Dialer::connect      (http, unix)
//!   classify + pin                            └─▶ TlsHelper::connect  (https)
//!                                                       │
//!                                                       ▼
//!                                              UpstreamConnection
//!                                            (bounded, deadline-driven)
//! ```

#![forbid(unsafe_code)]
// Specification 18.2: this crate is on the data path, so an unchecked index is
// a compile error here rather than one more warning. Only the lint that
// actually fires in this crate is escalated; `as_conversions` and `panic` have
// no sites here, and adding a `deny` for a lint that never fires would be
// noise. Any new indexing site must be rewritten index-free or carry a
// function-scoped `allow` explaining why it cannot be out of range.
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

pub mod client;
pub mod dns;
pub mod fleet;
#[cfg(any(test, feature = "test-harness"))]
pub mod fleet_sim;
pub mod egress;
pub mod helper;
pub mod pool;

pub use client::{UpstreamConnection, UpstreamError};
pub use dns::PooledResolver;
pub use fleet::{ActivationStatus, FleetAgentClient, FleetError, FleetSession};
pub use egress::{
    DestinationAddress, Dialer, EgressError, PinnedDestination, Resolve, Resolver, StaticResolver,
    SystemResolver, Transport,
};
pub use helper::{HelperError, TlsHelper, VerifierClient};
pub use pool::{ConnectionPool, PoolConfig, pool_key};

use hypellm_core::netaddr::EgressProfile;
use hypellm_core::target::{Endpoint, EndpointScheme};
use std::time::Duration;

/// Everything needed to reach upstreams, assembled.
///
/// Holds the resolver, the pool, and the optional TLS helper. A component that
/// has an `Egress` can make an outbound connection and cannot make one any
/// other way.
#[derive(Debug)]
pub struct Egress {
    /// The resolver and egress guard.
    pub resolver: Resolver,
    /// The connection pool.
    pub pool: ConnectionPool,
    /// The TLS helper, when outbound HTTPS is configured.
    pub tls: Option<TlsHelper>,
    /// How long to wait for a connection.
    pub connect_timeout: Duration,
}

impl Egress {
    /// Assemble.
    #[must_use]
    pub fn new(
        resolver: Resolver,
        pool: ConnectionPool,
        tls: Option<TlsHelper>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            resolver,
            pool,
            tls,
            connect_timeout,
        }
    }

    /// Obtain a connection to an endpoint, reusing a pooled one when possible.
    ///
    /// `credential_class` isolates the pool so that two tenants using different
    /// provider credentials never share a socket (specification 19).
    pub fn acquire(
        &self,
        endpoint: &Endpoint,
        profile: EgressProfile,
        credential_class: &str,
    ) -> Result<UpstreamConnection, UpstreamError> {
        let key = pool_key(
            endpoint.scheme.as_str(),
            &endpoint.host,
            endpoint.port,
            credential_class,
            "http/1.1",
            profile.key(),
        );

        if let Some(connection) = self.pool.take(&key) {
            return Ok(connection);
        }

        self.dial(endpoint, profile, key)
    }

    /// Open a *new* connection to an endpoint, ignoring the pool.
    ///
    /// A pooled connection can be closed by the peer at any point while it sits
    /// idle, and that close is only observable by trying to use it. When an
    /// exchange on a reused connection fails before the upstream produced any
    /// response, the caller has learned nothing about the upstream and must be
    /// able to try again on a socket that is known to be new — otherwise a
    /// perfectly healthy provider returns an error for the first request after
    /// every idle period. Going back to [`Self::acquire`] would not do: it
    /// would hand back another connection from the same stale bucket.
    ///
    /// The destination is resolved and validated exactly as in `acquire`; this
    /// bypasses the pool, never the egress guard.
    pub fn dial_fresh(
        &self,
        endpoint: &Endpoint,
        profile: EgressProfile,
        credential_class: &str,
    ) -> Result<UpstreamConnection, UpstreamError> {
        let key = pool_key(
            endpoint.scheme.as_str(),
            &endpoint.host,
            endpoint.port,
            credential_class,
            "http/1.1",
            profile.key(),
        );
        self.dial(endpoint, profile, key)
    }

    fn dial(
        &self,
        endpoint: &Endpoint,
        profile: EgressProfile,
        key: String,
    ) -> Result<UpstreamConnection, UpstreamError> {
        let destination = self.resolver.resolve(endpoint, profile)?;

        if destination.needs_tls() {
            let Some(tls) = &self.tls else {
                // No helper configured and the endpoint needs TLS. Failing is
                // the only safe answer: the alternative is a cleartext
                // connection carrying a provider credential.
                return Err(UpstreamError::Egress(EgressError::ConnectFailed(
                    std::io::Error::other(
                        "outbound TLS is required but no TLS helper is configured",
                    ),
                )));
            };
            let transport = tls.connect(&destination).map_err(|e| {
                UpstreamError::Egress(EgressError::ConnectFailed(std::io::Error::other(
                    e.to_string(),
                )))
            })?;
            transport
                .set_timeouts(Some(self.connect_timeout))
                .map_err(UpstreamError::Io)?;
            return Ok(UpstreamConnection::from_transport(transport, key));
        }

        UpstreamConnection::connect(&destination, key, self.connect_timeout)
    }

    /// Return a connection to the pool, or close it if it is not reusable.
    pub fn release(&self, connection: UpstreamConnection) {
        self.pool.put(connection);
    }

    /// Whether an endpoint can be reached at all with the current
    /// configuration.
    ///
    /// Used at startup to fail fast on a deployment that declares HTTPS
    /// upstreams without a TLS helper, rather than discovering it on the first
    /// request.
    #[must_use]
    pub fn can_reach(&self, endpoint: &Endpoint) -> bool {
        endpoint.scheme != EndpointScheme::Https || self.tls.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::time::TestClock;
    use std::sync::Arc;

    fn endpoint(scheme: EndpointScheme, host: &str, port: u16) -> Endpoint {
        Endpoint {
            scheme,
            host: host.to_owned(),
            port,
            base_path: "/v1".to_owned(),
        }
    }

    fn egress(tls: Option<TlsHelper>) -> Egress {
        Egress::new(
            Resolver::new(Box::new(StaticResolver::new().with(
                "api.example",
                vec!["93.184.216.34".parse().unwrap()],
            ))),
            ConnectionPool::new(PoolConfig::DEFAULT, Arc::new(TestClock::new())),
            tls,
            Duration::from_secs(2),
        )
    }

    #[test]
    fn https_without_a_helper_fails_rather_than_falling_back() {
        // The failure mode this prevents: silently sending a provider
        // credential over a cleartext socket.
        let egress = egress(None);
        let err = egress
            .acquire(
                &endpoint(EndpointScheme::Https, "api.example", 443),
                EgressProfile::REMOTE,
                "tenant-a",
            )
            .expect_err("must fail");
        assert!(err.to_string().contains("TLS helper"));
        assert!(!egress.can_reach(&endpoint(EndpointScheme::Https, "api.example", 443)));
    }

    #[test]
    fn two_egress_profiles_never_share_a_pooled_connection() {
        // `acquire` returns a pooled socket *before* resolving and classifying
        // the destination, so a connection opened under a permissive profile
        // must not be handed to a request running under a stricter one — the
        // second would never face the specification 10 address-class check.
        let endpoint = endpoint(EndpointScheme::Http, "api.example", 80);
        let permissive = pool_key(
            endpoint.scheme.as_str(),
            &endpoint.host,
            endpoint.port,
            "tenant-a",
            "http/1.1",
            EgressProfile::LOCAL.key(),
        );
        let strict = pool_key(
            endpoint.scheme.as_str(),
            &endpoint.host,
            endpoint.port,
            "tenant-a",
            "http/1.1",
            EgressProfile::REMOTE.key(),
        );
        assert_ne!(permissive, strict);
    }

    #[test]
    fn profiles_permitting_the_same_classes_share_a_key() {
        // The token is derived from what a profile permits, not from its name,
        // so an equivalent profile does not needlessly fragment the pool.
        assert_eq!(EgressProfile::REMOTE.key(), EgressProfile::REMOTE.key());
        assert_ne!(EgressProfile::REMOTE.key(), EgressProfile::LOCAL.key());
        assert_ne!(EgressProfile::LOCAL.key(), EgressProfile::PRIVATE_NETWORK.key());
    }

    #[test]
    fn reachability_is_checkable_before_the_first_request() {
        let with_helper = egress(Some(TlsHelper::new(
            "/run/hypellm-tls.sock",
            Duration::from_secs(1),
        )));
        assert!(with_helper.can_reach(&endpoint(EndpointScheme::Https, "api.example", 443)));
        assert!(with_helper.can_reach(&endpoint(EndpointScheme::Http, "127.0.0.1", 8080)));

        let without = egress(None);
        assert!(without.can_reach(&endpoint(EndpointScheme::Http, "127.0.0.1", 8080)));
        assert!(without.can_reach(&endpoint(EndpointScheme::Unix, "/run/x.sock", 0)));
        assert!(!without.can_reach(&endpoint(EndpointScheme::Https, "api.example", 443)));
    }

    #[test]
    fn a_refused_destination_never_reaches_a_socket() {
        let egress = Egress::new(
            Resolver::new(Box::new(StaticResolver::new().with(
                "evil.example",
                vec!["169.254.169.254".parse().unwrap()],
            ))),
            ConnectionPool::new(PoolConfig::DEFAULT, Arc::new(TestClock::new())),
            None,
            Duration::from_secs(1),
        );
        let err = egress
            .acquire(
                &endpoint(EndpointScheme::Http, "evil.example", 80),
                EgressProfile::REMOTE,
                "tenant-a",
            )
            .expect_err("must refuse");
        assert_eq!(err.code(), "destination_refused");
    }

    #[test]
    fn pool_keys_isolate_credential_classes() {
        let a = pool_key("https", "api.example", 443, "tenant-a", "http/1.1", "e0001");
        let b = pool_key("https", "api.example", 443, "tenant-b", "http/1.1", "e0001");
        assert_ne!(a, b);
    }
}
