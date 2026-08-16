//! Connection pooling.
//!
//! Specification 19: "Pools keyed by exact endpoint, TLS identity/profile,
//! credential isolation class, and protocol. **No cross-tenant reuse where auth
//! binding is unsafe.**"
//!
//! The credential isolation class is part of the key, so two tenants using
//! different provider credentials against the same endpoint never share a
//! socket. Where a provider binds authentication to the connection rather than
//! to the request — and some do — sharing would let one tenant's request go out
//! under another's credential.
//!
//! A connection is returned to the pool only if the exchange left it in a known
//! state: a complete response, no `Connection: close`, no protocol error. A
//! connection whose framing is in doubt is closed, because reusing it is how a
//! desynchronised response becomes the next caller's answer.

use crate::client::UpstreamConnection;
use hypellm_core::time::Clock;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Pool limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Maximum idle connections per key.
    pub max_idle_per_key: usize,
    /// Maximum idle connections overall.
    pub max_idle_total: usize,
    /// How long an idle connection may sit before being closed.
    pub idle_timeout_millis: u64,
}

impl PoolConfig {
    /// Reasonable defaults for a gateway with a handful of upstreams.
    pub const DEFAULT: Self = Self {
        max_idle_per_key: 32,
        max_idle_total: 512,
        idle_timeout_millis: 60_000,
    };
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug)]
struct Idle {
    connection: UpstreamConnection,
    since_millis: u64,
}

/// A pool of reusable upstream connections.
#[derive(Debug)]
pub struct ConnectionPool {
    config: PoolConfig,
    clock: Arc<dyn Clock>,
    idle: Mutex<BTreeMap<String, Vec<Idle>>>,
}

impl ConnectionPool {
    /// Create a pool.
    #[must_use]
    pub fn new(config: PoolConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            idle: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<Idle>>> {
        match self.idle.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Take an idle connection for `key`, if one is available and fresh.
    pub fn take(&self, key: &str) -> Option<UpstreamConnection> {
        let now = self.clock.now_millis();
        let mut idle = self.lock();
        let bucket = idle.get_mut(key)?;

        while let Some(entry) = bucket.pop() {
            let stale = now.saturating_sub(entry.since_millis) >= self.config.idle_timeout_millis;
            if stale || !entry.connection.is_reusable() {
                let mut connection = entry.connection;
                connection.close();
                continue;
            }
            // The caller has to be able to tell a reused socket from a fresh
            // one: only the reused one can fail because the peer closed it
            // while it was idle, which is a failure of the pool rather than of
            // the upstream and must not be reported as one.
            let mut connection = entry.connection;
            connection.mark_pooled();
            return Some(connection);
        }
        None
    }

    /// Return a connection to the pool.
    ///
    /// A connection that is not reusable is closed here rather than stored, so
    /// a caller cannot accidentally pool a desynchronised socket.
    pub fn put(&self, mut connection: UpstreamConnection) {
        if !connection.is_reusable() {
            connection.close();
            return;
        }
        let now = self.clock.now_millis();
        let key = connection.pool_key().to_owned();
        let mut idle = self.lock();

        let total: usize = idle.values().map(Vec::len).sum();
        if total >= self.config.max_idle_total {
            connection.close();
            return;
        }

        let bucket = idle.entry(key).or_default();
        if bucket.len() >= self.config.max_idle_per_key {
            connection.close();
            return;
        }
        bucket.push(Idle {
            connection,
            since_millis: now,
        });
    }

    /// Close connections idle beyond the timeout.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now_millis();
        let mut idle = self.lock();
        let mut closed = 0usize;
        for bucket in idle.values_mut() {
            let mut keep = Vec::with_capacity(bucket.len());
            for entry in bucket.drain(..) {
                if now.saturating_sub(entry.since_millis) >= self.config.idle_timeout_millis {
                    let mut connection = entry.connection;
                    connection.close();
                    closed += 1;
                } else {
                    keep.push(entry);
                }
            }
            *bucket = keep;
        }
        idle.retain(|_, b| !b.is_empty());
        closed
    }

    /// Close every idle connection, for shutdown or credential rotation.
    ///
    /// Specification 22.2 step 17: "Drain/recycle connections whose
    /// authentication is connection-bound."
    pub fn drain(&self) -> usize {
        let mut idle = self.lock();
        let mut closed = 0usize;
        for (_, bucket) in idle.iter_mut() {
            for entry in bucket.drain(..) {
                let mut connection = entry.connection;
                connection.close();
                closed += 1;
            }
        }
        idle.clear();
        closed
    }

    /// Close idle connections for one key, for a single credential rotation.
    pub fn drain_key(&self, key: &str) -> usize {
        let mut idle = self.lock();
        let Some(bucket) = idle.remove(key) else {
            return 0;
        };
        let count = bucket.len();
        for entry in bucket {
            let mut connection = entry.connection;
            connection.close();
        }
        count
    }

    /// Close every idle connection whose pool key satisfies `matches`.
    ///
    /// Returns how many were closed. The predicate form rather than an exact
    /// key, because a credential is one *component* of the key
    /// (`pool_key`: scheme, host, port, credential class, protocol, egress
    /// profile) — draining "everything opened under this credential" means
    /// matching a component, not a whole key, and the caller is the only one
    /// that knows how its component is spelled.
    ///
    /// Only *idle* connections are closed. One currently serving a request is
    /// left alone: it was authenticated under the old credential, its exchange
    /// is already in flight, and killing it mid-response would turn a rotation
    /// into a client-visible failure. It is poisoned or returned to the pool
    /// when it finishes, and a returned one no longer matches anything the next
    /// drain would find, because the next request rebuilds the key.
    pub fn drain_where(&self, matches: impl Fn(&str) -> bool) -> usize {
        let mut idle = self.lock();
        let keys: Vec<String> = idle
            .keys()
            .filter(|key| matches(key))
            .cloned()
            .collect();
        let mut closed = 0;
        for key in keys {
            let Some(bucket) = idle.remove(&key) else {
                continue;
            };
            closed += bucket.len();
            for entry in bucket {
                let mut connection = entry.connection;
                connection.close();
            }
        }
        closed
    }

    /// How many idle connections are held.
    #[must_use]
    pub fn idle_count(&self) -> usize {
        self.lock().values().map(Vec::len).sum()
    }

    /// How many idle connections are held for one key.
    #[must_use]
    pub fn idle_count_for(&self, key: &str) -> usize {
        self.lock().get(key).map_or(0, Vec::len)
    }
}

/// Build a pool key.
///
/// Specification 19's four components — endpoint, TLS profile, credential
/// isolation class, protocol — plus the egress profile.
///
/// The egress profile belongs in the key because a pool hit returns a socket
/// *before* [`Egress::acquire`] resolves and classifies the destination. Two
/// requests to the same host under different profiles would otherwise share a
/// connection, and the second would never face the address-class check that
/// specification 10 requires. Keying on the profile means a connection can only
/// be reused under the profile it was opened for.
#[must_use]
pub fn pool_key(
    scheme: &str,
    host: &str,
    port: u16,
    credential_class: &str,
    protocol: &str,
    egress_profile: &str,
) -> String {
    format!("{scheme}|{host}|{port}|{credential_class}|{protocol}|{egress_profile}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn draining_by_credential_closes_only_that_credentials_sockets() {
        // Specification 22.2 step 17: "Drain/recycle connections whose
        // authentication is connection-bound." `drain_key` existed and was
        // called only from its own unit test; nothing rotated a credential and
        // then dropped the sockets opened under it.
        //
        // The predicate form matters: a credential is one *component* of the
        // pool key, so draining "everything opened under this credential" means
        // matching a component, and a whole-key API cannot express it.
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);
        let (destination, _listener) = holding_listener();
        let _ = &destination;

        let rotating = pool_key("http", "a.example", 80, "5:acme:4:cred", "http1", "remote");
        let other = pool_key("http", "a.example", 80, "5:acme:5:other", "http1", "remote");
        let same_credential_other_tenant =
            pool_key("http", "a.example", 80, "6:globex:4:cred", "http1", "remote");

        for key in [&rotating, &other, &same_credential_other_tenant] {
            pool.put(connect(&destination, key));
        }
        assert_eq!(pool.idle_count(), 3);

        // Every tenant's sockets for this credential, and no others.
        let suffix = format!(":{}:{}", "cred".len(), "cred");
        let drained = pool.drain_where(|key| {
            key.split('|')
                .nth(3)
                .is_some_and(|class| class.ends_with(&suffix))
        });
        assert_eq!(drained, 2, "both tenants' sockets for `cred` must close");
        assert_eq!(pool.idle_count(), 1, "the unrelated credential is untouched");
    }

    #[test]
    fn draining_matches_nothing_when_no_key_qualifies() {
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);
        assert_eq!(pool.drain_where(|_| true), 0);
        assert_eq!(pool.drain_where(|_| false), 0);
    }

    use super::*;
    use crate::egress::{DestinationAddress, PinnedDestination};
    use hypellm_core::time::TestClock;
    use std::net::TcpListener;
    use std::time::Duration;

    /// A listener that accepts and holds connections, so pooled sockets stay
    /// genuinely open.
    fn holding_listener() -> (PinnedDestination, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().take(64) {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        (
            PinnedDestination::for_tests(DestinationAddress::Socket(addr), "127.0.0.1", None, false),
            handle,
        )
    }

    fn connect(destination: &PinnedDestination, key: &str) -> UpstreamConnection {
        UpstreamConnection::connect(destination, key.to_owned(), Duration::from_secs(5))
            .expect("connect")
    }

    #[test]
    fn a_returned_connection_is_reused() {
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);

        assert!(pool.take("k").is_none());
        pool.put(connect(&destination, "k"));
        assert_eq!(pool.idle_count(), 1);

        let taken = pool.take("k").expect("reuses");
        assert_eq!(taken.pool_key(), "k");
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn a_poisoned_connection_is_never_pooled() {
        // A connection whose framing is in doubt must not become the next
        // caller's socket.
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);

        let mut connection = connect(&destination, "k");
        connection.poison();
        pool.put(connection);
        assert_eq!(pool.idle_count(), 0);
        assert!(pool.take("k").is_none());
    }

    #[test]
    fn keys_isolate_credentials_and_endpoints() {
        // The cross-tenant reuse the specification forbids.
        let a = pool_key("https", "api.example", 443, "tenant-a", "http/1.1", "e0001");
        let b = pool_key("https", "api.example", 443, "tenant-b", "http/1.1", "e0001");
        assert_ne!(a, b);

        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);
        pool.put(connect(&destination, &a));

        assert!(
            pool.take(&b).is_none(),
            "tenant b must not receive tenant a's connection"
        );
        assert!(pool.take(&a).is_some());
    }

    #[test]
    fn keys_separate_every_component() {
        let base = pool_key("https", "api.example", 443, "c", "http/1.1", "e0001");
        assert_ne!(base, pool_key("http", "api.example", 443, "c", "http/1.1", "e0001"));
        assert_ne!(base, pool_key("https", "other.example", 443, "c", "http/1.1", "e0001"));
        assert_ne!(base, pool_key("https", "api.example", 8443, "c", "http/1.1", "e0001"));
        assert_ne!(base, pool_key("https", "api.example", 443, "d", "http/1.1", "e0001"));
        assert_ne!(base, pool_key("https", "api.example", 443, "c", "http/2", "e0001"));
        assert_ne!(base, pool_key("https", "api.example", 443, "c", "http/1.1", "e1000"));
    }

    #[test]
    fn idle_connections_expire() {
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, Arc::clone(&clock) as Arc<dyn Clock>);

        pool.put(connect(&destination, "k"));
        assert_eq!(pool.idle_count(), 1);

        clock.advance(PoolConfig::DEFAULT.idle_timeout_millis);
        assert!(pool.take("k").is_none(), "a stale connection must not be reused");
    }

    #[test]
    fn sweeping_closes_stale_connections() {
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, Arc::clone(&clock) as Arc<dyn Clock>);

        for _ in 0..3 {
            pool.put(connect(&destination, "k"));
        }
        assert_eq!(pool.sweep(), 0);
        clock.advance(PoolConfig::DEFAULT.idle_timeout_millis + 1);
        assert_eq!(pool.sweep(), 3);
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn the_pool_is_bounded_per_key_and_overall() {
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(
            PoolConfig {
                max_idle_per_key: 2,
                max_idle_total: 3,
                idle_timeout_millis: 60_000,
            },
            clock,
        );

        for _ in 0..5 {
            pool.put(connect(&destination, "a"));
        }
        assert_eq!(pool.idle_count_for("a"), 2, "per-key bound");

        for _ in 0..5 {
            pool.put(connect(&destination, "b"));
        }
        assert_eq!(pool.idle_count(), 3, "overall bound");
    }

    #[test]
    fn draining_closes_everything() {
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);

        pool.put(connect(&destination, "a"));
        pool.put(connect(&destination, "b"));
        assert_eq!(pool.drain(), 2);
        assert_eq!(pool.idle_count(), 0);
        assert!(pool.take("a").is_none());
    }

    #[test]
    fn draining_one_key_leaves_the_rest() {
        // Credential rotation for one provider must not close every connection.
        let (destination, _server) = holding_listener();
        let clock = Arc::new(TestClock::new());
        let pool = ConnectionPool::new(PoolConfig::DEFAULT, clock);

        pool.put(connect(&destination, "rotating"));
        pool.put(connect(&destination, "untouched"));

        assert_eq!(pool.drain_key("rotating"), 1);
        assert_eq!(pool.idle_count_for("rotating"), 0);
        assert_eq!(pool.idle_count_for("untouched"), 1);
        assert_eq!(pool.drain_key("nonexistent"), 0);
    }
}
