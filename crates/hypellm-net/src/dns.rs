//! A bounded, deadline-bearing name resolver.
//!
//! Specification 3.2: "Blocking DNS, filesystem synchronization, configuration
//! compaction, and audit export MUST run on bounded worker pools" and "No
//! request may create an unbounded thread, task, buffer, channel, retry loop,
//! or log entry."
//!
//! The platform resolver is a blocking call with no timeout of its own.
//! `getaddrinfo` against an unreachable nameserver can sit for tens of seconds,
//! and calling it from the request thread means one slow zone stalls a worker
//! for as long as the operating system feels like it — with no deadline, no
//! cancellation, and no bound on how many workers end up stuck there at once.
//!
//! This module puts a fixed number of threads between the request path and the
//! resolver:
//!
//! ```text
//!  request thread                      pool (N threads)
//!       │  submit(host, port) ─────────▶ getaddrinfo (blocking)
//!       │                                     │
//!       └── recv_timeout(deadline) ◀──────────┘
//!             │
//!             └─ on timeout: give up on *waiting*, not on the lookup
//! ```
//!
//! A lookup in progress cannot be cancelled — the operating system offers no
//! way to abort `getaddrinfo` — so the pool bounds the damage instead. The
//! request thread stops waiting at its deadline and returns an error; the
//! worker finishes in its own time and discards the answer. The queue is
//! bounded too: when every worker is stuck and the queue is full, a new lookup
//! is refused immediately rather than joining an unbounded backlog, which is
//! the behaviour specification 3.2 asks for and the one that keeps a DNS
//! outage from becoming a router outage.

use crate::egress::{Resolve, SystemResolver};
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One lookup request handed to the pool.
struct Job {
    host: String,
    port: u16,
    reply: SyncSender<io::Result<Vec<SocketAddr>>>,
}

/// A name resolver backed by a fixed thread pool.
#[derive(Debug)]
pub struct PooledResolver {
    submit: SyncSender<Job>,
    timeout: Duration,
}

impl PooledResolver {
    /// Default worker count.
    ///
    /// Four is enough to keep several distinct upstream zones resolving
    /// concurrently while staying far below the point where blocked
    /// `getaddrinfo` calls become the dominant resource.
    pub const DEFAULT_WORKERS: usize = 4;

    /// Default queued lookups.
    ///
    /// Small on purpose. A deep queue only delays the moment a caller learns
    /// that resolution is not working, and every queued entry is a request
    /// already burning its deadline.
    pub const DEFAULT_QUEUE: usize = 32;

    /// Default per-lookup deadline.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Build a pool around the platform resolver.
    #[must_use]
    pub fn system(workers: usize, queue: usize, timeout: Duration) -> Self {
        Self::with_inner(Box::new(SystemResolver), workers, queue, timeout)
    }

    /// Build a pool around any resolver.
    #[must_use]
    pub fn with_inner(
        inner: Box<dyn Resolve>,
        workers: usize,
        queue: usize,
        timeout: Duration,
    ) -> Self {
        let (submit, receive) = sync_channel::<Job>(queue.max(1));
        let receive = Arc::new(Mutex::new(receive));
        let inner: Arc<dyn Resolve> = Arc::from(inner);

        for index in 0..workers.max(1) {
            let receive: Arc<Mutex<Receiver<Job>>> = Arc::clone(&receive);
            let inner = Arc::clone(&inner);
            // A named thread so a stuck resolver is identifiable in a stack
            // dump rather than appearing as an anonymous blocked thread.
            let spawned = std::thread::Builder::new()
                .name(format!("hypellm-dns-{index}"))
                .spawn(move || {
                    loop {
                        // The guard is dropped before the lookup, so one worker
                        // blocking in `getaddrinfo` does not hold the queue
                        // closed against the others.
                        let job = {
                            let Ok(guard) = receive.lock() else {
                                return;
                            };
                            match guard.recv() {
                                Ok(job) => job,
                                // Every sender is gone: the router is shutting
                                // down.
                                Err(_) => return,
                            }
                        };

                        let answer = inner.lookup(&job.host, job.port);
                        // The caller may have stopped waiting. That is the
                        // normal timeout path, not an error.
                        let _ = job.reply.try_send(answer);
                    }
                });
            if spawned.is_err() {
                // A router that cannot spawn its resolver workers will fail
                // later in a more confusing place; there is nothing useful to
                // do here beyond continuing with fewer workers.
                break;
            }
        }

        Self { submit, timeout }
    }

    /// The configured per-lookup deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for PooledResolver {
    fn default() -> Self {
        Self::system(
            Self::DEFAULT_WORKERS,
            Self::DEFAULT_QUEUE,
            Self::DEFAULT_TIMEOUT,
        )
    }
}

impl Resolve for PooledResolver {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        // Capacity one: the reply is used once, and a bounded sender lets the
        // worker discard the answer without blocking when the caller has
        // already timed out.
        let (reply, answer) = sync_channel::<io::Result<Vec<SocketAddr>>>(1);

        self.submit
            .try_send(Job {
                host: host.to_owned(),
                port,
                reply,
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the resolver pool is saturated; name resolution is not keeping up",
                )
            })?;

        match answer.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "name resolution did not complete within its deadline",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// A resolver that answers after `delay`.
    #[derive(Debug)]
    struct SlowResolver {
        delay: Duration,
    }

    impl Resolve for SlowResolver {
        fn lookup(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            std::thread::sleep(self.delay);
            Ok(vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)])
        }
    }

    #[derive(Debug)]
    struct FailingResolver;

    impl Resolve for FailingResolver {
        fn lookup(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        }
    }

    #[test]
    fn a_prompt_lookup_returns_its_answer() {
        let pool = PooledResolver::with_inner(
            Box::new(SlowResolver { delay: Duration::from_millis(1) }),
            2,
            8,
            Duration::from_secs(2),
        );
        let addresses = pool.lookup("api.example", 443).expect("resolves");
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses.first().expect("one address").port(), 443);
    }

    #[test]
    fn a_slow_lookup_is_abandoned_at_the_deadline() {
        // The property that matters: the *caller* stops waiting. Without this
        // a stalled nameserver holds a request thread for as long as the
        // operating system takes to give up, which can be tens of seconds.
        let pool = PooledResolver::with_inner(
            Box::new(SlowResolver { delay: Duration::from_secs(30) }),
            1,
            4,
            Duration::from_millis(100),
        );

        let started = std::time::Instant::now();
        let error = pool.lookup("slow.example", 443).expect_err("must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the caller waited {:?}, far past its deadline",
            started.elapsed()
        );
    }

    #[test]
    fn a_saturated_pool_refuses_rather_than_queueing_without_bound() {
        // One worker, a queue of one, and a resolver that never finishes in
        // time. Once both are occupied, further lookups must fail fast rather
        // than accumulate.
        let pool = PooledResolver::with_inner(
            Box::new(SlowResolver { delay: Duration::from_secs(30) }),
            1,
            1,
            Duration::from_millis(50),
        );

        // Occupy the worker.
        let busy = std::thread::spawn({
            let _ = &pool;
            || {}
        });
        let _ = busy.join();

        let mut saturated = false;
        for _ in 0..8 {
            match pool.lookup("slow.example", 443) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert!(
            saturated,
            "a pool with one worker and a queue of one must eventually refuse"
        );
    }

    #[test]
    fn a_lookup_failure_is_reported_as_itself() {
        let pool = PooledResolver::with_inner(
            Box::new(FailingResolver),
            1,
            4,
            Duration::from_secs(1),
        );
        let error = pool.lookup("nope.example", 443).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn several_lookups_proceed_concurrently() {
        // Two workers must overlap two slow lookups rather than serialising
        // them; otherwise the pool is a bottleneck rather than a bound.
        let pool = Arc::new(PooledResolver::with_inner(
            Box::new(SlowResolver { delay: Duration::from_millis(200) }),
            2,
            8,
            Duration::from_secs(2),
        ));

        let started = std::time::Instant::now();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || pool.lookup("api.example", 443))
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread").expect("resolves");
        }

        assert!(
            started.elapsed() < Duration::from_millis(350),
            "two workers serialised two lookups: {:?}",
            started.elapsed()
        );
    }
}
