//! Atomic configuration activation.
//!
//! Specification 11: "The runtime … computes a digest, and swaps a single
//! shared pointer. Requests already in flight retain the prior snapshot.
//! Partial mutation is never visible."
//!
//! [`Activatable`] is that pointer. A reader takes the lock only long enough to
//! clone an `Arc` and then works from its own handle, so:
//!
//! - a request that started before an activation finishes against the snapshot
//!   it started with, which is what makes a decision trace reproducible;
//! - an activation never waits for in-flight requests to drain;
//! - no reader ever observes a half-built configuration, because the value
//!   behind the pointer is immutable and is fully constructed before the swap.
//!
//! Specification 19 targets "pointer swap < 1 ms". The swap here is an
//! `Arc` store under a write lock — bounded by the time a reader holds the read
//! lock, which is a single clone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// A value that can be replaced atomically while readers hold the old one.
#[derive(Debug)]
pub struct Activatable<T> {
    current: RwLock<Arc<T>>,
    /// Retained previous versions, newest first, for rollback.
    history: RwLock<Vec<Arc<T>>>,
    /// How many versions to retain.
    history_limit: usize,
    generation: AtomicU64,
}

impl<T> Activatable<T> {
    /// Create with an initial value.
    #[must_use]
    pub fn new(initial: T) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            history: RwLock::new(Vec::new()),
            history_limit: 8,
            generation: AtomicU64::new(0),
        }
    }

    /// Create with an initial value and a rollback depth.
    #[must_use]
    pub fn with_history(initial: T, history_limit: usize) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            history: RwLock::new(Vec::new()),
            history_limit,
            generation: AtomicU64::new(0),
        }
    }

    /// Take a handle to the current value.
    ///
    /// The returned `Arc` stays valid across any number of subsequent
    /// activations.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock means a writer panicked mid-swap. The value
            // behind the pointer is still a fully constructed snapshot — the
            // pointer is either the old one or the new one — so continuing with
            // it is correct, and refusing to route would be worse.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Replace the value, returning the one it replaced.
    pub fn activate(&self, next: T) -> Arc<T> {
        let next = Arc::new(next);
        let previous = {
            let mut guard = match self.current.write() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            core::mem::replace(&mut *guard, next)
        };
        self.generation.fetch_add(1, Ordering::SeqCst);

        if self.history_limit > 0 {
            if let Ok(mut history) = self.history.write() {
                history.insert(0, Arc::clone(&previous));
                history.truncate(self.history_limit);
            }
        }
        previous
    }

    /// The value a rollback would restore, without performing one.
    ///
    /// # Why there is no `rollback()` here
    ///
    /// There was one, and nothing called it. The management API restores a
    /// configuration by re-loading the previous *text* under a new version and
    /// activating that, rather than swapping the old object back in — because
    /// two different configurations must never share a version number, and
    /// `If-Match` ETags, `/health/ready`, and the overview are all derived from
    /// it.
    ///
    /// A swap-back method that reinstates the old version alongside this one
    /// would be a second, subtly different activation path that nothing uses,
    /// which is the shape of dead code most likely to be picked up by mistake.
    /// This accessor is what the real path needs, and is all of it that
    /// survived.
    ///
    /// A caller needs this to refuse cleanly: rolling back with nothing
    /// retained must be an error, not a silent no-op reported as success. And
    /// the durable record has to be written *before* the pointer swap, which
    /// means knowing what the swap will produce before committing to it.
    #[must_use]
    pub fn previous(&self) -> Option<Arc<T>> {
        self.history.read().ok()?.first().map(Arc::clone)
    }

    /// How many times the value has been replaced.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// How many previous versions are retained.
    #[must_use]
    pub fn history_depth(&self) -> usize {
        self.history.read().map_or(0, |h| h.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        version: u64,
        payload: String,
    }

    fn snapshot(version: u64) -> Snapshot {
        Snapshot {
            version,
            payload: format!("configuration v{version}"),
        }
    }

    #[test]
    fn load_returns_the_current_value() {
        let a = Activatable::new(snapshot(1));
        assert_eq!(a.load().version, 1);
        a.activate(snapshot(2));
        assert_eq!(a.load().version, 2);
        assert_eq!(a.generation(), 1);
    }

    #[test]
    fn an_in_flight_handle_survives_activation() {
        // The property that makes a decision trace reproducible: a request that
        // started under v1 finishes under v1.
        let a = Activatable::new(snapshot(1));
        let in_flight = a.load();

        a.activate(snapshot(2));
        a.activate(snapshot(3));

        assert_eq!(in_flight.version, 1, "the old handle must not change");
        assert_eq!(in_flight.payload, "configuration v1");
        assert_eq!(a.load().version, 3);
    }

    #[test]
    fn activate_returns_the_replaced_value() {
        let a = Activatable::new(snapshot(1));
        let previous = a.activate(snapshot(2));
        assert_eq!(previous.version, 1);
    }

    #[test]
    fn previous_reports_what_a_rollback_would_restore() {
        let a = Activatable::new(snapshot(1));
        a.activate(snapshot(2));
        a.activate(snapshot(3));
        assert_eq!(a.load().version, 3);

        // Peeking must not change anything: the management API writes the
        // durable activation frame *before* it swaps, so it has to know what
        // the swap will produce without committing to it.
        assert_eq!(a.previous().expect("history").version, 2);
        assert_eq!(a.load().version, 3, "peeking must not activate");
        assert_eq!(a.previous().expect("history").version, 2);
    }

    #[test]
    fn history_is_bounded() {
        let a = Activatable::with_history(snapshot(0), 3);
        for v in 1..=10 {
            a.activate(snapshot(v));
        }
        assert_eq!(a.history_depth(), 3);
        assert_eq!(a.load().version, 10);
        assert_eq!(a.previous().expect("history").version, 9);
    }

    #[test]
    fn history_can_be_disabled() {
        let a = Activatable::with_history(snapshot(0), 0);
        a.activate(snapshot(1));
        assert_eq!(a.history_depth(), 0);
        assert!(
            a.previous().is_none(),
            "with no history there is nothing to roll back to, and the API must refuse \
             rather than report a rollback that did not happen"
        );
    }

    #[test]
    fn readers_never_observe_a_torn_value() {
        // Many readers against a stream of activations: every value observed
        // must be internally consistent, never a mix of two versions.
        let a = Arc::new(Activatable::new(snapshot(0)));
        let barrier = Arc::new(Barrier::new(9));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&a);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..2_000 {
                    let s = a.load();
                    assert_eq!(
                        s.payload,
                        format!("configuration v{}", s.version),
                        "observed a torn snapshot"
                    );
                }
            }));
        }

        let writer = {
            let a = Arc::clone(&a);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for v in 1..=500 {
                    a.activate(snapshot(v));
                }
            })
        };

        writer.join().expect("writer");
        for h in handles {
            h.join().expect("reader");
        }
        assert_eq!(a.load().version, 500);
        assert_eq!(a.generation(), 500);
    }

    #[test]
    fn concurrent_activations_all_take_effect() {
        let a = Arc::new(Activatable::new(snapshot(0)));
        let mut handles = Vec::new();
        for t in 0..4u64 {
            let a = Arc::clone(&a);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    a.activate(snapshot(t * 1000 + i));
                }
            }));
        }
        for h in handles {
            h.join().expect("writer");
        }
        assert_eq!(a.generation(), 200);
    }
}
