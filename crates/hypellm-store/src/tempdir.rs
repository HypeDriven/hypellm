//! A self-removing temporary directory.
//!
//! The dependency policy (specification 4) admits no `tempfile` crate, and the
//! store, audit, and resilience tests all need scratch directories. Uniqueness
//! comes from the process identifier plus a counter, which is sufficient for
//! concurrent tests within and across test binaries.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A directory that is removed when the value is dropped.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a temporary directory tagged with `tag` for readability.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created. This is a test utility; a
    /// failure here means the test environment is broken, and returning a
    /// `Result` would only push the panic to the call site.
    #[must_use]
    // This is test scaffolding, not a data-plane path: nothing here reads a
    // request, a frame, or a byte off disk. The panic is the documented
    // contract above — a scratch directory that cannot be created means the
    // test environment is broken, and a `Result` would only move the same
    // panic into every caller.
    #[allow(clippy::panic, reason = "test-only utility; failure means the test environment is broken")]
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "hypellm-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("cannot create temporary directory {}: {e}", path.display()));
        Self { path }
    }

    /// The directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Keep the directory after drop, for debugging a failing test.
    #[must_use]
    pub fn into_path(self) -> PathBuf {
        let path = self.path.clone();
        core::mem::forget(self);
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_removes() {
        let path = {
            let d = TempDir::new("basic");
            assert!(d.path().is_dir());
            fs::write(d.join("f"), b"x").unwrap();
            d.path().to_path_buf()
        };
        assert!(!path.exists(), "the directory must be removed on drop");
    }

    #[test]
    fn instances_are_distinct() {
        let a = TempDir::new("same");
        let b = TempDir::new("same");
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn into_path_keeps_the_directory() {
        let path = TempDir::new("kept").into_path();
        assert!(path.is_dir());
        let _ = fs::remove_dir_all(&path);
    }
}
