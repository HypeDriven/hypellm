//! The job result spool: artifact parts on disk, bounded and expiring
//! (orchestration §11.5).
//!
//! Song-length audio, high-bitrate video and textured meshes outgrow the
//! in-memory result a chat job keeps, and memory multiplies by every retained
//! job. So an artifact job's parts are written here, one directory per job
//! under `<state_dir>/jobs/`, while the deployment that made them is still
//! held — an eviction cannot destroy a result the router has promised.
//!
//! # What keeps the router from being a blob store
//!
//! Bound and expiry, not the medium:
//!
//! - **Per part**: `settings max_job_part_bytes`. A shim declaring more fails
//!   the job before a byte is fetched.
//! - **In total**: `settings max_job_spool_bytes`, reserved for every part of a
//!   job before the first is fetched, so concurrent completions cannot jointly
//!   overrun it.
//! - **Expiry**: a part goes when its job leaves the table — at
//!   `job_retention_ms`, on cancel, or when a fetch fails.
//! - **Restart**: jobs are not durable, so nothing here can be served after a
//!   restart; [`Spool::open`] removes the whole directory.
//!
//! # What reaches a path
//!
//! A directory is named by the router's own [`JobId`] — `job_` and 32
//! lowercase hex digits, minted from the OS entropy source — and a file by a
//! [`PartName`], 1–64 characters of `[A-Za-z0-9_-]` validated when the shim's
//! reply was parsed. Neither can hold a separator or `..`.

use crate::jobs::JobId;
use hypellm_adapters::job::{PartMediaType, PartName};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One part, spooled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpooledPart {
    /// Its name.
    pub name: PartName,
    /// Its media type, as the shim declared it and its head confirmed.
    pub media_type: PartMediaType,
    /// Its length.
    pub bytes: u64,
    /// The SHA-256 of what was written, computed as it was.
    pub sha256: [u8; 32],
}

/// The spool.
#[derive(Debug)]
pub struct Spool {
    root: PathBuf,
    max_part_bytes: u64,
    max_total_bytes: u64,
    /// Bytes reserved or written, across every job.
    used: Mutex<u64>,
}

impl Spool {
    /// Open the spool under `state_dir`, removing whatever a previous process
    /// left: jobs are not durable, so no part there can be served again.
    ///
    /// # Errors
    ///
    /// The directory cannot be removed or created.
    pub fn open(state_dir: &Path, max_part_bytes: u64, max_total_bytes: u64) -> io::Result<Self> {
        let root = state_dir.join("jobs");
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            max_part_bytes,
            max_total_bytes,
            used: Mutex::new(0),
        })
    }

    /// The largest part this spool takes.
    #[must_use]
    pub const fn max_part_bytes(&self) -> u64 {
        self.max_part_bytes
    }

    /// Reserve room for `bytes`, or say there is none.
    ///
    /// Taken for all of a job's parts at once, before the first fetch, so two
    /// jobs completing together cannot each see room the other is about to
    /// use.
    #[must_use]
    pub fn reserve(&self, bytes: u64) -> bool {
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        match used.checked_add(bytes) {
            Some(total) if total <= self.max_total_bytes => {
                *used = total;
                true
            }
            _ => false,
        }
    }

    /// Give back a reservation.
    pub fn release(&self, bytes: u64) {
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        *used = used.saturating_sub(bytes);
    }

    /// Bytes reserved or held now.
    #[must_use]
    pub fn used(&self) -> u64 {
        *self.used.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn job_dir(&self, job: &JobId) -> PathBuf {
        self.root.join(job.as_str())
    }

    /// Create a part's file, which must not exist yet.
    ///
    /// # Errors
    ///
    /// The directory or the file cannot be created, or the file exists.
    pub fn create(&self, job: &JobId, part: &PartName) -> io::Result<File> {
        let dir = self.job_dir(job);
        std::fs::create_dir_all(&dir)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(part.as_str()))
    }

    /// Open a part for reading.
    ///
    /// # Errors
    ///
    /// The part does not exist.
    pub fn open_part(&self, job: &JobId, part: &PartName) -> io::Result<File> {
        File::open(self.job_dir(job).join(part.as_str()))
    }

    /// Remove a job's parts and give back `bytes`.
    pub fn remove(&self, job: &JobId, bytes: u64) {
        let _ = std::fs::remove_dir_all(self.job_dir(job));
        self.release(bytes);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test module: failure is a panic"
)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hypellm-spool-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_reservation_never_takes_the_spool_past_its_total() {
        let dir = temp("total");
        let spool = Spool::open(&dir, 100, 250).unwrap();
        assert!(spool.reserve(100));
        assert!(spool.reserve(100));
        assert!(!spool.reserve(100), "the third would take 300 of 250");
        assert!(spool.reserve(50));
        spool.release(100);
        assert_eq!(spool.used(), 150);
        assert!(!spool.reserve(u64::MAX), "an overflowing reservation is refused");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_the_spool_removes_what_a_previous_process_left() {
        let dir = temp("sweep");
        let job = JobId::generate().unwrap();
        let part = PartName::parse("song").unwrap();
        {
            let spool = Spool::open(&dir, 100, 1000).unwrap();
            spool.create(&job, &part).unwrap().write_all(b"old").unwrap();
        }
        let spool = Spool::open(&dir, 100, 1000).unwrap();
        assert!(spool.open_part(&job, &part).is_err(), "a part survived a restart");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_part_is_written_once_read_back_and_removed_with_its_job() {
        let dir = temp("part");
        let spool = Spool::open(&dir, 100, 1000).unwrap();
        let job = JobId::generate().unwrap();
        let part = PartName::parse("mesh").unwrap();
        assert!(spool.reserve(5));
        spool.create(&job, &part).unwrap().write_all(b"hello").unwrap();
        assert!(spool.create(&job, &part).is_err(), "a part was overwritten");
        let mut text = String::new();
        spool.open_part(&job, &part).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello");
        spool.remove(&job, 5);
        assert!(spool.open_part(&job, &part).is_err());
        assert_eq!(spool.used(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }
}
