//! Durable file operations and the single-writer process lock.
//!
//! Specification 11.2: "Writes use temporary file, fsync, atomic rename, and
//! directory fsync." and "Single-node mode uses an exclusive process lock".
//!
//! The directory fsync is the step most often omitted. Without it, the rename
//! itself may not be durable: after a crash the file can exist under its old
//! name, or under neither name, even though the data blocks were synced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Persist `bytes` to `dir/name` atomically.
///
/// A reader either sees the previous content or the new content, never a
/// partial write, and the result survives a power loss immediately after this
/// returns.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let target = dir.join(name);

    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        // Data blocks and metadata, before the rename makes the name visible.
        file.sync_all()?;
    }

    fs::rename(&tmp, &target)?;
    sync_dir(dir)?;
    Ok(())
}

/// fsync a directory, making a rename or create durable.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    // Opening a directory read-only and syncing it is the portable-on-Linux way
    // to make a rename durable. `sync_all` on a directory handle is a no-op on
    // some platforms; on Linux it is the operation that matters.
    File::open(dir)?.sync_all()
}

/// Read a file if it exists.
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    read_optional_bounded(path, MAX_STATE_FILE_BYTES)
}

/// The largest state file that may be read into memory.
///
/// Specification 3.2 bounds every buffer, and a snapshot is a file whose size
/// is not this process's decision alone — a corrupt or substituted one can be
/// any length. 256 MiB is far above a real snapshot and far below what a node
/// cannot hold.
pub const MAX_STATE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Read a file, refusing one larger than `limit`.
///
/// The size is checked from the metadata *before* the read, so an oversized
/// file is a message rather than an allocation failure. A file that grows
/// between the check and the read is bounded by `take`, which is the case a
/// metadata-only check would miss.
pub fn read_optional_bounded(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(f) => {
            let len = f.metadata()?.len();
            if len > limit {
                return Err(io::Error::other(format!(
                    "{} is {len} bytes, past the {limit}-byte limit for a state file",
                    path.display()
                )));
            }
            let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
            let mut reader = f.take(limit.saturating_add(1));
            reader.read_to_end(&mut buf)?;
            if u64::try_from(buf.len()).unwrap_or(u64::MAX) > limit {
                return Err(io::Error::other(format!(
                    "{} grew past the {limit}-byte limit while it was being read",
                    path.display()
                )));
            }
            Ok(Some(buf))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// An exclusive single-writer lock over a state directory.
///
/// Held for the lifetime of the process. Released on drop, and reclaimed on
/// startup if the recorded process is no longer alive — otherwise a crash would
/// require manual intervention before the router could restart, which is the
/// wrong trade for an availability-critical component.
#[derive(Debug)]
pub struct ProcessLock {
    path: PathBuf,
}

/// Why a lock could not be acquired.
#[derive(Debug)]
pub enum LockError {
    /// Another live process holds the lock.
    Held {
        /// The process identifier recorded in the lock file.
        pid: u32,
    },
    /// The lock file could not be created or read.
    Io(io::Error),
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Held { pid } => write!(
                f,
                "the state directory is locked by a running process (pid {pid})"
            ),
            Self::Io(e) => write!(f, "lock file error: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<io::Error> for LockError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl ProcessLock {
    /// Acquire the lock for `dir`.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        let path = dir.join("lock");

        match Self::try_create(&path) {
            Ok(()) => return Ok(Self { path }),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                return Err(LockError::Io(e));
            }
            Err(_) => {}
        }

        // The lock exists. Decide whether its owner is still running.
        let existing = read_optional(&path)?.unwrap_or_default();
        let pid = core::str::from_utf8(&existing)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());

        match pid {
            Some(pid) if process_is_alive(pid) => Err(LockError::Held { pid }),
            _ => {
                // Stale: the recorded process is gone, or the file is
                // unreadable. Reclaim it.
                fs::remove_file(&path)?;
                Self::try_create(&path)?;
                Ok(Self { path })
            }
        }
    }

    fn try_create(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        write!(file, "{}", std::process::id())?;
        file.sync_all()
    }

    /// The lock file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        // Best effort. A failure here leaves a stale lock, which the next
        // startup reclaims after finding the process gone.
        let _ = fs::remove_file(&self.path);
    }
}

/// Whether a process is running.
///
/// Reads `/proc`, which is a filesystem operation rather than a system call
/// binding — `kill(pid, 0)` would need `unsafe` FFI, which this workspace
/// forbids. On a system without `/proc` this returns true, which fails safe:
/// the lock is treated as held rather than stolen.
#[must_use]
pub fn process_is_alive(pid: u32) -> bool {
    let proc_root = Path::new("/proc");
    if !proc_root.is_dir() {
        return true;
    }
    proc_root.join(pid.to_string()).exists()
}

/// Create a directory and its parents if absent.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that removes itself.
    ///
    /// The dependency policy admits no `tempfile` crate, and the router's own
    /// tests need one. Uniqueness comes from the process id and a counter,
    /// which is sufficient within a single test binary.
    #[derive(Debug)]
    pub(crate) struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let base = std::env::temp_dir();
            let path = base.join(format!("hypellm-test-{}-{tag}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = TempDir::new("atomic");
        write_atomic(dir.path(), "snapshot.bin", b"first").unwrap();
        assert_eq!(
            read_optional(&dir.path().join("snapshot.bin")).unwrap(),
            Some(b"first".to_vec())
        );

        write_atomic(dir.path(), "snapshot.bin", b"second").unwrap();
        assert_eq!(
            read_optional(&dir.path().join("snapshot.bin")).unwrap(),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn atomic_write_leaves_no_temporary_behind() {
        let dir = TempDir::new("no-temp");
        write_atomic(dir.path(), "f", b"x").unwrap();
        assert!(!dir.path().join("f.tmp").exists());
    }

    #[test]
    fn reading_an_absent_file_is_not_an_error() {
        let dir = TempDir::new("absent");
        assert_eq!(read_optional(&dir.path().join("nope")).unwrap(), None);
    }

    #[test]
    fn large_writes_round_trip() {
        let dir = TempDir::new("large");
        let data = vec![0x5au8; 3_000_000];
        write_atomic(dir.path(), "big", &data).unwrap();
        assert_eq!(
            read_optional(&dir.path().join("big")).unwrap().unwrap().len(),
            data.len()
        );
    }

    #[test]
    fn the_lock_is_exclusive() {
        let dir = TempDir::new("lock");
        let first = ProcessLock::acquire(dir.path()).expect("first acquire");

        match ProcessLock::acquire(dir.path()) {
            Err(LockError::Held { pid }) => assert_eq!(pid, std::process::id()),
            other => panic!("expected Held, got {other:?}"),
        }

        drop(first);
        // Released, so it can be taken again.
        let _second = ProcessLock::acquire(dir.path()).expect("reacquire after release");
    }

    #[test]
    fn a_stale_lock_is_reclaimed() {
        // After a crash the lock file survives with a dead process id. Refusing
        // to start would need manual intervention on every crash.
        let dir = TempDir::new("stale");
        let path = dir.path().join("lock");
        // A pid that cannot be running: the kernel maximum is well below this.
        fs::write(&path, "4294967000").unwrap();

        let lock = ProcessLock::acquire(dir.path()).expect("stale lock should be reclaimed");
        assert_eq!(lock.path(), path.as_path());
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim(), std::process::id().to_string());
    }

    #[test]
    fn an_unreadable_lock_is_reclaimed() {
        let dir = TempDir::new("garbage-lock");
        fs::write(dir.path().join("lock"), b"\xff\xfe not a pid").unwrap();
        let _lock = ProcessLock::acquire(dir.path()).expect("garbage lock should be reclaimed");
    }

    #[test]
    fn the_current_process_is_alive() {
        assert!(process_is_alive(std::process::id()));
        assert!(!process_is_alive(4_294_967_000));
    }

    #[test]
    fn ensure_dir_is_idempotent() {
        let dir = TempDir::new("ensure");
        let nested = dir.path().join("a/b/c");
        ensure_dir(&nested).unwrap();
        assert!(nested.is_dir());
        ensure_dir(&nested).unwrap();
        assert!(nested.is_dir());
    }
}
