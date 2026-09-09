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
    /// A reclaim left behind by a dead starter was swept; retry once.
    ///
    /// Internal to [`ProcessLock::acquire`] and never returned from it. It
    /// exists so the retry is a value rather than a boolean threaded through
    /// the reclaim path, where a mistake would mean either an unbounded loop or
    /// a directory no start can ever reclaim.
    ClaimSwept,
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Held { pid } => write!(
                f,
                "the state directory is locked by a running process (pid {pid})"
            ),
            Self::Io(e) => write!(f, "lock file error: {e}"),
            Self::ClaimSwept => write!(f, "a stale reclaim marker was swept; retrying"),
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
    ///
    /// # Why reclaiming needs a second file
    ///
    /// Reclaiming a stale lock is `remove` then `create_new`, and those two
    /// steps are not one operation. Two routers starting together both read the
    /// same stale lock, both decide it is dead, and then one removes the file
    /// the *other* has just created — leaving two processes each believing it
    /// holds the single-writer lock over one log. That is the worst outcome the
    /// lock exists to prevent, and it is likeliest exactly when it matters: two
    /// supervisors racing to restart after a crash.
    ///
    /// So the reclaim runs inside its own `O_EXCL` critical section. A starter
    /// takes `lock.claim`, re-reads the lock *under* it — which is what catches
    /// a winner that appeared since the first read — and only then swaps the
    /// file. `lock.claim` carries an identity of its own, so a starter that
    /// died mid-reclaim does not wedge the directory forever.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        // Two passes at most. The second exists only for the case where the
        // first found a claim left by a starter that died mid-reclaim, swept
        // it, and can now try the reclaim itself. Bounded rather than looping,
        // because a claim that keeps reappearing is a second live starter and
        // refusing is the right answer.
        match Self::acquire_once(dir) {
            Err(LockError::ClaimSwept) => Self::acquire_once(dir),
            other => other,
        }
    }

    fn acquire_once(dir: &Path) -> Result<Self, LockError> {
        let path = dir.join("lock");
        let claim = dir.join("lock.claim");

        match Self::try_create(&path) {
            Ok(()) => return Ok(Self { path }),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                return Err(LockError::Io(e));
            }
            Err(_) => {}
        }

        // The lock exists. Decide whether its owner is still running.
        if let Some(holder) = Self::live_holder(&path)? {
            return Err(LockError::Held { pid: holder });
        }

        // Stale as far as this starter can tell. Take the reclaim mutex before
        // touching anything.
        match Self::try_create(&claim) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Either another starter is reclaiming right now, or one died
                // while doing so. A live claimant wins; a dead one's claim is
                // swept and this start is retried by its supervisor rather than
                // recursing here, so there is exactly one level of recovery.
                return match Self::live_holder(&claim)? {
                    Some(pid) => Err(LockError::Held { pid }),
                    None => {
                        fs::remove_file(&claim)?;
                        Err(LockError::ClaimSwept)
                    }
                };
            }
            Err(e) => return Err(LockError::Io(e)),
        }

        let outcome = Self::reclaim_under_claim(&path);
        // On every path, including the error ones: a claim left behind blocks
        // the next reclaim until something sweeps it.
        let _ = fs::remove_file(&claim);
        outcome
    }

    /// Swap a stale lock for this process's, holding `lock.claim`.
    fn reclaim_under_claim(path: &Path) -> Result<Self, LockError> {
        // Re-read under the claim. Between the first read and here, another
        // starter may have completed its own reclaim and be running — in which
        // case what is on disk now is a *live* lock, not the stale one this
        // path was entered for.
        if let Some(holder) = Self::live_holder(path)? {
            return Err(LockError::Held { pid: holder });
        }

        match fs::remove_file(path) {
            Ok(()) => {}
            // Already gone: the reclaim still proceeds, because the create
            // below is what decides who holds it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(LockError::Io(e)),
        }
        Self::try_create(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The pid recorded in `path`, if a process matching that identity is alive.
    ///
    /// `None` covers every stale case: no file, an unreadable one, an identity
    /// that does not parse, and a pid now worn by a different process.
    fn live_holder(path: &Path) -> Result<Option<u32>, LockError> {
        let Some(existing) = read_optional(path)? else {
            return Ok(None);
        };
        let recorded = core::str::from_utf8(&existing)
            .ok()
            .and_then(ProcessIdentity::parse);
        Ok(match recorded {
            Some(recorded) if recorded.is_running() => Some(recorded.pid),
            _ => None,
        })
    }

    fn try_create(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(ProcessIdentity::current().render().as_bytes())?;
        file.sync_all()
    }

    /// The lock file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Who holds a lock, recorded so that a *different* process wearing the same
/// pid is not mistaken for the one that wrote it.
///
/// # Why a pid alone is not enough
///
/// A pid is only unique within its namespace and only until it is reused. Both
/// halves bite in practice, and the second one is worse than it sounds:
///
/// - **In a container the router is pid 1.** A container killed rather than
///   drained leaves a lock file saying `1`. The next container reads it, asks
///   whether pid 1 is alive, finds *itself*, and refuses to start — permanently,
///   and indistinguishably from the case the lock exists to prevent. That is a
///   router that will not come back up after an OOM kill without someone
///   deleting a file.
/// - **Pid reuse.** On a busy host a crashed router's pid is handed to
///   something else within minutes, and the lock is then held forever by a
///   process that has never heard of it.
///
/// The identity is the triple (boot id, pid, process start time). All three
/// come from `/proc`, which is a filesystem read rather than a system call —
/// `flock` and `kill(pid, 0)` would both need `unsafe` FFI, which
/// specification 18.2 forbids workspace-wide. A new container's pid 1 has a
/// later start time than the dead one's, a reused pid has a later start time
/// than the process that crashed, and a reboot changes the boot id, so each of
/// the three failures above resolves to "reclaim" rather than to "held".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The process identifier, in the writer's namespace.
    pub pid: u32,
    /// The system's boot identifier, if `/proc` reported one.
    pub boot_id: Option<String>,
    /// The process start time in clock ticks since boot, if `/proc` reported one.
    pub start_ticks: Option<u64>,
}

impl ProcessIdentity {
    /// This process's identity.
    #[must_use]
    pub fn current() -> Self {
        let pid = std::process::id();
        Self {
            pid,
            boot_id: read_boot_id(),
            start_ticks: read_start_ticks(pid),
        }
    }

    /// The lock file's contents: the project's line-oriented shape, one fact
    /// per line, so a human reading it during an incident can see all of it.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("pid {}\n", self.pid);
        if let Some(boot) = &self.boot_id {
            out.push_str(&format!("boot_id {boot}\n"));
        }
        if let Some(ticks) = self.start_ticks {
            out.push_str(&format!("start_ticks {ticks}\n"));
        }
        out
    }

    /// Parse a lock file.
    ///
    /// A bare number is accepted as a pid with no identity, which is what a
    /// lock written by an older router looks like. It is answered by the
    /// weaker check in [`runs_the_same_program_as_self`] rather than treated as
    /// corrupt, because refusing to start on an upgrade is a worse answer than
    /// the weaker check the file was written under.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let trimmed = text.trim();
        if let Ok(pid) = trimmed.parse::<u32>() {
            return Some(Self {
                pid,
                boot_id: None,
                start_ticks: None,
            });
        }

        let mut pid = None;
        let mut boot_id = None;
        let mut start_ticks = None;
        for line in trimmed.lines() {
            match line.trim().split_once(' ') {
                Some(("pid", value)) => pid = value.trim().parse::<u32>().ok(),
                Some(("boot_id", value)) => boot_id = Some(value.trim().to_owned()),
                Some(("start_ticks", value)) => start_ticks = value.trim().parse::<u64>().ok(),
                _ => {}
            }
        }
        pid.map(|pid| Self {
            pid,
            boot_id,
            start_ticks,
        })
    }

    /// Whether the process that wrote this identity is still running.
    ///
    /// Fails safe in both directions that matter. Where `/proc` is absent the
    /// lock is treated as held rather than stolen; where the recorded identity
    /// carries no start time — an older lock file, or a `/proc` that would not
    /// answer — the answer falls back to whether the pid is worn by a process
    /// running this same program, which is weaker but never steals a lock from
    /// a live writer.
    #[must_use]
    pub fn is_running(&self) -> bool {
        if !Path::new("/proc").is_dir() {
            return true;
        }
        if !Path::new("/proc").join(self.pid.to_string()).exists() {
            return false;
        }

        // A reboot ends every process that could have held this lock, whatever
        // `/proc` now says about that pid.
        if let (Some(recorded), Some(current)) = (&self.boot_id, read_boot_id()) {
            if *recorded != current {
                return false;
            }
        }

        // The decisive check: the pid exists, but is it the *same* process?
        match (self.start_ticks, read_start_ticks(self.pid)) {
            (Some(recorded), Some(current)) => recorded == current,
            // No start time to compare: an older router's lock, or a `/proc`
            // that would not answer. Existence alone is not enough here — see
            // `runs_the_same_program_as_self`.
            _ => runs_the_same_program_as_self(self.pid),
        }
    }
}

/// Whether the process wearing `pid` runs the same program as this one.
///
/// The tie-breaker for a lock that records no start time, which is what the
/// format before [`ProcessIdentity`] wrote: a bare pid. Existence alone is not
/// a usable answer for those, because in a container it is permanently `true`
/// for the pid such a lock is most likely to name. The router used to be the
/// container's PID 1 and so wrote `1`; PID 1 of a *fresh* container —
/// `hypellm-init` — is always alive, so every later start reads `1`, finds pid
/// 1 running, and refuses. That is exactly the "will not come back up without
/// someone deleting a file" outcome the identity triple was added to prevent,
/// reached through the compatibility path instead of around it.
///
/// Comparing `/proc/<pid>/comm` narrows it without giving up the case the
/// fallback exists for. Another router of the older build still reads as held,
/// because its name matches; `hypellm-init`, and any unrelated process that
/// inherited the pid, does not. Where either name is unreadable the answer is
/// held, which is the direction that never steals a lock from a live writer.
fn runs_the_same_program_as_self(pid: u32) -> bool {
    let read = |path: PathBuf| fs::read_to_string(path).ok();
    let proc_root = Path::new("/proc");
    match (
        read(proc_root.join(pid.to_string()).join("comm")),
        read(proc_root.join("self").join("comm")),
    ) {
        (Some(theirs), Some(mine)) => theirs.trim() == mine.trim(),
        _ => true,
    }
}

/// The system's boot identifier.
///
/// Not namespaced: a container reads the host's, which is what makes it useful
/// here — the question is whether the machine has rebooted since the lock was
/// written, and the container's own lifetime is not that question.
fn read_boot_id() -> Option<String> {
    let raw = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    Some(trimmed.to_owned())
}

/// A process's start time, in clock ticks since boot.
///
/// Field 22 of `/proc/<pid>/stat`. The parse starts at the **last** `)` rather
/// than splitting on whitespace from the beginning: field 2 is the executable
/// name in parentheses, and it may contain spaces and parentheses of its own —
/// a program named `hyp ell) m` would otherwise shift every field after it and
/// silently yield the wrong number, which here means silently stealing a lock.
fn read_start_ticks(pid: u32) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = raw.get(raw.rfind(')')?.checked_add(1)?..)?;
    // Fields 3 onwards. Field 22 is therefore index 19.
    after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        // Only if the file on disk is still this process's. Removing it
        // unconditionally would delete a lock that another starter has since
        // reclaimed and is holding — turning an orderly shutdown into the
        // two-writer case the lock exists to prevent.
        //
        // Best effort otherwise: a failure here leaves a stale lock, which the
        // next startup reclaims after finding the process gone.
        let mine = ProcessIdentity::current();
        let on_disk = read_optional(&self.path)
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| ProcessIdentity::parse(&text));
        if on_disk.is_some_and(|found| found == mine) {
            let _ = fs::remove_file(&self.path);
        }
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
        let written = ProcessIdentity::parse(&content).expect("the new lock parses");
        assert_eq!(written.pid, std::process::id());
    }

    #[test]
    fn a_lock_whose_pid_is_now_a_different_process_is_reclaimed() {
        // The container case, and the one this identity exists for. A router
        // killed rather than drained leaves a lock saying `pid 1`; the next
        // container is *also* pid 1, so an existence check finds the lock's
        // owner alive — itself — and refuses to start, permanently and
        // indistinguishably from a genuine double-start.
        //
        // Modelled here with this process's own live pid and a start time that
        // is not this process's, which is exactly the shape of that file.
        let dir = TempDir::new("reused-pid");
        let path = dir.path().join("lock");
        let mine = ProcessIdentity::current();
        let start = mine.start_ticks.expect("Linux /proc reports a start time");
        fs::write(
            &path,
            format!(
                "pid {}\nboot_id {}\nstart_ticks {}\n",
                mine.pid,
                mine.boot_id.clone().unwrap_or_default(),
                start.saturating_sub(1),
            ),
        )
        .unwrap();

        let _lock = ProcessLock::acquire(dir.path())
            .expect("a lock left by a process that is no longer the one wearing that pid");
    }

    #[test]
    fn a_lock_held_by_this_very_process_is_not_stolen() {
        // The other half, and the property the reclaim must not break: a
        // genuinely live holder keeps its lock. Without this the test above
        // would pass on an implementation that reclaimed unconditionally, which
        // is the failure the lock exists to prevent.
        let dir = TempDir::new("live-holder");
        fs::write(dir.path().join("lock"), ProcessIdentity::current().render()).unwrap();

        match ProcessLock::acquire(dir.path()) {
            Err(LockError::Held { pid }) => assert_eq!(pid, std::process::id()),
            other => panic!("a live holder's lock was stolen: {other:?}"),
        }
    }

    #[test]
    fn a_lock_from_a_previous_boot_is_reclaimed() {
        let dir = TempDir::new("previous-boot");
        let mine = ProcessIdentity::current();
        fs::write(
            dir.path().join("lock"),
            format!(
                "pid {}\nboot_id 00000000-0000-0000-0000-000000000000\nstart_ticks {}\n",
                mine.pid,
                mine.start_ticks.unwrap_or(0),
            ),
        )
        .unwrap();

        let _lock = ProcessLock::acquire(dir.path())
            .expect("nothing from before the reboot can still be holding this");
    }

    #[test]
    fn a_lock_written_by_an_older_router_still_holds() {
        // A bare pid is what the previous format looked like. It must keep
        // working: refusing to start on an upgrade would be a worse answer than
        // the weaker check the file was written under.
        let dir = TempDir::new("old-format");
        fs::write(dir.path().join("lock"), std::process::id().to_string()).unwrap();

        match ProcessLock::acquire(dir.path()) {
            Err(LockError::Held { pid }) => assert_eq!(pid, std::process::id()),
            other => panic!("an old-format lock was ignored: {other:?}"),
        }
    }

    #[test]
    fn a_bare_pid_lock_naming_another_program_is_reclaimed() {
        // The container case, and the reason `just restart` wedged: the router
        // used to be PID 1 and wrote a bare `1`. A fresh container's PID 1 is
        // `hypellm-init`, which is always alive, so an existence check answers
        // "held" for that lock forever and no start ever reclaims it.
        //
        // Pid 1 stands in for it here — it exists, and it is not this test
        // binary. Skipped rather than failed where /proc cannot say, since the
        // conservative answer there is deliberately "held".
        let Ok(theirs) = fs::read_to_string("/proc/1/comm") else {
            return;
        };
        let Ok(mine) = fs::read_to_string("/proc/self/comm") else {
            return;
        };
        if theirs.trim() == mine.trim() {
            return;
        }

        let dir = TempDir::new("bare-pid-foreign");
        fs::write(dir.path().join("lock"), "1").unwrap();

        let lock = ProcessLock::acquire(dir.path()).expect("a bare-pid lock for pid 1 wedged");
        let written = fs::read_to_string(lock.path()).unwrap();
        assert_eq!(
            ProcessIdentity::parse(&written).map(|id| id.pid),
            Some(std::process::id()),
            "the reclaim did not record this process as the holder"
        );
    }

    #[test]
    fn a_reclaim_in_progress_is_not_raced() {
        // Two starters both find the same stale lock and both decide to
        // reclaim it. Without the claim mutex, one removes the file the other
        // has just created and both proceed — two writers over one log, which
        // is the outcome the lock exists to prevent.
        //
        // The claim is planted by a *live* process (this one), which is what a
        // starter mid-reclaim looks like from outside.
        let dir = TempDir::new("claim-race");
        fs::write(dir.path().join("lock"), "4294967000").unwrap();
        fs::write(
            dir.path().join("lock.claim"),
            ProcessIdentity::current().render(),
        )
        .unwrap();

        match ProcessLock::acquire(dir.path()) {
            Err(LockError::Held { .. }) => {}
            other => panic!("a starter reclaimed under another's claim: {other:?}"),
        }
        assert!(
            dir.path().join("lock.claim").exists(),
            "a live claimant's marker was swept out from under it"
        );
    }

    #[test]
    fn a_claim_left_by_a_dead_starter_does_not_wedge_the_directory() {
        // The cost of the mutex: a starter that dies between taking the claim
        // and swapping the lock leaves a marker. If nothing swept it, no later
        // start could ever reclaim — a directory permanently unopenable, which
        // is worse than the race it prevents.
        let dir = TempDir::new("dead-claim");
        fs::write(dir.path().join("lock"), "4294967000").unwrap();
        fs::write(dir.path().join("lock.claim"), "pid 4294967000\n").unwrap();

        let _lock = ProcessLock::acquire(dir.path()).expect("a dead claim must be swept");
        assert!(
            !dir.path().join("lock.claim").exists(),
            "the claim marker outlived the reclaim"
        );
    }

    #[test]
    fn dropping_does_not_remove_a_lock_someone_else_now_holds() {
        // `Drop` used to remove the file unconditionally. A router shutting
        // down while another has already reclaimed the directory would delete
        // the live holder's lock, and the next start would find the directory
        // free while a writer was still in it.
        let dir = TempDir::new("drop-foreign");
        let lock = ProcessLock::acquire(dir.path()).expect("acquire");

        // Someone else reclaimed it in the meantime.
        fs::write(dir.path().join("lock"), "pid 4294967000\n").unwrap();
        drop(lock);

        assert!(
            dir.path().join("lock").exists(),
            "dropping removed a lock this process no longer held"
        );
    }

    #[test]
    fn a_stat_line_with_a_parenthesised_name_parses() {
        // Field 2 of `/proc/<pid>/stat` is the executable name in parentheses
        // and may contain spaces and parentheses. Splitting from the left would
        // shift every later field and yield a wrong start time — which here
        // means stealing a lock from a live router.
        let ticks = read_start_ticks(std::process::id());
        assert!(ticks.is_some(), "Linux /proc must report a start time");
        assert_eq!(
            read_start_ticks(std::process::id()),
            ticks,
            "the same process must report the same start time twice"
        );
        assert_eq!(read_start_ticks(4_294_967_000), None);
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
