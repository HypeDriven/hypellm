//! Durable state: framed log, snapshots, atomic activation, audit chain.
//!
//! Specification 18.1: "store — Framed log, snapshots, atomic configuration
//! activation, audit chain."
//!
//! # Layout
//!
//! ```text
//! <state_dir>/
//!   lock              exclusive single-writer lock (specification 11.2)
//!   snapshot.bin      the last compacted state
//!   snapshot.meta     sequence and audit head at the snapshot point
//!   log.bin           frames appended since the snapshot
//! ```
//!
//! # Startup
//!
//! 1. Acquire the process lock, reclaiming it if the recorded process is gone.
//! 2. Read the snapshot, if any.
//! 3. Replay the log. A torn tail truncates; a protected-record integrity
//!    failure aborts startup (specification 11.2).
//! 4. Resume the audit chain from the snapshot's recorded head.
//!
//! # Compaction
//!
//! Specification 11.2: "Compaction runs off the request path and retains the
//! prior snapshot until the replacement is durable." [`Store::compact`] writes
//! the new snapshot atomically *first* and only then resets the log, so a crash
//! at any point leaves either the old snapshot plus the full log, or the new
//! snapshot plus an empty log — never a new snapshot with records that predate
//! it already discarded.

#![forbid(unsafe_code)]
// Specification 18.2: no panics on data-plane input, all integer conversions
// checked. This crate decodes bytes read from the state directory, which the
// threat model treats as hostile, so the workspace-level warnings are errors
// here: a new unchecked index or silent `as` in this crate fails the build
// rather than joining a list of warnings.
// `not(test)` so the escalation applies to the code that decodes those bytes
// and not to the tests that exercise it — a `panic!` in an assertion is a test
// failure, which is the point of it.
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::as_conversions, clippy::panic)
)]

pub mod activation;
pub mod audit;
pub mod durable;
pub mod frame;
pub mod log;
#[cfg(any(test, feature = "test-harness"))]
pub mod tempdir;

pub use activation::Activatable;
pub use audit::{
    AuditAction, AuditChain, AuditCheckpoint, AuditEvent, AuditOutcome, AuditRecord,
    ChainVerification, verify_chain,
};
pub use durable::{LockError, ProcessLock, ensure_dir, read_optional, write_atomic};
pub use frame::{Frame, FrameError, RecordKind};
pub use log::{Log, LogError, Replay};
#[cfg(any(test, feature = "test-harness"))]
pub use tempdir::TempDir;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// The snapshot payload plus the position it was taken at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotState {
    /// The opaque snapshot payload, written by the caller.
    pub payload: Vec<u8>,
    /// The sequence number the snapshot covers up to.
    pub sequence: u64,
    /// The audit chain head at that point.
    pub audit_head: [u8; 32],
    /// How many audit records the chain covered.
    pub audit_count: u64,
}

/// What startup recovered.
#[derive(Debug)]
pub struct Recovery {
    /// The snapshot, if one existed.
    pub snapshot: Option<SnapshotState>,
    /// Frames replayed from the log.
    pub frames: Vec<Frame>,
    /// Whether a torn tail was truncated.
    pub truncated: bool,
    /// The sequence number of the first audit record that did not follow its
    /// predecessor, if any.
    ///
    /// Specification 17 makes the audit records "a hash/MAC chain": each record
    /// commits to the one before it, so removing or reordering one breaks every
    /// link after it. Startup is the only place that break can be noticed —
    /// re-chaining without checking simply adopts whatever head the last record
    /// happens to carry, which is exactly the tamper the chain exists to
    /// detect.
    ///
    /// A break is reported rather than acted on here, because what to do about
    /// it is the caller's decision: specification 11.2 says startup "fails
    /// closed on protected-record integrity errors", and the router does.
    pub audit_chain_broken_at: Option<u64>,
    /// The reason replay stopped early, if it did.
    pub stop_reason: Option<FrameError>,
}

impl Recovery {
    /// The highest sequence number recovered.
    #[must_use]
    pub fn max_sequence(&self) -> u64 {
        let from_log = self.frames.last().map_or(0, |f| f.sequence);
        let from_snapshot = self.snapshot.as_ref().map_or(0, |s| s.sequence);
        from_log.max(from_snapshot)
    }

    /// Frames of one kind.
    pub fn of_kind(&self, kind: RecordKind) -> impl Iterator<Item = &Frame> {
        self.frames.iter().filter(move |f| f.kind == kind)
    }
}

/// A store failure.
#[derive(Debug)]
pub enum StoreError {
    /// The state directory is locked by a live process.
    Locked(LockError),
    /// The log could not be replayed.
    Log(LogError),
    /// The snapshot metadata was malformed.
    CorruptSnapshotMetadata,
    /// The snapshot did not authenticate against the store MAC key.
    ///
    /// Distinct from [`StoreError::CorruptSnapshotMetadata`] because the two
    /// mean different things to an operator: malformed is damage, while an
    /// integrity failure is either the wrong key or deliberate tampering.
    SnapshotIntegrity,
    /// An I/O failure.
    Io(std::io::Error),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Locked(e) => write!(f, "{e}"),
            Self::Log(e) => write!(f, "{e}"),
            Self::CorruptSnapshotMetadata => f.write_str("snapshot metadata is malformed"),
            Self::SnapshotIntegrity => {
                f.write_str("the snapshot did not authenticate: wrong key or tampering")
            }
            Self::Io(e) => write!(f, "store I/O error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LogError> for StoreError {
    fn from(e: LogError) -> Self {
        Self::Log(e)
    }
}

impl From<LockError> for StoreError {
    fn from(e: LockError) -> Self {
        Self::Locked(e)
    }
}

/// The most audit records one durable read may return.
///
/// Specification 3.2 bounds every input, and this one replays the log to
/// answer. A page larger than this is not a paging request, it is an export —
/// which has its own endpoint and its own permission.
pub const MAX_AUDIT_PAGE: usize = 500;

const SNAPSHOT_FILE: &str = "snapshot.bin";
const SNAPSHOT_META: &str = "snapshot.meta";
const LOG_FILE: &str = "log.bin";
/// Snapshot-metadata magic.
///
/// Renamed alongside the frame magic in `frame.rs` rather than left behind:
/// two on-disk tags in one crate, one carrying the old brand and one the new,
/// is a half-finished format that reads as an oversight to whoever greps next.
///
/// Unlike the log, a wrong value here fails closed on its own —
/// `read_snapshot` rejects it as `CorruptSnapshotMetadata` — so this one needed
/// no separate guard.
const META_MAGIC: &[u8; 4] = b"HYMT";
/// magic + sequence + audit head + audit count + payload digest + MAC.
const META_LEN: usize = 4 + 8 + 32 + 8 + 32 + 32;

/// The durable store.
pub struct Store {
    dir: PathBuf,
    /// Held for the process lifetime; released on drop.
    _lock: ProcessLock,
    log: Mutex<Log>,
    sequence: AtomicU64,
    mac_key: Vec<u8>,
    audit: Mutex<AuditChain>,
    audit_since_checkpoint: AtomicU64,
    checkpoint_interval: u64,
}

impl fmt::Debug for Store {
    /// Redacted. The store MAC key authenticates every protected frame and the
    /// audit hash chain; disclosing it would let a tampered log verify.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("dir", &self.dir)
            .field("sequence", &self.sequence)
            .field("mac_key", &"[redacted key material]")
            .field("audit_since_checkpoint", &self.audit_since_checkpoint)
            .field("checkpoint_interval", &self.checkpoint_interval)
            .finish()
    }
}

impl Store {
    /// Open the store at `dir`, recovering any existing state.
    ///
    /// `mac_key` authenticates protected frames. It must come from the platform
    /// secret facility (specification 10); the store never generates or
    /// persists it.
    pub fn open(
        dir: &Path,
        mac_key: &[u8],
        checkpoint_interval: u64,
    ) -> Result<(Self, Recovery), StoreError> {
        ensure_dir(dir)?;
        let lock = ProcessLock::acquire(dir)?;

        let snapshot = read_snapshot(dir, mac_key)?;

        let mut log = Log::open(&dir.join(LOG_FILE), true)?;
        let replay = log.replay(mac_key)?;
        let truncated = replay.truncated_at.is_some();
        if truncated {
            // A torn tail. Discard it so the next append does not follow a
            // partial frame.
            log.truncate(replay.valid_len)?;
        }

        let recovery = Recovery {
            snapshot: snapshot.clone(),
            frames: replay.frames,
            truncated,
            stop_reason: replay.stop_reason,
            audit_chain_broken_at: None,
        };

        let sequence = recovery.max_sequence();
        let audit = match &snapshot {
            Some(s) => AuditChain::resume(s.audit_head, s.audit_count),
            None => AuditChain::new(),
        };

        // Re-chain any audit records that were logged after the snapshot, and
        // verify each one follows from the head before it.
        //
        // The check is the point. Adopting `record.link()` unconditionally —
        // which is what this did — makes the chain self-consistent by
        // construction and therefore evidence of nothing: a record deleted from
        // the middle, or two swapped, leaves every subsequent link "valid"
        // because the reader simply believes whatever it is handed.
        let mut audit = audit;
        let mut broken_at = None;
        for frame in recovery
            .frames
            .iter()
            .filter(|f| f.kind == RecordKind::AuditEvent)
        {
            let Some(record) = AuditRecord::from_payload(&frame.payload) else {
                // A frame that authenticated under the store MAC but does not
                // parse as an audit record is itself an integrity error, and
                // skipping it silently is how the live head diverges from the
                // durable history with nothing said. It breaks the chain for
                // the same reason a removed record does: the next record's
                // `previous_link` commits to a link this reader cannot compute.
                if broken_at.is_none() {
                    broken_at = Some(frame.sequence);
                }
                continue;
            };
            if broken_at.is_none() && record.previous_link != audit.head() {
                broken_at = Some(frame.sequence);
            }
            audit = AuditChain::resume(record.link(), audit.count().saturating_add(1));
        }
        let recovery = Recovery {
            audit_chain_broken_at: broken_at,
            ..recovery
        };

        let store = Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            log: Mutex::new(log),
            sequence: AtomicU64::new(sequence),
            mac_key: mac_key.to_vec(),
            audit: Mutex::new(audit),
            audit_since_checkpoint: AtomicU64::new(0),
            checkpoint_interval,
        };

        Ok((store, recovery))
    }

    /// The state directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The next sequence number that will be assigned.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst) + 1
    }

    /// The current audit chain head.
    #[must_use]
    pub fn audit_head(&self) -> [u8; 32] {
        self.lock_audit().head()
    }

    /// How many audit records the chain covers.
    #[must_use]
    pub fn audit_count(&self) -> u64 {
        self.lock_audit().count()
    }

    fn lock_audit(&self) -> std::sync::MutexGuard<'_, AuditChain> {
        match self.audit.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn lock_log(&self) -> std::sync::MutexGuard<'_, Log> {
        match self.log.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Append a record and return its sequence number.
    ///
    /// The sequence number is allocated *while holding the log lock*. Doing it
    /// outside would let two threads take numbers in one order and write them
    /// in another, which replay correctly rejects as a reordered log.
    pub fn append(&self, kind: RecordKind, payload: &[u8]) -> Result<u64, StoreError> {
        let mut log = self.lock_log();
        self.append_locked(&mut log, kind, payload)
    }

    /// Append with the log lock already held.
    ///
    /// Lock order throughout this type is **log, then audit**. `compact` needs
    /// both and takes them in that order, so every other path must too.
    fn append_locked(
        &self,
        log: &mut Log,
        kind: RecordKind,
        payload: &[u8],
    ) -> Result<u64, StoreError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        log.append(kind, sequence, payload, &self.mac_key)?;
        Ok(sequence)
    }

    /// Append an audit event, chaining it and writing a checkpoint when due.
    ///
    /// Specification 18.3: "Audit::append(event) — Bounded fields; integrity
    /// chained; failure policy configurable but security changes fail closed."
    /// An I/O failure here propagates: a security-relevant action whose audit
    /// record did not reach disk must not be reported as having succeeded.
    pub fn append_audit(&self, event: AuditEvent) -> Result<AuditAppended, StoreError> {
        // Both locks are held across chaining and writing, in the documented
        // order. Chaining under one lock and writing under another would let
        // two events be linked in one order and logged in the other, so replay
        // would rebuild a different head than the live chain holds.
        let mut log = self.lock_log();
        let mut chain = self.lock_audit();

        // The chain has to advance before the write, because the record's
        // payload contains the link. So the head is captured first and restored
        // if the write fails: otherwise a full disk would leave the live head
        // including a record that never reached disk, every later record would
        // chain from that phantom head, and replay after a restart would
        // rebuild the chain without it — reporting the links as broken. A full
        // disk presenting as tampering is the wrong incident: one is a page to
        // whoever owns the storage, the other is a security response.
        let restore = (chain.head(), chain.count());
        let record = chain.append(event);
        let sequence =
            match self.append_locked(&mut log, RecordKind::AuditEvent, &record.to_payload()) {
                Ok(sequence) => sequence,
                Err(e) => {
                    *chain = AuditChain::resume(restore.0, restore.1);
                    return Err(e);
                }
            };

        let since = self.audit_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
        let mut checkpoint = None;
        if self.checkpoint_interval > 0 && since >= self.checkpoint_interval {
            self.audit_since_checkpoint.store(0, Ordering::SeqCst);
            let taken = chain.checkpoint(sequence, record.event.timestamp_millis, &self.mac_key);
            // A checkpoint is a summary of the chain, not a link in it, so a
            // failure here leaves the chain correct and only loses the
            // checkpoint. The counter is put back so the next append retries
            // rather than waiting a whole interval to try again.
            if let Err(e) = self.append_locked(&mut log, RecordKind::AuditCheckpoint, &taken.to_payload())
            {
                self.audit_since_checkpoint.store(since, Ordering::SeqCst);
                return Err(e);
            }
            checkpoint = Some(taken);
        }

        Ok(AuditAppended {
            sequence,
            link: record.link(),
            checkpoint,
        })
    }

    /// Force an audit checkpoint now.
    pub fn checkpoint_audit(&self, timestamp_millis: u64) -> Result<AuditCheckpoint, StoreError> {
        let mut log = self.lock_log();
        let chain = self.lock_audit();
        let sequence = self.sequence.load(Ordering::SeqCst);
        let checkpoint = chain.checkpoint(sequence, timestamp_millis, &self.mac_key);
        self.append_locked(&mut log, RecordKind::AuditCheckpoint, &checkpoint.to_payload())?;
        self.audit_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(checkpoint)
    }

    /// Verify a checkpoint against this store's key.
    #[must_use]
    pub fn verify_checkpoint(&self, checkpoint: &AuditCheckpoint) -> bool {
        checkpoint.verify(&self.mac_key)
    }

    /// Flush and sync the log.
    pub fn sync(&self) -> Result<(), StoreError> {
        self.lock_log().sync()?;
        Ok(())
    }

    /// Write a snapshot and reset the log.
    ///
    /// The order is deliberate and is the whole point of the operation:
    ///
    /// 1. write the new snapshot to a temporary file and fsync it;
    /// 2. rename it into place and fsync the directory;
    /// 3. only then reset the log.
    ///
    /// A crash before step 2 leaves the previous snapshot and the full log — no
    /// data is lost. A crash between 2 and 3 leaves the new snapshot and a log
    /// whose records are already reflected in it, which replays harmlessly.
    ///
    /// # `payload` must represent everything the log holds
    ///
    /// This is the sharp edge, and it is sharp in the direction of silent data
    /// loss. Step 3 **discards every frame in the log**, and the log is where
    /// the router keeps things that are not otherwise persisted:
    ///
    /// - API key creations and revocations, replayed by `restore_keys` — a
    ///   compaction whose payload omits them leaves every issued key
    ///   non-authenticating after the next restart;
    /// - the audit chain, read by [`Store::audit_records`] — omitting it
    ///   discards the durable history the checkpoints anchor;
    /// - configuration activations, replayed by `resume_activation`.
    ///
    /// So this is not a maintenance task that can be scheduled on a timer
    /// against the current state: it needs a snapshot codec that encodes all
    /// three, and that codec does not exist. Calling this with a partial
    /// payload compiles, succeeds, and destroys the rest.
    ///
    /// Until that codec exists, the log's growth is bounded by
    /// [`log::MAX_LOG_BYTES`], which refuses to replay an oversized log rather
    /// than exhausting memory — a visible failure instead of a silent one.
    pub fn compact(&self, payload: &[u8]) -> Result<(), StoreError> {
        // Take the log lock for the whole operation so that no append can land
        // between the snapshot being taken and the log being reset.
        let mut log = self.lock_log();
        let sequence = self.sequence.load(Ordering::SeqCst);
        let (audit_head, audit_count) = {
            let chain = self.lock_audit();
            (chain.head(), chain.count())
        };

        write_atomic(&self.dir, SNAPSHOT_FILE, payload)?;
        write_atomic(
            &self.dir,
            SNAPSHOT_META,
            &encode_meta(sequence, audit_head, audit_count, payload, &self.mac_key),
        )?;
        log.reset()?;
        Ok(())
    }

    /// Read audit records from the durable chain, newest first.
    ///
    /// The in-memory index the management API reads is a bounded ring that
    /// starts empty on every restart. That is the right shape for the common
    /// case — a screen showing recent activity — and the wrong one for an
    /// investigation, which is exactly the case that needs to look further back
    /// than the ring holds and across the restart that may have been part of
    /// the incident.
    ///
    /// `before_sequence` pages backwards: pass `None` for the newest page, then
    /// the lowest sequence returned to continue. `limit` is clamped, so a
    /// caller cannot ask the router to materialise the whole chain.
    ///
    /// This replays the log, which is why it is not the hot path. It is
    /// deliberately not cached: an investigation reading a stale cache of the
    /// audit trail is worse than one that waits.
    pub fn audit_records(
        &self,
        before_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, AuditRecord)>, StoreError> {
        let limit = limit.min(MAX_AUDIT_PAGE);
        let mut log = self.lock_log();
        // Only audit frames are kept. Every frame is still verified; this
        // decides what is materialised, so a page of the chain does not cost
        // the whole log in memory.
        let replay = log.replay_retaining(&self.mac_key, |frame| {
            frame.kind == RecordKind::AuditEvent
        })?;

        let mut out: Vec<(u64, AuditRecord)> = replay
            .frames
            .iter()
            .filter(|frame| frame.kind == RecordKind::AuditEvent)
            .filter(|frame| before_sequence.is_none_or(|before| frame.sequence < before))
            .filter_map(|frame| {
                AuditRecord::from_payload(&frame.payload).map(|record| (frame.sequence, record))
            })
            .collect();
        // Newest first, which is the order an investigation reads in.
        out.reverse();
        out.truncate(limit);
        Ok(out)
    }

    /// Every audit checkpoint in the durable log, oldest first.
    ///
    /// Specification 11.2 calls checkpoints the trust anchor for the chain, and
    /// requires them "exported to immutable storage". A caller cannot ship them
    /// without being able to read them, and until this existed nothing could.
    pub fn checkpoints(&self) -> Result<Vec<AuditCheckpoint>, StoreError> {
        let mut log = self.lock_log();
        let replay = log.replay_retaining(&self.mac_key, |frame| {
            frame.kind == RecordKind::AuditCheckpoint
        })?;
        Ok(replay
            .frames
            .iter()
            .filter(|frame| frame.kind == RecordKind::AuditCheckpoint)
            .filter_map(|frame| AuditCheckpoint::from_payload(&frame.payload))
            // A checkpoint that does not verify under this store's key is not a
            // checkpoint; exporting one would ship a trust anchor that anchors
            // nothing, which is worse than exporting none.
            .filter(|checkpoint| self.verify_checkpoint(checkpoint))
            .collect())
    }

    /// Every payload of the given kinds, in log order.
    ///
    /// For state a component rebuilds at startup and the store has no opinion
    /// about — policy drafts, for instance. Returns kinds alongside payloads so
    /// a caller can interleave a record and its closing record without
    /// replaying twice.
    pub fn records_of_kinds(
        &self,
        kinds: &[RecordKind],
    ) -> Result<Vec<(RecordKind, Vec<u8>)>, StoreError> {
        let mut log = self.lock_log();
        let replay = log.replay_retaining(&self.mac_key, |frame| kinds.contains(&frame.kind))?;
        Ok(replay
            .frames
            .iter()
            .filter(|frame| kinds.contains(&frame.kind))
            .map(|frame| (frame.kind, frame.payload.clone()))
            .collect())
    }

    /// Read the current snapshot, if any.
    pub fn snapshot(&self) -> Result<Option<SnapshotState>, StoreError> {
        read_snapshot(&self.dir, &self.mac_key)
    }

    /// Copy a consistent point-in-time backup into `target`.
    ///
    /// Specification 11.2: "supports point-in-time backup by copying a
    /// validated snapshot plus log boundary." The log lock is held so the
    /// boundary is exact.
    pub fn backup_to(&self, target: &Path) -> Result<BackupManifest, StoreError> {
        ensure_dir(target)?;
        let log = self.lock_log();
        let log_len = log.len();

        let snapshot_payload = read_optional(&self.dir.join(SNAPSHOT_FILE))?;
        let snapshot_meta = read_optional(&self.dir.join(SNAPSHOT_META))?;
        let log_bytes = read_optional(&self.dir.join(LOG_FILE))?.unwrap_or_default();
        // Copy up to the recorded boundary, and never past what the file
        // actually holds: `log_len` is the writer's view, while `log_bytes` is
        // what a reader just found on disk, and a truncated or replaced state
        // directory can make the second shorter than the first.
        let boundary = usize::try_from(log_len)
            .unwrap_or(usize::MAX)
            .min(log_bytes.len());
        let bounded_log = log_bytes.get(..boundary).unwrap_or(&log_bytes);

        if let Some(payload) = &snapshot_payload {
            write_atomic(target, SNAPSHOT_FILE, payload)?;
        }
        if let Some(meta) = &snapshot_meta {
            write_atomic(target, SNAPSHOT_META, meta)?;
        }
        write_atomic(target, LOG_FILE, bounded_log)?;

        Ok(BackupManifest {
            sequence: self.sequence.load(Ordering::SeqCst),
            // What was actually copied, which is what the field documents. On a
            // healthy directory this equals `log_len`; when the file on disk is
            // shorter than the writer's view it is the smaller figure, so the
            // manifest never overstates the backup.
            log_bytes: u64::try_from(bounded_log.len()).unwrap_or(u64::MAX),
            snapshot_bytes: snapshot_payload
                .map_or(0, |p| u64::try_from(p.len()).unwrap_or(u64::MAX)),
            audit_head: self.lock_audit().head(),
        })
    }
}

/// What a backup captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifest {
    /// The sequence number at the boundary.
    pub sequence: u64,
    /// Bytes of log copied.
    pub log_bytes: u64,
    /// Bytes of snapshot copied.
    pub snapshot_bytes: u64,
    /// The audit chain head at the boundary.
    pub audit_head: [u8; 32],
}

/// The result of appending an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAppended {
    /// The record's sequence number.
    pub sequence: u64,
    /// The new chain head.
    pub link: [u8; 32],
    /// A checkpoint, if one fell due.
    pub checkpoint: Option<AuditCheckpoint>,
}

/// Encode `snapshot.meta`.
///
/// The MAC covers a digest of the snapshot payload as well as the position
/// fields. Authenticating the metadata alone would leave `snapshot.bin`
/// unprotected: an attacker with write access to the state directory could
/// substitute a different snapshot body and keep the genuine metadata, and the
/// store would accept it as authentic state at the recorded sequence.
fn encode_meta(
    sequence: u64,
    audit_head: [u8; 32],
    audit_count: u64,
    payload: &[u8],
    mac_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(META_LEN);
    out.extend_from_slice(META_MAGIC);
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&audit_head);
    out.extend_from_slice(&audit_count.to_le_bytes());
    out.extend_from_slice(&hypellm_crypto::sha256(payload));
    let mac = hypellm_crypto::hmac_sha256(mac_key, &out);
    out.extend_from_slice(&mac);
    out
}

/// Read and authenticate the snapshot.
///
/// Specification 11.2: startup "fails closed on protected-record integrity
/// errors". The MAC was previously written and never checked, so `snapshot.meta`
/// could be edited to rewind the sequence or substitute an audit head — either
/// of which lets a tampered log verify against a chain that never covered it.
fn read_snapshot(dir: &Path, mac_key: &[u8]) -> Result<Option<SnapshotState>, StoreError> {
    let Some(payload) = read_optional(&dir.join(SNAPSHOT_FILE))? else {
        return Ok(None);
    };
    let Some(meta) = read_optional(&dir.join(SNAPSHOT_META))? else {
        return Err(StoreError::CorruptSnapshotMetadata);
    };
    if meta.len() != META_LEN || meta.get(0..4) != Some(&META_MAGIC[..]) {
        return Err(StoreError::CorruptSnapshotMetadata);
    }

    let (signed, presented) = meta.split_at(META_LEN - 32);
    let expected = hypellm_crypto::hmac_sha256(mac_key, signed);
    if !hypellm_crypto::ct::eq(presented, &expected) {
        return Err(StoreError::SnapshotIntegrity);
    }

    let mut sequence = [0u8; 8];
    sequence.copy_from_slice(signed.get(4..12).ok_or(StoreError::CorruptSnapshotMetadata)?);
    let mut audit_head = [0u8; 32];
    audit_head.copy_from_slice(signed.get(12..44).ok_or(StoreError::CorruptSnapshotMetadata)?);
    let mut audit_count = [0u8; 8];
    audit_count.copy_from_slice(signed.get(44..52).ok_or(StoreError::CorruptSnapshotMetadata)?);
    let recorded_digest = signed.get(52..84).ok_or(StoreError::CorruptSnapshotMetadata)?;

    // The metadata is authentic; confirm it describes *this* payload.
    if !hypellm_crypto::ct::eq(recorded_digest, &hypellm_crypto::sha256(&payload)) {
        return Err(StoreError::SnapshotIntegrity);
    }

    Ok(Some(SnapshotState {
        payload,
        sequence: u64::from_le_bytes(sequence),
        audit_head,
        audit_count: u64::from_le_bytes(audit_count),
    }))
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_log_that_never_reaches_end_of_file_is_refused_rather_than_replayed_forever() {
        // Replay's size guard reads `metadata().len()`, which is right for a
        // regular file and wrong for anything else. `/dev/full` reports a
        // length of zero and yields bytes forever, so the guard passed and the
        // streaming replay read without end — a startup hang with no
        // diagnostic. Specification 3.2 bounds every loop, so the reader now
        // counts what it has actually read rather than trusting the filesystem.
        //
        // A character device is not a realistic log, but a file that grows
        // during replay has the same shape, and the failure mode is the same.
        if !std::path::Path::new("/dev/full").exists() {
            return;
        }
        let dir = TempDir::new("endless-log");
        let log = dir.join("log.bin");
        if std::os::unix::fs::symlink("/dev/full", &log).is_err() {
            return;
        }

        // What must hold is that replay *terminates and refuses*. Which
        // refusal it gives depends on the content: an all-zero source fails
        // the offset-zero format check before it can read far enough to hit the
        // size bound, and that is the better answer — it stops immediately
        // rather than after 256 MiB. The size bound itself is covered directly
        // by `the_window_stops_reading_an_endless_source_after_max_log_bytes`,
        // which drives the case where valid frames come first.
        let mut opened = Log::open(&log, false).expect("open the device");
        match opened.replay(b"endless-log-mac-key") {
            Err(LogError::UnknownFormat { .. } | LogError::TooLarge { .. }) => {}
            other => panic!("an endless log must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_audit_append_leaves_the_chain_where_it_was() {
        // `AuditChain::append` advances the running head *before* the record is
        // written, because the record's payload contains the link. So a durable
        // write that fails — a full disk — used to leave the live head
        // including a record that never reached disk. Every later record then
        // chained from that phantom head, and on restart replay rebuilt the
        // chain without it, so the links no longer matched and
        // `audit_chain_broken_at` reported damage.
        //
        // A full disk presenting as tampering is the wrong incident entirely:
        // one is a page to whoever owns the storage, the other is a security
        // response.
        //
        // Tested against the chain directly. Injecting a write failure into an
        // open `Store` is not reachable from safe Rust with no dependencies —
        // the file descriptor is already open, so permissions no longer apply,
        // and `/dev/full` cannot be replayed to open a store on it at all (see
        // the test above). What is testable is that the restore is exact, which
        // is the part with logic in it; the two-line wiring in `append_audit`
        // is verified by reading.
        let mut chain = AuditChain::new();
        chain.append(AuditEvent::new(1, "admin", AuditAction::KeyCreated));
        let head = chain.head();
        let count = chain.count();

        // The record that "fails to write".
        let _ = chain.append(AuditEvent::new(2, "admin", AuditAction::KeyRevoked));
        assert_ne!(chain.head(), head, "the fixture must actually advance");

        chain = AuditChain::resume(head, count);
        assert_eq!(chain.head(), head);
        assert_eq!(chain.count(), count);

        // And the next record chains from the restored head, so replay from
        // disk rebuilds the same links the live chain holds.
        let next = chain.append(AuditEvent::new(3, "admin", AuditAction::KeyCreated));
        assert_eq!(
            next.previous_link, head,
            "the record after a failed append did not chain from the last durable one"
        );
    }
    use super::*;

    const KEY: &[u8] = b"store-integration-mac-key";

    fn open(dir: &Path) -> (Store, Recovery) {
        Store::open(dir, KEY, 0).expect("open store")
    }

    #[test]
    fn an_intact_audit_chain_verifies_on_recovery() {
        let dir = TempDir::new("store-chain-intact");
        {
            let (store, _) = open(dir.path());
            for n in 0..6 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
        }
        let (_store, recovery) = open(dir.path());
        assert_eq!(recovery.audit_chain_broken_at, None);
    }

    #[test]
    fn a_removed_audit_record_breaks_the_chain() {
        // The tamper the chain exists to detect. Every remaining frame is
        // individually well-formed and correctly MAC'd — only the *sequence* of
        // links is wrong, which is invisible to any per-frame check.
        //
        // Recovery used to adopt each record's own `link()` as the new head
        // without comparing it to the previous one, which made the chain
        // self-consistent by construction and therefore evidence of nothing.
        let dir = TempDir::new("store-chain-removed");
        {
            let (store, _) = open(dir.path());
            for n in 0..6 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
        }

        // Rebuild the log without the third audit frame. The store is a
        // single-writer, so everything the rebuild needs is read in one open.
        let surviving: Vec<(RecordKind, Vec<u8>)> = {
            let (_store, recovery) = open(dir.path());
            let removed = recovery
                .frames
                .iter()
                .filter(|f| f.kind == RecordKind::AuditEvent)
                .nth(2)
                .map(|f| f.sequence)
                .expect("a middle audit record");
            recovery
                .frames
                .iter()
                .filter(|f| f.sequence != removed)
                .map(|f| (f.kind, f.payload.clone()))
                .collect()
        };

        let rebuilt = TempDir::new("store-chain-removed-rebuilt");
        {
            let (store, _) = open(rebuilt.path());
            for (kind, payload) in &surviving {
                store.append(*kind, payload).expect("append");
            }
        }

        let (_store, recovery) = open(rebuilt.path());
        assert!(
            recovery.audit_chain_broken_at.is_some(),
            "a removed audit record left the chain reported as intact"
        );
    }

    #[test]
    fn an_unparseable_audit_record_breaks_the_chain() {
        // DI-043's shape: a frame that authenticates under the store MAC but is
        // not a decodable audit record. It used to be skipped silently, which
        // left the live head diverged from the durable history with no error
        // anywhere — the one outcome an audit trail may not have.
        let dir = TempDir::new("store-chain-unparseable");
        {
            let (store, _) = open(dir.path());
            for n in 0..3 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
            // Well-framed, correctly MAC'd, and not an audit record.
            store
                .append(RecordKind::AuditEvent, b"not an audit record")
                .unwrap();
            for n in 3..6 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
        }

        let (_store, recovery) = open(dir.path());
        assert!(
            recovery.audit_chain_broken_at.is_some(),
            "an undecodable audit frame was skipped in silence"
        );
    }

    #[test]
    fn a_reordered_audit_record_breaks_the_chain() {
        let dir = TempDir::new("store-chain-reordered");
        {
            let (store, _) = open(dir.path());
            for n in 0..6 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
        }

        let mut payloads: Vec<(RecordKind, Vec<u8>)> = {
            let (_store, recovery) = open(dir.path());
            recovery
                .frames
                .iter()
                .map(|f| (f.kind, f.payload.clone()))
                .collect()
        };
        // Swap two adjacent audit records.
        let audit_positions: Vec<usize> = payloads
            .iter()
            .enumerate()
            .filter(|(_, (kind, _))| *kind == RecordKind::AuditEvent)
            .map(|(i, _)| i)
            .collect();
        let (Some(a), Some(b)) = (audit_positions.get(1), audit_positions.get(2)) else {
            panic!("expected at least three audit records");
        };
        payloads.swap(*a, *b);

        let rebuilt = TempDir::new("store-chain-reordered-rebuilt");
        {
            let (store, _) = open(rebuilt.path());
            for (kind, payload) in &payloads {
                store.append(*kind, payload).expect("append");
            }
        }

        let (_store, recovery) = open(rebuilt.path());
        assert!(
            recovery.audit_chain_broken_at.is_some(),
            "two swapped audit records left the chain reported as intact"
        );
    }

    #[test]
    fn tampered_snapshot_metadata_is_refused() {
        // Specification 11.2: startup "fails closed on protected-record
        // integrity errors". The MAC was previously written and never checked,
        // so rewinding the sequence here was accepted silently.
        let dir = TempDir::new("store-meta-tamper");
        {
            let (store, _) = open(dir.path());
            store
                .append_audit(AuditEvent::new(1, "admin", AuditAction::KeyCreated))
                .unwrap();
            store.compact(b"snapshot-state").expect("compact");
        }

        let meta_path = dir.path().join(SNAPSHOT_META);
        let mut meta = std::fs::read(&meta_path).expect("read meta");
        // Rewind the recorded sequence.
        meta[4] ^= 0xff;
        std::fs::write(&meta_path, &meta).expect("write meta");

        match Store::open(dir.path(), KEY, 0) {
            Err(StoreError::SnapshotIntegrity) => {}
            other => panic!("expected an integrity failure, got {other:?}"),
        }
    }

    #[test]
    fn a_substituted_snapshot_payload_is_refused() {
        // Authenticating the metadata alone would leave `snapshot.bin` free to
        // swap while the genuine metadata vouched for it.
        let dir = TempDir::new("store-payload-swap");
        {
            let (store, _) = open(dir.path());
            store.compact(b"the-real-state").expect("compact");
        }

        std::fs::write(dir.path().join(SNAPSHOT_FILE), b"substituted-state").expect("write");

        match Store::open(dir.path(), KEY, 0) {
            Err(StoreError::SnapshotIntegrity) => {}
            other => panic!("expected an integrity failure, got {other:?}"),
        }
    }

    #[test]
    fn a_snapshot_written_under_another_key_is_refused() {
        let dir = TempDir::new("store-wrong-key");
        {
            let (store, _) = open(dir.path());
            store.compact(b"state").expect("compact");
        }

        match Store::open(dir.path(), b"a-completely-different-mac-key", 0) {
            Err(StoreError::SnapshotIntegrity) => {}
            other => panic!("expected an integrity failure, got {other:?}"),
        }
    }

    #[test]
    fn an_authentic_snapshot_still_loads() {
        let dir = TempDir::new("store-authentic");
        {
            let (store, _) = open(dir.path());
            store
                .append_audit(AuditEvent::new(1, "admin", AuditAction::KeyCreated))
                .unwrap();
            store.compact(b"authentic-state").expect("compact");
        }

        let (_store, recovery) = open(dir.path());
        let snapshot = recovery.snapshot.expect("a snapshot");
        assert_eq!(snapshot.payload, b"authentic-state");
    }

    #[test]
    fn debug_output_never_contains_the_mac_key() {
        // The store MAC key authenticates protected frames and the audit hash
        // chain. With it, a tampered log verifies.
        let dir = TempDir::new("store-debug-redaction");
        let (store, _) = open(dir.path());
        let rendered = format!("{store:?}");
        assert!(
            !rendered.contains(&String::from_utf8_lossy(KEY).to_string()),
            "Store leaked the MAC key: {rendered}"
        );
        assert!(rendered.contains("[redacted"));
    }

    #[test]
    fn a_fresh_store_recovers_nothing() {
        let dir = TempDir::new("store-fresh");
        let (store, recovery) = open(dir.path());
        assert!(recovery.snapshot.is_none());
        assert!(recovery.frames.is_empty());
        assert!(!recovery.truncated);
        assert_eq!(store.next_sequence(), 1);
        assert_eq!(store.audit_head(), audit::GENESIS);
    }

    #[test]
    fn records_survive_a_restart() {
        let dir = TempDir::new("store-restart");
        {
            let (store, _) = open(dir.path());
            store.append(RecordKind::UsageAggregate, b"usage-1").unwrap();
            store.append(RecordKind::ApiKey, b"key-record").unwrap();
            store.sync().unwrap();
        }
        let (store, recovery) = open(dir.path());
        assert_eq!(recovery.frames.len(), 2);
        assert_eq!(recovery.frames[0].payload, b"usage-1");
        assert_eq!(store.next_sequence(), 3);
    }

    #[test]
    fn sequence_numbers_are_monotonic_across_restarts() {
        let dir = TempDir::new("store-seq");
        {
            let (store, _) = open(dir.path());
            for i in 0..5 {
                let seq = store
                    .append(RecordKind::UsageAggregate, format!("r{i}").as_bytes())
                    .unwrap();
                assert_eq!(seq, i + 1);
            }
        }
        let (store, _) = open(dir.path());
        assert_eq!(
            store.append(RecordKind::UsageAggregate, b"after").unwrap(),
            6
        );
    }

    #[test]
    fn the_audit_chain_survives_a_restart() {
        let dir = TempDir::new("store-audit-restart");
        let head_before = {
            let (store, _) = open(dir.path());
            for n in 0..5u64 {
                store
                    .append_audit(AuditEvent::new(1000 + n, "admin", AuditAction::Login))
                    .unwrap();
            }
            assert_eq!(store.audit_count(), 5);
            store.audit_head()
        };

        let (store, recovery) = open(dir.path());
        assert_eq!(
            store.audit_head(),
            head_before,
            "the chain head must be reconstructed from the log"
        );

        // And the recovered records verify as a chain.
        let records: Vec<AuditRecord> = recovery
            .of_kind(RecordKind::AuditEvent)
            .filter_map(|f| AuditRecord::from_payload(&f.payload))
            .collect();
        assert_eq!(records.len(), 5);
        assert!(verify_chain(&records).is_intact());
    }

    #[test]
    fn compaction_preserves_state_and_empties_the_log() {
        let dir = TempDir::new("store-compact");
        {
            let (store, _) = open(dir.path());
            for n in 0..10u64 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                    .unwrap();
            }
            store.compact(b"compacted-state-v1").unwrap();
            // Post-compaction appends land in the fresh log.
            store.append(RecordKind::UsageAggregate, b"after").unwrap();
        }

        let (store, recovery) = open(dir.path());
        let snapshot = recovery.snapshot.expect("a snapshot");
        assert_eq!(snapshot.payload, b"compacted-state-v1");
        assert_eq!(snapshot.audit_count, 10);
        assert_eq!(recovery.frames.len(), 1, "only post-compaction records remain");
        assert_eq!(recovery.frames[0].payload, b"after");
        assert_eq!(
            store.audit_head(),
            snapshot.audit_head,
            "the chain resumes from the snapshot"
        );
        assert_eq!(store.audit_count(), 10);
    }

    #[test]
    fn compaction_keeps_sequence_numbers_moving_forward() {
        let dir = TempDir::new("store-compact-seq");
        let (store, _) = open(dir.path());
        for _ in 0..5 {
            store.append(RecordKind::UsageAggregate, b"x").unwrap();
        }
        store.compact(b"state").unwrap();
        let seq = store.append(RecordKind::UsageAggregate, b"y").unwrap();
        assert_eq!(seq, 6, "compaction must not reuse sequence numbers");
    }

    #[test]
    fn a_missing_snapshot_metadata_file_fails_closed() {
        let dir = TempDir::new("store-meta-missing");
        {
            let (store, _) = open(dir.path());
            store.compact(b"state").unwrap();
        }
        std::fs::remove_file(dir.join("snapshot.meta")).unwrap();
        match Store::open(dir.path(), KEY, 0) {
            Err(StoreError::CorruptSnapshotMetadata) => {}
            other => panic!("expected corrupt metadata, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_snapshot_metadata_fails_closed() {
        let dir = TempDir::new("store-meta-corrupt");
        {
            let (store, _) = open(dir.path());
            store.compact(b"state").unwrap();
        }
        std::fs::write(dir.join("snapshot.meta"), b"garbage").unwrap();
        assert!(matches!(
            Store::open(dir.path(), KEY, 0),
            Err(StoreError::CorruptSnapshotMetadata)
        ));
    }

    #[test]
    fn a_torn_tail_is_recovered_and_reported() {
        let dir = TempDir::new("store-torn");
        {
            let (store, _) = open(dir.path());
            store.append(RecordKind::UsageAggregate, b"complete").unwrap();
        }
        // Append a partial frame, as a crash mid-write would.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join("log.bin"))
                .unwrap();
            f.write_all(b"HYPE\x01\x00").unwrap();
            f.sync_all().unwrap();
        }

        let (store, recovery) = open(dir.path());
        assert!(recovery.truncated, "the torn tail must be reported");
        assert_eq!(recovery.frames.len(), 1);
        assert!(recovery.stop_reason.expect("reason").is_recoverable_tail());

        // The store is usable and the log no longer holds the partial frame.
        store.append(RecordKind::UsageAggregate, b"after").unwrap();
        drop(store); // release the single-writer lock before reopening
        let (_, recovery) = open(dir.path());
        assert!(!recovery.truncated);
        assert_eq!(recovery.frames.len(), 2);
    }

    #[test]
    fn tampering_with_the_log_prevents_startup() {
        let dir = TempDir::new("store-tampered");
        {
            let (store, _) = open(dir.path());
            store
                .append_audit(AuditEvent::new(1, "admin", AuditAction::PolicyPublished))
                .unwrap();
        }

        // Forge the payload and recompute the CRC, as an attacker with write
        // access to the state directory would.
        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        let payload_start = frame::HEADER_LEN;
        let payload_len = bytes.len() - payload_start - frame::CRC_LEN - frame::MAC_LEN;
        bytes[payload_start + 40] ^= 0x20;
        let body_len = payload_start + payload_len;
        let crc = hypellm_crypto::crc32(&bytes[..body_len]);
        bytes[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        match Store::open(dir.path(), KEY, 0) {
            Err(StoreError::Log(LogError::Integrity { error, .. })) => {
                assert!(error.is_integrity_violation());
            }
            other => panic!("tampering must prevent startup, got {other:?}"),
        }
    }

    #[test]
    fn the_store_is_single_writer() {
        let dir = TempDir::new("store-exclusive");
        let (_first, _) = open(dir.path());
        match Store::open(dir.path(), KEY, 0) {
            Err(StoreError::Locked(_)) => {}
            other => panic!("expected a lock error, got {other:?}"),
        }
    }

    #[test]
    fn checkpoints_fall_due_on_the_configured_interval() {
        let dir = TempDir::new("store-checkpoint");
        let (store, _) = Store::open(dir.path(), KEY, 3).expect("open");

        let mut checkpoints = 0;
        for n in 0..9u64 {
            let appended = store
                .append_audit(AuditEvent::new(n, "admin", AuditAction::Login))
                .unwrap();
            if let Some(checkpoint) = appended.checkpoint {
                assert!(store.verify_checkpoint(&checkpoint));
                assert_eq!(checkpoint.link, appended.link);
                checkpoints += 1;
            }
        }
        assert_eq!(checkpoints, 3, "one checkpoint every three records");
    }

    #[test]
    fn a_forced_checkpoint_covers_the_current_head() {
        let dir = TempDir::new("store-force-checkpoint");
        let (store, _) = open(dir.path());
        store
            .append_audit(AuditEvent::new(1, "admin", AuditAction::Login))
            .unwrap();
        let checkpoint = store.checkpoint_audit(1_767_225_600_000).unwrap();
        assert!(store.verify_checkpoint(&checkpoint));
        assert_eq!(checkpoint.link, store.audit_head());
    }

    #[test]
    fn backup_captures_a_consistent_boundary() {
        let source = TempDir::new("store-backup-src");
        let dest = TempDir::new("store-backup-dst");

        let manifest = {
            let (store, _) = open(source.path());
            for n in 0..20u64 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::Login))
                    .unwrap();
            }
            store.compact(b"snapshot-state").unwrap();
            for n in 20..25u64 {
                store
                    .append_audit(AuditEvent::new(n, "admin", AuditAction::Logout))
                    .unwrap();
            }
            store.backup_to(dest.path()).unwrap()
        };

        assert_eq!(manifest.sequence, 25);
        assert!(manifest.log_bytes > 0);
        assert_eq!(manifest.snapshot_bytes, b"snapshot-state".len() as u64);

        // The backup opens as a working store with the same audit head.
        let (restored, recovery) = open(dest.path());
        assert_eq!(restored.audit_head(), manifest.audit_head);
        assert_eq!(
            recovery.snapshot.as_ref().expect("snapshot").payload,
            b"snapshot-state"
        );
        assert_eq!(recovery.of_kind(RecordKind::AuditEvent).count(), 5);
    }

    #[test]
    fn backup_survives_a_log_file_truncated_under_it() {
        // The hostile-state-directory boundary: the writer's tracked log length
        // is longer than what a reader actually finds on disk, because the file
        // was truncated or replaced. `backup_to` must copy what is there and
        // return, not panic on an out-of-range slice.
        let source = TempDir::new("store-backup-truncated-src");
        let dest = TempDir::new("store-backup-truncated-dst");

        let (store, _) = open(source.path());
        for n in 0..10u64 {
            store
                .append_audit(AuditEvent::new(n, "admin", AuditAction::Login))
                .unwrap();
        }

        // Truncate log.bin behind the store's back, so the in-memory length is
        // larger than the file.
        let log_path = source.path().join(LOG_FILE);
        let full = std::fs::read(&log_path).unwrap();
        assert!(full.len() > 8, "the log should hold the appended frames");
        std::fs::write(&log_path, &full[..8]).unwrap();

        let manifest = store.backup_to(dest.path()).unwrap();
        assert_eq!(
            manifest.log_bytes, 8,
            "the backup reports only the bytes that were actually on disk"
        );
        assert_eq!(std::fs::read(dest.path().join(LOG_FILE)).unwrap(), &full[..8]);
    }

    #[test]
    fn backup_of_a_removed_log_file_is_empty_rather_than_a_panic() {
        let source = TempDir::new("store-backup-missing-src");
        let dest = TempDir::new("store-backup-missing-dst");

        let (store, _) = open(source.path());
        store
            .append_audit(AuditEvent::new(1, "admin", AuditAction::Login))
            .unwrap();
        std::fs::remove_file(source.path().join(LOG_FILE)).unwrap();

        let manifest = store.backup_to(dest.path()).unwrap();
        assert_eq!(manifest.log_bytes, 0);
    }

    #[test]
    fn concurrent_appends_produce_unique_sequences() {
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new("store-concurrent");
        let (store, _) = open(dir.path());
        let store = Arc::new(store);

        let mut handles = Vec::new();
        for t in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let mut seqs = Vec::new();
                for i in 0..50 {
                    seqs.push(
                        store
                            .append(RecordKind::UsageAggregate, format!("{t}-{i}").as_bytes())
                            .unwrap(),
                    );
                }
                seqs
            }));
        }

        let mut all = BTreeSet::new();
        for h in handles {
            for seq in h.join().expect("thread") {
                assert!(all.insert(seq), "sequence {seq} was issued twice");
            }
        }
        assert_eq!(all.len(), 400);

        // And the log replays cleanly, which requires the sequences to be
        // written in increasing order.
        drop(store);
        let (_, recovery) = open(dir.path());
        assert_eq!(recovery.frames.len(), 400);
    }
}
