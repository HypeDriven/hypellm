//! The append-only framed log.
//!
//! Specification 11.2: "The default embedded store is an append-only framed log
//! plus periodic snapshot… Startup replays only complete valid frames and fails
//! closed on protected-record integrity errors."
//!
//! Those two clauses pull in opposite directions and the distinction matters:
//!
//! - A **torn tail** is normal. A crash between `write` and `fsync` leaves a
//!   partial frame. Replay stops there, the log is truncated to the last good
//!   frame, and the router starts. Refusing to start would turn every power
//!   loss into an outage.
//! - A **MAC failure** is not normal. It means a protected record was modified
//!   by something holding write access to the state directory. Replay stops and
//!   startup fails, because continuing would run on configuration or audit
//!   history that somebody edited.

use crate::frame::{self, Frame, FrameError, RecordKind};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The outcome of replaying a log.
#[derive(Debug)]
pub struct Replay {
    /// Frames that decoded cleanly, in order.
    pub frames: Vec<Frame>,
    /// Byte offset of the first frame that did not decode, if any.
    ///
    /// Everything from here on was discarded.
    pub truncated_at: Option<u64>,
    /// Why replay stopped, if it stopped early.
    pub stop_reason: Option<FrameError>,
    /// Total bytes of valid log content.
    pub valid_len: u64,
}

impl Replay {
    /// The highest sequence number seen.
    #[must_use]
    pub fn max_sequence(&self) -> u64 {
        self.frames.last().map_or(0, |f| f.sequence)
    }

    /// Frames of one kind.
    pub fn of_kind(&self, kind: RecordKind) -> impl Iterator<Item = &Frame> {
        self.frames.iter().filter(move |f| f.kind == kind)
    }
}

/// A log failure.
#[derive(Debug)]
pub enum LogError {
    /// A protected record failed verification. Startup must fail closed.
    Integrity {
        /// Byte offset of the offending frame.
        offset: u64,
        /// What was wrong.
        error: FrameError,
    },
    /// Sequence numbers were not monotonic, meaning records were reordered or
    /// removed.
    NonMonotonicSequence {
        /// The previous sequence number.
        previous: u64,
        /// The sequence number that followed it.
        found: u64,
    },
    /// The first frame in a non-empty log did not decode, and the failure is
    /// not one a torn write produces.
    ///
    /// The file is not this router's log: another format, or another version
    /// of this one. Refusing to start is the only answer that does not destroy
    /// it — truncating would discard every byte and report it as a crash
    /// artifact.
    UnknownFormat {
        /// What decoding the first frame reported.
        error: FrameError,
    },
    /// A frame failed to decode, and a valid frame with a higher sequence
    /// number was found after it.
    ///
    /// That combination distinguishes damage in the *middle* of the log from a
    /// torn tail. A tail is the only thing a clean crash produces, and
    /// truncating it is correct. Damage with valid records after it means those
    /// records — durably recorded key revocations, configuration activations,
    /// audit entries — would be discarded by a truncating recovery, silently.
    /// Refusing to start is the only answer that does not lose them.
    MidFileDamage {
        /// Byte offset where decoding failed.
        offset: u64,
        /// The highest sequence number recovered before the damage.
        last_good_sequence: u64,
        /// A sequence number found *after* the damage, proving records follow.
        surviving_sequence: u64,
    },
    /// The log is larger than may be replayed into memory.
    TooLarge {
        /// The log's size on disk.
        bytes: u64,
        /// The ceiling.
        limit: u64,
    },
    /// An I/O failure.
    Io(io::Error),
}

/// The largest log that may be replayed at startup.
///
/// Replay materialises the file and then its frames, so peak memory is roughly
/// twice this. 256 MiB is far above what a compacting deployment reaches and
/// far below what a node cannot hold.
///
/// This is a *backstop*, not a design: a log that approaches it is one where
/// compaction has stopped running, and the ceiling turns "the router OOMs on
/// restart, repeatedly, and you cannot read the state to find out why" into a
/// message naming the file and the limit.
pub const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Integrity { offset, error } => write!(
                f,
                "store integrity failure at byte {offset}: {error}; refusing to start"
            ),
            Self::UnknownFormat { error } => write!(
                f,
                "the store log does not start with a valid frame ({error}), and the failure \
                 is not one a torn write produces — the file is not this router's log, or \
                 not a version it understands. Truncating it would discard every record it \
                 holds and report the loss as a routine crash artifact, so startup refuses \
                 instead. Point `state_dir` at the right directory, or move this file aside \
                 if you mean to start with an empty log."
            ),
            Self::NonMonotonicSequence { previous, found } => write!(
                f,
                "store sequence went backwards: {found} followed {previous}; refusing to start"
            ),
            Self::MidFileDamage {
                offset,
                last_good_sequence,
                surviving_sequence,
            } => write!(
                f,
                "the store log is damaged at byte {offset}, and record {surviving_sequence} \
                 survives after it (the last intact record before it is \
                 {last_good_sequence}). Truncating would discard every durable record \
                 after the damage — key revocations, configuration activations, audit \
                 entries — so startup refuses instead. Restore from a backup, or recover \
                 the surviving records offline before restarting."
            ),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "the store log is {bytes} bytes, past the {limit}-byte replay limit. \
                 Compaction has not been running: back up the state directory, then \
                 compact it offline or start from a snapshot. Refusing rather than \
                 exhausting memory during startup."
            ),
            Self::Io(e) => write!(f, "store I/O error: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<io::Error> for LogError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Widen a byte count to the `u64` the log offsets are expressed in.
///
/// On every supported target `usize` is no wider than `u64`, so the fallback is
/// unreachable; it exists so that the conversion is checked rather than silent.
/// The first sequence number found after damage that is higher than the last
/// good one, if any.
///
/// Scans byte by byte for the frame magic rather than assuming any alignment:
/// the damage has unknown length, so the next frame can start anywhere. Every
/// candidate is fully decoded and MAC-checked before it counts, so a chance
/// occurrence of the magic inside a payload cannot be mistaken for a frame.
///
/// The scan is bounded by the remaining buffer, which is bounded by the log
/// file, and it runs once at startup on a path that is already about to refuse
/// or truncate. It stops at the first proof rather than cataloguing the damage:
/// one surviving record is enough to make truncation the wrong answer.
/// The largest a single encoded frame can be.
///
/// Derived from the frame format rather than chosen, so it cannot drift away
/// from what `frame::decode` will accept: header, the maximum payload, the CRC,
/// and the MAC. This is the ceiling the streaming window may grow to, and the
/// reason the window is bounded at all.
pub const MAX_FRAME_BYTES: usize =
    frame::HEADER_LEN + frame::MAX_PAYLOAD_LEN + frame::CRC_LEN + frame::MAC_LEN;

/// Initial size of the streaming window.
///
/// Every frame the router actually writes is far below this, so in normal
/// operation the window never grows and replay holds one small buffer rather
/// than the whole file.
const WINDOW_START_BYTES: usize = 64 * 1024;

/// A bounded sliding window over a log file.
///
/// Replay used to `read_to_end` the whole log, so peak startup memory was the
/// file size plus the frames materialised from it (`DI-044`). This holds **one
/// frame** instead: typically `WINDOW_START_BYTES`, and never more than
/// [`MAX_FRAME_BYTES`].
///
/// The window deliberately does **not** parse the length prefix to decide how
/// much to read. A second implementation of "how long is this frame" that
/// disagreed with `frame::decode` is precisely how a log gets silently
/// truncated — the defect class `DI-042` was. Instead it feeds `decode`
/// whatever it has and grows on `FrameError::Incomplete`, which leaves `decode`
/// the single authority on frame length and on validity.
struct Window<R> {
    source: R,
    buf: Vec<u8>,
    /// Bytes of `buf` that hold data, starting at `start`.
    start: usize,
    end: usize,
    /// Whether `source` has returned EOF.
    exhausted: bool,
    /// Total bytes read from `source` so far.
    ///
    /// Replay's size guard reads `metadata().len()`, which is right for a
    /// regular file and wrong for anything else: a character device reports
    /// zero and yields bytes forever, and a file being appended to never
    /// reaches the length that was measured. Trusting it alone made the
    /// streaming replay loop without bound — a startup hang with no diagnostic,
    /// which is worse than the buffered version's out-of-memory crash.
    /// Specification 3.2 bounds every buffer and every loop; this bounds the
    /// loop independently of what the filesystem claims.
    total_read: u64,
    /// Set when `total_read` passed [`MAX_LOG_BYTES`].
    over_limit: bool,
}

impl<R: Read> Window<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            buf: vec![0u8; WINDOW_START_BYTES],
            start: 0,
            end: 0,
            exhausted: false,
            total_read: 0,
            over_limit: false,
        }
    }

    /// The bytes currently available to decode.
    fn available(&self) -> &[u8] {
        self.buf.get(self.start..self.end).unwrap_or(&[])
    }

    /// Drop `count` bytes from the front.
    fn consume(&mut self, count: usize) {
        self.start = self.start.saturating_add(count).min(self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Make more bytes available, growing the buffer only when it is full.
    ///
    /// Returns `false` when the source is exhausted and nothing more can
    /// arrive, which is what turns a persistent `Incomplete` into a torn tail
    /// rather than an infinite retry loop.
    fn refill(&mut self) -> io::Result<bool> {
        if self.exhausted {
            return Ok(false);
        }
        // Compact first: a window that has been consumed from has free space at
        // the front, and reusing it is what keeps a log of small frames from
        // growing the buffer at all.
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end = self.end.saturating_sub(self.start);
            self.start = 0;
        }
        if self.end == self.buf.len() {
            // Full and still `Incomplete`, so this frame needs a larger window.
            // Doubling bounds the number of retries per frame to O(log n) while
            // the ceiling keeps the whole thing bounded.
            if self.buf.len() >= MAX_FRAME_BYTES {
                return Ok(false);
            }
            let grown = self
                .buf
                .len()
                .saturating_mul(2)
                .min(MAX_FRAME_BYTES);
            self.buf.resize(grown, 0);
        }
        let Some(target) = self.buf.get_mut(self.end..) else {
            return Ok(false);
        };
        let read = self.source.read(target)?;
        if read == 0 {
            self.exhausted = true;
            return Ok(false);
        }
        self.end = self.end.saturating_add(read);
        self.total_read = self.total_read.saturating_add(to_u64(read));
        if self.total_read > MAX_LOG_BYTES {
            // Stop reading and say why. Treating it as end-of-file would
            // silently truncate a log that is merely too large, which is the
            // one outcome worse than refusing to start.
            self.over_limit = true;
            self.exhausted = true;
        }
        Ok(true)
    }

    /// Fill the window as far as it will go, for a lookahead scan.
    fn fill(&mut self) -> io::Result<()> {
        while self.end < self.buf.len() && !self.exhausted {
            if !self.refill()? {
                break;
            }
        }
        Ok(())
    }
}

/// The buffered lookahead, retained only for the differential test.
///
/// Replay streams now (`DI-044`), so nothing in the shipped library calls this.
/// It stays because `replay_buffered` — the reference implementation the
/// streaming rewrite is checked against — needs the *old* behaviour to compare
/// with, and a reference that shared the new implementation's helpers would
/// agree with it by construction.
///
/// Whether damage at the current position is followed by a surviving frame,
/// reading forward through a bounded window.
///
/// The streaming counterpart of [`surviving_sequence_after`]. It exists because
/// the distinction it draws is not cosmetic: specification 11.2 truncates a
/// torn *tail*, and doing that to damage in the *middle* of a file discards
/// every durable record after it without a word. `DI-042` was exactly that bug.
///
/// Bounded in memory, not in file extent — it will scan to the end of the log
/// if it has to, through a window that never exceeds [`MAX_FRAME_BYTES`] plus
/// the bytes already buffered. Capping how far it looks would reintroduce the
/// defect for any log with enough garbage after the damage.
fn surviving_sequence_streaming<R: Read>(
    window: &mut Window<R>,
    mac_key: &[u8],
    last_good: Option<u64>,
) -> io::Result<Option<u64>> {
    let threshold = last_good.unwrap_or(0);
    // Offset 0 is the frame that just failed, so start one byte past it.
    window.consume(1);
    let mut final_pass = false;

    loop {
        window.fill()?;
        let available = window.available();
        if available.is_empty() {
            return Ok(None);
        }

        // A candidate the window is too small to judge. It must not be
        // discarded: dropping it because there were not enough bytes yet is a
        // surviving frame missed, and a missed surviving frame is a mid-file
        // corruption reported as a torn tail — the `DI-042` defect exactly.
        let mut incomplete_at: Option<usize> = None;

        for start in 0..available.len() {
            let Some(candidate) = available.get(start..) else {
                break;
            };
            if !candidate.starts_with(&frame::MAGIC) {
                continue;
            }
            // A frame here must both decode and follow, or it proves nothing: a
            // lower sequence number is stale bytes from a compacted log, not a
            // surviving record.
            match frame::decode(candidate, mac_key) {
                Ok(decoded) if decoded.frame.sequence > threshold => {
                    return Ok(Some(decoded.frame.sequence));
                }
                Ok(_) => {}
                Err(FrameError::Incomplete) if !window.exhausted => {
                    incomplete_at = Some(start);
                    break;
                }
                Err(_) => {}
            }
        }

        if final_pass {
            return Ok(None);
        }

        match incomplete_at {
            // Move the candidate to the front so the window can grow behind it,
            // and rescan. Nothing before it is discarded that was not already
            // scanned.
            Some(at) => window.consume(at),
            None => {
                // Everything here was scanned and rejected. Keep only enough to
                // catch a magic straddling the boundary — three bytes, since a
                // magic starting any earlier was already tested in full.
                let keep = frame::MAGIC.len().saturating_sub(1);
                let drop = available.len().saturating_sub(keep);
                window.consume(drop);
            }
        }

        if !window.refill()? {
            // Nothing more can arrive, either because the file ended or because
            // the window is already at its ceiling. Scan once more — with
            // `exhausted` set, an `Incomplete` candidate is now judged rather
            // than deferred — and then stop.
            final_pass = true;
        }
    }
}

#[cfg(test)]
fn surviving_sequence_after(
    remaining: &[u8],
    mac_key: &[u8],
    last_good: Option<u64>,
) -> Option<u64> {
    let threshold = last_good.unwrap_or(0);
    // Start at 1: offset 0 is the frame that just failed to decode.
    for start in 1..remaining.len() {
        let candidate = remaining.get(start..)?;
        if !candidate.starts_with(&frame::MAGIC) {
            continue;
        }
        // A frame here must both decode and follow, or it proves nothing: a
        // lower sequence number is stale bytes from a compacted log, not a
        // surviving record.
        if let Ok(decoded) = frame::decode(candidate, mac_key) {
            if decoded.frame.sequence > threshold {
                return Some(decoded.frame.sequence);
            }
        }
    }
    None
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// An append-only log file.
#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    file: File,
    /// Whether each append is followed by an fsync.
    sync_on_append: bool,
    len: u64,
}

impl Log {
    /// Open or create a log at `path`.
    pub fn open(path: &Path, sync_on_append: bool) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            sync_on_append,
            len,
        })
    }

    /// Current length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the log is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The log path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a frame and return its byte offset.
    pub fn append(
        &mut self,
        kind: RecordKind,
        sequence: u64,
        payload: &[u8],
        mac_key: &[u8],
    ) -> io::Result<u64> {
        let bytes = frame::encode(kind, sequence, payload, mac_key);
        let offset = self.len;
        self.file.write_all(&bytes)?;
        if self.sync_on_append {
            self.file.sync_data()?;
        }
        self.len += to_u64(bytes.len());
        Ok(offset)
    }

    /// Flush and sync.
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_data()
    }

    /// Read and verify every frame.
    ///
    /// Stops at the first frame that does not decode. A recoverable tail
    /// (incomplete or checksum failure) truncates; an integrity violation is an
    /// error.
    pub fn replay(&mut self, mac_key: &[u8]) -> Result<Replay, LogError> {
        self.replay_retaining(mac_key, |_| true)
    }

    /// Replay, keeping only the frames `retain` accepts.
    ///
    /// Every frame is still decoded and every integrity check still runs —
    /// the filter decides what is *kept*, never what is *verified*. A frame
    /// that fails its MAC still aborts startup even if the caller had no
    /// interest in its kind, because integrity is a property of the log and not
    /// of the question being asked of it.
    ///
    /// This is what makes a targeted read cheap. `Store::audit_records`,
    /// `checkpoints`, and `records_of_kinds` each want one kind and previously
    /// materialised every frame in the log to get it — so an audit export on a
    /// large log held the whole thing in memory to return a page of it.
    pub fn replay_retaining(
        &mut self,
        mac_key: &[u8],
        retain: impl Fn(&Frame) -> bool,
    ) -> Result<Replay, LogError> {
        // Specification 3.2 bounds every buffer, and this one is the size of a
        // file on disk. Checked *before* reading rather than while reading: a
        // log large enough to exhaust memory must be refused with a message an
        // operator can act on, not discovered by the allocator.
        //
        // Reaching this bound in normal operation means compaction is not
        // running — see `Store::compact`, which the router's housekeeping
        // thread calls.
        if self.len > MAX_LOG_BYTES {
            return Err(LogError::TooLarge {
                bytes: self.len,
                limit: MAX_LOG_BYTES,
            });
        }
        self.file.seek(SeekFrom::Start(0))?;
        // Streamed through a bounded window rather than read whole (`DI-044`).
        // Peak memory is one frame plus the frames actually retained, not the
        // file plus the frames. `decode` and every integrity check below are
        // untouched: the window decides what is *in memory*, never what is
        // *verified*.
        let mut window = Window::new(&mut self.file);

        let mut frames = Vec::new();
        let mut offset = 0u64;
        let mut previous_sequence: Option<u64> = None;

        let outcome = loop {
            // Grow-and-retry rather than parsing the length prefix here: a
            // second opinion on frame length that disagreed with `decode` is
            // how a log gets silently truncated.
            let decoded = match frame::decode(window.available(), mac_key) {
                Ok(decoded) => decoded,
                Err(FrameError::Incomplete) if window.refill()? => continue,
                Err(e) => {
                    if window.available().is_empty() && matches!(e, FrameError::Incomplete) {
                        // A clean end of file, not a torn frame.
                        break Replay {
                            frames,
                            truncated_at: None,
                            stop_reason: None,
                            valid_len: offset,
                        };
                    }
                    if e.is_integrity_violation() {
                        self.file.seek(SeekFrom::End(0))?;
                        return Err(LogError::Integrity { offset, error: e });
                    }
                    // A log whose *very first* frame does not decode is not a
                    // torn tail. A tail is what a crash leaves behind, and it
                    // requires valid frames in front of it; at offset zero
                    // there are none, so "discard the tail" means "discard the
                    // entire file".
                    //
                    // The two are still distinguishable, which is why this is
                    // scoped by error rather than by offset alone. A crash
                    // mid-append leaves a *short* frame — `Incomplete`, or
                    // `ChecksumMismatch` over partially written bytes — and
                    // both are `is_recoverable_tail()`, so a torn first append
                    // still truncates as it should. `BadMagic`,
                    // `UnsupportedVersion` and `PayloadTooLarge` at offset zero
                    // mean the bytes are not this router's log at all: a file
                    // from another format or another version. Truncating that
                    // destroys it and reports the loss as a routine crash
                    // artifact, which is the failure `DI-042` and `DI-054` are
                    // both about. Fail closed and make the operator look.
                    if offset == 0 && !e.is_recoverable_tail() {
                        self.file.seek(SeekFrom::End(0))?;
                        return Err(LogError::UnknownFormat { error: e });
                    }
                    // Specification 11.2: "Startup replays only complete valid
                    // frames." Truncating here is right for a torn *tail* — the
                    // only thing a clean crash produces — and wrong for damage
                    // in the middle of the file, which a partial write on ENOSPC
                    // can leave behind: `Log::append` returns an error without
                    // advancing `self.len`, so the next append lands past the
                    // partial bytes and every record after the damage is
                    // durable, valid, and about to be discarded without a word.
                    //
                    // The two are distinguishable: look past the damage for a
                    // frame that decodes and carries a higher sequence number.
                    let surviving =
                        surviving_sequence_streaming(&mut window, mac_key, previous_sequence)?;
                    if let Some(surviving) = surviving {
                        self.file.seek(SeekFrom::End(0))?;
                        return Err(LogError::MidFileDamage {
                            offset,
                            last_good_sequence: previous_sequence.unwrap_or(0),
                            surviving_sequence: surviving,
                        });
                    }
                    break Replay {
                        frames,
                        truncated_at: Some(offset),
                        stop_reason: Some(e),
                        valid_len: offset,
                    };
                }
            };

            if let Some(prev) = previous_sequence {
                if decoded.frame.sequence <= prev {
                    self.file.seek(SeekFrom::End(0))?;
                    return Err(LogError::NonMonotonicSequence {
                        previous: prev,
                        found: decoded.frame.sequence,
                    });
                }
            }
            previous_sequence = Some(decoded.frame.sequence);
            offset += to_u64(decoded.length);
            window.consume(decoded.length);
            if retain(&decoded.frame) {
                frames.push(decoded.frame);
            }
        };
        // Setting `over_limit` also sets `exhausted`, so the loop above has
        // already stopped of its own accord; this only decides what to report.
        let (over_limit, total_read) = (window.over_limit, window.total_read);
        drop(window);

        // Reading moved the cursor; the handle is append-only for writes, but
        // restore the position so a subsequent read behaves predictably.
        self.file.seek(SeekFrom::End(0))?;
        // The window stopped because it had read more than `MAX_LOG_BYTES`,
        // whatever the file's metadata claimed. Reported here rather than
        // inside the loop, where `self.file` is still borrowed by the window.
        if over_limit {
            return Err(LogError::TooLarge {
                bytes: total_read,
                limit: MAX_LOG_BYTES,
            });
        }
        Ok(outcome)
    }

    /// Discard everything after `valid_len`.
    ///
    /// Called after a replay that found a torn tail, so that the next append
    /// does not follow a partial frame.
    pub fn truncate(&mut self, valid_len: u64) -> io::Result<()> {
        self.file.set_len(valid_len)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::End(0))?;
        self.len = valid_len;
        Ok(())
    }

    /// Replace the log with an empty one, atomically.
    ///
    /// Used by compaction once a replacement snapshot is durable.
    pub fn reset(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.len = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;

    const KEY: &[u8] = b"log-test-mac-key";

    /// The buffered replay this file used before `DI-044`, kept as a reference
    /// implementation for the differential test below.
    ///
    /// The streaming rewrite touched the integrity path — the one that failed
    /// closed on tampering and distinguished mid-file damage from a torn tail —
    /// and a rewrite there is only as trustworthy as the evidence that it did
    /// not change behaviour. Comparing against the code it replaced is that
    /// evidence, which is why this is worth its length.
    fn replay_buffered(buf: &[u8], mac_key: &[u8]) -> Result<Replay, LogError> {
        let mut frames = Vec::new();
        let mut remaining: &[u8] = buf;
        let mut offset = 0u64;
        let mut previous_sequence: Option<u64> = None;

        loop {
            if remaining.is_empty() {
                return Ok(Replay {
                    frames,
                    truncated_at: None,
                    stop_reason: None,
                    valid_len: offset,
                });
            }
            match frame::decode(remaining, mac_key) {
                Ok(decoded) => {
                    if let Some(prev) = previous_sequence {
                        if decoded.frame.sequence <= prev {
                            return Err(LogError::NonMonotonicSequence {
                                previous: prev,
                                found: decoded.frame.sequence,
                            });
                        }
                    }
                    previous_sequence = Some(decoded.frame.sequence);
                    offset += to_u64(decoded.length);
                    remaining = remaining.get(decoded.length..).unwrap_or(&[]);
                    if retain_all(&decoded.frame) {
                        frames.push(decoded.frame);
                    }
                }
                Err(e) if e.is_integrity_violation() => {
                    return Err(LogError::Integrity { offset, error: e });
                }
                // Mirrors the rule in `replay_retaining`. The reference exists
                // to catch *unintended* divergence between the two decoders,
                // not to freeze an earlier semantics — so a deliberate change
                // to what replay means belongs in both.
                Err(e) if offset == 0 && !e.is_recoverable_tail() => {
                    return Err(LogError::UnknownFormat { error: e });
                }
                Err(e) => {
                    if let Some(surviving) =
                        surviving_sequence_after(remaining, mac_key, previous_sequence)
                    {
                        return Err(LogError::MidFileDamage {
                            offset,
                            last_good_sequence: previous_sequence.unwrap_or(0),
                            surviving_sequence: surviving,
                        });
                    }
                    return Ok(Replay {
                        frames,
                        truncated_at: Some(offset),
                        stop_reason: Some(e),
                        valid_len: offset,
                    });
                }
            }
        }
    }

    const fn retain_all(_: &Frame) -> bool {
        true
    }

    /// A log whose every write fails with `ENOSPC`.
    ///
    /// `/dev/full` is a standard Linux device: writes return "no space left on
    /// device", reads return zeros, and it needs no privileges and no
    /// dependency. It is the only way to exercise the disk-full path for real
    /// rather than by faking the error type — and specification 21 requires a
    /// resilience layer covering "disk full", with Appendix C asking for it
    /// **demonstrated**.
    ///
    /// `None` where the device is absent, so this does not fail the suite on a
    /// platform that has no equivalent.
    fn full_disk_log() -> Option<Log> {
        let path = Path::new("/dev/full");
        if !path.exists() {
            return None;
        }
        Log::open(path, false).ok()
    }

    #[test]
    fn the_window_stops_reading_an_endless_source_after_max_log_bytes() {
        // The bound `DI-054` added, tested directly rather than through
        // `replay`. Replay no longer reaches it on an all-zero source, because
        // the offset-zero guard refuses that as `UnknownFormat` first — which
        // is better behaviour but leaves the bound itself uncovered.
        //
        // The reachable shape is a log that starts with valid frames and then
        // never ends: a file being appended to while it is replayed. Modelled
        // with `Cursor` chained to `io::repeat`, which needs no device and no
        // platform support.
        let valid = frame::encode(RecordKind::AuditEvent, 1, b"payload", KEY);
        let endless = std::io::Cursor::new(valid).chain(std::io::repeat(0u8));
        let mut window = Window::new(endless);

        // Driven the way the mid-file-damage scan drives it: read, consume
        // what was read, keep going. That is the path where an endless source
        // matters, because the scan walks forward looking for a surviving
        // frame and would otherwise walk forever.
        let mut rounds = 0u64;
        while window.refill().expect("refill") {
            let available = window.available().len();
            window.consume(available);
            rounds = rounds.saturating_add(1);
            assert!(
                rounds < 1_000_000,
                "the window read {} bytes without stopping",
                window.total_read
            );
        }
        assert!(window.over_limit, "the window stopped for some other reason");
        assert!(
            window.total_read > MAX_LOG_BYTES,
            "stopped at {} bytes, before the limit",
            window.total_read
        );
    }

    #[test]
    fn a_log_in_an_unrecognised_format_is_refused_rather_than_erased() {
        // A log whose first frame does not decode is not a torn tail: a tail
        // requires valid frames in front of it, and at offset zero there are
        // none. Truncating therefore discards the entire file — every key
        // record, configuration activation and audit event it holds — and the
        // only signal is a *warning* named `store.tail_truncated`, which reads
        // as a routine crash artifact.
        //
        // This is reachable in practice: a `state_dir` pointed at the wrong
        // directory, or a log written by a different build. It is the same
        // silent-whole-file-loss class as `DI-042` and `DI-054`.
        let dir = TempDir::new("foreign-log");
        let path = dir.join("log.bin");
        std::fs::write(&path, b"NOTALOG\x00some other file entirely, several bytes long")
            .expect("write");

        let mut log = Log::open(&path, false).expect("open");
        match log.replay(KEY) {
            Err(LogError::UnknownFormat { error }) => {
                assert_eq!(error, FrameError::BadMagic);
            }
            other => panic!("a foreign file must be refused, got {other:?}"),
        }

        // And it is still on disk: refusing must not be a slower way of
        // destroying it.
        assert!(
            std::fs::metadata(&path).expect("still there").len() > 0,
            "the refused file was truncated anyway"
        );
    }

    #[test]
    fn a_torn_first_append_still_truncates() {
        // The other half of the rule, and the reason it is scoped by error
        // rather than by offset alone. A crash during the very first append
        // leaves a short frame at offset zero — genuinely a torn tail, with no
        // valid frames before it because none were ever written. That must
        // still recover by truncating, or a crash on a brand-new store would
        // need manual intervention to start.
        let dir = TempDir::new("torn-first");
        let path = dir.join("log.bin");
        let whole = frame::encode(RecordKind::AuditEvent, 1, b"payload", KEY);
        // Half a frame: the magic is intact, the rest is missing.
        std::fs::write(&path, whole.get(..whole.len() / 2).expect("half")).expect("write");

        let mut log = Log::open(&path, false).expect("open");
        let replay = log.replay(KEY).expect("a torn first append must recover");
        assert_eq!(replay.frames.len(), 0);
        assert_eq!(replay.valid_len, 0);
        assert_eq!(replay.truncated_at, Some(0));
        assert!(
            replay.stop_reason.is_some_and(FrameError::is_recoverable_tail),
            "a half-written first frame must read as a recoverable tail, got {:?}",
            replay.stop_reason
        );
    }

    #[test]
    fn a_full_disk_fails_the_append_rather_than_reporting_success() {
        // The property that matters is not that the write fails — the kernel
        // does that — but that the failure *propagates*. `Store::append_audit`
        // returns this error, and specification 18.3 requires a security action
        // whose audit record did not reach disk to fail rather than report
        // success. An append that swallowed `ENOSPC` would make the audit trail
        // silently incomplete exactly when the disk filled.
        let Some(mut log) = full_disk_log() else {
            return;
        };
        let before = log.len();
        let result = log.append(RecordKind::AuditEvent, 1, b"payload", KEY);

        let error = result.expect_err("a write to a full disk must fail");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::StorageFull,
            "expected ENOSPC, got {error:?}"
        );

        // And the length must not advance. This is what makes recovery from a
        // partial write correct: `append` leaves `len` where it was, so the
        // next append lands past the partial bytes rather than interleaving
        // with them — which is precisely the mid-file damage `DI-042` was
        // about, arriving from the other direction.
        assert_eq!(
            log.len(),
            before,
            "a failed append advanced the log length, so the next append would \
             overlap the partial frame"
        );
    }

    #[test]
    fn a_full_disk_fails_every_subsequent_append_the_same_way() {
        // Not a latch: the store keeps returning the error rather than
        // succeeding once the caller retries. A router that reported success on
        // the second attempt would have lost the first record without saying so.
        let Some(mut log) = full_disk_log() else {
            return;
        };
        for sequence in 1..=5 {
            let result = log.append(RecordKind::AuditEvent, sequence, b"payload", KEY);
            assert!(
                result.is_err(),
                "append {sequence} succeeded against a full disk"
            );
            assert_eq!(log.len(), 0);
        }
    }

    #[test]
    fn streaming_replay_agrees_with_the_buffered_reference() {
        // `DI-044`: replay was rewritten from `read_to_end` to a bounded
        // window. This is the evidence that the rewrite changed memory and
        // nothing else — every generated log, intact or damaged, must produce
        // byte-identical outcomes through both implementations.
        //
        // The damage shapes are chosen to hit each branch that differs between
        // them: a torn tail (the window is exhausted mid-frame), mid-file
        // damage (the lookahead scan has to cross a window boundary), tampering
        // (must fail closed before any truncation decision), and a frame large
        // enough to force the window to grow.
        let mut rng = hypellm_test_corpus::fuzz::Rng::new(0xd1ff_0044);
        let kinds = [
            RecordKind::AuditEvent,
            RecordKind::ApiKey,
            RecordKind::UsageAggregate,
            RecordKind::ConfigActivation,
        ];

        for case in 0..600u32 {
            // Build an intact log first.
            let count = 1 + rng.below(12);
            let mut bytes: Vec<u8> = Vec::new();
            let mut boundaries: Vec<usize> = Vec::new();
            for n in 0..count {
                let kind = *rng.pick(&kinds).unwrap_or(&RecordKind::AuditEvent);
                // Most payloads small, some large enough to force the window
                // past `WINDOW_START_BYTES` — the growth path is the one most
                // likely to differ, so it must actually be exercised.
                let len = if rng.below(10) == 0 {
                    WINDOW_START_BYTES + rng.below(4096)
                } else {
                    rng.below(300)
                };
                let payload: Vec<u8> = (0..len).map(|_| rng.below(256).try_into().unwrap_or(0)).collect();
                boundaries.push(bytes.len());
                bytes.extend_from_slice(&frame::encode(
                    kind,
                    to_u64(n).saturating_add(1),
                    &payload,
                    KEY,
                ));
            }

            // Then damage it, in one of the shapes recovery has to tell apart.
            match case % 5 {
                0 => {}
                1 => {
                    // Torn tail: cut somewhere inside the last frame.
                    let cut = bytes.len().saturating_sub(1 + rng.below(40).min(bytes.len()));
                    bytes.truncate(cut);
                }
                2 => {
                    // Mid-file damage: corrupt a frame that has frames after it.
                    if boundaries.len() > 1 {
                        let which = 1 + rng.below(boundaries.len() - 1);
                        if let Some(&at) = boundaries.get(which) {
                            if let Some(b) = bytes.get_mut(at.saturating_add(8)) {
                                *b ^= 0xff;
                            }
                        }
                    }
                }
                3 => {
                    // Tampering: flip a payload byte so the MAC fails.
                    if let Some(&at) = boundaries.first() {
                        let target = at
                            .saturating_add(frame::HEADER_LEN)
                            .min(bytes.len().saturating_sub(1));
                        if let Some(b) = bytes.get_mut(target) {
                            *b ^= 0x01;
                        }
                    }
                }
                _ => {
                    // Garbage spliced in, which may or may not be recoverable.
                    let at = rng.below(bytes.len().max(1)).min(bytes.len());
                    let junk: Vec<u8> = (0..rng.below(64))
                        .map(|_| rng.below(256).try_into().unwrap_or(0))
                        .collect();
                    bytes.splice(at..at, junk);
                }
            }

            let dir = TempDir::new("replay-differential");
            let path = dir.join("log.bin");
            std::fs::write(&path, &bytes).expect("write log");
            let mut log = Log::open(&path, false).expect("open");

            let streamed = log.replay(KEY);
            let reference = replay_buffered(&bytes, KEY);

            assert_eq!(
                outcome_of(&streamed),
                outcome_of(&reference),
                "case {case}: streaming replay diverged from the buffered reference \
                 on a {}-byte log",
                bytes.len()
            );
        }
    }

    #[test]
    fn the_window_grows_only_as_far_as_a_frame_needs_and_no_further() {
        // The bound that makes the rewrite worth having. A frame larger than
        // the starting window must still replay — growth on demand — but the
        // window must stop at that frame's size rather than at the file's, and
        // must never exceed `MAX_FRAME_BYTES`.
        let dir = TempDir::new("replay-growth");
        let path = dir.join("log.bin");
        let big = vec![b'q'; WINDOW_START_BYTES * 3];
        let mut bytes = frame::encode(RecordKind::AuditEvent, 1, &big, KEY);
        // Several more large frames, so the file is much larger than any one
        // frame. If the window tracked the file this would show.
        for n in 2..=4u64 {
            bytes.extend_from_slice(&frame::encode(RecordKind::AuditEvent, n, &big, KEY));
        }
        std::fs::write(&path, &bytes).expect("write");

        let mut log = Log::open(&path, false).expect("open");
        let replay = log.replay(KEY).expect("replay");
        assert_eq!(replay.frames.len(), 4);

        let mut window = Window::new(std::fs::File::open(&path).expect("reopen"));
        // Drive it exactly as replay does: decode, grow on Incomplete.
        loop {
            match frame::decode(window.available(), KEY) {
                Ok(decoded) => {
                    window.consume(decoded.length);
                    break;
                }
                Err(FrameError::Incomplete) => {
                    assert!(window.refill().expect("refill"), "ran out before decoding");
                }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        let one_frame = frame::encode(RecordKind::AuditEvent, 1, &big, KEY).len();
        assert!(
            window.buf.len() < bytes.len(),
            "the window grew to the size of the file ({}) rather than a frame",
            bytes.len()
        );
        assert!(
            window.buf.len() >= one_frame,
            "the window never reached one frame, so decoding could not have succeeded"
        );
        assert!(window.buf.len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn the_replay_window_stays_bounded_on_a_log_far_larger_than_it() {
        // The point of `DI-044`: peak memory is one frame, not the file. A log
        // of many small frames must never grow the window past its initial
        // size, which is what makes a large log replayable at all.
        let dir = TempDir::new("replay-bounded");
        let path = dir.join("log.bin");
        let mut bytes = Vec::new();
        for n in 1..=2_000u64 {
            bytes.extend_from_slice(&frame::encode(
                RecordKind::AuditEvent,
                n,
                &[b'x'; 256],
                KEY,
            ));
        }
        assert!(
            bytes.len() > WINDOW_START_BYTES * 4,
            "the fixture must be several windows long to prove anything"
        );
        std::fs::write(&path, &bytes).expect("write");

        let mut log = Log::open(&path, false).expect("open");
        let replay = log.replay(KEY).expect("replay");
        assert_eq!(replay.frames.len(), 2_000);
        assert_eq!(replay.valid_len, to_u64(bytes.len()));

        // And the window itself never had to grow.
        let mut window = Window::new(std::fs::File::open(&path).expect("reopen"));
        window.refill().expect("refill");
        assert_eq!(
            window.buf.len(),
            WINDOW_START_BYTES,
            "a log of small frames grew the window"
        );
    }

    /// A comparable rendering of a replay outcome.
    ///
    /// Compared as a string because neither `Replay` nor `LogError` is
    /// `PartialEq`, and making them so purely for a test would put a derive on
    /// the integrity types for the convenience of their own test.
    fn outcome_of(result: &Result<Replay, LogError>) -> String {
        match result {
            Ok(replay) => format!(
                "ok frames={:?} truncated_at={:?} stop={:?} valid_len={}",
                replay
                    .frames
                    .iter()
                    .map(|f| (f.sequence, f.kind, f.payload.len()))
                    .collect::<Vec<_>>(),
                replay.truncated_at,
                replay.stop_reason,
                replay.valid_len
            ),
            Err(e) => format!("err {e:?}"),
        }
    }

    fn open(dir: &TempDir) -> Log {
        Log::open(&dir.join("log.bin"), true).expect("open log")
    }

    #[test]
    fn append_and_replay() {
        let dir = TempDir::new("log-basic");
        let mut log = open(&dir);
        assert!(log.is_empty());

        log.append(RecordKind::AuditEvent, 1, b"one", KEY).unwrap();
        log.append(RecordKind::AuditEvent, 2, b"two", KEY).unwrap();
        log.append(RecordKind::UsageAggregate, 3, b"three", KEY).unwrap();

        let replay = log.replay(KEY).unwrap();
        assert_eq!(replay.frames.len(), 3);
        assert_eq!(replay.truncated_at, None);
        assert_eq!(replay.max_sequence(), 3);
        assert_eq!(replay.frames[0].payload, b"one");
        assert_eq!(replay.of_kind(RecordKind::AuditEvent).count(), 2);
    }

    #[test]
    fn replay_survives_reopening() {
        let dir = TempDir::new("log-reopen");
        {
            let mut log = open(&dir);
            for i in 1..=10u64 {
                log.append(RecordKind::AuditEvent, i, format!("e{i}").as_bytes(), KEY)
                    .unwrap();
            }
        }
        let mut log = open(&dir);
        let replay = log.replay(KEY).unwrap();
        assert_eq!(replay.frames.len(), 10);
        assert_eq!(replay.max_sequence(), 10);
    }

    #[test]
    fn appends_continue_after_replay() {
        let dir = TempDir::new("log-continue");
        let mut log = open(&dir);
        log.append(RecordKind::AuditEvent, 1, b"a", KEY).unwrap();
        let _ = log.replay(KEY).unwrap();
        log.append(RecordKind::AuditEvent, 2, b"b", KEY).unwrap();
        let replay = log.replay(KEY).unwrap();
        assert_eq!(replay.frames.len(), 2);
    }

    #[test]
    fn a_torn_tail_truncates_rather_than_failing() {
        // The crash case: a partial frame at the end of the log.
        let dir = TempDir::new("log-torn");
        let mut log = open(&dir);
        log.append(RecordKind::AuditEvent, 1, b"complete", KEY).unwrap();
        log.append(RecordKind::AuditEvent, 2, b"also complete", KEY).unwrap();
        let good_len = log.len();

        // Simulate a write interrupted mid-frame.
        {
            let partial = frame::encode(RecordKind::AuditEvent, 3, b"interrupted", KEY);
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join("log.bin"))
                .unwrap();
            f.write_all(&partial[..partial.len() / 2]).unwrap();
            f.sync_all().unwrap();
        }

        let mut log = open(&dir);
        let replay = log.replay(KEY).unwrap();
        assert_eq!(replay.frames.len(), 2, "complete frames survive");
        assert_eq!(replay.truncated_at, Some(good_len));
        assert!(
            replay
                .stop_reason
                .expect("a stop reason")
                .is_recoverable_tail()
        );

        // Truncating lets appends continue cleanly.
        log.truncate(replay.valid_len).unwrap();
        log.append(RecordKind::AuditEvent, 3, b"after recovery", KEY)
            .unwrap();
        let replay = log.replay(KEY).unwrap();
        assert_eq!(replay.frames.len(), 3);
        assert_eq!(replay.truncated_at, None);
    }

    #[test]
    fn truncation_at_every_byte_is_handled() {
        // Whatever byte the crash happened on, replay must either keep a prefix
        // of whole frames or report a recoverable tail — never fail closed and
        // never invent a frame.
        let dir = TempDir::new("log-cut");
        let full = {
            let mut log = open(&dir);
            for i in 1..=4u64 {
                log.append(RecordKind::AuditEvent, i, b"payload", KEY).unwrap();
            }
            std::fs::read(dir.join("log.bin")).unwrap()
        };

        for cut in 0..full.len() {
            let cut_dir = TempDir::new("log-cut-n");
            std::fs::write(cut_dir.join("log.bin"), &full[..cut]).unwrap();
            let mut log = Log::open(&cut_dir.join("log.bin"), true).unwrap();
            let replay = log
                .replay(KEY)
                .unwrap_or_else(|e| panic!("cut at {cut} failed closed: {e}"));
            assert!(replay.frames.len() <= 4);
            if let Some(reason) = replay.stop_reason {
                assert!(reason.is_recoverable_tail(), "cut {cut}: {reason:?}");
            }
        }
    }

    #[test]
    fn tampering_with_a_protected_record_fails_startup() {
        let dir = TempDir::new("log-tamper");
        {
            let mut log = open(&dir);
            log.append(RecordKind::AuditEvent, 1, b"actor=alice", KEY).unwrap();
            log.append(RecordKind::AuditEvent, 2, b"actor=bob", KEY).unwrap();
        }

        // Edit a payload byte in place, as an attacker with directory write
        // access would.
        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        let payload_start = frame::HEADER_LEN;
        bytes[payload_start] = b'X';
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        let mut log = open(&dir);
        match log.replay(KEY) {
            // A payload edit may fail the MAC or the CRC first; both refuse.
            Err(LogError::Integrity { offset, error }) => {
                assert_eq!(offset, 0);
                assert!(error.is_integrity_violation());
            }
            // Tampering with the *first* of two records is mid-file damage by
            // definition: a valid record follows it. Truncating there would
            // discard record 2, so replay refuses instead of returning a short
            // log. This arm used to accept a truncating `Ok`, which was the
            // weaker outcome.
            Err(LogError::MidFileDamage {
                offset,
                surviving_sequence,
                ..
            }) => {
                assert_eq!(offset, 0);
                assert_eq!(surviving_sequence, 2);
            }
            Ok(replay) => panic!(
                "a tampered record must not replay: got {} frame(s)",
                replay.frames.len()
            ),
            Err(e) => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn a_forged_record_with_a_recomputed_checksum_fails_closed() {
        // The precise threat the MAC exists for: an attacker who knows the
        // frame format and fixes up the CRC.
        let dir = TempDir::new("log-forge");
        {
            let mut log = open(&dir);
            log.append(RecordKind::AuditEvent, 1, b"role=viewer", KEY).unwrap();
        }
        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        let payload_start = frame::HEADER_LEN;
        bytes[payload_start..payload_start + 11].copy_from_slice(b"role=admin!");
        let body_len = payload_start + 11;
        let crc = hypellm_crypto::crc32(&bytes[..body_len]);
        bytes[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        let mut log = open(&dir);
        match log.replay(KEY) {
            Err(LogError::Integrity { error, .. }) => {
                assert_eq!(error, FrameError::MacMismatch);
            }
            other => panic!("forgery must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn a_reordered_log_fails_closed() {
        // Deleting or reordering audit records must be detectable even if each
        // individual frame verifies.
        let dir = TempDir::new("log-reorder");
        let first = frame::encode(RecordKind::AuditEvent, 1, b"a", KEY);
        let second = frame::encode(RecordKind::AuditEvent, 2, b"b", KEY);
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&second);
        swapped.extend_from_slice(&first);
        std::fs::write(dir.join("log.bin"), &swapped).unwrap();

        let mut log = open(&dir);
        match log.replay(KEY) {
            Err(LogError::NonMonotonicSequence { previous, found }) => {
                assert_eq!(previous, 2);
                assert_eq!(found, 1);
            }
            other => panic!("reordering must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn a_filtered_replay_verifies_everything_and_keeps_only_what_was_asked_for() {
        // The filter decides what is *kept*, never what is *verified*. A
        // targeted read that skipped verification for kinds it did not want
        // would mean an audit export could not detect tampering in a key
        // record, which is the wrong shape entirely.
        let dir = TempDir::new("log-filtered");
        {
            let mut log = open(&dir);
            log.append(RecordKind::AuditEvent, 1, b"audit-1", KEY).unwrap();
            log.append(RecordKind::ApiKey, 2, b"key-1", KEY).unwrap();
            log.append(RecordKind::AuditEvent, 3, b"audit-2", KEY).unwrap();
            log.append(RecordKind::ConfigActivation, 4, b"config", KEY).unwrap();
        }

        let mut log = open(&dir);
        let filtered = log
            .replay_retaining(KEY, |frame| frame.kind == RecordKind::AuditEvent)
            .expect("replay");
        assert_eq!(filtered.frames.len(), 2);
        assert!(
            filtered
                .frames
                .iter()
                .all(|f| f.kind == RecordKind::AuditEvent)
        );
        // Sequence numbers come from the whole log, not from the kept subset:
        // the filter must not make the log look shorter than it is.
        assert_eq!(filtered.max_sequence(), 3);
        assert_eq!(filtered.valid_len, log.len());

        // An unfiltered replay sees everything, so the two agree about the log.
        let all = log.replay(KEY).expect("replay");
        assert_eq!(all.frames.len(), 4);
        assert_eq!(all.valid_len, filtered.valid_len);
    }

    #[test]
    fn a_filtered_replay_still_refuses_a_tampered_frame_of_another_kind() {
        // The property the previous test's comment claims. Tamper with an
        // `ApiKey` frame and ask only for audit events: it must still fail.
        let dir = TempDir::new("log-filtered-integrity");
        {
            let mut log = open(&dir);
            log.append(RecordKind::AuditEvent, 1, b"audit-1", KEY).unwrap();
            log.append(RecordKind::ApiKey, 2, b"key-payload", KEY).unwrap();
            log.append(RecordKind::AuditEvent, 3, b"audit-2", KEY).unwrap();
        }

        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        let second = {
            let decoded = frame::decode(&bytes, KEY).unwrap();
            decoded.length
        };
        bytes[second + frame::HEADER_LEN] ^= 0xff;
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        let mut log = open(&dir);
        match log.replay_retaining(KEY, |f| f.kind == RecordKind::AuditEvent) {
            Ok(replay) => panic!(
                "a tampered frame of an unasked-for kind was ignored: {} frame(s)",
                replay.frames.len()
            ),
            Err(_) => {}
        }
    }

    #[test]
    fn mid_file_damage_refuses_rather_than_discarding_what_follows() {
        // The ENOSPC shape. `Log::append` returns an error without advancing
        // `self.len`, so a partially written frame stays on disk and the next
        // append lands past it. Every record after the damage is durable and
        // valid — and a truncating recovery drops all of them without a word.
        //
        // The records this loses are the ones it can least afford to: key
        // revocations, configuration activations, audit entries.
        let dir = TempDir::new("log-midfile");
        {
            let mut log = open(&dir);
            for n in 1..=5u64 {
                log.append(RecordKind::AuditEvent, n, format!("record-{n}").as_bytes(), KEY)
                    .unwrap();
            }
        }

        // Corrupt the third frame's payload, leaving 4 and 5 intact.
        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        let third = {
            let mut offset = 0usize;
            for _ in 0..2 {
                let decoded = frame::decode(&bytes[offset..], KEY).unwrap();
                offset += decoded.length;
            }
            offset
        };
        bytes[third + frame::HEADER_LEN] ^= 0xff;
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        let mut log = open(&dir);
        match log.replay(KEY) {
            Err(LogError::MidFileDamage {
                last_good_sequence,
                surviving_sequence,
                ..
            }) => {
                assert_eq!(last_good_sequence, 2, "records 1 and 2 were intact");
                assert!(
                    surviving_sequence > 2,
                    "the refusal must name a record that would have been lost"
                );
            }
            Err(LogError::Integrity { .. }) => {
                // Also a refusal, and also acceptable: the MAC caught it before
                // the scan ran. What must not happen is a silent truncation.
            }
            Ok(replay) => panic!(
                "records after the damage were silently discarded: replayed {} of 5",
                replay.frames.len()
            ),
            Err(e) => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn a_torn_tail_still_truncates() {
        // The other half, and the reason the distinction has to be made rather
        // than simply refusing on any decode failure: a torn tail is what a
        // clean crash produces, it happens routinely, and refusing to start
        // over one would turn every unclean shutdown into an outage.
        let dir = TempDir::new("log-torn-tail");
        {
            let mut log = open(&dir);
            for n in 1..=3u64 {
                log.append(RecordKind::AuditEvent, n, b"payload", KEY).unwrap();
            }
        }

        let mut bytes = std::fs::read(dir.join("log.bin")).unwrap();
        // Cut the last frame in half. Nothing valid follows it.
        let keep = bytes.len() - 8;
        bytes.truncate(keep);
        std::fs::write(dir.join("log.bin"), &bytes).unwrap();

        let mut log = open(&dir);
        let replay = log.replay(KEY).expect("a torn tail must not refuse");
        assert_eq!(replay.frames.len(), 2, "the intact prefix is kept");
        assert!(replay.truncated_at.is_some());
    }

    #[test]
    fn an_oversize_log_is_refused_rather_than_replayed() {
        // Specification 3.2 bounds every buffer, and replay materialises the
        // file and then its frames — so peak memory is roughly twice the log.
        // Without a ceiling, a log that has outgrown memory makes the router
        // OOM on every restart, and the state that would explain why is the
        // state it cannot read.
        let dir = TempDir::new("log-oversize");
        {
            let mut log = open(&dir);
            log.append(RecordKind::AuditEvent, 1, b"payload", KEY).unwrap();
        }

        let mut log = open(&dir);
        // Claim a size past the ceiling without writing 256 MiB to disk.
        log.len = super::MAX_LOG_BYTES + 1;
        match log.replay(KEY) {
            Err(LogError::TooLarge { bytes, limit }) => {
                assert_eq!(limit, super::MAX_LOG_BYTES);
                assert!(bytes > limit);
            }
            other => panic!("an oversize log must be refused, got {other:?}"),
        }
    }

    #[test]
    fn reset_empties_the_log() {
        let dir = TempDir::new("log-reset");
        let mut log = open(&dir);
        log.append(RecordKind::AuditEvent, 1, b"a", KEY).unwrap();
        assert!(!log.is_empty());
        log.reset().unwrap();
        assert!(log.is_empty());
        assert!(log.replay(KEY).unwrap().frames.is_empty());
        log.append(RecordKind::AuditEvent, 1, b"fresh", KEY).unwrap();
        assert_eq!(log.replay(KEY).unwrap().frames.len(), 1);
    }

    #[test]
    fn an_empty_log_replays_to_nothing() {
        let dir = TempDir::new("log-empty");
        let mut log = open(&dir);
        let replay = log.replay(KEY).unwrap();
        assert!(replay.frames.is_empty());
        assert_eq!(replay.truncated_at, None);
        assert_eq!(replay.max_sequence(), 0);
    }
}
