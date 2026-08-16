# Module: hypellm-store

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace lint table. |
| External dependencies | None third-party. Workspace path dependencies only: `hypellm-core`, `hypellm-crypto`, `wire-json`. |
| Fuzz targets | None implemented. Required targets are listed under [Fuzz targets](#fuzz-targets). |

## Scope

This module owns durable state on a single node: the append-only framed log, the
periodic snapshot, the process lock, atomic file replacement, the audit hash
chain with signed checkpoints, and the pointer swap that activates a validated
configuration (specification 11, 11.2, 18.1).

The boundary matters as much as the contents. This module does **not**:

- **Interpret payloads.** `Frame::payload` is opaque bytes. Only `audit.rs`
  imposes a payload shape, and only on its own two record kinds. The store never
  parses a configuration document, a key record, or a usage aggregate — it
  stores and returns them. Validation belongs to the module that owns the type.
- **Hold or derive the MAC key.** `Store::open` takes `mac_key: &[u8]` from the
  platform secret facility (specification 10). The store never generates it,
  never persists it, and has no rotation path: re-keying invalidates every
  protected frame already on disk, so it is an offline re-write, not a runtime
  operation.
- **Invent cryptography.** Every digest, MAC, and constant-time comparison comes
  from `hypellm-crypto`. There is no signature scheme here, and the "signed
  checkpoint" of specification 11.2 is an HMAC under the router's own key, not
  an asymmetric signature.
- **Export anything.** Specification 11.2 requires checkpoints to be "exported
  to immutable storage". This module *produces* checkpoints and a point-in-time
  backup (`Store::backup_to`); shipping either off the node is the caller's job.
- **Distribute state.** Specification 11.2 defers multi-node to an external
  consensus/config distributor. There is no replication, no leader election, and
  no distributed lock here — only `ProcessLock`, which is single-node by
  construction.
- **Decide policy.** `Activatable<T>` is generic and holds no routing knowledge;
  it is a pointer with bounded history.

## Threat notes

**Two integrity mechanisms for two different adversaries.** CRC-32 covers header
and payload and detects a torn write, a short read, or bit rot; it is not a
security control. HMAC-SHA-256 covers header, payload, and CRC on *protected*
kinds (`RecordKind::is_protected`) — the ones that decide authorization or carry
accountability. The distinction drives recovery: `FrameError::is_recoverable_tail`
(incomplete, checksum) truncates and the router starts; `is_integrity_violation`
(MAC mismatch, missing MAC, unexpected MAC) fails startup closed. Getting this
backwards in either direction is a bug — turning every power loss into an outage,
or booting on an edited audit history.

**Forgery with a recomputed checksum.** The realistic attacker holds write access
to the state directory, knows the frame format, and can fix up the CRC. The MAC
covers the sequence number, the record kind, and the protected flag, so
renumbering, retyping, and flag-stripping are all rejected
(`FrameError::MissingMac` / `UnexpectedMac` / `MacMismatch`). Reordering or
deleting whole frames that each verify is caught separately, by the strictly
increasing sequence check in `Log::replay`
(`LogError::NonMonotonicSequence`).

**The audit chain alone is not tamper-evident.** `link_of` is unkeyed SHA-256, so
an attacker who can rewrite the entire log can recompute a self-consistent chain
from genesis. What actually resists that is the per-frame HMAC and the
checkpoint MAC, both keyed with material the attacker does not hold. Treat the
chain as *ordering and continuity* evidence and the checkpoint as the trust
anchor; a chain verified without a checkpoint proves very little.

**Snapshot metadata is MACed on write and verified on read.** `encode_meta`
appends an HMAC over the magic, sequence, audit head, audit count, and a SHA-256
of the payload; `read_snapshot` recomputes that MAC and rejects a mismatch as
`SnapshotIntegrity`, using a constant-time compare. Editing `snapshot.meta` to
rewind the sequence number or substitute an audit head therefore fails startup
rather than being accepted.

**The two files are cross-checked.** `Store::compact` writes `snapshot.bin` and
`snapshot.meta` as two separate atomic replacements, so a crash between them
leaves a new payload paired with the previous metadata. That pair is now caught:
the metadata carries a digest of the payload it describes, and `read_snapshot`
compares it against the payload actually on disk. A mismatched pair is
`SnapshotIntegrity`, not a silent acceptance of stale sequence and audit head.
The log reset still happens last, so no records are lost either way.

**Recovery rebuilds the chain head without verifying it.** `Store::open`
re-chains post-snapshot audit frames by taking each record's own `link()`. It
never calls `verify_chain`, so continuity is not checked at startup, and a
record whose payload fails `AuditRecord::from_payload` is skipped silently —
advancing the count but not the head. A protected frame that verifies its MAC
yet does not parse (see the field-length asymmetry below) will therefore leave
the live head diverged from the durable history, with no error surfaced.

**Written-but-unreadable audit records.** `AuditEvent::reason` is capped at 512
bytes, but `actor`, `tenant`, `object`, `request_id`, and `source` are plain
`String` with no cap on the write path — while the read path parses under
`wire_json::Limits::SMALL` (64 KiB per string, 1 MiB total). A caller that
supplies an oversized actor or object writes a record that cannot be parsed
back. Specification 17 requires capped audit fields; callers must cap these
themselves today.

**A torn frame in the middle of the log discards everything after it.**
`Log::replay` stops at the first frame that does not decode and reports that
offset as `valid_len`; `Store::open` then truncates there. This is correct for a
tail, which is the only case a clean crash produces. It is not correct for a
frame damaged mid-file — for example after a partial write on ENOSPC, where
`Log::append` returns an error without advancing `self.len` and the next append
lands past the partial bytes. Every durable record after the damage is then
silently dropped at the next startup.

**Unbounded startup memory.** `Log::replay` reads the whole log into a `Vec` with
`read_to_end` and then materialises every frame, so peak startup memory is
roughly twice the log size. Nothing in this crate caps the log or triggers
compaction; that budget is set by whoever calls `Store::compact`. `read_optional`
is likewise unbounded and is what loads `snapshot.bin`.

**The MAC key is in a `Debug`-derived struct.** `Store` holds `mac_key: Vec<u8>`
under `#[derive(Debug)]`, so any `{:?}` of a `Store` prints the key bytes.
Specification 7.1 and 10 require redacting `Debug` on secret material; this
field should move to `hypellm_crypto::Secret` or get a hand-written `Debug`.

**The process lock is advisory and racy.** `ProcessLock` is a PID file, not an OS
lock — `flock` would need `unsafe` FFI, which the workspace forbids. Liveness is
`/proc/<pid>` existence, so PID reuse can report `Held` against an unrelated
process (a spurious refusal to start), and the stale-reclaim path
(`remove_file` then `create_new`) is not atomic: two starters that both observe
a stale lock can both proceed, giving two writers on one log. `Drop` removes the
lock file unconditionally, including one another process has since claimed. On a
shared or network volume the lock provides no protection at all.

**Backup trusts the in-memory boundary.** `Store::backup_to` slices the log bytes
it read from disk to `Log::len()`. If the file is shorter than the tracked length
— an external truncation, or a length desynchronised by a failed append — the
slice is out of range and panics.

**Forward compatibility is one-directional.** An unknown `RecordKind` is
preserved as `Unknown(v)` so a newer writer's records survive a rollback, but
`Unknown` reports `is_protected() == false`. A *protected* record kind added in a
later version therefore arrives at an older reader with the protected flag set,
is classified `UnexpectedMac`, and fails startup closed. Adding an
authorization-relevant record kind is a format-version change, not an additive
one.

**Sequence gaps are legal.** `Store::append_locked` consumes a sequence number
before the write; a failed append leaves a hole. Replay requires strictly
increasing, not contiguous, sequence numbers, so gaps are accepted by design and
cannot be used to detect deletion — that is the chain's job.

## Limits

Enforced:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Declared frame payload length | 64 MiB | `frame::MAX_PAYLOAD_LEN`, checked in `frame::decode` **before** any allocation |
| Frame header / CRC / MAC | 24 / 4 / 32 bytes, fixed | `frame::HEADER_LEN`, `CRC_LEN`, `MAC_LEN` |
| Frame format version | Exactly `1` | `frame::FORMAT_VERSION`; anything else is `UnsupportedVersion` |
| Audit record JSON | depth 32, 64 KiB per string, 1 MiB total, 10 000 array items, 2 000 object entries, duplicate keys rejected | `wire_json::Limits::SMALL` in `AuditRecord::from_payload` |
| Audit reason text | 512 bytes, truncated on a char boundary | `Capped::new(reason, 512)` in `AuditEvent::with_reason` and `from_json` |
| Audit checkpoint payload | Exactly 80 bytes | `AuditCheckpoint::from_payload` |
| Snapshot metadata | Exactly 116 bytes (`META_LEN`) with `HYMT` magic | `read_snapshot` |
| Retained activation history | 8 versions by default, caller-chosen via `Activatable::with_history`; 0 disables rollback | `history_limit` plus `Vec::truncate` in `activate` |
| Audit checkpoint cadence | Caller-supplied record interval; `0` disables automatic checkpoints | `Store::checkpoint_interval` |
| Sequence ordering | Strictly increasing across the log | `Log::replay` → `LogError::NonMonotonicSequence` |

Not enforced — stated so the gap is visible rather than assumed:

| Input / resource | Status |
|---|---|
| Total log file size | Unbounded. Compaction is caller-driven; `Log::replay` buffers the entire file. |
| Snapshot payload size | Unbounded on both write (`Store::compact`) and read (`read_optional`). |
| Frames materialised by one replay | Unbounded; `Replay::frames` grows with the log. |
| `AuditEvent` actor / tenant / object / request_id / source | Unbounded on write; only the read path is bounded, which is the asymmetry noted above. |
| Reserved header field (bytes 10..12) | Not validated on decode. Covered by CRC and MAC, so it cannot be edited in place, but a non-zero value decodes successfully. |
| Snapshot metadata MAC | Computed and stored, never verified. |

## Fuzz targets

`tests/fuzz.rs` — seven targets over specification 21's "state recovery" row,
run by `cargo test -p hypellm-store`, driven by the seeded mutation engine in
`hypellm-test-corpus::fuzz`. There is no `fuzz/` directory and no libFuzzer
harness, because specification 4 admits no such dependency.

| Target | Property asserted |
|---|---|
| `truncating_the_log_at_any_offset_recovers_a_prefix_and_never_panics` | A torn tail is a prefix, not a crash |
| `truncation_never_discards_a_frame_that_precedes_the_damage` | Recovery keeps everything before the damage |
| `a_corrupted_byte_anywhere_is_detected_or_confined` | A flipped bit is caught or cannot cross a frame |
| `a_forged_protected_frame_does_not_authenticate` | The MAC is load-bearing |
| `random_bytes_are_not_mistaken_for_a_log` | No accidental recognition |
| `a_log_written_under_another_key_is_refused` | Key confusion is refused |
| `recovery_is_repeatable` | Two recoveries of one directory agree |

Offsets are sampled rather than exhaustive (96 exhaustive, then a prime stride,
then the last 48 bytes) to keep the run under a few seconds; a bug living only
at an unsampled interior offset would be missed.

Still outstanding:

| Target | Property under test |
|---|---|
| `store_frame_decode` | Required, not yet implemented (§21). Arbitrary bytes into `frame::decode` never panic, never allocate beyond `MAX_PAYLOAD_LEN`, and always terminate. |
| `store_log_replay` | Required, not yet implemented (§21). Arbitrary log files replay to a prefix of whole frames or a classified stop reason — never a fabricated frame, never a panic. |
| `store_recovery` | Required, not yet implemented (§21). Structured: a generated append sequence, cut at an arbitrary offset, must reopen; the resulting `valid_len` must be a frame boundary. |
| `store_audit_payload` | Required, not yet implemented (§21). `AuditRecord::from_payload` and `AuditCheckpoint::from_payload` over arbitrary bytes. |
| `store_snapshot_meta` | Required, not yet implemented (§21). `read_snapshot` over arbitrary `snapshot.meta` content, including the length and magic boundaries. |

Differential and property coverage that fuzzing should back: encode/decode round
trip for every `RecordKind`, and "every proper prefix of a frame reports
`Incomplete`" — both currently exist only as unit tests in `frame.rs`.

## Public API

See `lib.rs`. `Store` is the intended entry point: `open`, `append`,
`append_audit`, `checkpoint_audit`, `compact`, `snapshot`, `backup_to`, `sync`.
The lower layers (`frame`, `log`, `durable`, `audit`, `activation`) are public
because the router startup path, the admin API, and the recovery tooling each
need one of them directly, not because the layering is optional — in particular,
the documented lock order inside `Store` is **log, then audit**, and any caller
reaching past `Store` to `Log` forfeits that guarantee.

`tempdir::TempDir` is a test utility shipped in the library rather than under
`#[cfg(test)]` so that other crates' integration tests can use it; the dependency
policy (specification 4) admits no `tempfile` crate. It panics on failure and
must not appear on any production path.
