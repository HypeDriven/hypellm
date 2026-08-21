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

### Fleet records

Three kinds join the log for fleet orchestration (specification 26.6):
`FleetLease`, `FleetActivation` and `FleetFlap`. Two of them are **protected**,
and the reason is worth stating: a lease authorises stopping a production model,
so an unprotected one could be forged on disk between a crash and a restart and
the router would reconcile against it — re-issuing a verb nobody asked for. Flap
counters are protected for the same reason inverted: clearing one on disk would
grant a fresh burst of exactly the thrash the backoff exists to stop.

`FleetActivation` is an outcome record, recomputable from the audit trail and
high-volume, so it is unprotected — the same judgement `UsageAggregate` already
carries.

The payload codec is `hypellm_fleet::durable`, not this crate: a record that
fails any range check on the way back in is **skipped rather than adopted**,
because a corrupt lease the router acted on would send a verb nobody asked for
while a skipped one merely expires and is audited.

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

**Recovery verifies integrity and continuity.** `Store::open` authenticates
protected frames, checks monotonic sequence numbers, decodes every audit record
under the same field bounds used by the writer, and verifies each chain link.
A torn final frame is recoverable; corruption before the tail, an unreadable
protected record or a broken chain refuses startup rather than discarding later
history.

**Replay is window-bounded.** Log replay streams through a bounded window rather
than materialising the complete log. Snapshot payload size is validated before
allocation. Compaction remains an operator-controlled lifecycle action, so disk
capacity still needs monitoring.

**Diagnostic output redacts the MAC key.** `Store` has a hand-written `Debug`
implementation that never renders key bytes.

**The process lock is advisory and racy.** `ProcessLock` is a PID file, not an OS
lock — `flock` would need `unsafe` FFI, which the workspace forbids. Liveness is
`/proc/<pid>` existence, so PID reuse can report `Held` against an unrelated
process (a spurious refusal to start), and the stale-reclaim path
(`remove_file` then `create_new`) is not atomic: two starters that both observe
a stale lock can both proceed, giving two writers on one log. `Drop` removes the
lock file unconditionally, including one another process has since claimed. On a
shared or network volume the lock provides no protection at all.

**Backup validates its boundary.** `Store::backup_to` refuses a log shorter than
the tracked durable boundary and copies only complete validated bytes.

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
| Frame decode | Mutated bytes terminate without panic or oversized allocation | Implemented in `tests/fuzz.rs` |
| Log replay | Mutated logs produce a validated frame prefix or a classified integrity failure | Implemented in `tests/fuzz.rs` |
| Recovery | Structured truncation and corruption preserve the torn-tail versus mid-file-damage distinction | Implemented in `tests/fuzz.rs` |
| Audit payloads | Mutated records and checkpoints cannot fabricate authenticated history | Implemented in `tests/fuzz.rs` |
| Snapshot metadata | Mutated metadata and payload pairs are bounded and integrity-checked | Implemented in `tests/fuzz.rs` |

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
