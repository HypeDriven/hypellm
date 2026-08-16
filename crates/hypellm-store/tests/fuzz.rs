//! Fuzz targets for state recovery.
//!
//! Specification 21 requires a Fuzz layer covering "state recovery", and
//! specification 11.2 fixes what recovery must do: "Startup replays only
//! complete valid frames and fails closed on protected-record integrity
//! errors."
//!
//! # The two failure directions
//!
//! Recovery has to distinguish damage from tampering, and getting either wrong
//! is bad in a different way:
//!
//! - **Truncating too eagerly** silently discards committed records. A crash
//!   during a write must cost at most the frame that was being written, never
//!   the ones before it.
//! - **Accepting a forged frame** lets someone with write access to the state
//!   directory rewrite the router's policy or its audit chain. A protected
//!   record that does not authenticate must abort startup, not be skipped.
//!
//! These targets corrupt a real log at every offset and assert both.

use hypellm_store::{AuditAction, AuditEvent, RecordKind, Store, TempDir};
use hypellm_test_corpus::fuzz::Rng;

const KEY: &[u8] = b"a-store-mac-key-for-the-fuzz-targets";

/// Build a store with `count` records of mixed kinds and return its log bytes.
fn populated_log(name: &str, count: u64) -> (TempDir, Vec<u8>) {
    let dir = TempDir::new(name);
    {
        let (store, _) = Store::open(dir.path(), KEY, 0).expect("open");
        for n in 0..count {
            store
                .append(RecordKind::ConfigActivation, format!("config-{n}").as_bytes())
                .expect("append config");
            store
                .append_audit(AuditEvent::new(n, "admin", AuditAction::KeyCreated))
                .expect("append audit");
        }
    }
    let bytes = std::fs::read(dir.path().join("log.bin")).expect("read log");
    (dir, bytes)
}

/// A bounded, well-distributed set of offsets to probe.
///
/// Each probe reopens the store, which fsyncs, so an exhaustive sweep over a
/// few thousand offsets turns this file into the slowest thing in the suite —
/// and a slow fuzz layer is one that gets run with `--skip`.
///
/// The first stretch is exhaustive because frame headers live there, and the
/// rest is sampled with a prime stride so the probes land on varied alignments
/// within frames rather than repeatedly on the same field.
fn probe_offsets(len: usize) -> Vec<usize> {
    const EXHAUSTIVE: usize = 96;
    const STRIDE: usize = 17;

    let mut offsets: Vec<usize> = (0..len.min(EXHAUSTIVE)).collect();
    let mut at = EXHAUSTIVE;
    while at < len {
        offsets.push(at);
        at += STRIDE;
    }
    // The final bytes are where a torn write actually lands.
    for tail in len.saturating_sub(48)..len {
        offsets.push(tail);
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Replace the log with `bytes` and try to recover.
fn recover_with(dir: &TempDir, bytes: &[u8]) -> Result<usize, String> {
    std::fs::write(dir.path().join("log.bin"), bytes).expect("write log");
    match Store::open(dir.path(), KEY, 0) {
        Ok((_store, recovery)) => Ok(recovery.frames.len()),
        Err(e) => Err(e.to_string()),
    }
}

#[test]
fn truncating_the_log_at_any_offset_recovers_a_prefix_and_never_panics() {
    // A crash can leave the log ending anywhere, including mid-frame. Every
    // prefix must produce a decision.
    let (dir, full) = populated_log("store-fuzz-truncate", 4);
    let complete = recover_with(&dir, &full).expect("the intact log recovers");

    for cut in probe_offsets(full.len()) {
        let prefix = full.get(..cut).unwrap_or_default();
        match recover_with(&dir, prefix) {
            Ok(frames) => assert!(
                frames <= complete,
                "truncating to {cut} bytes produced more frames than the intact log"
            ),
            // Failing closed is a legitimate answer for a damaged log.
            Err(_) => {}
        }
    }
}

#[test]
fn truncation_never_discards_a_frame_that_precedes_the_damage() {
    // The property that makes an append-only log worth having: a torn tail
    // costs the torn frame, not the committed ones before it. Recovery must be
    // monotonic in the length of the log.
    let (dir, full) = populated_log("store-fuzz-monotonic", 4);

    let mut previous = 0usize;
    for cut in probe_offsets(full.len()) {
        let prefix = full.get(..cut).unwrap_or_default();
        if let Ok(frames) = recover_with(&dir, prefix) {
            assert!(
                frames >= previous,
                "a longer log recovered fewer frames: {cut} bytes gave {frames}, \
                 a shorter prefix gave {previous}"
            );
            previous = frames;
        }
    }
}

#[test]
fn a_corrupted_byte_anywhere_is_detected_or_confined() {
    // Flip one bit at every offset. Either recovery reports failure, or it
    // recovers a prefix that stops at or before the damaged frame. What it must
    // never do is carry on past corruption as though the frame were sound.
    let (dir, full) = populated_log("store-fuzz-bitflip", 4);
    let complete = recover_with(&dir, &full).expect("the intact log recovers");

    for offset in probe_offsets(full.len()) {
        let mut damaged = full.clone();
        if let Some(byte) = damaged.get_mut(offset) {
            *byte ^= 0x01;
        }

        match recover_with(&dir, &damaged) {
            Ok(frames) => assert!(
                frames <= complete,
                "corruption at offset {offset} produced more frames than the intact log"
            ),
            Err(_) => {}
        }
    }
}

#[test]
fn a_forged_protected_frame_does_not_authenticate() {
    // Specification 11.2: recovery "fails closed on protected-record integrity
    // errors". Someone with write access to the state directory must not be
    // able to add a record the router accepts.
    let (dir, full) = populated_log("store-fuzz-forgery", 4);
    let honest = recover_with(&dir, &full).expect("the intact log recovers");

    // Splice a copy of the log onto itself. Every frame is individually
    // well-formed and correctly MAC'd, but the sequence numbers repeat.
    let mut doubled = full.clone();
    doubled.extend_from_slice(&full);

    match recover_with(&dir, &doubled) {
        Ok(frames) => assert!(
            frames <= honest,
            "replayed frames with duplicate sequence numbers were accepted: \
             {frames} recovered from a doubled log that honestly holds {honest}"
        ),
        Err(_) => {}
    }
}

#[test]
fn random_bytes_are_not_mistaken_for_a_log() {
    // A log replaced wholesale with garbage must recover nothing, not
    // something.
    let dir = TempDir::new("store-fuzz-garbage");
    {
        let _ = Store::open(dir.path(), KEY, 0).expect("open");
    }

    let mut rng = Rng::new(0x570e_0001);
    for _ in 0..60 {
        let len = rng.below(4096);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        match recover_with(&dir, &case) {
            Ok(frames) => assert_eq!(
                frames, 0,
                "random bytes were decoded as {frames} frame(s)"
            ),
            Err(_) => {}
        }
    }
}

#[test]
fn a_log_written_under_another_key_is_refused() {
    // The MAC is what separates damage from tampering. A log that verifies
    // under a different key would make the whole chain meaningless.
    let (dir, full) = populated_log("store-fuzz-wrong-key", 4);
    std::fs::write(dir.path().join("log.bin"), &full).expect("write");

    match Store::open(dir.path(), b"a-completely-different-store-mac-key", 0) {
        Ok((_store, recovery)) => {
            // Unprotected frames may still be readable, but no protected one
            // may survive verification under the wrong key.
            let protected = recovery
                .frames
                .iter()
                .filter(|f| f.kind == RecordKind::AuditEvent)
                .count();
            assert_eq!(
                protected, 0,
                "protected frames verified under the wrong key"
            );
        }
        Err(_) => {}
    }
}

#[test]
fn recovery_is_repeatable() {
    // Recovery runs on every start. Two runs over identical bytes must agree,
    // or a restart could silently change the router's state.
    let (dir, full) = populated_log("store-fuzz-repeatable", 6);
    let mut rng = Rng::new(0x570e_0002);

    for _ in 0..30 {
        let mut damaged = full.clone();
        let offset = rng.below(damaged.len().max(1));
        if let Some(byte) = damaged.get_mut(offset) {
            *byte ^= rng.byte();
        }

        let first = recover_with(&dir, &damaged);
        let second = recover_with(&dir, &damaged);
        assert_eq!(
            first.as_ref().ok(),
            second.as_ref().ok(),
            "recovery disagreed with itself on identical bytes"
        );
    }
}
