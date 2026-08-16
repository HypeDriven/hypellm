//! The store frame format.
//!
//! Specification 11.2: "Each frame contains magic, format version, monotonic
//! sequence, record type, payload length, payload, and checksum/MAC as
//! appropriate."
//!
//! ```text
//!  0      4      6      8     10     12            20     24        24+len      +4        +32
//! ┌──────┬──────┬──────┬──────┬──────┬─────────────┬──────┬──────────┬─────────┬──────────┐
//! │magic │ ver  │ kind │flags │ rsvd │  sequence   │ len  │ payload  │  crc32  │   mac    │
//! │"HYPE"│ u16  │ u16  │ u16  │ u16  │     u64     │ u32  │  bytes   │   u32   │ optional │
//! └──────┴──────┴──────┴──────┴──────┴─────────────┴──────┴──────────┴─────────┴──────────┘
//! ```
//!
//! Two integrity mechanisms, for two different threats:
//!
//! - **CRC-32** covers header and payload. It detects a torn write, a short
//!   read, and bit rot. It is not a security control and is not treated as one.
//! - **HMAC-SHA-256** is present only on *protected* records — those whose
//!   content decides authorization or accountability, such as a configuration
//!   activation or an audit event. A CRC would let an attacker with write
//!   access to the state directory rewrite an audit record and recompute the
//!   checksum; a MAC keyed by material the attacker does not hold will not.
//!
//! Startup treats these differently: a CRC failure at the tail is a torn write
//! and truncates the log, while a MAC failure is tampering and fails closed
//! (specification 11.2: "fails closed on protected-record integrity errors").

use hypellm_crypto::{crc32, ct, hmac_sha256};
use core::fmt;

/// Frame magic.
pub const MAGIC: [u8; 4] = *b"HYPE";

/// Current format version.
pub const FORMAT_VERSION: u16 = 1;

/// Fixed header length.
pub const HEADER_LEN: usize = 24;

/// CRC trailer length.
pub const CRC_LEN: usize = 4;

/// MAC trailer length.
pub const MAC_LEN: usize = 32;

/// Maximum payload length a frame may declare.
///
/// Bounds the allocation a corrupt length field can cause: without it, a
/// flipped bit in `len` asks for a four gigabyte buffer.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024 * 1024;

/// Flag bit: the frame carries a MAC.
const FLAG_PROTECTED: u16 = 0x0001;

/// What a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordKind {
    /// An activated configuration document.
    ConfigActivation,
    /// An audit event in the hash chain.
    AuditEvent,
    /// A signed audit checkpoint.
    AuditCheckpoint,
    /// An API key record.
    ApiKey,
    /// An API key revocation.
    ApiKeyRevocation,
    /// Credential metadata. Never a secret value.
    CredentialMeta,
    /// A usage aggregate.
    UsageAggregate,
    /// A session record.
    Session,
    /// A marker written when a snapshot is taken.
    SnapshotMarker,
    /// A policy draft awaiting validation, approval, or publication.
    PolicyDraft,
    /// A policy draft that was published or discarded.
    PolicyDraftClosed,
    /// An unrecognised kind, preserved so that a newer writer's records survive
    /// a rollback to an older reader rather than being dropped.
    Unknown(u16),
}

impl RecordKind {
    /// The wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ConfigActivation => 1,
            Self::AuditEvent => 2,
            Self::AuditCheckpoint => 3,
            Self::ApiKey => 4,
            Self::ApiKeyRevocation => 5,
            Self::CredentialMeta => 6,
            Self::UsageAggregate => 7,
            Self::Session => 8,
            Self::SnapshotMarker => 9,
            Self::PolicyDraft => 10,
            Self::PolicyDraftClosed => 11,
            Self::Unknown(v) => v,
        }
    }

    /// Parse a wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::ConfigActivation,
            2 => Self::AuditEvent,
            3 => Self::AuditCheckpoint,
            4 => Self::ApiKey,
            5 => Self::ApiKeyRevocation,
            6 => Self::CredentialMeta,
            7 => Self::UsageAggregate,
            8 => Self::Session,
            9 => Self::SnapshotMarker,
            10 => Self::PolicyDraft,
            11 => Self::PolicyDraftClosed,
            other => Self::Unknown(other),
        }
    }

    /// Whether a record of this kind must carry a MAC.
    ///
    /// Everything that decides authorization or supports accountability is
    /// protected. Usage aggregates are not: they are recomputable from the
    /// audit trail and are high-volume.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(
            self,
            Self::ConfigActivation
                | Self::AuditEvent
                | Self::AuditCheckpoint
                | Self::ApiKey
                | Self::ApiKeyRevocation
                | Self::CredentialMeta
                | Self::Session
                // A draft is the text a publication will activate, and
                // publication is the most consequential management action there
                // is. An unprotected draft could be edited on disk between
                // authoring and approval, so the approver would review one
                // document and publish another.
                | Self::PolicyDraft
                | Self::PolicyDraftClosed
        )
    }

    /// Stable name for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigActivation => "config_activation",
            Self::AuditEvent => "audit_event",
            Self::AuditCheckpoint => "audit_checkpoint",
            Self::ApiKey => "api_key",
            Self::ApiKeyRevocation => "api_key_revocation",
            Self::CredentialMeta => "credential_meta",
            Self::UsageAggregate => "usage_aggregate",
            Self::Session => "session",
            Self::SnapshotMarker => "snapshot_marker",
            Self::PolicyDraft => "policy_draft",
            Self::PolicyDraftClosed => "policy_draft_closed",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Every known kind, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ConfigActivation,
            Self::AuditEvent,
            Self::AuditCheckpoint,
            Self::ApiKey,
            Self::ApiKeyRevocation,
            Self::CredentialMeta,
            Self::UsageAggregate,
            Self::Session,
            Self::SnapshotMarker,
            Self::PolicyDraft,
            Self::PolicyDraftClosed,
        ]
    }
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The record kind.
    pub kind: RecordKind,
    /// Monotonic sequence number.
    pub sequence: u64,
    /// The payload.
    pub payload: Vec<u8>,
    /// Whether the frame carried a MAC.
    pub protected: bool,
}

/// Why a frame could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer ended before the frame did.
    ///
    /// At the end of a log this is a torn write, which is expected after a
    /// crash and is handled by truncating.
    Incomplete,
    /// The magic did not match.
    BadMagic,
    /// The format version is not supported.
    UnsupportedVersion(u16),
    /// The declared payload length exceeds [`MAX_PAYLOAD_LEN`].
    PayloadTooLarge,
    /// The CRC did not match: corruption.
    ChecksumMismatch,
    /// The MAC did not match: tampering.
    ///
    /// This is the one that fails startup closed.
    MacMismatch,
    /// A protected record kind arrived without a MAC.
    MissingMac,
    /// An unprotected record kind arrived with a MAC.
    UnexpectedMac,
}

impl FrameError {
    /// Whether this error indicates deliberate modification rather than
    /// incidental corruption.
    #[must_use]
    pub const fn is_integrity_violation(self) -> bool {
        matches!(self, Self::MacMismatch | Self::MissingMac | Self::UnexpectedMac)
    }

    /// Whether this error is consistent with a torn write at the end of a log.
    #[must_use]
    pub const fn is_recoverable_tail(self) -> bool {
        matches!(self, Self::Incomplete | Self::ChecksumMismatch)
    }

    /// Stable code for diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete_frame",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedVersion(_) => "unsupported_format_version",
            Self::PayloadTooLarge => "payload_too_large",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::MacMismatch => "mac_mismatch",
            Self::MissingMac => "missing_mac",
            Self::UnexpectedMac => "unexpected_mac",
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => f.write_str("frame is incomplete"),
            Self::BadMagic => f.write_str("frame magic does not match"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported frame format version {v}"),
            Self::PayloadTooLarge => f.write_str("frame payload exceeds the permitted size"),
            Self::ChecksumMismatch => f.write_str("frame checksum does not match"),
            Self::MacMismatch => f.write_str("frame authentication code does not match"),
            Self::MissingMac => f.write_str("protected frame has no authentication code"),
            Self::UnexpectedMac => f.write_str("unprotected frame carries an authentication code"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode a frame.
#[must_use]
pub fn encode(kind: RecordKind, sequence: u64, payload: &[u8], mac_key: &[u8]) -> Vec<u8> {
    let protected = kind.is_protected();
    let mut out =
        Vec::with_capacity(HEADER_LEN + payload.len() + CRC_LEN + if protected { MAC_LEN } else { 0 });

    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&kind.as_u16().to_le_bytes());
    out.extend_from_slice(&if protected { FLAG_PROTECTED } else { 0 }.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&sequence.to_le_bytes());
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);

    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());

    if protected {
        // The MAC covers the header, the payload, and the CRC — so neither the
        // sequence number nor the record kind can be edited independently.
        let mac = hmac_sha256(mac_key, &out);
        out.extend_from_slice(&mac);
    }

    out
}

/// A decoded frame together with the number of bytes it occupied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// The frame.
    pub frame: Frame,
    /// Total bytes consumed.
    pub length: usize,
}

/// Decode the frame at the start of `buf`.
///
/// `buf` is bytes off disk in a directory the threat model treats as hostile,
/// so every field width and offset below is established by splitting the slice
/// rather than by indexing into it: a length that does not fit yields
/// [`FrameError::Incomplete`] instead of a panic.
pub fn decode(buf: &[u8], mac_key: &[u8]) -> Result<DecodedFrame, FrameError> {
    let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
        return Err(FrameError::Incomplete);
    };
    // Destructuring the fixed header makes the field offsets in the module
    // diagram something the compiler checks rather than something a reader
    // counts: the pattern is only irrefutable if it covers exactly 24 bytes.
    let [
        magic0,
        magic1,
        magic2,
        magic3,
        version0,
        version1,
        kind0,
        kind1,
        flags0,
        flags1,
        _reserved0,
        _reserved1,
        seq0,
        seq1,
        seq2,
        seq3,
        seq4,
        seq5,
        seq6,
        seq7,
        len0,
        len1,
        len2,
        len3,
    ] = *header;

    if [magic0, magic1, magic2, magic3] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = u16::from_le_bytes([version0, version1]);
    if version != FORMAT_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let kind = RecordKind::from_u16(u16::from_le_bytes([kind0, kind1]));
    let flags = u16::from_le_bytes([flags0, flags1]);
    let protected = flags & FLAG_PROTECTED != 0;
    let sequence = u64::from_le_bytes([seq0, seq1, seq2, seq3, seq4, seq5, seq6, seq7]);
    // A declared length that does not fit in `usize` cannot address a payload
    // this process could hold; it is rejected on the same path as one that
    // exceeds the payload bound.
    let Ok(len) = usize::try_from(u32::from_le_bytes([len0, len1, len2, len3])) else {
        return Err(FrameError::PayloadTooLarge);
    };

    if len > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge);
    }

    // A protected *kind* must be marked protected, and vice versa: otherwise
    // clearing the flag bit would strip the MAC requirement.
    if kind.is_protected() != protected {
        return Err(if kind.is_protected() {
            FrameError::MissingMac
        } else {
            FrameError::UnexpectedMac
        });
    }

    // `len` is bounded by MAX_PAYLOAD_LEN, so neither sum can overflow.
    let crc_end = HEADER_LEN + len + CRC_LEN;
    let total = crc_end + if protected { MAC_LEN } else { 0 };

    // One split per boundary, outermost first: the whole frame, then the MAC
    // trailer, then the CRC trailer, then the payload.
    let Some((framed, _after)) = buf.split_at_checked(total) else {
        return Err(FrameError::Incomplete);
    };
    let Some((crc_covered, stored_mac)) = framed.split_at_checked(crc_end) else {
        return Err(FrameError::Incomplete);
    };
    let Some((body, stored_crc)) = crc_covered.split_last_chunk::<CRC_LEN>() else {
        return Err(FrameError::Incomplete);
    };
    let Some((_header_bytes, payload)) = body.split_at_checked(HEADER_LEN) else {
        return Err(FrameError::Incomplete);
    };

    if crc32(body) != u32::from_le_bytes(*stored_crc) {
        return Err(FrameError::ChecksumMismatch);
    }

    if protected {
        // The MAC covers header, payload, and CRC — `crc_covered` is exactly
        // the span `encode` authenticated.
        let expected = hmac_sha256(mac_key, crc_covered);
        if !ct::eq(&expected, stored_mac) {
            return Err(FrameError::MacMismatch);
        }
    }

    Ok(DecodedFrame {
        frame: Frame {
            kind,
            sequence,
            payload: payload.to_vec(),
            protected,
        },
        length: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"store-mac-key-for-tests";

    #[test]
    fn roundtrip_unprotected() {
        let bytes = encode(RecordKind::UsageAggregate, 7, b"payload", KEY);
        let decoded = decode(&bytes, KEY).unwrap();
        assert_eq!(decoded.length, bytes.len());
        assert_eq!(decoded.frame.kind, RecordKind::UsageAggregate);
        assert_eq!(decoded.frame.sequence, 7);
        assert_eq!(decoded.frame.payload, b"payload");
        assert!(!decoded.frame.protected);
    }

    #[test]
    fn roundtrip_protected() {
        let bytes = encode(RecordKind::AuditEvent, 42, b"actor=admin", KEY);
        let decoded = decode(&bytes, KEY).unwrap();
        assert!(decoded.frame.protected);
        assert_eq!(decoded.frame.sequence, 42);
        assert_eq!(decoded.frame.payload, b"actor=admin");
        assert_eq!(bytes.len(), HEADER_LEN + 11 + CRC_LEN + MAC_LEN);
    }

    #[test]
    fn empty_payload_roundtrips() {
        let bytes = encode(RecordKind::SnapshotMarker, 1, b"", KEY);
        let decoded = decode(&bytes, KEY).unwrap();
        assert!(decoded.frame.payload.is_empty());
        assert_eq!(decoded.length, bytes.len());
    }

    #[test]
    fn large_payload_roundtrips() {
        let payload = vec![0xa5u8; 1_000_000];
        let bytes = encode(RecordKind::UsageAggregate, 1, &payload, KEY);
        let decoded = decode(&bytes, KEY).unwrap();
        assert_eq!(decoded.frame.payload.len(), payload.len());
    }

    #[test]
    fn every_prefix_reports_incomplete_not_corruption() {
        // A torn write must be distinguishable from tampering, at every
        // possible truncation point.
        let bytes = encode(RecordKind::AuditEvent, 1, b"some payload here", KEY);
        for cut in 0..bytes.len() {
            let e = decode(&bytes[..cut], KEY).unwrap_err();
            assert_eq!(
                e,
                FrameError::Incomplete,
                "prefix of {cut} bytes gave {e:?}"
            );
            assert!(e.is_recoverable_tail());
            assert!(!e.is_integrity_violation());
        }
        assert!(decode(&bytes, KEY).is_ok());
    }

    #[test]
    fn a_flipped_payload_bit_fails_the_checksum() {
        let bytes = encode(RecordKind::UsageAggregate, 1, b"0123456789", KEY);
        for i in HEADER_LEN..HEADER_LEN + 10 {
            let mut corrupt = bytes.clone();
            corrupt[i] ^= 0x01;
            assert_eq!(
                decode(&corrupt, KEY).unwrap_err(),
                FrameError::ChecksumMismatch,
                "byte {i}"
            );
        }
    }

    #[test]
    fn tampering_with_a_protected_frame_fails_the_mac() {
        // The attack: an operator with write access to the state directory
        // edits an audit record and recomputes the CRC. The MAC does not
        // recompute without the key.
        let bytes = encode(RecordKind::AuditEvent, 1, b"actor=alice action=read", KEY);
        let mut forged = bytes.clone();
        let payload_start = HEADER_LEN;
        forged[payload_start..payload_start + 5].copy_from_slice(b"actor");
        forged[payload_start + 6..payload_start + 11].copy_from_slice(b"malry");
        // Recompute the CRC, as an attacker would.
        let body_len = HEADER_LEN + 23;
        let crc = crc32(&forged[..body_len]);
        forged[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());

        let e = decode(&forged, KEY).unwrap_err();
        assert_eq!(e, FrameError::MacMismatch);
        assert!(e.is_integrity_violation());
        assert!(!e.is_recoverable_tail());
    }

    #[test]
    fn a_frame_cannot_be_verified_with_the_wrong_key() {
        let bytes = encode(RecordKind::AuditEvent, 1, b"x", KEY);
        assert_eq!(
            decode(&bytes, b"different-key").unwrap_err(),
            FrameError::MacMismatch
        );
    }

    #[test]
    fn the_sequence_number_is_covered_by_the_mac() {
        // Reordering or renumbering audit records must be detectable.
        let bytes = encode(RecordKind::AuditEvent, 1, b"x", KEY);
        let mut renumbered = bytes.clone();
        renumbered[12..20].copy_from_slice(&99u64.to_le_bytes());
        let body_len = HEADER_LEN + 1;
        let crc = crc32(&renumbered[..body_len]);
        renumbered[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode(&renumbered, KEY).unwrap_err(), FrameError::MacMismatch);
    }

    #[test]
    fn the_record_kind_is_covered_by_the_mac() {
        let bytes = encode(RecordKind::AuditEvent, 1, b"x", KEY);
        let mut retyped = bytes.clone();
        retyped[6..8].copy_from_slice(&RecordKind::ApiKey.as_u16().to_le_bytes());
        let body_len = HEADER_LEN + 1;
        let crc = crc32(&retyped[..body_len]);
        retyped[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode(&retyped, KEY).unwrap_err(), FrameError::MacMismatch);
    }

    #[test]
    fn stripping_the_protected_flag_is_rejected() {
        // Clearing the flag would drop the MAC requirement if the kind were not
        // also checked.
        let bytes = encode(RecordKind::AuditEvent, 1, b"x", KEY);
        let mut stripped = bytes[..HEADER_LEN + 1 + CRC_LEN].to_vec();
        stripped[8..10].copy_from_slice(&0u16.to_le_bytes());
        let body_len = HEADER_LEN + 1;
        let crc = crc32(&stripped[..body_len]);
        stripped[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());

        let e = decode(&stripped, KEY).unwrap_err();
        assert_eq!(e, FrameError::MissingMac);
        assert!(e.is_integrity_violation());
    }

    #[test]
    fn adding_a_mac_to_an_unprotected_kind_is_rejected() {
        let mut bytes = encode(RecordKind::UsageAggregate, 1, b"x", KEY);
        bytes[8..10].copy_from_slice(&FLAG_PROTECTED.to_le_bytes());
        let body_len = HEADER_LEN + 1;
        let crc = crc32(&bytes[..body_len]);
        bytes[body_len..body_len + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode(&bytes, KEY).unwrap_err(), FrameError::UnexpectedMac);
    }

    #[test]
    fn bad_magic_and_version_are_rejected() {
        let mut bytes = encode(RecordKind::UsageAggregate, 1, b"x", KEY);
        bytes[0] = b'X';
        assert_eq!(decode(&bytes, KEY).unwrap_err(), FrameError::BadMagic);

        let mut bytes = encode(RecordKind::UsageAggregate, 1, b"x", KEY);
        bytes[4..6].copy_from_slice(&999u16.to_le_bytes());
        assert_eq!(
            decode(&bytes, KEY).unwrap_err(),
            FrameError::UnsupportedVersion(999)
        );
    }

    #[test]
    fn an_absurd_length_is_rejected_before_allocation() {
        // A flipped bit in the length field must not ask for a giant buffer.
        let mut bytes = encode(RecordKind::UsageAggregate, 1, b"x", KEY);
        bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bytes, KEY).unwrap_err(), FrameError::PayloadTooLarge);
    }

    #[test]
    fn record_kinds_roundtrip_and_have_distinct_values() {
        let mut values: Vec<u16> = RecordKind::all().iter().map(|k| k.as_u16()).collect();
        values.sort_unstable();
        let before = values.len();
        values.dedup();
        assert_eq!(values.len(), before);

        for k in RecordKind::all() {
            assert_eq!(RecordKind::from_u16(k.as_u16()), *k);
        }
        assert_eq!(RecordKind::from_u16(9999), RecordKind::Unknown(9999));
    }

    #[test]
    fn authorization_relevant_kinds_are_protected() {
        for kind in [
            RecordKind::ConfigActivation,
            RecordKind::AuditEvent,
            RecordKind::AuditCheckpoint,
            RecordKind::ApiKey,
            RecordKind::ApiKeyRevocation,
            RecordKind::CredentialMeta,
            RecordKind::Session,
        ] {
            assert!(kind.is_protected(), "{kind:?} must be protected");
        }
        assert!(!RecordKind::UsageAggregate.is_protected());
    }
}
