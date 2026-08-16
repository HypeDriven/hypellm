//! `Secret<N>` and `Digest`: the two carrier types for sensitive fixed-size
//! material inside the router.
//!
//! Specification 18.2 requires a `Sensitive<T>` with redacted `Debug`/`Display`
//! that is not `Clone` without justification. The general-purpose wrapper lives
//! in `hypellm-core` (which can depend on this crate); the fixed-size byte-array
//! forms live here because the primitives themselves need them.

use crate::ct;
use crate::hex;

/// A fixed-size secret byte array that redacts its `Debug` output and scrubs
/// on drop.
///
/// Deliberately not `Clone`: duplicating key material should be a visible act.
/// Use [`Secret::expose`] at the single point where the bytes are consumed.
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Wrap existing bytes.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    ///
    /// Named `expose` rather than `as_bytes` so that every call site reads as a
    /// deliberate disclosure during review.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Always false; present so `len` does not trip the standard lint pairing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Constant-time equality against another secret of the same width.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        ct::eq(&self.bytes, &other.bytes)
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

impl<const N: usize> core::fmt::Display for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

/// A 256-bit digest.
///
/// Unlike [`Secret`], a digest is safe to copy and to display in truncated
/// form: it is the *output* of a one-way function. Comparison is still
/// constant-time because digests are frequently compared against attacker-
/// supplied candidates (session lookups, key verification).
#[derive(Clone, Copy)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Wrap raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }

    /// Short hex prefix for bounded log and trace fields (specification 17).
    #[must_use]
    pub fn short(self) -> String {
        hex::encode_prefix(&self.0, 6)
    }

    /// Parse from full hex.
    pub fn parse_hex(s: &str) -> Result<Self, hex::HexError> {
        Ok(Self(hex::decode_digest(s.as_bytes())?))
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        ct::eq_digest(&self.0, &other.0)
    }
}

impl Eq for Digest {}

/// Byte-wise ordering, so a digest can key a `BTreeMap`.
///
/// Deliberately **not** constant time, unlike [`PartialEq`]. The distinction is
/// intentional and the reasoning is worth stating, because the two impls
/// disagreeing on timing looks like an oversight:
///
/// - `eq` is used to *authenticate*: "does this candidate match the stored
///   verifier". A timing signal there leaks how much of a guess was correct, so
///   it goes through [`crate::ct`].
/// - `cmp` is used to *place a value in a map*. The keys are one-way digests
///   the caller does not choose directly — a session identifier is
///   `HMAC(server_key, token)`, so shaping the digest requires inverting the
///   MAC. Ordering leaks nothing an attacker can act on, and a constant-time
///   comparator would make every map operation linear in the tree depth for no
///   security benefit.
///
/// Both agree on the *result*: `cmp(a, b) == Equal` exactly when `a == b`.
impl Ord for Digest {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for Digest {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Hashing a digest is safe: it is already one-way output. Using the
        // first 8 bytes keeps map operations cheap.
        state.write(&self.0);
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({}…)", self.short())
    }
}

impl core::fmt::Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_redacts() {
        let s = Secret::new([0xabu8; 16]);
        assert_eq!(format!("{s:?}"), "Secret<16>(redacted)");
        assert_eq!(format!("{s}"), "[redacted]");
        assert_eq!(s.expose()[0], 0xab);
        assert_eq!(s.len(), 16);
        assert!(!s.is_empty());
    }

    #[test]
    fn secret_ct_eq() {
        let a = Secret::new([1u8; 32]);
        let b = Secret::new([1u8; 32]);
        let c = Secret::new([2u8; 32]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn digest_hex_roundtrip() {
        let d = Digest::from_bytes([0x0fu8; 32]);
        let s = d.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(Digest::parse_hex(&s).unwrap(), d);
        assert_eq!(d.short().len(), 12);
        assert!(format!("{d:?}").starts_with("Digest(0f0f0f0f0f0f"));
    }

    #[test]
    fn digest_rejects_bad_hex() {
        assert!(Digest::parse_hex("00").is_err());
        assert!(Digest::parse_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn digest_equality_is_value_based() {
        let a = Digest::from_bytes([7u8; 32]);
        let mut raw = [7u8; 32];
        raw[31] = 8;
        assert_eq!(a, Digest::from_bytes([7u8; 32]));
        assert_ne!(a, Digest::from_bytes(raw));
    }
}
