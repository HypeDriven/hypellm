//! In-repository reviewed cryptographic and encoding primitives for HypeLLM
//! Router.
//!
//! Scope is deliberately narrow — see `MODULE.md` for the security decision
//! record. This crate implements only fully-specified, deterministic,
//! test-vector-verifiable primitives:
//!
//! - [`sha256`] — FIPS 180-4
//! - [`hmac`] — RFC 2104 / FIPS 198-1
//! - [`crc32`] — IEEE 802.3, corruption detection only
//! - [`base64`] — RFC 4648, strict decoding
//! - [`hex`] — RFC 4648 section 8
//! - [`ct`] — constant-time comparison
//! - [`random`] — OS entropy, fail-closed
//! - [`secret`] — redacting carriers for key material and digests
//!
//! It does **not** implement TLS, asymmetric signatures, key agreement, JWT
//! verification, or any AEAD. Specification 4 and 9.1 forbid writing novel
//! signature or TLS code to satisfy the dependency policy; those functions are
//! delegated to the platform boundary in `hypellm-net`.

#![forbid(unsafe_code)]
// Specification 18.2: no panics on data-plane input, all integer conversions
// checked. Every primitive here runs on the data path (digests, MACs, JWT
// segment decoding), so the workspace-level warnings are escalated to errors
// for this crate: an unchecked index or a silent `as` is a build failure, not a
// line in a warning list. The two remaining indexes carry a function-scoped
// `#[allow]` and a proof of their bound (`crc32::build_table`, `Crc32::update`).
#![deny(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::integer_division
)]
// Unit tests index fixed test vectors on purpose; they keep the workspace-level
// `warn` rather than being silenced, so the signal stays visible there too.
#![cfg_attr(
    test,
    warn(
        clippy::indexing_slicing,
        clippy::as_conversions,
        clippy::integer_division
    )
)]

pub mod base64;
pub mod crc32;
pub mod ct;
pub mod hex;
pub mod hmac;
pub mod random;
pub mod secret;
pub mod sha256;

pub use crc32::crc32;
pub use hmac::{HmacSha256, hmac_sha256, hmac_sha256_parts};
pub use secret::{Digest, Secret};
pub use sha256::{Sha256, sha256, sha256_parts};

/// Convenience: SHA-256 digest of `data` as a [`Digest`].
#[must_use]
pub fn digest(data: &[u8]) -> Digest {
    Digest::from_bytes(sha256(data))
}

/// Convenience: SHA-256 digest of several parts as a [`Digest`].
#[must_use]
pub fn digest_parts(parts: &[&[u8]]) -> Digest {
    Digest::from_bytes(sha256_parts(parts))
}

/// Convenience: keyed digest as a [`Digest`].
#[must_use]
pub fn keyed_digest(key: &[u8], parts: &[&[u8]]) -> Digest {
    Digest::from_bytes(hmac_sha256_parts(key, parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_helpers_agree_with_primitives() {
        assert_eq!(digest(b"abc").as_bytes(), &sha256(b"abc"));
        assert_eq!(
            digest_parts(&[b"a", b"bc"]).as_bytes(),
            &sha256_parts(&[b"a", b"bc"])
        );
        assert_eq!(
            keyed_digest(b"k", &[b"m"]).as_bytes(),
            &hmac_sha256_parts(b"k", &[b"m"])
        );
    }

    #[test]
    fn keyed_digest_depends_on_key() {
        assert_ne!(keyed_digest(b"k1", &[b"m"]), keyed_digest(b"k2", &[b"m"]));
    }
}
