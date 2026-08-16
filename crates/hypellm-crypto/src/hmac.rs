//! HMAC-SHA-256 as specified by RFC 2104 / FIPS 198-1.
//!
//! Used for keyed API-key digests, protected store frames, CSRF token binding,
//! the audit chain MAC, and deterministic telemetry pseudonyms. Raw SHA-256 is
//! length-extendable; never authenticate with `sha256(key || msg)`.

use crate::sha256::{BLOCK_LEN, DIGEST_LEN, Sha256, sha256};

/// Incremental HMAC-SHA-256 state.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer_key: [u8; BLOCK_LEN],
}

impl core::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The outer key pad is derived from the secret key: never print it.
        f.write_str("HmacSha256(redacted)")
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        // Best-effort scrub of the derived key pad. Specification 7.1: "zeroed on
        // release where the platform permits". `write_volatile` would be a
        // stronger guarantee but requires `unsafe`, which is forbidden here.
        for byte in &mut self.outer_key {
            *byte = 0;
        }
    }
}

impl HmacSha256 {
    /// Create an HMAC state from a key of any length.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        // RFC 2104 section 2: K0 is the key, hashed first if it exceeds the block
        // size, then zero-padded to the block size.
        let mut k0 = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let d = sha256(key);
            // DIGEST_LEN (32) is smaller than BLOCK_LEN (64), so the split is in
            // range and `dst` is exactly digest-sized.
            let (dst, _) = k0.split_at_mut(DIGEST_LEN);
            dst.copy_from_slice(&d);
        } else {
            // This branch runs only when `key.len() <= BLOCK_LEN`.
            let (dst, _) = k0.split_at_mut(key.len());
            dst.copy_from_slice(key);
        }

        let mut ipad = [0u8; BLOCK_LEN];
        let mut opad = [0u8; BLOCK_LEN];
        for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k0.iter()) {
            *i = k ^ 0x36;
            *o = k ^ 0x5c;
        }
        k0.fill(0);

        let mut inner = Sha256::new();
        inner.update(&ipad);
        ipad.fill(0);

        Self {
            inner,
            outer_key: opad,
        }
    }

    /// Absorb message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and produce the tag.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let inner_digest = self.inner.clone().finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key);
        outer.update(&inner_digest);
        outer.finalize()
    }
}

/// One-shot HMAC-SHA-256.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; DIGEST_LEN] {
    let mut m = HmacSha256::new(key);
    m.update(msg);
    m.finalize()
}

/// One-shot HMAC over several parts, with an unambiguous length-prefixed
/// encoding so that `["ab","c"]` and `["a","bc"]` produce different tags.
///
/// Domain separation matters: several call sites MAC tuples of caller-supplied
/// strings, and a naive concatenation would let one field bleed into the next.
#[must_use]
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut m = HmacSha256::new(key);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        m.update(&len.to_be_bytes());
        m.update(part);
    }
    m.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    // RFC 4231 test vectors for HMAC-SHA-256.

    #[test]
    fn rfc4231_case1() {
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_case2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let tag = hmac_sha256(&key, &data);
        assert_eq!(
            hex::encode(&tag),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc4231_case4() {
        let key: Vec<u8> = (1u8..=25).collect();
        let data = [0xcdu8; 50];
        let tag = hmac_sha256(&key, &data);
        assert_eq!(
            hex::encode(&tag),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc4231_case6_long_key() {
        let key = [0xaau8; 131];
        let tag = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex::encode(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc4231_case7_long_key_and_data() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let tag = hmac_sha256(&key, data);
        assert_eq!(
            hex::encode(&tag),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let key = b"routing-policy-key";
        let msg: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let expect = hmac_sha256(key, &msg);
        for split in [0usize, 1, 63, 64, 65, 128, 299, 300] {
            let mut m = HmacSha256::new(key);
            m.update(&msg[..split]);
            m.update(&msg[split..]);
            assert_eq!(m.finalize(), expect, "split {split}");
        }
    }

    #[test]
    fn parts_encoding_is_unambiguous() {
        let key = b"k";
        let a = hmac_sha256_parts(key, &[b"ab", b"c"]);
        let b = hmac_sha256_parts(key, &[b"a", b"bc"]);
        assert_ne!(a, b, "length-prefixed encoding must separate fields");
    }

    #[test]
    fn debug_is_redacted() {
        let m = HmacSha256::new(b"super-secret");
        assert_eq!(format!("{m:?}"), "HmacSha256(redacted)");
    }
}
