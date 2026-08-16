//! SHA-256 as specified by FIPS 180-4.
//!
//! Implemented in-repository because the dependency policy (specification 4)
//! admits no registry crates and the router needs a collision-resistant digest
//! for configuration digests, the audit hash chain, and credential digests.
//!
//! This is a *fully specified, deterministic* primitive validated against the
//! published NIST vectors in the tests below. It is explicitly not "novel
//! cryptography" in the sense forbidden by specification 4 and 9.1.

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// SHA-256 block size in bytes.
pub const BLOCK_LEN: usize = 64;

/// FIPS 180-4 section 5.3.3 initial hash value.
const H_INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4 section 4.2.2 round constants.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Incremental SHA-256 state.
///
/// The struct is `Copy`-free on purpose: cloning a hasher mid-stream is a
/// legitimate operation (used by the audit chain) but must be explicit.
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Total message length in bytes. FIPS bounds the message at 2^64 - 1 bits;
    /// we saturate rather than wrap so an absurd length produces a wrong-but-
    /// bounded result instead of silently aliasing a shorter message.
    total_len: u64,
}

impl core::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print internal state: it is a function of (possibly secret) input.
        f.debug_struct("Sha256")
            .field("total_len", &self.total_len)
            .finish_non_exhaustive()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            h: H_INIT,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self
            .total_len
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let mut input = data;

        if self.buf_len > 0 {
            // Invariant: `buf_len <= BLOCK_LEN`, so the split is in range and
            // `tail` is exactly the unused remainder of the block buffer.
            let (_, tail) = self.buf.split_at_mut(self.buf_len);
            let take = tail.len().min(input.len());
            let (dst, _) = tail.split_at_mut(take);
            let (head, rest) = input.split_at(take);
            dst.copy_from_slice(head);
            self.buf_len += take;
            input = rest;
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        let mut blocks = input.chunks_exact(BLOCK_LEN);
        for block in blocks.by_ref() {
            let mut b = [0u8; BLOCK_LEN];
            // `chunks_exact` yields slices of exactly BLOCK_LEN bytes.
            b.copy_from_slice(block);
            compress(&mut self.h, &b);
        }

        let rest = blocks.remainder();
        if !rest.is_empty() {
            // `remainder()` is shorter than BLOCK_LEN, so the split is in range.
            let (dst, _) = self.buf.split_at_mut(rest.len());
            dst.copy_from_slice(rest);
            self.buf_len = rest.len();
        }
    }

    /// Finish and produce the digest. Consumes the hasher.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.saturating_mul(8);

        // FIPS 180-4 section 5.1.1: append 0x80, then zeroes, then 64-bit length.
        // `buf_len` is strictly less than BLOCK_LEN on entry — `update` compresses
        // and resets the buffer the moment it fills — so the marker always fits
        // and `get_mut` always yields the slot.
        if let Some(slot) = self.buf.get_mut(self.buf_len) {
            *slot = 0x80;
            self.buf_len += 1;
        }
        for byte in self.buf.iter_mut().skip(self.buf_len) {
            *byte = 0;
        }
        if self.buf_len > BLOCK_LEN - 8 {
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf = [0u8; BLOCK_LEN];
        }
        // BLOCK_LEN - 8 is a constant interior split point of a BLOCK_LEN array,
        // so `len_be` is exactly the trailing 8 bytes.
        let (_, len_be) = self.buf.split_at_mut(BLOCK_LEN - 8);
        len_be.copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        compress(&mut self.h, &block);

        let mut out = [0u8; DIGEST_LEN];
        for (slot, word) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One-shot digest.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Digest of the concatenation of several parts, without allocating.
#[must_use]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

#[inline]
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 64];
    // FIPS 180-4 section 6.2.2 step 1, first case: the 16 words of the block.
    // `chunks_exact(4)` yields exactly 16 chunks for a BLOCK_LEN block, so the
    // zip fills w[0..16] and leaves the rest zero for the expansion below.
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        let mut be = [0u8; 4];
        be.copy_from_slice(chunk);
        *word = u32::from_be_bytes(be);
    }
    // Second case: extend to 64 words. Each new word reads only the sixteen
    // words before it, so the already-computed prefix is split off and its last
    // sixteen words are destructured positionally: the bindings are w[i-16],
    // w[i-15], w[i-7] and w[i-2], with no index arithmetic to get wrong.
    for i in 16..64 {
        let (head, tail) = w.split_at_mut(i);
        // `head.len() == i` and the loop starts at 16, so the chunk is present.
        let Some(&[wm16, wm15, _, _, _, _, _, _, _, wm7, _, _, _, _, wm2, _]) =
            head.last_chunk::<16>()
        else {
            return;
        };
        let s0 = wm15.rotate_right(7) ^ wm15.rotate_right(18) ^ (wm15 >> 3);
        let s1 = wm2.rotate_right(17) ^ wm2.rotate_right(19) ^ (wm2 >> 10);
        if let Some(next) = tail.first_mut() {
            *next = wm16.wrapping_add(s0).wrapping_add(wm7).wrapping_add(s1);
        }
    }

    let [h0, h1, h2, h3, h4, h5, h6, h7] = *h;
    let (mut a, mut b, mut c, mut d) = (h0, h1, h2, h3);
    let (mut e, mut f, mut g, mut hh) = (h4, h5, h6, h7);

    // K and w are both 64 words long, so the zip runs the full 64 rounds.
    for (&k, &wi) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    *h = [
        h0.wrapping_add(a),
        h1.wrapping_add(b),
        h2.wrapping_add(c),
        h3.wrapping_add(d),
        h4.wrapping_add(e),
        h5.wrapping_add(f),
        h6.wrapping_add(g),
        h7.wrapping_add(hh),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn hexs(d: [u8; DIGEST_LEN]) -> String {
        hex::encode(&d)
    }

    #[test]
    fn nist_empty() {
        assert_eq!(
            hexs(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nist_abc() {
        assert_eq!(
            hexs(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn nist_two_block() {
        assert_eq!(
            hexs(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn nist_896_bit_multi_block() {
        assert_eq!(
            hexs(sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn nist_million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hexs(h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        // Every split point of a 200-byte message must produce the same digest.
        let msg: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let expect = sha256(&msg);
        for split in 0..=msg.len() {
            let mut h = Sha256::new();
            h.update(&msg[..split]);
            h.update(&msg[split..]);
            assert_eq!(h.finalize(), expect, "split at {split}");
        }
    }

    #[test]
    fn three_way_split_matches() {
        let msg: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let expect = sha256(&msg);
        for a in [0usize, 1, 63, 64, 65, 127, 128, 200] {
            for b in [0usize, 1, 63, 64, 65, 99] {
                let a = a.min(msg.len());
                let b = (a + b).min(msg.len());
                let mut h = Sha256::new();
                h.update(&msg[..a]);
                h.update(&msg[a..b]);
                h.update(&msg[b..]);
                assert_eq!(h.finalize(), expect);
            }
        }
    }

    #[test]
    fn block_boundary_lengths() {
        // Lengths around the padding boundary are the classic bug source.
        for len in 0..=130usize {
            let msg = vec![0x5au8; len];
            let mut a = Sha256::new();
            a.update(&msg);
            let one = a.finalize();
            let mut b = Sha256::new();
            for byte in &msg {
                b.update(&[*byte]);
            }
            assert_eq!(one, b.finalize(), "len {len}");
        }
    }

    #[test]
    fn parts_matches_concat() {
        let parts: [&[u8]; 3] = [b"hypellm", b"-", b"router"];
        assert_eq!(sha256_parts(&parts), sha256(b"hypellm-router"));
    }

    #[test]
    fn debug_does_not_leak_state() {
        let mut h = Sha256::new();
        h.update(b"secret-material");
        let s = format!("{h:?}");
        assert!(!s.contains("h:"));
        assert!(!s.contains("buf"));
    }
}
