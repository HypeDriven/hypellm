//! CRC-32 (IEEE 802.3 / ITU-T V.42, reflected, polynomial 0xEDB88320).
//!
//! Used only for *corruption* detection on unprotected store frames
//! (specification 11.2: "checksum/MAC as appropriate"). It is not a security
//! primitive: any frame whose integrity matters for authorization carries an
//! HMAC instead. Truncated writes and bit rot are what this catches.

const POLY: u32 = 0xEDB8_8320;

/// Precomputed table. `const fn` evaluation keeps it in `.rodata` with no
/// lazy-initialisation branch on the hot path.
const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    // `idx` and `entry` are the same counter in two types: `const fn` cannot
    // call `u32::try_from`, and this avoids a silent `as` conversion.
    let mut idx = 0usize;
    let mut entry = 0u32;
    while idx < 256 {
        let mut crc = entry;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        // The loop condition bounds `idx` below 256, the length of `table`;
        // `get_mut` is not callable from a `const fn`, so the index stands.
        #[allow(clippy::indexing_slicing)]
        {
            table[idx] = crc;
        }
        idx += 1;
        entry += 1;
    }
    table
}

/// Incremental CRC-32 state.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Create a fresh CRC state.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Absorb bytes.
    // The table index is built from a `u8`, so it is always below 256, and
    // `TABLE` has exactly 256 entries: the lookup cannot be out of range. The
    // allow is scoped to this function, and keeps the per-byte inner loop free
    // of a redundant bounds check.
    #[allow(clippy::indexing_slicing)]
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for byte in data {
            let [low, ..] = crc.to_le_bytes();
            let idx = usize::from(low ^ *byte);
            crc = (crc >> 8) ^ TABLE[idx];
        }
        self.state = crc;
    }

    /// Produce the final value.
    #[must_use]
    pub const fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

/// One-shot CRC-32.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

/// CRC-32 over several parts.
#[must_use]
pub fn crc32_parts(parts: &[&[u8]]) -> u32 {
    let mut c = Crc32::new();
    for part in parts {
        c.update(part);
    }
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let expect = crc32(&data);
        for split in [0usize, 1, 17, 250, 499, 500] {
            let mut c = Crc32::new();
            c.update(&data[..split]);
            c.update(&data[split..]);
            assert_eq!(c.finalize(), expect);
        }
    }

    #[test]
    fn detects_single_bit_flip() {
        let mut data = vec![0x5au8; 128];
        let base = crc32(&data);
        for i in 0..data.len() {
            for bit in 0..8u8 {
                data[i] ^= 1 << bit;
                assert_ne!(crc32(&data), base, "bit {bit} of byte {i} undetected");
                data[i] ^= 1 << bit;
            }
        }
    }

    #[test]
    fn parts_matches_concat() {
        assert_eq!(crc32_parts(&[b"123", b"456", b"789"]), crc32(b"123456789"));
    }
}
