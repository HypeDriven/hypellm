//! Constant-time comparison helpers.
//!
//! Every comparison of a caller-supplied value against a stored secret digest
//! (API keys, session identifiers, CSRF tokens, frame MACs) must go through
//! this module. `==` on byte slices short-circuits and leaks a prefix-match
//! length through timing.

/// Compare two byte slices without an early exit.
///
/// Returns `false` for differing lengths. Length itself is not secret in any
/// router call site: all compared values are fixed-size digests or tokens whose
/// length is public.
#[must_use]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        // `core::hint::black_box` prevents LLVM from rewriting the accumulate
        // loop into an early-exit comparison.
        diff |= core::hint::black_box(x ^ y);
    }
    core::hint::black_box(diff) == 0
}

/// Compare two 32-byte digests without an early exit.
#[must_use]
pub fn eq_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    eq(a.as_slice(), b.as_slice())
}

/// Select `a` if `choice` is true, otherwise `b`, without branching on `choice`.
///
/// Used where a rejection path must not be distinguishable by timing from an
/// acceptance path that does equivalent work.
#[must_use]
pub fn select_u8(choice: bool, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(u8::from(choice));
    (a & mask) | (b & !mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_and_unequal() {
        assert!(eq(b"", b""));
        assert!(eq(b"abc", b"abc"));
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"ab"));
        assert!(!eq(b"", b"a"));
    }

    #[test]
    fn digest_helper() {
        let a = [3u8; 32];
        let mut b = [3u8; 32];
        assert!(eq_digest(&a, &b));
        b[31] = 4;
        assert!(!eq_digest(&a, &b));
        b[31] = 3;
        b[0] = 4;
        assert!(!eq_digest(&a, &b));
    }

    #[test]
    fn select_is_correct() {
        assert_eq!(select_u8(true, 0xaa, 0x55), 0xaa);
        assert_eq!(select_u8(false, 0xaa, 0x55), 0x55);
    }
}
