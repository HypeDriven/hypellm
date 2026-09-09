//! scrypt (RFC 7914), the memory-hard key derivation function behind
//! `local_user` password verifiers.
//!
//! # Why this is admissible here
//!
//! This crate's `MODULE.md` admits a primitive when it is "fully specified,
//! deterministic, test-vector-verifiable" and the router cannot function
//! without it. scrypt meets the first three exactly: RFC 7914 specifies
//! Salsa20/8 core, `scryptBlockMix`, `scryptROMix` and `scrypt` itself in full,
//! and publishes vectors for the whole construction, which the tests below hold
//! this against. It is also not a new *cryptographic* idea in this crate: the
//! outer and inner passes are [`crate::pbkdf2`], already here, and the mixing
//! function is a fixed permutation with no key schedule, no field arithmetic
//! and no parsing. Specification 4 forbids "novel signature or TLS code"; this
//! is neither.
//!
//! It replaces PBKDF2 for password verifiers because PBKDF2 is not memory-hard.
//! An iterated SHA-256 is exactly the shape a GPU or an ASIC is good at, so an
//! attacker holding an offline copy of the configuration gets orders of
//! magnitude more guesses per second against a PBKDF2 verifier than against an
//! scrypt one at the same wall-clock cost to the router. That asymmetry is the
//! whole point of the function.
//!
//! # Bounded, because a request reaches it
//!
//! `POST /admin/v1/auth/password` runs before any session, so an
//! unauthenticated caller decides how often this runs. Memory is
//! `128 * N * r` bytes per call — 32 MiB at the defaults — and the management
//! plane bounds concurrent verifications, so the peak is that product and not a
//! function of request rate. [`MAX_MEMORY_BYTES`] refuses parameters that would
//! exceed the bound rather than trusting a configuration to be sensible: a
//! verifier is parsed from a file, and `ln=30` in it must be a configuration
//! error rather than an allocation.

use crate::pbkdf2;

/// The largest `128 * N * r` this implementation will allocate, in bytes.
///
/// 128 MiB. Four times the default working set, so a deployment may raise the
/// cost deliberately, and far enough below any plausible host that a mistyped
/// `ln` is refused instead of taking the router down. The management plane's
/// concurrency bound multiplies this; both are needed, because this one alone
/// would still let two callers at once take twice it.
pub const MAX_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

/// Default `log2(N)`: 32 768 iterations of the mixing loop.
///
/// With [`DEFAULT_R`] this is 32 MiB and roughly 100 ms of CPU — the interactive
/// figure RFC 7914 section 2 describes, and the same order as the PBKDF2 cost it
/// replaces, so the endpoint's existing concurrency bound still holds.
pub const DEFAULT_LOG_N: u8 = 15;

/// The smallest `log2(N)` a verifier may declare.
///
/// Not a security recommendation — [`DEFAULT_LOG_N`] is that. It is the same
/// trade the PBKDF2 floor makes: low enough (256 KiB, about a millisecond) that
/// a test suite can afford real verifiers in a debug build, high enough that
/// `ln=1` cannot reach production by way of a typo.
pub const MIN_LOG_N: u8 = 8;

/// Default block size factor.
///
/// Eight, as in every published parameter set. `r` tunes the size of each
/// memory read, not the total; changing it without changing `ln` changes the
/// memory as well, which is why they are chosen together.
pub const DEFAULT_R: u32 = 8;

/// Default parallelism.
///
/// One. `p` multiplies CPU without multiplying memory, which is the wrong knob
/// for a router that is bounding CPU on an unauthenticated endpoint.
pub const DEFAULT_P: u32 = 1;

/// Why a derivation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScryptError {
    /// `N` was not a power of two greater than one, or `r` or `p` was zero.
    Parameters,
    /// `128 * N * r` exceeds [`MAX_MEMORY_BYTES`], or the size does not fit a
    /// `usize` on this target.
    TooMuchMemory,
}

impl core::fmt::Display for ScryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parameters => f.write_str(
                "scrypt parameters are invalid: N must be a power of two above one, r and p nonzero",
            ),
            Self::TooMuchMemory => f.write_str(
                "scrypt parameters ask for more memory than this router will allocate",
            ),
        }
    }
}

impl std::error::Error for ScryptError {}

/// The Salsa20/8 core (RFC 7914 section 3).
///
/// Eight rounds — four double rounds — over sixteen little-endian words, added
/// word-wise to the input. Not Salsa20 the cipher: there is no key, no nonce
/// and no counter, and the result is never used as a keystream. It is the
/// permutation `scryptBlockMix` is defined in terms of, and nothing else here
/// depends on its cryptographic properties.
fn salsa20_8(block: &mut [u8; 64]) {
    #[inline]
    const fn rotl(value: u32, n: u32) -> u32 {
        value.rotate_left(n)
    }

    let mut input = [0u32; 16];
    for (word, chunk) in input.iter_mut().zip(block.chunks_exact(4)) {
        // `chunks_exact(4)` yields exactly four bytes, so the conversion cannot
        // fail; `unwrap_or` keeps that a total function rather than a panic.
        *word = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
    }
    let mut x = input;

    for _ in 0..4 {
        // Column round.
        x[4] ^= rotl(x[0].wrapping_add(x[12]), 7);
        x[8] ^= rotl(x[4].wrapping_add(x[0]), 9);
        x[12] ^= rotl(x[8].wrapping_add(x[4]), 13);
        x[0] ^= rotl(x[12].wrapping_add(x[8]), 18);

        x[9] ^= rotl(x[5].wrapping_add(x[1]), 7);
        x[13] ^= rotl(x[9].wrapping_add(x[5]), 9);
        x[1] ^= rotl(x[13].wrapping_add(x[9]), 13);
        x[5] ^= rotl(x[1].wrapping_add(x[13]), 18);

        x[14] ^= rotl(x[10].wrapping_add(x[6]), 7);
        x[2] ^= rotl(x[14].wrapping_add(x[10]), 9);
        x[6] ^= rotl(x[2].wrapping_add(x[14]), 13);
        x[10] ^= rotl(x[6].wrapping_add(x[2]), 18);

        x[3] ^= rotl(x[15].wrapping_add(x[11]), 7);
        x[7] ^= rotl(x[3].wrapping_add(x[15]), 9);
        x[11] ^= rotl(x[7].wrapping_add(x[3]), 13);
        x[15] ^= rotl(x[11].wrapping_add(x[7]), 18);

        // Row round.
        x[1] ^= rotl(x[0].wrapping_add(x[3]), 7);
        x[2] ^= rotl(x[1].wrapping_add(x[0]), 9);
        x[3] ^= rotl(x[2].wrapping_add(x[1]), 13);
        x[0] ^= rotl(x[3].wrapping_add(x[2]), 18);

        x[6] ^= rotl(x[5].wrapping_add(x[4]), 7);
        x[7] ^= rotl(x[6].wrapping_add(x[5]), 9);
        x[4] ^= rotl(x[7].wrapping_add(x[6]), 13);
        x[5] ^= rotl(x[4].wrapping_add(x[7]), 18);

        x[11] ^= rotl(x[10].wrapping_add(x[9]), 7);
        x[8] ^= rotl(x[11].wrapping_add(x[10]), 9);
        x[9] ^= rotl(x[8].wrapping_add(x[11]), 13);
        x[10] ^= rotl(x[9].wrapping_add(x[8]), 18);

        x[12] ^= rotl(x[15].wrapping_add(x[14]), 7);
        x[13] ^= rotl(x[12].wrapping_add(x[15]), 9);
        x[14] ^= rotl(x[13].wrapping_add(x[12]), 13);
        x[15] ^= rotl(x[14].wrapping_add(x[13]), 18);
    }

    for (i, chunk) in block.chunks_exact_mut(4).enumerate() {
        let value = x
            .get(i)
            .copied()
            .unwrap_or(0)
            .wrapping_add(input.get(i).copied().unwrap_or(0));
        chunk.copy_from_slice(&value.to_le_bytes());
    }
}

/// `scryptBlockMix` (RFC 7914 section 4), in place over `2 * r` 64-byte blocks.
///
/// The shuffle at the end — even-indexed outputs first, then odd — is not
/// decoration. Without it the function is a plain chain and the `ROMix` access
/// pattern below stops depending on the whole of `V`, which is where the
/// memory-hardness comes from.
#[allow(
    clippy::integer_division,
    reason = "RFC 7914 section 4 defines the output shuffle as Y[i/2] with \
              truncating integer division; `i` is a block index and the \
              truncation is the specification, not a rounding choice"
)]
fn block_mix(input: &[u8], output: &mut [u8], r: usize) {
    let blocks = r.saturating_mul(2);
    let mut x = [0u8; 64];
    // X = B[2r - 1]
    if let Some(last) = input.get(blocks.saturating_sub(1).saturating_mul(64)..) {
        if let Some(chunk) = last.get(..64) {
            x.copy_from_slice(chunk);
        }
    }

    for i in 0..blocks {
        if let Some(bi) = input.get(i.saturating_mul(64)..) {
            if let Some(bi) = bi.get(..64) {
                for (a, b) in x.iter_mut().zip(bi.iter()) {
                    *a ^= *b;
                }
            }
        }
        salsa20_8(&mut x);

        // Even i to the first half, odd i to the second.
        let position = if i % 2 == 0 {
            i / 2
        } else {
            r.saturating_add(i / 2)
        };
        if let Some(slot) = output.get_mut(position.saturating_mul(64)..) {
            if let Some(slot) = slot.get_mut(..64) {
                slot.copy_from_slice(&x);
            }
        }
    }
}

/// `scryptROMix` (RFC 7914 section 5), in place over one `128 * r`-byte block.
///
/// The second loop's index comes from the block being mixed, so which of the
/// `N` stored blocks is read next is not known until the previous step
/// finishes. That is what makes storing all of `V` cheaper than recomputing it,
/// and it is the reason the function costs memory rather than only time.
fn ro_mix(block: &mut [u8], n: usize, r: usize, v: &mut [u8], scratch: &mut [u8]) {
    let block_len = r.saturating_mul(128);

    for i in 0..n {
        if let Some(slot) = v.get_mut(i.saturating_mul(block_len)..) {
            if let Some(slot) = slot.get_mut(..block_len) {
                slot.copy_from_slice(block);
            }
        }
        block_mix(block, scratch, r);
        copy_back(block, scratch, block_len);
    }

    for _ in 0..n {
        // Integerify(X): the first 8 bytes of the last 64-byte block, little
        // endian, taken modulo N. N is a power of two, so this is a mask.
        let offset = block_len.saturating_sub(64);
        let mut index_bytes = [0u8; 8];
        if let Some(tail) = block.get(offset..) {
            if let Some(tail) = tail.get(..8) {
                index_bytes.copy_from_slice(tail);
            }
        }
        let j = usize::try_from(u64::from_le_bytes(index_bytes)).unwrap_or(0) & n.saturating_sub(1);

        if let Some(stored) = v.get(j.saturating_mul(block_len)..) {
            if let Some(stored) = stored.get(..block_len) {
                for (a, b) in block.iter_mut().zip(stored.iter()) {
                    *a ^= *b;
                }
            }
        }
        block_mix(block, scratch, r);
        copy_back(block, scratch, block_len);
    }
}

/// Copy `scratch[..block_len]` over `block`, if the lengths agree.
///
/// A helper rather than an inline `copy_from_slice` because the fallback has to
/// be "leave `block` alone", and expressing that inline needs a borrow of
/// `block` that outlives the assignment to it.
fn copy_back(block: &mut [u8], scratch: &[u8], block_len: usize) {
    if let Some(source) = scratch.get(..block_len) {
        if source.len() == block.len() {
            block.copy_from_slice(source);
        }
    }
}

/// Derive `output.len()` bytes with scrypt (RFC 7914 section 6).
///
/// # Errors
///
/// [`ScryptError`] if the parameters are not a valid scrypt parameter set, or
/// if they ask for more memory than [`MAX_MEMORY_BYTES`].
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    output: &mut [u8],
) -> Result<(), ScryptError> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
        return Err(ScryptError::Parameters);
    }

    // Checked before anything is allocated, and in `u64` so the multiplication
    // cannot wrap on a 32-bit target and pass a bound it exceeds.
    let working = 128u64
        .checked_mul(n)
        .and_then(|v| v.checked_mul(u64::from(r)))
        .ok_or(ScryptError::TooMuchMemory)?;
    let per_lane = 128u64
        .checked_mul(u64::from(r))
        .and_then(|v| v.checked_mul(u64::from(p)))
        .ok_or(ScryptError::TooMuchMemory)?;
    if working > MAX_MEMORY_BYTES || per_lane > MAX_MEMORY_BYTES {
        return Err(ScryptError::TooMuchMemory);
    }
    let working = usize::try_from(working).map_err(|_| ScryptError::TooMuchMemory)?;
    let per_lane = usize::try_from(per_lane).map_err(|_| ScryptError::TooMuchMemory)?;
    let n = usize::try_from(n).map_err(|_| ScryptError::TooMuchMemory)?;
    let r = usize::try_from(r).map_err(|_| ScryptError::TooMuchMemory)?;
    let block_len = r.saturating_mul(128);

    // B = PBKDF2(P, S, 1, p * 128 * r)
    let mut b = vec![0u8; per_lane];
    pbkdf2::derive_into(password, salt, 1, &mut b);

    let mut v = vec![0u8; working];
    let mut scratch = vec![0u8; block_len];
    for lane in b.chunks_exact_mut(block_len) {
        ro_mix(lane, n, r, &mut v, &mut scratch);
    }

    // DK = PBKDF2(P, B, 1, dkLen)
    pbkdf2::derive_into(password, &b, 1, output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7914 section 12's published vectors, which are the whole reason this
    /// function is admissible in this crate at all.
    ///
    /// They validate the entire construction transitively: a wrong rotation in
    /// Salsa20/8, a missed shuffle in `scryptBlockMix`, a big-endian
    /// `Integerify`, or a zero-based PBKDF2 block counter each produce a
    /// self-consistent function that agrees with no other implementation, and
    /// each fails here.
    fn vector(password: &str, salt: &str, n: u64, r: u32, p: u32, expected: &str) {
        let want = crate::hex::decode(expected.replace([' ', '\n'], "").as_bytes(), 256)
            .expect("vector hex");
        let mut got = vec![0u8; want.len()];
        scrypt(password.as_bytes(), salt.as_bytes(), n, r, p, &mut got).expect("derive");
        assert_eq!(
            crate::hex::encode(&got),
            crate::hex::encode(&want),
            "scrypt(P={password:?}, S={salt:?}, N={n}, r={r}, p={p})"
        );
    }

    #[test]
    fn rfc_7914_vector_one() {
        vector(
            "",
            "",
            16,
            1,
            1,
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        );
    }

    #[test]
    fn rfc_7914_vector_two() {
        vector(
            "password",
            "NaCl",
            1024,
            8,
            16,
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        );
    }

    #[test]
    fn rfc_7914_vector_three() {
        // N = 16384, r = 8: 16 MiB and the slowest of the three. Still well
        // inside an ordinary test run, and it is the vector closest to the
        // parameters the router actually uses.
        vector(
            "pleaseletmein",
            "SodiumChloride",
            16384,
            8,
            1,
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
             d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
        );
    }

    #[test]
    fn parameters_that_are_not_a_parameter_set_are_refused() {
        let mut out = [0u8; 32];
        // N must be a power of two above one: `Integerify mod N` is implemented
        // as a mask, which is only correct for a power of two.
        for (n, r, p) in [(0u64, 8u32, 1u32), (1, 8, 1), (3, 8, 1), (1024, 0, 1), (1024, 8, 0)] {
            assert_eq!(
                scrypt(b"p", b"s", n, r, p, &mut out),
                Err(ScryptError::Parameters),
                "N={n} r={r} p={p}"
            );
        }
    }

    #[test]
    fn parameters_beyond_the_memory_bound_are_refused_rather_than_allocated() {
        // A verifier is parsed from a configuration file. `ln=30` in one must
        // be a configuration error, not a gigabyte of allocation on the
        // unauthenticated sign-in path.
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt(b"p", b"s", 1 << 30, 8, 1, &mut out),
            Err(ScryptError::TooMuchMemory)
        );
        assert_eq!(
            scrypt(b"p", b"s", 1024, 8, 1 << 20, &mut out),
            Err(ScryptError::TooMuchMemory)
        );
    }

    #[test]
    fn the_defaults_stay_inside_the_memory_bound() {
        // A guard on the constants themselves: raising `DEFAULT_LOG_N` past the
        // bound would make every sign-in fail, and it would fail at runtime on
        // the endpoint rather than here.
        let working = 128u64 * (1u64 << DEFAULT_LOG_N) * u64::from(DEFAULT_R);
        assert!(
            working <= MAX_MEMORY_BYTES,
            "the default parameters ask for {working} bytes"
        );
    }
}
