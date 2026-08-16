//! Cryptographically secure randomness from the operating system.
//!
//! Specification 9.1 requires `state`, `nonce`, and the PKCE verifier to come
//! from a cryptographically secure OS random source. There is deliberately no
//! user-space PRNG here: a seeded generator would need its own review, and a
//! silent fallback to a weak source is exactly the failure mode that makes
//! session fixation possible.
//!
//! On failure the API returns an error and the caller fails closed.

use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Error returned when the OS entropy source is unavailable.
#[derive(Debug)]
pub struct RandomError {
    detail: &'static str,
}

impl core::fmt::Display for RandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "operating system entropy source unavailable: {}", self.detail)
    }
}

impl std::error::Error for RandomError {}

/// The entropy source path. `/dev/urandom` is the correct choice on Linux: it
/// is non-blocking after initial seeding and is what `getrandom(2)` returns
/// without `GRND_RANDOM`. Reading `getrandom` directly would require `unsafe`
/// FFI, which is forbidden in this workspace.
const SOURCE: &str = "/dev/urandom";

/// The router keeps one open handle rather than reopening per call: opening a
/// file per token generation is both slow and a file-descriptor-exhaustion
/// amplifier under load.
static HANDLE: OnceLock<Mutex<File>> = OnceLock::new();

fn handle() -> Result<&'static Mutex<File>, RandomError> {
    if let Some(h) = HANDLE.get() {
        return Ok(h);
    }
    let f = File::open(SOURCE).map_err(|_| RandomError {
        detail: "cannot open /dev/urandom",
    })?;
    // A race here means two handles are opened and one is dropped: harmless.
    let _ = HANDLE.set(Mutex::new(f));
    HANDLE.get().ok_or(RandomError {
        detail: "entropy handle unavailable",
    })
}

/// Fill `dest` with random bytes, or fail.
pub fn fill(dest: &mut [u8]) -> Result<(), RandomError> {
    if dest.is_empty() {
        return Ok(());
    }
    let h = handle()?;
    let mut guard = h.lock().map_err(|_| RandomError {
        detail: "entropy handle poisoned",
    })?;
    guard.read_exact(dest).map_err(|_| RandomError {
        detail: "short read from entropy source",
    })
}

/// Produce a random array of `N` bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Produce a 128-bit value, used for request identifiers (specification 5.1).
pub fn u128_value() -> Result<u128, RandomError> {
    Ok(u128::from_be_bytes(bytes::<16>()?))
}

/// Produce a 64-bit value.
pub fn u64_value() -> Result<u64, RandomError> {
    Ok(u64::from_be_bytes(bytes::<8>()?))
}

/// Produce a 256-bit secret, the router's standard API key and session strength.
pub fn secret_256() -> Result<[u8; 32], RandomError> {
    bytes::<32>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn fills_and_varies() {
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let b = secret_256().expect("entropy source must be available in tests");
            assert!(seen.insert(b), "repeated 256-bit value from OS entropy");
        }
    }

    #[test]
    fn empty_is_ok() {
        let mut empty: [u8; 0] = [];
        fill(&mut empty).expect("empty fill succeeds");
    }

    #[test]
    fn not_all_zero() {
        // A source stuck at zero is the failure this catches. 32 bytes of zero
        // has probability 2^-256; a failure here means the source is broken.
        let b = bytes::<32>().expect("entropy");
        assert!(b.iter().any(|x| *x != 0));
    }

    #[test]
    fn distinct_widths() {
        let a = u128_value().expect("entropy");
        let b = u128_value().expect("entropy");
        assert_ne!(a, b);
        let c = u64_value().expect("entropy");
        let d = u64_value().expect("entropy");
        assert_ne!(c, d);
    }
}
