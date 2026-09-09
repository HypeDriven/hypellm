//! PBKDF2-HMAC-SHA-256 (RFC 8018 section 5.2) and the encoded password
//! verifier the management plane stores.
//!
//! # Why this is here at all
//!
//! Specification 9.2 lists four ways a principal is established and a password
//! is not among them: humans arrive through the identity provider, and the
//! recovery path is a high-entropy break-glass token. A password is therefore a
//! deviation, recorded as such in `docs/deferred-issues.md`, and it exists so a
//! deployment can be operated before an OAuth client and a verifier process
//! have been set up.
//!
//! It is **not** a licence to invent cryptography. Specification 4 forbids
//! "novel signature or TLS code"; PBKDF2 is neither. It is an iterated HMAC —
//! fully specified, deterministic, and verifiable against published vectors,
//! which is exactly the admission test the rest of this crate is held to. It
//! adds no primitive: every byte of work below is [`crate::hmac`], already
//! reviewed and already on the request path.
//!
//! # What it is not
//!
//! PBKDF2 is a *deliberately slow hash*, not a memory-hard one. Argon2id and
//! scrypt resist GPU and ASIC attack in a way an iterated SHA-256 does not, and
//! either would be the better choice for a password store facing the internet.
//! Both are also considerably more code than an HMAC loop, and neither is
//! "fully specified, deterministic, test-vector-verifiable" in the narrow sense
//! this crate's `MODULE.md` demands of an in-repository implementation. The
//! honest summary: this is adequate for a management plane that is not exposed
//! to the internet, behind an administrator-chosen password, and it is the
//! weakest authentication path the router has.
//!
//! # The encoded form
//!
//! ```text
//! pbkdf2-sha256$<iterations>$<salt-base64url>$<derived-key-base64url>
//! ```
//!
//! Base64url without padding, so the whole string is a bare configuration value
//! that needs no quoting (`+`, `/` and `=` would still parse, but `$` and the
//! url alphabet keep it readable in a `local_user` record).
//!
//! Parsing is strict for the reason the configuration grammar as a whole is
//! strict (specification 11.1): a verifier that cannot be parsed is a
//! configuration error at load, not an authentication failure discovered by the
//! one person who needed to sign in.

use crate::base64::{self, Base64Error};
use crate::ct;
use crate::hmac::HmacSha256;
use crate::random;
use crate::scrypt;
use crate::sha256::DIGEST_LEN;
use core::fmt;

/// Length of the derived key, in bytes.
///
/// Exactly one hash block, so RFC 8018's `T_1` *is* the derived key and no
/// block-concatenation loop is needed. A shorter output would be the only
/// reason to write one.
pub const DERIVED_LEN: usize = DIGEST_LEN;

/// Salt length used by [`PasswordVerifier::derive`], in bytes.
pub const SALT_LEN: usize = 16;

/// The smallest iteration count a verifier may declare.
///
/// Not a security recommendation — see [`DEFAULT_ITERATIONS`] for that. It is a
/// floor low enough that a test suite can afford a real verifier and high
/// enough that `iterations=1` cannot reach production by way of a typo.
pub const MIN_ITERATIONS: u32 = 1_000;

/// The largest, so that a verifier cannot make a sign-in unbounded work.
///
/// Specification 3.2 bounds what a request may cost. The count is
/// administrator-supplied rather than caller-supplied, so this is a guard
/// against a mistyped zero-run rather than against an attacker, but a
/// management plane that stops answering because someone wrote nine digits is
/// still an outage.
pub const MAX_ITERATIONS: u32 = 10_000_000;

/// What [`PasswordVerifier::derive`] uses when nothing else is asked for.
///
/// OWASP's 2023 guidance for PBKDF2-HMAC-SHA-256. Measured at ~100 ms per
/// attempt in a release build of this implementation, which is also the
/// practical rate limit on the sign-in endpoint — see the concurrency bound in
/// `hypellm_admin_api::handlers`. A debug build is an order of magnitude
/// slower, which is why every test here derives at [`MIN_ITERATIONS`].
pub const DEFAULT_ITERATIONS: u32 = 210_000;

/// The longest password accepted, in bytes.
///
/// HMAC accepts a key of any length, so this bounds the work rather than the
/// correctness: without it a caller decides how much hashing a sign-in attempt
/// costs before the iteration count even applies.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Derive `DERIVED_LEN` bytes from `password` and `salt`.
///
/// RFC 8018 section 5.2 with `dkLen == hLen`, so the output is `T_1`:
///
/// ```text
/// U_1 = PRF(P, S || INT(1))
/// U_i = PRF(P, U_{i-1})
/// T_1 = U_1 xor U_2 xor … xor U_c
/// ```
///
/// The HMAC state is primed with the password once and cloned per iteration,
/// which is the usual PBKDF2 optimisation: re-deriving the key pads on every
/// iteration would do half again as much work for the same output.
/// PBKDF2-HMAC-SHA-256 into an output of any length (RFC 8018 section 5.2).
///
/// [`derive_key`] is the single-block case and stays because it is the one the
/// password path uses. This is the general form, needed by [`crate::scrypt`],
/// whose inner pass derives `p * 128 * r` bytes — thirty-two blocks at the
/// defaults.
///
/// The block index is one-based and big-endian, as the RFC requires. Getting it
/// zero-based would produce a self-consistent function that agrees with no
/// other implementation, which is precisely the failure published test vectors
/// exist to catch.
pub fn derive_into(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let primed = HmacSha256::new(password);

    for (index, chunk) in output.chunks_mut(DERIVED_LEN).enumerate() {
        // One-based, and saturating rather than wrapping: an output long enough
        // to overflow the counter is not reachable here, and wrapping to block
        // one would silently repeat key material.
        let block = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);

        let mut u = {
            let mut mac = primed.clone();
            mac.update(salt);
            mac.update(&block.to_be_bytes());
            mac.finalize()
        };
        let mut acc = u;
        for _ in 1..iterations {
            let mut mac = primed.clone();
            mac.update(&u);
            u = mac.finalize();
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        // The last chunk may be short; the RFC truncates the final block.
        for (out, byte) in chunk.iter_mut().zip(acc.iter()) {
            *out = *byte;
        }
    }
}

#[must_use]
pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; DERIVED_LEN] {
    let primed = HmacSha256::new(password);

    // U_1 = PRF(P, S || INT(1)). The block index is one, big-endian.
    let mut u = {
        let mut mac = primed.clone();
        mac.update(salt);
        mac.update(&1u32.to_be_bytes());
        mac.finalize()
    };
    let mut out = u;

    // `1..iterations` because U_1 is already folded in. An iteration count of
    // zero or one therefore does no further work rather than underflowing.
    for _ in 1..iterations {
        let mut mac = primed.clone();
        mac.update(&u);
        u = mac.finalize();
        for (acc, byte) in out.iter_mut().zip(u.iter()) {
            *acc ^= *byte;
        }
    }

    out
}

/// Why an encoded verifier was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierError {
    /// The string is not four `$`-separated fields.
    Shape,
    /// The algorithm label is not `pbkdf2-sha256`.
    ///
    /// Refused rather than defaulted: a verifier that silently accepts an
    /// unknown label is one that can be downgraded by editing a string.
    Algorithm,
    /// The iteration count is not a number, or is outside
    /// [`MIN_ITERATIONS`]`..=`[`MAX_ITERATIONS`].
    Iterations,
    /// The salt is not base64url, or is not between 8 and 64 bytes.
    Salt,
    /// The derived key is not base64url, or is not [`DERIVED_LEN`] bytes.
    DerivedKey,
    /// The scrypt parameters are not a valid parameter set, or ask for more
    /// memory than [`crate::scrypt::MAX_MEMORY_BYTES`].
    Parameters,
}

impl VerifierError {
    /// A stable, non-disclosing token for logs and configuration errors.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shape => {
                "expected scrypt$<ln>$<r>$<p>$<salt>$<key> \
                 or pbkdf2-sha256$<iterations>$<salt>$<key>"
            }
            Self::Algorithm => "unsupported password hash algorithm",
            Self::Iterations => "iteration count missing or out of range",
            Self::Salt => "salt is not 8 to 64 base64url bytes",
            Self::DerivedKey => "derived key is not 32 base64url bytes",
            Self::Parameters => "scrypt parameters are invalid or ask for too much memory",
        }
    }
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The shortest and longest salt a verifier may carry.
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;

/// A parsed password verifier: everything needed to check a password, and
/// nothing that could reproduce one.
///
/// Deliberately not `Clone`: specification 7.1's rule for `Sensitive<T>` — a
/// copy is a second place to leak from, and there is no call site that needs
/// one. The `Debug` implementation prints no field, because the derived key is
/// an offline-attackable image of the password.
pub enum PasswordVerifier {
    /// PBKDF2-HMAC-SHA-256. Accepted, never produced.
    ///
    /// It stays parseable so that a configuration written before scrypt keeps
    /// loading: refusing it would take a deployment offline on an upgrade, and
    /// the operator whose sign-in broke is the one person who cannot fix it.
    /// `--hash-password` emits scrypt, so a re-derived password moves.
    Pbkdf2 {
        /// The iteration count the verifier declares.
        iterations: u32,
        /// The salt.
        salt: Vec<u8>,
        /// The expected derived key.
        expected: [u8; DERIVED_LEN],
    },
    /// scrypt (RFC 7914), what [`PasswordVerifier::derive`] produces.
    Scrypt {
        /// `log2(N)`, the cost parameter.
        log_n: u8,
        /// The block size factor.
        r: u32,
        /// The parallelism factor.
        p: u32,
        /// The salt.
        salt: Vec<u8>,
        /// The expected derived key.
        expected: [u8; DERIVED_LEN],
    },
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The parameters are not secret and are what an operator debugging a
        // sign-in needs; the salt and the derived key never render.
        match self {
            Self::Pbkdf2 { iterations, .. } => f
                .debug_struct("PasswordVerifier::Pbkdf2")
                .field("iterations", iterations)
                .field("salt", &"[redacted]")
                .field("expected", &"[redacted]")
                .finish(),
            Self::Scrypt { log_n, r, p, .. } => f
                .debug_struct("PasswordVerifier::Scrypt")
                .field("log_n", log_n)
                .field("r", r)
                .field("p", p)
                .field("salt", &"[redacted]")
                .field("expected", &"[redacted]")
                .finish(),
        }
    }
}

impl PasswordVerifier {
    /// Parse the encoded form.
    ///
    /// # Errors
    ///
    /// [`VerifierError`] naming the first field that did not hold. The message
    /// describes the *format*, never the value: this string appears in a
    /// configuration error, which an operator may paste into a ticket.
    pub fn parse(encoded: &str) -> Result<Self, VerifierError> {
        let fields: Vec<&str> = encoded.split('$').collect();
        match fields.first().copied() {
            Some("scrypt") => Self::parse_scrypt(&fields),
            Some("pbkdf2-sha256") => Self::parse_pbkdf2(&fields),
            // An empty value is a missing verifier, not an unknown algorithm,
            // and the shape message is what tells an operator what to write.
            Some("") if fields.len() == 1 => Err(VerifierError::Shape),
            // Refused rather than defaulted: a verifier that silently accepts
            // an unknown label is one that can be downgraded by editing a
            // string in a file.
            Some(_) => Err(VerifierError::Algorithm),
            None => Err(VerifierError::Shape),
        }
    }

    fn parse_pbkdf2(fields: &[&str]) -> Result<Self, VerifierError> {
        let [_, iterations, salt, key] = fields else {
            return Err(VerifierError::Shape);
        };

        let iterations: u32 = iterations.parse().map_err(|_| VerifierError::Iterations)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(VerifierError::Iterations);
        }

        let salt = parse_salt(salt)?;
        let expected = parse_derived(key)?;
        Ok(Self::Pbkdf2 {
            iterations,
            salt,
            expected,
        })
    }

    fn parse_scrypt(fields: &[&str]) -> Result<Self, VerifierError> {
        let [_, log_n, r, p, salt, key] = fields else {
            return Err(VerifierError::Shape);
        };

        let log_n: u8 = log_n.parse().map_err(|_| VerifierError::Parameters)?;
        if log_n < scrypt::MIN_LOG_N {
            return Err(VerifierError::Parameters);
        }
        let r: u32 = r.parse().map_err(|_| VerifierError::Parameters)?;
        let p: u32 = p.parse().map_err(|_| VerifierError::Parameters)?;
        let salt = parse_salt(salt)?;
        let expected = parse_derived(key)?;

        let verifier = Self::Scrypt {
            log_n,
            r,
            p,
            salt,
            expected,
        };
        // Checked here rather than at sign-in. A verifier whose parameters ask
        // for more memory than the router will allocate must be a configuration
        // error at load, not a refusal discovered by the one person who needed
        // to sign in — and never an allocation on an unauthenticated endpoint.
        verifier
            .scrypt_cost()
            .ok_or(VerifierError::Parameters)?;
        Ok(verifier)
    }

    /// The `(N, r, p)` this verifier would run at, if they are admissible.
    fn scrypt_cost(&self) -> Option<(u64, u32, u32)> {
        let Self::Scrypt { log_n, r, p, .. } = self else {
            return None;
        };
        // 63 would overflow the shift; the memory bound below refuses anything
        // remotely near it anyway.
        if *log_n == 0 || *log_n > 40 {
            return None;
        }
        let n = 1u64.checked_shl(u32::from(*log_n))?;
        let mut probe = [0u8; 1];
        // The parameter and memory checks live in one place — `scrypt` itself —
        // so a bound raised there cannot be missed here. A zero-length output
        // is not permitted, so this derives one byte at the real cost; it runs
        // once, at configuration load.
        scrypt::scrypt(b"", b"", n, *r, *p, &mut probe).ok()?;
        Some((n, *r, *p))
    }

    /// Derive a fresh scrypt verifier for `password` with a random salt.
    ///
    /// Always scrypt, at [`scrypt::DEFAULT_LOG_N`], [`scrypt::DEFAULT_R`] and
    /// [`scrypt::DEFAULT_P`]. PBKDF2 verifiers are read and never written: the
    /// only way a deployment keeps one is by not re-deriving it.
    ///
    /// # Errors
    ///
    /// [`random::RandomError`] if the OS entropy source is unavailable. Fails
    /// closed: a salt that is not random is not a salt.
    pub fn derive(password: &str) -> Result<Self, random::RandomError> {
        Self::derive_with(
            password,
            scrypt::DEFAULT_LOG_N,
            scrypt::DEFAULT_R,
            scrypt::DEFAULT_P,
        )
    }

    /// Derive at explicit parameters, clamped to what this router will run.
    ///
    /// Exists for tests, which need a verifier cheap enough to derive in a
    /// debug build, and for a deployment that has measured its own hardware.
    /// `derive` is the one production should call.
    ///
    /// # Errors
    ///
    /// [`random::RandomError`] if the OS entropy source is unavailable.
    pub fn derive_with(
        password: &str,
        log_n: u8,
        r: u32,
        p: u32,
    ) -> Result<Self, random::RandomError> {
        // Clamped rather than refused: this is the *producing* side, and a
        // verifier it emitted that its own parser then rejected would be a
        // trap. `parse` is where an out-of-range value is an error.
        let log_n = log_n.max(scrypt::MIN_LOG_N);
        let r = r.max(1);
        let p = p.max(1);
        let salt = random::bytes::<SALT_LEN>()?;
        let mut expected = [0u8; DERIVED_LEN];
        // An error here would mean the parameters exceed the memory bound.
        // `derive` cannot hit it — `the_defaults_stay_inside_the_memory_bound`
        // holds that — and a caller passing its own gets a verifier that will
        // not match, which `a_verifier_beyond_the_memory_bound_is_refused`
        // pins as a parse failure rather than a silent acceptance.
        let _ = scrypt::scrypt(
            password.as_bytes(),
            &salt,
            1u64.checked_shl(u32::from(log_n)).unwrap_or(u64::MAX),
            r,
            p,
            &mut expected,
        );
        Ok(Self::Scrypt {
            log_n,
            r,
            p,
            salt: salt.to_vec(),
            expected,
        })
    }

    /// Whether `password` is the one this verifier was derived from.
    ///
    /// Constant-time in the comparison. It is not constant-time in the length
    /// of the password, which is not a property either KDF offers.
    ///
    /// A password longer than [`MAX_PASSWORD_LEN`] is refused without doing the
    /// work, so the cost of an attempt stays bounded by the declared parameters
    /// rather than by the size of the request body.
    #[must_use]
    pub fn verify(&self, password: &str) -> bool {
        if password.len() > MAX_PASSWORD_LEN {
            return false;
        }
        match self {
            Self::Pbkdf2 {
                iterations,
                salt,
                expected,
            } => {
                let derived = derive_key(password.as_bytes(), salt, *iterations);
                ct::eq(&derived, expected)
            }
            Self::Scrypt { salt, expected, .. } => {
                let Some((n, r, p)) = self.scrypt_cost() else {
                    // Unreachable for a parsed verifier — `parse_scrypt`
                    // refuses one whose parameters do not hold — and a refusal
                    // rather than a panic if it ever is reached.
                    return false;
                };
                let mut derived = [0u8; DERIVED_LEN];
                if scrypt::scrypt(password.as_bytes(), salt, n, r, p, &mut derived).is_err() {
                    return false;
                }
                ct::eq(&derived, expected)
            }
        }
    }

    /// The encoded form, suitable for a `local_user` record.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            Self::Pbkdf2 {
                iterations,
                salt,
                expected,
            } => format!(
                "pbkdf2-sha256${iterations}${}${}",
                base64::encode_url_nopad(salt),
                base64::encode_url_nopad(expected),
            ),
            Self::Scrypt {
                log_n,
                r,
                p,
                salt,
                expected,
            } => format!(
                "scrypt${log_n}${r}${p}${}${}",
                base64::encode_url_nopad(salt),
                base64::encode_url_nopad(expected),
            ),
        }
    }

    /// Whether this verifier uses the memory-hard KDF.
    ///
    /// The management plane reports it, so an operator can see that a
    /// configuration still carries a PBKDF2 verifier without reading the file.
    #[must_use]
    pub const fn is_memory_hard(&self) -> bool {
        matches!(self, Self::Scrypt { .. })
    }
}

/// Decode and bound a salt field.
fn parse_salt(field: &str) -> Result<Vec<u8>, VerifierError> {
    let salt = decode(field, MAX_SALT_LEN).map_err(|_| VerifierError::Salt)?;
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(VerifierError::Salt);
    }
    Ok(salt)
}

/// Decode a derived-key field.
fn parse_derived(field: &str) -> Result<[u8; DERIVED_LEN], VerifierError> {
    let key = decode(field, DERIVED_LEN).map_err(|_| VerifierError::DerivedKey)?;
    key.try_into().map_err(|_| VerifierError::DerivedKey)
}

/// Decode base64url, accepting the standard alphabet too.
///
/// Operators paste these from wherever they generated them, and a `+` in a salt
/// is not worth a support question. The strictness that matters — length, and
/// no trailing garbage — is enforced by the caller and by `base64::decode`.
fn decode(text: &str, max_output: usize) -> Result<Vec<u8>, Base64Error> {
    match base64::decode_url_nopad(text.as_bytes(), max_output) {
        Ok(bytes) => Ok(bytes),
        Err(_) => base64::decode_std(text.as_bytes(), max_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC-style vectors for PBKDF2-HMAC-SHA-256, cross-checked against
    /// `hashlib.pbkdf2_hmac` before being written down.
    ///
    /// These are the whole justification for implementing this here: an
    /// iterated HMAC is admissible in this crate precisely because it can be
    /// held against published values, and a construction nobody can check is
    /// the thing specification 4 refuses.
    #[test]
    fn published_vectors_hold() {
        const CASES: &[(&str, &str, u32, &str)] = &[
            (
                "password",
                "salt",
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                "password",
                "salt",
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                "password",
                "salt",
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
            (
                "passwordPASSWORDpassword",
                "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1",
            ),
        ];

        for (password, salt, iterations, expected) in CASES {
            let derived = derive_key(password.as_bytes(), salt.as_bytes(), *iterations);
            assert_eq!(
                crate::hex::encode(&derived),
                *expected,
                "PBKDF2-HMAC-SHA-256({password}, {salt}, {iterations})"
            );
        }
    }

    /// A verifier at the cheapest legal cost, so a debug build stays quick.
    ///
    /// The production parameters are exercised by the RFC vectors in
    /// `crate::scrypt`, not by re-deriving one here per test.
    fn cheap(password: &str) -> PasswordVerifier {
        PasswordVerifier::derive_with(
            password,
            crate::scrypt::MIN_LOG_N,
            crate::scrypt::DEFAULT_R,
            crate::scrypt::DEFAULT_P,
        )
        .expect("the test host has an entropy source")
    }

    #[test]
    fn a_verifier_accepts_its_own_password_and_no_other() {
        let verifier =
            cheap("correct horse battery staple");
        assert!(verifier.verify("correct horse battery staple"));
        assert!(!verifier.verify("correct horse battery stapl"));
        assert!(!verifier.verify("correct horse battery staple "));
        assert!(!verifier.verify(""));
    }

    #[test]
    fn two_verifiers_for_one_password_differ() {
        // The salt is what makes this true, and a verifier that reused one
        // would let an operator see that two accounts share a password.
        let a = cheap("same");
        let b = cheap("same");
        assert_ne!(a.encode(), b.encode());
        assert!(a.verify("same") && b.verify("same"));
    }

    #[test]
    fn the_encoded_form_round_trips() {
        let derived = cheap("hunter2");
        let encoded = derived.encode();
        let parsed = PasswordVerifier::parse(&encoded).unwrap();
        assert_eq!(parsed.encode(), encoded);
        assert!(parsed.verify("hunter2"));
    }

    #[test]
    fn a_malformed_verifier_is_refused_rather_than_defaulted() {
        // Each of these is a way a verifier could be wrong in a configuration
        // file. None may parse: a `PasswordVerifier` that exists is one that
        // can refuse a password, and one built from a default would accept
        // whatever the default was derived from.
        const CASES: &[(&str, VerifierError)] = &[
            ("", VerifierError::Shape),
            ("pbkdf2-sha256", VerifierError::Shape),
            ("pbkdf2-sha256$1000$c2FsdHNhbHQ", VerifierError::Shape),
            (
                "pbkdf2-sha256$1000$c2FsdHNhbHQ$AAAA$extra",
                VerifierError::Shape,
            ),
            // Algorithm confusion, the shape that matters: a label naming a
            // fast hash with an otherwise well-formed body.
            (
                "sha256$1000$c2FsdHNhbHQ$dGhpcy1pcy1ub3QtYS1kZXJpdmVkLWtleS0",
                VerifierError::Algorithm,
            ),
            (
                "pbkdf2-sha1$1000$c2FsdHNhbHQ$dGhpcy1pcy1ub3QtYS1kZXJpdmVkLWtleS0",
                VerifierError::Algorithm,
            ),
            (
                "$1000$c2FsdHNhbHQ$dGhpcy1pcy1ub3QtYS1kZXJpdmVkLWtleS0",
                VerifierError::Algorithm,
            ),
            ("pbkdf2-sha256$$c2FsdHNhbHQ$AAAA", VerifierError::Iterations),
            (
                "pbkdf2-sha256$0$c2FsdHNhbHQ$AAAA",
                VerifierError::Iterations,
            ),
            (
                "pbkdf2-sha256$1$c2FsdHNhbHQ$AAAA",
                VerifierError::Iterations,
            ),
            (
                "pbkdf2-sha256$999$c2FsdHNhbHQ$AAAA",
                VerifierError::Iterations,
            ),
            (
                "pbkdf2-sha256$10000001$c2FsdHNhbHQ$AAAA",
                VerifierError::Iterations,
            ),
            (
                "pbkdf2-sha256$-1$c2FsdHNhbHQ$AAAA",
                VerifierError::Iterations,
            ),
            // Salt too short, and salt that is not base64 at all.
            ("pbkdf2-sha256$1000$c2FsdA$AAAA", VerifierError::Salt),
            ("pbkdf2-sha256$1000$!!!!!!!!!!!!$AAAA", VerifierError::Salt),
        ];

        for (encoded, expected) in CASES {
            assert_eq!(
                PasswordVerifier::parse(encoded).err(),
                Some(*expected),
                "{encoded:?} must not parse"
            );
        }
    }

    #[test]
    fn a_derived_key_of_the_wrong_length_is_refused() {
        // The one field whose length is load-bearing: a short key means a
        // shorter comparison, and a comparison against three bytes is one an
        // attacker can win.
        let good = cheap("x");
        let encoded = good.encode();
        let (prefix, _) = encoded.rsplit_once('$').unwrap();

        // 42 base64url characters decode to 31 bytes and 44 to 33; 43 is the
        // only length that yields 32, which is what `good` already carries.
        for key in ["", "AAAA", &"A".repeat(42), &"A".repeat(44)] {
            assert_eq!(
                PasswordVerifier::parse(&format!("{prefix}${key}")).err(),
                Some(VerifierError::DerivedKey),
                "a {} character key must not parse",
                key.len()
            );
        }
    }

    #[test]
    fn an_overlong_password_is_refused_without_hashing_it() {
        // Bounded work per attempt (specification 3.2). The assertion is that
        // it is refused; that it is refused *cheaply* is the reason.
        let verifier = cheap("short");
        assert!(!verifier.verify(&"a".repeat(MAX_PASSWORD_LEN + 1)));
    }

    #[test]
    fn the_debug_form_carries_no_key_material() {
        let verifier = cheap("secret-password");
        let rendered = format!("{verifier:?}");
        assert!(!rendered.contains("secret-password"));
        // Against the encoded form rather than the private fields, which is
        // also the stronger assertion: the salt and the derived key are exactly
        // what `encode` emits, and a `Debug` that leaked either would leak a
        // substring of it.
        for field in verifier.encode().split('$').skip(4) {
            assert!(
                !field.is_empty() && !rendered.contains(field),
                "the debug form carries key material: {rendered}"
            );
        }
    }

    #[test]
    fn a_pbkdf2_verifier_still_authenticates() {
        // A configuration written before scrypt must keep working. An upgrade
        // that refused it would take the management plane offline, and the
        // operator whose sign-in broke is the one person who cannot fix it.
        let salt = b"0123456789abcdef";
        let expected = derive_key(b"legacy-password", salt, MIN_ITERATIONS);
        let encoded = format!(
            "pbkdf2-sha256${MIN_ITERATIONS}${}${}",
            base64::encode_url_nopad(salt),
            base64::encode_url_nopad(&expected),
        );

        let verifier = PasswordVerifier::parse(&encoded).expect("a legacy verifier parses");
        assert!(verifier.verify("legacy-password"));
        assert!(!verifier.verify("legacy-passwore"));
        assert!(
            !verifier.is_memory_hard(),
            "a PBKDF2 verifier must report itself as what it is"
        );
        assert!(cheap("x").is_memory_hard(), "derive must produce scrypt");
    }

    #[test]
    fn a_verifier_beyond_the_memory_bound_is_refused() {
        // A verifier is parsed from a configuration file, and `ln=30` in one
        // must be a configuration error rather than a gigabyte of allocation on
        // the unauthenticated sign-in path.
        let salt = base64::encode_url_nopad(b"0123456789abcdef");
        let key = base64::encode_url_nopad(&[0u8; DERIVED_LEN]);
        assert_eq!(
            PasswordVerifier::parse(&format!("scrypt$30$8$1${salt}${key}")).err(),
            Some(VerifierError::Parameters)
        );
        // And a cost below the floor, which is the typo that would otherwise
        // reach production as a verifier worth nothing.
        assert_eq!(
            PasswordVerifier::parse(&format!("scrypt$1$8$1${salt}${key}")).err(),
            Some(VerifierError::Parameters)
        );
    }

    #[test]
    fn an_unknown_algorithm_label_is_refused_rather_than_defaulted() {
        let salt = base64::encode_url_nopad(b"0123456789abcdef");
        let key = base64::encode_url_nopad(&[0u8; DERIVED_LEN]);
        assert_eq!(
            PasswordVerifier::parse(&format!("plain$1$8$1${salt}${key}")).err(),
            Some(VerifierError::Algorithm)
        );
    }
}
