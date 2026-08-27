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
}

impl VerifierError {
    /// A stable, non-disclosing token for logs and configuration errors.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shape => "expected pbkdf2-sha256$<iterations>$<salt>$<key>",
            Self::Algorithm => "unsupported password hash algorithm",
            Self::Iterations => "iteration count missing or out of range",
            Self::Salt => "salt is not 8 to 64 base64url bytes",
            Self::DerivedKey => "derived key is not 32 base64url bytes",
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
pub struct PasswordVerifier {
    iterations: u32,
    salt: Vec<u8>,
    expected: [u8; DERIVED_LEN],
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordVerifier")
            .field("iterations", &self.iterations)
            .field("salt", &"[redacted]")
            .field("expected", &"[redacted]")
            .finish()
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
        let mut fields = encoded.split('$');
        let (Some(algorithm), Some(iterations), Some(salt), Some(key), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(VerifierError::Shape);
        };

        if algorithm != "pbkdf2-sha256" {
            return Err(VerifierError::Algorithm);
        }

        let iterations: u32 = iterations.parse().map_err(|_| VerifierError::Iterations)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(VerifierError::Iterations);
        }

        let salt = decode(salt, MAX_SALT_LEN).map_err(|_| VerifierError::Salt)?;
        if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
            return Err(VerifierError::Salt);
        }

        let key = decode(key, DERIVED_LEN).map_err(|_| VerifierError::DerivedKey)?;
        let expected: [u8; DERIVED_LEN] =
            key.try_into().map_err(|_| VerifierError::DerivedKey)?;

        Ok(Self {
            iterations,
            salt,
            expected,
        })
    }

    /// Derive a fresh verifier for `password` with a random salt.
    ///
    /// # Errors
    ///
    /// [`random::RandomError`] if the OS entropy source is unavailable. Fails
    /// closed: a salt that is not random is not a salt.
    pub fn derive(password: &str, iterations: u32) -> Result<Self, random::RandomError> {
        let iterations = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
        let salt = random::bytes::<SALT_LEN>()?;
        Ok(Self {
            iterations,
            salt: salt.to_vec(),
            expected: derive_key(password.as_bytes(), &salt, iterations),
        })
    }

    /// Whether `password` is the one this verifier was derived from.
    ///
    /// Constant-time in the comparison. It is not constant-time in the length
    /// of the password, which is not a property PBKDF2 has to offer.
    ///
    /// A password longer than [`MAX_PASSWORD_LEN`] is refused without doing the
    /// work, so the cost of an attempt stays bounded by the iteration count
    /// rather than by the size of the request body.
    #[must_use]
    pub fn verify(&self, password: &str) -> bool {
        if password.len() > MAX_PASSWORD_LEN {
            return false;
        }
        let derived = derive_key(password.as_bytes(), &self.salt, self.iterations);
        ct::eq(&derived, &self.expected)
    }

    /// The encoded form, suitable for a `local_user` record.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "pbkdf2-sha256${}${}${}",
            self.iterations,
            base64::encode_url_nopad(&self.salt),
            base64::encode_url_nopad(&self.expected),
        )
    }

    /// The iteration count this verifier declares.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }
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

    #[test]
    fn a_verifier_accepts_its_own_password_and_no_other() {
        let verifier =
            PasswordVerifier::derive("correct horse battery staple", MIN_ITERATIONS).unwrap();
        assert!(verifier.verify("correct horse battery staple"));
        assert!(!verifier.verify("correct horse battery stapl"));
        assert!(!verifier.verify("correct horse battery staple "));
        assert!(!verifier.verify(""));
    }

    #[test]
    fn two_verifiers_for_one_password_differ() {
        // The salt is what makes this true, and a verifier that reused one
        // would let an operator see that two accounts share a password.
        let a = PasswordVerifier::derive("same", MIN_ITERATIONS).unwrap();
        let b = PasswordVerifier::derive("same", MIN_ITERATIONS).unwrap();
        assert_ne!(a.encode(), b.encode());
        assert!(a.verify("same") && b.verify("same"));
    }

    #[test]
    fn the_encoded_form_round_trips() {
        let derived = PasswordVerifier::derive("hunter2", MIN_ITERATIONS).unwrap();
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
        let good = PasswordVerifier::derive("x", MIN_ITERATIONS).unwrap();
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
        let verifier = PasswordVerifier::derive("short", MIN_ITERATIONS).unwrap();
        assert!(!verifier.verify(&"a".repeat(MAX_PASSWORD_LEN + 1)));
    }

    #[test]
    fn the_debug_form_carries_no_key_material() {
        let verifier = PasswordVerifier::derive("secret-password", MIN_ITERATIONS).unwrap();
        let rendered = format!("{verifier:?}");
        assert!(!rendered.contains("secret-password"));
        assert!(!rendered.contains(&base64::encode_url_nopad(&verifier.salt)));
        assert!(!rendered.contains(&base64::encode_url_nopad(&verifier.expected)));
    }
}
