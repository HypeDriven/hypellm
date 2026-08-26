//! The router's real client against the reference verifier's real process.
//!
//! Everything else in this repository tests one side of that boundary against a
//! stand-in. `tests/fuzz.rs` drives `VerifierClient` against a socket this
//! crate scripts; `verifier/hypellm-verifier --selftest` drives the verifier's
//! JOSE logic in-process. Neither proves the two agree on the wire, and a
//! framing disagreement between them is invisible until a sign-in fails in
//! production.
//!
//! # Why these are `#[ignore]`d
//!
//! Standing the verifier up means running a process, and specification 4.1
//! forbids the router from doing that — `depscan`'s `forbidden-api` rule fails
//! the build on `process::Command`, and a test crate that worked around it
//! would be arguing against the rule it exists to enforce. So the process is
//! started by `verifier/acceptance`, which then runs these tests with the
//! socket path in the environment. They are skipped by a plain
//! `cargo test --workspace`, which stays hermetic and needs neither Python,
//! OpenSSL, nor a listening socket.
//!
//! Run them with:
//!
//! ```text
//! just verifier-acceptance      # or: verifier/acceptance
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_auth::oidc::TokenVerifier;
use hypellm_net::VerifierClient;
use std::time::Duration;

/// The harness's contribution, or a message that says how to get one.
fn from_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is not set. These tests need a running verifier; start one with \
             `just verifier-acceptance`, which sets it."
        )
    })
}

fn client() -> VerifierClient {
    // Generous, because the verifier fetches a key set over TLS on the first
    // request. A short timeout here would make a cold start look like a
    // protocol failure.
    VerifierClient::new(from_environment("HYPELLM_VERIFIER_SOCKET"), Duration::from_secs(20))
}

#[test]
#[ignore = "needs a running verifier; started by verifier/acceptance"]
fn a_signed_token_verifies_and_arrives_intact() {
    let claims = client()
        .verify(&from_environment("HYPELLM_VERIFIER_TOKEN"))
        .expect("the verifier should accept a token it published the key for");

    // Field by field, because the failure this test exists to catch is a
    // *partial* agreement: a frame that parses, an identity that is subtly not
    // the one the token carried.
    assert_eq!(claims.iss, from_environment("HYPELLM_VERIFIER_EXPECT_ISS"));
    assert_eq!(claims.sub, from_environment("HYPELLM_VERIFIER_EXPECT_SUB"));
    assert_eq!(
        claims.aud,
        vec![from_environment("HYPELLM_VERIFIER_EXPECT_AUD")]
    );
    assert_eq!(
        claims.email.as_deref(),
        Some(from_environment("HYPELLM_VERIFIER_EXPECT_EMAIL").as_str())
    );
    assert!(
        claims.email_verified,
        "the token asserts a verified email and the claim did not survive"
    );
    assert_eq!(claims.hd.as_deref(), Some("example.com"));
    assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));

    // `exp` and `iat` default to 0 when they do not arrive as numbers, and 0 is
    // what `validate_claims` reads as expired. A round trip that silently
    // dropped them would fail every sign-in for a reason nothing reports.
    assert!(claims.exp > claims.iat, "exp and iat did not survive as numbers");
}

#[test]
#[ignore = "needs a running verifier; started by verifier/acceptance"]
fn a_tampered_token_is_refused_as_a_bad_signature() {
    // Not merely "is_err": the router maps a helper refusal to
    // `SignatureInvalid` and anything else to `VerifierUnavailable`, and those
    // two go to different places — one is a failed sign-in, the other is an
    // outage someone should be paged for. A verifier that closed the connection
    // instead of answering `ERR` would look like an outage on every forged
    // token.
    let error = client()
        .verify(&from_environment("HYPELLM_VERIFIER_TAMPERED"))
        .expect_err("a tampered token must not verify");
    assert_eq!(
        error,
        hypellm_auth::oidc::OidcError::SignatureInvalid,
        "a refusal was reported as something other than a bad signature"
    );
}

#[test]
#[ignore = "needs a running verifier; started by verifier/acceptance"]
fn a_token_signed_by_an_unpublished_key_is_refused() {
    let error = client()
        .verify(&from_environment("HYPELLM_VERIFIER_UNKNOWN_KID"))
        .expect_err("a token whose kid the issuer does not publish must not verify");
    assert_eq!(error, hypellm_auth::oidc::OidcError::SignatureInvalid);
}
