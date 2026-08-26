//! Seeded, deterministic fuzzing of the identity verifier boundary.
//!
//! There is no `fuzz/` directory and no libFuzzer: specification 4 admits no
//! such dependency. The engine is the shared mutator in
//! `hypellm_test_corpus::fuzz`, driven from ordinary `#[test]` functions so
//! that `cargo test` runs it and a failure is reproducible by seed number.
//!
//! # Why this boundary
//!
//! `verifier/` is a separate process in the trusted computing base, and §9.1
//! puts it there deliberately: the router does not verify signatures. But
//! "trusted" is a statement about what it is *allowed* to assert, not a licence
//! for the router to believe a malformed reply. A verifier that is buggy, mid-
//! upgrade, replaced, or reached over a socket somebody else can also open must
//! not be able to make the router invent an identity — and an identity is the
//! one thing on this path that decides who a caller is.
//!
//! # Each target asserts a property
//!
//! A target that only asserts "does not panic" is close to worthless here.
//!
//! - **`no_claim_is_fabricated`** — every field of a returned
//!   `IdTokenClaims` is traceable to the document it came from. Nothing is
//!   defaulted into existence, and `sub` in particular never arrives from a
//!   number, a null, or a missing key.
//! - **`an_unverified_email_never_reads_as_verified`** — the single most
//!   dangerous default on this path. `email_verified` is `unwrap_or(false)`,
//!   and the property that matters is the direction: no document that does not
//!   say `true` may produce `true`.
//! - **`the_client_returns_exactly_what_the_reply_carried`** — the same
//!   through the real `VerifierClient` over a real Unix socket, against an
//!   independent re-derivation of the frame. Catches a framing bug that let a
//!   body run past its declared length and pick up whatever followed.
//! - **`a_refusal_never_yields_an_identity`** — an `ERR` reply, or a frame the
//!   client cannot read, produces an error and never claims.
//!
//! # What this is not
//!
//! Not coverage-guided, and it does not shrink. It finds what its seeds and
//! mutation strategies reach, and a failing case prints at whatever size it was
//! generated.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_auth::oidc::{IdTokenClaims, TokenVerifier};
use hypellm_net::VerifierClient;
use hypellm_net::helper::parse_claims;
use hypellm_store::TempDir;
use hypellm_test_corpus::fuzz::{Rng, mutate};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use wire_json::{Limits, Value, parse};

/// Mirrors `MAX_CLAIMS_BYTES` in `crates/hypellm-net/src/helper.rs`, which is
/// private. Named here rather than inlined so that a change there which this
/// file does not follow shows up as a failing bound rather than as a test that
/// quietly stops covering the case.
const MAX_CLAIMS_BYTES: usize = 64 * 1024;

/// Claims documents a verifier could plausibly return.
///
/// The first is a complete Google identity token payload; the rest strip it
/// down to the shapes where defaulting decisions live — a multi-valued `aud`,
/// the bare minimum `parse_claims` accepts, and a document that is missing the
/// two fields it requires.
const CLAIMS_SEEDS: &[&[u8]] = &[
    br#"{"iss":"https://accounts.google.com","sub":"104729183746152938471","aud":"c.apps.googleusercontent.com","azp":"c.apps.googleusercontent.com","exp":4102444800,"iat":1700000000,"nonce":"n-0S6_WzA2Mj","email":"operator@example.com","email_verified":true,"hd":"example.com","name":"Alice"}"#,
    br#"{"iss":"https://accounts.google.com","sub":"1047","aud":["one","two"],"exp":1,"iat":0,"email_verified":false}"#,
    br#"{"iss":"i","sub":"s"}"#,
    br#"{"iss":"i","sub":"s","email_verified":"true","exp":"4102444800","aud":[1,2,"three"]}"#,
    br#"{"sub":"s","email_verified":null}"#,
    br#"{}"#,
];

/// The document's `aud`, as the set of strings it actually contains.
fn document_audiences(document: &Value) -> Vec<String> {
    match document.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Assert that nothing in `claims` was invented.
///
/// Every field is checked against the document it was supposedly read from.
/// This is the whole property: `parse_claims` is allowed to drop a field it
/// does not understand and allowed to refuse the document outright, but it is
/// never allowed to produce a value the document did not carry.
fn assert_traceable(document: &Value, claims: &IdTokenClaims, case: &[u8]) {
    let context = String::from_utf8_lossy(case).into_owned();

    // The two the router keys identity on. `?` on both means a document without
    // them must have been refused, so reaching here with either absent — or
    // holding a non-string — is a fabricated identity.
    assert_eq!(
        document.get("iss").and_then(Value::as_str),
        Some(claims.iss.as_str()),
        "iss was not read from the document: {context}"
    );
    assert_eq!(
        document.get("sub").and_then(Value::as_str),
        Some(claims.sub.as_str()),
        "sub was not read from the document: {context}"
    );

    assert_eq!(
        claims.aud,
        document_audiences(document),
        "aud does not match the document: {context}"
    );

    for (name, value) in [
        ("azp", claims.azp.as_deref()),
        ("nonce", claims.nonce.as_deref()),
        ("email", claims.email.as_deref()),
        ("hd", claims.hd.as_deref()),
        ("name", claims.name.as_deref()),
    ] {
        assert_eq!(
            document.get(name).and_then(Value::as_str),
            value,
            "{name} does not match the document: {context}"
        );
    }

    // `exp` and `iat` default to 0, which `validate_claims` reads as "expired"
    // and "issued at the epoch" — both refusals. The direction that matters is
    // that a non-numeric field can never become a *large* number, because that
    // is the one that would extend a token's life.
    for (name, value) in [("exp", claims.exp), ("iat", claims.iat)] {
        let from_document = document.get(name).and_then(Value::as_u64);
        assert!(
            from_document == Some(value) || (from_document.is_none() && value == 0),
            "{name} is {value} but the document does not carry it: {context}"
        );
    }

    assert!(
        !claims.email_verified || document.get("email_verified") == Some(&Value::Bool(true)),
        "email_verified is true but the document does not say so: {context}"
    );
}

#[test]
fn no_claim_is_fabricated_from_a_malformed_document() {
    let mut rng = Rng::new(0x5e_71f1);
    let mut accepted = 0u32;

    for _ in 0..8_000 {
        let seed = rng.pick(CLAIMS_SEEDS).copied().unwrap_or(b"{}");
        let case = mutate(seed, &mut rng);

        // A document the router's own parser refuses never reaches
        // `parse_claims`, so it is not a case.
        let Ok(document) = parse(&case, &Limits::SMALL) else {
            continue;
        };
        let Some(claims) = parse_claims(&document) else {
            continue;
        };
        accepted += 1;
        assert_traceable(&document, &claims, &case);
    }

    assert!(
        accepted > 100,
        "only {accepted} documents produced claims; the mutator is not reaching parse_claims"
    );
}

#[test]
fn an_unverified_email_never_reads_as_verified() {
    // Split out from the target above because it is the one default on this
    // path that is a privilege decision: `validate_claims` refuses an
    // unverified email, so a `true` invented here is a sign-in that should not
    // have happened. The mutator is pointed straight at the field.
    let seeds: &[&[u8]] = &[
        br#"{"iss":"i","sub":"s","email":"a@b.c","email_verified":true}"#,
        br#"{"iss":"i","sub":"s","email":"a@b.c","email_verified":false}"#,
        br#"{"iss":"i","sub":"s","email":"a@b.c","email_verified":"true"}"#,
        br#"{"iss":"i","sub":"s","email":"a@b.c","email_verified":1}"#,
        br#"{"iss":"i","sub":"s","email":"a@b.c","email_verified":null}"#,
        br#"{"iss":"i","sub":"s","email":"a@b.c"}"#,
    ];

    let mut rng = Rng::new(0x5e_71f2);
    let mut verified = 0u32;
    let mut unverified = 0u32;

    for _ in 0..8_000 {
        let seed = rng.pick(seeds).copied().unwrap_or(b"{}");
        let case = mutate(seed, &mut rng);
        let Ok(document) = parse(&case, &Limits::SMALL) else {
            continue;
        };
        let Some(claims) = parse_claims(&document) else {
            continue;
        };

        if claims.email_verified {
            verified += 1;
            assert_eq!(
                document.get("email_verified"),
                Some(&Value::Bool(true)),
                "an unverified email read as verified: {}",
                String::from_utf8_lossy(&case)
            );
        } else {
            unverified += 1;
        }
    }

    // Both arms must have been reached, or the property is vacuous: a run where
    // nothing ever verified would pass with the check removed.
    assert!(
        verified > 10 && unverified > 10,
        "the fuzzer reached {verified} verified and {unverified} unverified documents"
    );
}

// -- Through the real client -------------------------------------------------

/// A verifier socket that replies with whatever is handed to it.
///
/// One reply per connection, taken from the channel in order. The client opens
/// a fresh connection per request, so pushing a reply and then calling `verify`
/// is deterministic.
fn reply_server(dir: &TempDir, name: &str) -> (String, mpsc::Sender<Vec<u8>>) {
    let path = dir.join(name).to_string_lossy().into_owned();
    let listener = UnixListener::bind(&path).expect("bind");
    let (sender, receiver) = mpsc::channel::<Vec<u8>>();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut socket) = stream else {
                break;
            };
            let Ok(reply) = receiver.recv() else {
                break;
            };
            // Drained so the client's write never blocks against a full buffer.
            let mut scratch = [0u8; 8192];
            let _ = socket.read(&mut scratch);
            let _ = socket.write_all(&reply);
            let _ = socket.flush();
        }
    });

    (path, sender)
}

/// An independent re-derivation of what an `OK` frame carries.
///
/// Deliberately a second implementation rather than a call into the client:
/// the point is to disagree with it if the framing is wrong. It reads the
/// status line, takes *exactly* the declared number of bytes, and refuses
/// anything the client is also required to refuse.
fn oracle(reply: &[u8]) -> Option<IdTokenClaims> {
    let newline = reply.iter().position(|b| *b == b'\n')?;
    let status = core::str::from_utf8(&reply[..newline]).ok()?;
    let length: usize = status.strip_prefix("OK ")?.trim().parse().ok()?;
    if length > MAX_CLAIMS_BYTES {
        return None;
    }
    let body = reply.get(newline + 1..newline + 1 + length)?;
    let document = parse(body, &Limits::SMALL).ok()?;
    parse_claims(&document)
}

/// Whole replies, for fuzzing the *framing*. Lengths are deliberately a mix of
/// correct, short, long and absurd, because the framing is what decides how
/// many bytes of the body the client is willing to believe.
const REPLY_SEEDS: &[&[u8]] = &[
    b"OK 47\n{\"iss\":\"https://accounts.google.com\",\"sub\":\"1\"}",
    b"OK 21\n{\"iss\":\"i\",\"sub\":\"s\"}trailing-bytes-after-the-body",
    b"OK 2\n{}",
    b"OK 0\n",
    b"ERR signature_invalid\n",
    b"ERR unknown_kid\n",
    b"OK 99999999\n{\"iss\":\"i\",\"sub\":\"s\"}",
    b"not a status line at all\n",
];

#[test]
fn the_client_returns_exactly_what_the_reply_carried() {
    let dir = TempDir::new("verifier-fuzz-claims");
    let (path, replies) = reply_server(&dir, "verify.sock");
    let client = VerifierClient::new(path, Duration::from_secs(5));

    let mut rng = Rng::new(0x5e_71f3);
    let mut accepted = 0u32;

    for _ in 0..1_600 {
        // Two kinds of case, because there are two things to break. Mutating a
        // whole reply almost always destroys the declared length, which tests
        // the framing thoroughly and never reaches the claims parser; framing a
        // mutated *body* with a correct length points the mutator at the JSON,
        // which is where a fabricated claim would come from. Doing only the
        // first is how this target passed while covering nothing.
        let case = if rng.bool() {
            let seed = rng.pick(CLAIMS_SEEDS).copied().unwrap_or(b"{}");
            let body = mutate(seed, &mut rng);
            let mut framed = format!("OK {}\n", body.len()).into_bytes();
            framed.extend_from_slice(&body);
            framed
        } else {
            let seed = rng.pick(REPLY_SEEDS).copied().unwrap_or(b"ERR x\n");
            mutate(seed, &mut rng)
        };

        if replies.send(case.clone()).is_err() {
            panic!("the reply server stopped accepting");
        }
        let result = client.verify("an.id.token");

        match result {
            Ok(claims) => {
                accepted += 1;
                assert_eq!(
                    Some(claims),
                    oracle(&case),
                    "the client produced claims the frame does not carry: {}",
                    String::from_utf8_lossy(&case)
                );
            }
            Err(_) => {
                // A refusal is always permitted: the client is stricter than
                // the oracle in places (a short read, a timeout), and being
                // stricter is never the failure being hunted here.
            }
        }
    }

    assert!(
        accepted > 20,
        "only {accepted} replies were accepted; the mutator is not reaching the claims path"
    );
}

#[test]
fn a_refusal_never_yields_an_identity() {
    // The direction that matters on the other side: an `ERR` frame, whatever
    // follows it, must not produce a session. A client that read past the
    // status line would find a perfectly good claims document sitting there.
    let dir = TempDir::new("verifier-fuzz-refusal");
    let (path, replies) = reply_server(&dir, "verify.sock");
    let client = VerifierClient::new(path, Duration::from_secs(5));

    let seeds: &[&[u8]] = &[
        b"ERR signature_invalid\n{\"iss\":\"i\",\"sub\":\"s\"}",
        b"ERR unknown_kid\nOK 21\n{\"iss\":\"i\",\"sub\":\"s\"}",
        b"ERR \n{\"iss\":\"i\",\"sub\":\"s\"}",
        b"ERR verifier_fault\n",
    ];

    let mut rng = Rng::new(0x5e_71f4);
    for _ in 0..600 {
        let seed = rng.pick(seeds).copied().unwrap_or(b"ERR x\n");
        let mut case = mutate(seed, &mut rng);
        // Mutation may destroy the prefix, which would make the case something
        // other than a refusal. Restoring it keeps every iteration on target.
        if !case.starts_with(b"ERR ") {
            let mut restored = b"ERR ".to_vec();
            restored.append(&mut case);
            case = restored;
        }

        replies.send(case.clone()).expect("server accepts");
        assert!(
            client.verify("an.id.token").is_err(),
            "a refusal produced an identity: {}",
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn a_reply_larger_than_the_bound_is_refused_rather_than_read() {
    // The bound exists so a verifier — or anything else that can open this
    // socket — cannot make the router allocate without limit.
    //
    // The reply sent here is *complete and valid*: the declared length is
    // honest, the body is that many bytes, and it parses into perfectly good
    // claims under `Limits::SMALL` (which permits a 64 KiB string and a 1 MiB
    // document). So the only thing that can refuse it is the client's own cap.
    // A test that sent a short body instead would pass with the cap deleted,
    // because `read_exact` would fail on the truncation rather than on the
    // bound — which is the version of this test that proves nothing.
    let dir = TempDir::new("verifier-fuzz-bound");
    let (path, replies) = reply_server(&dir, "verify.sock");
    let client = VerifierClient::new(path, Duration::from_secs(5));

    // Split across two fields because `Limits::SMALL` caps a single string at
    // 64 KiB — the same number as the frame bound — so one padding field long
    // enough to exceed the frame would be refused by the JSON parser instead,
    // and the test would again be measuring the wrong refusal.
    // Exact halves: the bound is a power of two, so this is not a rounding
    // question, and naming the divisor keeps the fixture's size obvious.
    #[allow(clippy::integer_division, reason = "the bound is a power of two")]
    let half = "p".repeat(MAX_CLAIMS_BYTES / 2);
    let body = format!(r#"{{"iss":"i","sub":"s","name":"{half}","nonce":"{half}"}}"#);
    assert!(
        body.len() > MAX_CLAIMS_BYTES,
        "the fixture must exceed the bound to be testing it"
    );

    let mut reply = format!("OK {}\n", body.len()).into_bytes();
    reply.extend_from_slice(body.as_bytes());
    replies.send(reply).expect("server accepts");
    assert!(
        client.verify("an.id.token").is_err(),
        "a {} byte reply was accepted past the {MAX_CLAIMS_BYTES} byte bound",
        body.len()
    );

    // The same body one byte under the bound must still work, or the test above
    // would also pass if the client had simply stopped accepting anything.
    let padding = "p".repeat(MAX_CLAIMS_BYTES - 1024);
    let ok_body = format!(r#"{{"iss":"i","sub":"s","name":"{padding}"}}"#);
    assert!(ok_body.len() < MAX_CLAIMS_BYTES);
    let mut reply = format!("OK {}\n", ok_body.len()).into_bytes();
    reply.extend_from_slice(ok_body.as_bytes());
    replies.send(reply).expect("server accepts");
    assert!(
        client.verify("an.id.token").is_ok(),
        "a reply inside the bound was refused, so the bound test proves nothing"
    );

    // And a status line with no newline at all must not be read forever.
    let mut unterminated = b"OK ".to_vec();
    unterminated.extend(std::iter::repeat_n(b'9', 4096));
    replies.send(unterminated).expect("server accepts");
    assert!(
        client.verify("an.id.token").is_err(),
        "an unterminated status line was accepted"
    );
}
