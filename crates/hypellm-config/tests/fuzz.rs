//! Fuzz targets for the configuration grammar.
//!
//! Specification 21 requires a Fuzz layer covering "config"; this is that
//! target.
//!
//! # Why fuzz an administrator-authored format
//!
//! Configuration is not attacker-controlled the way a request body is, so the
//! threat here is not remote code execution — it is a **fail-open**. This
//! parser decides who may reach which model. A malformed record that is
//! silently ignored, or a field that quietly falls back to a permissive
//! default, widens access without anyone seeing an error. That is exactly the
//! shape of the defect this suite already found once: an invalid alias
//! identifier in a `grant` used to become "every alias" instead of an error.
//!
//! So beyond "does not panic", these targets assert the two properties that
//! make a configuration parser trustworthy:
//!
//! - **Total decision.** Every input either loads or reports errors. Nothing is
//!   half-applied.
//! - **No silent widening.** A configuration that loads must not grant more than
//!   its text says. The generators mutate grants and bindings specifically,
//!   since those are the records that carry authorization.

use hypellm_test_corpus::fuzz::{self, Rng};
use hypellm_config::load;

const ITERATIONS: u32 = 20_000;

/// Seeds spanning the record types, including several that must be refused.
const SEEDS: &[&[u8]] = &[
    b"tenant id=acme\n",
    b"settings state_dir=/var/lib/hypellm max_body_bytes=1048576\n",
    b"provider id=p family=openai scheme=https host=api.example base_path=/v1\n",
    b"target id=p:m provider=p model=m operations=chat context=1000 max_output=100\n",
    b"alias id=code targets=p:m family_failover=true\n",
    b"grant scope=tenant:acme model=* allow=true\n",
    b"grant scope=principal:user:42 model=code allow=true\n",
    b"binding id=b scope=tenant:acme model=* prefer=p:m deny=p:*\n",
    b"quota scope=tenant:acme concurrency=10 tpm=1000\n",
    b"role_binding subject=principal:user:42 role=viewer\n",
    b"group id=g tenant=acme members=user:1,user:2\n",
    b"credential id=c scope=openai rotates_after_days=30\n",
    b"# a comment\n\n  \n",
    b"tenant id=acme\nprovider id=p family=openai scheme=https host=a.example\n\
      target id=p:m provider=p model=m operations=chat context=1000 max_output=100\n\
      alias id=a targets=p:m\ngrant scope=tenant:acme model=* allow=true\n",
];

#[test]
fn no_mutation_of_a_configuration_panics_the_loader() {
    let (accepted, rejected) = fuzz::sweep(SEEDS, ITERATIONS, 0xc0f1_0001, |case| {
        // Non-UTF-8 is a legitimate input to reject, not a reason to skip.
        match core::str::from_utf8(case) {
            Ok(text) => load(text, 1).is_ok(),
            Err(_) => false,
        }
    });

    assert!(accepted > 0, "no mutated configuration ever loaded");
    assert_eq!(accepted + rejected, ITERATIONS);
}

#[test]
fn a_loaded_configuration_never_grants_more_than_its_text_says() {
    // The fail-open this file exists to catch. A mutation that corrupts an
    // alias identifier in a grant must produce an error, never a grant whose
    // model selector silently became "any".
    let mut rng = Rng::new(0xc0f1_0002);
    let seed: &[u8] = b"tenant id=acme\ngrant scope=tenant:acme model=code allow=true\n";

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(seed, &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        let Ok(config) = load(text, 1) else {
            continue;
        };

        // Attribution has to be unambiguous for the assertion to mean
        // anything: with two grants in the text there is no way to say which
        // line produced which selector, and a legitimately unrestricted second
        // grant would look like the first one widening. Cases where the
        // mutation split or duplicated the record are skipped rather than
        // guessed at.
        let grant_lines: Vec<&str> = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .filter(|line| line.starts_with("grant"))
            .collect();
        if grant_lines.len() != 1 || config.snapshot.grants.len() != 1 {
            continue;
        }

        let (Some(line), Some(grant)) = (grant_lines.first(), config.snapshot.grants.first())
        else {
            continue;
        };

        if matches!(grant.model, hypellm_core::policy::ModelSelector::Any) {
            // A grant over every alias is only legitimate if its own line
            // either omitted `model` or asked for the wildcard.
            let names_a_model = line
                .split_whitespace()
                .filter_map(|token| token.split_once('='))
                .any(|(key, value)| key == "model" && !value.is_empty() && value != "*");
            assert!(
                !names_a_model,
                "a grant naming one alias widened to every alias:\n{text}"
            );
        }
    }
}

#[test]
fn an_unknown_field_is_always_an_error() {
    // Specification 11.1: "Unknown fields are errors." This is what makes a
    // typo fail at load rather than leaving a capability un-declared. A
    // mutation that renames a field must never be quietly ignored.
    let mut rng = Rng::new(0xc0f1_0003);
    let seed: &[u8] = b"tenant id=acme retention_days=30\n";

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(seed, &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        if load(text, 1).is_ok() {
            // Every key present must be one the schema knows.
            for line in text.lines() {
                // `#` starts a comment anywhere on the line, so anything after
                // one was never seen by the parser. Stripping it here is what
                // keeps this test asserting the parser's behaviour rather than
                // its own misreading.
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                for token in line.split_whitespace().skip(1) {
                    if let Some((key, _)) = token.split_once('=') {
                        assert!(
                            matches!(
                                key,
                                "id" | "inherit_global"
                                    | "status"
                                    | "residency"
                                    | "retention_days"
                                    | "max_cost"
                            ),
                            "unknown field '{key}' was accepted on a tenant record:\n{text}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn the_loader_is_deterministic() {
    // A configuration digest is only meaningful if the same text always
    // produces the same snapshot. Two loads of one input must agree.
    let mut rng = Rng::new(0xc0f1_0004);

    for _ in 0..2_000 {
        let Some(base) = rng.pick(SEEDS).copied() else {
            break;
        };
        let case = fuzz::mutate(base, &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };

        match (load(text, 1), load(text, 1)) {
            (Ok(a), Ok(b)) => assert_eq!(a.digest, b.digest, "digest differed for:\n{text}"),
            (Err(a), Err(b)) => assert_eq!(
                a.iter().map(|e| e.code).collect::<Vec<_>>(),
                b.iter().map(|e| e.code).collect::<Vec<_>>(),
                "error codes differed for:\n{text}"
            ),
            _ => panic!("the loader disagreed with itself on:\n{text}"),
        }
    }
}

#[test]
fn a_very_long_line_is_refused_rather_than_consuming_the_process() {
    // Specification 11.1's grammar is line-oriented, so a single line is the
    // natural unbounded input.
    let mut text = String::from("tenant id=");
    text.push_str(&"a".repeat(8 * 1024 * 1024));
    text.push('\n');

    assert!(load(&text, 1).is_err());
}

#[test]
fn deeply_repeated_records_are_bounded() {
    // Many records rather than one long line: the other shape of oversize
    // input.
    let mut text = String::new();
    for n in 0..200_000u32 {
        text.push_str(&format!("tenant id=t{n}\n"));
    }
    // Whatever it decides, it must decide, and within the test timeout.
    let _ = load(&text, 1);
}

#[test]
fn random_text_is_rejected_without_panicking() {
    let mut rng = Rng::new(0xc0f1_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(256);
        let case: String = (0..len)
            .map(|_| {
                // Printable ASCII plus the delimiters the grammar cares about.
                let choices = b" \t\r\n=\"#abcABC0123:,*\\";
                char::from(*rng.pick(choices).unwrap_or(&b'a'))
            })
            .collect();
        let _ = load(&case, 1);
    }
}
