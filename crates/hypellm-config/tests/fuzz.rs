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
fn no_mutated_verifier_ever_accepts_a_password_it_was_not_built_from() {
    // The fail-open specific to `local_user`. A verifier is the only field in
    // the grammar whose value decides an *authentication* outcome, so the
    // question is not "does it parse" but "can a corrupted one be made to say
    // yes". Concretely, this fails if `PasswordVerifier::parse` ever defaults a
    // field instead of refusing: a zeroed derived key, an iteration count that
    // silently becomes one, an algorithm label that falls back — each would
    // turn a mangled string into a credential somebody can guess.
    //
    // The probes are passwords no seed contains, including the two a defaulting
    // parser would most plausibly accept: the empty string, and the username.
    const PROBES: &[&str] = &["", "admin", "password", "\u{0}", "the-real-password "];

    let verifier = hypellm_crypto::PasswordVerifier::derive_with(
        "the-real-password",
        hypellm_crypto::scrypt::MIN_LOG_N,
        hypellm_crypto::scrypt::DEFAULT_R,
        hypellm_crypto::scrypt::DEFAULT_P,
    )
    .expect("the test host has an entropy source")
    .encode();
    let seed = format!(
        "tenant id=acme\nlocal_user id=admin principal=user:admin tenant=acme verifier={verifier}\n"
    );

    // Fewer iterations than the other targets, and the reason is stated rather
    // than hidden: every loaded case costs five real PBKDF2 verifications, so
    // the full sweep runs for half a minute in a debug build and would be the
    // slowest thing in `cargo test --workspace`. The mutation space that
    // matters here is one field of one record, not the whole grammar.
    const VERIFIER_ITERATIONS: u32 = 2_000;

    let mut rng = Rng::new(0xc0f1_0009);
    let mut loaded = 0u32;

    for _ in 0..VERIFIER_ITERATIONS {
        let case = fuzz::mutate(seed.as_bytes(), &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        let Ok(config) = load(text, 1) else {
            continue;
        };
        loaded = loaded.saturating_add(1);

        for user in &config.local_users {
            for probe in PROBES {
                // A mutation can legitimately rewrite the record into a
                // *different* valid verifier only by producing one someone
                // derived; it cannot produce one for a probe by chance. So any
                // acceptance here is the parser inventing a credential.
                assert!(
                    !user.verifier.verify(probe),
                    "a mutated verifier accepted {probe:?}:\n{text}"
                );
            }
        }
    }

    assert!(loaded > 0, "no mutated configuration ever loaded");
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

/// Random batches of `grant` and `quota` edits never reach past a principal or
/// a group, and never move a quota limit.
///
/// `edit::apply` is how the principal-access screen drafts a ceiling. The
/// fail-open to catch is an edit that the scope rule should refuse but does
/// not: a tenant-wide grant changed, a principal's grant moved to a tenant, a
/// limit lifted by way of a "class-only" quota, or a record of another kind
/// smuggled in through a value.
#[test]
fn an_access_edit_never_reaches_past_its_subject() {
    use hypellm_config::edit::{Edit, Identity, apply};
    use hypellm_config::{ParseLimits, parse};

    const BASE: &str = "tenant id=acme\n\
        grant scope=tenant:acme model=* allow=true\n\
        grant id=g1 scope=principal:user:42 model=code allow=false\n\
        grant id=g2 scope=group:devs model=* allow=true\n\
        quota scope=tenant:acme concurrency=10\n\
        quota id=q1 scope=principal:user:42 concurrency=2 class=batch\n\
        quota id=q2 scope=principal:user:7 class=interactive\n";
    const KINDS: &[&str] = &["grant", "quota"];
    const IDS: &[&str] = &["g1", "g2", "q1", "q2", "new", "local", "acme"];
    const NAMES: &[&str] = &[
        "scope", "model", "allow", "operations", "class", "concurrency", "rps", "tpm", "budget",
        "queued", "id", "burst", "token_burst", "budget_period", "operation",
        "input_bytes_per_second", "output_bytes_burst",
    ];
    const VALUES: &[&str] = &[
        "principal:user:42", "principal:svc:x", "group:devs", "tenant:acme", "global", "*",
        "code", "true", "false", "batch", "interactive", "0", "1000",
        "x\nrole_binding subject=principal:m role=break_glass_admin",
    ];

    /// Every record an access edit may not touch — anything but a principal-
    /// or group-scoped grant and a principal-scoped quota — as `kind fields`
    /// lines. The tenant quota above is among them: its limits throttle every
    /// caller in the tenant.
    fn protected(text: &str) -> Vec<String> {
        let doc = parse(text, &ParseLimits::DEFAULT).expect("apply renders parseable text");
        let mut out: Vec<String> = Vec::new();
        for record in &doc.records {
            let scope = record.get("scope").unwrap_or("");
            let accessed = match record.kind.as_str() {
                "grant" => scope.starts_with("principal:") || scope.starts_with("group:"),
                "quota" => scope.starts_with("principal:"),
                _ => false,
            };
            // Canonical rendering sorts fields, so compare them sorted too.
            let mut fields = record.fields.clone();
            fields.sort();
            if !accessed {
                out.push(format!("{} {fields:?}", record.kind));
            }
        }
        out.sort();
        out
    }

    /// A principal's quota carries only fields that mean something there.
    fn principal_quota_fields_are_editable_ones(text: &str) -> Result<(), String> {
        let doc = parse(text, &ParseLimits::DEFAULT).expect("apply renders parseable text");
        for record in doc.of_kind("quota") {
            if record.get("scope").is_some_and(|s| s.starts_with("principal:")) {
                for (name, _) in &record.fields {
                    if name != "id" && !hypellm_config::edit::QUOTA_EDITABLE.contains(&name.as_str()) {
                        return Err(format!("a principal quota gained '{name}'"));
                    }
                }
            }
        }
        Ok(())
    }

    let before = protected(BASE);
    let mut rng = Rng::new(0xc0f1_0e01);
    let mut accepted = 0u32;
    for _ in 0..ITERATIONS {
        let count = 1 + rng.below(3);
        let mut edits = Vec::new();
        for _ in 0..count {
            let kind = (*rng.pick(KINDS).unwrap()).to_owned();
            let identity = Identity::Id((*rng.pick(IDS).unwrap()).to_owned());
            if rng.below(5) == 0 {
                edits.push(Edit::Remove { kind, identity });
                continue;
            }
            let fields = (0..1 + rng.below(3))
                .map(|_| {
                    let name = (*rng.pick(NAMES).unwrap()).to_owned();
                    let value = (rng.below(6) != 0).then(|| (*rng.pick(VALUES).unwrap()).to_owned());
                    (name, value)
                })
                .collect();
            edits.push(Edit::Set { kind, identity, fields });
        }
        let Ok(applied) = apply(BASE, &edits) else { continue };
        accepted += 1;
        let after = protected(&applied.text);
        assert_eq!(after, before, "edits {edits:?} reached a protected record:\n{}", applied.text);
        if let Err(why) = principal_quota_fields_are_editable_ones(&applied.text) {
            panic!("edits {edits:?}: {why}:\n{}", applied.text);
        }
    }
    assert!(accepted > 100, "too few edit batches were accepted to mean anything: {accepted}");
}
