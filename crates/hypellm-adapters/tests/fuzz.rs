//! Fuzz targets for provider event decoding.
//!
//! Specification 21 requires a Fuzz layer covering "provider events"; this is
//! that target. The seeds are the recorded fixtures in `hypellm-test-corpus`, so
//! every mutation starts from bytes a real provider actually sent.
//!
//! # What a provider can do to this router
//!
//! An adapter is the only code that reads a provider's bytes, and it reads them
//! after the router has already authenticated the caller, reserved capacity, and
//! in the streaming case begun writing to the client. A panic here is a dropped
//! connection at best; the more interesting failures are quieter:
//!
//! - **Leakage.** A provider's error message routinely contains an internal
//!   hostname, a quota identifier, or an echo of the prompt. Specification 10
//!   keeps those out of the client's error, so `safe_detail` must not carry the
//!   body through no matter how the body is shaped.
//! - **Unbounded work.** A single event is attacker-influenced in length and
//!   nesting; specification 3.2 bounds both.
//! - **Silent success.** A non-2xx status that decodes to an empty completion
//!   would report success to the caller and bill them for it.
//!
//! These targets assert those properties rather than only "does not panic".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

use hypellm_adapters::adapter_for;
use hypellm_core::target::ProviderFamily;
use hypellm_test_corpus::fuzz::{self, Rng};
use hypellm_test_corpus::golden;

const ITERATIONS: u32 = 20_000;

fn families() -> [ProviderFamily; 2] {
    [ProviderFamily::OpenAi, ProviderFamily::Anthropic]
}

fn family_for(family: golden::GoldenFamily) -> ProviderFamily {
    match family {
        golden::GoldenFamily::OpenAiCompatible => ProviderFamily::OpenAi,
        golden::GoldenFamily::Anthropic => ProviderFamily::Anthropic,
    }
}

/// Every recorded stream frame payload, as fuzz seeds.
fn stream_seeds() -> Vec<&'static [u8]> {
    golden::streams()
        .iter()
        .flat_map(|s| s.frames.iter())
        .map(|frame| frame.data.as_bytes())
        .collect()
}

/// Every recorded response body, as fuzz seeds.
fn body_seeds() -> Vec<&'static [u8]> {
    golden::responses()
        .iter()
        .map(|r| r.body.as_bytes())
        .chain(golden::failures().iter().map(|f| f.body.as_bytes()))
        .collect()
}

#[test]
fn no_mutation_of_a_recorded_stream_frame_panics_a_decoder() {
    let seeds = stream_seeds();
    assert!(!seeds.is_empty(), "the corpus supplied no stream frames");
    let mut rng = Rng::new(0xada9_0001);
    let names = [None, Some("message_start"), Some("error"), Some("nonsense")];

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b""), &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        for family in families() {
            let adapter = adapter_for(family);
            let name = rng.pick(&names).copied().flatten();
            // Whatever it decides, it must decide.
            let _ = adapter.decode_stream_event(name, text);
            let _ = adapter.is_stream_terminator(text);
        }
    }
}

#[test]
fn no_mutation_of_a_recorded_body_panics_a_decoder() {
    let seeds = body_seeds();
    assert!(!seeds.is_empty(), "the corpus supplied no bodies");
    let statuses = [200u16, 201, 400, 401, 403, 404, 429, 500, 502, 503, 599];
    let mut rng = Rng::new(0xada9_0002);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b""), &mut rng);
        let status = rng.pick(&statuses).copied().unwrap_or(200);
        for family in families() {
            let adapter = adapter_for(family);
            let _ = adapter.decode_response(status, &case);
            let _ = adapter.classify_error(status, &case);
        }
    }
}

#[test]
fn a_non_success_status_never_decodes_to_a_completion() {
    // The silent-success failure. A 500 whose body happens to parse as a
    // completion must not be handed to the caller as one: nothing was
    // generated, and the router would bill for it and stop failing over.
    let seeds = body_seeds();
    let mut rng = Rng::new(0xada9_0003);

    for _ in 0..ITERATIONS {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b""), &mut rng);
        for status in [400u16, 401, 403, 404, 429, 500, 502, 503] {
            for family in families() {
                let adapter = adapter_for(family);
                assert!(
                    adapter.decode_response(status, &case).is_err(),
                    "{family:?} decoded a {status} response as a completion:\n{}",
                    String::from_utf8_lossy(&case)
                );
            }
        }
    }
}

#[test]
fn a_classified_error_never_carries_the_provider_body_to_the_client() {
    // Specification 10: a provider's message can contain an internal hostname,
    // a quota identifier, or an echo of the prompt. The fixtures each name a
    // fragment of their own body that must not survive; this asserts the same
    // property against mutated bodies, where the fragment is planted.
    //
    // The marker deliberately carries characters outside the identifier
    // alphabet. `provider_code` is *meant* to carry the provider's own error
    // type token — asserting the marker never appears there would be asserting
    // that the field does not work — so what is checked there is the narrowing
    // and the bound, which is what keeps a type token out of log-injection
    // territory.
    const PLANTED: &str = "s3cret internal:host/corp\u{7}invalid";
    let seeds = body_seeds();
    let mut rng = Rng::new(0xada9_0004);

    for _ in 0..ITERATIONS {
        let mut case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b""), &mut rng);
        // Plant the marker inside the body wherever it lands.
        let at = rng.below(case.len().max(1)).min(case.len());
        case.splice(at..at, PLANTED.bytes());

        for status in [400u16, 429, 500] {
            for family in families() {
                let adapter = adapter_for(family);
                let classification = adapter.classify_error(status, &case);
                assert!(
                    !classification.safe_detail.as_str().contains(PLANTED),
                    "{family:?} leaked the provider body into the client detail:\n{}",
                    classification.safe_detail.as_str()
                );
                if let Some(code) = &classification.provider_code {
                    let code = code.as_str();
                    assert!(
                        code.len() <= 64,
                        "{family:?} recorded an unbounded provider code ({} bytes)",
                        code.len()
                    );
                    assert!(
                        code.chars().all(|c| c.is_ascii_alphanumeric()
                            || c == '_'
                            || c == '-'
                            || c == '.'),
                        "{family:?} recorded an un-narrowed provider code: {code:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_classification_is_deterministic() {
    // A retry decision that differs between two reads of the same bytes would
    // make failover behaviour unreproducible, and specification 6.5's rules
    // unprovable.
    let seeds = body_seeds();
    let mut rng = Rng::new(0xada9_0005);

    for _ in 0..2_000 {
        let case = fuzz::mutate(rng.pick(&seeds).copied().unwrap_or(b""), &mut rng);
        for family in families() {
            let adapter = adapter_for(family);
            let a = adapter.classify_error(500, &case);
            let b = adapter.classify_error(500, &case);
            assert_eq!(a.class, b.class);
            assert_eq!(a.safe_detail.as_str(), b.safe_detail.as_str());
            assert_eq!(a.is_retriable(), b.is_retriable());
        }
    }
}

#[test]
fn an_oversize_stream_event_is_refused_rather_than_decoded() {
    // Specification 3.2 bounds a single decoded event
    // (`wire_json::Limits::STREAM_EVENT`, 2 MiB). The provider controls this
    // length entirely.
    let mut payload = String::from(r#"{"choices":[{"delta":{"content":""#);
    payload.push_str(&"a".repeat(8 * 1024 * 1024));
    payload.push_str(r#""}}]}"#);

    for family in families() {
        let adapter = adapter_for(family);
        assert!(
            adapter.decode_stream_event(None, &payload).is_err(),
            "{family:?} decoded an 8 MiB event"
        );
    }
}

#[test]
fn deeply_nested_provider_json_is_refused_rather_than_overflowing_the_stack() {
    let mut payload = String::new();
    for _ in 0..10_000 {
        payload.push_str(r#"{"a":"#);
    }
    payload.push('1');
    for _ in 0..10_000 {
        payload.push('}');
    }

    for family in families() {
        let adapter = adapter_for(family);
        assert!(adapter.decode_stream_event(None, &payload).is_err());
        assert!(adapter.decode_response(200, payload.as_bytes()).is_err());
    }
}

#[test]
fn random_bytes_are_handled_without_panicking() {
    let mut rng = Rng::new(0xada9_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(512);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        for family in families() {
            let adapter = adapter_for(family);
            let _ = adapter.decode_response(200, &case);
            let _ = adapter.classify_error(500, &case);
            if let Ok(text) = core::str::from_utf8(&case) {
                let _ = adapter.decode_stream_event(None, text);
                let _ = adapter.is_stream_terminator(text);
            }
        }
    }
}

#[test]
fn every_recorded_fixture_is_reachable_as_a_seed() {
    // A seed set that silently shrank would leave these targets fuzzing a
    // fraction of the corpus while still passing.
    assert!(stream_seeds().len() >= golden::streams().len());
    assert_eq!(
        body_seeds().len(),
        golden::responses().len() + golden::failures().len()
    );
    for stream in golden::streams() {
        // Every fixture names a family this test can build an adapter for.
        let _ = adapter_for(family_for(stream.family));
    }
}
