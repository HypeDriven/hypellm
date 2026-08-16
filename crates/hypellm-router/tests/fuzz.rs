//! Fuzz targets for the client-facing protocol parsers.
//!
//! Specification 21 requires a Fuzz layer covering the request surface; these
//! are the parsers that read it. Every byte they see is chosen by an
//! authenticated but otherwise untrusted caller, and they run *before* routing,
//! admission, and any upstream contact — so a fault here is reachable by anyone
//! holding a valid API key.
//!
//! # What is asserted beyond "does not panic"
//!
//! Appendix B: "No client-controlled value may influence an upstream
//! destination, Host/SNI, credential handle, file path, or socket", and
//! "prompts are inert data". The parser is where that begins: it is the only
//! code that turns a caller's bytes into the `CanonicalRequest` that routing
//! then reads. So these targets assert that no mutation can produce a request
//! whose *identity* — tenant, principal, request id — differs from the one the
//! authenticated context supplied, and that every bound in specification 3.2
//! holds against a body shaped to break it.
//!
//! The residency and cost ceiling get the same treatment. Specification 5.1
//! keeps them out of the caller's hands, because a constraint a client could
//! set is one it could also unset.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: a failed assumption should fail the test loudly"
)]

use hypellm_core::ids::{PrincipalId, RequestId, TenantId};
use hypellm_core::canonical::{CostClass, Residency};
use hypellm_core::time::{Deadline, SystemClock};
use hypellm_router::protocol::openai::ParseContext;
use hypellm_router::protocol::{anthropic, openai};
use hypellm_test_corpus::fuzz::{self, Rng};
use std::time::Duration;
use wire_json::Limits;

const ITERATIONS: u32 = 20_000;
const TENANT: &str = "acme";
const PRINCIPAL: &str = "svc:fuzz";

fn context() -> ParseContext {
    let clock = SystemClock::new();
    ParseContext {
        request_id: RequestId::parse("00000000000000000000000000000001").expect("request id"),
        tenant: TenantId::new(TENANT).expect("tenant"),
        principal: PrincipalId::new(PRINCIPAL).expect("principal"),
        deadline: Deadline::after(&clock, Duration::from_secs(30)),
        hints_permitted: false,
        residency: Some(Residency::new("eu")),
        max_cost_class: Some(CostClass::new(3)),
    }
}

const CHAT_SEEDS: &[&[u8]] = &[
    br#"{"model":"a","messages":[{"role":"user","content":"hi"}]}"#,
    br#"{"model":"a","messages":[{"role":"system","content":"be brief"},{"role":"user","content":[{"type":"text","text":"hi"}]}],"stream":true,"max_tokens":16}"#,
    br#"{"model":"a","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"tool_choice":"auto"}"#,
    br#"{"model":"a","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"ok"}]}"#,
    br#"{"model":"a","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"s","schema":{"type":"object"}}},"temperature":0.5,"top_p":0.9,"seed":7}"#,
];

const RESPONSES_SEEDS: &[&[u8]] = &[
    br#"{"model":"a","input":"hi"}"#,
    br#"{"model":"a","instructions":"be brief","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_output_tokens":32}"#,
    br#"{"model":"a","input":[{"type":"function_call","call_id":"c1","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"ok"}]}"#,
    br#"{"model":"a","input":"hi","tools":[{"type":"function","name":"f","parameters":{"type":"object"},"strict":true}],"text":{"format":{"type":"json_schema","name":"s","schema":{"type":"object"}}}}"#,
];

const EMBEDDINGS_SEEDS: &[&[u8]] = &[
    br#"{"model":"a","input":"hi"}"#,
    br#"{"model":"a","input":["one","two"],"encoding_format":"float"}"#,
    br#"{"model":"a","input":[1,2,3]}"#,
];

const MESSAGES_SEEDS: &[&[u8]] = &[
    br#"{"model":"a","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#,
    br#"{"model":"a","max_tokens":16,"system":"be brief","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"stream":true}"#,
    br#"{"model":"a","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto"}}"#,
    br#"{"model":"a","max_tokens":16,"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"c1","name":"f","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"c1","content":"ok"}]}]}"#,
];

/// Every parser, behind one signature, so a target covers all four.
type Parser = fn(&[u8], &ParseContext, &Limits) -> Result<hypellm_core::canonical::CanonicalRequest, hypellm_core::error::RouterError>;

fn parsers() -> [(&'static str, Parser, &'static [&'static [u8]]); 4] {
    [
        ("chat", openai::parse_chat_request, CHAT_SEEDS),
        ("responses", openai::parse_responses_request, RESPONSES_SEEDS),
        (
            "embeddings",
            openai::parse_embeddings_request,
            EMBEDDINGS_SEEDS,
        ),
        ("messages", anthropic::parse_messages_request, MESSAGES_SEEDS),
    ]
}

#[test]
fn no_mutation_of_a_valid_request_panics_a_parser() {
    for (name, parse, seeds) in parsers() {
        let (accepted, rejected) = fuzz::sweep(seeds, ITERATIONS, 0x0c11_0001, |case| {
            parse(case, &context(), &Limits::DEFAULT).is_ok()
        });
        assert_eq!(accepted + rejected, ITERATIONS, "{name} lost a case");
        assert!(accepted > 0, "{name}: no mutated request ever parsed");
    }
}

#[test]
fn a_parsed_request_never_carries_an_identity_the_caller_chose() {
    // Appendix B, and the whole reason the identity arrives in a context rather
    // than in the body. A mutation that plants `"tenant"`, `"principal"`, or
    // `"request_id"` in the body must change nothing.
    let plants: &[&str] = &[
        r#","tenant":"other-tenant""#,
        r#","principal":"svc:someone-else""#,
        r#","request_id":"ffffffffffffffffffffffffffffffff""#,
        r#","residency":"us""#,
        r#","max_cost_class":"premium""#,
        r#","hypellm":{"tenant":"other-tenant"}"#,
    ];
    let mut rng = Rng::new(0x0c11_0002);

    for (name, parse, seeds) in parsers() {
        // A property test that never reaches its assertion is decoration. The
        // planted field could easily make every case unparseable — an unknown
        // top-level field is not rejected here, but a mutation that lands
        // badly is — so the count is asserted alongside the property.
        let mut asserted = 0u32;
        for _ in 0..2_000 {
            let seed = rng.pick(seeds).copied().unwrap_or(b"{}");
            // Plant before the closing brace of the top-level object.
            let Some(cut) = seed.iter().rposition(|b| *b == b'}') else {
                continue;
            };
            let plant = rng.pick(plants).copied().unwrap_or("");
            let mut case = seed[..cut].to_vec();
            case.extend_from_slice(plant.as_bytes());
            case.extend_from_slice(&seed[cut..]);

            let Ok(request) = parse(&case, &context(), &Limits::DEFAULT) else {
                continue;
            };
            assert_eq!(request.tenant.as_str(), TENANT, "{name} took a body tenant");
            assert_eq!(
                request.principal.as_str(),
                PRINCIPAL,
                "{name} took a body principal"
            );
            assert_eq!(
                request.request_id.to_hex(),
                "00000000000000000000000000000001",
                "{name} took a body request id"
            );
            assert_eq!(
                request.limits.residency,
                Some(Residency::new("eu")),
                "{name} let the body change residency"
            );
            assert_eq!(
                request.limits.max_cost_class,
                Some(CostClass::new(3)),
                "{name} let the body change the cost ceiling"
            );
            asserted += 1;
        }
        assert!(
            asserted > 0,
            "{name}: no planted body ever parsed, so nothing was asserted"
        );
    }
}

#[test]
fn a_hint_is_ignored_unless_the_principal_may_supply_one() {
    // Specification 5.1: hints are "ignored or rejected unless principal has
    // permission". A hint that survived would let a caller narrow — and
    // therefore influence — selection.
    let mut rng = Rng::new(0x0c11_0003);
    let hints = [
        r#","hypellm":{"prefer_target":"local:model"}"#,
        r#","hypellm":{"idempotency_key":"k"}"#,
        r#","hypellm":{"session_affinity":"s"}"#,
    ];

    for (name, parse, seeds) in parsers() {
        let mut asserted = 0u32;
        for _ in 0..1_000 {
            let seed = rng.pick(seeds).copied().unwrap_or(b"{}");
            let Some(cut) = seed.iter().rposition(|b| *b == b'}') else {
                continue;
            };
            let mut case = seed[..cut].to_vec();
            case.extend_from_slice(rng.pick(&hints).copied().unwrap_or("").as_bytes());
            case.extend_from_slice(&seed[cut..]);

            let mut context = context();
            context.hints_permitted = false;
            let Ok(request) = parse(&case, &context, &Limits::DEFAULT) else {
                continue;
            };
            assert!(
                request.hints.prefer_target.is_none(),
                "{name} honoured a target hint from a principal not permitted one"
            );
            asserted += 1;
        }
        assert!(
            asserted > 0,
            "{name}: no hinted body ever parsed, so nothing was asserted"
        );
    }
}

#[test]
fn the_parsers_are_deterministic() {
    // A parse that differed between two reads of one body would make the
    // decision trace unreproducible.
    let mut rng = Rng::new(0x0c11_0004);
    for (name, parse, seeds) in parsers() {
        for _ in 0..2_000 {
            let case = fuzz::mutate(rng.pick(seeds).copied().unwrap_or(b"{}"), &mut rng);
            let a = parse(&case, &context(), &Limits::DEFAULT);
            let b = parse(&case, &context(), &Limits::DEFAULT);
            match (a, b) {
                (Ok(x), Ok(y)) => {
                    assert_eq!(x.requested_model, y.requested_model, "{name}");
                    assert_eq!(x.messages.len(), y.messages.len(), "{name}");
                    assert_eq!(x.operation, y.operation, "{name}");
                }
                (Err(x), Err(y)) => assert_eq!(x.code, y.code, "{name}"),
                _ => panic!("{name} disagreed with itself on:\n{}", String::from_utf8_lossy(&case)),
            }
        }
    }
}

#[test]
fn an_oversize_body_is_refused_rather_than_buffered() {
    // Specification 3.2 bounds the input; the listener bounds it first, but a
    // parser that trusted the listener would be one refactor from not being
    // bounded at all.
    let mut body = String::from(r#"{"model":"a","messages":[{"role":"user","content":""#);
    body.push_str(&"a".repeat(32 * 1024 * 1024));
    body.push_str(r#""}]}"#);

    let limits = Limits::DEFAULT;
    for (name, parse, _) in parsers() {
        assert!(
            parse(body.as_bytes(), &context(), &limits).is_err(),
            "{name} accepted a 32 MiB body"
        );
    }
}

#[test]
fn deeply_nested_input_is_refused_rather_than_overflowing_the_stack() {
    let mut body = String::from(r#"{"model":"a","messages":"#);
    for _ in 0..10_000 {
        body.push('[');
    }
    for _ in 0..10_000 {
        body.push(']');
    }
    body.push('}');

    for (name, parse, _) in parsers() {
        assert!(
            parse(body.as_bytes(), &context(), &Limits::DEFAULT).is_err(),
            "{name} accepted 10,000 levels of nesting"
        );
    }
}

#[test]
fn a_huge_message_count_is_bounded() {
    // The other shape of oversize input: many small items rather than one large
    // one. Whatever it decides, it must decide within the test timeout.
    let mut body = String::from(r#"{"model":"a","max_tokens":16,"messages":["#);
    for n in 0..200_000u32 {
        if n > 0 {
            body.push(',');
        }
        body.push_str(r#"{"role":"user","content":"x"}"#);
    }
    body.push_str("]}");

    for (_, parse, _) in parsers() {
        let _ = parse(body.as_bytes(), &context(), &Limits::DEFAULT);
    }
}

#[test]
fn truncation_at_every_offset_is_handled() {
    for (name, parse, seeds) in parsers() {
        for seed in seeds {
            for cut in 0..seed.len() {
                // A prefix is either a clean rejection or, if it happens to be
                // a complete document, a clean parse. Never a panic.
                let _ = parse(&seed[..cut], &context(), &Limits::DEFAULT);
            }
            let _ = name;
        }
    }
}

#[test]
fn random_bytes_are_rejected_without_panicking() {
    let mut rng = Rng::new(0x0c11_beef);
    for _ in 0..ITERATIONS {
        let len = rng.below(256);
        let case: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        for (_, parse, _) in parsers() {
            let _ = parse(&case, &context(), &Limits::DEFAULT);
        }
    }
}
