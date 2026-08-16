//! Strict, bounded JSON for HypeLLM Router.
//!
//! Specification 18.1 calls for a "small strict JSON tokenizer/parser/
//! serializer with depth and size limits". This crate is that component.
//!
//! Three properties matter more than throughput:
//!
//! 1. **No parser differential.** Every syntax extension that some parsers
//!    accept — comments, trailing commas, `NaN`, leading zeros, duplicate keys,
//!    lone surrogates — is rejected. If the router and an upstream disagree
//!    about what a document means, an attacker chooses which one is right.
//! 2. **Bounded work before allocation.** Depth, string length, element counts
//!    and total input size are checked against an explicit [`Limits`] value
//!    named at each call site (specification 3.2).
//! 3. **No input in error messages.** Failures carry a category and a byte
//!    offset. Request bodies are sensitive by default (specification 10), so a
//!    parse error must not quote the prompt that caused it.
//!
//! ```
//! use wire_json::{Limits, Value, parse_str, to_string};
//!
//! let v = parse_str(r#"{"model":"code-premium","stream":true}"#, &Limits::DEFAULT)?;
//! assert_eq!(v.field_str("model")?, "code-premium");
//! assert_eq!(to_string(&v), r#"{"model":"code-premium","stream":true}"#);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
// Data plane: this crate parses every request body, so specification 18.2's
// "no panics on data-plane input" and "all integer conversions checked" are
// compile errors here, not warnings. A new unchecked index or silent `as`
// fails the build; the few sites that genuinely need one carry a
// function-scoped `allow` and a comment saying why it cannot go wrong.
#![deny(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_sign_loss
)]
// Specification 18.2 permits these in tests, so `cfg(test)` steps the
// escalation back down. `warn` rather than `allow`: the tests here do not
// currently need any of the three, and keeping the signal visible means the day
// one does, it is a decision someone makes rather than one the attribute made
// for them.
#![cfg_attr(
    test,
    warn(
        clippy::indexing_slicing,
        clippy::as_conversions,
        clippy::cast_sign_loss
    )
)]

pub mod limits;
pub mod parse;
pub mod value;
pub mod write;

pub use limits::Limits;
pub use parse::{ErrorKind, JsonError, parse, parse_str};
pub use value::{Number, Object, TypeError, Value, array, object};
pub use write::{
    escape_string, to_canonical_string, to_canonical_vec, to_string, to_vec, write_string, write_to,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// A realistic OpenAI-shaped chat request must survive a full round trip
    /// with values intact.
    #[test]
    fn chat_completion_request_roundtrip() {
        let src = r#"{"model":"code-premium","messages":[{"role":"system","content":"You are terse."},{"role":"user","content":"Explain backpressure."}],"stream":true,"max_tokens":512,"temperature":0.2,"tools":[{"type":"function","function":{"name":"lookup","description":"Look something up","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}}]}"#;
        let v = parse_str(src, &Limits::DEFAULT).expect("parses");

        assert_eq!(v.field_str("model").unwrap(), "code-premium");
        assert_eq!(v.opt_field_bool("stream").unwrap(), Some(true));
        assert_eq!(v.field_i64("max_tokens").unwrap(), 512);
        assert_eq!(v.field_array("messages").unwrap().len(), 2);
        assert_eq!(
            v.field_array("messages")
                .unwrap()
                .get(1)
                .unwrap()
                .field_str("role")
                .unwrap(),
            "user"
        );
        let tools = v.field_array("tools").unwrap();
        let tool = tools.first().unwrap();
        assert_eq!(
            tool.get("function").unwrap().field_str("name").unwrap(),
            "lookup"
        );

        assert_eq!(to_string(&v), src, "compact output must be byte-stable");
    }

    /// Canonical output is what configuration and audit digests are computed
    /// over, so two documents that differ only in key order must hash alike.
    #[test]
    fn canonical_form_is_order_independent() {
        let a = parse_str(r#"{"b":1,"a":{"d":2,"c":3}}"#, &Limits::DEFAULT).unwrap();
        let b = parse_str(r#"{"a":{"c":3,"d":2},"b":1}"#, &Limits::DEFAULT).unwrap();
        assert_ne!(to_string(&a), to_string(&b));
        assert_eq!(to_canonical_vec(&a), to_canonical_vec(&b));
    }

    /// The parser must terminate on every prefix of a valid document rather
    /// than looping or panicking. This is the property the fuzz target asserts.
    #[test]
    fn every_prefix_terminates_without_panic() {
        let src = r#"{"a":[1,2.5,"xé",{"b":null}],"c":true}"#;
        for i in 0..=src.len() {
            if !src.is_char_boundary(i) {
                continue;
            }
            let _ = parse_str(&src[..i], &Limits::DEFAULT);
        }
    }

    /// Truncating anywhere must never yield a *successful* parse of a different
    /// document — the trailing-content and unexpected-end checks together make
    /// partial reads detectable.
    #[test]
    fn truncation_never_silently_succeeds_with_different_meaning() {
        let src = r#"{"stream":true,"max_tokens":512}"#;
        let full = parse_str(src, &Limits::DEFAULT).unwrap();
        for i in 0..src.len() {
            if let Ok(v) = parse_str(&src[..i], &Limits::DEFAULT) {
                assert_eq!(v, full, "truncated prefix parsed to a different value");
            }
        }
    }

    /// Bounded work: a pathological document must be rejected quickly rather
    /// than consuming memory proportional to its nesting.
    #[test]
    fn adversarial_documents_are_rejected() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(
            parse_str(&deep, &Limits::DEFAULT).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );

        let unterminated = "[".repeat(10_000);
        assert!(parse_str(&unterminated, &Limits::DEFAULT).is_err());

        let many_keys = {
            let mut s = String::from("{");
            for i in 0..20_000 {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!("\"k{i}\":1"));
            }
            s.push('}');
            s
        };
        assert_eq!(
            parse_str(&many_keys, &Limits::DEFAULT).unwrap_err().kind,
            ErrorKind::ObjectTooLarge
        );
    }

    /// Streaming events use tighter limits than request bodies.
    #[test]
    fn stream_event_limits_are_tighter_than_request_limits() {
        assert!(Limits::STREAM_EVENT.max_input_bytes < Limits::DEFAULT.max_input_bytes);
        assert!(Limits::STREAM_EVENT.max_depth < Limits::DEFAULT.max_depth);
        assert!(Limits::SMALL.max_string_bytes < Limits::DEFAULT.max_string_bytes);
    }
}
