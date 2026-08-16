//! Serialization.
//!
//! Two modes:
//!
//! - **Compact** preserves insertion order. Used for provider requests and
//!   streaming frames, where key order sometimes carries meaning to a
//!   downstream implementation and reordering would be a gratuitous change.
//! - **Canonical** sorts every object's keys recursively. Specification 11.1
//!   requires the management API to emit canonical ordering, and configuration
//!   digests must not change because a key moved.

use crate::value::{Number, Object, Value};

/// Serialize compactly into a new `String`.
#[must_use]
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Serialize compactly into a new byte vector.
#[must_use]
pub fn to_vec(value: &Value) -> Vec<u8> {
    to_string(value).into_bytes()
}

/// Append a compact serialization to an existing buffer.
///
/// Streaming frames are built into a reused buffer to avoid an allocation per
/// token delta.
pub fn write_to(out: &mut String, value: &Value) {
    write_value(out, value);
}

/// Serialize with every object key sorted, recursively.
#[must_use]
pub fn to_canonical_string(value: &Value) -> String {
    let mut sorted = value.clone();
    sorted.sort_keys();
    to_string(&sorted)
}

/// Canonical serialization as bytes, the input to configuration and audit
/// digests.
#[must_use]
pub fn to_canonical_vec(value: &Value) -> Vec<u8> {
    to_canonical_string(value).into_bytes()
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, *n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(obj) => write_object(out, obj),
    }
}

fn write_object(out: &mut String, obj: &Object) {
    out.push('{');
    for (i, (k, v)) in obj.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, k);
        out.push(':');
        write_value(out, v);
    }
    out.push('}');
}

fn write_number(out: &mut String, n: Number) {
    match n {
        Number::Int(i) => {
            let mut buf = itoa(i);
            out.push_str(buf.as_str());
            buf.clear();
        }
        Number::Float(f) => {
            if f.is_finite() {
                // `Debug` for f64 is the shortest representation that
                // round-trips, and always produces valid JSON syntax
                // (`1.0`, `1e300`) — unlike `Display`, which expands large
                // magnitudes into hundreds of digits.
                out.push_str(&format!("{f:?}"));
            } else {
                // JSON has no NaN or Infinity. Reaching here means a caller
                // built a non-finite number programmatically; emitting `null`
                // keeps the document parseable. Parsed input can never be
                // non-finite: the parser rejects it as `NumberOutOfRange`.
                out.push_str("null");
            }
        }
    }
}

/// Small integer formatter that avoids `format!`'s machinery on the hot path.
fn itoa(v: i64) -> String {
    let mut s = String::with_capacity(20);
    if v == 0 {
        s.push('0');
        return s;
    }
    let negative = v < 0;
    // `unsigned_abs` takes the magnitude without the overflow that negating
    // `i64::MIN` would cause, so no wider type is needed.
    let mut n = v.unsigned_abs();
    // 20 slots hold every u64, and the loop is bounded by the array rather
    // than by `len`, so the digit count can never run past the buffer.
    let mut digits = ['0'; 20];
    let mut len = 0usize;
    for slot in &mut digits {
        if n == 0 {
            break;
        }
        // `n % 10` is a single decimal digit, so both the narrowing and
        // `from_digit` succeed; '0' is an unreachable fallback.
        *slot = u32::try_from(n % 10)
            .ok()
            .and_then(|d| char::from_digit(d, 10))
            .unwrap_or('0');
        n /= 10;
        len += 1;
    }
    if negative {
        s.push('-');
    }
    s.extend(digits.iter().take(len).rev());
    s
}

/// Write a JSON string literal, including the surrounding quotes.
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                out.push_str("\\u");
                let v = u32::from(c);
                for shift in [12u32, 8, 4, 0] {
                    // A nibble is below 16, so `from_digit` in radix 16 always
                    // yields a lowercase hex digit; '0' is unreachable.
                    let nibble = (v >> shift) & 0xF;
                    out.push(char::from_digit(nibble, 16).unwrap_or('0'));
                }
            }
            // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are legal
            // JSON but terminate a line in some JavaScript contexts. Escaping
            // them is semantically identical and removes the hazard for any
            // consumer that embeds the output in a script context.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Escape a string as a JSON literal.
#[must_use]
pub fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_string(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::parse::parse_str;
    use crate::value::{array, object};

    #[test]
    fn scalars() {
        assert_eq!(to_string(&Value::Null), "null");
        assert_eq!(to_string(&Value::Bool(true)), "true");
        assert_eq!(to_string(&Value::Bool(false)), "false");
        assert_eq!(to_string(&Value::from(0i64)), "0");
        assert_eq!(to_string(&Value::from(42i64)), "42");
        assert_eq!(to_string(&Value::from(-42i64)), "-42");
        assert_eq!(to_string(&Value::from(i64::MAX)), "9223372036854775807");
        assert_eq!(to_string(&Value::from(i64::MIN)), "-9223372036854775808");
        assert_eq!(to_string(&Value::from(1.5f64)), "1.5");
        assert_eq!(to_string(&Value::from("hi")), "\"hi\"");
    }

    #[test]
    fn structures_are_compact() {
        let v = object(vec![
            ("a", array(vec![Value::from(1i64), Value::from(2i64)])),
            ("b", Value::Null),
        ]);
        assert_eq!(to_string(&v), r#"{"a":[1,2],"b":null}"#);
        assert_eq!(to_string(&Value::Array(vec![])), "[]");
        assert_eq!(to_string(&Value::Object(Object::new())), "{}");
    }

    #[test]
    fn escapes_are_minimal_and_correct() {
        assert_eq!(escape_string("a\"b"), r#""a\"b""#);
        assert_eq!(escape_string("a\\b"), r#""a\\b""#);
        assert_eq!(escape_string("a\nb"), r#""a\nb""#);
        assert_eq!(escape_string("a\tb"), r#""a\tb""#);
        assert_eq!(escape_string("a\rb"), r#""a\rb""#);
        assert_eq!(escape_string("\u{8}\u{c}"), r#""\b\f""#);
        // Expected `\uXXXX` forms are assembled at runtime rather than written
        // as literals, for the same reason as in the parser tests: a literal
        // escape can be rewritten into the character it denotes by a text
        // processing step, leaving a test that no longer tests anything.
        let bs = '\u{5c}'.to_string(); // REVERSE SOLIDUS
        let esc = |body: &str| format!("\"{}\"", body.replace('~', &bs));
        assert_eq!(escape_string("\u{0}"), esc("~u0000"));
        assert_eq!(escape_string("\u{1}"), esc("~u0001"));
        assert_eq!(escape_string("\u{1e}"), esc("~u001e"));
        assert_eq!(escape_string("\u{1f}"), esc("~u001f"));
        // 0x7F (DEL) is not a C0 control character and is emitted bare.
        assert_eq!(escape_string("\u{7f}"), "\"\u{7f}\"");
        // Forward slash must not be escaped: it is legal bare, and escaping it
        // changes byte-for-byte comparisons against provider expectations.
        assert_eq!(escape_string("a/b"), r#""a/b""#);
        // Non-ASCII stays as UTF-8.
        assert_eq!(escape_string("héllo 😀"), "\"héllo 😀\"");
        // U+2028 and U+2029 are escaped defensively; see `write_string`.
        assert_eq!(escape_string("\u{2028}"), esc("~u2028"));
        assert_eq!(escape_string("\u{2029}"), esc("~u2029"));
    }

    #[test]
    fn roundtrips_through_the_parser() {
        let inputs = [
            r#"{"a":1,"b":[true,false,null],"c":{"d":"e"}}"#,
            r#"[1,-2,3.5,"x"]"#,
            r#"{"unicode":"héllo 😀 مرحبا"}"#,
            r#"{"esc":"a\"b\\c\nd"}"#,
            "[]",
            "{}",
            "0",
            r#""""#,
        ];
        for input in inputs {
            let v = parse_str(input, &Limits::DEFAULT).unwrap();
            let s = to_string(&v);
            let v2 = parse_str(&s, &Limits::DEFAULT).unwrap();
            assert_eq!(v, v2, "value changed across roundtrip for {input}");
            assert_eq!(s, input, "serialization is not byte-stable for {input}");
        }
    }

    #[test]
    fn float_output_is_parseable() {
        for f in [
            0.0f64,
            1.0,
            -1.0,
            0.1,
            1e300,
            1e-300,
            f64::MAX,
            f64::MIN,
            f64::MIN_POSITIVE,
        ] {
            let s = to_string(&Value::from(f));
            let back = parse_str(&s, &Limits::DEFAULT)
                .unwrap_or_else(|e| panic!("{f} serialized as {s} did not reparse: {e}"));
            assert_eq!(back.as_f64().unwrap(), f, "roundtrip changed {f}");
        }
    }

    #[test]
    fn non_finite_degrades_to_null_rather_than_invalid_json() {
        for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let s = to_string(&Value::from(f));
            assert_eq!(s, "null");
            assert!(parse_str(&s, &Limits::DEFAULT).is_ok());
        }
    }

    #[test]
    fn canonical_sorts_recursively_and_is_stable() {
        let v = object(vec![
            ("z", Value::from(1i64)),
            ("a", object(vec![("y", Value::from(2i64)), ("b", Value::from(3i64))])),
            ("m", array(vec![object(vec![("q", Value::Null), ("p", Value::Null)])])),
        ]);
        let c = to_canonical_string(&v);
        assert_eq!(c, r#"{"a":{"b":3,"y":2},"m":[{"p":null,"q":null}],"z":1}"#);

        // Reordering the input must not change canonical output: this is what
        // makes a configuration digest meaningful.
        let v2 = object(vec![
            ("m", array(vec![object(vec![("p", Value::Null), ("q", Value::Null)])])),
            ("a", object(vec![("b", Value::from(3i64)), ("y", Value::from(2i64))])),
            ("z", Value::from(1i64)),
        ]);
        assert_eq!(to_canonical_string(&v2), c);

        // The compact form preserves order and therefore differs.
        assert_ne!(to_string(&v), to_string(&v2));
    }

    #[test]
    fn canonical_does_not_mutate_the_input() {
        let v = object(vec![("z", Value::from(1i64)), ("a", Value::from(2i64))]);
        let before = to_string(&v);
        let _ = to_canonical_string(&v);
        assert_eq!(to_string(&v), before);
    }

    #[test]
    fn write_to_appends() {
        let mut buf = String::from("data: ");
        write_to(&mut buf, &object(vec![("a", Value::from(1i64))]));
        buf.push_str("\n\n");
        assert_eq!(buf, "data: {\"a\":1}\n\n");
    }

    #[test]
    fn integer_formatter_matches_std() {
        for v in [
            0i64,
            1,
            -1,
            9,
            10,
            -10,
            99,
            100,
            12345,
            -12345,
            i64::MAX,
            i64::MIN,
        ] {
            assert_eq!(itoa(v), v.to_string(), "itoa({v})");
        }
    }
}
