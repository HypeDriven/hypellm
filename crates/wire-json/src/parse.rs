//! Strict RFC 8259 parser.
//!
//! Strict means: no comments, no trailing commas, no single quotes, no
//! `NaN`/`Infinity`, no leading `+`, no leading zeros, no byte-order mark, no
//! trailing content, no unescaped control characters, no lone surrogates, no
//! invalid UTF-8, and (by default) no duplicate object keys.
//!
//! Every one of those extensions is a real parser-differential: a lenient
//! router and a strict upstream can be made to disagree about the same bytes.
//! Specification 3.1 requires rejecting ambiguous input rather than normalising
//! it, so this parser fails closed.

use crate::limits::Limits;
use crate::value::{Number, Object, Value};

/// What went wrong, without echoing the input.
///
/// Specification 10 makes request bodies sensitive by default, so a parse error
/// reports a position and a category and never a fragment of the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Input exceeded [`Limits::max_input_bytes`].
    InputTooLarge,
    /// Input was empty or contained only whitespace.
    Empty,
    /// A value ended before it was complete.
    UnexpectedEnd,
    /// A byte appeared where the grammar does not allow it.
    UnexpectedByte,
    /// Content followed the top-level value.
    TrailingContent,
    /// Nesting exceeded [`Limits::max_depth`].
    DepthExceeded,
    /// A string exceeded [`Limits::max_string_bytes`].
    StringTooLong,
    /// An array exceeded [`Limits::max_array_items`].
    ArrayTooLong,
    /// An object exceeded [`Limits::max_object_entries`].
    ObjectTooLarge,
    /// The same key appeared twice in one object.
    DuplicateKey,
    /// A string contained an unescaped control character (below U+0020).
    ControlCharacterInString,
    /// A `\` escape was malformed.
    InvalidEscape,
    /// A `\u` escape was not four hex digits, or formed a lone surrogate.
    InvalidUnicodeEscape,
    /// A number did not match the JSON grammar (leading zero, leading `+`,
    /// bare `.`, missing exponent digits).
    InvalidNumber,
    /// A number was syntactically valid but overflowed to a non-finite value.
    NumberOutOfRange,
    /// A byte-order mark was present.
    ByteOrderMark,
}

impl ErrorKind {
    /// Stable machine-readable code for the client error contract.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InputTooLarge => "input_too_large",
            Self::Empty => "empty_input",
            Self::UnexpectedEnd => "unexpected_end",
            Self::UnexpectedByte => "unexpected_byte",
            Self::TrailingContent => "trailing_content",
            Self::DepthExceeded => "depth_exceeded",
            Self::StringTooLong => "string_too_long",
            Self::ArrayTooLong => "array_too_long",
            Self::ObjectTooLarge => "object_too_large",
            Self::DuplicateKey => "duplicate_key",
            Self::ControlCharacterInString => "control_character_in_string",
            Self::InvalidEscape => "invalid_escape",
            Self::InvalidUnicodeEscape => "invalid_unicode_escape",
            Self::InvalidNumber => "invalid_number",
            Self::NumberOutOfRange => "number_out_of_range",
            Self::ByteOrderMark => "byte_order_mark",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "input is not valid UTF-8",
            Self::InputTooLarge => "input exceeds the permitted size",
            Self::Empty => "input contains no JSON value",
            Self::UnexpectedEnd => "input ended inside a value",
            Self::UnexpectedByte => "unexpected character",
            Self::TrailingContent => "content after the top-level value",
            Self::DepthExceeded => "nesting depth exceeds the permitted maximum",
            Self::StringTooLong => "string exceeds the permitted length",
            Self::ArrayTooLong => "array exceeds the permitted element count",
            Self::ObjectTooLarge => "object exceeds the permitted entry count",
            Self::DuplicateKey => "object contains a duplicate key",
            Self::ControlCharacterInString => "unescaped control character in string",
            Self::InvalidEscape => "invalid escape sequence",
            Self::InvalidUnicodeEscape => "invalid unicode escape sequence",
            Self::InvalidNumber => "number does not match the JSON grammar",
            Self::NumberOutOfRange => "number is not finite",
            Self::ByteOrderMark => "byte-order mark is not permitted",
        }
    }
}

/// A parse failure: a category and a byte offset, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    /// What went wrong.
    pub kind: ErrorKind,
    /// Byte offset into the input where the problem was detected.
    pub offset: usize,
}

impl core::fmt::Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind.message(), self.offset)
    }
}

impl std::error::Error for JsonError {}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    limits: Limits,
}

/// Parse a complete JSON document.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Value, JsonError> {
    if input.len() > limits.max_input_bytes {
        return Err(JsonError {
            kind: ErrorKind::InputTooLarge,
            offset: 0,
        });
    }
    if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JsonError {
            kind: ErrorKind::ByteOrderMark,
            offset: 0,
        });
    }
    if core::str::from_utf8(input).is_err() {
        return Err(JsonError {
            kind: ErrorKind::InvalidUtf8,
            offset: 0,
        });
    }

    let mut p = Parser {
        input,
        pos: 0,
        limits: *limits,
    };
    p.skip_ws();
    if p.pos >= p.input.len() {
        return Err(p.err(ErrorKind::Empty));
    }
    let value = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(p.err(ErrorKind::TrailingContent));
    }
    Ok(value)
}

/// Parse a complete JSON document from a string.
pub fn parse_str(input: &str, limits: &Limits) -> Result<Value, JsonError> {
    parse(input.as_bytes(), limits)
}

impl<'a> Parser<'a> {
    fn err(&self, kind: ErrorKind) -> JsonError {
        JsonError {
            kind,
            offset: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Input bytes between two offsets.
    ///
    /// `pos` only ever moves forward inside `input`, so every range this is
    /// asked for is in bounds. Going through `get` rather than `[..]` means an
    /// arithmetic mistake in a future edit surfaces as a parse error on that
    /// document rather than as a panic on request data (specification 18.2).
    fn span(&self, from: usize, to: usize) -> Result<&'a [u8], JsonError> {
        self.input.get(from..to).ok_or(JsonError {
            kind: ErrorKind::UnexpectedEnd,
            offset: from,
        })
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// RFC 8259 whitespace only: space, tab, LF, CR. Notably *not* vertical
    /// tab, form feed, NBSP, or any Unicode space separator.
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        match self.peek() {
            Some(b) if b == byte => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(self.err(ErrorKind::UnexpectedByte)),
            None => Err(self.err(ErrorKind::UnexpectedEnd)),
        }
    }

    fn parse_value(&mut self, depth: u32) -> Result<Value, JsonError> {
        match self.peek() {
            None => Err(self.err(ErrorKind::UnexpectedEnd)),
            Some(b'n') => self.parse_literal(b"null", Value::Null),
            Some(b't') => self.parse_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(depth),
            Some(b'{') => self.parse_object(depth),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err(ErrorKind::UnexpectedByte)),
        }
    }

    fn parse_literal(&mut self, word: &[u8], value: Value) -> Result<Value, JsonError> {
        let rest = self.input.get(self.pos..).unwrap_or(&[]);
        if rest.len() < word.len() {
            return Err(self.err(ErrorKind::UnexpectedEnd));
        }
        if !rest.starts_with(word) {
            return Err(self.err(ErrorKind::UnexpectedByte));
        }
        self.pos += word.len();
        Ok(value)
    }

    fn parse_array(&mut self, depth: u32) -> Result<Value, JsonError> {
        if depth >= self.limits.max_depth {
            return Err(self.err(ErrorKind::DepthExceeded));
        }
        self.expect(b'[')?;
        let mut items: Vec<Value> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            if items.len() >= self.limits.max_array_items {
                return Err(self.err(ErrorKind::ArrayTooLong));
            }
            let v = self.parse_value(depth + 1)?;
            items.push(v);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                Some(_) => {
                    self.pos -= 1;
                    return Err(self.err(ErrorKind::UnexpectedByte));
                }
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
            }
            // A `,` must be followed by a value: no trailing commas.
            self.skip_ws();
            if self.peek() == Some(b']') {
                return Err(self.err(ErrorKind::UnexpectedByte));
            }
        }
    }

    fn parse_object(&mut self, depth: u32) -> Result<Value, JsonError> {
        if depth >= self.limits.max_depth {
            return Err(self.err(ErrorKind::DepthExceeded));
        }
        self.expect(b'{')?;
        let mut obj = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(obj));
        }
        loop {
            self.skip_ws();
            if obj.len() >= self.limits.max_object_entries {
                return Err(self.err(ErrorKind::ObjectTooLarge));
            }
            if self.peek() != Some(b'"') {
                return Err(self.err(match self.peek() {
                    Some(_) => ErrorKind::UnexpectedByte,
                    None => ErrorKind::UnexpectedEnd,
                }));
            }
            let key_at = self.pos;
            let key = self.parse_string()?;
            if self.limits.reject_duplicate_keys && obj.contains_key(&key) {
                return Err(JsonError {
                    kind: ErrorKind::DuplicateKey,
                    offset: key_at,
                });
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value(depth + 1)?;
            obj.push(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(obj)),
                Some(_) => {
                    self.pos -= 1;
                    return Err(self.err(ErrorKind::UnexpectedByte));
                }
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
            }
            self.skip_ws();
            if self.peek() == Some(b'}') {
                return Err(self.err(ErrorKind::UnexpectedByte));
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut out: Option<String> = None;

        loop {
            let b = match self.peek() {
                Some(b) => b,
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
            };
            match b {
                b'"' => {
                    let s = match out {
                        Some(s) => s,
                        None => {
                            // No escapes were seen: the slice is already the
                            // decoded value, and it is valid UTF-8 because the
                            // whole input was validated up front.
                            let raw = self.span(start, self.pos)?;
                            String::from_utf8(raw.to_vec())
                                .map_err(|_| self.err(ErrorKind::InvalidUtf8))?
                        }
                    };
                    if s.len() > self.limits.max_string_bytes {
                        return Err(self.err(ErrorKind::StringTooLong));
                    }
                    self.pos += 1;
                    return Ok(s);
                }
                0x00..=0x1F => return Err(self.err(ErrorKind::ControlCharacterInString)),
                b'\\' => {
                    let buf = match out {
                        Some(ref mut s) => s,
                        None => {
                            let raw = self.span(start, self.pos)?;
                            let s = String::from_utf8(raw.to_vec())
                                .map_err(|_| self.err(ErrorKind::InvalidUtf8))?;
                            out = Some(s);
                            match out {
                                Some(ref mut s) => s,
                                None => return Err(self.err(ErrorKind::InvalidEscape)),
                            }
                        }
                    };
                    if buf.len() > self.limits.max_string_bytes {
                        return Err(JsonError {
                            kind: ErrorKind::StringTooLong,
                            offset: self.pos,
                        });
                    }
                    self.pos += 1; // consume '\'
                    let esc = match self.bump() {
                        Some(e) => e,
                        None => return Err(self.err(ErrorKind::UnexpectedEnd)),
                    };
                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000C}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let cp = self.parse_unicode_escape()?;
                            buf.push(cp);
                            continue;
                        }
                        _ => {
                            self.pos -= 1;
                            return Err(self.err(ErrorKind::InvalidEscape));
                        }
                    };
                    buf.push(ch);
                }
                _ => {
                    // Copy the raw byte. Multi-byte sequences are copied byte by
                    // byte; validity is guaranteed by the up-front UTF-8 check.
                    if let Some(ref mut s) = out {
                        let ch_start = self.pos;
                        let len = utf8_len(b);
                        // A lead byte whose sequence runs past the end of the
                        // input cannot be valid UTF-8; taking the tail and then
                        // its first `len` bytes reports that without an
                        // addition that could be got wrong.
                        let Some(chunk) = self.input.get(ch_start..).and_then(|tail| tail.get(..len))
                        else {
                            return Err(self.err(ErrorKind::InvalidUtf8));
                        };
                        match core::str::from_utf8(chunk) {
                            Ok(valid) => s.push_str(valid),
                            Err(_) => return Err(self.err(ErrorKind::InvalidUtf8)),
                        }
                        self.pos += len;
                    } else {
                        self.pos += 1;
                    }
                    if self.pos - start > self.limits.max_string_bytes {
                        return Err(self.err(ErrorKind::StringTooLong));
                    }
                }
            }
        }
    }

    /// Parse the four hex digits after `\u`, joining a surrogate pair when
    /// present. Lone surrogates are rejected: they cannot be encoded as UTF-8,
    /// and silently substituting U+FFFD would let two components disagree about
    /// the string's contents.
    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.parse_hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            // High surrogate: a low surrogate must follow.
            if self.peek() != Some(b'\\') {
                return Err(self.err(ErrorKind::InvalidUnicodeEscape));
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(self.err(ErrorKind::InvalidUnicodeEscape));
            }
            self.pos += 1;
            let second = self.parse_hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(self.err(ErrorKind::InvalidUnicodeEscape));
            }
            let cp = 0x1_0000u32 + ((first - 0xD800) << 10) + (second - 0xDC00);
            char::from_u32(cp).ok_or_else(|| self.err(ErrorKind::InvalidUnicodeEscape))
        } else if (0xDC00..0xE000).contains(&first) {
            // Lone low surrogate.
            Err(self.err(ErrorKind::InvalidUnicodeEscape))
        } else {
            char::from_u32(first).ok_or_else(|| self.err(ErrorKind::InvalidUnicodeEscape))
        }
    }

    /// Read exactly four hex digits.
    ///
    /// A non-hex byte is an `InvalidUnicodeEscape`, not an `UnexpectedEnd`,
    /// even when it is the closing quote: `"\u00"` is a well-formed document
    /// containing a malformed escape, and saying so points the caller at the
    /// actual defect. `UnexpectedEnd` is reserved for input that really did run
    /// out, which is the signal a caller uses to decide whether to read more
    /// bytes from a socket.
    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let mut v = 0u32;
        for i in 0..4 {
            let c = match self.input.get(self.pos + i) {
                Some(c) => *c,
                None => {
                    self.pos += i;
                    return Err(self.err(ErrorKind::UnexpectedEnd));
                }
            };
            let d = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a') + 10,
                b'A'..=b'F' => u32::from(c - b'A') + 10,
                _ => {
                    self.pos += i;
                    return Err(self.err(ErrorKind::InvalidUnicodeEscape));
                }
            };
            v = (v << 4) | d;
        }
        self.pos += 4;
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;

        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        // Integer part: `0` alone, or a non-zero digit followed by digits.
        // A leading zero such as `01` is rejected: some parsers read it as
        // octal, others as decimal.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonError {
                        kind: ErrorKind::InvalidNumber,
                        offset: start,
                    });
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(JsonError {
                    kind: ErrorKind::InvalidNumber,
                    offset: start,
                });
            }
        }

        let mut is_float = false;

        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError {
                    kind: ErrorKind::InvalidNumber,
                    offset: start,
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError {
                    kind: ErrorKind::InvalidNumber,
                    offset: start,
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        let raw = self.span(start, self.pos)?;
        let text = core::str::from_utf8(raw).map_err(|_| JsonError {
            kind: ErrorKind::InvalidUtf8,
            offset: start,
        })?;

        if !is_float {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(Value::Number(Number::Int(i)));
            }
        }
        match text.parse::<f64>() {
            Ok(f) if f.is_finite() => Ok(Value::Number(Number::Float(f))),
            Ok(_) => Err(JsonError {
                kind: ErrorKind::NumberOutOfRange,
                offset: start,
            }),
            Err(_) => Err(JsonError {
                kind: ErrorKind::InvalidNumber,
                offset: start,
            }),
        }
    }
}

const fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        // Continuation or invalid lead byte. The up-front UTF-8 validation makes
        // this unreachable for well-formed input; returning 1 keeps progress
        // bounded rather than looping.
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Value, JsonError> {
        parse_str(s, &Limits::DEFAULT)
    }

    fn kind(s: &str) -> ErrorKind {
        p(s).unwrap_err().kind
    }

    #[test]
    fn parses_scalars() {
        assert_eq!(p("null").unwrap(), Value::Null);
        assert_eq!(p("true").unwrap(), Value::Bool(true));
        assert_eq!(p("false").unwrap(), Value::Bool(false));
        assert_eq!(p("0").unwrap().as_i64(), Some(0));
        assert_eq!(p("-0").unwrap().as_i64(), Some(0));
        assert_eq!(p("42").unwrap().as_i64(), Some(42));
        assert_eq!(p("-42").unwrap().as_i64(), Some(-42));
        assert_eq!(p("1.5").unwrap().as_f64(), Some(1.5));
        assert_eq!(p("1e3").unwrap().as_f64(), Some(1000.0));
        assert_eq!(p("1E-3").unwrap().as_f64(), Some(0.001));
        assert_eq!(p(r#""hi""#).unwrap().as_str(), Some("hi"));
        assert_eq!(p(r#""""#).unwrap().as_str(), Some(""));
    }

    #[test]
    fn parses_structures() {
        let v = p(r#"{"a":[1,2,{"b":null}],"c":true}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("c").unwrap().as_bool(), Some(true));
        assert_eq!(p("[]").unwrap().as_array().unwrap().len(), 0);
        assert_eq!(p("{}").unwrap().as_object().unwrap().len(), 0);
        assert_eq!(p(" [ 1 , 2 ] ").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn integers_stay_exact_across_i64_range() {
        assert_eq!(p("9223372036854775807").unwrap().as_i64(), Some(i64::MAX));
        assert_eq!(p("-9223372036854775808").unwrap().as_i64(), Some(i64::MIN));
        // Beyond i64 the value degrades to f64 rather than being rejected,
        // because RFC 8259 permits it; callers requiring exactness use
        // `field_i64`, which then reports a type error.
        assert!(p("9223372036854775808").unwrap().as_i64().is_none());
    }

    #[test]
    fn rejects_number_extensions() {
        assert_eq!(kind("01"), ErrorKind::InvalidNumber);
        assert_eq!(kind("-01"), ErrorKind::InvalidNumber);
        assert_eq!(kind("+1"), ErrorKind::UnexpectedByte);
        assert_eq!(kind(".5"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("1."), ErrorKind::InvalidNumber);
        assert_eq!(kind("1.e3"), ErrorKind::InvalidNumber);
        assert_eq!(kind("1e"), ErrorKind::InvalidNumber);
        assert_eq!(kind("1e+"), ErrorKind::InvalidNumber);
        assert_eq!(kind("0x10"), ErrorKind::TrailingContent);
        assert_eq!(kind("Infinity"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("NaN"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("-Infinity"), ErrorKind::InvalidNumber);
        assert_eq!(kind("1e999"), ErrorKind::NumberOutOfRange);
    }

    #[test]
    fn rejects_syntax_extensions() {
        assert_eq!(kind("[1,]"), ErrorKind::UnexpectedByte);
        assert_eq!(kind(r#"{"a":1,}"#), ErrorKind::UnexpectedByte);
        assert_eq!(kind("'a'"), ErrorKind::UnexpectedByte);
        assert_eq!(kind(r#"{a:1}"#), ErrorKind::UnexpectedByte);
        assert_eq!(kind("[1 2]"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("// c\n1"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("1 /* c */"), ErrorKind::TrailingContent);
        assert_eq!(kind("{} {}"), ErrorKind::TrailingContent);
        assert_eq!(kind("1 2"), ErrorKind::TrailingContent);
        assert_eq!(kind(""), ErrorKind::Empty);
        assert_eq!(kind("   "), ErrorKind::Empty);
        assert_eq!(kind("["), ErrorKind::UnexpectedEnd);
        assert_eq!(kind(r#"{"a""#), ErrorKind::UnexpectedEnd);
        assert_eq!(kind("tru"), ErrorKind::UnexpectedEnd);
        assert_eq!(kind("trux"), ErrorKind::UnexpectedByte);
    }

    #[test]
    fn rejects_byte_order_mark() {
        assert_eq!(
            parse("\u{FEFF}{}".as_bytes(), &Limits::DEFAULT)
                .unwrap_err()
                .kind,
            ErrorKind::ByteOrderMark
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(
            parse(&[b'"', 0xFF, b'"'], &Limits::DEFAULT).unwrap_err().kind,
            ErrorKind::InvalidUtf8
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(p(r#""a\"b""#).unwrap().as_str(), Some("a\"b"));
        assert_eq!(p(r#""a\\b""#).unwrap().as_str(), Some("a\\b"));
        assert_eq!(p(r#""a\/b""#).unwrap().as_str(), Some("a/b"));
        assert_eq!(p(r#""\b\f\n\r\t""#).unwrap().as_str(), Some("\u{8}\u{c}\n\r\t"));
        // Escape sequences of the `\uXXXX` form. The expected inputs are
        // assembled at runtime rather than written as literals: a source file
        // containing a literal escape is vulnerable to a text-processing step
        // rewriting it into the character it denotes, which would silently stop
        // exercising the escape path while leaving a passing test behind.
        let bs = '\u{5c}'.to_string(); // REVERSE SOLIDUS
        let esc = |body: &str| format!("\"{}\"", body.replace('~', &bs));
        assert_eq!(p(&esc("~u0041")).unwrap().as_str(), Some("A"));
        assert_eq!(p(&esc("~u00e9")).unwrap().as_str(), Some("é"));
        assert_eq!(p(&esc("~u00E9")).unwrap().as_str(), Some("é"));
        assert_eq!(p(&esc("a~u0041b")).unwrap().as_str(), Some("aAb"));
        // A surrogate pair encodes one non-BMP code point.
        assert_eq!(p(&esc("~ud83d~ude00")).unwrap().as_str(), Some("😀"));
        assert_eq!(p(&esc("~uD83D~uDE00")).unwrap().as_str(), Some("😀"));
        // NUL is representable only via an escape.
        assert_eq!(p(&esc("~u0000")).unwrap().as_str(), Some("\u{0}"));
        // The escaped and raw spellings must decode to the same value.
        assert_eq!(p(&esc("~u00e9")).unwrap(), p("\"é\"").unwrap());
    }

    #[test]
    fn rejects_bad_escapes() {
        assert_eq!(kind(r#""\x41""#), ErrorKind::InvalidEscape);
        assert_eq!(kind(r#""\u00""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind(r#""\uZZZZ""#), ErrorKind::InvalidUnicodeEscape);
        // Lone high surrogate, lone low surrogate, high surrogate followed by a
        // non-surrogate escape, and high surrogate followed by a raw character.
        assert_eq!(kind(r#""\uD83D""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind(r#""\uDE00""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind(r#""\uD83DA""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind(r#""\uD83D\n""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind(r#""\uD83Dx""#), ErrorKind::InvalidUnicodeEscape);
        assert_eq!(kind("\"a\\\""), ErrorKind::UnexpectedEnd);
    }

    #[test]
    fn rejects_raw_control_characters_in_strings() {
        assert_eq!(kind("\"a\nb\""), ErrorKind::ControlCharacterInString);
        assert_eq!(kind("\"a\tb\""), ErrorKind::ControlCharacterInString);
        assert_eq!(kind("\"\u{0}\""), ErrorKind::ControlCharacterInString);
        // 0x7F (DEL) is not a C0 control and is permitted by RFC 8259.
        assert!(p("\"\u{7f}\"").is_ok());
    }

    #[test]
    fn multibyte_after_escape_is_preserved() {
        // Exercises the copy path taken once a string has seen an escape.
        let v = p(r#""\n héllo 😀 مرحبا""#).unwrap();
        assert_eq!(v.as_str(), Some("\n héllo 😀 مرحبا"));
    }

    #[test]
    fn duplicate_keys_rejected_by_default() {
        assert_eq!(kind(r#"{"a":1,"a":2}"#), ErrorKind::DuplicateKey);
        let lenient = Limits {
            reject_duplicate_keys: false,
            ..Limits::DEFAULT
        };
        let v = parse_str(r#"{"a":1,"a":2}"#, &lenient).unwrap();
        // First occurrence wins when the check is disabled.
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1));
    }

    #[test]
    fn depth_is_bounded() {
        // `max_depth` is the number of nesting levels permitted, so exactly
        // that many nest successfully and one more does not.
        let limits = Limits::DEFAULT.with_max_depth(3);
        assert!(parse_str("[[[1]]]", &limits).is_ok());
        assert_eq!(
            parse_str("[[[[1]]]]", &limits).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );
        assert!(parse_str(r#"{"a":{"b":{"c":1}}}"#, &limits).is_ok());
        assert_eq!(
            parse_str(r#"{"a":{"b":{"c":{"d":1}}}}"#, &limits).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );
        // Mixed nesting counts the same way.
        assert!(parse_str(r#"[{"a":[1]}]"#, &limits).is_ok());
        assert_eq!(
            parse_str(r#"[{"a":[{"b":1}]}]"#, &limits).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert_eq!(
            parse_str(&deep, &Limits::DEFAULT).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );
        let deep_obj = format!(
            "{}1{}",
            r#"{"a":"#.repeat(200),
            "}".repeat(200)
        );
        assert_eq!(
            parse_str(&deep_obj, &Limits::DEFAULT).unwrap_err().kind,
            ErrorKind::DepthExceeded
        );
    }

    #[test]
    fn size_limits_enforced() {
        let limits = Limits {
            max_input_bytes: 10,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_str("[1,2,3,4,5,6,7,8,9]", &limits).unwrap_err().kind,
            ErrorKind::InputTooLarge
        );

        let limits = Limits {
            max_string_bytes: 3,
            ..Limits::DEFAULT
        };
        assert!(parse_str(r#""abc""#, &limits).is_ok());
        assert_eq!(
            parse_str(r#""abcd""#, &limits).unwrap_err().kind,
            ErrorKind::StringTooLong
        );

        let limits = Limits {
            max_array_items: 2,
            ..Limits::DEFAULT
        };
        assert!(parse_str("[1,2]", &limits).is_ok());
        assert_eq!(
            parse_str("[1,2,3]", &limits).unwrap_err().kind,
            ErrorKind::ArrayTooLong
        );

        let limits = Limits {
            max_object_entries: 1,
            ..Limits::DEFAULT
        };
        assert!(parse_str(r#"{"a":1}"#, &limits).is_ok());
        assert_eq!(
            parse_str(r#"{"a":1,"b":2}"#, &limits).unwrap_err().kind,
            ErrorKind::ObjectTooLarge
        );
    }

    #[test]
    fn only_rfc_whitespace_is_skipped() {
        assert!(p("\t\r\n 1").is_ok());
        // Form feed and vertical tab are not JSON whitespace.
        assert_eq!(kind("\u{0c}1"), ErrorKind::UnexpectedByte);
        assert_eq!(kind("\u{0b}1"), ErrorKind::UnexpectedByte);
        // Non-breaking space is not whitespace either.
        assert_eq!(kind("\u{a0}1"), ErrorKind::UnexpectedByte);
    }

    #[test]
    fn error_never_echoes_input() {
        let err = p(r#"{"prompt":"my-secret-prompt","n":}"#).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("secret"));
        assert!(msg.contains("byte"));
    }

    #[test]
    fn offsets_point_at_the_problem() {
        let err = p("[1,2,x]").unwrap_err();
        assert_eq!(err.offset, 5);
        assert_eq!(err.kind, ErrorKind::UnexpectedByte);
    }

    #[test]
    fn error_codes_are_stable_and_distinct() {
        let all = [
            ErrorKind::InvalidUtf8,
            ErrorKind::InputTooLarge,
            ErrorKind::Empty,
            ErrorKind::UnexpectedEnd,
            ErrorKind::UnexpectedByte,
            ErrorKind::TrailingContent,
            ErrorKind::DepthExceeded,
            ErrorKind::StringTooLong,
            ErrorKind::ArrayTooLong,
            ErrorKind::ObjectTooLarge,
            ErrorKind::DuplicateKey,
            ErrorKind::ControlCharacterInString,
            ErrorKind::InvalidEscape,
            ErrorKind::InvalidUnicodeEscape,
            ErrorKind::InvalidNumber,
            ErrorKind::NumberOutOfRange,
            ErrorKind::ByteOrderMark,
        ];
        let mut codes: Vec<&str> = all.iter().map(|k| k.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "error codes must be distinct");
    }
}
