//! The native configuration grammar.
//!
//! Specification 11.1: "To avoid a parser dependency, use a deliberately small
//! line-oriented UTF-8 grammar rather than full YAML/TOML. Each record is
//! `type key=value …`; strings use JSON-style quoted escapes from the
//! in-repository parser; comments begin with `#` outside strings. Unknown
//! fields are errors. Includes, environment expansion, anchors, expressions,
//! and executable templates are forbidden."
//!
//! The forbidden list is the interesting half. Every item on it is a way for a
//! configuration file to *compute* something at load time, and each has been a
//! real vulnerability class in some deployment tool: `!!python/object` in YAML,
//! `${ENV}` expansion leaking a secret into a log, an `!include` reading
//! `/etc/shadow`, a billion-laughs anchor expansion. A grammar with no
//! evaluation step cannot have any of them.
//!
//! ```text
//! # A comment.
//! provider id=openai family=openai endpoint=https://api.openai.com:443/v1 \
//!   credential=cred_openai_primary
//! target id=openai:gpt provider=openai model=gpt-4.1 context=128000
//! alias id=code-premium targets=local:qwen,openai:gpt
//! ```

use core::fmt;

/// Where a problem was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// One-based line number.
    pub line: u32,
    /// One-based column, in characters.
    pub column: u32,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {} column {}", self.line, self.column)
    }
}

/// What went wrong while parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A record had no type token.
    EmptyRecord,
    /// The record type was not a valid identifier.
    InvalidRecordType,
    /// A token was not of the form `key=value`.
    MissingAssignment,
    /// A key was not a valid identifier.
    InvalidKey,
    /// The same key appeared twice in one record.
    DuplicateKey(String),
    /// A quoted string was not terminated.
    UnterminatedString,
    /// A `\` escape was malformed.
    InvalidEscape,
    /// A `\u` escape was not four hex digits or formed a lone surrogate.
    InvalidUnicodeEscape,
    /// A raw control character appeared in a value.
    ControlCharacter,
    /// A construct the grammar deliberately excludes was used.
    ForbiddenConstruct(&'static str),
    /// The document exceeded a size limit.
    TooLarge(&'static str),
    /// A line continuation was not followed by a line.
    DanglingContinuation,
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRecord => f.write_str("record has no type"),
            Self::InvalidRecordType => f.write_str("record type is not a valid identifier"),
            Self::MissingAssignment => f.write_str("token is not of the form key=value"),
            Self::InvalidKey => f.write_str("key is not a valid identifier"),
            Self::DuplicateKey(k) => write!(f, "duplicate key '{k}'"),
            Self::UnterminatedString => f.write_str("unterminated quoted string"),
            Self::InvalidEscape => f.write_str("invalid escape sequence"),
            Self::InvalidUnicodeEscape => f.write_str("invalid unicode escape sequence"),
            Self::ControlCharacter => f.write_str("raw control character in value"),
            Self::ForbiddenConstruct(what) => {
                write!(f, "{what} is not permitted by the configuration grammar")
            }
            Self::TooLarge(what) => write!(f, "{what} exceeds the permitted size"),
            Self::DanglingContinuation => f.write_str("line continuation at end of input"),
        }
    }
}

/// A parse failure with a position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub kind: ParseErrorKind,
    /// Where.
    pub position: Position,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.kind, self.position)
    }
}

impl std::error::Error for ParseError {}

/// Limits applied while parsing a configuration document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Maximum total document size in bytes.
    pub max_bytes: usize,
    /// Maximum number of records.
    pub max_records: usize,
    /// Maximum fields in one record.
    pub max_fields_per_record: usize,
    /// Maximum length of a single value.
    pub max_value_bytes: usize,
    /// Maximum continuation lines forming one logical record.
    pub max_continuations: u32,
}

impl ParseLimits {
    /// Defaults sized for a large but human-maintained deployment.
    pub const DEFAULT: Self = Self {
        max_bytes: 4 * 1024 * 1024,
        max_records: 20_000,
        max_fields_per_record: 64,
        max_value_bytes: 8 * 1024,
        max_continuations: 32,
    };
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One `type key=value …` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record type, for example `provider` or `binding`.
    pub kind: String,
    /// Fields in source order.
    pub fields: Vec<(String, String)>,
    /// Where the record started.
    pub position: Position,
}

impl Record {
    /// Look up a field.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether a field is present.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Field names in source order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(k, _)| k.as_str())
    }
}

/// A parsed configuration document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    /// Records in source order.
    pub records: Vec<Record>,
}

impl Document {
    /// Records of one type.
    pub fn of_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Record> + 'a {
        self.records.iter().filter(move |r| r.kind == kind)
    }

    /// Emit the canonical form: records sorted by type then by identity, fields
    /// sorted by name, values quoted only when necessary.
    ///
    /// Specification 11.1: "The management API emits canonical ordering."
    /// Specification 11 computes a digest over the activated configuration, so
    /// two documents that differ only in ordering or whitespace must produce
    /// identical bytes here.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        let mut records = self.records.clone();
        for r in &mut records {
            r.fields.sort_by(|a, b| a.0.cmp(&b.0));
        }
        records.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| identity(a).cmp(&identity(b)))
                .then_with(|| a.fields.cmp(&b.fields))
        });

        let mut out = String::new();
        for r in &records {
            out.push_str(&r.kind);
            for (k, v) in &r.fields {
                out.push(' ');
                out.push_str(k);
                out.push('=');
                out.push_str(&quote_if_needed(v));
            }
            out.push('\n');
        }
        out
    }
}

fn identity(r: &Record) -> String {
    r.get("id").unwrap_or("").to_owned()
}

/// Quote a value if it cannot be written bare.
#[must_use]
pub fn quote_if_needed(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value.chars().any(|c| {
            c.is_whitespace() || c == '"' || c == '\\' || c == '#' || u32::from(c) < 0x20
        });
    if !needs_quotes {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse a configuration document.
pub fn parse(text: &str, limits: &ParseLimits) -> Result<Document, ParseError> {
    if text.len() > limits.max_bytes {
        return Err(ParseError {
            kind: ParseErrorKind::TooLarge("document"),
            position: Position { line: 1, column: 1 },
        });
    }

    let mut doc = Document::default();
    let mut logical: String = String::new();
    let mut logical_start: u32 = 0;
    let mut continuations: u32 = 0;

    for (index, raw_line) in text.split('\n').enumerate() {
        let line_no = u32::try_from(index + 1).unwrap_or(u32::MAX);
        // A trailing CR from a CRLF file is not part of the content.
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        // A trailing backslash continues the record onto the next line. This is
        // the only multi-line construct in the grammar, and it joins text — it
        // does not evaluate anything.
        if let Some(head) = line.strip_suffix('\\') {
            if logical.is_empty() {
                logical_start = line_no;
            }
            continuations += 1;
            if continuations > limits.max_continuations {
                return Err(ParseError {
                    kind: ParseErrorKind::TooLarge("logical line"),
                    position: Position {
                        line: line_no,
                        column: 1,
                    },
                });
            }
            logical.push_str(head);
            logical.push(' ');
            continue;
        }

        if logical.is_empty() {
            logical_start = line_no;
        }
        logical.push_str(line);
        continuations = 0;

        let source = core::mem::take(&mut logical);
        if let Some(record) = parse_logical_line(&source, logical_start, limits)? {
            if doc.records.len() >= limits.max_records {
                return Err(ParseError {
                    kind: ParseErrorKind::TooLarge("record count"),
                    position: Position {
                        line: line_no,
                        column: 1,
                    },
                });
            }
            doc.records.push(record);
        }
    }

    if !logical.is_empty() {
        return Err(ParseError {
            kind: ParseErrorKind::DanglingContinuation,
            position: Position {
                line: logical_start,
                column: 1,
            },
        });
    }

    Ok(doc)
}

fn parse_logical_line(
    line: &str,
    line_no: u32,
    limits: &ParseLimits,
) -> Result<Option<Record>, ParseError> {
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    // Columns are kept as `usize` character offsets and narrowed once, inside
    // `pos`, so no site has to convert a column by hand.
    let mut tokens: Vec<(String, usize)> = Vec::new();

    let pos = |col: usize| Position {
        line: line_no,
        column: u32::try_from(col.saturating_add(1)).unwrap_or(u32::MAX),
    };

    while i < bytes.len() {
        // Skip inter-token whitespace.
        while matches!(bytes.get(i), Some(&(' ' | '\t'))) {
            i += 1;
        }
        // A `#` outside a string begins a comment; end of line ends the record.
        match bytes.get(i) {
            None | Some(&'#') => break,
            Some(_) => {}
        }

        let token_start = i;
        let mut token = String::new();

        while let Some(&c) = bytes.get(i) {
            match c {
                ' ' | '\t' => break,
                '#' => break,
                '"' => {
                    let (text, next) = parse_quoted(&bytes, i, line_no)?;
                    if text.len() > limits.max_value_bytes {
                        return Err(ParseError {
                            kind: ParseErrorKind::TooLarge("value"),
                            position: pos(token_start),
                        });
                    }
                    token.push_str(&text);
                    i = next;
                }
                c if u32::from(c) < 0x20 => {
                    return Err(ParseError {
                        kind: ParseErrorKind::ControlCharacter,
                        position: pos(i),
                    });
                }
                c => {
                    token.push(c);
                    i += 1;
                }
            }
        }

        if token.len() > limits.max_value_bytes {
            return Err(ParseError {
                kind: ParseErrorKind::TooLarge("value"),
                position: pos(token_start),
            });
        }
        tokens.push((token, token_start));
    }

    // The first token is the record type; the rest are fields. Taking it from
    // the iterator rather than `remove(0)` keeps the empty case a `None` match
    // instead of a length precondition.
    let mut tokens = tokens.into_iter();
    let Some((kind, kind_col)) = tokens.next() else {
        return Ok(None);
    };
    if kind.is_empty() {
        return Err(ParseError {
            kind: ParseErrorKind::EmptyRecord,
            position: pos(kind_col),
        });
    }
    if !is_identifier(&kind) {
        return Err(ParseError {
            kind: ParseErrorKind::InvalidRecordType,
            position: pos(kind_col),
        });
    }

    if tokens.len() > limits.max_fields_per_record {
        return Err(ParseError {
            kind: ParseErrorKind::TooLarge("field count"),
            position: pos(kind_col),
        });
    }

    let mut fields: Vec<(String, String)> = Vec::with_capacity(tokens.len());
    for (token, col) in tokens {
        let Some(eq) = token.find('=') else {
            return Err(ParseError {
                kind: ParseErrorKind::MissingAssignment,
                position: pos(col),
            });
        };
        let key = &token[..eq];
        let value = &token[eq + 1..];
        if !is_identifier(key) {
            return Err(ParseError {
                kind: ParseErrorKind::InvalidKey,
                position: pos(col),
            });
        }
        if fields.iter().any(|(k, _)| k == key) {
            return Err(ParseError {
                kind: ParseErrorKind::DuplicateKey(key.to_owned()),
                position: pos(col),
            });
        }
        fields.push((key.to_owned(), value.to_owned()));
    }

    Ok(Some(Record {
        kind,
        fields,
        position: Position {
            line: line_no,
            column: 1,
        },
    }))
}

/// Parse a JSON-style quoted string starting at `start`, returning the decoded
/// text and the index just past the closing quote.
fn parse_quoted(
    chars: &[char],
    start: usize,
    line_no: u32,
) -> Result<(String, usize), ParseError> {
    let pos = |col: usize| Position {
        line: line_no,
        column: u32::try_from(col + 1).unwrap_or(u32::MAX),
    };

    let mut i = start.saturating_add(1); // skip the opening quote
    let mut out = String::new();

    while let Some(&c) = chars.get(i) {
        match c {
            '"' => return Ok((out, i + 1)),
            '\\' => {
                i += 1;
                let Some(esc) = chars.get(i) else {
                    return Err(ParseError {
                        kind: ParseErrorKind::UnterminatedString,
                        position: pos(start),
                    });
                };
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let cp = parse_hex4(chars, i + 1, line_no, start)?;
                        i += 4;
                        if (0xD800..0xDC00).contains(&cp) {
                            // Surrogate pair.
                            if chars.get(i + 1) != Some(&'\\') || chars.get(i + 2) != Some(&'u') {
                                return Err(ParseError {
                                    kind: ParseErrorKind::InvalidUnicodeEscape,
                                    position: pos(i),
                                });
                            }
                            let low = parse_hex4(chars, i + 3, line_no, start)?;
                            if !(0xDC00..0xE000).contains(&low) {
                                return Err(ParseError {
                                    kind: ParseErrorKind::InvalidUnicodeEscape,
                                    position: pos(i),
                                });
                            }
                            i += 6;
                            let combined = 0x1_0000u32 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            let Some(c) = char::from_u32(combined) else {
                                return Err(ParseError {
                                    kind: ParseErrorKind::InvalidUnicodeEscape,
                                    position: pos(i),
                                });
                            };
                            out.push(c);
                        } else if (0xDC00..0xE000).contains(&cp) {
                            return Err(ParseError {
                                kind: ParseErrorKind::InvalidUnicodeEscape,
                                position: pos(i),
                            });
                        } else {
                            let Some(c) = char::from_u32(cp) else {
                                return Err(ParseError {
                                    kind: ParseErrorKind::InvalidUnicodeEscape,
                                    position: pos(i),
                                });
                            };
                            out.push(c);
                        }
                    }
                    _ => {
                        return Err(ParseError {
                            kind: ParseErrorKind::InvalidEscape,
                            position: pos(i),
                        });
                    }
                }
                i += 1;
            }
            c if u32::from(c) < 0x20 => {
                return Err(ParseError {
                    kind: ParseErrorKind::ControlCharacter,
                    position: pos(i),
                });
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }

    Err(ParseError {
        kind: ParseErrorKind::UnterminatedString,
        position: pos(start),
    })
}

fn parse_hex4(
    chars: &[char],
    start: usize,
    line_no: u32,
    quote_start: usize,
) -> Result<u32, ParseError> {
    let mut v = 0u32;
    for offset in 0..4 {
        let Some(c) = chars.get(start + offset) else {
            return Err(ParseError {
                kind: ParseErrorKind::UnterminatedString,
                position: Position {
                    line: line_no,
                    column: u32::try_from(quote_start + 1).unwrap_or(u32::MAX),
                },
            });
        };
        let Some(d) = c.to_digit(16) else {
            return Err(ParseError {
                kind: ParseErrorKind::InvalidUnicodeEscape,
                position: Position {
                    line: line_no,
                    column: u32::try_from(start + offset + 1).unwrap_or(u32::MAX),
                },
            });
        };
        v = (v << 4) | d;
    }
    Ok(v)
}

/// Whether `s` is a valid record type or key.
#[must_use]
pub fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
}

/// Split a comma-separated list value, trimming nothing.
///
/// An empty string is an empty list, not a list with one empty element.
#[must_use]
pub fn split_list(value: &str) -> Vec<&str> {
    if value.is_empty() {
        return Vec::new();
    }
    value.split(',').collect()
}

// Tests index fixtures whose shape the test itself constructs; a panic there is
// a test failure, which is the intended signal. The escalation stays in force
// for the library code above.
#[allow(clippy::indexing_slicing, clippy::as_conversions)]
#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Result<Document, ParseError> {
        parse(text, &ParseLimits::DEFAULT)
    }

    fn kind_of(text: &str) -> ParseErrorKind {
        p(text).expect_err("must fail").kind
    }

    #[test]
    fn parses_a_simple_record() {
        let doc = p("provider id=openai family=openai").unwrap();
        assert_eq!(doc.records.len(), 1);
        let r = &doc.records[0];
        assert_eq!(r.kind, "provider");
        assert_eq!(r.get("id"), Some("openai"));
        assert_eq!(r.get("family"), Some("openai"));
        assert_eq!(r.get("absent"), None);
        assert_eq!(r.position.line, 1);
    }

    #[test]
    fn blank_lines_and_comments_are_ignored() {
        let doc = p("# a comment\n\n   \nprovider id=a\n\t# indented comment\n").unwrap();
        assert_eq!(doc.records.len(), 1);
        assert_eq!(doc.records[0].get("id"), Some("a"));
    }

    #[test]
    fn trailing_comments_are_stripped() {
        let doc = p("provider id=a family=openai # trailing note").unwrap();
        assert_eq!(doc.records[0].fields.len(), 2);
        assert_eq!(doc.records[0].get("family"), Some("openai"));
    }

    #[test]
    fn a_hash_inside_a_quoted_value_is_content() {
        let doc = p(r#"alias id=a description="uses #1 model""#).unwrap();
        assert_eq!(doc.records[0].get("description"), Some("uses #1 model"));
    }

    #[test]
    fn quoted_values_carry_spaces_and_escapes() {
        let doc = p(r#"alias id=a description="a \"quoted\" value\nwith newline""#).unwrap();
        assert_eq!(
            doc.records[0].get("description"),
            Some("a \"quoted\" value\nwith newline")
        );
    }

    #[test]
    fn unicode_escapes_decode() {
        // Assembled at runtime so the source file contains no literal escape a
        // text-processing step could rewrite.
        let bs = '\u{5c}'.to_string();
        let text = format!("alias id=a d=\"{bs}u0041{bs}u00e9\"");
        assert_eq!(p(&text).unwrap().records[0].get("d"), Some("Aé"));

        let text = format!("alias id=a d=\"{bs}ud83d{bs}ude00\"");
        assert_eq!(p(&text).unwrap().records[0].get("d"), Some("😀"));
    }

    #[test]
    fn lone_surrogates_are_rejected() {
        let bs = '\u{5c}'.to_string();
        assert_eq!(
            kind_of(&format!("alias id=a d=\"{bs}ud83d\"")),
            ParseErrorKind::InvalidUnicodeEscape
        );
        assert_eq!(
            kind_of(&format!("alias id=a d=\"{bs}ude00\"")),
            ParseErrorKind::InvalidUnicodeEscape
        );
        assert_eq!(
            kind_of(&format!("alias id=a d=\"{bs}uZZZZ\"")),
            ParseErrorKind::InvalidUnicodeEscape
        );
    }

    #[test]
    fn bad_escapes_are_rejected() {
        let bs = '\u{5c}'.to_string();
        assert_eq!(
            kind_of(&format!("alias id=a d=\"{bs}x41\"")),
            ParseErrorKind::InvalidEscape
        );
    }

    #[test]
    fn unterminated_strings_are_rejected() {
        assert_eq!(
            kind_of(r#"alias id=a d="never closed"#),
            ParseErrorKind::UnterminatedString
        );
    }

    #[test]
    fn control_characters_are_rejected() {
        assert_eq!(
            kind_of("alias id=a\u{7}b"),
            ParseErrorKind::ControlCharacter
        );
        assert_eq!(
            kind_of("alias id=\"a\u{0}b\""),
            ParseErrorKind::ControlCharacter
        );
    }

    #[test]
    fn line_continuations_join_records() {
        let doc = p("provider id=openai \\\n  family=openai \\\n  enabled=true\n").unwrap();
        assert_eq!(doc.records.len(), 1);
        assert_eq!(doc.records[0].get("enabled"), Some("true"));
        assert_eq!(doc.records[0].position.line, 1);
    }

    #[test]
    fn dangling_continuation_is_rejected() {
        assert_eq!(
            kind_of("provider id=a \\"),
            ParseErrorKind::DanglingContinuation
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        // Two spellings of the same key is exactly the ambiguity the strict
        // JSON parser also refuses: two readers could disagree.
        assert_eq!(
            kind_of("provider id=a id=b"),
            ParseErrorKind::DuplicateKey("id".to_owned())
        );
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert_eq!(kind_of("provider bare_token"), ParseErrorKind::MissingAssignment);
        assert_eq!(kind_of("Provider id=a"), ParseErrorKind::InvalidRecordType);
        assert_eq!(kind_of("provider ID=a"), ParseErrorKind::InvalidKey);
        assert_eq!(kind_of("provider 1bad=a"), ParseErrorKind::InvalidKey);
        assert_eq!(kind_of("provider -bad=a"), ParseErrorKind::InvalidKey);
        assert_eq!(kind_of("1provider id=a"), ParseErrorKind::InvalidRecordType);
    }

    // -- The forbidden constructs -------------------------------------------

    #[test]
    fn there_is_no_environment_expansion() {
        // The grammar has no evaluation step at all, so `${HOME}` is simply a
        // literal value. This test pins that behaviour: a future "convenience"
        // that expands it would be a secret-exfiltration primitive.
        let doc = p("provider id=a token=${SECRET_TOKEN}").unwrap();
        assert_eq!(doc.records[0].get("token"), Some("${SECRET_TOKEN}"));

        let doc = p("provider id=a token=$SECRET").unwrap();
        assert_eq!(doc.records[0].get("token"), Some("$SECRET"));
    }

    #[test]
    fn there_is_no_include_directive() {
        // `include` is not a known record type; the schema layer rejects it,
        // and the parser treats it as an ordinary record with no special
        // meaning. Nothing here opens a file.
        let doc = p("include path=/etc/shadow").unwrap();
        assert_eq!(doc.records[0].kind, "include");
        assert_eq!(doc.records[0].get("path"), Some("/etc/shadow"));
    }

    #[test]
    fn there_are_no_anchors_or_references() {
        let doc = p("provider id=a ref=*anchor other=&anchor").unwrap();
        assert_eq!(doc.records[0].get("ref"), Some("*anchor"));
        assert_eq!(doc.records[0].get("other"), Some("&anchor"));
    }

    #[test]
    fn there_are_no_expressions_or_templates() {
        let doc = p(r#"provider id=a expr="{{ 1 + 1 }}""#).unwrap();
        assert_eq!(doc.records[0].get("expr"), Some("{{ 1 + 1 }}"));
    }

    #[test]
    fn there_are_no_type_tags() {
        let doc = p("provider id=a v=!!python/object:os.system").unwrap();
        assert_eq!(doc.records[0].get("v"), Some("!!python/object:os.system"));
    }

    // -- Limits --------------------------------------------------------------

    #[test]
    fn document_size_is_bounded() {
        let limits = ParseLimits {
            max_bytes: 32,
            ..ParseLimits::DEFAULT
        };
        let text = "provider id=".to_owned() + &"a".repeat(100);
        assert_eq!(
            parse(&text, &limits).unwrap_err().kind,
            ParseErrorKind::TooLarge("document")
        );
    }

    #[test]
    fn record_count_is_bounded() {
        let limits = ParseLimits {
            max_records: 2,
            ..ParseLimits::DEFAULT
        };
        let text = "provider id=a\nprovider id=b\nprovider id=c\n";
        assert_eq!(
            parse(text, &limits).unwrap_err().kind,
            ParseErrorKind::TooLarge("record count")
        );
    }

    #[test]
    fn field_count_and_value_size_are_bounded() {
        let limits = ParseLimits {
            max_fields_per_record: 2,
            max_value_bytes: 8,
            ..ParseLimits::DEFAULT
        };
        assert_eq!(
            parse("provider a=1 b=2 c=3", &limits).unwrap_err().kind,
            ParseErrorKind::TooLarge("field count")
        );
        let long = format!("provider id={}", "a".repeat(64));
        assert_eq!(
            parse(&long, &limits).unwrap_err().kind,
            ParseErrorKind::TooLarge("value")
        );
    }

    #[test]
    fn continuation_count_is_bounded() {
        let limits = ParseLimits {
            max_continuations: 3,
            ..ParseLimits::DEFAULT
        };
        let text = "provider \\\n".repeat(10) + "id=a\n";
        assert_eq!(
            parse(&text, &limits).unwrap_err().kind,
            ParseErrorKind::TooLarge("logical line")
        );
    }

    // -- Canonical form ------------------------------------------------------

    #[test]
    fn canonical_form_is_order_independent() {
        let a = p("target id=t2 provider=p\nprovider id=p family=openai\ntarget id=t1 provider=p")
            .unwrap();
        let b = p("provider id=p family=openai\ntarget id=t1 provider=p\ntarget id=t2 provider=p")
            .unwrap();
        assert_eq!(a.to_canonical_string(), b.to_canonical_string());
        assert_eq!(
            a.to_canonical_string(),
            "provider family=openai id=p\ntarget id=t1 provider=p\ntarget id=t2 provider=p\n"
        );
    }

    #[test]
    fn canonical_form_is_field_order_independent() {
        let a = p("provider id=p family=openai enabled=true").unwrap();
        let b = p("provider enabled=true family=openai id=p").unwrap();
        assert_eq!(a.to_canonical_string(), b.to_canonical_string());
    }

    #[test]
    fn canonical_form_is_whitespace_and_comment_independent() {
        let a = p("provider id=p family=openai").unwrap();
        let b = p("# header\n\nprovider   id=p    family=openai   # note\n\n").unwrap();
        assert_eq!(a.to_canonical_string(), b.to_canonical_string());
    }

    #[test]
    fn canonical_form_reparses_to_the_same_document() {
        let original = p(concat!(
            "provider id=p family=openai\n",
            "alias id=a description=\"has spaces and a # hash\"\n",
            "target id=t provider=p model=gpt-4.1\n",
        ))
        .unwrap();
        let canonical = original.to_canonical_string();
        let reparsed = p(&canonical).unwrap();
        assert_eq!(reparsed.to_canonical_string(), canonical);
        assert_eq!(
            reparsed
                .of_kind("alias")
                .next()
                .and_then(|r| r.get("description")),
            Some("has spaces and a # hash")
        );
    }

    #[test]
    fn quoting_round_trips_awkward_values() {
        for value in [
            "simple",
            "has space",
            "has\"quote",
            "has\\backslash",
            "has#hash",
            "has\nnewline",
            "has\ttab",
            "",
            "héllo 😀",
        ] {
            let text = format!("alias id=a v={}", quote_if_needed(value));
            let doc = p(&text).unwrap_or_else(|e| panic!("{value:?} produced {text:?}: {e}"));
            assert_eq!(doc.records[0].get("v"), Some(value), "value {value:?}");
        }
    }

    #[test]
    fn list_splitting() {
        assert_eq!(split_list("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(split_list("a"), vec!["a"]);
        assert_eq!(split_list(""), Vec::<&str>::new());
        assert_eq!(split_list("a,"), vec!["a", ""]);
    }

    #[test]
    fn positions_point_at_the_problem() {
        let err = p("provider id=a\ntarget bad_token\n").unwrap_err();
        assert_eq!(err.position.line, 2);
        assert_eq!(err.kind, ParseErrorKind::MissingAssignment);
    }

    #[test]
    fn crlf_files_parse_identically() {
        let unix = p("provider id=a\ntarget id=b provider=a\n").unwrap();
        let dos = p("provider id=a\r\ntarget id=b provider=a\r\n").unwrap();
        assert_eq!(unix, dos);
    }

    #[test]
    fn identifier_rules() {
        assert!(is_identifier("provider"));
        assert!(is_identifier("max_output_tokens"));
        assert!(is_identifier("a1"));
        assert!(!is_identifier(""));
        assert!(!is_identifier("Provider"));
        assert!(!is_identifier("1a"));
        assert!(!is_identifier("_a"));
        assert!(!is_identifier("a-b"));
        assert!(!is_identifier("a.b"));
        assert!(!is_identifier(&"a".repeat(65)));
    }
}
