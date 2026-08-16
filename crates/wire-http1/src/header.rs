//! Header storage and field validation.
//!
//! Names are normalised to lowercase on insert so that every lookup is a plain
//! comparison. Storage is an ordered `Vec`, not a map: order is preserved for
//! faithful forwarding, and the entry count is bounded by
//! [`crate::Limits::max_header_count`].

use crate::error::{HttpError, HttpErrorKind};

/// Headers that carry framing, authentication, or origin decisions, and that
/// therefore must appear at most once.
///
/// Specification 3.1 requires rejecting "duplicate security headers", and
/// 10.1 names request smuggling as a threat. The failure mode is always the
/// same shape: the router reads one occurrence and something else reads
/// another. Rather than defining a merge rule nobody can audit, the router
/// refuses the message.
pub const SINGLE_VALUED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "content-type",
    "authorization",
    "proxy-authorization",
    "expect",
    "upgrade",
    "cookie",
    "origin",
    "referer",
    "x-api-key",
    "anthropic-version",
    "content-encoding",
    "location",
];

/// Header fields that must never appear in a chunked trailer section.
///
/// A trailer that re-declares framing is a smuggling attempt: the head has
/// already been used to decide how many bytes the body has.
pub const FORBIDDEN_TRAILERS: &[&str] = &[
    "transfer-encoding",
    "content-length",
    "host",
    "authorization",
    "proxy-authorization",
    "trailer",
    "te",
    "expect",
    "cookie",
    "set-cookie",
    "content-encoding",
];

/// True when `b` is an RFC 9110 `tchar`, the alphabet of a header name.
#[must_use]
pub const fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

/// True when every byte of `s` is a token byte and `s` is non-empty.
#[must_use]
pub fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|b| is_token_byte(*b))
}

/// True when `b` may appear in a header field value.
///
/// Visible ASCII, space, horizontal tab, and `obs-text` (0x80-0xFF). Control
/// characters — in particular CR, LF, and NUL — are excluded, which is what
/// stops a header value from injecting a new header or terminating the head.
#[must_use]
pub const fn is_field_value_byte(b: u8) -> bool {
    matches!(b, b'\t' | b' ' | 0x21..=0x7E | 0x80..=0xFF)
}

/// True when every byte of `s` may appear in a field value.
#[must_use]
pub fn is_field_value(s: &[u8]) -> bool {
    s.iter().all(|b| is_field_value_byte(*b))
}

/// Split `line` at the first occurrence of `sep`, returning the bytes before
/// it and the bytes after it, or `None` when `sep` does not occur.
///
/// Written with slice patterns rather than index arithmetic so that neither
/// half can be an out-of-range range expression: a header line arrives from an
/// untrusted peer and a panic here would be a remote crash.
pub(crate) fn split_field(line: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let at = line.iter().position(|b| *b == sep)?;
    // `at` is an index into `line` yielded by `position`, and the byte at `at`
    // is `sep`, so the split succeeds and the tail is non-empty.
    let (name, tail) = line.split_at_checked(at)?;
    let value = tail.get(1..)?;
    Some((name, value))
}

/// An ordered, lowercase-normalised header collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// Empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Empty collection with capacity.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }

    /// Number of header entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a header, validating name and value.
    ///
    /// The name is lowercased. Returns an error rather than silently dropping
    /// or sanitising an invalid field.
    pub fn append(&mut self, name: &str, value: &str) -> Result<(), HttpError> {
        if !is_token(name.as_bytes()) {
            return Err(HttpErrorKind::InvalidHeaderName.into());
        }
        if !is_field_value(value.as_bytes()) {
            return Err(HttpErrorKind::InvalidHeaderValue.into());
        }
        let lower = name.to_ascii_lowercase();
        if SINGLE_VALUED.contains(&lower.as_str()) && self.contains(&lower) {
            return Err(HttpErrorKind::DuplicateHeader.into());
        }
        self.entries.push((lower, value.to_owned()));
        Ok(())
    }

    /// Append without the single-valued duplicate check.
    ///
    /// Only for building outbound messages where the caller controls every
    /// name, such as emitting multiple `Set-Cookie` headers.
    pub fn append_unchecked(&mut self, name: &str, value: &str) -> Result<(), HttpError> {
        if !is_token(name.as_bytes()) {
            return Err(HttpErrorKind::InvalidHeaderName.into());
        }
        if !is_field_value(value.as_bytes()) {
            return Err(HttpErrorKind::InvalidHeaderValue.into());
        }
        self.entries.push((name.to_ascii_lowercase(), value.to_owned()));
        Ok(())
    }

    /// Replace every occurrence of `name` with a single entry.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), HttpError> {
        let lower = name.to_ascii_lowercase();
        self.entries.retain(|(k, _)| *k != lower);
        self.append_unchecked(&lower, value)
    }

    /// First value for `name`, which must already be lowercase.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        debug_assert!(
            name.bytes().all(|b| !b.is_ascii_uppercase()),
            "lookup names must be lowercase"
        );
        self.entries
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// All values for `name`.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Number of entries with this name.
    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.entries.iter().filter(|(k, _)| k == name).count()
    }

    /// True when the name is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == name)
    }

    /// Remove every entry with this name.
    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|(k, _)| k != name);
    }

    /// Iterate over `(name, value)` in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// True when a comma-separated list header contains `token`,
    /// case-insensitively.
    ///
    /// Used for `Connection: close`, `Expect: 100-continue`, and
    /// `Accept-Encoding` probing.
    #[must_use]
    pub fn list_contains(&self, name: &str, token: &str) -> bool {
        self.get_all(name).any(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    }

    /// Total bytes this collection would occupy on the wire, used to bound
    /// forwarded head size.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.entries
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum()
    }
}

/// Remove optional whitespace from both ends of a field value.
///
/// RFC 9112 permits leading and trailing `OWS` around a field value and
/// requires it to be stripped before interpretation.
#[must_use]
pub fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_alphabet() {
        assert!(is_token(b"Content-Length"));
        assert!(is_token(b"x-api-key"));
        assert!(is_token(b"a!#$%&'*+-.^_`|~9"));
        assert!(!is_token(b""));
        assert!(!is_token(b"has space"));
        assert!(!is_token(b"has:colon"));
        assert!(!is_token(b"has\tteb"));
        assert!(!is_token(b"has\nnewline"));
        assert!(!is_token("héader".as_bytes()));
        assert!(!is_token(b"(paren)"));
        assert!(!is_token(b"quo\"te"));
    }

    #[test]
    fn field_value_alphabet() {
        assert!(is_field_value(b"simple"));
        assert!(is_field_value(b"with space and\ttab"));
        assert!(is_field_value(&[0x80, 0xFF])); // obs-text
        assert!(!is_field_value(b"with\rCR"));
        assert!(!is_field_value(b"with\nLF"));
        assert!(!is_field_value(&[0x00]));
        assert!(!is_field_value(&[0x1F]));
        assert!(!is_field_value(&[0x7F])); // DEL is a control character
    }

    #[test]
    fn append_and_lookup() {
        let mut h = Headers::new();
        h.append("Content-Type", "application/json").unwrap();
        h.append("Accept", "text/event-stream").unwrap();
        assert_eq!(h.get("content-type"), Some("application/json"));
        assert_eq!(h.get("accept"), Some("text/event-stream"));
        assert_eq!(h.get("missing"), None);
        assert_eq!(h.len(), 2);
        assert!(!h.is_empty());
    }

    #[test]
    fn names_are_case_insensitive() {
        let mut h = Headers::new();
        h.append("CoNtEnT-TyPe", "application/json").unwrap();
        assert_eq!(h.get("content-type"), Some("application/json"));
        assert!(h.contains("content-type"));
    }

    #[test]
    fn single_valued_duplicates_are_rejected() {
        for name in ["Content-Length", "Host", "Transfer-Encoding", "Authorization"] {
            let mut h = Headers::new();
            h.append(name, "1").unwrap();
            assert_eq!(
                h.append(name, "2").unwrap_err().kind,
                HttpErrorKind::DuplicateHeader,
                "{name} must not be repeatable"
            );
        }
    }

    #[test]
    fn multi_valued_headers_are_allowed_twice() {
        let mut h = Headers::new();
        h.append("Accept", "a").unwrap();
        h.append("Accept", "b").unwrap();
        assert_eq!(h.count("accept"), 2);
        let all: Vec<&str> = h.get_all("accept").collect();
        assert_eq!(all, vec!["a", "b"]);
        assert_eq!(h.get("accept"), Some("a"), "get returns the first value");
    }

    #[test]
    fn invalid_names_and_values_are_rejected() {
        let mut h = Headers::new();
        assert_eq!(
            h.append("bad name", "v").unwrap_err().kind,
            HttpErrorKind::InvalidHeaderName
        );
        assert_eq!(
            h.append("X-Ok", "bad\r\nInjected: yes").unwrap_err().kind,
            HttpErrorKind::InvalidHeaderValue
        );
        assert_eq!(
            h.append("X-Ok", "bad\nvalue").unwrap_err().kind,
            HttpErrorKind::InvalidHeaderValue
        );
        assert!(h.is_empty(), "rejected headers must not be stored");
    }

    #[test]
    fn set_replaces_all_occurrences() {
        let mut h = Headers::new();
        h.append("Accept", "a").unwrap();
        h.append("Accept", "b").unwrap();
        h.set("Accept", "c").unwrap();
        assert_eq!(h.count("accept"), 1);
        assert_eq!(h.get("accept"), Some("c"));
    }

    #[test]
    fn remove_deletes_every_occurrence() {
        let mut h = Headers::new();
        h.append("Accept", "a").unwrap();
        h.append("Accept", "b").unwrap();
        h.append("Other", "x").unwrap();
        h.remove("accept");
        assert_eq!(h.count("accept"), 0);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn list_contains_handles_commas_and_case() {
        let mut h = Headers::new();
        h.append("Connection", "keep-alive, Close").unwrap();
        assert!(h.list_contains("connection", "close"));
        assert!(h.list_contains("connection", "KEEP-ALIVE"));
        assert!(!h.list_contains("connection", "upgrade"));
        // A token must match wholly, not as a substring.
        let mut h2 = Headers::new();
        h2.append("Connection", "not-close").unwrap();
        assert!(!h2.list_contains("connection", "close"));
    }

    #[test]
    fn ows_trimming() {
        assert_eq!(trim_ows("  value  "), "value");
        assert_eq!(trim_ows("\tvalue\t"), "value");
        assert_eq!(trim_ows("value"), "value");
        assert_eq!(trim_ows("   "), "");
        assert_eq!(trim_ows("a b"), "a b", "interior space is preserved");
    }

    #[test]
    fn wire_len_accounts_for_separators() {
        let mut h = Headers::new();
        h.append("A", "b").unwrap();
        // "a" + ": " + "b" + CRLF
        assert_eq!(h.wire_len(), 1 + 2 + 1 + 2);
    }

    #[test]
    fn forbidden_trailer_list_covers_framing_and_auth() {
        for name in ["transfer-encoding", "content-length", "authorization", "host"] {
            assert!(FORBIDDEN_TRAILERS.contains(&name), "{name} must be forbidden");
        }
    }
}
