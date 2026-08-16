//! `Sensitive<T>`: the general-purpose redacting carrier.
//!
//! Specification 18.2: "`Sensitive<T>` implements redacted `Debug`/`Display`
//! and is not `Clone` unless justified."
//!
//! Specification 10 makes authorization headers, cookies, API keys, code,
//! prompts, tool arguments, and provider bodies sensitive by default. The point
//! of the wrapper is that the *default* rendering of such a value is safe:
//! a developer who adds a value to a log line, a trace, or a panic message gets
//! `[redacted]` unless they went out of their way to unwrap it.

use core::fmt;

/// A value whose contents must never reach a log, trace, error, or crash dump.
///
/// Not `Clone` by design. Duplicating sensitive material should be a visible
/// act in review; use [`Sensitive::cloned`] where it is genuinely needed and
/// the reason is stated at the call site.
pub struct Sensitive<T> {
    value: T,
    /// A short, non-secret label describing what kind of value this is, so that
    /// redacted output is still diagnosable: `[redacted api_key]` tells an
    /// operator which field was involved without disclosing it.
    kind: &'static str,
}

impl<T> Sensitive<T> {
    /// Wrap a value with a non-secret kind label.
    pub const fn new(value: T, kind: &'static str) -> Self {
        Self { value, kind }
    }

    /// Borrow the inner value.
    ///
    /// Named `expose` so that every read is greppable and reviewable.
    pub const fn expose(&self) -> &T {
        &self.value
    }

    /// Mutably borrow the inner value.
    pub const fn expose_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consume the wrapper and yield the inner value.
    pub fn into_inner(self) -> T {
        self.value
    }

    /// The non-secret kind label.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Map to another sensitive value, keeping the label.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sensitive<U> {
        Sensitive {
            value: f(self.value),
            kind: self.kind,
        }
    }
}

impl<T: Clone> Sensitive<T> {
    /// Explicitly duplicate the value.
    ///
    /// The name is deliberately not `clone`: `#[derive(Clone)]` on a containing
    /// struct will not silently copy secret material, because `Sensitive` does
    /// not implement `Clone`.
    #[must_use]
    pub fn cloned(&self) -> Self {
        Self {
            value: self.value.clone(),
            kind: self.kind,
        }
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted {}]", self.kind)
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted {}]", self.kind)
    }
}

/// A string that is capped and redacted when rendered.
///
/// Specification 17 requires capped log fields. Where a value is not secret but
/// is attacker-influenced — an upstream error message, a model name echoed back
/// — this type bounds what can reach a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped {
    text: String,
    truncated: bool,
}

impl Capped {
    /// Truncate `text` to at most `max` bytes, on a character boundary.
    #[must_use]
    pub fn new(text: &str, max: usize) -> Self {
        if text.len() <= max {
            return Self {
                text: text.to_owned(),
                truncated: false,
            };
        }
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            text: text[..end].to_owned(),
            truncated: true,
        }
    }

    /// Truncate to the standard log field cap of 256 bytes.
    #[must_use]
    pub fn log_field(text: &str) -> Self {
        Self::new(text, 256)
    }

    /// The truncated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether truncation occurred.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Display for Capped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)?;
        if self.truncated {
            f.write_str("…")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = Sensitive::new("sk-live-abcdef123456".to_owned(), "api_key");
        assert_eq!(format!("{s:?}"), "[redacted api_key]");
        assert_eq!(format!("{s}"), "[redacted api_key]");
        assert!(!format!("{s:?}").contains("sk-live"));
    }

    #[test]
    fn redaction_survives_being_nested_in_a_struct() {
        // The property that matters: a developer deriving Debug on a struct
        // containing a secret gets redacted output for free.
        #[derive(Debug)]
        struct Credential {
            id: &'static str,
            secret: Sensitive<String>,
        }
        let c = Credential {
            id: "cred_1",
            secret: Sensitive::new("super-secret-value".to_owned(), "provider_credential"),
        };
        let rendered = format!("{c:?}");
        assert!(rendered.contains("cred_1"));
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("[redacted provider_credential]"));
    }

    #[test]
    fn expose_returns_the_value() {
        let s = Sensitive::new(vec![1u8, 2, 3], "key_material");
        assert_eq!(s.expose(), &vec![1u8, 2, 3]);
        assert_eq!(s.kind(), "key_material");
        assert_eq!(s.into_inner(), vec![1u8, 2, 3]);
    }

    #[test]
    fn map_preserves_the_label() {
        let s = Sensitive::new("abc".to_owned(), "prompt");
        let t = s.map(|v| v.len());
        assert_eq!(t.kind(), "prompt");
        assert_eq!(*t.expose(), 3);
        assert_eq!(format!("{t:?}"), "[redacted prompt]");
    }

    #[test]
    fn capped_truncates_on_a_character_boundary() {
        let c = Capped::new("héllo wörld", 3);
        assert!(c.is_truncated());
        assert!(c.as_str().len() <= 3);
        // Must not split the two-byte é.
        assert!(c.as_str().is_char_boundary(c.as_str().len()));
        assert_eq!(c.to_string(), "hé…");
    }

    #[test]
    fn capped_leaves_short_text_alone() {
        let c = Capped::new("short", 256);
        assert!(!c.is_truncated());
        assert_eq!(c.to_string(), "short");
    }

    #[test]
    fn capped_handles_empty_and_exact_lengths() {
        assert_eq!(Capped::new("", 10).to_string(), "");
        assert_eq!(Capped::new("abc", 3).to_string(), "abc");
        assert!(!Capped::new("abc", 3).is_truncated());
        assert!(Capped::new("abcd", 3).is_truncated());
    }

    #[test]
    fn log_field_cap_is_256_bytes() {
        let long = "a".repeat(1000);
        let c = Capped::log_field(&long);
        assert_eq!(c.as_str().len(), 256);
        assert!(c.is_truncated());
    }
}
