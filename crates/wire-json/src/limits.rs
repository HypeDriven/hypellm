//! Parser limits.
//!
//! Specification 3.2 requires explicit maxima before allocation: JSON depth 64
//! levels and string length 8 MiB by default, with endpoint-specific body
//! limits. Every parse call names the limit set it is operating under, so a
//! reviewer can see at the call site what an attacker is bounded by.

/// Bounds applied while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth of arrays and objects.
    pub max_depth: u32,
    /// Maximum decoded length of any single string value, in bytes.
    pub max_string_bytes: usize,
    /// Maximum total input length, in bytes.
    pub max_input_bytes: usize,
    /// Maximum number of elements in any single array.
    pub max_array_items: usize,
    /// Maximum number of entries in any single object.
    pub max_object_entries: usize,
    /// Reject objects containing the same key twice.
    ///
    /// Duplicate keys are a parser-differential hazard: if the router honours
    /// the first occurrence and an upstream honours the last, a caller can make
    /// the two disagree about the model, the tool schema, or the stream flag.
    /// The router refuses the ambiguity instead of picking a side.
    pub reject_duplicate_keys: bool,
}

impl Limits {
    /// Default data-plane limits (specification 3.2).
    pub const DEFAULT: Self = Self {
        max_depth: 64,
        max_string_bytes: 8 * 1024 * 1024,
        max_input_bytes: 16 * 1024 * 1024,
        max_array_items: 100_000,
        max_object_entries: 10_000,
        reject_duplicate_keys: true,
    };

    /// Tight limits for control-plane documents and small payloads such as
    /// OIDC token responses, provider error bodies, and management requests.
    pub const SMALL: Self = Self {
        max_depth: 32,
        max_string_bytes: 64 * 1024,
        max_input_bytes: 1024 * 1024,
        max_array_items: 10_000,
        max_object_entries: 2_000,
        reject_duplicate_keys: true,
    };

    /// Limits for a single decoded streaming event from an upstream provider.
    /// Specification 14 requires bounded event size.
    pub const STREAM_EVENT: Self = Self {
        max_depth: 32,
        max_string_bytes: 1024 * 1024,
        max_input_bytes: 2 * 1024 * 1024,
        max_array_items: 4_096,
        max_object_entries: 512,
        reject_duplicate_keys: true,
    };

    /// Narrow the input bound, keeping every other limit.
    #[must_use]
    pub const fn with_max_input_bytes(mut self, bytes: usize) -> Self {
        self.max_input_bytes = bytes;
        self
    }

    /// Narrow the depth bound.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_specification() {
        assert_eq!(Limits::DEFAULT.max_depth, 64);
        assert_eq!(Limits::DEFAULT.max_string_bytes, 8 * 1024 * 1024);
        assert_eq!(Limits::DEFAULT.max_input_bytes, 16 * 1024 * 1024);
        assert!(Limits::DEFAULT.reject_duplicate_keys);
    }

    #[test]
    fn narrowing_preserves_other_fields() {
        let l = Limits::DEFAULT.with_max_input_bytes(1024).with_max_depth(4);
        assert_eq!(l.max_input_bytes, 1024);
        assert_eq!(l.max_depth, 4);
        assert_eq!(l.max_string_bytes, Limits::DEFAULT.max_string_bytes);
    }
}
