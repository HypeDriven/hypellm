//! Transport bounds.
//!
//! Specification 3.2 fixes the inbound header budget at 32 KiB by default with
//! a 64 KiB hard maximum. Everything else here exists so that no single
//! connection can make the router allocate or scan an unbounded amount before
//! the request is even authenticated.

/// Bounds applied while parsing a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes in the message head, including the request/status line and
    /// the terminating blank line.
    pub max_head_bytes: usize,
    /// Maximum number of header fields.
    pub max_header_count: usize,
    /// Maximum bytes in the request target.
    pub max_target_bytes: usize,
    /// Maximum bytes in the method token.
    pub max_method_bytes: usize,
    /// Maximum body size the endpoint will accept.
    pub max_body_bytes: u64,
    /// Maximum bytes in one chunk-size line, including extensions.
    pub max_chunk_line_bytes: usize,
    /// Maximum bytes in the trailer section.
    pub max_trailer_bytes: usize,
}

impl Limits {
    /// Hard ceiling on the head, per specification 3.2. No profile may exceed
    /// this.
    pub const HARD_MAX_HEAD_BYTES: usize = 64 * 1024;

    /// Default inbound limits.
    pub const DEFAULT: Self = Self {
        max_head_bytes: 32 * 1024,
        max_header_count: 100,
        max_target_bytes: 8 * 1024,
        max_method_bytes: 32,
        max_body_bytes: 16 * 1024 * 1024,
        max_chunk_line_bytes: 256,
        max_trailer_bytes: 4 * 1024,
    };

    /// Tighter limits for the management listener, which never carries a large
    /// body and is reachable only from the admin network.
    pub const ADMIN: Self = Self {
        max_head_bytes: 16 * 1024,
        max_header_count: 64,
        max_target_bytes: 2 * 1024,
        max_method_bytes: 16,
        max_body_bytes: 1024 * 1024,
        max_chunk_line_bytes: 128,
        max_trailer_bytes: 1024,
    };

    /// Limits applied to responses read from an upstream provider.
    ///
    /// A provider is not trusted: specification 8.2 has a dedicated
    /// `upstream_invalid_response` status for one that violates its contract.
    pub const UPSTREAM: Self = Self {
        max_head_bytes: 32 * 1024,
        max_header_count: 100,
        max_target_bytes: 8 * 1024,
        max_method_bytes: 32,
        // Non-streaming provider responses are read whole; streaming responses
        // are bounded per event by `wire_sse` rather than in total.
        max_body_bytes: 64 * 1024 * 1024,
        max_chunk_line_bytes: 256,
        max_trailer_bytes: 4 * 1024,
    };

    /// Clamp to the specification's hard maximum, so that a misconfiguration
    /// cannot raise the head budget past what the parser is reviewed for.
    #[must_use]
    pub const fn clamped(mut self) -> Self {
        if self.max_head_bytes > Self::HARD_MAX_HEAD_BYTES {
            self.max_head_bytes = Self::HARD_MAX_HEAD_BYTES;
        }
        self
    }

    /// Narrow the body bound for one endpoint.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, bytes: u64) -> Self {
        self.max_body_bytes = bytes;
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
    fn defaults_match_specification_3_2() {
        assert_eq!(Limits::DEFAULT.max_head_bytes, 32 * 1024);
        assert_eq!(Limits::HARD_MAX_HEAD_BYTES, 64 * 1024);
        assert_eq!(Limits::DEFAULT.max_body_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn clamping_enforces_the_hard_maximum() {
        let l = Limits {
            max_head_bytes: 1024 * 1024,
            ..Limits::DEFAULT
        }
        .clamped();
        assert_eq!(l.max_head_bytes, Limits::HARD_MAX_HEAD_BYTES);
        // A conforming value is left alone.
        assert_eq!(Limits::DEFAULT.clamped().max_head_bytes, 32 * 1024);
    }

    #[test]
    fn admin_profile_is_not_looser_than_default() {
        assert!(Limits::ADMIN.max_head_bytes <= Limits::DEFAULT.max_head_bytes);
        assert!(Limits::ADMIN.max_header_count <= Limits::DEFAULT.max_header_count);
        assert!(Limits::ADMIN.max_body_bytes <= Limits::DEFAULT.max_body_bytes);
    }
}
