//! Identifier newtypes.
//!
//! Every identifier in the domain model (specification 5) gets its own type.
//! The router routinely holds a tenant id, a principal id, a target id, and a
//! provider id in the same scope; making them structurally distinct means a
//! transposition is a compile error rather than a cross-tenant lookup.
//!
//! Identifiers are validated on construction: they appear in configuration, in
//! state keys, in audit records, and in metric labels, so an unconstrained
//! string would be an injection surface in all four.

use core::fmt;

/// Why an identifier was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded the permitted length.
    TooLong,
    /// The identifier contained a character outside the permitted alphabet.
    InvalidCharacter,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "identifier is empty",
            Self::TooLong => "identifier is too long",
            Self::InvalidCharacter => {
                "identifier contains a character outside [A-Za-z0-9._:-]"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for IdError {}

/// Maximum length of any identifier.
pub const MAX_ID_LEN: usize = 128;

/// The permitted alphabet.
///
/// Deliberately excludes `/`, whitespace, quotes, and control characters:
/// identifiers are concatenated into store keys and printed into the native
/// configuration grammar and into newline-delimited logs, and every one of
/// those contexts has a delimiter that must not appear inside a value.
fn validate(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > MAX_ID_LEN {
        return Err(IdError::TooLong);
    }
    for b in s.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':');
        if !ok {
            return Err(IdError::InvalidCharacter);
        }
    }
    Ok(())
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident, $label:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap.
            pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
                let s = s.into();
                validate(&s)?;
                Ok(Self(s))
            }

            /// Borrow as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the inner `String`.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }

            /// The kind label used in diagnostics.
            #[must_use]
            pub const fn kind() -> &'static str {
                $label
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $label, self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id!(
    /// A tenant. Present in every state key (specification 10.1: cross-tenant
    /// access control).
    TenantId,
    "tenant"
);
define_id!(
    /// A principal: human, service account, API key, or workload identity.
    PrincipalId,
    "principal"
);
define_id!(
    /// A group used for policy binding.
    GroupId,
    "group"
);
define_id!(
    /// A provider such as `openai` or `local-llamacpp`.
    ProviderId,
    "provider"
);
define_id!(
    /// A concrete provider/model/endpoint tuple.
    TargetId,
    "target"
);
define_id!(
    /// A client-visible model alias.
    AliasId,
    "alias"
);
define_id!(
    /// An opaque handle to a provider credential. Never the secret itself.
    CredentialRef,
    "credential_ref"
);
define_id!(
    /// A routing policy document.
    PolicyId,
    "policy"
);
define_id!(
    /// A priority binding within a policy.
    BindingId,
    "binding"
);
define_id!(
    /// An API key record. The prefix that identifies which key was presented,
    /// never the secret.
    KeyId,
    "key"
);
define_id!(
    /// A fleet agent: the out-of-process actuator that owns a set of hosts.
    ///
    /// Names a configured socket, never an address. See `hypellm-fleet`.
    AgentId,
    "agent"
);
define_id!(
    /// A machine in the managed fleet.
    ///
    /// Administrator-configured. No client-supplied value ever becomes one:
    /// the identifier crosses the agent socket, and the agent resolves it
    /// against its own allowlist to reach an actual host.
    HostId,
    "host"
);
define_id!(
    /// One accelerator on a host, as the agent addresses it.
    ///
    /// Globally unique rather than unique-within-host, because a `deployment`
    /// record names an accelerator without repeating its host. A machine with
    /// two very different GPUs — the fleet has one — needs two distinguishable
    /// identifiers anyway, so the constraint costs nothing and removes a whole
    /// class of "which host's device 1?" mistake.
    AcceleratorId,
    "accelerator"
);
define_id!(
    /// The placement of one routable target onto one accelerator.
    ///
    /// The only fleet identifier that crosses the agent socket as part of a
    /// mutating verb.
    DeploymentId,
    "deployment"
);
define_id!(
    /// A distributable model or image, content-addressed by digest.
    ArtifactId,
    "artifact"
);
define_id!(
    /// A memory budget shared by one or more accelerators.
    ///
    /// Unified memory is modelled by giving an accelerator and its host the
    /// same pool, so a resident model correctly reduces host RAM availability.
    PoolId,
    "pool"
);
define_id!(
    /// One router's claim on a piece of fleet work.
    ///
    /// Router-generated, durable, and idempotent at the agent: re-sending a
    /// verb under the same lease returns the same activation rather than
    /// starting a second one, which is what makes crash recovery tractable.
    LeaseId,
    "lease"
);
define_id!(
    /// An agent-assigned handle to one in-flight activation.
    ActivationId,
    "activation"
);

/// A 128-bit request identifier.
///
/// Specification 5.1: "128-bit random or validated client id; never used as
/// authorization." It is rendered as lowercase hex so that it is safe in a URL
/// path, a log field, and a metric exemplar.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u128);

impl RequestId {
    /// Wrap a raw value.
    #[must_use]
    pub const fn from_u128(v: u128) -> Self {
        Self(v)
    }

    /// The raw value, used to seed the deterministic tie-breaker
    /// (specification 6.3).
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// Parse from 32 lowercase hex characters.
    ///
    /// Client-supplied identifiers are accepted for correlation but are never
    /// treated as authorization, so the only requirement is that the value be
    /// well-formed and bounded.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.len() != 32 {
            return Err(IdError::InvalidCharacter);
        }
        let mut v: u128 = 0;
        for b in s.bytes() {
            let d = match b {
                b'0'..=b'9' => u128::from(b - b'0'),
                b'a'..=b'f' => u128::from(b - b'a') + 10,
                _ => return Err(IdError::InvalidCharacter),
            };
            v = (v << 4) | d;
        }
        Ok(Self(v))
    }

    /// Render as 32 lowercase hex characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request({:032x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_are_accepted() {
        for s in [
            "openai",
            "local-llamacpp",
            "user:42",
            "gpt-4.1_mini",
            "a",
            &"x".repeat(MAX_ID_LEN),
        ] {
            assert!(TargetId::new(s).is_ok(), "{s} should be valid");
        }
    }

    #[test]
    fn invalid_identifiers_are_rejected() {
        assert_eq!(TargetId::new("").unwrap_err(), IdError::Empty);
        assert_eq!(
            TargetId::new("x".repeat(MAX_ID_LEN + 1)).unwrap_err(),
            IdError::TooLong
        );
        for s in [
            "has space",
            "has/slash",
            "has\nnewline",
            "has\ttab",
            "has\"quote",
            "has'quote",
            "café",
            "has=equals",
            "has\0nul",
        ] {
            assert_eq!(
                TargetId::new(s).unwrap_err(),
                IdError::InvalidCharacter,
                "{s:?} should be rejected"
            );
        }
    }

    #[test]
    fn identifier_types_are_structurally_distinct() {
        // This is the point of the newtypes: the following would be a type
        // error, which is what stops a tenant id reaching a target lookup.
        let tenant = TenantId::new("acme").unwrap();
        let target = TargetId::new("acme").unwrap();
        assert_eq!(tenant.as_str(), target.as_str());
        // `assert_eq!(tenant, target)` does not compile, by construction.
        assert_eq!(TenantId::kind(), "tenant");
        assert_eq!(TargetId::kind(), "target");
    }

    #[test]
    fn debug_output_names_the_kind() {
        let t = TenantId::new("acme").unwrap();
        assert_eq!(format!("{t:?}"), "tenant(acme)");
        assert_eq!(format!("{t}"), "acme");
    }

    #[test]
    fn identifiers_order_deterministically() {
        // Specification 6 forbids inferring ordering from map iteration; ties
        // are broken by identifier, so ordering must be total and stable.
        let mut ids: Vec<TargetId> = ["c", "a", "b"]
            .iter()
            .map(|s| TargetId::new(*s).unwrap())
            .collect();
        ids.sort();
        let strs: Vec<&str> = ids.iter().map(TargetId::as_str).collect();
        assert_eq!(strs, vec!["a", "b", "c"]);
    }

    #[test]
    fn request_id_hex_roundtrip() {
        let id = RequestId::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(RequestId::parse(&hex).unwrap(), id);
        assert_eq!(id.to_string(), hex);
        assert_eq!(format!("{id:?}"), format!("request({hex})"));
    }

    #[test]
    fn request_id_zero_is_padded() {
        assert_eq!(RequestId::from_u128(0).to_hex(), "0".repeat(32));
    }

    #[test]
    fn request_id_rejects_malformed_input() {
        assert!(RequestId::parse("").is_err());
        assert!(RequestId::parse("abc").is_err());
        assert!(RequestId::parse(&"0".repeat(31)).is_err());
        assert!(RequestId::parse(&"0".repeat(33)).is_err());
        assert!(RequestId::parse(&"G".repeat(32)).is_err());
        // Uppercase is rejected so that a request id has exactly one spelling
        // and therefore one metric label and one audit key.
        assert!(RequestId::parse(&"A".repeat(32)).is_err());
    }
}
