//! Record schemas and typed field extraction.
//!
//! Specification 11.1: "Unknown fields are errors." That rule is what makes a
//! configuration typo fail at load rather than silently doing nothing — a
//! misspelled `stremaing=true` that is ignored leaves a target advertising a
//! capability it does not have, and the failure surfaces as a provider error in
//! production instead of a parse error at startup.

use crate::parse::{ParseLimits, Position, Record, split_list};
use core::fmt;

/// The schema for one record type.
#[derive(Debug, Clone, Copy)]
pub struct Schema {
    /// The record type.
    pub kind: &'static str,
    /// Fields that must be present.
    pub required: &'static [&'static str],
    /// Fields that may be present.
    pub optional: &'static [&'static str],
    /// Whether at most one record of this type may exist.
    pub singleton: bool,
}

/// Every record type the grammar defines.
///
/// Specification 11.1 names `provider`, `target`, `alias`, `binding`, `quota`,
/// and `role_binding`. The remaining types carry the settings, tenant, grant,
/// credential-metadata, and price-schedule the rest of the specification
/// requires.
pub const SCHEMAS: &[Schema] = &[
    Schema {
        kind: "settings",
        required: &[],
        optional: &[
            "inference_listen",
            "admin_listen",
            "metrics_listen",
            "max_body_bytes",
            "max_head_bytes",
            "allow_generic_adapter",
            "weighted_tie_break",
            "max_failure_percent",
            "default_deadline_ms",
            "max_attempts",
            "retry_budget_ms",
            "oidc_issuer",
            "oidc_client_id",
            "oidc_authorization_endpoint",
            "oidc_token_endpoint",
            "oidc_redirect_uri",
            "oidc_hosted_domains",
            "oidc_verifier_socket",
            "cors_origins",
            "session_idle_secs",
            "session_absolute_secs",
            "tls_helper_socket",
            "state_dir",
            "audit_checkpoint_interval",
            "capture_bodies",
            "keepalive_interval_ms",
            "slow_client_timeout_ms",
            "queue_timeout_ms",
            "max_connections",
            "max_requests_per_connection",
            "read_timeout_ms",
            "keepalive_timeout_ms",
            "connection_stack_kib",
            "quota_partitions",
            "fleet_enabled",
            "fleet_state_dir",
            "max_documents_per_request",
            "max_document_bytes",
            "max_inline_document_bytes",
            "default_document_token_estimate",
            "activation_effort_headroom_ms",
            "break_glass_principal",
            "break_glass_tenant",
            "break_glass_ttl_secs",
            "anonymous_principal",
            "anonymous_tenant",
            "anonymous_scopes",
            "control_socket",
        ],
        singleton: true,
    },
    Schema {
        kind: "tenant",
        required: &["id"],
        optional: &[
            "inherit_global",
            "status",
            "residency",
            "retention_days",
            "max_cost",
            "min_quality",
        ],
        singleton: false,
    },
    Schema {
        kind: "provider",
        required: &["id", "family", "scheme", "host"],
        optional: &[
            "port",
            "base_path",
            "credential",
            "enabled",
            "egress",
            "ports",
        ],
        singleton: false,
    },
    Schema {
        kind: "target",
        required: &["id", "provider", "model"],
        optional: &[
            "aliases",
            "operations",
            "capabilities",
            "modalities",
            "reasoning_efforts",
            "effort_multipliers",
            "document_token_estimate",
            "quality_class",
            "streaming",
            "tools",
            "parallel_tools",
            "json_mode",
            "structured_output",
            "reasoning",
            "prompt_caching",
            "context",
            "max_output",
            "embedding_dims",
            "tokenizer",
            "cost",
            "residency",
            "local",
            "state",
            "concurrency",
            "rps",
            "endpoint",
        ],
        singleton: false,
    },
    Schema {
        kind: "alias",
        required: &["id", "targets"],
        optional: &["family_failover", "description", "capability"],
        singleton: false,
    },
    Schema {
        kind: "binding",
        required: &["id", "scope"],
        optional: &[
            "model",
            "prefer",
            "weight",
            "deny",
            "allow",
            "pin",
            "fallback",
            "priority",
        ],
        singleton: false,
    },
    Schema {
        kind: "grant",
        required: &["scope"],
        optional: &["model", "operations", "allow"],
        singleton: false,
    },
    Schema {
        kind: "quota",
        required: &["scope"],
        optional: &[
            "input_bytes_per_second",
            "input_bytes_burst",
            "output_bytes_per_second",
            "output_bytes_burst",
            "budget",
            "budget_period",
            "operation",
            "concurrency",
            "queued",
            "rps",
            "burst",
            "tpm",
            "token_burst",
            "class",
        ],
        singleton: false,
    },
    Schema {
        kind: "role_binding",
        required: &["subject", "role"],
        optional: &[],
        singleton: false,
    },
    Schema {
        kind: "identity",
        required: &["issuer", "subject", "principal", "tenant"],
        optional: &["description"],
        singleton: false,
    },
    // Local password sign-in. A deviation from specification 9.2's four
    // authentication methods, recorded in `docs/deferred-issues.md`: it exists
    // so a deployment can be operated before an identity provider and a
    // verifier process have been set up.
    //
    // `verifier` carries the encoded PBKDF2 hash, never a password. A record
    // that named a password in cleartext would put it in the configuration
    // digest, the canonical text, every draft, and the management API's view of
    // the active configuration.
    Schema {
        kind: "local_user",
        required: &["id", "principal", "tenant", "verifier"],
        optional: &["description"],
        singleton: false,
    },
    Schema {
        kind: "group",
        required: &["id", "tenant"],
        optional: &["members", "description"],
        singleton: false,
    },
    Schema {
        kind: "credential",
        required: &["id"],
        optional: &["scope", "description", "rotates_after_days"],
        singleton: false,
    },
    // -- Fleet orchestration (specification-extension 13) ------------------
    //
    // Optional records. A configuration that declares none of them routes
    // exactly as it did before orchestration existed, which is what keeps every
    // deployed configuration valid and every deployed behaviour unchanged.
    Schema {
        kind: "fleet_agent",
        required: &["id", "socket"],
        optional: &[
            "observation_interval_ms",
            "observation_max_age_ms",
            "request_timeout_ms",
        ],
        singleton: false,
    },
    Schema {
        kind: "host",
        required: &["id", "agent", "arch"],
        optional: &[
            "status",
            "reserved_memory_bytes",
            "max_concurrent_activations",
        ],
        singleton: false,
    },
    Schema {
        kind: "accelerator",
        required: &["id", "host", "kind", "memory_bytes"],
        optional: &["pool"],
        singleton: false,
    },
    Schema {
        kind: "deployment",
        required: &["id", "target", "accelerator", "memory_bytes"],
        optional: &[
            "artifact",
            "start_ms",
            "stop_ms",
            "drain_ms",
            "probe_ms",
            "readiness",
            "min_resident_ms",
            "evictable",
            "pinned",
            "autostart",
            "retention_weight",
            "max_drainable_inflight",
            "force_stop",
        ],
        singleton: false,
    },
    Schema {
        kind: "artifact",
        required: &["id", "kind", "arch", "digest"],
        optional: &["size_bytes", "source"],
        singleton: false,
    },
    Schema {
        kind: "fleet_policy",
        required: &["scope"],
        optional: &[
            "max_activations_per_hour",
            "eviction_margin_permille",
            "max_eviction_set",
            "activation_min_demand",
            "activation_max_wait_ms",
            "reactivation_cooldown_ms",
            "flap_window_ms",
            "max_flap_cooldown_ms",
            "allow_fetch",
            "fetch_disk_headroom_bytes",
            "memory_drift_tolerance_permille",
            "adopt_unmanaged",
        ],
        singleton: false,
    },
    Schema {
        kind: "price",
        required: &["target"],
        optional: &[
            "input_per_million",
            "output_per_million",
            "cached_input_per_million",
            "currency",
            "effective_from",
        ],
        singleton: false,
    },
];

/// Look up a schema by record type.
#[must_use]
pub fn schema_for(kind: &str) -> Option<&'static Schema> {
    SCHEMAS.iter().find(|s| s.kind == kind)
}

/// A configuration error with a position and a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Machine-readable code, surfaced by the validation endpoint.
    pub code: &'static str,
    /// Human-readable message. Never contains a secret; configuration values
    /// are administrator-authored and no field here holds key material.
    pub message: String,
    /// Where the problem is.
    pub position: Position,
}

impl ConfigError {
    /// Construct.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>, position: Position) -> Self {
        Self {
            code,
            message: message.into(),
            position,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] at {}", self.message, self.code, self.position)
    }
}

impl std::error::Error for ConfigError {}

/// Check a record against its schema.
pub fn validate_record(record: &Record) -> Result<(), ConfigError> {
    let Some(schema) = schema_for(&record.kind) else {
        return Err(ConfigError::new(
            "unknown_record_type",
            format!("unknown record type '{}'", record.kind),
            record.position,
        ));
    };

    for key in record.keys() {
        let known = schema.required.contains(&key) || schema.optional.contains(&key);
        if !known {
            return Err(ConfigError::new(
                "unknown_field",
                format!("unknown field '{key}' on record '{}'", record.kind),
                record.position,
            ));
        }
    }

    for required in schema.required {
        if !record.has(required) {
            return Err(ConfigError::new(
                "missing_field",
                format!(
                    "record '{}' is missing required field '{required}'",
                    record.kind
                ),
                record.position,
            ));
        }
    }

    Ok(())
}

/// Typed field access over a record.
#[derive(Debug)]
pub struct Fields<'a> {
    record: &'a Record,
}

impl<'a> Fields<'a> {
    /// Wrap a record.
    #[must_use]
    pub const fn new(record: &'a Record) -> Self {
        Self { record }
    }

    /// The record's position.
    #[must_use]
    pub const fn position(&self) -> Position {
        self.record.position
    }

    fn err(&self, code: &'static str, message: String) -> ConfigError {
        ConfigError::new(code, message, self.record.position)
    }

    /// A required string field.
    pub fn str_field(&self, key: &str) -> Result<&'a str, ConfigError> {
        self.record.get(key).ok_or_else(|| {
            self.err(
                "missing_field",
                format!("missing required field '{key}'"),
            )
        })
    }

    /// An optional string field.
    #[must_use]
    pub fn opt_str(&self, key: &str) -> Option<&'a str> {
        self.record.get(key).filter(|v| !v.is_empty())
    }

    /// Whether the field was written at all, regardless of its value.
    ///
    /// [`Fields::opt_str`] treats an empty value as absence, which is right for
    /// most fields and wrong for any field that widens authority when omitted:
    /// `model=` and `model` being indistinguishable means a truncated line
    /// silently turns a grant for one alias into a grant for every alias. A
    /// caller reading such a field checks presence separately.
    #[must_use]
    pub fn present(&self, key: &str) -> bool {
        self.record.has(key)
    }

    /// A boolean field, defaulting when absent.
    ///
    /// Only `true` and `false` are accepted. Accepting `yes`, `on`, or `1`
    /// invites a config where `enabled=yse` silently reads as false.
    pub fn bool_field(&self, key: &str, default: bool) -> Result<bool, ConfigError> {
        match self.record.get(key) {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(other) => Err(self.err(
                "invalid_boolean",
                format!("field '{key}' must be true or false, found '{other}'"),
            )),
        }
    }

    /// An unsigned 64-bit field, defaulting when absent.
    pub fn u64_field(&self, key: &str, default: u64) -> Result<u64, ConfigError> {
        match self.record.get(key) {
            None => Ok(default),
            Some(v) => v.parse::<u64>().map_err(|_| {
                self.err(
                    "invalid_integer",
                    format!("field '{key}' must be a non-negative integer, found '{v}'"),
                )
            }),
        }
    }

    /// An unsigned 32-bit field, defaulting when absent.
    pub fn u32_field(&self, key: &str, default: u32) -> Result<u32, ConfigError> {
        let v = self.u64_field(key, u64::from(default))?;
        u32::try_from(v).map_err(|_| {
            self.err(
                "integer_out_of_range",
                format!("field '{key}' exceeds the 32-bit range"),
            )
        })
    }

    /// A signed 64-bit field, defaulting when absent.
    pub fn i64_field(&self, key: &str, default: i64) -> Result<i64, ConfigError> {
        match self.record.get(key) {
            None => Ok(default),
            Some(v) => v.parse::<i64>().map_err(|_| {
                self.err(
                    "invalid_integer",
                    format!("field '{key}' must be an integer, found '{v}'"),
                )
            }),
        }
    }

    /// A signed 32-bit field, defaulting when absent.
    pub fn i32_field(&self, key: &str, default: i32) -> Result<i32, ConfigError> {
        let v = self.i64_field(key, i64::from(default))?;
        i32::try_from(v).map_err(|_| {
            self.err(
                "integer_out_of_range",
                format!("field '{key}' exceeds the 32-bit range"),
            )
        })
    }

    /// A comma-separated list field, empty when absent.
    #[must_use]
    pub fn list_field(&self, key: &str) -> Vec<&'a str> {
        self.record.get(key).map(split_list).unwrap_or_default()
    }

    /// A field parsed by a caller-supplied function.
    pub fn parsed<T>(
        &self,
        key: &str,
        code: &'static str,
        parser: impl Fn(&str) -> Option<T>,
    ) -> Result<T, ConfigError> {
        let raw = self.str_field(key)?;
        parser(raw).ok_or_else(|| self.err(code, format!("field '{key}' has invalid value '{raw}'")))
    }

    /// An optional field parsed by a caller-supplied function.
    pub fn opt_parsed<T>(
        &self,
        key: &str,
        code: &'static str,
        parser: impl Fn(&str) -> Option<T>,
    ) -> Result<Option<T>, ConfigError> {
        match self.opt_str(key) {
            None => Ok(None),
            Some(raw) => parser(raw)
                .map(Some)
                .ok_or_else(|| self.err(code, format!("field '{key}' has invalid value '{raw}'"))),
        }
    }

    /// Raise an error anchored at this record.
    pub fn error(&self, code: &'static str, message: impl Into<String>) -> ConfigError {
        ConfigError::new(code, message, self.record.position)
    }
}

/// Parse limits used for configuration documents.
#[must_use]
pub const fn default_limits() -> ParseLimits {
    ParseLimits::DEFAULT
}

// Tests index fixtures whose shape the test itself constructs; a panic there is
// a test failure, which is the intended signal. The escalation stays in force
// for the library code above.
#[allow(clippy::indexing_slicing, clippy::as_conversions)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ParseLimits, parse};

    fn record(text: &str) -> Record {
        parse(text, &ParseLimits::DEFAULT)
            .expect("parses")
            .records
            .into_iter()
            .next()
            .expect("one record")
    }

    #[test]
    fn known_records_validate() {
        for text in [
            "provider id=p family=openai scheme=https host=api.example",
            "target id=t provider=p model=gpt",
            "alias id=a targets=t",
            "binding id=b scope=global",
            "quota scope=global",
            "role_binding subject=principal:u role=viewer",
            "settings admin_listen=127.0.0.1:9443",
            "tenant id=acme",
            "grant scope=global",
            "credential id=c",
        ] {
            let r = record(text);
            validate_record(&r).unwrap_or_else(|e| panic!("{text} rejected: {e}"));
        }
    }

    #[test]
    fn unknown_record_types_are_rejected() {
        let r = record("include path=/etc/passwd");
        let e = validate_record(&r).unwrap_err();
        assert_eq!(e.code, "unknown_record_type");
        assert!(e.message.contains("include"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // The typo that would otherwise silently disable a capability.
        let r = record("target id=t provider=p model=m stremaing=true");
        let e = validate_record(&r).unwrap_err();
        assert_eq!(e.code, "unknown_field");
        assert!(e.message.contains("stremaing"));
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        let r = record("target id=t provider=p");
        let e = validate_record(&r).unwrap_err();
        assert_eq!(e.code, "missing_field");
        assert!(e.message.contains("model"));
    }

    #[test]
    fn booleans_are_strict() {
        let r = record("target id=t provider=p model=m streaming=true");
        assert!(Fields::new(&r).bool_field("streaming", false).unwrap());

        let r = record("target id=t provider=p model=m streaming=false");
        assert!(!Fields::new(&r).bool_field("streaming", true).unwrap());

        // Absent uses the default.
        let r = record("target id=t provider=p model=m");
        assert!(Fields::new(&r).bool_field("streaming", true).unwrap());

        for bad in ["yes", "1", "TRUE", "True", "on", ""] {
            let r = record(&format!("target id=t provider=p model=m streaming=\"{bad}\""));
            let e = Fields::new(&r).bool_field("streaming", false).unwrap_err();
            assert_eq!(e.code, "invalid_boolean", "value {bad:?}");
        }
    }

    #[test]
    fn integers_are_validated_and_ranged() {
        let r = record("target id=t provider=p model=m context=128000");
        assert_eq!(Fields::new(&r).u32_field("context", 0).unwrap(), 128_000);
        assert_eq!(Fields::new(&r).u32_field("absent", 7).unwrap(), 7);

        let r = record("target id=t provider=p model=m context=notanumber");
        assert_eq!(
            Fields::new(&r).u32_field("context", 0).unwrap_err().code,
            "invalid_integer"
        );

        let r = record("target id=t provider=p model=m context=99999999999");
        assert_eq!(
            Fields::new(&r).u32_field("context", 0).unwrap_err().code,
            "integer_out_of_range"
        );

        let r = record("target id=t provider=p model=m context=-1");
        assert_eq!(
            Fields::new(&r).u32_field("context", 0).unwrap_err().code,
            "invalid_integer"
        );

        let r = record("binding id=b scope=global priority=-5");
        assert_eq!(Fields::new(&r).i32_field("priority", 0).unwrap(), -5);
    }

    #[test]
    fn lists_split_on_commas() {
        let r = record("alias id=a targets=t1,t2,t3");
        assert_eq!(Fields::new(&r).list_field("targets"), vec!["t1", "t2", "t3"]);
        assert!(Fields::new(&r).list_field("absent").is_empty());
    }

    #[test]
    fn optional_strings_treat_empty_as_absent() {
        let r = record(r#"alias id=a targets=t description="""#);
        assert_eq!(Fields::new(&r).opt_str("description"), None);
        let r = record(r#"alias id=a targets=t description="x""#);
        assert_eq!(Fields::new(&r).opt_str("description"), Some("x"));
    }

    #[test]
    fn schema_kinds_are_unique() {
        let mut kinds: Vec<&str> = SCHEMAS.iter().map(|s| s.kind).collect();
        kinds.sort_unstable();
        let before = kinds.len();
        kinds.dedup();
        assert_eq!(kinds.len(), before);
    }

    #[test]
    fn schema_fields_do_not_overlap_between_required_and_optional() {
        for s in SCHEMAS {
            for r in s.required {
                assert!(
                    !s.optional.contains(r),
                    "{}: '{r}' is both required and optional",
                    s.kind
                );
            }
        }
    }

    #[test]
    fn specification_11_1_record_types_all_exist() {
        for kind in ["provider", "target", "alias", "binding", "quota", "role_binding"] {
            assert!(schema_for(kind).is_some(), "{kind} must be defined");
        }
    }
}
