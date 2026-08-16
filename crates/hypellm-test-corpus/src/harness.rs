//! Versioned coding-harness compatibility profiles.
//!
//! Specification 8.1: "Because harness behavior changes, the project maintains
//! versioned profiles rather than claiming universal compatibility. Each profile
//! records required endpoints, headers, SSE details, tool-call behavior, max
//! body, cancellation method, and known limitations."
//!
//! # What these profiles are, and what they are not
//!
//! Each profile below is one row of the specification's 8.1 table, written out
//! as data. **No third-party harness has been recorded, measured, or tested
//! against this router.** These describe the classes of client the router
//! commits to serving; they do not describe any named tool's observed
//! behaviour, and they must not be read as a compatibility claim for one.
//!
//! Specification 8.1 also requires the suite to "include representative popular
//! coding harnesses selected at release time". Selecting and recording those is
//! release work that has not happened. Naming a harness here without having run
//! it would be the exact false assurance the versioning rule exists to prevent —
//! so this module names classes, and the gap is recorded in `MODULE.md`.
//!
//! # What is not checked
//!
//! Nothing binds these profiles to the router's actual route table. The tests
//! below confirm each declared endpoint is one specification 8 defines, but no
//! test starts a listener and confirms the router answers it. A profile can
//! therefore be internally consistent and still describe a deployment that does
//! not exist.
//!
//! # Versioning
//!
//! [`HarnessProfile::version`] is bumped whenever a profile's *content*
//! changes: an endpoint added or removed, a header requirement changed, a
//! limitation resolved. Consumers pin the version they were written against, so
//! a bump is a visible break rather than a silent redefinition. A profile's
//! [`HarnessProfile::id`] never changes meaning.

/// How strongly the specification requires an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Specification 8 marks it MUST. A harness in this class does not work
    /// without it.
    Must,
    /// Specification 8 marks it SHOULD.
    Should,
    /// Specification 8 marks it MAY; advertised through capabilities.
    May,
}

/// One endpoint a harness class calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessEndpoint {
    /// The HTTP method.
    pub method: &'static str,
    /// The path, relative to the listener root.
    pub path: &'static str,
    /// How strongly it is required.
    pub requirement: Requirement,
}

/// How a harness class expects incremental output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingProfile {
    /// The class does not stream.
    None,
    /// Server-sent events.
    ServerSentEvents {
        /// A sentinel payload that ends the stream, when the profile uses one.
        /// `None` means the stream ends with a named terminal event and the
        /// connection closing.
        terminal_marker: Option<&'static str>,
        /// Whether every event carries an `event:` name.
        named_events: bool,
        /// Whether the router may send SSE comments as keepalives.
        keepalive_comments: bool,
    },
}

/// How a harness class expects tool calls to be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallingProfile {
    /// The class does not call tools.
    None,
    /// OpenAI `tools` / `tool_calls`, with arguments as a JSON string.
    OpenAiFunctions {
        /// Whether more than one call may be open at once.
        parallel: bool,
        /// Whether arguments arrive as fragments across stream frames.
        streamed_argument_fragments: bool,
    },
    /// Anthropic `tool_use` content blocks, with arguments as a JSON object.
    AnthropicToolUse {
        /// Whether arguments arrive as `input_json_delta` fragments.
        streamed_argument_fragments: bool,
    },
}

/// How a harness class discovers which models it may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelListing {
    /// The class is configured with a model name and never lists.
    Configured,
    /// The class lists models before use.
    ListEndpoint {
        /// The path it lists from.
        path: &'static str,
        /// Whether the response is filtered to what the caller may use.
        ///
        /// Always true: specification 8 requires `/v1/models` to return "only
        /// aliases/models authorized for the principal", and a listing that
        /// leaks another tenant's aliases is a tenant-isolation failure, not a
        /// cosmetic one.
        authorized_only: bool,
    },
}

/// How a harness class cancels an in-flight request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancellation {
    /// It closes the connection and expects the router to propagate the
    /// cancellation upstream and release the reservation.
    ClientDisconnect,
}

/// One versioned harness-compatibility profile.
#[derive(Debug, Clone, Copy)]
pub struct HarnessProfile {
    /// Stable identifier. Never reused for a different class.
    pub id: &'static str,
    /// Content version. Bumped on any change to the fields below.
    pub version: u32,
    /// The specification 8.1 harness class this profile records.
    pub class: &'static str,
    /// The configuration pattern from specification 8.1.
    pub configuration_pattern: &'static str,
    /// Endpoints this class calls.
    pub endpoints: &'static [HarnessEndpoint],
    /// Request headers the router must accept from this class.
    pub request_headers: &'static [&'static str],
    /// Streaming expectations.
    pub streaming: StreamingProfile,
    /// Tool-calling expectations.
    pub tool_calling: ToolCallingProfile,
    /// Model-discovery expectations.
    pub model_listing: ModelListing,
    /// Largest request body this class is expected to send, in bytes.
    ///
    /// Bounded by specification 3.2's 16 MiB inbound body limit; a profile may
    /// declare less but never more.
    pub max_request_bytes: u64,
    /// How this class cancels.
    pub cancellation: Cancellation,
    /// Environment variables that configure this class, when it is configured
    /// that way.
    pub environment_variables: &'static [&'static str],
    /// What is known not to work, or not to have been verified.
    ///
    /// A profile with an empty list is claiming complete compatibility, which
    /// is exactly the claim specification 8.1 tells the project not to make
    /// without evidence.
    pub known_limitations: &'static [&'static str],
}

/// The inbound body ceiling of specification 3.2, in bytes.
pub const SPEC_MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

/// Every profile.
#[must_use]
pub const fn all() -> &'static [HarnessProfile] {
    PROFILES
}

/// Look one profile up by identifier.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static HarnessProfile> {
    PROFILES.iter().find(|p| p.id == id)
}

impl HarnessProfile {
    /// The endpoints this profile marks [`Requirement::Must`].
    ///
    /// These are what a compatibility suite has to exercise: a harness in this
    /// class cannot function if one of them is missing.
    pub fn required_endpoints(&self) -> impl Iterator<Item = &'static HarnessEndpoint> {
        self.endpoints
            .iter()
            .filter(|e| e.requirement == Requirement::Must)
    }

    /// Whether this profile expects streamed responses at all.
    #[must_use]
    pub const fn streams(&self) -> bool {
        !matches!(self.streaming, StreamingProfile::None)
    }
}

const OPENAI_SSE: StreamingProfile = StreamingProfile::ServerSentEvents {
    terminal_marker: Some("[DONE]"),
    named_events: false,
    keepalive_comments: true,
};

const PROFILES: &[HarnessProfile] = &[
    HarnessProfile {
        id: "openai-compatible-cli",
        version: 1,
        class: "OpenAI-compatible CLI/IDE",
        configuration_pattern:
            "Base URL = https://router.example/v1; API key = scoped router key; model = alias.",
        endpoints: &[
            HarnessEndpoint {
                method: "POST",
                path: "/v1/chat/completions",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/v1/models",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "POST",
                path: "/v1/responses",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "POST",
                path: "/v1/embeddings",
                requirement: Requirement::Should,
            },
        ],
        request_headers: &["authorization", "content-type", "accept"],
        streaming: OPENAI_SSE,
        tool_calling: ToolCallingProfile::OpenAiFunctions {
            parallel: true,
            streamed_argument_fragments: true,
        },
        model_listing: ModelListing::ListEndpoint {
            path: "/v1/models",
            authorized_only: true,
        },
        max_request_bytes: SPEC_MAX_REQUEST_BYTES,
        cancellation: Cancellation::ClientDisconnect,
        environment_variables: &[],
        known_limitations: &[
            "No third-party harness has been recorded or run against the router; this profile is derived from specification 8.1, not from measurement.",
            "Specification 25 leaves HTTP/2 an open decision, so a harness that requires it is out of profile.",
            "`/v1/responses` event normalization is required by specification 8 but has no recorded golden stream in this corpus.",
        ],
    },
    HarnessProfile {
        id: "anthropic-compatible-coding-client",
        version: 1,
        class: "Anthropic-compatible coding client",
        configuration_pattern:
            "Base URL = router Anthropic listener/path; router API key; model alias.",
        endpoints: &[HarnessEndpoint {
            method: "POST",
            path: "/v1/messages",
            requirement: Requirement::Should,
        }],
        // This family authenticates with `x-api-key` rather than a bearer
        // token, and requires its own version header. The router accepts both
        // spellings against the same key store: which header a harness uses is
        // a transport detail, not a second credential type.
        request_headers: &["x-api-key", "anthropic-version", "content-type", "accept"],
        streaming: StreamingProfile::ServerSentEvents {
            terminal_marker: None,
            named_events: true,
            keepalive_comments: true,
        },
        tool_calling: ToolCallingProfile::AnthropicToolUse {
            streamed_argument_fragments: true,
        },
        model_listing: ModelListing::Configured,
        max_request_bytes: SPEC_MAX_REQUEST_BYTES,
        cancellation: Cancellation::ClientDisconnect,
        environment_variables: &[],
        known_limitations: &[
            "No third-party harness has been recorded or run against the router; this profile is derived from specification 8.1, not from measurement.",
            "Specification 8 marks this endpoint SHOULD rather than MUST, so a deployment may not serve it at all.",
            "This protocol has no model-listing endpoint, so a client in this class cannot discover which aliases it is authorized for.",
        ],
    },
    HarnessProfile {
        id: "environment-driven-harness",
        version: 1,
        class: "Environment-driven harness",
        configuration_pattern: "OPENAI_BASE_URL / OPENAI_API_KEY or equivalent.",
        endpoints: &[
            HarnessEndpoint {
                method: "POST",
                path: "/v1/chat/completions",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/v1/models",
                requirement: Requirement::Must,
            },
        ],
        request_headers: &["authorization", "content-type", "accept"],
        streaming: OPENAI_SSE,
        tool_calling: ToolCallingProfile::OpenAiFunctions {
            parallel: true,
            streamed_argument_fragments: true,
        },
        model_listing: ModelListing::ListEndpoint {
            path: "/v1/models",
            authorized_only: true,
        },
        max_request_bytes: SPEC_MAX_REQUEST_BYTES,
        cancellation: Cancellation::ClientDisconnect,
        // Specification 8.1: "Document per-tool variables; never require
        // wrapper scripts when native configuration exists." The variables are
        // read by the harness, never by the router — a router that consulted
        // them would be taking a destination from its environment.
        environment_variables: &["OPENAI_BASE_URL", "OPENAI_API_KEY"],
        known_limitations: &[
            "No third-party harness has been recorded or run against the router; this profile is derived from specification 8.1, not from measurement.",
            "Variable names differ per tool and are not enumerable in advance; the two listed are the common spelling, not a complete set.",
        ],
    },
    HarnessProfile {
        id: "local-development",
        version: 1,
        class: "Local development",
        configuration_pattern:
            "http://127.0.0.1:<port>/v1 over loopback, or HTTPS edge. Loopback listener defaults to local-only; remote cleartext forbidden.",
        endpoints: &[
            HarnessEndpoint {
                method: "POST",
                path: "/v1/chat/completions",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/v1/models",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/health/live",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/health/ready",
                requirement: Requirement::Must,
            },
        ],
        request_headers: &["authorization", "content-type", "accept"],
        streaming: OPENAI_SSE,
        tool_calling: ToolCallingProfile::OpenAiFunctions {
            parallel: true,
            streamed_argument_fragments: true,
        },
        model_listing: ModelListing::ListEndpoint {
            path: "/v1/models",
            authorized_only: true,
        },
        max_request_bytes: SPEC_MAX_REQUEST_BYTES,
        cancellation: Cancellation::ClientDisconnect,
        environment_variables: &["OPENAI_BASE_URL", "OPENAI_API_KEY"],
        known_limitations: &[
            "Cleartext is permitted only because the listener is loopback-bound. A profile that reached this listener from another host would be serving credentials in the clear.",
            "The health endpoints must stay free of provider detail (specification 8); they are reachable without authentication.",
        ],
    },
    HarnessProfile {
        id: "custom-integration",
        version: 1,
        class: "Custom integration",
        configuration_pattern: "Versioned canonical extension endpoints; use advertised capabilities and request id.",
        endpoints: &[
            HarnessEndpoint {
                method: "POST",
                path: "/v1/chat/completions",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "GET",
                path: "/v1/models",
                requirement: Requirement::Must,
            },
            HarnessEndpoint {
                method: "POST",
                path: "/v1/tokenize",
                requirement: Requirement::May,
            },
        ],
        request_headers: &["authorization", "content-type", "accept"],
        streaming: OPENAI_SSE,
        tool_calling: ToolCallingProfile::OpenAiFunctions {
            parallel: true,
            streamed_argument_fragments: true,
        },
        model_listing: ModelListing::ListEndpoint {
            path: "/v1/models",
            authorized_only: true,
        },
        max_request_bytes: SPEC_MAX_REQUEST_BYTES,
        cancellation: Cancellation::ClientDisconnect,
        environment_variables: &[],
        known_limitations: &[
            "`/v1/tokenize` is a normalized extension (specification 8, MAY) and a target may not declare a native tokenizer, in which case the router has no exact answer to give.",
            "Extension endpoints are versioned; a client that pins a version the deployment does not serve is out of profile.",
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique() {
        let mut ids: Vec<&str> = PROFILES.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before);
    }

    #[test]
    fn every_specification_8_1_class_has_a_profile() {
        // The five rows of the specification 8.1 table. A missing one is a
        // client the router has not decided how to serve.
        for class in [
            "OpenAI-compatible CLI/IDE",
            "Anthropic-compatible coding client",
            "Environment-driven harness",
            "Local development",
            "Custom integration",
        ] {
            assert!(
                PROFILES.iter().any(|p| p.class == class),
                "no profile for the {class:?} class"
            );
        }
    }

    #[test]
    fn every_profile_is_versioned_and_documents_its_limits() {
        for profile in PROFILES {
            assert!(profile.version >= 1, "{} is unversioned", profile.id);
            assert!(
                !profile.known_limitations.is_empty(),
                "{} claims complete compatibility, which specification 8.1 forbids without evidence",
                profile.id
            );
            assert!(!profile.endpoints.is_empty(), "{} calls nothing", profile.id);
            assert!(
                profile.max_request_bytes <= SPEC_MAX_REQUEST_BYTES,
                "{} declares a body limit above the specification 3.2 ceiling",
                profile.id
            );
        }
    }

    #[test]
    fn every_profile_states_that_no_harness_was_measured_or_is_router_local() {
        // The three profiles describing third-party tooling must each carry the
        // disclaimer. `local-development` and `custom-integration` describe
        // configurations rather than tools, so they are exempt.
        for id in [
            "openai-compatible-cli",
            "anthropic-compatible-coding-client",
            "environment-driven-harness",
        ] {
            let profile = by_id(id).expect("present");
            assert!(
                profile
                    .known_limitations
                    .iter()
                    .any(|l| l.contains("recorded or run")),
                "{id} does not say that no harness was measured"
            );
        }
    }

    #[test]
    fn every_profile_endpoint_appears_in_the_specification_8_table() {
        // The endpoints specification 8 defines, with the method each is
        // defined for. A profile naming anything else is either a typo or a
        // route the router does not serve — and a typo here would make a
        // compatibility suite exercise a path that returns 404 while the test
        // that walks these profiles still passes.
        const DEFINED: &[(&str, &str)] = &[
            ("POST", "/v1/chat/completions"),
            ("POST", "/v1/responses"),
            ("POST", "/v1/embeddings"),
            ("GET", "/v1/models"),
            ("POST", "/v1/messages"),
            ("GET", "/health/live"),
            ("GET", "/health/ready"),
            ("POST", "/v1/tokenize"),
        ];
        for profile in PROFILES {
            for endpoint in profile.endpoints {
                assert!(
                    DEFINED.contains(&(endpoint.method, endpoint.path)),
                    "{} lists {} {}, which specification 8 does not define",
                    profile.id,
                    endpoint.method,
                    endpoint.path
                );
            }
        }
    }

    #[test]
    fn a_model_listing_path_is_also_declared_as_an_endpoint() {
        // Otherwise a profile could claim to discover models from a path it
        // never says it calls, and no suite would exercise it.
        for profile in PROFILES {
            if let ModelListing::ListEndpoint { path, .. } = profile.model_listing {
                assert!(
                    profile.endpoints.iter().any(|e| e.path == path),
                    "{} lists models from {path} but does not declare that endpoint",
                    profile.id
                );
            }
        }
    }

    #[test]
    fn endpoint_paths_are_absolute_and_methods_upper_case() {
        for profile in PROFILES {
            for endpoint in profile.endpoints {
                assert!(
                    endpoint.path.starts_with('/'),
                    "{} lists a relative path {}",
                    profile.id,
                    endpoint.path
                );
                assert!(
                    endpoint.method.chars().all(|c| c.is_ascii_uppercase()),
                    "{} lists method {}",
                    profile.id,
                    endpoint.method
                );
            }
        }
    }

    #[test]
    fn required_endpoints_are_a_subset_of_the_endpoint_list() {
        for profile in PROFILES {
            let required: Vec<&str> = profile.required_endpoints().map(|e| e.path).collect();
            assert!(
                required
                    .iter()
                    .all(|path| profile.endpoints.iter().any(|e| e.path == *path))
            );
        }
    }

    #[test]
    fn the_anthropic_profile_uses_its_own_header_and_no_terminal_marker() {
        let profile = by_id("anthropic-compatible-coding-client").expect("present");
        assert!(profile.request_headers.contains(&"x-api-key"));
        assert!(profile.request_headers.contains(&"anthropic-version"));
        assert!(!profile.request_headers.contains(&"authorization"));
        match profile.streaming {
            StreamingProfile::ServerSentEvents {
                terminal_marker,
                named_events,
                ..
            } => {
                assert_eq!(terminal_marker, None, "this profile has no sentinel payload");
                assert!(named_events);
            }
            StreamingProfile::None => panic!("this profile streams"),
        }
    }

    #[test]
    fn openai_shaped_profiles_share_one_streaming_contract() {
        for id in [
            "openai-compatible-cli",
            "environment-driven-harness",
            "local-development",
            "custom-integration",
        ] {
            let profile = by_id(id).expect("present");
            assert_eq!(profile.streaming, OPENAI_SSE, "{id} diverges");
            assert!(profile.streams());
        }
    }

    #[test]
    fn every_model_listing_is_authorization_filtered() {
        // Specification 8: `/v1/models` returns only what the principal may
        // use. A profile that expected an unfiltered listing would be asking
        // the router to break tenant isolation.
        for profile in PROFILES {
            if let ModelListing::ListEndpoint {
                authorized_only, ..
            } = profile.model_listing
            {
                assert!(authorized_only, "{} expects an unfiltered listing", profile.id);
            }
        }
    }
}
