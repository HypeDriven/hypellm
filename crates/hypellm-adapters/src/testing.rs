//! Shared fixtures for adapter tests and the golden corpus.
//!
//! Public rather than `#[cfg(test)]` so that `hypellm-test-corpus` and the
//! compatibility suite build the same canonical requests the unit tests use.
//! Two suites constructing subtly different fixtures is how a golden test ends
//! up passing against something the router never actually sends.

use hypellm_core::canonical::{
    CanonicalRequest, ClientProtocol, CostClass, Message, Operation, RequestLimits, Role,
    RoutingHints, Sampling, StreamOptions,
};
use hypellm_core::ids::{AliasId, PrincipalId, ProviderId, RequestId, TargetId, TenantId};
use hypellm_core::target::{AdminState, Capabilities, Endpoint, EndpointScheme, Target};
use hypellm_core::time::{Deadline, TestClock};
use std::time::Duration;

use crate::contract::RequestMeta;

/// A capable chat target.
///
/// The identifier `expect`s below are on string literals fixed at compile time
/// that satisfy the [`hypellm_core::ids`] grammar (non-empty, within
/// `MAX_ID_LEN`, only the permitted character set). No caller, request, or
/// configuration can supply a different value, so the constructors cannot
/// return `Err` here; and any edit that broke a literal would fail every test
/// in the workspace that builds this fixture, at the first assertion.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "test fixture; the identifiers are compile-time literals that cannot fail validation"
)]
pub fn target_fixture() -> Target {
    Target {
        id: TargetId::new("openai:gpt").expect("valid identifier"),
        provider_id: ProviderId::new("openai").expect("valid identifier"),
        native_model: "gpt-4.1".to_owned(),
        aliases: vec![AliasId::new("code-premium").expect("valid identifier")],
        capabilities: Capabilities {
            operations: vec![Operation::Chat, Operation::Responses, Operation::Embeddings],
            modalities: vec![
                hypellm_core::canonical::Modality::Text,
                hypellm_core::canonical::Modality::Image,
            ],
            streaming: true,
            tools: true,
            parallel_tool_calls: true,
            json_mode: true,
            structured_output: true,
            reasoning: false,
            prompt_caching: false,
            max_context_tokens: 128_000,
            max_output_tokens: 16_384,
            embedding_dimensions: None,
            native_tokenizer: false,
        },
        cost_class: CostClass::new(4),
        residency: None,
        is_local: false,
        admin_state: AdminState::Enabled,
        endpoint_index: 0,
        max_concurrency: 16,
        max_requests_per_second: 100,
    }
}

/// An Anthropic-shaped target.
///
/// Same reasoning as [`target_fixture`]: compile-time identifier literals.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "test fixture; the identifiers are compile-time literals that cannot fail validation"
)]
pub fn anthropic_target_fixture() -> Target {
    Target {
        id: TargetId::new("anthropic:claude").expect("valid identifier"),
        provider_id: ProviderId::new("anthropic").expect("valid identifier"),
        native_model: "claude-sonnet-5".to_owned(),
        capabilities: Capabilities {
            operations: vec![Operation::Chat],
            prompt_caching: true,
            max_context_tokens: 200_000,
            max_output_tokens: 8_192,
            ..target_fixture().capabilities
        },
        ..target_fixture()
    }
}

/// An HTTPS endpoint.
#[must_use]
pub fn endpoint_fixture(host: &str) -> Endpoint {
    Endpoint {
        scheme: EndpointScheme::Https,
        host: host.to_owned(),
        port: 443,
        base_path: "/v1".to_owned(),
    }
}

/// A two-message chat request.
///
/// Same reasoning as [`target_fixture`]: compile-time identifier literals.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "test fixture; the identifiers are compile-time literals that cannot fail validation"
)]
pub fn request_fixture() -> CanonicalRequest {
    let clock = TestClock::new();
    CanonicalRequest {
        request_id: RequestId::from_u128(0x0123_4567_89ab_cdef),
        tenant: TenantId::new("acme").expect("valid identifier"),
        principal: PrincipalId::new("user:42").expect("valid identifier"),
        protocol: ClientProtocol::OpenAiChat,
        operation: Operation::Chat,
        requested_model: AliasId::new("code-premium").expect("valid identifier"),
        messages: vec![
            Message::text(Role::System, "You are terse."),
            Message::text(Role::User, "Explain backpressure."),
        ],
        inputs: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        limits: RequestLimits {
            max_output_tokens: Some(512),
            deadline: Deadline::after(&clock, Duration::from_secs(60)),
            max_cost_class: None,
            residency: None,
        },
        stream: StreamOptions {
            enabled: false,
            include_usage: false,
        },
        hints: RoutingHints::default(),
    }
}

/// Request metadata for an exchange.
#[must_use]
pub fn meta_fixture<'a>(
    target: &'a Target,
    endpoint: &'a Endpoint,
    streaming: bool,
) -> RequestMeta<'a> {
    RequestMeta {
        target,
        endpoint,
        request_id: "0123456789abcdef0123456789abcdef".to_owned(),
        streaming,
        idempotency_key: None,
    }
}
