//! Compile-time provider-family adapters.
//!
//! Specification 7: "Adapters are compile-time modules selected by
//! `provider.family`." Not plugins, not dynamically loaded, not configurable —
//! specification 2.2 makes "dynamic third-party plugins, Lua, WASM, shared
//! objects, downloaded adapters, or runtime code evaluation" an explicit
//! non-goal.
//!
//! [`adapter_for`] is the whole selection mechanism: a `match` over a closed
//! enum returning a `&'static dyn Adapter`. There is no registration, no
//! lookup table an operator can extend, and no path by which a request selects
//! an adapter.
//!
//! # Family coverage (specification 7)
//!
//! | Family | Adapter | Notes |
//! |---|---|---|
//! | llama.cpp | [`openai::OpenAiAdapter`] | OpenAI-compatible surface, local transport |
//! | OpenAI | [`openai::OpenAiAdapter`] | Chat Completions and Responses paths |
//! | Anthropic | [`anthropic::AnthropicAdapter`] | `/v1/messages`, content-block streaming |
//! | DeepSeek | [`openai::OpenAiAdapter`] | OpenAI-compatible, capabilities declared per target |
//! | Moonshot / Kimi | [`openai::OpenAiAdapter`] | as above; "no assumptions from model name" |
//! | Generic OpenAI | [`openai::OpenAiAdapter`] | opt-in only, see `hypellm-config` |

#![forbid(unsafe_code)]
// Specification 18.2: no panics on data-plane input, all integer conversions
// checked. Adapters *are* the data plane — they parse provider responses and
// narrow provider-supplied numbers — so the workspace-level `warn` on these
// lints is escalated to `deny` here. A new unchecked conversion or a new
// `expect` in this crate is a build failure, not another line of output.
//
// Only lints this crate actually needed are listed. `indexing_slicing`,
// `integer_division`, `unwrap_used`, `cast_sign_loss`, and `cast_possible_wrap`
// never fired: adapters index nothing and divide nothing, and they should keep
// it that way — add the corresponding `deny` the first time one appears rather
// than leaving it at workspace `warn`.
//
// The four narrow `allow`s that override this sit on individual functions —
// one in `openai`, three in `testing` — each with its reason recorded at the
// site. There is no module- or crate-level `allow` for any of these lints.
#![cfg_attr(not(test), deny(clippy::as_conversions, clippy::cast_possible_truncation))]
// `expect_used` is denied for the shipped library only. The workspace policy is
// that "test code legitimately uses them", and this crate's `#[cfg(test)]`
// modules assert with `expect`/`expect_err` throughout; escalating there would
// buy nothing and cost every assertion a wrapper. Test builds keep the
// workspace-level `warn`, so the lint still reports — it just is not fatal.
#![cfg_attr(not(test), deny(clippy::expect_used))]

pub mod anthropic;
pub mod contract;
pub mod openai;
#[cfg(any(test, feature = "test-harness"))]
pub mod testing;

pub use anthropic::AnthropicAdapter;
pub use contract::{
    Adapter, CredentialHandle, ErrorClassification, RequestMeta, SensitiveHeaders,
    ValidationFailure, ValidationResult, is_usable_credential,
};
pub use openai::OpenAiAdapter;

use hypellm_core::target::ProviderFamily;

static OPENAI: OpenAiAdapter = OpenAiAdapter::new(ProviderFamily::OpenAi);
static LLAMACPP: OpenAiAdapter = OpenAiAdapter::new(ProviderFamily::LlamaCpp);
static DEEPSEEK: OpenAiAdapter = OpenAiAdapter::new(ProviderFamily::DeepSeek);
static MOONSHOT: OpenAiAdapter = OpenAiAdapter::new(ProviderFamily::Moonshot);
static GENERIC: OpenAiAdapter = OpenAiAdapter::new(ProviderFamily::GenericOpenAi);
static ANTHROPIC: AnthropicAdapter = AnthropicAdapter;

/// The adapter for a provider family.
///
/// Total over the enum, so adding a family is a compile error until an adapter
/// is chosen for it.
#[must_use]
pub fn adapter_for(family: ProviderFamily) -> &'static dyn Adapter {
    match family {
        ProviderFamily::OpenAi => &OPENAI,
        ProviderFamily::LlamaCpp => &LLAMACPP,
        ProviderFamily::Anthropic => &ANTHROPIC,
        ProviderFamily::DeepSeek => &DEEPSEEK,
        ProviderFamily::Moonshot => &MOONSHOT,
        ProviderFamily::GenericOpenAi => &GENERIC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{endpoint_fixture, meta_fixture, request_fixture, target_fixture};
    use hypellm_core::canonical::Operation;
    use hypellm_core::event::CanonicalEvent;
    use wire_json::{Limits, parse};

    #[test]
    fn every_family_has_an_adapter_that_reports_itself() {
        for family in ProviderFamily::all() {
            let adapter = adapter_for(*family);
            assert_eq!(
                adapter.family(),
                *family,
                "the adapter for {family} reports a different family"
            );
        }
    }

    #[test]
    fn the_openai_compatible_families_share_an_encoding() {
        // Specification 23: capabilities are declared per target, not inferred
        // from the family. The families differ in what they declare, not in
        // how a request is encoded.
        let request = request_fixture();
        let target = target_fixture();
        let endpoint = endpoint_fixture("api.example");
        let meta = meta_fixture(&target, &endpoint, false);

        let mut bodies = Vec::new();
        for family in [
            ProviderFamily::OpenAi,
            ProviderFamily::LlamaCpp,
            ProviderFamily::DeepSeek,
            ProviderFamily::Moonshot,
            ProviderFamily::GenericOpenAi,
        ] {
            bodies.push(
                adapter_for(family)
                    .encode_request(&request, &meta)
                    .expect("encodes"),
            );
        }
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "the OpenAI-compatible families must encode identically"
        );
    }

    #[test]
    fn anthropic_encodes_differently() {
        let request = request_fixture();
        let target = testing::anthropic_target_fixture();
        let endpoint = endpoint_fixture("api.anthropic.com");
        let meta = meta_fixture(&target, &endpoint, false);

        let anthropic = adapter_for(ProviderFamily::Anthropic)
            .encode_request(&request, &meta)
            .expect("encodes");
        let body = parse(&anthropic, &Limits::DEFAULT).expect("valid JSON");
        // The distinguishing marks: a hoisted system field and a mandatory
        // max_tokens.
        assert!(body.get("system").is_some());
        assert!(body.get("max_tokens").is_some());
    }

    #[test]
    fn paths_differ_by_family() {
        let request = request_fixture();
        assert_eq!(
            adapter_for(ProviderFamily::OpenAi).path_for(&request).unwrap(),
            "/chat/completions"
        );
        assert_eq!(
            adapter_for(ProviderFamily::Anthropic)
                .path_for(&request)
                .unwrap(),
            "/messages"
        );
    }

    #[test]
    fn no_adapter_leaks_a_credential_into_its_debug_output() {
        // Specification 7: adapters "cannot expose credentials in errors".
        let reference = hypellm_core::ids::CredentialRef::new("cred_x").unwrap();
        let credential = CredentialHandle::new(&reference, b"super-secret-provider-key");
        let target = target_fixture();
        let endpoint = endpoint_fixture("api.example");
        let meta = meta_fixture(&target, &endpoint, false);

        for family in ProviderFamily::all() {
            let headers = adapter_for(*family).encode_headers(Some(&credential), &meta);
            let rendered = format!("{headers:?}");
            assert!(
                !rendered.contains("super-secret-provider-key"),
                "{family} leaked the credential in Debug output"
            );
        }
    }

    #[test]
    fn no_adapter_puts_a_provider_message_in_a_client_detail() {
        // Every family's error path must drop the provider's message, which
        // routinely echoes the prompt.
        let body = br#"{"error":{"type":"invalid_request_error","message":"the prompt 'CONFIDENTIAL PAYLOAD' was rejected"}}"#;
        for family in ProviderFamily::all() {
            let classification = adapter_for(*family).classify_error(400, body);
            assert!(
                !classification.safe_detail.as_str().contains("CONFIDENTIAL"),
                "{family} forwarded the provider message"
            );
        }
    }

    #[test]
    fn every_adapter_reports_usage_provenance() {
        // Specification 14: usage is marked provider-reported or estimated.
        for family in ProviderFamily::all() {
            let adapter = adapter_for(*family);
            let estimated = adapter.usage_from_events(&[]);
            assert!(
                !estimated.is_reported(),
                "{family} reported an absent usage as provider-supplied"
            );

            let reported = adapter.usage_from_events(&[CanonicalEvent::Usage(
                hypellm_core::event::CanonicalUsage::reported(10, 5),
            )]);
            assert!(reported.is_reported(), "{family} lost the provenance");
            assert_eq!(reported.input_tokens, 10);
        }
    }

    #[test]
    fn validation_is_capability_driven_for_every_family() {
        let mut target = target_fixture();
        target.capabilities.streaming = false;
        let mut request = request_fixture();
        request.stream.enabled = true;
        request.operation = Operation::Chat;

        for family in ProviderFamily::all() {
            let failure = adapter_for(*family)
                .validate(&request, &target.capabilities)
                .expect_err("streaming is not declared");
            assert_eq!(
                failure.code, "streaming_unsupported",
                "{family} gave the wrong reason"
            );
        }
    }
}
