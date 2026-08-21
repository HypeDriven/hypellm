//! Client protocol translation.
//!
//! Specification 8: compatibility is behavioural, not path-level. Each module
//! here owns one client dialect end to end — parsing a request into the
//! canonical model and rendering canonical events back out — so that a
//! dialect's quirks stay in one file and cannot leak into routing.
//!
//! | Module | Endpoints |
//! |---|---|
//! | [`openai`] | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/models` |
//! | [`anthropic`] | `/v1/messages` |

pub mod anthropic;
pub mod openai;

pub use openai::{DocumentLimits, ParseContext};

/// Enforce the document bounds of specification-extension 3.3.
///
/// One function for every dialect, called once after parsing, because the
/// bounds are a property of the *request* rather than of the wire shape it
/// arrived in — and a limit enforced in two places eventually disagrees with
/// itself.
///
/// Three separate bounds, each answering a different question:
///
/// - **Count** caps the reservation and the provider cost one request can
///   incur, since each document contributes a fixed token estimate.
/// - **Per-part size** stops one enormous document from consuming the whole
///   inline budget.
/// - **Aggregate size** is what actually bounds memory, and is validated
///   against `max_body_bytes` at configuration time so that the encoded form
///   fits the body the reader will accept.
///
/// URL-form documents count toward the *count* limit and toward nothing else:
/// the router never fetches them, so it cannot know their size, which is
/// precisely why the per-document token constant errs high.
pub fn enforce_document_limits(
    request: &hypellm_core::canonical::CanonicalRequest,
    limits: &openai::DocumentLimits,
) -> Result<(), hypellm_core::error::RouterError> {
    use hypellm_core::error::RouterError;

    let count = request.document_parts();
    if count == 0 {
        return Ok(());
    }
    if u64::try_from(count).unwrap_or(u64::MAX) > u64::from(limits.max_documents) {
        return Err(RouterError::invalid_request(&format!(
            "a request may carry at most {} document parts",
            limits.max_documents
        ))
        .with_param("messages"));
    }

    for message in &request.messages {
        for part in &message.content {
            let Some(bytes) = part.inline_document_bytes() else {
                continue;
            };
            if u64::try_from(bytes).unwrap_or(u64::MAX) > limits.max_document_bytes {
                return Err(RouterError::invalid_request(&format!(
                    "an inline document may be at most {} bytes",
                    limits.max_document_bytes
                ))
                .with_param("messages"));
            }
        }
    }

    if request.inline_document_bytes() > limits.max_inline_bytes {
        return Err(RouterError::invalid_request(&format!(
            "a request may carry at most {} bytes of inline documents",
            limits.max_inline_bytes
        ))
        .with_param("messages"));
    }

    Ok(())
}
