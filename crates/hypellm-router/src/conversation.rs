//! Recognising a conversation from what a harness already sends.
//!
//! Coding harnesses do not send `hypellm_routing.conversation_id`, but every
//! one resends its conversation from the start on each turn, and keeps that
//! start byte-identical — it is what makes provider prompt caching work for
//! them. So the start identifies the conversation: the system messages and
//! the first user message.
//!
//! [`prefix_fingerprint`] is a keyed hash of that start. It holds no prompt
//! content — the key is the router's own, so the value cannot be checked
//! against a guessed prompt — and it is used only as the identifier under which
//! the affinity table remembers a target. Like an explicit identifier it is
//! scoped by tenant, principal and alias, and it names no target.

use hypellm_core::canonical::{CanonicalRequest, ContentPart, Operation, Role};

/// Bytes of one message's text that are hashed. A start longer than this is
/// still distinguished by everything before the cap and by its full length.
const MAX_HASHED_BYTES_PER_MESSAGE: usize = 16 * 1024;
/// Messages examined for the start, so a body of nothing but system messages
/// costs a bounded amount.
const MAX_PREFIX_MESSAGES: usize = 16;
/// The prefix every derived identifier carries, so it reads as derived.
pub const FINGERPRINT_PREFIX: &str = "prefix:";

/// The key the fingerprint is computed under, derived from the router's
/// pseudonym secret so it is stable across restarts and never stored.
#[must_use]
pub fn fingerprint_key(pseudonym_secret: &[u8]) -> [u8; 32] {
    hypellm_crypto::hmac_sha256(pseudonym_secret, b"hypellm conversation prefix v1")
}

/// A conversation identifier derived from the request's opening messages.
///
/// `None` for an operation that is not a conversation, or a request with no
/// user message to anchor it.
#[must_use]
pub fn prefix_fingerprint(key: &[u8; 32], request: &CanonicalRequest) -> Option<String> {
    if !matches!(request.operation, Operation::Chat | Operation::Responses) {
        return None;
    }
    let mut mac = hypellm_crypto::HmacSha256::new(key);
    let mut anchored = false;
    for message in request.messages.iter().take(MAX_PREFIX_MESSAGES) {
        mac.update(message.role.as_str().as_bytes());
        mac.update(b"\0");
        for part in &message.content {
            match part {
                ContentPart::Text(text) => {
                    mac.update(b"t");
                    mac.update(&u64::try_from(text.len()).unwrap_or(u64::MAX).to_be_bytes());
                    let cut = text.len().min(MAX_HASHED_BYTES_PER_MESSAGE);
                    mac.update(text.as_bytes().get(..cut).unwrap_or_default());
                }
                // Only the kind: a harness resends the same parts, and hashing
                // a payload could cost megabytes per request.
                ContentPart::Image(_) => mac.update(b"i"),
                ContentPart::Document { .. } => mac.update(b"d"),
                ContentPart::Audio { .. } => mac.update(b"a"),
                ContentPart::ToolResult { .. } => mac.update(b"r"),
            }
        }
        mac.update(b"\x1e");
        if message.role == Role::User {
            anchored = true;
            break;
        }
    }
    if !anchored {
        return None;
    }
    let digest = mac.finalize();
    Some(format!(
        "{FINGERPRINT_PREFIX}{}",
        hypellm_crypto::hex::encode(digest.get(..16).unwrap_or_default())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::canonical::Message;

    const KEY: [u8; 32] = [7; 32];

    fn request(messages: &[(Role, &str)]) -> CanonicalRequest {
        let mut request = hypellm_adapters::testing::request_fixture();
        request.operation = Operation::Chat;
        request.messages = messages
            .iter()
            .map(|(role, text)| Message::text(*role, *text))
            .collect();
        request
    }

    #[test]
    fn every_turn_of_a_conversation_has_the_same_fingerprint() {
        let first = request(&[
            (Role::System, "You are a coder."),
            (Role::User, "Fix the bug."),
        ]);
        let later = request(&[
            (Role::System, "You are a coder."),
            (Role::User, "Fix the bug."),
            (Role::Assistant, "Which one?"),
            (Role::User, "The parser."),
        ]);
        let id = prefix_fingerprint(&KEY, &first).unwrap();
        assert_eq!(
            prefix_fingerprint(&KEY, &later).as_deref(),
            Some(id.as_str())
        );
        assert!(hypellm_core::valid_conversation_id(&id), "{id}");
    }

    #[test]
    fn a_different_opening_is_a_different_conversation() {
        let a = request(&[(Role::System, "S"), (Role::User, "one")]);
        let b = request(&[(Role::System, "S"), (Role::User, "two")]);
        let c = request(&[(Role::System, "T"), (Role::User, "one")]);
        // Role boundaries are part of the hash: moving text between
        // messages must not produce the same start.
        let d = request(&[(Role::User, "Sone")]);
        let ids: std::collections::BTreeSet<_> = [&a, &b, &c, &d]
            .iter()
            .map(|r| prefix_fingerprint(&KEY, r).unwrap())
            .collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn the_fingerprint_depends_on_the_key_and_reveals_no_text() {
        let r = request(&[(Role::User, "secret plan")]);
        let a = prefix_fingerprint(&KEY, &r).unwrap();
        assert_ne!(Some(a.clone()), prefix_fingerprint(&[8; 32], &r));
        assert!(!a.contains("secret"));
    }

    #[test]
    fn a_request_with_no_user_turn_or_no_conversation_has_none() {
        assert!(prefix_fingerprint(&KEY, &request(&[(Role::System, "S")])).is_none());
        let mut embeddings = request(&[(Role::User, "x")]);
        embeddings.operation = Operation::Embeddings;
        assert!(prefix_fingerprint(&KEY, &embeddings).is_none());
    }
}
