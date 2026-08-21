//! The fleet-agent wire protocol.
//!
//! The same line-oriented shape as `hypellm_net::helper`, over an owner-only
//! Unix socket. It is the third member of a family: specification 4 delegates
//! outbound TLS to a helper with a narrow CONNECT-like API, specification 9.1
//! delegates JWT verification to a local verifier, and this delegates
//! actuation to an agent that holds the SSH keys. The router never executes a
//! process.
//!
//! ```text
//! → HELLO 1 <nonce> <fleet-digest> <hmac>\n
//! ← OK <agent-version> <fleet-digest>\n | ERR <code>\n
//!
//! → OBSERVE\n
//! ← OK <length>\n<inventory JSON, at most 256 KiB>
//!
//! → ACTIVATE <deployment-id> <lease-id> <deadline-ms>\n
//! ← ACCEPTED <activation-id>\n | ERR <code>\n
//!
//! → DEACTIVATE <deployment-id> <lease-id> <drain-ms>\n
//! ← ACCEPTED <activation-id>\n | ERR <code>\n
//!
//! → FETCH <artifact-id> <host-id> <deadline-ms>\n
//! ← ACCEPTED <activation-id>\n | ERR <code>\n
//!
//! → STATUS <activation-id>\n
//! ← OK <state> <detail-code> <progress-permille>\n
//!
//! → CANCEL <activation-id>\n
//! ← OK\n | ERR <code>\n
//! ```
//!
//! # What may cross this socket
//!
//! Identifiers and bounded integers. No image name, no host address, no file
//! path, no container name, no Docker flag, no shell fragment, no URL. Both
//! sides hold the identifiers from their own configuration, and the agent
//! resolves each against its own allowlist. The goal is specific: **a fully
//! compromised router cannot cause arbitrary code to run on a slave.**
//!
//! # Why this is stronger than the control socket
//!
//! `control.key` sends the hex-encoded key itself as a bearer line and
//! constant-time-compares it. That is adequate for a local stop command and
//! inadequate for verbs that stop production models: a bearer line carries no
//! keyed digest and binds no message. `HELLO` carries
//! `HMAC-SHA-256(fleet.key, version ‖ nonce ‖ fleet-digest)`, so the handshake
//! binds both the protocol version and the fleet configuration each side
//! claims, and the agent rejects a nonce it has already accepted.
//!
//! The nonce is defence in depth rather than the primary control — reaching an
//! owner-only socket at all already requires the owner's privileges — but a
//! captured handshake that could be replayed would be a needless gift.
//!
//! # Why `HELLO` carries the digest as well as covering it
//!
//! The design sketch had the router send only a nonce and a tag computed over
//! its own digest. That does not work, and the way it fails is instructive: an
//! agent whose fleet file differs computes a *different* tag, so the handshake
//! fails as `unauthenticated` and the two failures an operator most needs to
//! tell apart — the wrong key, and a stale fleet file on one slave — arrive as
//! the same error.
//!
//! Sending the digest and covering it with the tag keeps both properties. The
//! tag still binds the claim, so a captured `HELLO` cannot be edited to assert
//! a different fleet; and the agent can compare a digest it has actually
//! received, so a mismatch is reported as a mismatch.

use core::fmt;
use hypellm_core::ids::{ActivationId, ArtifactId, DeploymentId, HostId, LeaseId};

/// The protocol version this router speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum bytes in one status line, in either direction.
pub const MAX_LINE: usize = 512;

/// Maximum bytes of an agent-supplied error code, after sanitising.
pub const MAX_CODE_LEN: usize = 64;

/// A request the router may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    /// Open the session, binding version and fleet digest.
    Hello {
        /// A fresh random nonce, lowercase hex.
        nonce: String,
        /// The digest this router computes over its own fleet configuration.
        fleet_digest: String,
        /// `HMAC-SHA-256(fleet.key, version ‖ nonce ‖ digest)`, lowercase hex.
        hmac: String,
    },
    /// Ask for the current inventory.
    Observe,
    /// Bring a deployment up.
    Activate {
        /// Which deployment.
        deployment: DeploymentId,
        /// The lease this is idempotent under.
        lease: LeaseId,
        /// How long the agent may take before giving up.
        deadline_ms: u64,
    },
    /// Take a deployment down.
    Deactivate {
        /// Which deployment.
        deployment: DeploymentId,
        /// The lease this is idempotent under.
        lease: LeaseId,
        /// How long in-flight work is given to finish.
        drain_ms: u64,
    },
    /// Acquire an artifact onto a host.
    Fetch {
        /// Which artifact.
        artifact: ArtifactId,
        /// Which host.
        host: HostId,
        /// How long the agent may take.
        deadline_ms: u64,
    },
    /// Ask how an activation is going.
    Status {
        /// Which activation.
        activation: ActivationId,
    },
    /// Abandon an activation.
    Cancel {
        /// Which activation.
        activation: ActivationId,
    },
}

impl AgentRequest {
    /// Whether this verb changes the fleet.
    ///
    /// The router issues no mutating verb while the fleet digests disagree, so
    /// this predicate is a gate rather than a description.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Activate { .. } | Self::Deactivate { .. } | Self::Fetch { .. } | Self::Cancel { .. }
        )
    }

    /// The verb token, for logs and metrics.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "HELLO",
            Self::Observe => "OBSERVE",
            Self::Activate { .. } => "ACTIVATE",
            Self::Deactivate { .. } => "DEACTIVATE",
            Self::Fetch { .. } => "FETCH",
            Self::Status { .. } => "STATUS",
            Self::Cancel { .. } => "CANCEL",
        }
    }
}

/// Render a request as its wire line, newline included.
///
/// Every component is either a validated identifier — whose alphabet excludes
/// whitespace by construction — or an integer, so there is no escaping to get
/// wrong and no way for a value to introduce a second line.
#[must_use]
pub fn encode_request(request: &AgentRequest) -> String {
    match request {
        AgentRequest::Hello {
            nonce,
            fleet_digest,
            hmac,
        } => format!("HELLO {PROTOCOL_VERSION} {nonce} {fleet_digest} {hmac}\n"),
        AgentRequest::Observe => "OBSERVE\n".to_owned(),
        AgentRequest::Activate {
            deployment,
            lease,
            deadline_ms,
        } => format!("ACTIVATE {deployment} {lease} {deadline_ms}\n"),
        AgentRequest::Deactivate {
            deployment,
            lease,
            drain_ms,
        } => format!("DEACTIVATE {deployment} {lease} {drain_ms}\n"),
        AgentRequest::Fetch {
            artifact,
            host,
            deadline_ms,
        } => format!("FETCH {artifact} {host} {deadline_ms}\n"),
        AgentRequest::Status { activation } => format!("STATUS {activation}\n"),
        AgentRequest::Cancel { activation } => format!("CANCEL {activation}\n"),
    }
}

/// The message the `HELLO` HMAC is computed over.
///
/// Version, nonce, and fleet digest, in that order, as separate parts rather
/// than a concatenated string: `hmac_sha256_parts` keeps the boundaries, so a
/// nonce ending in digits cannot be read as part of a version.
#[must_use]
pub fn hello_hmac(key: &[u8], nonce: &str, fleet_digest: &str) -> String {
    let version = PROTOCOL_VERSION.to_string();
    let mac = hypellm_crypto::hmac::hmac_sha256_parts(
        key,
        &[version.as_bytes(), nonce.as_bytes(), fleet_digest.as_bytes()],
    );
    hypellm_crypto::hex::encode(&mac)
}

/// What the agent replied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentReply {
    /// `OK <agent-version> <fleet-digest>` — the handshake succeeded.
    Hello {
        /// The agent's own version string, sanitised.
        agent_version: String,
        /// The digest the agent computes over its fleet.
        fleet_digest: String,
    },
    /// `OK <length>` — an inventory of `length` bytes follows.
    InventoryPending {
        /// How many bytes follow.
        length: usize,
    },
    /// `ACCEPTED <activation-id>` — the verb was accepted.
    Accepted {
        /// The handle to ask about later.
        activation: ActivationId,
    },
    /// `OK <state> <detail> <progress>` — a status report.
    Status {
        /// The lifecycle state.
        state: crate::state::ObservedState,
        /// A sanitised, bounded detail code.
        detail: String,
        /// Progress in permille, 0 to 1000.
        progress_permille: u16,
    },
    /// `OK` — a bare acknowledgement.
    Ok,
    /// `ERR <code>` — the agent refused.
    Error {
        /// The sanitised code.
        code: String,
    },
}

/// Why a reply could not be understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The line did not match the protocol.
    Malformed,
    /// The line exceeded [`MAX_LINE`].
    TooLong,
    /// A field held a value outside its permitted range.
    OutOfRange,
    /// A token was outside its closed vocabulary.
    UnknownToken,
}

impl ProtocolError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "fleet_protocol_violation",
            Self::TooLong => "fleet_reply_too_large",
            Self::OutOfRange => "fleet_reply_out_of_range",
            Self::UnknownToken => "fleet_reply_unknown_token",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the agent reply violated the protocol",
            Self::TooLong => "the agent reply exceeded the permitted size",
            Self::OutOfRange => "an agent reply field was out of range",
            Self::UnknownToken => "an agent reply token was not recognised",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// Bound and narrow an agent-supplied token to an identifier alphabet.
///
/// The agent is trusted to actuate, not to author strings the router will echo
/// into a log line, an error body, or an operator's browser. Truncating to
/// [`MAX_CODE_LEN`] and mapping everything outside `[A-Za-z0-9_.-]` to `_`
/// closes terminal-escape, newline, and quote injection in one place — the same
/// treatment `hypellm_net::helper::sanitize_code` gives the TLS helper.
#[must_use]
pub fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .take(MAX_CODE_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parse one reply line against the verb that provoked it.
///
/// The request is required, not incidental: `OK 4096` means "an inventory of
/// 4,096 bytes follows" after `OBSERVE` and means nothing at all after
/// `CANCEL`, and a parser that accepted either would let a confused agent
/// advance a state machine it was not answering.
pub fn parse_reply(request: &AgentRequest, line: &str) -> Result<AgentReply, ProtocolError> {
    if line.len() > MAX_LINE {
        return Err(ProtocolError::TooLong);
    }
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if let Some(code) = line.strip_prefix("ERR ") {
        return Ok(AgentReply::Error {
            code: sanitize_token(code),
        });
    }
    if line == "ERR" {
        return Ok(AgentReply::Error {
            code: "unspecified".to_owned(),
        });
    }

    let mut parts = line.split(' ');
    let head = parts.next().unwrap_or("");

    match request {
        AgentRequest::Hello { .. } => {
            if head != "OK" {
                return Err(ProtocolError::Malformed);
            }
            let (Some(version), Some(digest)) = (parts.next(), parts.next()) else {
                return Err(ProtocolError::Malformed);
            };
            if parts.next().is_some() {
                return Err(ProtocolError::Malformed);
            }
            Ok(AgentReply::Hello {
                agent_version: sanitize_token(version),
                fleet_digest: sanitize_token(digest),
            })
        }
        AgentRequest::Observe => {
            if head != "OK" {
                return Err(ProtocolError::Malformed);
            }
            let Some(raw) = parts.next() else {
                return Err(ProtocolError::Malformed);
            };
            if parts.next().is_some() {
                return Err(ProtocolError::Malformed);
            }
            let length: usize = raw.parse().map_err(|_| ProtocolError::Malformed)?;
            if length > crate::state::MAX_INVENTORY_BYTES {
                // Checked against the declared length *before* anything is
                // allocated, so an agent cannot make the router reserve a
                // quarter of a gigabyte by writing a number.
                return Err(ProtocolError::TooLong);
            }
            Ok(AgentReply::InventoryPending { length })
        }
        AgentRequest::Activate { .. } | AgentRequest::Deactivate { .. } | AgentRequest::Fetch { .. } => {
            if head != "ACCEPTED" {
                return Err(ProtocolError::Malformed);
            }
            let Some(raw) = parts.next() else {
                return Err(ProtocolError::Malformed);
            };
            if parts.next().is_some() {
                return Err(ProtocolError::Malformed);
            }
            let activation = ActivationId::new(raw).map_err(|_| ProtocolError::Malformed)?;
            Ok(AgentReply::Accepted { activation })
        }
        AgentRequest::Status { .. } => {
            if head != "OK" {
                return Err(ProtocolError::Malformed);
            }
            let (Some(state), Some(detail), Some(progress)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(ProtocolError::Malformed);
            };
            if parts.next().is_some() {
                return Err(ProtocolError::Malformed);
            }
            let state =
                crate::state::ObservedState::parse(state).ok_or(ProtocolError::UnknownToken)?;
            let progress: u16 = progress.parse().map_err(|_| ProtocolError::Malformed)?;
            if progress > 1_000 {
                return Err(ProtocolError::OutOfRange);
            }
            Ok(AgentReply::Status {
                state,
                detail: sanitize_token(detail),
                progress_permille: progress,
            })
        }
        AgentRequest::Cancel { .. } => {
            if head == "OK" && parts.next().is_none() {
                Ok(AgentReply::Ok)
            } else {
                Err(ProtocolError::Malformed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activate() -> AgentRequest {
        AgentRequest::Activate {
            deployment: DeploymentId::new("spark-music3").expect("id"),
            lease: LeaseId::new("l-1").expect("id"),
            deadline_ms: 300_000,
        }
    }

    #[test]
    fn a_request_line_carries_identifiers_and_integers_and_nothing_else() {
        let line = encode_request(&activate());
        assert_eq!(line, "ACTIVATE spark-music3 l-1 300000\n");
        // The identifier alphabet excludes whitespace, so no component can
        // introduce a field or a line. Asserted rather than assumed, because
        // the whole trust boundary rests on it.
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(line.trim_end().split(' ').count(), 4);
    }

    #[test]
    fn a_reply_is_parsed_against_the_verb_that_provoked_it() {
        // `OK 4096` is an inventory length after OBSERVE and nonsense after
        // ACTIVATE. A parser that accepted either would let a confused agent
        // advance a state machine it was not answering.
        assert_eq!(
            parse_reply(&AgentRequest::Observe, "OK 4096\n"),
            Ok(AgentReply::InventoryPending { length: 4096 })
        );
        assert_eq!(
            parse_reply(&activate(), "OK 4096\n"),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            parse_reply(&AgentRequest::Observe, "ACCEPTED a-1\n"),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_oversized_inventory_length_is_refused_before_anything_is_allocated() {
        let line = format!("OK {}\n", crate::state::MAX_INVENTORY_BYTES + 1);
        assert_eq!(
            parse_reply(&AgentRequest::Observe, &line),
            Err(ProtocolError::TooLong)
        );
    }

    #[test]
    fn an_agent_error_code_cannot_carry_control_characters_into_a_log() {
        let reply = parse_reply(&activate(), "ERR \u{1b}[2Jwiped\nnewline\n").expect("parses");
        let AgentReply::Error { code } = reply else {
            panic!("expected an error reply");
        };
        assert!(!code.contains('\u{1b}'));
        assert!(!code.contains('\n'));
        assert!(code.len() <= MAX_CODE_LEN);
    }

    #[test]
    fn a_status_progress_beyond_one_thousand_permille_is_refused() {
        let status = AgentRequest::Status {
            activation: ActivationId::new("a-1").expect("id"),
        };
        assert_eq!(
            parse_reply(&status, "OK starting loading 500\n"),
            Ok(AgentReply::Status {
                state: crate::state::ObservedState::Starting,
                detail: "loading".to_owned(),
                progress_permille: 500,
            })
        );
        assert_eq!(
            parse_reply(&status, "OK starting loading 1001\n"),
            Err(ProtocolError::OutOfRange)
        );
        assert_eq!(
            parse_reply(&status, "OK levitating loading 500\n"),
            Err(ProtocolError::UnknownToken)
        );
    }

    #[test]
    fn a_reply_with_trailing_fields_is_refused_rather_than_truncated() {
        // Extra fields mean the two sides disagree about the protocol version,
        // and the handshake exists precisely so that they cannot.
        assert_eq!(
            parse_reply(&activate(), "ACCEPTED a-1 extra\n"),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn the_handshake_hmac_binds_the_version_the_nonce_and_the_digest() {
        let key = b"fleet key";
        let base = hello_hmac(key, "abc", "sha256:1111");
        assert_ne!(base, hello_hmac(key, "abd", "sha256:1111"));
        assert_ne!(base, hello_hmac(key, "abc", "sha256:2222"));
        assert_ne!(base, hello_hmac(b"other key", "abc", "sha256:1111"));
        // Part boundaries are preserved: shifting a character across the
        // nonce/digest boundary must not produce the same tag.
        assert_ne!(
            hello_hmac(key, "ab", "csha256:1111"),
            hello_hmac(key, "abc", "sha256:1111")
        );
    }
}
