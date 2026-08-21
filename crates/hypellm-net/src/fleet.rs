//! The fleet-agent client.
//!
//! The third member of the helper family. Specification 4 delegates outbound
//! TLS to a platform helper; specification 9.1 delegates JWT verification to a
//! local verifier; this delegates *actuation* to an agent that holds SSH keys
//! to the fleet. The router never runs `ssh`, `docker`, or `powershell.exe`, and
//! must not be changed so that it can: `depscan`'s `forbidden-api` rule fails
//! the build on `process::Command`, and a router that can spawn a shell is a
//! different security proposition.
//!
//! This module is the socket. The protocol itself — what a line means, what a
//! reply may contain, what an inventory may declare — is
//! `hypellm_fleet::protocol` and `hypellm_fleet::state`, which are pure and
//! fuzzed. Keeping the two apart means the parsing rules can be tested without a
//! socket, and the socket has nothing to interpret.
//!
//! # The session, and why it is not one connection per verb
//!
//! `TlsHelper` and `VerifierClient` open a connection per exchange, which is
//! right for a stateless request. This handshake is not stateless: `HELLO` binds
//! the protocol version and the fleet digest, and re-handshaking for every
//! `STATUS` poll would spend an HMAC and a nonce on each one. A session is held
//! open and re-established on any error, which is also what makes "the agent is
//! unreachable" a state the router can observe rather than infer.

use core::fmt;
use hypellm_core::ids::{ActivationId, ArtifactId, DeploymentId, HostId, LeaseId};
use hypellm_fleet::model::FleetConfig;
use hypellm_fleet::protocol::{
    AgentReply, AgentRequest, ProtocolError, encode_request, hello_hmac, parse_reply,
};
use hypellm_fleet::state::{Inventory, InventoryError, ObservedState, parse_inventory};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Maximum bytes the client will read while looking for a newline.
const MAX_LINE: usize = hypellm_fleet::protocol::MAX_LINE;

/// Why an exchange with the fleet agent failed.
#[derive(Debug)]
pub enum FleetError {
    /// The agent socket could not be reached.
    Unavailable(io::Error),
    /// The agent refused the request, with its sanitised code.
    Refused {
        /// The agent's code, bounded and narrowed to an identifier alphabet.
        code: String,
    },
    /// The agent's reply did not match the protocol.
    Protocol(ProtocolError),
    /// The agent's inventory could not be adopted.
    Inventory(InventoryError),
    /// The router and the agent disagree about the fleet configuration.
    ///
    /// Fails closed rather than warning: the router issues no mutating verb,
    /// every orchestrated target is excluded, and the disagreement is audited.
    /// A router and an agent that disagree about what an identifier *means*
    /// must not act on that disagreement.
    DigestMismatch {
        /// What this router computes.
        ours: String,
        /// What the agent computes.
        theirs: String,
    },
}

impl FleetError {
    /// Stable code for logs, metrics, and audit records.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "fleet_agent_unavailable",
            Self::Refused { .. } => "fleet_agent_refused",
            Self::Protocol(e) => e.code(),
            Self::Inventory(e) => e.code(),
            Self::DigestMismatch { .. } => "fleet_configuration_mismatch",
        }
    }

    /// Whether the session must be discarded and re-established.
    ///
    /// A refusal is the agent answering; anything else means the router no
    /// longer knows where in the conversation it is, and continuing on the same
    /// socket would risk reading one verb's reply as another's.
    #[must_use]
    pub const fn is_fatal_to_session(&self) -> bool {
        !matches!(self, Self::Refused { .. })
    }
}

impl fmt::Display for FleetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "the fleet agent is unavailable: {e}"),
            Self::Refused { code } => write!(f, "the fleet agent refused the request: {code}"),
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Inventory(e) => write!(f, "{e}"),
            Self::DigestMismatch { ours, theirs } => write!(
                f,
                "the fleet configuration digests disagree: router {ours}, agent {theirs}"
            ),
        }
    }
}

impl std::error::Error for FleetError {}

/// What the agent reported about one activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationStatus {
    /// Where it has got to.
    pub state: ObservedState,
    /// A bounded, sanitised detail code.
    pub detail: String,
    /// Progress in permille.
    pub progress_permille: u16,
}

/// A client for one configured fleet agent.
///
/// Holds the socket path and the timeout, not the key: the key is borrowed for
/// the length of a handshake and never retained, so no long-lived value in this
/// process holds `fleet.key`.
#[derive(Debug, Clone)]
pub struct FleetAgentClient {
    socket_path: String,
    timeout: Duration,
}

impl FleetAgentClient {
    /// Create a client for the agent at `socket_path`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout,
        }
    }

    /// The configured socket path.
    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Open a session, performing the authenticated handshake.
    ///
    /// The digest is computed by the caller from its own `FleetConfig` and
    /// compared against the agent's. A mismatch is an error rather than a
    /// warning, and the session is not returned: without a shared
    /// understanding of what each identifier means, no verb is safe to send.
    pub fn open(&self, key: &[u8], fleet_digest: &str) -> Result<FleetSession, FleetError> {
        let stream = UnixStream::connect(&self.socket_path).map_err(FleetError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(FleetError::Unavailable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(FleetError::Unavailable)?;

        let nonce = nonce()?;
        let hmac = hello_hmac(key, &nonce, fleet_digest);
        let request = AgentRequest::Hello {
            nonce,
            fleet_digest: fleet_digest.to_owned(),
            hmac,
        };

        let mut session = FleetSession {
            reader: BufReader::new(stream.try_clone().map_err(FleetError::Unavailable)?),
            writer: stream,
            agent_version: String::new(),
        };

        match session.exchange(&request)? {
            AgentReply::Hello {
                agent_version,
                fleet_digest: theirs,
            } => {
                // A constant-time comparison is not required here — the digest
                // is public, computed from configuration both sides hold — but
                // the comparison must be exact and must fail closed.
                if theirs != fleet_digest {
                    return Err(FleetError::DigestMismatch {
                        ours: fleet_digest.to_owned(),
                        theirs,
                    });
                }
                session.agent_version = agent_version;
                Ok(session)
            }
            AgentReply::Error { code } => Err(FleetError::Refused { code }),
            _ => Err(FleetError::Protocol(ProtocolError::Malformed)),
        }
    }
}

/// A fresh nonce for one handshake.
///
/// Failure to obtain randomness is an availability failure, not something to
/// paper over with a counter: a predictable nonce would defeat the replay
/// protection the handshake exists to provide.
fn nonce() -> Result<String, FleetError> {
    let bytes = hypellm_crypto::random::bytes::<16>().map_err(|_| {
        FleetError::Unavailable(io::Error::other("the system entropy source is unavailable"))
    })?;
    Ok(hypellm_crypto::hex::encode(&bytes))
}

/// An open, authenticated session with a fleet agent.
#[derive(Debug)]
pub struct FleetSession {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    agent_version: String,
}

impl FleetSession {
    /// The agent's declared version, sanitised.
    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    /// Send one request and read its single-line reply.
    fn exchange(&mut self, request: &AgentRequest) -> Result<AgentReply, FleetError> {
        let line = encode_request(request);
        self.writer
            .write_all(line.as_bytes())
            .map_err(FleetError::Unavailable)?;
        self.writer.flush().map_err(FleetError::Unavailable)?;
        let reply = self.read_line()?;
        parse_reply(request, &reply).map_err(FleetError::Protocol)
    }

    /// Read one bounded, newline-terminated line.
    ///
    /// Byte at a time against a fixed ceiling, like
    /// `helper::read_status_line`: a `read_line` that grew a `String` until it
    /// found a newline would let an agent that never sends one exhaust memory.
    fn read_line(&mut self) -> Result<String, FleetError> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if line.len() >= MAX_LINE {
                return Err(FleetError::Protocol(ProtocolError::TooLong));
            }
            let read = self.reader.read(&mut byte).map_err(FleetError::Unavailable)?;
            if read == 0 {
                return Err(FleetError::Protocol(ProtocolError::Malformed));
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        String::from_utf8(line).map_err(|_| FleetError::Protocol(ProtocolError::Malformed))
    }

    /// Ask for the current inventory.
    ///
    /// The declared length is checked against the bound *before* anything is
    /// allocated, so an agent cannot make the router reserve a quarter of a
    /// gigabyte by writing a number. The payload is then parsed against the
    /// caller's own `FleetConfig`, which is what drops identifiers the
    /// administrator never declared.
    pub fn observe(&mut self, fleet: &FleetConfig) -> Result<Inventory, FleetError> {
        let reply = self.exchange(&AgentRequest::Observe)?;
        let length = match reply {
            AgentReply::InventoryPending { length } => length,
            AgentReply::Error { code } => return Err(FleetError::Refused { code }),
            _ => return Err(FleetError::Protocol(ProtocolError::Malformed)),
        };
        let mut payload = vec![0u8; length];
        self.reader
            .read_exact(&mut payload)
            .map_err(|_| FleetError::Protocol(ProtocolError::Malformed))?;
        parse_inventory(&payload, fleet).map_err(FleetError::Inventory)
    }

    /// Bring a deployment up.
    ///
    /// Idempotent per lease: re-sending under the same lease returns the same
    /// activation rather than starting a second one, which is what makes
    /// restart recovery tractable.
    pub fn activate(
        &mut self,
        deployment: &DeploymentId,
        lease: &LeaseId,
        deadline_ms: u64,
    ) -> Result<ActivationId, FleetError> {
        self.accepted(&AgentRequest::Activate {
            deployment: deployment.clone(),
            lease: lease.clone(),
            deadline_ms,
        })
    }

    /// Take a deployment down, giving in-flight work `drain_ms` to finish.
    pub fn deactivate(
        &mut self,
        deployment: &DeploymentId,
        lease: &LeaseId,
        drain_ms: u64,
    ) -> Result<ActivationId, FleetError> {
        self.accepted(&AgentRequest::Deactivate {
            deployment: deployment.clone(),
            lease: lease.clone(),
            drain_ms,
        })
    }

    /// Acquire an artifact onto a host.
    pub fn fetch(
        &mut self,
        artifact: &ArtifactId,
        host: &HostId,
        deadline_ms: u64,
    ) -> Result<ActivationId, FleetError> {
        self.accepted(&AgentRequest::Fetch {
            artifact: artifact.clone(),
            host: host.clone(),
            deadline_ms,
        })
    }

    fn accepted(&mut self, request: &AgentRequest) -> Result<ActivationId, FleetError> {
        match self.exchange(request)? {
            AgentReply::Accepted { activation } => Ok(activation),
            AgentReply::Error { code } => Err(FleetError::Refused { code }),
            _ => Err(FleetError::Protocol(ProtocolError::Malformed)),
        }
    }

    /// Ask how an activation is going.
    pub fn status(&mut self, activation: &ActivationId) -> Result<ActivationStatus, FleetError> {
        match self.exchange(&AgentRequest::Status {
            activation: activation.clone(),
        })? {
            AgentReply::Status {
                state,
                detail,
                progress_permille,
            } => Ok(ActivationStatus {
                state,
                detail,
                progress_permille,
            }),
            AgentReply::Error { code } => Err(FleetError::Refused { code }),
            _ => Err(FleetError::Protocol(ProtocolError::Malformed)),
        }
    }

    /// Abandon an activation.
    pub fn cancel(&mut self, activation: &ActivationId) -> Result<(), FleetError> {
        match self.exchange(&AgentRequest::Cancel {
            activation: activation.clone(),
        })? {
            AgentReply::Ok => Ok(()),
            AgentReply::Error { code } => Err(FleetError::Refused { code }),
            _ => Err(FleetError::Protocol(ProtocolError::Malformed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_store::TempDir;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Run a scripted agent that replies with each line in turn.
    ///
    /// Returns the socket path and a handle yielding everything the router
    /// sent, so a test can assert on the *request* as well as the response —
    /// which is where the trust boundary lives.
    fn agent(dir: &TempDir, name: &str, script: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<u8>>) {
        let path = dir.join(name).to_string_lossy().into_owned();
        let listener = UnixListener::bind(&path).expect("bind");
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut seen = Vec::new();
            for reply in script {
                // Read one line of request before answering, so the exchange
                // stays in lockstep and a test cannot pass by accident.
                let mut byte = [0u8; 1];
                loop {
                    match socket.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            seen.push(byte[0]);
                            if byte[0] == b'\n' {
                                break;
                            }
                        }
                    }
                }
                if socket.write_all(&reply).is_err() {
                    break;
                }
                let _ = socket.flush();
            }
            seen
        });
        (path, handle)
    }

    const DIGEST: &str = "sha256deadbeef";

    #[test]
    fn a_digest_mismatch_refuses_the_session_rather_than_warning() {
        // The router and the agent disagreeing about what an identifier means
        // is exactly the moment not to send a verb that stops a model.
        let dir = TempDir::new("fleet-digest");
        let (path, server) = agent(&dir, "a.sock", vec![b"OK agent-1 sha256other\n".to_vec()]);
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let error = client.open(b"key", DIGEST).expect_err("must refuse");
        assert!(matches!(error, FleetError::DigestMismatch { .. }));
        assert_eq!(error.code(), "fleet_configuration_mismatch");
        let _ = server.join();
    }

    #[test]
    fn the_handshake_sends_a_keyed_tag_and_never_the_key() {
        let dir = TempDir::new("fleet-hello");
        let (path, server) = agent(
            &dir,
            "a.sock",
            vec![format!("OK agent-1 {DIGEST}\n").into_bytes()],
        );
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let session = client.open(b"super-secret-key", DIGEST).expect("opens");
        assert_eq!(session.agent_version(), "agent-1");
        drop(session);

        let sent = String::from_utf8(server.join().expect("join")).expect("utf8");
        assert!(sent.starts_with("HELLO 1 "), "got {sent:?}");
        assert!(
            !sent.contains("super-secret-key"),
            "the key must never reach the wire"
        );
        // Verb, version, nonce, claimed digest, and tag: five fields, one line.
        assert_eq!(sent.trim_end().split(' ').count(), 5);
        assert!(
            sent.contains(DIGEST),
            "the digest is sent as well as covered, so a mismatch is diagnosable"
        );
        assert_eq!(sent.matches('\n').count(), 1);
    }

    #[test]
    fn an_activation_request_carries_only_identifiers_and_an_integer() {
        let dir = TempDir::new("fleet-activate");
        let (path, server) = agent(
            &dir,
            "a.sock",
            vec![
                format!("OK agent-1 {DIGEST}\n").into_bytes(),
                b"ACCEPTED act-7\n".to_vec(),
            ],
        );
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let mut session = client.open(b"key", DIGEST).expect("opens");
        let activation = session
            .activate(
                &DeploymentId::new("spark-music3").expect("id"),
                &LeaseId::new("lease-1").expect("id"),
                300_000,
            )
            .expect("accepted");
        assert_eq!(activation.as_str(), "act-7");
        drop(session);

        let sent = String::from_utf8(server.join().expect("join")).expect("utf8");
        let verb = sent.lines().nth(1).unwrap_or_default();
        assert_eq!(verb, "ACTIVATE spark-music3 lease-1 300000");
    }

    #[test]
    fn an_agent_naming_an_undeclared_deployment_has_it_dropped() {
        let dir = TempDir::new("fleet-observe");
        let body = br#"{"deployments":[{"id":"not-declared","state":"ready"}]}"#;
        let mut reply = format!("OK {}\n", body.len()).into_bytes();
        reply.extend_from_slice(body);
        let (path, server) = agent(
            &dir,
            "a.sock",
            vec![format!("OK agent-1 {DIGEST}\n").into_bytes(), reply],
        );
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let mut session = client.open(b"key", DIGEST).expect("opens");
        let inventory = session
            .observe(&FleetConfig::empty())
            .expect("an inventory of nothing is still an inventory");
        assert!(inventory.deployments.is_empty());
        assert_eq!(inventory.unknown_identifiers, 1);
        drop(session);
        let _ = server.join();
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_it_is_read() {
        let dir = TempDir::new("fleet-oversize");
        let huge = hypellm_fleet::state::MAX_INVENTORY_BYTES + 1;
        let (path, server) = agent(
            &dir,
            "a.sock",
            vec![
                format!("OK agent-1 {DIGEST}\n").into_bytes(),
                format!("OK {huge}\n").into_bytes(),
            ],
        );
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let mut session = client.open(b"key", DIGEST).expect("opens");
        let error = session
            .observe(&FleetConfig::empty())
            .expect_err("must refuse");
        assert_eq!(error.code(), "fleet_reply_too_large");
        assert!(error.is_fatal_to_session());
        drop(session);
        let _ = server.join();
    }

    #[test]
    fn a_line_with_no_newline_cannot_exhaust_memory() {
        let dir = TempDir::new("fleet-unbounded");
        let (path, server) = agent(&dir, "a.sock", vec![vec![b'A'; MAX_LINE * 4]]);
        let client = FleetAgentClient::new(path, Duration::from_secs(5));
        let error = client.open(b"key", DIGEST).expect_err("must refuse");
        assert_eq!(error.code(), "fleet_reply_too_large");
        let _ = server.join();
    }

    #[test]
    fn an_unreachable_agent_is_unavailable_rather_than_a_refusal() {
        // The distinction matters operationally: a refusal means the agent
        // answered, and an outage means it did not.
        let client = FleetAgentClient::new("/nonexistent/fleet.sock", Duration::from_millis(50));
        let error = client.open(b"key", DIGEST).expect_err("must fail");
        assert_eq!(error.code(), "fleet_agent_unavailable");
    }
}
