//! A simulated fleet agent.
//!
//! The real agent holds SSH keys to five machines and runs `docker compose`.
//! Nothing in `cargo test --workspace --offline` may do either, and a test
//! suite that could not exercise the activation path at all would be worse than
//! one that exercises it against a simulation — so this is the simulation, and
//! it is deliberately a *conformant* one rather than a stub.
//!
//! It speaks the whole protocol, over a real Unix socket, against the real
//! client. It verifies the handshake HMAC with the real
//! `hypellm_crypto::hmac`, refuses a nonce it has already accepted, keeps its
//! own allowlist of deployment identifiers, and drives a deployment through
//! `starting → probing → ready` on a clock the test controls.
//!
//! # What it deliberately does not do
//!
//! It does not compute the fleet digest. Computing it would mean reimplementing
//! `FleetConfig::canonical_form` here, and two implementations of one canonical
//! form is exactly the disagreement the digest exists to detect — a bug in the
//! copy would make the test pass and production fail. The digest it reports is
//! supplied by the test, which also lets a test hand it the *wrong* one and
//! assert that the router refuses to issue a verb.
//!
//! # Why it lives here
//!
//! Beside the client it exercises, behind `test-harness` so it does not ship.
//! `hypellm-fleet` states that it performs no I/O, and a socket server in it —
//! even a test-only one — would make that claim false.

use hypellm_core::ids::{ActivationId, ArtifactId, DeploymentId, HostId};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// How the agent should behave for one deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Becomes ready after `steps` polls.
    ReadyAfter(u32),
    /// Reports `failed` after `steps` polls.
    FailsAfter(u32),
    /// Never leaves `starting`, so the caller's deadline is what ends it.
    Hangs,
    /// Refuses the verb outright with `ERR <code>`.
    Refuses(&'static str),
}

/// What the simulated agent will admit and how it will behave.
#[derive(Debug, Clone)]
pub struct AgentScript {
    /// The digest the agent claims. A test may set this to something the router
    /// does not compute, to exercise the mismatch path.
    pub fleet_digest: String,
    /// The key the handshake is verified with.
    pub key: Vec<u8>,
    /// Deployments the agent will act on. Anything else is refused with
    /// `ERR unknown_deployment`, which is the property that matters: a
    /// compromised router can reorder declared deployments and cannot
    /// introduce one.
    pub deployments: BTreeMap<DeploymentId, Behaviour>,
    /// Artifacts the agent will fetch.
    pub artifacts: BTreeSet<ArtifactId>,
    /// Hosts the agent manages.
    pub hosts: BTreeSet<HostId>,
    /// The state each deployment starts in, before any verb.
    pub initial_states: BTreeMap<DeploymentId, String>,
    /// Extra inventory entries, rendered verbatim into the `deployments`
    /// array.
    ///
    /// The escape hatch for tests about *malformed or undeclared* input: an
    /// identifier the router's configuration does not declare, a state token
    /// outside the vocabulary, a number out of range. Everything a conformant
    /// agent would report comes from the live state map instead.
    pub raw_deployments: Vec<String>,
    /// Extra top-level inventory keys, rendered verbatim.
    pub extra_inventory: String,
}

impl AgentScript {
    /// An agent that admits nothing, for tests about refusal.
    #[must_use]
    pub fn empty(fleet_digest: impl Into<String>, key: &[u8]) -> Self {
        Self {
            fleet_digest: fleet_digest.into(),
            key: key.to_vec(),
            deployments: BTreeMap::new(),
            artifacts: BTreeSet::new(),
            hosts: BTreeSet::new(),
            initial_states: BTreeMap::new(),
            raw_deployments: Vec::new(),
            extra_inventory: String::new(),
        }
    }

    /// Admit one deployment with a behaviour.
    #[must_use]
    pub fn with_deployment(mut self, id: &str, behaviour: Behaviour) -> Self {
        if let Ok(id) = DeploymentId::new(id) {
            self.deployments.insert(id, behaviour);
        }
        self
    }

    /// Admit one artifact.
    #[must_use]
    pub fn with_artifact(mut self, id: &str) -> Self {
        if let Ok(id) = ArtifactId::new(id) {
            self.artifacts.insert(id);
        }
        self
    }

    /// Start a deployment in a given state.
    #[must_use]
    pub fn with_state(mut self, id: &str, state: &str) -> Self {
        if let Ok(id) = DeploymentId::new(id) {
            self.initial_states.insert(id, state.to_owned());
        }
        self
    }

    /// Add an inventory entry the agent renders verbatim.
    #[must_use]
    pub fn with_raw_deployment(mut self, json: impl Into<String>) -> Self {
        self.raw_deployments.push(json.into());
        self
    }

    /// Add extra top-level inventory keys, rendered verbatim.
    #[must_use]
    pub fn with_extra_inventory(mut self, json: impl Into<String>) -> Self {
        self.extra_inventory = json.into();
        self
    }
}

/// A running simulated agent.
#[derive(Debug)]
pub struct SimulatedAgent {
    path: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    /// Verbs received, in order, so a test can assert on what crossed the
    /// socket rather than only on what came back.
    seen: Arc<Mutex<Vec<String>>>,
    /// Nonces already accepted, so a replayed handshake is refused.
    nonces: Arc<Mutex<BTreeSet<String>>>,
    /// Current state per deployment, as the agent believes it.
    states: Arc<Mutex<BTreeMap<DeploymentId, String>>>,
}

/// One in-flight verb, and what it will end as.
#[derive(Debug, Clone)]
struct Pending {
    deployment: DeploymentId,
    /// Polls remaining before the terminal state.
    remaining: u32,
    behaviour: Behaviour,
    /// Whether the verb was bringing the deployment up or taking it down.
    ///
    /// The terminal state differs: a completed `ACTIVATE` ends `ready` and a
    /// completed `DEACTIVATE` ends `stopped`. A simulator that reported both as
    /// `ready` would let a test believe a model it had just stopped was still
    /// running — and that is exactly the belief the cooldown rules depend on.
    starting: bool,
}

impl SimulatedAgent {
    /// Start an agent on `path`.
    ///
    /// # Panics
    ///
    /// If the socket cannot be bound. This is test scaffolding; a bind failure
    /// means the test cannot run at all.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "test scaffolding: a socket that cannot be bound means the test cannot run"
    )]
    pub fn start(path: &str, script: AgentScript) -> Self {
        let listener = UnixListener::bind(path).expect("bind the simulated agent socket");
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let nonces = Arc::new(Mutex::new(BTreeSet::new()));
        let states = Arc::new(Mutex::new(script.initial_states.clone()));
        let countdowns = Arc::new(Mutex::new(BTreeMap::new()));
        let next_activation = Arc::new(AtomicU64::new(1));

        let worker = Arc::new(Worker {
            script,
            stop: Arc::clone(&stop),
            seen: Arc::clone(&seen),
            nonces: Arc::clone(&nonces),
            states: Arc::clone(&states),
            countdowns: Arc::clone(&countdowns),
            next_activation: Arc::clone(&next_activation),
        });
        let handle = thread::spawn(move || worker.run(&listener));

        Self {
            path: path.to_owned(),
            stop,
            handle: Some(handle),
            seen,
            nonces,
            states,
        }
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Every verb the agent received, in order.
    #[must_use]
    pub fn verbs(&self) -> Vec<String> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// The state the agent believes a deployment is in.
    #[must_use]
    pub fn state_of(&self, deployment: &str) -> Option<String> {
        let id = DeploymentId::new(deployment).ok()?;
        self.states.lock().ok()?.get(&id).cloned()
    }

    /// How many distinct handshakes have been accepted.
    #[must_use]
    pub fn handshakes(&self) -> usize {
        self.nonces.lock().map(|n| n.len()).unwrap_or(0)
    }

    /// Stop the agent and remove its socket.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop by connecting once.
        let _ = UnixStream::connect(&self.path);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for SimulatedAgent {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct Worker {
    script: AgentScript,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<String>>>,
    nonces: Arc<Mutex<BTreeSet<String>>>,
    states: Arc<Mutex<BTreeMap<DeploymentId, String>>>,
    countdowns: Arc<Mutex<BTreeMap<ActivationId, Pending>>>,
    next_activation: Arc<AtomicU64>,
}

impl Worker {
    fn run(self: &Arc<Self>, listener: &UnixListener) {
        let mut connections: Vec<thread::JoinHandle<()>> = Vec::new();
        while !self.stop.load(Ordering::SeqCst) {
            let Ok((stream, _)) = listener.accept() else {
                continue;
            };
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // One thread per connection. The router holds its session open for
            // the life of the process, so an accept loop that served inline
            // would never come back to notice the stop flag — and a test that
            // could not stop its own agent would hang the suite rather than
            // fail it.
            let worker = Arc::clone(self);
            connections.push(thread::spawn(move || worker.serve(stream)));
            connections.retain(|h| !h.is_finished());
        }
        for handle in connections {
            let _ = handle.join();
        }
    }

    fn serve(&self, stream: UnixStream) {
        // A read timeout rather than a blocking read, so a session nobody is
        // using still notices the stop flag.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
        let Ok(mut writer) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(stream);
        let mut authenticated = false;
        let mut pending: Vec<u8> = Vec::new();

        while !self.stop.load(Ordering::SeqCst) {
            let mut byte = [0u8; 1];
            match reader.read(&mut byte) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            }
            if byte[0] != b'\n' {
                if pending.len() >= 4096 {
                    return;
                }
                pending.push(byte[0]);
                continue;
            }

            let Ok(line) = String::from_utf8(core::mem::take(&mut pending)) else {
                return;
            };
            let line = line.trim_end().to_owned();
            if line.is_empty() {
                return;
            }
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(line.clone());
            }

            // Rendered before the status line, because the status line
            // declares its length and the two must not be able to disagree.
            let inventory = self.inventory();
            let reply = self.answer(&line, &inventory, &mut authenticated);
            if writer.write_all(reply.as_bytes()).is_err() {
                return;
            }
            if line == "OBSERVE"
                && authenticated
                && writer.write_all(inventory.as_bytes()).is_err()
            {
                return;
            }
            if writer.flush().is_err() {
                return;
            }
        }
    }

    /// Render the inventory from the agent's own belief.
    ///
    /// A conformant agent reports what it observes, so the simulation does too:
    /// a deployment it has just started appears as `ready`, which is what lets
    /// a test exercise the whole path from cold to serving rather than only the
    /// verbs along the way.
    fn inventory(&self) -> String {
        let mut items: Vec<String> = Vec::new();
        if let Ok(states) = self.states.lock() {
            for (id, state) in states.iter() {
                items.push(format!(
                    r#"{{"id":"{id}","state":"{state}","memory_bytes":0,"inflight":0}}"#
                ));
            }
        }
        items.extend(self.script.raw_deployments.iter().cloned());
        let extra = if self.script.extra_inventory.is_empty() {
            String::new()
        } else {
            format!(",{}", self.script.extra_inventory)
        };
        format!(r#"{{"deployments":[{}]{extra}}}"#, items.join(","))
    }

    fn answer(&self, line: &str, inventory: &str, authenticated: &mut bool) -> String {
        let mut parts = line.split(' ');
        let verb = parts.next().unwrap_or("");

        if verb == "HELLO" {
            let (Some(version), Some(nonce), Some(claimed), Some(tag)) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return "ERR malformed\n".to_owned();
            };
            if version != "1" {
                return "ERR unsupported_version\n".to_owned();
            }
            // A nonce the agent has already accepted is refused, so a captured
            // handshake cannot be replayed.
            let fresh = match self.nonces.lock() {
                Ok(mut seen) => seen.insert(nonce.to_owned()),
                Err(_) => false,
            };
            if !fresh {
                return "ERR replayed_nonce\n".to_owned();
            }
            // Verified against the digest the router *claims*, so that
            // holding the key is proved independently of whether the two sides
            // agree about the fleet — and so a mismatch is diagnosable rather
            // than arriving as an authentication failure.
            let expected = hypellm_crypto::hmac::hmac_sha256_parts(
                &self.script.key,
                &[version.as_bytes(), nonce.as_bytes(), claimed.as_bytes()],
            );
            let expected_hex = hypellm_crypto::hex::encode(&expected);
            if !hypellm_crypto::ct::eq(expected_hex.as_bytes(), tag.as_bytes()) {
                return "ERR unauthenticated\n".to_owned();
            }
            // Authenticated either way: the router proved it holds the key. The
            // session opens so the router can *read* the disagreement, and the
            // router is what refuses to issue a mutating verb.
            *authenticated = true;
            return format!("OK sim-1 {}\n", self.script.fleet_digest);
        }

        if !*authenticated {
            // Nothing before the handshake. An agent that answered `OBSERVE`
            // to an unauthenticated caller would leak the fleet's shape to
            // anyone who could reach the socket.
            return "ERR unauthenticated\n".to_owned();
        }

        match verb {
            "OBSERVE" => format!("OK {}\n", inventory.len()),
            "ACTIVATE" | "DEACTIVATE" => {
                let Some(raw) = parts.next() else {
                    return "ERR malformed\n".to_owned();
                };
                let Ok(deployment) = DeploymentId::new(raw) else {
                    return "ERR unknown_deployment\n".to_owned();
                };
                let Some(behaviour) = self.script.deployments.get(&deployment).copied() else {
                    // The allowlist. This is the whole trust boundary: the
                    // router names an identifier and the agent decides whether
                    // it means anything.
                    return "ERR unknown_deployment\n".to_owned();
                };
                if let Behaviour::Refuses(code) = behaviour {
                    return format!("ERR {code}\n");
                }
                let id = self.next_activation.fetch_add(1, Ordering::SeqCst);
                let Ok(activation) = ActivationId::new(format!("act-{id}")) else {
                    return "ERR internal\n".to_owned();
                };
                let terminal_after = match behaviour {
                    Behaviour::ReadyAfter(n) | Behaviour::FailsAfter(n) => n,
                    _ => u32::MAX,
                };
                let starting = verb == "ACTIVATE";
                if let Ok(mut states) = self.states.lock() {
                    states.insert(
                        deployment.clone(),
                        if starting { "starting" } else { "stopping" }.to_owned(),
                    );
                }
                if let Ok(mut countdowns) = self.countdowns.lock() {
                    countdowns.insert(
                        activation.clone(),
                        Pending {
                            deployment,
                            remaining: terminal_after,
                            behaviour,
                            starting,
                        },
                    );
                }
                format!("ACCEPTED {activation}\n")
            }
            "FETCH" => {
                let Some(raw) = parts.next() else {
                    return "ERR malformed\n".to_owned();
                };
                let Ok(artifact) = ArtifactId::new(raw) else {
                    return "ERR unknown_artifact\n".to_owned();
                };
                if !self.script.artifacts.contains(&artifact) {
                    return "ERR unknown_artifact\n".to_owned();
                }
                let id = self.next_activation.fetch_add(1, Ordering::SeqCst);
                format!("ACCEPTED act-{id}\n")
            }
            "STATUS" => {
                let Some(raw) = parts.next() else {
                    return "ERR malformed\n".to_owned();
                };
                let Ok(activation) = ActivationId::new(raw) else {
                    return "ERR unknown_activation\n".to_owned();
                };
                let Ok(mut countdowns) = self.countdowns.lock() else {
                    return "ERR internal\n".to_owned();
                };
                let Some(pending) = countdowns.get_mut(&activation) else {
                    // An unknown activation is not "ready": a router that read
                    // it as success would dispatch to a model that never
                    // started.
                    return "ERR unknown_activation\n".to_owned();
                };
                if pending.remaining > 0 {
                    pending.remaining = pending.remaining.saturating_sub(1);
                    let interim = if pending.starting { "starting" } else { "stopping" };
                    return format!("OK {interim} working 500\n");
                }
                let state = match pending.behaviour {
                    Behaviour::FailsAfter(_) => "failed",
                    Behaviour::Hangs if pending.starting => "starting",
                    Behaviour::Hangs => "stopping",
                    _ if pending.starting => "ready",
                    _ => "stopped",
                };
                if let Ok(mut states) = self.states.lock() {
                    states.insert(pending.deployment.clone(), state.to_owned());
                }
                format!("OK {state} done 1000\n")
            }
            "CANCEL" => "OK\n".to_owned(),
            _ => "ERR unknown_verb\n".to_owned(),
        }
    }
}
