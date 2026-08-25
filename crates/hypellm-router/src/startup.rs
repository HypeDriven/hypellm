//! Startup, assembly, and shutdown.
//!
//! Specification 18.1: "Binary, startup validation, listener orchestration,
//! privilege drop, shutdown." Specification 20.1 requires that "graceful
//! shutdown stops admission, drains within deadline, cancels remainder,
//! flushes audit/state, and exits nonzero on integrity failure".
//!
//! # Startup order
//!
//! The order is deliberate and each step gates the next:
//!
//! 1. **Load and validate the configuration.** A deployment with an unresolved
//!    reference or a cleartext remote endpoint fails here, before a socket is
//!    bound (specification 11).
//! 2. **Open the store.** Its exclusive lock is what stops two routers writing
//!    one state directory; a torn tail truncates, an integrity failure aborts
//!    (specification 11.2).
//! 3. **Check reachability.** A configuration declaring HTTPS upstreams with no
//!    TLS helper fails now rather than on the first request.
//! 4. **Bind the listeners.** Last, so a router that answers is a router that
//!    is actually able to serve.

use hypellm_admin_api::{AdminApi, CorsPolicy, DecisionCache};
use hypellm_auth::{KeyStore, SessionPolicy, SessionStore, TrustedEdge};
use hypellm_config::ValidatedConfig;
use hypellm_core::admission::{AdmissionController, ScopeLimits};
use hypellm_core::health::{BreakerConfig, HealthRegistry};
use hypellm_core::ids::CredentialRef;
use hypellm_core::time::{Clock, SystemClock};
use hypellm_net::{
    ConnectionPool, Egress, PoolConfig, PooledResolver, Resolver, TlsHelper, VerifierClient,
};
use hypellm_store::{Activatable, AuditAction, AuditEvent, RecordKind, Store};
use hypellm_telemetry::{Severity, Telemetry};
use core::fmt;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::admin::AdminHandler;
use crate::routes::InferenceHandler;
use crate::server::{
    MAX_CONNECTION_STACK_BYTES, MIN_CONNECTION_STACK_BYTES, Server, ServerConfig, ShutdownHandle,
};
use crate::state::{CredentialStore, RouterState};

/// Why startup failed.
#[derive(Debug)]
pub enum StartupError {
    /// The configuration file could not be read.
    ConfigUnreadable {
        /// The path attempted.
        path: PathBuf,
        /// The underlying error.
        detail: String,
    },
    /// The configuration did not validate.
    ConfigInvalid(Vec<hypellm_config::ConfigError>),
    /// The durable store could not be opened.
    Store(String),
    /// The configuration declares destinations the deployment cannot reach.
    Unreachable(Vec<String>),
    /// A listener could not be bound.
    Listener {
        /// Which listener.
        which: &'static str,
        /// The address attempted.
        address: String,
        /// The underlying error.
        detail: String,
    },
    /// A required secret was not available.
    MissingSecret(&'static str),
    /// A declared provider credential could not be read.
    CredentialUnreadable {
        /// The credential reference from the configuration.
        reference: String,
        /// The file that was expected to hold it.
        path: PathBuf,
        /// Why it could not be read.
        detail: String,
    },
    /// The audit chain did not verify.
    ///
    /// Specification 11.2: startup "fails closed on protected-record integrity
    /// errors", and specification 17 makes the audit records a hash chain
    /// precisely so that a removed or reordered record is detectable. A router
    /// that starts anyway would be asserting an audit trail it cannot stand
    /// behind — which is worse than refusing, because the refusal is visible
    /// and the false assurance is not.
    AuditChainBroken {
        /// Sequence number of the first record that did not follow its
        /// predecessor.
        sequence: u64,
    },
    /// A configuration activation was recovered from the log but could not be
    /// restored.
    ///
    /// Startup fails rather than falling back to the file, because a silent
    /// fallback would revert a published policy — dropping an approved change
    /// with no signal beyond a log line nobody reads.
    ActivationUnrecoverable {
        /// The sequence number of the activation frame.
        sequence: u64,
        /// Why it could not be restored.
        detail: String,
    },
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigUnreadable { path, detail } => {
                write!(f, "cannot read {}: {detail}", path.display())
            }
            Self::ConfigInvalid(errors) => {
                writeln!(f, "the configuration did not validate:")?;
                for error in errors {
                    writeln!(f, "  {error}")?;
                }
                Ok(())
            }
            Self::Store(detail) => write!(f, "cannot open the state directory: {detail}"),
            Self::Unreachable(problems) => {
                writeln!(f, "the configuration declares unreachable destinations:")?;
                for problem in problems {
                    writeln!(f, "  {problem}")?;
                }
                Ok(())
            }
            Self::Listener {
                which,
                address,
                detail,
            } => write!(f, "cannot bind the {which} listener on {address}: {detail}"),
            Self::MissingSecret(name) => {
                write!(f, "the required secret '{name}' is not available")
            }
            Self::CredentialUnreadable {
                reference,
                path,
                detail,
            } => write!(
                f,
                "the configuration declares credential '{reference}' but its secret at {} \
                 could not be read: {detail}",
                path.display()
            ),
            Self::AuditChainBroken { sequence } => write!(
                f,
                "the audit chain is broken at sequence {sequence}: that record does not follow \
                 the one before it, which means a record was removed, reordered, or replaced. \
                 Refusing to start rather than vouch for an audit trail that does not verify. \
                 Investigate the state directory; the log is at <state_dir>/log.bin."
            ),
            Self::ActivationUnrecoverable { sequence, detail } => write!(
                f,
                "the configuration activation recorded at sequence {sequence} could not be \
                 restored: {detail}. Refusing to start on the file configuration, which would \
                 silently revert the published policy. Resolve by repairing the state \
                 directory or by starting with an empty one to adopt the file."
            ),
        }
    }
}

impl std::error::Error for StartupError {}

/// Secrets the router needs, supplied by the platform.
///
/// Specification 10: "At rest, secrets use an OS/platform secret facility or an
/// approved external vault accessed through a narrow local agent. If neither
/// exists, encrypted files require an operator-supplied startup key not stored
/// beside ciphertext."
///
/// The router reads these from files whose paths are given on the command
/// line, so the secret material never appears in the process's argument list
/// (visible in `/proc`) or in an environment variable (inherited by children).
pub struct Secrets {
    /// Authenticates protected store frames and the audit chain.
    pub store_mac: Vec<u8>,
    /// Derives API key verifiers.
    pub key_verifier: Vec<u8>,
    /// Derives session digests and CSRF tokens.
    pub session: Vec<u8>,
    /// Derives log pseudonyms.
    pub pseudonym: Vec<u8>,
    /// Derives OIDC transaction handles.
    pub oidc: Vec<u8>,
    /// Verifies a break-glass token. The digest, never the token.
    ///
    /// Specification 22.4: "Authorized operators use a preprovisioned local
    /// break-glass method stored offline." *Offline* is the whole point, so
    /// what the router keeps is a verifier — reading the secrets directory does
    /// not yield a way in. The token itself is printed once by
    /// `--generate-secrets` and is the operator's to store.
    pub break_glass: Vec<u8>,
    /// The break-glass token, present only in a bundle that was just generated.
    ///
    /// Never written to disk and never read back: `from_dir` always leaves this
    /// `None`. It exists so `--generate-secrets` can print the token once.
    pub break_glass_token: Option<String>,
    /// Authenticates commands on the control socket.
    ///
    /// Specification 20.1 requires graceful shutdown to exist; it does not
    /// authorise an unauthenticated trigger for it. Filesystem permission on
    /// the socket is the first control and this is the second, because a
    /// permission that depends on the deployment getting a directory mode right
    /// is one mistake away from letting any local account stop the router.
    pub control: Vec<u8>,
    /// Authenticates the fleet-agent handshake.
    ///
    /// Deliberately **not** `control.key`. That one sends the hex-encoded key
    /// itself as a bearer line; adequate for a local stop command, and
    /// inadequate for verbs that stop production models. The fleet handshake
    /// carries a keyed digest over the protocol version, a nonce, and the fleet
    /// digest, so it binds both what is being spoken and what both sides think
    /// the fleet is.
    ///
    /// Optional: a deployment with no fleet has no such file, and its absence
    /// is not a startup failure. A deployment *with* a fleet and no key cannot
    /// authenticate to its agent, which is.
    pub fleet: Option<Vec<u8>>,
    /// Provider credential secrets, keyed by the reference the configuration
    /// declares.
    ///
    /// Specification 7: adapters are "the only code that touches provider
    /// credentials", and they receive an opaque handle. These are the values
    /// behind those handles; nothing outside the adapter boundary reads one.
    pub provider: BTreeMap<CredentialRef, Vec<u8>>,
    /// The directory this bundle was read from, when it came from one.
    ///
    /// Kept so that provider credentials can be loaded after the configuration
    /// has been resolved — the set to load is declared by the configuration,
    /// which is not known when the bundle is first read.
    pub dir: Option<PathBuf>,
}

impl fmt::Debug for Secrets {
    /// Redacted. Every field is key material; a derived `Debug` would put the
    /// store MAC key, the API key verifier key, and every provider credential
    /// into any log line that formatted the startup bundle.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets")
            .field("store_mac", &"[redacted key material]")
            .field("key_verifier", &"[redacted key material]")
            .field("session", &"[redacted key material]")
            .field("pseudonym", &"[redacted key material]")
            .field("oidc", &"[redacted key material]")
            .field("control", &"[redacted key material]")
            .field("fleet", &"[redacted key material]")
            .field("break_glass", &"[redacted verifier]")
            .field("break_glass_token", &"[redacted key material]")
            .field("provider", &format_args!("{} credential(s) [redacted]", self.provider.len()))
            .finish()
    }
}

impl Secrets {
    /// Read the secret bundle from a directory.
    ///
    /// Each secret is one file. A missing file is an error rather than a
    /// generated default: a router that invents its own store MAC key on first
    /// boot cannot detect tampering across a restart, because an attacker can
    /// delete the state and let it invent a new one.
    pub fn from_dir(dir: &Path) -> Result<Self, StartupError> {
        fn read(dir: &Path, name: &'static str) -> Result<Vec<u8>, StartupError> {
            let path = dir.join(name);
            let bytes = std::fs::read(&path).map_err(|_| StartupError::MissingSecret(name))?;
            if bytes.len() < 32 {
                return Err(StartupError::MissingSecret(name));
            }
            Ok(bytes)
        }

        Ok(Self {
            store_mac: read(dir, "store_mac.key")?,
            key_verifier: read(dir, "key_verifier.key")?,
            session: read(dir, "session.key")?,
            pseudonym: read(dir, "pseudonym.key")?,
            oidc: read(dir, "oidc.key")?,
            control: read(dir, "control.key")?,
            // Optional, and read the same way as everything else when present:
            // a fleet key shorter than 32 bytes is treated as absent rather
            // than accepted, so a truncated file cannot silently weaken the
            // handshake.
            fleet: read(dir, "fleet.key").ok(),
            break_glass: read(dir, "break_glass.verifier")?,
            // Never read back: the token exists offline or not at all.
            break_glass_token: None,
            provider: BTreeMap::new(),
            dir: Some(dir.to_path_buf()),
        })
    }

    /// Load the provider credentials the configuration declares.
    ///
    /// Each `credential` record names one file in the secrets directory,
    /// `credentials/<id>`. This is a *declared* mapping, not discovery: the set
    /// of credentials comes from the configuration, the filename is a fixed
    /// function of the declared identifier, and a file nobody declared is never
    /// read. Specification 4.1 forbids "implicit file discovery", and reading
    /// whatever happens to be in a directory is exactly that.
    ///
    /// The identifier is validated by `CredentialRef`, so it cannot contain a
    /// path separator or `..` and cannot escape the directory.
    ///
    /// A declared credential whose file is missing is an error. Starting
    /// without it would leave the router unable to authenticate to that
    /// provider and only able to say so once a caller's request had already
    /// failed upstream.
    pub fn load_provider_credentials(
        &mut self,
        dir: &Path,
        declared: &[hypellm_config::CredentialMeta],
    ) -> Result<(), StartupError> {
        let root = dir.join("credentials");
        for credential in declared {
            let path = root.join(credential.id.as_str());
            let secret = std::fs::read(&path).map_err(|e| StartupError::CredentialUnreadable {
                reference: credential.id.as_str().to_owned(),
                path: path.clone(),
                detail: e.to_string(),
            })?;

            // Trailing newlines are what an operator gets from `echo key >
            // file`, and a credential with one appended authenticates nowhere.
            let trimmed: Vec<u8> = secret
                .iter()
                .copied()
                .rev()
                .skip_while(|b| matches!(b, b'\n' | b'\r'))
                .collect::<Vec<u8>>()
                .into_iter()
                .rev()
                .collect();

            if trimmed.is_empty() {
                return Err(StartupError::CredentialUnreadable {
                    reference: credential.id.as_str().to_owned(),
                    path,
                    detail: "the file is empty".to_owned(),
                });
            }
            // Refused here rather than at the adapter, where a value that is
            // not header-safe silently omits the authentication header and
            // dispatches the request unauthenticated — and where a value
            // containing CR or LF would inject headers of its own.
            if !hypellm_adapters::is_usable_credential(&trimmed) {
                return Err(StartupError::CredentialUnreadable {
                    reference: credential.id.as_str().to_owned(),
                    path,
                    detail: "the value contains bytes that cannot appear in an \
                             authentication header (visible ASCII and tab only)"
                        .to_owned(),
                });
            }
            self.provider.insert(credential.id.clone(), trimmed);
        }
        Ok(())
    }

    /// Generate a bundle, for a development profile.
    ///
    /// # Errors
    ///
    /// Fails if the OS entropy source is unavailable.
    pub fn generate() -> Result<Self, hypellm_crypto::random::RandomError> {
        let token = hypellm_crypto::base64::encode_url_nopad(
            hypellm_crypto::random::secret_256()?.as_slice(),
        );
        Ok(Self {
            store_mac: hypellm_crypto::random::secret_256()?.to_vec(),
            key_verifier: hypellm_crypto::random::secret_256()?.to_vec(),
            session: hypellm_crypto::random::secret_256()?.to_vec(),
            pseudonym: hypellm_crypto::random::secret_256()?.to_vec(),
            oidc: hypellm_crypto::random::secret_256()?.to_vec(),
            control: hypellm_crypto::random::secret_256()?.to_vec(),
            fleet: Some(hypellm_crypto::random::secret_256()?.to_vec()),
            break_glass: break_glass_verifier(&token),
            break_glass_token: Some(token),
            provider: BTreeMap::new(),
            dir: None,
        })
    }

    /// A bundle with an explicit store MAC key, for tests that must reopen the
    /// same state directory across several routers.
    ///
    /// `generate` mints a fresh key each time, so two routers built from it
    /// cannot read each other's log — which is correct for production and
    /// useless for a test about restart behaviour.
    #[cfg(test)]
    fn from_dir_or(store_mac: &[u8]) -> Self {
        let mut secrets = Self::generate().expect("entropy");
        secrets.store_mac = store_mac.to_vec();
        secrets
    }

    /// Write a generated bundle to a directory.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        hypellm_store::ensure_dir(dir)?;
        for (name, bytes) in [
            ("store_mac.key", &self.store_mac),
            ("key_verifier.key", &self.key_verifier),
            ("session.key", &self.session),
            ("pseudonym.key", &self.pseudonym),
            ("oidc.key", &self.oidc),
            ("control.key", &self.control),
            ("break_glass.verifier", &self.break_glass),
        ] {
            hypellm_store::write_atomic(dir, name, bytes)?;
            // `write_atomic` creates with the process umask, which commonly
            // leaves a file group- and world-readable. These five are the keys
            // that authenticate the audit chain, forge any API key, mint any
            // session, de-anonymize every log line, and complete anyone's
            // sign-in — at 0644 in the state directory, readable by every
            // account on the host.
            //
            // Credentials written through the management API were already
            // narrowed; the router's own keys were not, which is the more
            // serious of the two and was the easier to miss.
            crate::state::restrict_to_owner(&dir.join(name))?;
        }
        // Written only when present, so a bundle generated before this key
        // existed is not rewritten with an empty file — which would read as
        // "the fleet key is zero bytes" rather than "there is no fleet key".
        if let Some(fleet) = &self.fleet {
            hypellm_store::write_atomic(dir, "fleet.key", fleet)?;
            crate::state::restrict_to_owner(&dir.join("fleet.key"))?;
        }
        // The directory provider credentials are read from. Created empty so an
        // operator can see where they go without having to read the source.
        let credentials = dir.join("credentials");
        hypellm_store::ensure_dir(&credentials)?;
        crate::state::restrict_dir_to_owner(&credentials)?;
        Ok(())
    }
}

/// A fully assembled router, not yet serving.
#[derive(Debug)]
pub struct Router {
    /// The shared data-plane state.
    pub state: Arc<RouterState>,
    /// The inference listener.
    pub inference: Server,
    /// The management listener.
    pub management: Server,
    /// The dedicated metrics listener, when `settings metrics_listen` names
    /// one. Serving the exposition on its own address means a scrape agent does
    /// not have to be allowed onto the control plane.
    pub metrics: Option<Server>,
    /// Verifies a break-glass token. Carried from `assemble`, where the secret
    /// bundle is consumed, so `serve` does not have to be handed it again.
    break_glass_verifier: Vec<u8>,
}

impl Router {
    /// Load a configuration and assemble a router.
    pub fn assemble(
        config_path: &Path,
        secrets: Secrets,
        log_level: Severity,
    ) -> Result<Self, StartupError> {
        Self::assemble_with(config_path, secrets, log_level, None)
    }

    /// Assemble, optionally adopting the configuration file over any published
    /// activation.
    ///
    /// `adopt_reason` is `--adopt-config`'s mandatory reason. Specification 11.2
    /// makes a published activation authoritative, and it must be: a policy
    /// drafted, reviewed, approved, and durably recorded cannot disappear on the
    /// next restart. But that made the file permanently inert once anything had
    /// been published, and the only way back was to start against an empty state
    /// directory — discarding the audit chain and every stored API key to change
    /// a configuration line.
    ///
    /// Adoption records the file as a new activation instead: durable frame,
    /// audit record with the reason, and a `critical` log event. It is a
    /// deliberate, attributable override rather than a destructive workaround,
    /// which is what makes it safe to have at all.
    pub fn assemble_with(
        config_path: &Path,
        secrets: Secrets,
        log_level: Severity,
        adopt_reason: Option<&str>,
    ) -> Result<Self, StartupError> {
        // 1. Configuration.
        let text = std::fs::read_to_string(config_path).map_err(|e| {
            StartupError::ConfigUnreadable {
                path: config_path.to_path_buf(),
                detail: e.to_string(),
            }
        })?;
        let config = hypellm_config::load(&text, 1).map_err(StartupError::ConfigInvalid)?;

        // Specification 20.1's "dedicated unprivileged user". The router cannot
        // drop privilege — `setuid` is `unsafe` FFI, forbidden workspace-wide
        // (`DI-003`) — so it says so instead of starting quietly as root and
        // leaving the deployment to have got it right.
        //
        // A warning rather than a refusal: a container that genuinely runs as
        // uid 0 with everything else locked down is a real deployment, and
        // refusing it would substitute this router's opinion for the
        // operator's. What is not acceptable is *silence*.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        // Through `stderr`, which puts a background writer behind a bounded
        // queue. Constructing the logger directly over `StderrSink` — which is
        // what this did — meant every thread that emitted a line took the
        // process-wide stderr lock and wrote synchronously with no deadline, so
        // a log pipe nobody was draining would stall the data path.
        let telemetry = Arc::new(Telemetry::stderr(
            log_level,
            Arc::clone(&clock),
            &secrets.pseudonym,
        ));

        // Specification 20.1's process hardening, item by item. The router
        // implements none of it — `setuid`, `seccomp`, `setrlimit` and `mlock`
        // are all `unsafe` FFI, forbidden workspace-wide (`DI-003`) — so it
        // comes from the systemd unit or the container runtime.
        //
        // What the router *can* do is read what was actually applied and say
        // what is missing. A deployment can believe it applied those directives
        // and be wrong: a typo in a unit file, a runtime that drops
        // `SystemCallFilter`, a `LimitCORE` that never took. Without this,
        // nothing would say so.
        //
        // Warnings, never a refusal. A container running as uid 0 with
        // everything else locked down is a real deployment, and refusing to
        // start would substitute this router's opinion for the operator's on a
        // question it cannot see the whole of.
        for (property, explanation) in crate::hardening::Hardening::detect().missing() {
            telemetry.log(
                &hypellm_telemetry::Event::critical("startup.hardening_missing")
                    .str_field(hypellm_telemetry::Field::Code, property)
                    .str_field(hypellm_telemetry::Field::Detail, explanation),
            );
        }

        // 2. Store.
        let state_dir = PathBuf::from(&config.settings.state_dir);
        let (store, recovery) = Store::open(
            &state_dir,
            &secrets.store_mac,
            config.settings.audit_checkpoint_interval,
        )
        .map_err(|e| StartupError::Store(e.to_string()))?;

        // Specification 11.2: fail closed on a protected-record integrity
        // error. A broken chain is exactly that.
        if let Some(sequence) = recovery.audit_chain_broken_at {
            return Err(StartupError::AuditChainBroken { sequence });
        }

        if recovery.truncated {
            telemetry.log(
                &hypellm_telemetry::Event::warn("store.tail_truncated")
                    .str_field(
                        hypellm_telemetry::Field::Detail,
                        "a torn write at the end of the log was discarded",
                    )
                    .int_field(
                        hypellm_telemetry::Field::Count,
                        u64::try_from(recovery.frames.len()).unwrap_or(u64::MAX),
                    ),
            );
        }

        // 2b. Resume the last activated configuration.
        //
        // Specification 11.2: "Startup replays only complete valid frames".
        // Without this the router boots on the file every time and a policy
        // published through the management API — drafted, reviewed, approved,
        // and durably recorded — silently disappears on the next restart.
        let adopting = adopt_reason.is_some();
        let config = match resume_activation(&recovery, config)? {
            Resumed::FromLog { config, sequence } if adopting => {
                // The file wins, and the log records that it did.
                let _ = sequence;
                let _ = config;
                let text = std::fs::read_to_string(config_path).map_err(|e| {
                    StartupError::ConfigUnreadable {
                        path: config_path.to_path_buf(),
                        detail: e.to_string(),
                    }
                })?;
                hypellm_config::load(&text, recovery.max_sequence().saturating_add(1))
                    .map_err(StartupError::ConfigInvalid)?
            }
            Resumed::FromLog { config, sequence } => {
                telemetry.log(
                    &hypellm_telemetry::Event::info("config.activation_resumed")
                        .int_field(hypellm_telemetry::Field::Count, sequence)
                        .str_field(
                            hypellm_telemetry::Field::ConfigDigest,
                            &config.digest_short(),
                        ),
                );
                config
            }
            Resumed::FromFile(config) => {
                telemetry.log(
                    &hypellm_telemetry::Event::info("config.loaded_from_file").str_field(
                        hypellm_telemetry::Field::ConfigDigest,
                        &config.digest_short(),
                    ),
                );
                config
            }
        };

        // Adoption is durable and audited, in that order — the same order a
        // publication uses. A crash between them leaves a record of an
        // activation that did not take effect, which an operator can see; the
        // reverse would leave a running configuration nobody is accountable
        // for.
        if let Some(reason) = adopt_reason {
            store
                .append(
                    RecordKind::ConfigActivation,
                    config.canonical.as_bytes(),
                )
                .map_err(|e| StartupError::Store(e.to_string()))?;
            store
                .append_audit(
                    AuditEvent::new(
                        clock.wall_millis(),
                        "router",
                        AuditAction::ConfigAdopted,
                    )
                    .with_reason(reason)
                    .with_object(config.digest_short()),
                )
                .map_err(|e| StartupError::Store(e.to_string()))?;
            // Loud: this overrode a policy that went through review.
            telemetry.log(
                &hypellm_telemetry::Event::critical("config.adopted_from_file")
                    .str_field(hypellm_telemetry::Field::Detail, reason)
                    .str_field(
                        hypellm_telemetry::Field::ConfigDigest,
                        &config.digest_short(),
                    ),
            );
        }

        // 2c. Provider credentials, now that the configuration naming them is
        // settled. Loading them earlier would mean guessing which credentials
        // the *resumed* configuration declares, which is not the same set the
        // file declares.
        let mut secrets = secrets;
        let break_glass_verifier = secrets.break_glass.clone();
        if let Some(dir) = secrets.dir.clone() {
            secrets.load_provider_credentials(&dir, &config.credentials)?;
        }
        let secrets = secrets;

        // 3. Reachability.
        let tls = config
            .settings
            .tls_helper_socket
            .as_ref()
            .map(|path| TlsHelper::new(path.clone(), Duration::from_secs(10)));

        // Name resolution runs on a bounded pool rather than inline on the
        // request thread (specification 3.2: "Blocking DNS … MUST run on
        // bounded worker pools"). `getaddrinfo` has no timeout of its own, so
        // resolving inline let one unreachable nameserver hold a request
        // thread for as long as the operating system took to give up.
        let egress = Egress::new(
            Resolver::new(Box::new(PooledResolver::default())),
            ConnectionPool::new(PoolConfig::DEFAULT, Arc::clone(&clock)),
            tls,
            Duration::from_secs(10),
        );

        let mut unreachable = Vec::new();
        for provider in config.snapshot.providers.values() {
            for endpoint in &provider.endpoints {
                if !egress.can_reach(endpoint) {
                    unreachable.push(format!(
                        "provider '{}' endpoint {}://{}:{} requires outbound TLS, \
                         but no tls_helper_socket is configured",
                        provider.id,
                        endpoint.scheme.as_str(),
                        endpoint.host,
                        endpoint.port
                    ));
                }
            }
        }
        if !unreachable.is_empty() {
            return Err(StartupError::Unreachable(unreachable));
        }

        // Assemble the rest.
        let health = Arc::new(HealthRegistry::new(
            Arc::clone(&clock),
            BreakerConfig::DEFAULT,
        ));
        for (id, target) in &config.snapshot.targets {
            health.set_capacity(id, target.max_concurrency);
            // Keep the routing filter and the admission queue in agreement: a
            // target that will queue must stay eligible while it can queue.
            health.set_queue_allowance(
                id,
                config
                    .quotas
                    .iter()
                    .find(|q| q.scope == hypellm_config::QuotaScope::Target(id.clone()))
                    .map_or(0, |q| q.limits.max_queued),
            );
        }

        let admission = build_admission(&config, Arc::clone(&clock));
        // The adapters' credential source. Populated here and nowhere else:
        // specification 7 makes adapters "the only code that touches provider
        // credentials", and they reach these values through an opaque handle.
        let credentials = Arc::new(match secrets.dir.as_ref() {
            Some(dir) => CredentialStore::persisting_in(dir.join("credentials")),
            None => CredentialStore::new(),
        });
        for (reference, secret) in &secrets.provider {
            credentials.set(reference, secret.clone());
        }

        let keys = Arc::new(KeyStore::new(&secrets.key_verifier));
        let restored_keys = restore_keys(&recovery, &keys);
        if restored_keys.unreadable > 0 {
            // Dropping a record silently would quietly reduce a key's authority
            // or resurrect a revoked one; either deserves an operator's
            // attention even though startup continues.
            telemetry.log(
                &hypellm_telemetry::Event::warn("store.key_records_unreadable").int_field(
                    hypellm_telemetry::Field::Count,
                    restored_keys.unreadable,
                ),
            );
        }
        if restored_keys.restored > 0 {
            telemetry.log(
                &hypellm_telemetry::Event::info("store.keys_restored")
                    .int_field(hypellm_telemetry::Field::Count, restored_keys.restored),
            );
        }

        let sessions = Arc::new(SessionStore::new(
            &secrets.session,
            SessionPolicy {
                idle_millis: config.settings.session_idle_secs * 1000,
                absolute_millis: config.settings.session_absolute_secs * 1000,
                ..SessionPolicy::DEFAULT
            },
        ));

        let inference_address = config.settings.inference_listen.clone();
        let admin_address = config.settings.admin_listen.clone();
        // Captured before the configuration moves into the activatable pointer.
        let metrics_address = config.settings.metrics_listen.clone();
        let inference_listener = listener_config(ServerConfig::inference(), &config.settings);
        let management_listener = listener_config(ServerConfig::management(), &config.settings);
        let cors = CorsPolicy::with_origins(config.settings.cors_origins.clone());
        let oidc_config = build_oidc_config(&config);
        let verifier: Option<Arc<dyn hypellm_auth::oidc::TokenVerifier>> = config
            .settings
            .oidc_verifier_socket
            .as_ref()
            .map(|path| {
                let client: Arc<dyn hypellm_auth::oidc::TokenVerifier> =
                    Arc::new(VerifierClient::new(path.clone(), Duration::from_secs(5)));
                client
            });

        // The fleet runtime, before the configuration moves into the
        // activatable pointer.
        let fleet_config = std::sync::Arc::clone(&config.fleet);
        let fleet_enabled = fleet_config.is_active();
        let fleet_key = secrets.fleet.clone();
        if fleet_enabled && fleet_key.is_none() {
            // A declared, enabled fleet with no key cannot authenticate to its
            // agent. Refusing at startup is the honest failure: the alternative
            // is a router that appears healthy and refuses every orchestrated
            // target with a reason nobody expected.
            return Err(StartupError::MissingSecret("fleet.key"));
        }
        let policy_for_fleet = config.snapshot.clone();

        let state = Arc::new(RouterState {
            config: Arc::new(Activatable::new(config)),
            keys,
            sessions,
            credentials,
            health,
            admission,
            egress,
            telemetry: Arc::clone(&telemetry),
            store: Arc::new(store),
            clock: Arc::clone(&clock),
            trusted_edge: TrustedEdge::none(),
            decisions: Arc::new(DecisionCache::default()),
            usage: Arc::new(hypellm_admin_api::UsageAggregate::default()),
            fleet: std::sync::OnceLock::new(),
        });

        // Built after the state so it shares the same store, clock, and
        // telemetry, then published into the `OnceLock` every holder of the
        // `Arc` can see.
        if let (Some(key), true) = (fleet_key, fleet_enabled) {
            if let Some(runtime) = crate::fleet::FleetRuntime::new(
                fleet_config,
                key,
                Arc::clone(&state.clock),
                Arc::clone(&state.telemetry),
                Arc::clone(&state.store),
            ) {
                runtime.adopt_policy(&policy_for_fleet);
                // Replay leases and flap counters, then take a first
                // observation. Until one succeeds, every cold orchestrated
                // target is ineligible — the fail-closed reading of "no
                // observation has ever succeeded".
                runtime.recover();
                let _ = state.fleet.set(Arc::new(runtime));
            }
        }

        // 4. Listeners, last.
        //
        // The configured body and head limits reach the transport parser here.
        // Without this the settings were accepted, validated, and then ignored:
        // the listener used the compiled-in defaults and an operator who
        // lowered `max_body_bytes` got no such thing.
        let mut inference = Server::bind(
            &inference_address,
            inference_listener,
            Arc::clone(&clock),
        )
        .map_err(|e| StartupError::Listener {
            which: "inference",
            address: inference_address.clone(),
            detail: e.to_string(),
        })?;
        // Labelled per plane: specification 3.1 keeps the data and management
        // paths separate, and a shared connection or byte count that could not
        // tell them apart would undo that in the one place an operator looks
        // during an incident.
        inference.observe(crate::server::ListenerMetrics::new(
            Arc::clone(&telemetry),
            "inference",
        ));

        let mut management = Server::bind(
            &admin_address,
            management_listener,
            Arc::clone(&clock),
        )
        .map_err(|e| StartupError::Listener {
            which: "management",
            address: admin_address.clone(),
            detail: e.to_string(),
        })?;
        management.observe(crate::server::ListenerMetrics::new(
            Arc::clone(&telemetry),
            "management",
        ));

        let metrics = match metrics_address.as_deref() {
            None => None,
            Some(address) => {
                let mut server =
                    Server::bind(address, management_listener, Arc::clone(&clock)).map_err(
                        |e| StartupError::Listener {
                            which: "metrics",
                            address: address.to_owned(),
                            detail: e.to_string(),
                        },
                    )?;
                server.observe(crate::server::ListenerMetrics::new(
                    Arc::clone(&telemetry),
                    "metrics",
                ));
                Some(server)
            }
        };

        let _ = (cors, oidc_config, verifier);

        Ok(Self {
            state,
            inference,
            management,
            metrics,
            break_glass_verifier,
        })
    }

    /// Handles that stop every bound listener.
    ///
    /// A collection rather than a tuple because the set is not fixed: the
    /// metrics listener exists only when `settings metrics_listen` names an
    /// address. `serve` joins every listener thread it spawned, so a listener
    /// missing from this set is one nothing ever signals — and the join then
    /// blocks forever, leaving a router that acknowledged `shutdown`, drained
    /// the planes it knew about, and never exited.
    #[must_use]
    pub fn shutdown_handles(&self) -> Vec<ShutdownHandle> {
        let mut handles = vec![
            self.inference.shutdown_handle(),
            self.management.shutdown_handle(),
        ];
        if let Some(metrics) = &self.metrics {
            handles.push(metrics.shutdown_handle());
        }
        handles
    }

    /// Serve until every listener stops.
    ///
    /// # Errors
    ///
    /// Returns the first listener error.
    pub fn serve(
        self,
        cors: CorsPolicy,
        oidc_config: Option<hypellm_auth::oidc::OidcConfig>,
        verifier: Option<Arc<dyn hypellm_auth::oidc::TokenVerifier>>,
        oidc_key: Vec<u8>,
        static_root: Option<PathBuf>,
    ) -> std::io::Result<()> {
        let state = Arc::clone(&self.state);

        let admin_state = Arc::new(crate::admin::admin_state_from(
            &state,
            cors,
            oidc_config,
            verifier,
            &oidc_key,
            &self.break_glass_verifier,
        ));
        let mut admin_handler =
            AdminHandler::new(AdminApi::new(admin_state)).with_metrics(Arc::clone(&state));
        if let Some(root) = static_root {
            admin_handler = admin_handler.with_static_root(root);
        }

        let _ = state.store.append_audit(
            AuditEvent::new(
                state.clock.wall_millis(),
                "router",
                AuditAction::RouterStarted,
            )
            .with_reason(&format!(
                "configuration digest {}",
                state.config().digest_short()
            )),
        );

        state.telemetry.log(
            &hypellm_telemetry::Event::info("router.started")
                .str_field(
                    hypellm_telemetry::Field::ConfigDigest,
                    &state.config().digest_short(),
                )
                .int_field(
                    hypellm_telemetry::Field::Count,
                    u64::try_from(state.config().snapshot.targets.len()).unwrap_or(u64::MAX),
                ),
        );

        let inference_handler = Arc::new(InferenceHandler::new(Arc::clone(&state)));
        let management = self.management;
        let admin = Arc::new(admin_handler);

        let management_thread = std::thread::Builder::new()
            .name("hypellm-management".to_owned())
            .spawn(move || {
                let _ = management.serve(admin);
            })?;

        let metrics_thread = match self.metrics {
            None => None,
            Some(server) => {
                let handler: Arc<dyn crate::server::Handler> =
                    Arc::new(crate::admin::MetricsHandler::new(Arc::clone(&state)));
                Some(
                    std::thread::Builder::new()
                        .name("hypellm-metrics".to_owned())
                        .spawn(move || {
                            let _ = server.serve(handler);
                        })?,
                )
            }
        };

        // Specification 17: "Time synchronization status is monitored." and the
        // signal table's `config version`.
        //
        // One fixed thread rather than a sample on the request path: the
        // monitor takes a mutex, so sampling per request would serialise the
        // data plane on a diagnostic. It is not a per-request thread, so
        // specification 3.2's "no request may create an unbounded thread" is
        // unaffected — the count is one for the process.
        let housekeeping = {
            let state = Arc::clone(&state);
            let stopping = self.inference.shutdown_handle();
            std::thread::Builder::new()
                .name("hypellm-housekeeping".to_owned())
                .spawn(move || housekeeping_loop(&state, &stopping))?
        };

        // `serve` returns once the accept loop stops *and* its connections have
        // drained within their deadline.
        let result = self.inference.serve(inference_handler);
        let abandoned = self.inference.active_connections();

        let _ = management_thread.join();
        if let Some(thread) = metrics_thread {
            let _ = thread.join();
        }
        let _ = housekeeping.join();

        if abandoned > 0 {
            state.telemetry.log(
                &hypellm_telemetry::Event::warn("router.drain_incomplete")
                    .int_field(hypellm_telemetry::Field::Count, abandoned)
                    .str_field(
                        hypellm_telemetry::Field::Detail,
                        "exchanges were still running when the drain deadline passed",
                    ),
            );
        }

        let _ = state.store.append_audit(AuditEvent::new(
            state.clock.wall_millis(),
            "router",
            AuditAction::RouterStopped,
        ));

        // Specification 20.1: shutdown "flushes audit/state, and exits nonzero
        // on integrity failure". A failed sync means audit records and state
        // may not have reached disk — reporting success would tell an operator
        // the router stopped cleanly when its last records are missing.
        let flushed = state.store.sync();
        if let Err(error) = &flushed {
            state.telemetry.log(
                &hypellm_telemetry::Event::critical("router.flush_failed").str_field(
                    hypellm_telemetry::Field::Detail,
                    &error.to_string(),
                ),
            );
        }

        state
            .telemetry
            .log(&hypellm_telemetry::Event::info("router.stopped"));

        match (result, flushed) {
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(std::io::Error::other(format!(
                "state could not be flushed on shutdown: {e}"
            ))),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

/// How often the housekeeping thread samples the clock and republishes the
/// gauges that are not request-driven.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(10);

/// Periodic, non-request-driven telemetry.
///
/// Two things belong here rather than on the request path. Clock
/// synchronisation must be observed whether or not traffic is arriving —
/// a router that has been idle through a large step is exactly the one whose
/// next deadline computation is wrong. And a gauge such as the configuration
/// version has no natural emit site: it is a property of the process, not of an
/// event, so something has to restate it or it disappears from the exposition
/// after a restart of the collector.
fn housekeeping_loop(state: &Arc<RouterState>, stopping: &crate::server::ShutdownHandle) {
    // Short poll rather than one long sleep, so shutdown is not delayed by a
    // thread waiting out a full interval (specification 20.1's drain deadline).
    const POLL: Duration = Duration::from_millis(200);
    let monitor = hypellm_core::time::ClockSyncMonitor::new(MAX_CLOCK_STEP_MILLIS);
    let mut since_sample = Duration::ZERO;

    // Once at start, so the exposition carries them before the first interval.
    publish_process_gauges(state);

    // Observation runs on its own, shorter interval: belief that expires is
    // the gate on every fleet decision, and pacing it with the housekeeping
    // interval would mean the router spends most of its time unable to plan.
    let mut since_observation = Duration::ZERO;
    let observation_interval = state
        .fleet()
        .map(|fleet| {
            let config = fleet.config();
            Duration::from_millis(
                config
                    .agents
                    .values()
                    .map(|a| a.observation_interval_ms)
                    .min()
                    .unwrap_or(5_000)
                    .max(POLL.as_millis().try_into().unwrap_or(200)),
            )
        })
        .unwrap_or(Duration::MAX);

    while !stopping.is_shutting_down() {
        std::thread::sleep(POLL);

        if let Some(fleet) = state.fleet() {
            since_observation = since_observation.saturating_add(POLL);
            if since_observation >= observation_interval {
                since_observation = Duration::ZERO;
                // A publication may have swapped the configuration since the
                // last tick. Reconcile before observing, so an observation is
                // never parsed against a fleet the router has already replaced.
                fleet.sync_configuration(&state.config());
                fleet.observe();
                // A lease that outlived its expiry is not evidence that the
                // work is still running; it is evidence that whatever should
                // have reported back did not. Releasing it here is what keeps a
                // leaked lease from pinning a host out of service.
                fleet.expire_leases();
            }
        }

        since_sample = since_sample.saturating_add(POLL);
        if since_sample < HOUSEKEEPING_INTERVAL {
            continue;
        }
        since_sample = Duration::ZERO;

        if monitor.sample(state.clock.as_ref()) {
            state.telemetry.count(
                hypellm_telemetry::names::CLOCK_STEPS,
                "Wall-clock steps observed against the monotonic clock.",
                &hypellm_telemetry::Labels::new(),
            );
            // Loud, because specification 12's reservations, specification 6's
            // deadlines, and every audit timestamp are read against these two
            // clocks disagreeing about how much time passed.
            state.telemetry.log(
                &hypellm_telemetry::Event::warn("clock.step_detected").str_field(
                    hypellm_telemetry::Field::Detail,
                    "the wall clock moved by more than the monotonic clock; \
                     durations and deadlines remain monotonic, but audit and \
                     metering timestamps may be discontinuous",
                ),
            );
        }

        publish_process_gauges(state);
    }
}

/// Restate the gauges that describe the process rather than an event.
fn publish_process_gauges(state: &Arc<RouterState>) {
    state.telemetry.metrics.gauge_set(
        hypellm_telemetry::names::CONFIG_VERSION,
        "The active configuration version.",
        &hypellm_telemetry::Labels::new(),
        i64::try_from(state.config().snapshot.version).unwrap_or(i64::MAX),
    );
}

/// The wall-clock movement, relative to the monotonic clock, that counts as a
/// step rather than as ordinary drift.
///
/// Well above what NTP slewing produces over a ten-second window and well below
/// anything that would matter to a deadline, so the counter reports steps and
/// not noise.
const MAX_CLOCK_STEP_MILLIS: u64 = 2_000;

/// The verifier stored for a break-glass token.
///
/// A plain digest rather than a password hash, because the token is 256 bits of
/// machine-generated entropy: there is no dictionary to attack and no benefit
/// to a work factor, which would only slow the one sign-in that happens during
/// an outage. Domain-separated so a digest from this file cannot be replayed
/// as one from anywhere else in the system.
#[must_use]
pub fn break_glass_verifier(token: &str) -> Vec<u8> {
    hypellm_crypto::sha256::sha256_parts(&[b"hypellm/break-glass/v1\0", token.as_bytes()]).to_vec()
}

/// The command in an authenticated control line, if the token matches.
///
/// Specification 20.1 requires graceful shutdown to exist; it does not
/// authorise an unauthenticated trigger for it. The line is
/// `<hex token> <command>`.
///
/// Two properties matter and neither is obvious from the call site:
///
/// - The comparison has no early exit, so the socket cannot be used to recover
///   the token a byte at a time by timing.
/// - A missing token, a malformed line, and a wrong token are all the same
///   answer. Distinguishing them would tell an unauthenticated caller whether
///   it had the shape right, which is the only feedback it needs.
#[must_use]
pub fn authenticated_control_command<'a>(line: &'a str, expected_hex: &[u8]) -> Option<&'a str> {
    let (presented, command) = line.trim().split_once(char::is_whitespace)?;
    if hypellm_crypto::ct::eq(presented.as_bytes(), expected_hex) {
        Some(command.trim())
    } else {
        None
    }
}

/// Apply configured limits to a listener profile.
///
/// The profile supplies the connection-shaped defaults (how many connections,
/// how many requests each may serve); the configuration supplies the
/// message-shaped bounds an operator is expected to tune.
///
/// Both limits are clamped to the specification 3.2 ceilings rather than
/// trusted: `max_head_bytes` has a "hard maximum 64 KiB" that no profile may
/// exceed, and a body limit of zero would make every request fail in a way that
/// looks like a router fault rather than a configuration one.
fn listener_config(base: ServerConfig, settings: &hypellm_config::Settings) -> ServerConfig {
    let mut config = base;

    // On a 16-bit or 32-bit target the configured value may not fit a `usize`;
    // saturating there and then clamping lands on the hard ceiling, which is
    // the same answer the clamp would have given for any larger value.
    config.limits.max_head_bytes = usize::try_from(settings.max_head_bytes)
        .unwrap_or(usize::MAX)
        .clamp(1024, wire_http1::Limits::HARD_MAX_HEAD_BYTES);
    config.limits.max_body_bytes = settings.max_body_bytes.max(1024);

    // Specification 14: "slow-client timeout cancels upstream".
    if settings.slow_client_timeout_ms > 0 {
        config.write_timeout = Duration::from_millis(settings.slow_client_timeout_ms);
    }

    // A request may not outlive the deadline the router would apply to it
    // anyway; reading it more slowly than that is pointless work.
    if settings.default_deadline_ms > 0 {
        config.request_deadline = Duration::from_millis(settings.default_deadline_ms);
    }

    // Zero means "keep the profile default", so an operator tunes what they
    // mean to and inherits the rest. Every one is clamped: these are the bounds
    // that keep a connection flood from becoming memory exhaustion and a slow
    // client from holding a socket forever, and a configuration mistake must
    // not be able to remove a bound — only move it inside the allowed range.
    if settings.max_connections > 0 {
        config.max_connections = settings.max_connections.clamp(1, MAX_CONNECTIONS_CEILING);
    }
    if settings.connection_stack_kib > 0 {
        // `DI-001`: with one thread per connection, this is the multiplier that
        // decides whether `max_connections` is a number the process can
        // actually reach. Clamped at both ends — too small overflows a handler
        // stack (an abort, not an error), too large puts the ceiling back out
        // of reach.
        config.connection_stack_bytes = usize::try_from(settings.connection_stack_kib)
            .unwrap_or(usize::MAX)
            .saturating_mul(1024)
            .clamp(MIN_CONNECTION_STACK_BYTES, MAX_CONNECTION_STACK_BYTES);
    }
    if settings.max_requests_per_connection > 0 {
        config.max_requests_per_connection = settings
            .max_requests_per_connection
            .clamp(1, MAX_REQUESTS_PER_CONNECTION_CEILING);
    }
    if settings.read_timeout_ms > 0 {
        config.read_timeout = Duration::from_millis(
            settings
                .read_timeout_ms
                .clamp(MIN_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS),
        );
    }
    // Deliberately *not* `keepalive_interval_ms`, which is the SSE comment
    // cadence of specification 14 and a different thing entirely: how often the
    // router writes `:` into an open stream, versus how long an idle socket may
    // wait for its next request. Wiring one to the other would have made an
    // operator tuning stream liveness silently change connection reuse.
    if settings.keepalive_timeout_ms > 0 {
        config.keepalive_timeout = Duration::from_millis(
            settings
                .keepalive_timeout_ms
                .clamp(MIN_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS),
        );
    }

    config
}

/// The most connections any listener may be configured to accept.
///
/// Each costs a thread with a 512 KiB stack plus its buffers (`DI-001`), so
/// this is a memory bound wearing a connection-count disguise: 16 384 is about
/// 8 GiB of stack before anything else. Past it a deployment needs the event
/// loop, not a larger number.
const MAX_CONNECTIONS_CEILING: u64 = 16_384;

/// The most requests one keep-alive connection may serve before it is closed.
///
/// Recycling bounds the effect of any per-connection state that turns out to
/// leak, so "unlimited" is not offered.
const MAX_REQUESTS_PER_CONNECTION_CEILING: u32 = 100_000;

/// Read-timeout bounds.
///
/// The floor exists because a timeout short enough to cut a healthy client
/// mid-request reads as an intermittent network fault and is very hard to
/// diagnose; the ceiling because a socket a slow reader can hold for longer
/// than this is a slow-loris with extra steps.
const MIN_READ_TIMEOUT_MS: u64 = 1_000;
const MAX_READ_TIMEOUT_MS: u64 = 600_000;

/// What key replay recovered.
#[derive(Debug, Default, PartialEq, Eq)]
struct RestoredKeys {
    /// Records restored into the store.
    restored: u64,
    /// Records that could not be decoded and were dropped.
    unreadable: u64,
}

/// Replay API key records and revocations from the durable log.
///
/// Frames are applied in sequence order, so a revocation recorded after a
/// creation wins — which is what makes specification 22.3's "revocation
/// bypasses configuration publication delay" survive a restart. Without this
/// the whole key store is empty on boot and every issued credential stops
/// authenticating.
fn restore_keys(recovery: &hypellm_store::Recovery, keys: &KeyStore) -> RestoredKeys {
    let mut counts = RestoredKeys::default();

    for frame in &recovery.frames {
        match frame.kind {
            RecordKind::ApiKey => match hypellm_auth::KeyRecord::from_payload(&frame.payload) {
                Some(record) => {
                    keys.insert(record);
                    counts.restored = counts.restored.saturating_add(1);
                }
                None => counts.unreadable = counts.unreadable.saturating_add(1),
            },
            RecordKind::ApiKeyRevocation => {
                match core::str::from_utf8(&frame.payload)
                    .ok()
                    .and_then(|id| hypellm_core::ids::KeyId::new(id).ok())
                {
                    Some(id) => {
                        keys.revoke(&id);
                    }
                    None => counts.unreadable = counts.unreadable.saturating_add(1),
                }
            }
            _ => {}
        }
    }

    counts
}

/// Which configuration the router will run.
#[derive(Debug)]
enum Resumed {
    /// The last activation recorded in the durable log.
    FromLog {
        /// The restored configuration.
        config: ValidatedConfig,
        /// The sequence number it was recorded at.
        sequence: u64,
    },
    /// The configuration file, because the log held no activation.
    FromFile(ValidatedConfig),
}

/// Restore the last configuration activation from the durable log.
///
/// The management API records an activation *before* swapping the pointer
/// (specification 11.2: validate off-path, durable commit, atomic swap), so the
/// newest `ConfigActivation` frame is the last policy an operator published and
/// the one the router must resume on.
///
/// The frame's sequence number becomes the configuration version: it is
/// monotonic, durable, and already ordered, so a restart cannot reuse or
/// rewind a version number.
///
/// Two conditions fail startup rather than falling back to the file:
///
/// - the recorded document no longer validates, which usually means a
///   downgrade to a router that no longer understands a record it wrote;
/// - the recorded document names a different `state_dir`, since the store this
///   frame was read from was opened using the file's path, and honouring the
///   recovered value would leave the process reading one directory and writing
///   another.
fn resume_activation(
    recovery: &hypellm_store::Recovery,
    from_file: ValidatedConfig,
) -> Result<Resumed, StartupError> {
    // Frames are replayed in order, so the last activation is the newest.
    let Some(frame) = recovery.of_kind(RecordKind::ConfigActivation).last() else {
        return Ok(Resumed::FromFile(from_file));
    };

    let text = core::str::from_utf8(&frame.payload).map_err(|_| {
        StartupError::ActivationUnrecoverable {
            sequence: frame.sequence,
            detail: "the recorded document is not valid UTF-8".to_owned(),
        }
    })?;

    let config = hypellm_config::load(text, frame.sequence).map_err(|errors| {
        StartupError::ActivationUnrecoverable {
            sequence: frame.sequence,
            detail: errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        }
    })?;

    if config.settings.state_dir != from_file.settings.state_dir {
        return Err(StartupError::ActivationUnrecoverable {
            sequence: frame.sequence,
            detail: format!(
                "it declares state_dir '{}' but the store was opened at '{}'",
                config.settings.state_dir, from_file.settings.state_dir
            ),
        });
    }

    Ok(Resumed::FromLog {
        config,
        sequence: frame.sequence,
    })
}

fn build_admission(config: &ValidatedConfig, clock: Arc<dyn Clock>) -> AdmissionController {
    let global = config
        .quotas
        .iter()
        .find(|q| q.scope == hypellm_config::QuotaScope::Global)
        .map_or(
            ScopeLimits {
                max_concurrency: 10_000,
                ..ScopeLimits::UNLIMITED
            },
            |q| q.limits,
        );

    let admission = AdmissionController::new(clock, global);
    // Specification 12's Global layer byte rates (`DI-053`). Read from the
    // global quota, which is the only scope the grammar accepts them on.
    if let Some(rates) = config
        .quotas
        .iter()
        .find(|q| q.scope == hypellm_config::QuotaScope::Global)
        .map(|q| q.byte_rates)
    {
        admission.configure_byte_rates(
            rates.input_per_second,
            rates.input_burst,
            rates.output_per_second,
            rates.output_burst,
        );
    }
    for quota in &config.quotas {
        match &quota.scope {
            hypellm_config::QuotaScope::Global => {}
            hypellm_config::QuotaScope::Tenant(t) => {
                admission.configure_tenant(t, quota.limits);
                admission.set_class(&format!("tenant:{t}"), quota.class);
            }
            hypellm_config::QuotaScope::Principal(p) => {
                admission.configure_principal(p, quota.limits);
                admission.set_class(&format!("principal:{p}"), quota.class);
            }
            hypellm_config::QuotaScope::Target(t) => admission.configure_target(t, quota.limits),
            hypellm_config::QuotaScope::Alias { alias, operation } => {
                admission.configure_alias(alias, *operation, quota.limits);
            }
        }
    }
    // A target with a declared concurrency but no explicit quota still gets a
    // ceiling, so an undeclared quota does not mean unlimited.
    for (id, target) in &config.snapshot.targets {
        if target.max_concurrency > 0
            && !config
                .quotas
                .iter()
                .any(|q| q.scope == hypellm_config::QuotaScope::Target(id.clone()))
        {
            admission.configure_target(
                id,
                ScopeLimits {
                    max_concurrency: target.max_concurrency,
                    requests_per_second: target.max_requests_per_second,
                    request_burst: target.max_requests_per_second,
                    ..ScopeLimits::UNLIMITED
                },
            );
        }
    }
    admission
}

fn build_oidc_config(config: &ValidatedConfig) -> Option<hypellm_auth::oidc::OidcConfig> {
    let settings = &config.settings;
    Some(hypellm_auth::oidc::OidcConfig {
        issuer: settings.oidc_issuer.clone()?,
        client_id: settings.oidc_client_id.clone()?,
        authorization_endpoint: settings.oidc_authorization_endpoint.clone()?,
        token_endpoint: settings.oidc_token_endpoint.clone()?,
        redirect_uri: settings.oidc_redirect_uri.clone()?,
        hosted_domains: settings.oidc_hosted_domains.clone(),
        clock_skew_millis: 60_000,
    })
}


/// The maximum length of a Unix socket path.
///
/// `sockaddr_un.sun_path` is 108 bytes on Linux including the terminator. The
/// kernel reports a bare `EINVAL`-shaped error for an over-long path, which is
/// not a helpful thing to find in a log at three in the morning.
pub const MAX_UNIX_PATH: usize = 100;

/// Where the control socket should live, and why if it cannot.
///
/// Specification 20.1 requires graceful shutdown. A router with no reachable
/// control socket cannot be shut down gracefully, so a path that will not fit
/// is reported as a configuration problem with the fix in the message rather
/// than as an opaque bind failure.
pub fn control_socket_path(config: &ValidatedConfig) -> Result<PathBuf, String> {
    let path = config.settings.control_socket.as_ref().map_or_else(
        || PathBuf::from(&config.settings.state_dir).join("control.sock"),
        PathBuf::from,
    );

    let length = path.as_os_str().len();
    if length > MAX_UNIX_PATH {
        return Err(format!(
            "the control socket path is {length} bytes, over the {MAX_UNIX_PATH} byte limit \
             for a Unix socket ({}). Set `control_socket` in the settings record to a shorter \
             path, for example /run/hypellm/control.sock",
            path.display()
        ));
    }
    Ok(path)
}

/// Validate a configuration without starting anything.
///
/// Backs `hypellm-router --check`, so a deployment pipeline can fail on a bad
/// configuration before it reaches a running node.
pub fn check_config(path: &Path) -> Result<ValidatedConfig, StartupError> {
    let text = std::fs::read_to_string(path).map_err(|e| StartupError::ConfigUnreadable {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    hypellm_config::load(&text, 1).map_err(StartupError::ConfigInvalid)
}

#[cfg(test)]
// The crate-root `deny` in `lib.rs` guards production code. A test module
// indexes its own fixtures and reports failure by panicking; holding it to the
// data-plane rules would only push the panics behind `unwrap_or_else`.
#[allow(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::panic,
    clippy::expect_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    use super::*;
    use hypellm_store::TempDir;

    const MINIMAL: &str = "\
settings state_dir=STATE_DIR inference_listen=127.0.0.1:0 admin_listen=127.0.0.1:0
tenant id=acme
provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 egress=local
target id=local:m provider=local model=m local=true operations=chat streaming=true \\
       context=1000 max_output=100 concurrency=4
alias id=a targets=local:m
grant scope=tenant:acme model=* allow=true
binding id=b scope=tenant:acme model=* prefer=local:m
";

    fn write_config(dir: &TempDir, text: &str) -> PathBuf {
        let path = dir.join("hypellm.conf");
        std::fs::write(&path, text).expect("write config");
        path
    }

    /// A recovery containing one `ConfigActivation` frame carrying `text`.
    fn recovery_with_activation(dir: &TempDir, text: &str) -> hypellm_store::Recovery {
        let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("open store");
        store
            .append(RecordKind::ConfigActivation, text.as_bytes())
            .expect("append activation");
        drop(store);

        let (_store, recovery) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("reopen store");
        recovery
    }

    /// A secrets directory holding the router's own keys plus `credentials`.
    fn secrets_dir(dir: &TempDir) -> PathBuf {
        let path = dir.join("secrets");
        Secrets::generate()
            .expect("entropy")
            .write_to(&path)
            .expect("write secrets");
        path
    }

    #[test]
    fn a_declared_provider_credential_is_loaded_from_the_secrets_directory() {
        // Before this existed, `CredentialStore` was constructed empty and only
        // test code ever wrote to it — so no authenticated request to a remote
        // provider was possible at all.
        let dir = TempDir::new("startup-credentials");
        let secrets_path = secrets_dir(&dir);
        std::fs::write(
            secrets_path.join("credentials").join("cred_openai"),
            b"sk-secret-value\n",
        )
        .expect("write credential");

        let declared = vec![hypellm_config::CredentialMeta {
            id: hypellm_core::ids::CredentialRef::new("cred_openai").expect("reference"),
            scope: Vec::new(),
            description: None,
            rotates_after_days: 90,
        }];

        let mut secrets = Secrets::from_dir(&secrets_path).expect("read secrets");
        secrets
            .load_provider_credentials(&secrets_path, &declared)
            .expect("loads");

        let reference = hypellm_core::ids::CredentialRef::new("cred_openai").expect("reference");
        // The trailing newline an operator gets from `echo key > file` is
        // stripped; a credential with one authenticates nowhere.
        assert_eq!(
            secrets.provider.get(&reference).map(Vec::as_slice),
            Some(&b"sk-secret-value"[..])
        );
    }

    #[test]
    fn a_declared_credential_with_no_file_fails_startup() {
        // Starting without it would leave the router unable to authenticate to
        // that provider, and only able to say so after a caller's request had
        // already failed upstream.
        let dir = TempDir::new("startup-missing-credential");
        let secrets_path = secrets_dir(&dir);

        let declared = vec![hypellm_config::CredentialMeta {
            id: hypellm_core::ids::CredentialRef::new("cred_absent").expect("reference"),
            scope: Vec::new(),
            description: None,
            rotates_after_days: 90,
        }];

        let mut secrets = Secrets::from_dir(&secrets_path).expect("read secrets");
        match secrets.load_provider_credentials(&secrets_path, &declared) {
            Err(StartupError::CredentialUnreadable { reference, .. }) => {
                assert_eq!(reference, "cred_absent");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_credential_file_fails_startup() {
        let dir = TempDir::new("startup-empty-credential");
        let secrets_path = secrets_dir(&dir);
        std::fs::write(secrets_path.join("credentials").join("cred_blank"), b"\n\n")
            .expect("write");

        let declared = vec![hypellm_config::CredentialMeta {
            id: hypellm_core::ids::CredentialRef::new("cred_blank").expect("reference"),
            scope: Vec::new(),
            description: None,
            rotates_after_days: 90,
        }];

        let mut secrets = Secrets::from_dir(&secrets_path).expect("read secrets");
        match secrets.load_provider_credentials(&secrets_path, &declared) {
            Err(StartupError::CredentialUnreadable { detail, .. }) => {
                assert!(detail.contains("empty"), "{detail}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn only_declared_credentials_are_read() {
        // Specification 4.1 forbids "implicit file discovery". A file nobody
        // declared must never be loaded, however inviting its name.
        let dir = TempDir::new("startup-undeclared");
        let secrets_path = secrets_dir(&dir);
        std::fs::write(
            secrets_path.join("credentials").join("cred_undeclared"),
            b"should-not-be-read",
        )
        .expect("write");

        let mut secrets = Secrets::from_dir(&secrets_path).expect("read secrets");
        secrets
            .load_provider_credentials(&secrets_path, &[])
            .expect("loads nothing");
        assert!(secrets.provider.is_empty());
    }

    #[test]
    fn the_secrets_bundle_redacts_its_debug_output() {
        let dir = TempDir::new("startup-secret-redaction");
        let secrets_path = secrets_dir(&dir);
        let secrets = Secrets::from_dir(&secrets_path).expect("read secrets");

        let rendered = format!("{secrets:?}");
        assert!(rendered.contains("[redacted"));
        assert!(
            !rendered.contains(&format!("{:?}", secrets.store_mac)),
            "the bundle leaked its store MAC key"
        );
    }

    #[test]
    fn api_keys_survive_a_restart() {
        // Without replay the key store boots empty and every issued credential
        // silently stops authenticating.
        let dir = TempDir::new("startup-keys");
        let verifier_key = b"a-key-verifier-key-for-these-tests";

        let (id, secret) = {
            let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
                .expect("open store");
            let keys = KeyStore::new(verifier_key);
            let new_key = keys
                .create(
                    hypellm_core::ids::TenantId::new("acme").expect("tenant"),
                    hypellm_core::ids::PrincipalId::new("svc:test").expect("principal"),
                    vec![hypellm_auth::Scope::Inference],
                    Vec::new(),
                    None,
                    hypellm_auth::SourceRestriction::Any,
                    None,
                    1_767_225_600_000,
                )
                .expect("entropy");
            store
                .append(RecordKind::ApiKey, &new_key.record.to_payload())
                .expect("append");
            let id = new_key.id().clone();
            (id, new_key.into_secret())
        };

        let (_store, recovery) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("reopen");
        let keys = KeyStore::new(verifier_key);
        let counts = restore_keys(&recovery, &keys);

        assert_eq!(counts, RestoredKeys { restored: 1, unreadable: 0 });
        assert!(keys.get(&id).is_some(), "the record was not restored");
        assert!(
            keys.verify(&secret, None, 1_767_225_600_001).is_ok(),
            "the restored record must still authenticate the issued secret"
        );
    }

    #[test]
    fn a_revocation_survives_a_restart() {
        // Specification 22.3: a key is revoked because it leaked. A restart
        // that resurrects it is the worst possible failure of this path.
        let dir = TempDir::new("startup-revocation");
        let verifier_key = b"a-key-verifier-key-for-these-tests";

        let (id, secret) = {
            let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
                .expect("open store");
            let keys = KeyStore::new(verifier_key);
            let new_key = keys
                .create(
                    hypellm_core::ids::TenantId::new("acme").expect("tenant"),
                    hypellm_core::ids::PrincipalId::new("svc:test").expect("principal"),
                    vec![hypellm_auth::Scope::Inference],
                    Vec::new(),
                    None,
                    hypellm_auth::SourceRestriction::Any,
                    None,
                    1_767_225_600_000,
                )
                .expect("entropy");
            store
                .append(RecordKind::ApiKey, &new_key.record.to_payload())
                .expect("append");
            let id = new_key.id().clone();
            store
                .append(RecordKind::ApiKeyRevocation, id.as_str().as_bytes())
                .expect("append revocation");
            (id, new_key.into_secret())
        };

        let (_store, recovery) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("reopen");
        let keys = KeyStore::new(verifier_key);
        restore_keys(&recovery, &keys);

        assert!(keys.get(&id).is_some_and(|r| r.revoked), "the key was resurrected");
        assert!(
            keys.verify(&secret, None, 1_767_225_600_001).is_err(),
            "a revoked key must not authenticate after a restart"
        );
    }

    #[test]
    fn an_unreadable_key_record_is_counted_rather_than_ignored() {
        let dir = TempDir::new("startup-bad-key");
        {
            let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
                .expect("open store");
            store.append(RecordKind::ApiKey, b"not a key record").expect("append");
        }
        let (_store, recovery) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("reopen");
        let keys = KeyStore::new(b"a-key-verifier-key-for-these-tests");
        let counts = restore_keys(&recovery, &keys);
        assert_eq!(counts, RestoredKeys { restored: 0, unreadable: 1 });
    }

    #[test]
    fn a_published_activation_survives_a_restart() {
        // The defect this covers: startup read the file and ignored the log
        // entirely, so a policy published through the management API — drafted,
        // approved, and durably recorded — was silently reverted by the next
        // restart.
        let dir = TempDir::new("startup-resume");
        let state_dir = dir.path().display().to_string();
        let from_file = MINIMAL.replace("STATE_DIR", &state_dir);

        // The published document differs from the file in a way the snapshot
        // shows: a second alias.
        let published = format!("{from_file}alias id=published targets=local:m\n");

        let recovery = recovery_with_activation(&dir, &published);
        let file_config = hypellm_config::load(&from_file, 1).expect("file config validates");

        match resume_activation(&recovery, file_config).expect("resumes") {
            Resumed::FromLog { config, sequence } => {
                assert!(
                    config.snapshot.aliases.contains_key(
                        &hypellm_core::ids::AliasId::new("published").expect("alias id")
                    ),
                    "the resumed configuration must be the published one"
                );
                assert_eq!(sequence, 1, "the frame sequence becomes the version");
                assert_eq!(config.snapshot.version, 1);
            }
            Resumed::FromFile(_) => panic!("the recorded activation was ignored"),
        }
    }

    #[test]
    fn an_empty_log_falls_back_to_the_file() {
        let dir = TempDir::new("startup-no-activation");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let (_store, recovery) =
            Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0).expect("open");
        let file_config = hypellm_config::load(&text, 1).expect("validates");

        match resume_activation(&recovery, file_config).expect("resumes") {
            Resumed::FromFile(config) => assert_eq!(config.snapshot.aliases.len(), 1),
            Resumed::FromLog { .. } => panic!("there was no activation to resume"),
        }
    }

    #[test]
    fn the_newest_activation_wins() {
        let dir = TempDir::new("startup-newest");
        let state_dir = dir.path().display().to_string();
        let base = MINIMAL.replace("STATE_DIR", &state_dir);

        let (store, _) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("open store");
        store
            .append(
                RecordKind::ConfigActivation,
                format!("{base}alias id=older targets=local:m\n").as_bytes(),
            )
            .expect("append");
        store
            .append(
                RecordKind::ConfigActivation,
                format!("{base}alias id=newer targets=local:m\n").as_bytes(),
            )
            .expect("append");
        drop(store);
        let (_store, recovery) = Store::open(dir.path(), b"a-store-mac-key-for-these-tests", 0)
            .expect("reopen");

        let file_config = hypellm_config::load(&base, 1).expect("validates");
        match resume_activation(&recovery, file_config).expect("resumes") {
            Resumed::FromLog { config, .. } => {
                assert!(config.snapshot.aliases.contains_key(
                    &hypellm_core::ids::AliasId::new("newer").expect("alias id")
                ));
                assert!(!config.snapshot.aliases.contains_key(
                    &hypellm_core::ids::AliasId::new("older").expect("alias id")
                ));
            }
            Resumed::FromFile(_) => panic!("the activations were ignored"),
        }
    }

    #[test]
    fn an_unrestorable_activation_fails_startup_rather_than_reverting() {
        // Falling back to the file here would silently drop the published
        // policy — the failure mode this whole path exists to prevent.
        let dir = TempDir::new("startup-bad-activation");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let recovery = recovery_with_activation(&dir, "alias id=a targets=does-not-exist\n");
        let file_config = hypellm_config::load(&text, 1).expect("validates");

        match resume_activation(&recovery, file_config) {
            Err(StartupError::ActivationUnrecoverable { sequence, detail }) => {
                assert_eq!(sequence, 1);
                assert!(!detail.is_empty());
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_activation_naming_a_different_state_directory_fails_startup() {
        // The store was opened from the file's path; honouring a different one
        // would leave the process reading one directory and writing another.
        let dir = TempDir::new("startup-moved-state");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let elsewhere = MINIMAL.replace("STATE_DIR", "/var/lib/somewhere-else");
        let recovery = recovery_with_activation(&dir, &elsewhere);
        let file_config = hypellm_config::load(&text, 1).expect("validates");

        match resume_activation(&recovery, file_config) {
            Err(StartupError::ActivationUnrecoverable { detail, .. }) => {
                assert!(detail.contains("state_dir"), "{detail}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_configuration_checks() {
        let dir = TempDir::new("startup-check");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let path = write_config(&dir, &text);
        let config = check_config(&path).expect("checks");
        assert_eq!(config.snapshot.targets.len(), 1);
    }

    #[test]
    fn an_invalid_configuration_is_reported_with_every_error() {
        let dir = TempDir::new("startup-bad");
        let path = write_config(&dir, "alias id=a targets=missing1\nalias id=b targets=missing2\n");
        match check_config(&path) {
            Err(StartupError::ConfigInvalid(errors)) => {
                assert!(errors.len() >= 2, "expected several errors, got {errors:?}");
                let rendered = StartupError::ConfigInvalid(errors).to_string();
                assert!(rendered.contains("did not validate"));
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_configuration_is_reported_with_its_path() {
        let error = check_config(Path::new("/nonexistent/hypellm.conf")).expect_err("must fail");
        assert!(error.to_string().contains("/nonexistent/hypellm.conf"));
    }

    #[test]
    fn assembly_fails_when_an_https_upstream_has_no_tls_helper() {
        // Specification 4: outbound HTTPS goes through the platform helper.
        // Discovering that at startup beats discovering it on the first
        // request, when a credential would otherwise be at risk.
        let dir = TempDir::new("startup-tls");
        let text = format!(
            "settings state_dir={} inference_listen=127.0.0.1:0 admin_listen=127.0.0.1:0\n\
             tenant id=acme\n\
             credential id=cred\n\
             provider id=remote family=openai scheme=https host=api.example credential=cred\n\
             target id=remote:m provider=remote model=m operations=chat streaming=true \
             context=1000 max_output=100\n\
             alias id=a targets=remote:m\n\
             grant scope=tenant:acme model=* allow=true\n\
             binding id=b scope=tenant:acme model=* prefer=remote:m\n",
            dir.path().display()
        );
        let path = write_config(&dir, &text);
        let secrets = Secrets::generate().expect("entropy");

        match Router::assemble(&path, secrets, Severity::Warn) {
            Err(StartupError::Unreachable(problems)) => {
                assert_eq!(problems.len(), 1);
                assert!(problems[0].contains("tls_helper_socket"));
            }
            other => panic!("expected an unreachable-destination failure, got {other:?}"),
        }
    }

    #[test]
    fn a_router_assembles_and_binds() {
        let dir = TempDir::new("startup-assemble");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let path = write_config(&dir, &text);
        let secrets = Secrets::generate().expect("entropy");

        let router = Router::assemble(&path, secrets, Severity::Warn).expect("assembles");
        assert!(router.inference.local_addr().is_ok());
        assert!(router.management.local_addr().is_ok());
        assert_ne!(
            router.inference.local_addr().unwrap().port(),
            router.management.local_addr().unwrap().port(),
            "the two planes must be separate listeners"
        );

        // The target's declared concurrency became an admission ceiling even
        // though no explicit quota named it.
        let target = hypellm_core::ids::TargetId::new("local:m").unwrap();
        assert!(router.state.admission.target_scope(&target).is_some());
    }

    #[test]
    fn a_generated_bundle_carries_a_token_that_satisfies_the_verifier_it_wrote() {
        // `generate` mints the break-glass token, derives the verifier, and
        // writes only the verifier — so the token it returns is the whole of
        // that credential's distribution. `main` prints it and nothing else
        // reads it.
        //
        // The field went unread for a while, which is not a failure any test
        // of the verifier could catch: the verifier was correct and nothing
        // could satisfy it. On a deployment with no OIDC that leaves no way
        // into the management plane, and therefore no way to mint the API key
        // that inference requires.
        let dir = TempDir::new("startup-break-glass-token");
        let secrets = Secrets::generate().expect("entropy");

        let token = secrets
            .break_glass_token
            .clone()
            .expect("a generated bundle must carry its token, or it cannot be handed to anyone");
        assert!(
            token.len() >= 32,
            "a 256-bit token encodes to more than 32 characters, got {}",
            token.len()
        );

        let path = dir.join("secrets");
        secrets.write_to(&path).expect("write bundle");

        // What the router will actually check the presented token against is
        // the file, not the in-memory copy.
        let written = std::fs::read(path.join("break_glass.verifier")).expect("verifier written");
        assert_eq!(
            written,
            break_glass_verifier(&token),
            "the printed token must verify against the verifier that was written beside it"
        );
        assert_ne!(
            written,
            break_glass_verifier(&format!("{token}x")),
            "the verifier must not accept a token it was not derived from"
        );

        // And the token itself is not on disk anywhere in the bundle:
        // specification 22.4 requires it to live offline.
        for entry in std::fs::read_dir(&path).expect("read bundle") {
            let entry = entry.expect("entry");
            if entry.path().is_dir() {
                continue;
            }
            let bytes = std::fs::read(entry.path()).expect("read file");
            assert!(
                !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                "the token must not be written to {}",
                entry.path().display()
            );
        }
    }

    #[test]
    fn shutting_down_stops_the_metrics_listener_too() {
        // `serve` joins every listener thread it spawned, and the only thing
        // that ends a listener's accept loop is its own shutdown handle. When
        // `shutdown_handles` returned the inference and management pair and
        // nothing else, a router configured with `metrics_listen` answered
        // `shutdown` on the control socket, drained both planes, and then
        // blocked forever joining a metrics thread nobody had asked to stop.
        //
        // A deployment that scrapes metrics on their own address — which is
        // the reason the setting exists — therefore could not be stopped
        // gracefully at all, only killed.
        let dir = TempDir::new("startup-shutdown-metrics");
        let text = MINIMAL
            .replace("STATE_DIR", &dir.path().display().to_string())
            .replace(
                "admin_listen=127.0.0.1:0",
                "admin_listen=127.0.0.1:0 metrics_listen=127.0.0.1:0",
            );
        let path = write_config(&dir, &text);
        let secrets = Secrets::generate().expect("entropy");
        let router = Router::assemble(&path, secrets, Severity::Warn).expect("assembles");

        assert!(
            router.metrics.is_some(),
            "the fixture must actually bind a third listener, or this proves nothing"
        );
        let handles = router.shutdown_handles();
        assert_eq!(
            handles.len(),
            3,
            "one handle per bound listener: inference, management, metrics"
        );

        let (finished, waiting) = std::sync::mpsc::channel();
        let served = std::thread::spawn(move || {
            let outcome = router.serve(
                CorsPolicy::with_origins(Vec::new()),
                None,
                None,
                vec![7u8; 32],
                None,
            );
            let _ = finished.send(());
            outcome
        });

        for handle in &handles {
            handle.shutdown();
        }

        assert!(
            waiting
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "serve did not return within 10s of every handle being signalled"
        );
        assert!(served.join().expect("serve thread").is_ok());
    }

    #[test]
    fn listener_limits_are_configurable_and_clamped() {
        // `DI-031`: `max_connections`, `read_timeout`, `keepalive_timeout`, and
        // `max_requests_per_connection` were compile-time constants that no
        // settings field reached — including `keepalive_interval_ms`, which the
        // grammar accepted and nothing read.
        let mut settings = hypellm_config::Settings::default();
        let base = ServerConfig::inference();

        // Zero keeps the profile default, so an operator tunes what they mean
        // to and inherits the rest.
        let untouched = listener_config(base, &settings);
        assert_eq!(untouched.max_connections, base.max_connections);
        assert_eq!(untouched.read_timeout, base.read_timeout);
        assert_eq!(untouched.keepalive_timeout, base.keepalive_timeout);
        assert_eq!(
            untouched.connection_stack_bytes,
            base.connection_stack_bytes
        );

        settings.max_connections = 64;
        settings.max_requests_per_connection = 25;
        settings.read_timeout_ms = 5_000;
        settings.keepalive_timeout_ms = 9_000;
        settings.connection_stack_kib = 1_024;
        let tuned = listener_config(base, &settings);
        assert_eq!(tuned.max_connections, 64);
        assert_eq!(tuned.max_requests_per_connection, 25);
        assert_eq!(tuned.read_timeout, Duration::from_millis(5_000));
        assert_eq!(tuned.keepalive_timeout, Duration::from_millis(9_000));
        assert_eq!(tuned.connection_stack_bytes, 1_024 * 1024);

        // Clamped, not trusted. These are the bounds that keep a connection
        // flood from becoming memory exhaustion and a slow client from holding
        // a socket forever; a configuration mistake may move a bound inside the
        // allowed range and may not remove it.
        settings.max_connections = u64::MAX;
        settings.max_requests_per_connection = u32::MAX;
        settings.read_timeout_ms = u64::MAX;
        settings.keepalive_timeout_ms = u64::MAX;
        settings.connection_stack_kib = u64::MAX;
        let clamped = listener_config(base, &settings);
        assert_eq!(clamped.max_connections, MAX_CONNECTIONS_CEILING);
        assert_eq!(
            clamped.max_requests_per_connection,
            MAX_REQUESTS_PER_CONNECTION_CEILING
        );
        assert_eq!(
            clamped.read_timeout,
            Duration::from_millis(MAX_READ_TIMEOUT_MS)
        );
        // `DI-001`: an unbounded stack would put `max_connections` back out of
        // reach, since one thread per connection makes this a direct multiplier
        // on committed address space. Note the `u64::MAX` KiB figure overflows
        // a byte count — it must clamp, not wrap into something small.
        assert_eq!(clamped.connection_stack_bytes, MAX_CONNECTION_STACK_BYTES);

        // And too small is raised: a stack the handler overflows aborts the
        // process rather than failing the request.
        settings.connection_stack_kib = 1;
        let floored_stack = listener_config(base, &settings);
        assert_eq!(
            floored_stack.connection_stack_bytes,
            MIN_CONNECTION_STACK_BYTES
        );

        // And a value too small to be workable is raised, not honoured: a
        // read timeout that cuts a healthy client mid-request presents as an
        // intermittent network fault and is very hard to diagnose.
        settings.read_timeout_ms = 1;
        let floored = listener_config(base, &settings);
        assert_eq!(
            floored.read_timeout,
            Duration::from_millis(MIN_READ_TIMEOUT_MS)
        );
    }

    #[test]
    fn adopting_the_file_overrides_a_published_activation_and_records_why() {
        // `DI-027`. A published activation is authoritative — a policy that was
        // drafted, reviewed, approved, and durably recorded must not vanish on
        // the next restart — but that made the configuration file permanently
        // inert once anything had been published, and the only way back was to
        // start against an empty state directory, discarding the audit chain
        // and every stored API key to change a configuration line.
        let dir = TempDir::new("adopt-config");
        let state = dir.join("state");
        let file_text = MINIMAL.replace("STATE_DIR", &state.display().to_string());
        let path = write_config(&dir, &file_text);

        // Publish something else, the way the management API would.
        let published = file_text.replace("tenant id=acme", "tenant id=acme\ntenant id=published");
        let secrets = Secrets::generate().expect("entropy");
        let key = secrets.store_mac.clone();
        {
            let (store, _) = Store::open(&state, &key, 0).expect("open");
            store
                .append(RecordKind::ConfigActivation, published.as_bytes())
                .expect("append");
        }

        // Without adoption the published policy wins — that is `DI-027`'s
        // correct half, and the reason adoption has to be explicit.
        {
            let router = Router::assemble(&path, Secrets::from_dir_or(&key), Severity::Warn)
                .expect("assembles");
            assert!(
                router.state.config().tenants.contains_key(
                    &hypellm_core::ids::TenantId::new("published").expect("tenant")
                ),
                "the published activation must win by default"
            );
        }

        // With it, the file wins and the override is recorded.
        let router = Router::assemble_with(
            &path,
            Secrets::from_dir_or(&key),
            Severity::Warn,
            Some("reverting a bad publication, incident 4711"),
        )
        .expect("assembles");
        assert!(
            !router.state.config().tenants.contains_key(
                &hypellm_core::ids::TenantId::new("published").expect("tenant")
            ),
            "adoption must take the file"
        );

        // Durable and audited, so the override is attributable afterwards.
        let records = router
            .state
            .store
            .audit_records(None, 50)
            .expect("audit records");
        let adopted = records
            .iter()
            .find(|(_, r)| r.event.action == AuditAction::ConfigAdopted)
            .expect("adoption must be audited");
        assert_eq!(
            adopted.1.event.reason.as_ref().map(|r| r.as_str()),
            Some("reverting a bad publication, incident 4711")
        );
    }

    #[test]
    fn an_adopted_configuration_survives_the_next_restart() {
        // Adoption writes a new activation, so it is not a one-shot override
        // that silently reverts — which would be the worst of both designs.
        let dir = TempDir::new("adopt-persist");
        let state = dir.join("state");
        let file_text = MINIMAL.replace("STATE_DIR", &state.display().to_string());
        let path = write_config(&dir, &file_text);
        let key = Secrets::generate().expect("entropy").store_mac;

        let published = file_text.replace("tenant id=acme", "tenant id=acme\ntenant id=published");
        {
            let (store, _) = Store::open(&state, &key, 0).expect("open");
            store
                .append(RecordKind::ConfigActivation, published.as_bytes())
                .expect("append");
        }
        drop(
            Router::assemble_with(
                &path,
                Secrets::from_dir_or(&key),
                Severity::Warn,
                Some("adopting the file, incident 4711"),
            )
            .expect("assembles"),
        );

        let after = Router::assemble(&path, Secrets::from_dir_or(&key), Severity::Warn)
            .expect("assembles");
        assert!(
            !after.state.config().tenants.contains_key(
                &hypellm_core::ids::TenantId::new("published").expect("tenant")
            ),
            "the adoption did not persist"
        );
    }

    #[test]
    fn a_control_command_without_the_token_is_refused() {
        // Specification 20.1 requires graceful shutdown to exist; it does not
        // authorise an unauthenticated trigger for it. Before this, anything on
        // the host that could open the socket could stop the router, and the
        // socket was created under the process umask.
        let key = hypellm_crypto::hex::encode(b"a-control-token").into_bytes();

        assert_eq!(
            authenticated_control_command(
                &format!("{} shutdown", String::from_utf8_lossy(&key)),
                &key
            ),
            Some("shutdown")
        );

        for line in [
            "shutdown",                       // no token at all
            "  shutdown  ",                   // nor with whitespace
            "wrong shutdown",                 // a wrong token
            "",                               // nothing
            "6162 shutdown",                  // a token prefix
        ] {
            assert_eq!(
                authenticated_control_command(line, &key),
                None,
                "'{line}' was accepted"
            );
        }
    }

    #[test]
    fn the_control_token_is_part_of_a_generated_bundle_and_never_printed() {
        let dir = TempDir::new("control-key");
        let path = dir.join("secrets");
        let generated = Secrets::generate().expect("entropy");
        generated.write_to(&path).expect("write");

        assert!(
            path.join("control.key").is_file(),
            "--generate-secrets must produce the control token"
        );
        let loaded = Secrets::from_dir(&path).expect("read");
        assert_eq!(loaded.control, generated.control);

        // The whole bundle is redacted in `Debug`, this key included: a control
        // token in a log line is a shutdown switch in a log line.
        let rendered = format!("{loaded:?}");
        assert!(!rendered.contains(&format!("{:?}", generated.control)));
        assert!(rendered.contains("control"));
    }

    #[test]
    fn a_missing_control_key_fails_startup_rather_than_defaulting() {
        // An older bundle predates this file. Inventing a token would leave the
        // socket authenticated by a value nobody holds, which is indisputably
        // worse than saying so.
        let dir = TempDir::new("control-key-missing");
        let path = dir.join("secrets");
        Secrets::generate().expect("entropy").write_to(&path).expect("write");
        std::fs::remove_file(path.join("control.key")).expect("remove");

        match Secrets::from_dir(&path) {
            Err(StartupError::MissingSecret(name)) => assert_eq!(name, "control.key"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_broken_audit_chain_refuses_to_start() {
        // Specification 11.2: startup "fails closed on protected-record
        // integrity errors". Every frame below still authenticates under the
        // store MAC — one audit record was simply removed, so only the *chain*
        // disagrees. That is precisely the tamper a per-frame check cannot see,
        // and the only thing the hash chain is for.
        let dir = TempDir::new("startup-broken-chain");
        let state = dir.join("state");
        let scratch = dir.join("scratch");
        let text = MINIMAL.replace("STATE_DIR", &state.display().to_string());
        let path = write_config(&dir, &text);
        let secrets = Secrets::generate().expect("entropy");
        let key = secrets.store_mac.clone();

        let surviving: Vec<(RecordKind, Vec<u8>)> = {
            let (store, _) = Store::open(&scratch, &key, 0).expect("open scratch");
            for n in 0..6 {
                store
                    .append_audit(hypellm_store::AuditEvent::new(
                        n,
                        "admin",
                        hypellm_store::AuditAction::KeyCreated,
                    ))
                    .expect("audit");
            }
            drop(store);

            let (_store, recovery) = Store::open(&scratch, &key, 0).expect("reopen scratch");
            let removed = recovery
                .frames
                .iter()
                .filter(|f| f.kind == RecordKind::AuditEvent)
                .nth(2)
                .map(|f| f.sequence)
                .expect("a middle audit record");
            recovery
                .frames
                .iter()
                .filter(|f| f.sequence != removed)
                .map(|f| (f.kind, f.payload.clone()))
                .collect()
        };

        {
            let (store, _) = Store::open(&state, &key, 0).expect("open state");
            for (kind, payload) in &surviving {
                store.append(*kind, payload).expect("append");
            }
        }

        match Router::assemble(&path, secrets, Severity::Warn) {
            Err(StartupError::AuditChainBroken { .. }) => {}
            other => panic!("expected a refusal to start, got {other:?}"),
        }
    }

    #[test]
    fn two_routers_cannot_share_a_state_directory() {
        let dir = TempDir::new("startup-lock");
        let text = MINIMAL.replace("STATE_DIR", &dir.path().display().to_string());
        let path = write_config(&dir, &text);

        let _first = Router::assemble(&path, Secrets::generate().unwrap(), Severity::Warn)
            .expect("first assembles");
        match Router::assemble(&path, Secrets::generate().unwrap(), Severity::Warn) {
            Err(StartupError::Store(detail)) => assert!(detail.contains("locked")),
            other => panic!("expected a lock failure, got {other:?}"),
        }
    }

    #[test]
    fn the_control_socket_path_defaults_into_the_state_directory() {
        let dir = TempDir::new("control-default");
        let text = MINIMAL.replace("STATE_DIR", "/run/hypellm");
        let path = write_config(&dir, &text);
        let config = check_config(&path).expect("checks");
        assert_eq!(
            control_socket_path(&config).expect("fits"),
            PathBuf::from("/run/hypellm/control.sock")
        );
    }

    #[test]
    fn an_explicit_control_socket_overrides_the_default() {
        let dir = TempDir::new("control-explicit");
        let text = MINIMAL
            .replace("STATE_DIR", "/run/hypellm")
            .replace(
                "admin_listen=127.0.0.1:0",
                "admin_listen=127.0.0.1:0 control_socket=/run/a.sock",
            );
        let path = write_config(&dir, &text);
        let config = check_config(&path).expect("checks");
        assert_eq!(
            control_socket_path(&config).expect("fits"),
            PathBuf::from("/run/a.sock")
        );
    }

    #[test]
    fn an_over_long_control_socket_path_is_reported_with_the_fix() {
        // The kernel reports a bare error for this; an operator needs to be
        // told what to change, not that a path "must be shorter".
        let dir = TempDir::new("control-long");
        let deep = format!("/{}", "verylongdirectory/".repeat(12));
        let text = MINIMAL.replace("STATE_DIR", &deep);
        let path = write_config(&dir, &text);
        let config = check_config(&path).expect("checks");

        let message = control_socket_path(&config).expect_err("must not fit");
        assert!(message.contains("control_socket"));
        assert!(message.contains(&MAX_UNIX_PATH.to_string()));
    }

    #[test]
    fn secrets_round_trip_through_a_directory() {
        let dir = TempDir::new("secrets");
        let generated = Secrets::generate().expect("entropy");
        generated.write_to(dir.path()).expect("write");

        let loaded = Secrets::from_dir(dir.path()).expect("read");
        assert_eq!(loaded.store_mac, generated.store_mac);
        assert_eq!(loaded.session, generated.session);
        assert_eq!(loaded.pseudonym.len(), 32);
    }

    #[test]
    fn a_missing_or_short_secret_is_refused() {
        // A router that invents its own store MAC key on first boot cannot
        // detect tampering across a restart.
        let dir = TempDir::new("secrets-missing");
        match Secrets::from_dir(dir.path()) {
            Err(StartupError::MissingSecret(name)) => assert_eq!(name, "store_mac.key"),
            other => panic!("expected a missing secret, got {other:?}"),
        }

        std::fs::write(dir.join("store_mac.key"), b"tooshort").expect("write");
        assert!(matches!(
            Secrets::from_dir(dir.path()),
            Err(StartupError::MissingSecret("store_mac.key"))
        ));
    }

    #[test]
    fn generated_secrets_are_distinct() {
        let secrets = Secrets::generate().expect("entropy");
        assert_ne!(secrets.store_mac, secrets.session);
        assert_ne!(secrets.key_verifier, secrets.pseudonym);
        assert_ne!(secrets.oidc, secrets.store_mac);
    }
    #[test]
    fn an_enabled_fleet_without_a_key_refuses_to_start() {
        // The alternative is a router that appears healthy and refuses every
        // orchestrated target with a reason nobody expects, hours later.
        let dir = hypellm_store::TempDir::new("fleet-key");
        let state = dir.join("state");
        let path = dir.join("hypellm.conf");
        let text = format!(
            "settings state_dir={} fleet_enabled=true\n\
             tenant id=acme\n\
             provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 \
             egress=local\n\
             target id=local:m provider=local model=m local=true operations=chat \
             context=1000 max_output=100\n\
             alias id=a targets=local:m\n\
             grant scope=tenant:acme allow=true\n\
             binding id=b scope=tenant:acme prefer=local:m\n\
             fleet_agent id=local socket=\"/run/hypellm/fleet.sock\"\n\
             host id=h agent=local arch=x86_64\n\
             accelerator host=h id=gpu0 kind=cuda memory_bytes=8589934592\n\
             deployment id=d target=local:m accelerator=gpu0 memory_bytes=1073741824\n",
            state.display()
        );
        std::fs::write(&path, text).expect("write");

        let mut secrets = Secrets::generate().expect("entropy");
        secrets.fleet = None;
        let error = Router::assemble(&path, secrets, Severity::Warn)
            .err()
            .expect("a declared, enabled fleet with no key must not start");
        assert!(
            matches!(error, StartupError::MissingSecret("fleet.key")),
            "got {error:?}"
        );
    }

    #[test]
    fn a_declared_but_disabled_fleet_starts_without_a_key() {
        // Validation is off-path and does not depend on the switch: a fleet can
        // be written, checked and reviewed before it is turned on, and a router
        // that demanded the key to do that would make the review harder than
        // the deployment.
        let dir = hypellm_store::TempDir::new("fleet-key-off");
        let state = dir.join("state");
        let path = dir.join("hypellm.conf");
        let text = format!(
            // Port 0 so the test does not race the default listener with
            // whatever else the suite is running.
            "settings state_dir={} fleet_enabled=false \
             inference_listen=127.0.0.1:0 admin_listen=127.0.0.1:0\n\
             tenant id=acme\n\
             provider id=local family=llamacpp scheme=http host=127.0.0.1 port=8080 \
             egress=local\n\
             target id=local:m provider=local model=m local=true operations=chat \
             context=1000 max_output=100\n\
             alias id=a targets=local:m\n\
             grant scope=tenant:acme allow=true\n\
             binding id=b scope=tenant:acme prefer=local:m\n\
             fleet_agent id=local socket=\"/run/hypellm/fleet.sock\"\n\
             host id=h agent=local arch=x86_64\n\
             accelerator host=h id=gpu0 kind=cuda memory_bytes=8589934592\n\
             deployment id=d target=local:m accelerator=gpu0 memory_bytes=1073741824\n",
            state.display()
        );
        std::fs::write(&path, text).expect("write");

        let mut secrets = Secrets::generate().expect("entropy");
        secrets.fleet = None;
        let router = Router::assemble(&path, secrets, Severity::Warn).expect("assembles");
        assert!(
            router.state.fleet().is_none(),
            "a disabled fleet must produce no runtime"
        );
        assert_eq!(
            router.state.config().fleet.deployments.len(),
            1,
            "and must still be parsed and validated"
        );
    }

    #[test]
    fn generated_secrets_include_a_fleet_key_and_it_is_owner_only() {
        let dir = hypellm_store::TempDir::new("fleet-secrets");
        let secrets = Secrets::generate().expect("entropy");
        secrets.write_to(dir.path()).expect("write");
        let key = dir.join("fleet.key");
        assert!(key.is_file(), "--generate-secrets must write fleet.key");
        assert!(
            std::fs::read(&key).expect("read").len() >= 32,
            "a short key would silently weaken the handshake"
        );
        let reread = Secrets::from_dir(dir.path()).expect("reads back");
        assert!(reread.fleet.is_some());
    }

}
