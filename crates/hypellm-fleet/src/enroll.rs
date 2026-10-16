//! Slave enrollment (specification 26.8): the record, its state machine, the
//! registration a new slave reports, and the offer the fleet agent pulls.
//!
//! Pure, like the rest of this crate. Nothing here reads a clock, touches a
//! socket, or draws randomness: the caller passes `now`, mints the token, and
//! supplies the journal. That keeps the one rule that matters testable without
//! a store — **nothing becomes visible that was not committed first.**
//!
//! # The lifecycle
//!
//! ```text
//! issued ──register──▶ registered ──approve──▶ approved ──revoke──▶ revoked
//!   │                      │
//!   ├──reject──────────────┴──reject──▶ rejected
//!   └──(ttl passes)──▶ expired
//! ```
//!
//! A slave that has registered is **not** a fleet member. It becomes one only
//! when an administrator approves it, which drafts its `host` and
//! `accelerator` records, and a second person publishes that draft. Only then
//! is it offered to the fleet agent ([`offer_for_agent`]), and only an agent
//! configured to accept enrollments adds it to its allowlist.
//!
//! # What the token is
//!
//! A one-time bearer secret, minted by the management API and shown once. The
//! registry holds only its domain-separated SHA-256 ([`token_digest`]), so a
//! copy of the state directory cannot be used to register a machine. A token
//! matches only while its enrollment is `issued` and unexpired: registering
//! consumes it, and every other state answers exactly as an unknown token
//! does, so a caller cannot learn which tokens once existed.

use core::fmt;
use hypellm_core::ids::{AcceleratorId, AgentId, HostId};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use wire_json::{Object, Value};

use crate::model::{Arch, FleetConfig};

/// The host-kit version this router serves. The install script embeds the
/// same string and refuses a `--version` that differs.
pub const HOST_KIT_VERSION: &str = "1.1.0";

/// Enrollments not yet in a terminal state, at most.
pub const MAX_OPEN_ENROLLMENTS: usize = 64;

/// Terminal enrollments kept in memory for the dashboard, at most.
pub const MAX_RETAINED_ENROLLMENTS: usize = 256;

/// The default token lifetime: thirty minutes.
pub const DEFAULT_TTL_SECS: u64 = 30 * 60;

/// The shortest token lifetime an administrator may ask for.
pub const MIN_TTL_SECS: u64 = 60;

/// The longest token lifetime an administrator may ask for.
pub const MAX_TTL_SECS: u64 = 24 * 60 * 60;

/// [`DEFAULT_TTL_SECS`] in milliseconds.
pub const DEFAULT_TTL_MS: u64 = DEFAULT_TTL_SECS * 1000;

/// [`MIN_TTL_SECS`] in milliseconds.
pub const MIN_TTL_MS: u64 = MIN_TTL_SECS * 1000;

/// [`MAX_TTL_SECS`] in milliseconds.
pub const MAX_TTL_MS: u64 = MAX_TTL_SECS * 1000;

/// Accelerators one registration may report.
pub const MAX_GPUS: usize = 16;

/// Bytes of the agent offer, at most.
pub const MAX_OFFER_BYTES: usize = 64 * 1024;

/// Hosts one offer may carry.
pub const MAX_OFFER_HOSTS: usize = 64;

/// Failed token presentations tolerated per [`THROTTLE_WINDOW_MS`].
pub const MAX_FAILED_ATTEMPTS: usize = 20;

/// The window over which failed presentations are counted.
pub const THROTTLE_WINDOW_MS: u64 = 60 * 1000;

const MAX_DATA_DIR: usize = 256;
const MAX_HOSTNAME: usize = 64;
const MAX_GPU_NAME: usize = 64;
const MAX_SSH_USER: usize = 32;
const MAX_KIT_VERSION: usize = 32;

/// The domain-separated digest under which a token is held.
#[must_use]
pub fn token_digest(token: &str) -> [u8; 32] {
    hypellm_crypto::sha256::sha256_parts(&[b"hypellm/fleet-enroll-token/v1\0", token.as_bytes()])
}

/// Whether `token` has the shape the management API mints: 64 lowercase hex
/// characters. Checked before anything is hashed or compared.
#[must_use]
pub fn token_well_formed(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// -- Keys -----------------------------------------------------------------

/// The wire blob of an `ssh-ed25519` public key: the algorithm name and the
/// 32-byte key, each length-prefixed.
const SSH_ED25519_BLOB_LEN: usize = 4 + 11 + 4 + 32;

/// An OpenSSH Ed25519 public key, checked structurally.
///
/// Parsed, not verified: nothing here performs a signature operation
/// (specification 4 keeps asymmetric cryptography out of the router). The
/// structural check is what stops a hostile registration from writing an
/// option, a second key, or a newline into the agent's `known_hosts`.
#[derive(Clone, PartialEq, Eq)]
pub struct SshEd25519Key {
    blob: Vec<u8>,
}

impl fmt::Debug for SshEd25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SshEd25519Key({})", self.fingerprint())
    }
}

impl SshEd25519Key {
    /// `ssh-ed25519 <base64>`, without the comment.
    #[must_use]
    pub fn line(&self) -> String {
        format!("ssh-ed25519 {}", hypellm_crypto::base64::encode_std(&self.blob))
    }

    /// `SHA256:<base64, unpadded>` — the form `ssh-keygen -l` prints, so an
    /// administrator can compare it with what the slave showed.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.blob)
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest = hypellm_crypto::sha256::sha256(bytes);
    format!(
        "SHA256:{}",
        hypellm_crypto::base64::encode(
            &digest,
            hypellm_crypto::base64::Alphabet::Standard,
            hypellm_crypto::base64::Padding::Forbidden,
        )
    )
}

/// Parse one `ssh-ed25519 <base64> [comment]` line.
///
/// The comment, if any, is dropped rather than kept: it is free text that the
/// key's holder chose, and it has no business in a file the agent's `ssh`
/// reads.
#[must_use]
pub fn ssh_ed25519_line(raw: &str) -> Option<SshEd25519Key> {
    if raw.len() > 512 || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut parts = raw.split(' ').filter(|p| !p.is_empty());
    if parts.next()? != "ssh-ed25519" {
        return None;
    }
    let encoded = parts.next()?;
    let blob = hypellm_crypto::base64::decode(
        encoded.as_bytes(),
        hypellm_crypto::base64::Alphabet::Standard,
        hypellm_crypto::base64::Padding::Required,
        SSH_ED25519_BLOB_LEN,
    )
    .ok()?;
    let mut expected = Vec::with_capacity(SSH_ED25519_BLOB_LEN);
    expected.extend_from_slice(&11_u32.to_be_bytes());
    expected.extend_from_slice(b"ssh-ed25519");
    expected.extend_from_slice(&32_u32.to_be_bytes());
    if blob.len() != SSH_ED25519_BLOB_LEN || !blob.starts_with(&expected) {
        return None;
    }
    Some(SshEd25519Key { blob })
}

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A slave's device key: an Ed25519 public key in `SubjectPublicKeyInfo`.
///
/// Stored so a later LAN verb can authenticate the slave by a signature the
/// local verifier checks (specification 9.1's delegation, applied to a device
/// rather than a person). No such verb exists yet; see
/// `spec/deferred-issues.html`. Until one does, this is a pinned identity an
/// administrator can compare by fingerprint, and nothing more.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKey {
    der: Vec<u8>,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({})", self.fingerprint())
    }
}

impl DeviceKey {
    /// The PEM form, as the slave sent it (normalised).
    #[must_use]
    pub fn pem(&self) -> String {
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            hypellm_crypto::base64::encode_std(&self.der)
        )
    }

    /// `SHA256:<base64>` over the DER encoding.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.der)
    }
}

/// Parse a PEM `PUBLIC KEY` holding exactly one Ed25519 key.
#[must_use]
pub fn device_key_pem(raw: &str) -> Option<DeviceKey> {
    if raw.len() > 512 {
        return None;
    }
    let body = raw
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")?
        .strip_suffix("-----END PUBLIC KEY-----")?;
    let encoded: String = body.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    let der = hypellm_crypto::base64::decode(
        encoded.as_bytes(),
        hypellm_crypto::base64::Alphabet::Standard,
        hypellm_crypto::base64::Padding::Required,
        ED25519_SPKI_PREFIX.len() + 32,
    )
    .ok()?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(&ED25519_SPKI_PREFIX) {
        return None;
    }
    Some(DeviceKey { der })
}

// -- The registration -----------------------------------------------------

/// One accelerator a slave reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedGpu {
    /// The `nvidia-smi` index.
    pub index: u32,
    /// The device name, narrowed for display.
    pub name: String,
    /// Total memory in bytes.
    pub memory_bytes: u64,
}

/// What a slave reported about itself when it registered.
///
/// Every field is the slave's claim. It is shown to an administrator, who
/// decides; nothing here is trusted until they approve, and even then the
/// address and host key are pinned rather than re-read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The LAN address the agent will SSH to.
    pub address: IpAddr,
    /// Machine architecture.
    pub arch: Arch,
    /// The machine's own name, for display only.
    pub hostname: String,
    /// The account that will own the data directory and accept the agent's key.
    pub ssh_user: String,
    /// Where containers will be deployed and keep state.
    pub data_dir: String,
    /// Reported accelerators. Empty for a CPU-only machine.
    pub gpus: Vec<ReportedGpu>,
    /// Physical memory in bytes.
    pub memory_bytes: u64,
    /// The SSH host key the agent will pin.
    pub host_key: SshEd25519Key,
    /// The slave's device key.
    pub device_key: DeviceKey,
    /// The host-kit version that registered.
    pub kit_version: String,
}

/// Why a registration was refused. The code names the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportError(pub &'static str);

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the registration field '{}' is missing or invalid", self.0)
    }
}

fn narrow(raw: &str, max: usize) -> String {
    raw.chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ' | '(' | ')') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn is_ssh_user(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_SSH_USER
        && !raw.starts_with('-')
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
}

/// Whether `raw` is an acceptable data directory: absolute, bounded, and made
/// of characters that survive a shell, a JSON file and a `docker -v` argument
/// unchanged.
#[must_use]
pub fn is_data_dir(raw: &str) -> bool {
    raw.starts_with('/')
        && raw.len() <= MAX_DATA_DIR
        && !raw.split('/').any(|segment| segment == "..")
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

/// Parse the body of `POST /fleet/v1/enroll:complete`, less the token.
pub fn parse_registration(body: &Value) -> Result<Registration, ReportError> {
    let text = |name: &'static str| body.get(name).and_then(Value::as_str).ok_or(ReportError(name));

    let address: IpAddr = text("address")?.parse().map_err(|_| ReportError("address"))?;
    if address.is_unspecified() || address.is_multicast() {
        return Err(ReportError("address"));
    }
    let arch = Arch::parse(text("arch")?).ok_or(ReportError("arch"))?;
    let hostname = narrow(text("hostname")?, MAX_HOSTNAME);
    let ssh_user = text("ssh_user")?;
    if !is_ssh_user(ssh_user) {
        return Err(ReportError("ssh_user"));
    }
    let data_dir = text("data_dir")?;
    if !is_data_dir(data_dir) {
        return Err(ReportError("data_dir"));
    }
    let memory_bytes = body
        .get("memory_bytes")
        .and_then(Value::as_u64)
        .filter(|m| *m > 0)
        .ok_or(ReportError("memory_bytes"))?;
    let host_key = ssh_ed25519_line(text("ssh_host_key")?).ok_or(ReportError("ssh_host_key"))?;
    let device_key = device_key_pem(text("device_key")?).ok_or(ReportError("device_key"))?;
    let kit_version = text("kit_version")?;
    if kit_version.is_empty()
        || kit_version.len() > MAX_KIT_VERSION
        || !kit_version.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(ReportError("kit_version"));
    }

    let raw_gpus = match body.get("gpus") {
        None | Some(Value::Null) => &[][..],
        Some(value) => value.as_array().ok_or(ReportError("gpus"))?,
    };
    if raw_gpus.len() > MAX_GPUS {
        return Err(ReportError("gpus"));
    }
    let mut gpus: Vec<ReportedGpu> = Vec::with_capacity(raw_gpus.len());
    for raw in raw_gpus {
        let index = raw
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|i| u32::try_from(i).ok())
            .filter(|i| *i < 64)
            .ok_or(ReportError("gpus"))?;
        if gpus.iter().any(|g| g.index == index) {
            return Err(ReportError("gpus"));
        }
        gpus.push(ReportedGpu {
            index,
            name: narrow(raw.get("name").and_then(Value::as_str).unwrap_or(""), MAX_GPU_NAME),
            memory_bytes: raw
                .get("memory_bytes")
                .and_then(Value::as_u64)
                .filter(|m| *m > 0)
                .ok_or(ReportError("gpus"))?,
        });
    }
    gpus.sort_by_key(|g| g.index);

    Ok(Registration {
        address,
        arch,
        hostname,
        ssh_user: ssh_user.to_owned(),
        data_dir: data_dir.to_owned(),
        gpus,
        memory_bytes,
        host_key,
        device_key,
        kit_version: kit_version.to_owned(),
    })
}

// -- The record -----------------------------------------------------------

/// Where an enrollment has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnrollmentState {
    /// A token exists and has not been used.
    Issued,
    /// The slave has registered and awaits an administrator.
    Registered,
    /// An administrator approved it; its records were drafted.
    Approved,
    /// An administrator refused it.
    Rejected,
    /// The token's lifetime passed before it was used.
    Expired,
    /// An approval was withdrawn. The agent drops the host on its next offer.
    Revoked,
}

impl EnrollmentState {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Registered => "registered",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// Parse a stable token.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "issued" => Self::Issued,
            "registered" => Self::Registered,
            "approved" => Self::Approved,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => return None,
        })
    }

    /// Whether nothing further can happen.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Expired | Self::Revoked)
    }
}

/// One enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// Identifier: 16 lowercase hex characters.
    pub id: String,
    /// The host identifier the slave will have.
    pub host: HostId,
    /// The agent that will manage it.
    pub agent: AgentId,
    /// The token's digest. Never the token.
    pub token_digest: [u8; 32],
    /// Who minted the token.
    pub issued_by: String,
    /// When.
    pub issued_at_ms: u64,
    /// When the token stops working.
    pub expires_at_ms: u64,
    /// Where it has got to.
    pub state: EnrollmentState,
    /// What the slave reported, once it has.
    pub registration: Option<Registration>,
    /// When the slave registered.
    pub registered_at_ms: Option<u64>,
    /// Who approved, rejected, or revoked it.
    pub decided_by: Option<String>,
    /// When.
    pub decided_at_ms: Option<u64>,
    /// The draft an approval created.
    pub draft: Option<String>,
}

impl Enrollment {
    /// The state as of `now`: an unused token past its lifetime reads as
    /// expired even before anything has written that down.
    #[must_use]
    pub fn state_at(&self, now_ms: u64) -> EnrollmentState {
        if self.state == EnrollmentState::Issued && now_ms >= self.expires_at_ms {
            EnrollmentState::Expired
        } else {
            self.state
        }
    }

    /// Whether this enrollment counts against [`MAX_OPEN_ENROLLMENTS`].
    #[must_use]
    pub fn is_open(&self, now_ms: u64) -> bool {
        matches!(
            self.state_at(now_ms),
            EnrollmentState::Issued | EnrollmentState::Registered
        )
    }
}

/// Encode a record for the log.
#[must_use]
pub fn encode_enrollment(record: &Enrollment) -> Vec<u8> {
    let mut object = Object::new();
    object.push("id", Value::from(record.id.as_str()));
    object.push("host", Value::from(record.host.as_str()));
    object.push("agent", Value::from(record.agent.as_str()));
    object.push(
        "token_digest",
        Value::from(hypellm_crypto::hex::encode(&record.token_digest)),
    );
    object.push("issued_by", Value::from(record.issued_by.as_str()));
    object.push("issued_at", Value::from(record.issued_at_ms));
    object.push("expires_at", Value::from(record.expires_at_ms));
    object.push("state", Value::from(record.state.as_str()));
    if let Some(registration) = &record.registration {
        object.push("registration", registration_value(registration, true));
    }
    object.push_opt("registered_at", record.registered_at_ms.map(Value::from));
    object.push_opt("decided_by", record.decided_by.as_deref().map(Value::from));
    object.push_opt("decided_at", record.decided_at_ms.map(Value::from));
    object.push_opt("draft", record.draft.as_deref().map(Value::from));
    wire_json::to_string(&Value::Object(object)).into_bytes()
}

/// A registration as JSON: the stored form when `full`, the dashboard form
/// (fingerprints instead of key material) otherwise.
#[must_use]
pub fn registration_value(registration: &Registration, full: bool) -> Value {
    let mut object = Object::new();
    object.push("address", Value::from(registration.address.to_string()));
    object.push("arch", Value::from(registration.arch.as_str()));
    object.push("hostname", Value::from(registration.hostname.as_str()));
    object.push("ssh_user", Value::from(registration.ssh_user.as_str()));
    object.push("data_dir", Value::from(registration.data_dir.as_str()));
    object.push("memory_bytes", Value::from(registration.memory_bytes));
    object.push(
        "gpus",
        Value::Array(
            registration
                .gpus
                .iter()
                .map(|gpu| {
                    let mut g = Object::new();
                    g.push("index", Value::from(gpu.index));
                    g.push("name", Value::from(gpu.name.as_str()));
                    g.push("memory_bytes", Value::from(gpu.memory_bytes));
                    Value::Object(g)
                })
                .collect(),
        ),
    );
    if full {
        object.push("ssh_host_key", Value::from(registration.host_key.line()));
        object.push("device_key", Value::from(registration.device_key.pem()));
    }
    object.push(
        "ssh_host_key_fingerprint",
        Value::from(registration.host_key.fingerprint()),
    );
    object.push(
        "device_key_fingerprint",
        Value::from(registration.device_key.fingerprint()),
    );
    object.push("kit_version", Value::from(registration.kit_version.as_str()));
    Value::Object(object)
}

/// Whether `raw` is an enrollment identifier.
#[must_use]
pub fn is_enrollment_id(raw: &str) -> bool {
    raw.len() == 16 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode a record. `None` for anything that is not exactly one.
#[must_use]
pub fn decode_enrollment(payload: &[u8]) -> Option<Enrollment> {
    let value = wire_json::parse(payload, &wire_json::Limits::SMALL).ok()?;
    value.as_object()?;
    let text = |name: &str| value.get(name).and_then(Value::as_str);
    let optional_text = |name: &str| match value.get(name) {
        None | Some(Value::Null) => Some(None),
        Some(v) => v.as_str().map(|s| Some(s.to_owned())),
    };
    let optional_u64 = |name: &str| match value.get(name) {
        None | Some(Value::Null) => Some(None),
        Some(v) => v.as_u64().map(Some),
    };
    let id = text("id")?;
    if !is_enrollment_id(id) {
        return None;
    }
    let token_digest = hypellm_crypto::hex::decode_digest(text("token_digest")?.as_bytes()).ok()?;
    let registration = match value.get("registration") {
        None | Some(Value::Null) => None,
        Some(inner) => Some(parse_registration(inner).ok()?),
    };
    Some(Enrollment {
        id: id.to_owned(),
        host: HostId::new(text("host")?).ok()?,
        agent: AgentId::new(text("agent")?).ok()?,
        token_digest,
        issued_by: text("issued_by")?.to_owned(),
        issued_at_ms: value.get("issued_at")?.as_u64()?,
        expires_at_ms: value.get("expires_at")?.as_u64()?,
        state: EnrollmentState::parse(text("state")?)?,
        registration,
        registered_at_ms: optional_u64("registered_at")?,
        decided_by: optional_text("decided_by")?,
        decided_at_ms: optional_u64("decided_at")?,
        draft: optional_text("draft")?,
    })
}

// -- The registry ---------------------------------------------------------

/// The journal could not commit a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalError;

/// Where enrollment records are made durable.
pub trait EnrollmentJournal: Send + Sync + fmt::Debug {
    /// Commit `record`. Must be durable before returning.
    fn commit(&self, record: &Enrollment) -> Result<(), JournalError>;
}

/// Why a registry operation was refused. Stable codes; the sentence an
/// operator reads is written by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollError {
    /// No such enrollment.
    Unknown,
    /// The token matched nothing usable. Deliberately one answer for
    /// "never existed", "used", "expired", and "rejected".
    InvalidToken,
    /// Too many failed presentations recently.
    Throttled,
    /// Too many enrollments are open.
    TooMany,
    /// An open or approved enrollment already names this host.
    HostTaken,
    /// The enrollment is not in a state that permits the action.
    WrongState,
    /// The record could not be made durable; nothing changed.
    Journal,
}

impl EnrollError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_enrollment",
            Self::InvalidToken => "invalid_enrollment_token",
            Self::Throttled => "enrollment_throttled",
            Self::TooMany => "too_many_enrollments",
            Self::HostTaken => "enrollment_host_taken",
            Self::WrongState => "enrollment_wrong_state",
            Self::Journal => "enrollment_not_durable",
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    by_id: BTreeMap<String, Enrollment>,
    failures: VecDeque<u64>,
}

/// What [`EnrollmentRegistry::issue`] records.
#[derive(Debug, Clone)]
pub struct NewEnrollment {
    /// Identifier: 16 lowercase hex characters.
    pub id: String,
    /// The host identifier the slave will have.
    pub host: HostId,
    /// The agent that will manage it.
    pub agent: AgentId,
    /// The token's digest ([`token_digest`]).
    pub token_digest: [u8; 32],
    /// Who minted it.
    pub issued_by: String,
    /// Requested lifetime, clamped to [`MIN_TTL_MS`]..=[`MAX_TTL_MS`].
    pub ttl_ms: u64,
}

/// Every enrollment this router knows, behind one lock.
///
/// Each change is built on a copy, committed to the journal, and only then
/// installed — so a failed commit leaves the registry exactly as it was, and
/// a restart replays exactly what callers were told.
#[derive(Debug)]
pub struct EnrollmentRegistry {
    inner: Mutex<Inner>,
    journal: Arc<dyn EnrollmentJournal>,
}

impl EnrollmentRegistry {
    /// An empty registry over `journal`.
    #[must_use]
    pub fn new(journal: Arc<dyn EnrollmentJournal>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            journal,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a panic while holding it; the map is still a
        // consistent set of committed records, because nothing is installed
        // before its commit succeeds.
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adopt a record read back from the log. The last one per id wins.
    pub fn restore(&self, record: Enrollment) {
        let mut inner = self.lock();
        inner.by_id.insert(record.id.clone(), record);
        prune(&mut inner);
    }

    fn commit_locked(&self, inner: &mut Inner, record: Enrollment) -> Result<Enrollment, EnrollError> {
        self.journal.commit(&record).map_err(|_| EnrollError::Journal)?;
        inner.by_id.insert(record.id.clone(), record.clone());
        prune(inner);
        Ok(record)
    }

    /// Record a newly minted token.
    pub fn issue(&self, new: NewEnrollment, now_ms: u64) -> Result<Enrollment, EnrollError> {
        let NewEnrollment {
            id,
            host,
            agent,
            token_digest,
            issued_by,
            ttl_ms,
        } = new;
        let mut inner = self.lock();
        if inner.by_id.values().filter(|e| e.is_open(now_ms)).count() >= MAX_OPEN_ENROLLMENTS {
            return Err(EnrollError::TooMany);
        }
        if inner.by_id.values().any(|e| {
            e.host == host && (e.is_open(now_ms) || e.state == EnrollmentState::Approved)
        }) {
            return Err(EnrollError::HostTaken);
        }
        if inner.by_id.contains_key(&id) {
            return Err(EnrollError::HostTaken);
        }
        let record = Enrollment {
            id,
            host,
            agent,
            token_digest,
            issued_by,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms.clamp(MIN_TTL_MS, MAX_TTL_MS)),
            state: EnrollmentState::Issued,
            registration: None,
            registered_at_ms: None,
            decided_by: None,
            decided_at_ms: None,
            draft: None,
        };
        self.commit_locked(&mut inner, record)
    }

    /// Find the issued, unexpired enrollment a token belongs to.
    ///
    /// Throttled globally rather than per caller: every registration arrives
    /// through the same tailnet proxy, so there is no caller address to key
    /// on, and a 256-bit token is not guessable anyway — the throttle bounds
    /// the work a flood can cause, not the odds of a hit.
    pub fn redeem_peek(&self, token: &str, now_ms: u64) -> Result<Enrollment, EnrollError> {
        let mut inner = self.lock();
        find_issued(&mut inner, token, now_ms).cloned()
    }

    /// Consume a token with the slave's report.
    pub fn register(
        &self,
        token: &str,
        registration: Registration,
        now_ms: u64,
    ) -> Result<Enrollment, EnrollError> {
        let mut inner = self.lock();
        let mut record = find_issued(&mut inner, token, now_ms)?.clone();
        record.state = EnrollmentState::Registered;
        record.registration = Some(registration);
        record.registered_at_ms = Some(now_ms);
        self.commit_locked(&mut inner, record)
    }

    fn transition(
        &self,
        id: &str,
        actor: &str,
        now_ms: u64,
        from: &[EnrollmentState],
        to: EnrollmentState,
        draft: Option<String>,
    ) -> Result<Enrollment, EnrollError> {
        let mut inner = self.lock();
        let current = inner.by_id.get(id).ok_or(EnrollError::Unknown)?;
        if !from.contains(&current.state_at(now_ms)) {
            return Err(EnrollError::WrongState);
        }
        let mut record = current.clone();
        record.state = to;
        record.decided_by = Some(actor.to_owned());
        record.decided_at_ms = Some(now_ms);
        if draft.is_some() {
            record.draft = draft;
        }
        self.commit_locked(&mut inner, record)
    }

    /// Approve a registered slave, recording the draft that adds its records.
    pub fn approve(
        &self,
        id: &str,
        actor: &str,
        now_ms: u64,
        draft: String,
    ) -> Result<Enrollment, EnrollError> {
        self.transition(
            id,
            actor,
            now_ms,
            &[EnrollmentState::Registered],
            EnrollmentState::Approved,
            Some(draft),
        )
    }

    /// Refuse an issued or registered enrollment.
    pub fn reject(&self, id: &str, actor: &str, now_ms: u64) -> Result<Enrollment, EnrollError> {
        self.transition(
            id,
            actor,
            now_ms,
            &[EnrollmentState::Issued, EnrollmentState::Registered],
            EnrollmentState::Rejected,
            None,
        )
    }

    /// Withdraw an approval.
    pub fn revoke(&self, id: &str, actor: &str, now_ms: u64) -> Result<Enrollment, EnrollError> {
        self.transition(
            id,
            actor,
            now_ms,
            &[EnrollmentState::Approved],
            EnrollmentState::Revoked,
            None,
        )
    }

    /// One enrollment.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Enrollment> {
        self.lock().by_id.get(id).cloned()
    }

    /// Every enrollment, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<Enrollment> {
        let mut all: Vec<Enrollment> = self.lock().by_id.values().cloned().collect();
        all.sort_by(|a, b| b.issued_at_ms.cmp(&a.issued_at_ms).then_with(|| a.id.cmp(&b.id)));
        all
    }

    /// Whether any enrollment for `agent` has ever been approved — including
    /// one since revoked, whose withdrawal the agent still has to hear about.
    #[must_use]
    pub fn ever_approved_for(&self, agent: &AgentId) -> bool {
        self.lock().by_id.values().any(|e| {
            &e.agent == agent
                && matches!(e.state, EnrollmentState::Approved | EnrollmentState::Revoked)
        })
    }

    /// Approved enrollments for one agent.
    #[must_use]
    pub fn approved_for(&self, agent: &AgentId) -> Vec<Enrollment> {
        self.lock()
            .by_id
            .values()
            .filter(|e| e.state == EnrollmentState::Approved && &e.agent == agent)
            .cloned()
            .collect()
    }
}

fn find_issued<'a>(inner: &'a mut Inner, token: &str, now_ms: u64) -> Result<&'a Enrollment, EnrollError> {
    while inner
        .failures
        .front()
        .is_some_and(|at| now_ms.saturating_sub(*at) >= THROTTLE_WINDOW_MS)
    {
        inner.failures.pop_front();
    }
    if inner.failures.len() >= MAX_FAILED_ATTEMPTS {
        return Err(EnrollError::Throttled);
    }
    let digest = token_digest(token);
    let found = token_well_formed(token)
        .then(|| {
            inner.by_id.values().find(|e| {
                e.state_at(now_ms) == EnrollmentState::Issued
                    && hypellm_crypto::ct::eq_digest(&e.token_digest, &digest)
            })
        })
        .flatten()
        .map(|e| e.id.clone());
    match found {
        Some(id) => inner.by_id.get(&id).ok_or(EnrollError::InvalidToken),
        None => {
            inner.failures.push_back(now_ms);
            Err(EnrollError::InvalidToken)
        }
    }
}

/// Drop the oldest terminal records past [`MAX_RETAINED_ENROLLMENTS`].
fn prune(inner: &mut Inner) {
    let excess = inner.by_id.len().saturating_sub(MAX_RETAINED_ENROLLMENTS);
    if excess == 0 {
        return;
    }
    let mut terminal: Vec<(u64, String)> = inner
        .by_id
        .values()
        .filter(|e| e.state.is_terminal())
        .map(|e| (e.decided_at_ms.unwrap_or(e.issued_at_ms), e.id.clone()))
        .collect();
    terminal.sort();
    for (_, id) in terminal.into_iter().take(excess) {
        inner.by_id.remove(&id);
    }
}

// -- What is drafted on approval ------------------------------------------

/// The accelerator identifier an approval drafts for GPU `index`.
#[must_use]
pub fn gpu_accelerator_id(host: &HostId, index: u32) -> String {
    format!("{host}-gpu{index}")
}

/// The accelerator identifier an approval drafts for a CPU-only host.
#[must_use]
pub fn cpu_accelerator_id(host: &HostId) -> String {
    format!("{host}-cpu")
}

/// One record an approval drafts: kind, id, and fields.
pub type DraftRecord = (&'static str, String, Vec<(String, String)>);

/// The `host` and `accelerator` records an approval drafts.
///
/// A GPU becomes a `cuda` accelerator with the memory it reported; a machine
/// with none becomes one `cpu` accelerator sized by its RAM. The host is
/// drafted `enabled`, because a draft is reviewed and published by a second
/// person — that publication is the gate, and a host drafted `disabled` would
/// need a second draft to be any use.
#[must_use]
pub fn drafted_records(enrollment: &Enrollment, registration: &Registration) -> Vec<DraftRecord> {
    let mut records = vec![(
        "host",
        enrollment.host.as_str().to_owned(),
        vec![
            ("agent".to_owned(), enrollment.agent.as_str().to_owned()),
            ("arch".to_owned(), registration.arch.as_str().to_owned()),
        ],
    )];
    if registration.gpus.is_empty() {
        records.push((
            "accelerator",
            cpu_accelerator_id(&enrollment.host),
            vec![
                ("host".to_owned(), enrollment.host.as_str().to_owned()),
                ("kind".to_owned(), "cpu".to_owned()),
                ("memory_bytes".to_owned(), registration.memory_bytes.to_string()),
            ],
        ));
    }
    for gpu in &registration.gpus {
        records.push((
            "accelerator",
            gpu_accelerator_id(&enrollment.host, gpu.index),
            vec![
                ("host".to_owned(), enrollment.host.as_str().to_owned()),
                ("kind".to_owned(), "cuda".to_owned()),
                ("memory_bytes".to_owned(), gpu.memory_bytes.to_string()),
            ],
        ));
    }
    records
}

// -- The offer the agent pulls --------------------------------------------

/// One host offered to the fleet agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedHost {
    /// Host identifier.
    pub id: HostId,
    /// Architecture.
    pub arch: Arch,
    /// The pinned LAN address.
    pub address: IpAddr,
    /// The SSH login.
    pub ssh_user: String,
    /// The pinned host key line.
    pub host_key: String,
    /// The slave's data directory.
    pub data_dir: String,
    /// Accelerators, with the GPU index the agent matches `nvidia-smi` rows by.
    pub accelerators: Vec<(AcceleratorId, Option<u32>)>,
}

/// The hosts `agent` should hold by enrollment.
///
/// An approved enrollment is offered only once its host is in the **active**
/// configuration under this agent — that is, once the draft the approval
/// created has been published by a second person. Before then the router does
/// not route to the host, and an agent that held it would only produce a
/// digest mismatch. The accelerators offered are the configuration's, not the
/// registration's, so the agent's table and the router's digest agree on
/// exactly what was published.
#[must_use]
pub fn offer_for_agent(
    enrollments: &[Enrollment],
    fleet: &FleetConfig,
    agent: &AgentId,
) -> Vec<OfferedHost> {
    let mut offered = Vec::new();
    for enrollment in enrollments {
        if offered.len() >= MAX_OFFER_HOSTS {
            break;
        }
        if enrollment.state != EnrollmentState::Approved || &enrollment.agent != agent {
            continue;
        }
        let Some(registration) = &enrollment.registration else {
            continue;
        };
        let Some(host) = fleet.hosts.get(&enrollment.host) else {
            continue;
        };
        if &host.agent != agent {
            continue;
        }
        let prefix = format!("{}-gpu", host.id);
        let accelerators = fleet
            .accelerators
            .values()
            .filter(|a| a.host == host.id)
            .map(|a| {
                let index = a
                    .id
                    .as_str()
                    .strip_prefix(&prefix)
                    .and_then(|n| n.parse::<u32>().ok());
                (a.id.clone(), index)
            })
            .collect();
        offered.push(OfferedHost {
            id: host.id.clone(),
            arch: host.arch,
            address: registration.address,
            ssh_user: registration.ssh_user.clone(),
            host_key: registration.host_key.line(),
            data_dir: registration.data_dir.clone(),
            accelerators,
        });
    }
    offered
}

/// The `ENROLL` payload.
///
/// Returns `None` when it would exceed [`MAX_OFFER_BYTES`], which
/// [`MAX_OFFER_HOSTS`] makes unreachable with valid records; checked anyway,
/// because the agent refuses an oversized payload and the router should not
/// send what it knows will be refused.
#[must_use]
pub fn encode_offer(hosts: &[OfferedHost]) -> Option<Vec<u8>> {
    let items = hosts
        .iter()
        .map(|host| {
            let mut object = Object::new();
            object.push("id", Value::from(host.id.as_str()));
            object.push("arch", Value::from(host.arch.as_str()));
            object.push("address", Value::from(host.address.to_string()));
            object.push("ssh_user", Value::from(host.ssh_user.as_str()));
            object.push("host_key", Value::from(host.host_key.as_str()));
            object.push("data_dir", Value::from(host.data_dir.as_str()));
            object.push(
                "accelerators",
                Value::Array(
                    host.accelerators
                        .iter()
                        .map(|(id, index)| {
                            let mut a = Object::new();
                            a.push("id", Value::from(id.as_str()));
                            a.push_opt("index", index.map(Value::from));
                            Value::Object(a)
                        })
                        .collect(),
                ),
            );
            Value::Object(object)
        })
        .collect();
    let mut root = Object::new();
    root.push("hosts", Value::Array(items));
    let bytes = wire_json::to_vec(&Value::Object(root));
    (bytes.len() <= MAX_OFFER_BYTES).then_some(bytes)
}

/// The digest of an offer, so the router re-sends only when it changed.
#[must_use]
pub fn offer_digest(payload: &[u8]) -> String {
    hypellm_crypto::hex::encode(&hypellm_crypto::sha256::sha256(payload))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]
mod tests {
    use super::*;

    // A real key pair's public halves, generated with ssh-keygen and openssl.
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M host@x";
    const DEVICE_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAX5iBIxDSO2VYlfFZRE/T1VJfwE4OL9kokNcCposqRRI=\n-----END PUBLIC KEY-----\n";

    #[derive(Debug, Default)]
    struct Memory {
        records: Mutex<Vec<Enrollment>>,
        fail: std::sync::atomic::AtomicBool,
    }

    impl EnrollmentJournal for Memory {
        fn commit(&self, record: &Enrollment) -> Result<(), JournalError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(JournalError);
            }
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    fn report() -> Value {
        wire_json::parse_str(
            &format!(
                r#"{{"address":"192.168.1.20","arch":"x86_64","hostname":"spark-1","ssh_user":"albert",
                "data_dir":"/home/albert/.hypellm","memory_bytes":68719476736,
                "gpus":[{{"index":1,"name":"RTX 4090","memory_bytes":25769803776}},{{"index":0,"name":"RTX 4090","memory_bytes":25769803776}}],
                "ssh_host_key":"{HOST_KEY}","device_key":{},"kit_version":"1.0.0"}}"#,
                wire_json::escape_string(DEVICE_KEY)
            ),
            &wire_json::Limits::SMALL,
        )
        .unwrap()
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn registry() -> (Arc<Memory>, EnrollmentRegistry) {
        let journal = Arc::new(Memory::default());
        let registry = EnrollmentRegistry::new(journal.clone());
        registry
            .issue(
                NewEnrollment {
                    id: "00000000000000a1".to_owned(),
                    host: HostId::new("spark-1").unwrap(),
                    agent: AgentId::new("local").unwrap(),
                    token_digest: token_digest(TOKEN),
                    issued_by: "user:admin".to_owned(),
                    ttl_ms: DEFAULT_TTL_MS,
                },
                1_000,
            )
            .unwrap();
        (journal, registry)
    }

    #[test]
    fn keys_are_parsed_structurally_and_fingerprinted_as_ssh_keygen_does() {
        let key = ssh_ed25519_line(HOST_KEY).unwrap();
        // The comment is dropped: it is the key holder's free text.
        assert!(!key.line().contains("host@x"));
        // What `ssh-keygen -lf` printed for this key.
        assert_eq!(key.fingerprint(), "SHA256:PMco07vuSgY4X36KVLs/BWVRspIccQfR8awZG0Yr9OE");
        assert!(device_key_pem(DEVICE_KEY).is_some());

        // Option smuggling, a second key, and the wrong algorithm all fail.
        for bad in [
            "command=\"sh\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M\nssh-rsa AAAA",
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M",
            "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
        ] {
            assert!(ssh_ed25519_line(bad).is_none(), "{bad}");
        }
        assert!(device_key_pem(&DEVICE_KEY.replace("MCowBQYDK2Vw", "MCowBQYDK2Vx")).is_none());
    }

    #[test]
    fn a_registration_refuses_values_that_would_escape_a_file_or_a_shell() {
        assert!(parse_registration(&report()).is_ok());
        for (field, value) in [
            ("data_dir", "relative/path"),
            ("data_dir", "/home/x/../../etc"),
            ("data_dir", "/home/x; rm -rf /"),
            ("ssh_user", "root\nevil"),
            ("ssh_user", "-oProxyCommand=x"),
            ("address", "spark.local"),
            ("address", "0.0.0.0"),
            ("arch", "mips"),
        ] {
            let mut body = report();
            if let Value::Object(object) = &mut body {
                let mut replaced = Object::new();
                for (k, v) in object.iter() {
                    replaced.push(k, if k == field { Value::from(value) } else { v.clone() });
                }
                *object = replaced;
            }
            assert_eq!(
                parse_registration(&body).map(|_| ()).map_err(|e| e.0),
                Err(field),
                "{field}={value:?}"
            );
        }
    }

    #[test]
    fn a_token_is_consumed_by_registering_and_every_spent_token_looks_unknown() {
        let (_, registry) = registry();
        let registration = parse_registration(&report()).unwrap();
        assert!(registry.redeem_peek(TOKEN, 2_000).is_ok(), "peeking does not consume");
        let registered = registry.register(TOKEN, registration.clone(), 2_000).unwrap();
        assert_eq!(registered.state, EnrollmentState::Registered);
        assert_eq!(
            registry.register(TOKEN, registration, 3_000).map(|_| ()),
            Err(EnrollError::InvalidToken),
            "a used token answers exactly like one that never existed"
        );
    }

    #[test]
    fn an_expired_token_is_refused_as_unknown() {
        let (_, registry) = registry();
        let late = 1_000 + DEFAULT_TTL_MS;
        assert_eq!(
            registry.redeem_peek(TOKEN, late).map(|_| ()),
            Err(EnrollError::InvalidToken)
        );
        assert_eq!(registry.list()[0].state_at(late), EnrollmentState::Expired);
    }

    #[test]
    fn failed_presentations_are_throttled_before_a_valid_token_is_honoured() {
        let (_, registry) = registry();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let _ = registry.redeem_peek(&"f".repeat(64), 2_000);
        }
        assert_eq!(
            registry.redeem_peek(TOKEN, 2_000).map(|_| ()),
            Err(EnrollError::Throttled)
        );
        assert!(registry.redeem_peek(TOKEN, 2_000 + THROTTLE_WINDOW_MS).is_ok());
    }

    #[test]
    fn a_failed_commit_changes_nothing() {
        let (journal, registry) = registry();
        journal.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let registration = parse_registration(&report()).unwrap();
        assert_eq!(
            registry.register(TOKEN, registration.clone(), 2_000).map(|_| ()),
            Err(EnrollError::Journal)
        );
        journal.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        // Still issued, so the slave can retry with the same token.
        assert!(registry.register(TOKEN, registration, 2_000).is_ok());
    }

    #[test]
    fn approval_requires_a_registration_and_revocation_requires_an_approval() {
        let (_, registry) = registry();
        let id = "00000000000000a1";
        assert_eq!(
            registry.approve(id, "user:b", 2_000, "d1".to_owned()).map(|_| ()),
            Err(EnrollError::WrongState),
            "an issued token has nothing to approve"
        );
        assert_eq!(registry.revoke(id, "user:b", 2_000).map(|_| ()), Err(EnrollError::WrongState));
        registry
            .register(TOKEN, parse_registration(&report()).unwrap(), 2_000)
            .unwrap();
        assert!(registry.approve(id, "user:b", 3_000, "d1".to_owned()).is_ok());
        assert!(registry.revoke(id, "user:b", 4_000).is_ok());
        assert_eq!(registry.get(id).unwrap().state, EnrollmentState::Revoked);
    }

    #[test]
    fn a_host_cannot_be_enrolled_twice_while_one_is_open_or_approved() {
        let (_, registry) = registry();
        assert_eq!(
            registry
                .issue(
                NewEnrollment {
                    id: "00000000000000a2".to_owned(),
                    host: HostId::new("spark-1").unwrap(),
                    agent: AgentId::new("local").unwrap(),
                    token_digest: token_digest(&"1".repeat(64)),
                    issued_by: "user:admin".to_owned(),
                    ttl_ms: DEFAULT_TTL_MS,
                },
                2_000,
            )
                .map(|_| ()),
            Err(EnrollError::HostTaken)
        );
    }

    #[test]
    fn open_enrollments_are_bounded() {
        let registry = EnrollmentRegistry::new(Arc::new(Memory::default()));
        for n in 0..MAX_OPEN_ENROLLMENTS {
            registry
                .issue(
                NewEnrollment {
                    id: format!("{n:016x}"),
                    host: HostId::new(format!("h{n}")).unwrap(),
                    agent: AgentId::new("local").unwrap(),
                    token_digest: token_digest(&format!("{n:064x}")),
                    issued_by: "a".to_owned(),
                    ttl_ms: DEFAULT_TTL_MS,
                },
                0,
            )
                .unwrap();
        }
        assert_eq!(
            registry
                .issue(
                NewEnrollment {
                    id: "ffffffffffffffff".to_owned(),
                    host: HostId::new("extra").unwrap(),
                    agent: AgentId::new("local").unwrap(),
                    token_digest: token_digest(TOKEN),
                    issued_by: "a".to_owned(),
                    ttl_ms: DEFAULT_TTL_MS,
                },
                0,
            )
                .map(|_| ()),
            Err(EnrollError::TooMany)
        );
    }

    #[test]
    fn a_record_survives_the_log_exactly() {
        let (journal, registry) = registry();
        registry
            .register(TOKEN, parse_registration(&report()).unwrap(), 2_000)
            .unwrap();
        for record in journal.records.lock().unwrap().iter() {
            assert_eq!(decode_enrollment(&encode_enrollment(record)).as_ref(), Some(record));
        }
        let text = String::from_utf8(encode_enrollment(&registry.list()[0])).unwrap();
        assert!(!text.contains(TOKEN), "the token itself is never written");
    }

    #[test]
    fn approval_drafts_one_accelerator_per_gpu_or_one_cpu_accelerator() {
        let (_, registry) = registry();
        let registration = parse_registration(&report()).unwrap();
        let enrollment = registry.register(TOKEN, registration.clone(), 2_000).unwrap();
        let records = drafted_records(&enrollment, &registration);
        let ids: Vec<&str> = records.iter().map(|(_, id, _)| id.as_str()).collect();
        assert_eq!(ids, ["spark-1", "spark-1-gpu0", "spark-1-gpu1"]);

        let cpu = Registration {
            gpus: Vec::new(),
            ..registration
        };
        let records = drafted_records(&enrollment, &cpu);
        assert_eq!(records.len(), 2);
        assert!(records[1].2.contains(&("kind".to_owned(), "cpu".to_owned())));
    }

    #[test]
    fn an_approved_host_is_offered_only_once_its_records_are_published() {
        let (_, registry) = registry();
        let id = "00000000000000a1";
        registry
            .register(TOKEN, parse_registration(&report()).unwrap(), 2_000)
            .unwrap();
        registry.approve(id, "user:b", 3_000, "d1".to_owned()).unwrap();
        let agent = AgentId::new("local").unwrap();
        let empty = FleetConfig::empty();
        assert!(
            offer_for_agent(&registry.approved_for(&agent), &empty, &agent).is_empty(),
            "approved but unpublished: not offered"
        );

        let mut fleet = FleetConfig::empty();
        let host = HostId::new("spark-1").unwrap();
        fleet.hosts.insert(
            host.clone(),
            crate::model::Host {
                id: host.clone(),
                agent: agent.clone(),
                arch: Arch::X86_64,
                state: crate::model::HostState::Enabled,
                reserved_memory_bytes: 0,
                max_concurrent_activations: 1,
            },
        );
        let accelerator = AcceleratorId::new("spark-1-gpu1").unwrap();
        fleet.accelerators.insert(
            accelerator.clone(),
            crate::model::Accelerator {
                id: accelerator.clone(),
                host: host.clone(),
                kind: crate::model::AcceleratorKind::Cuda,
                memory_bytes: 1,
                pool: hypellm_core::ids::PoolId::new("p").unwrap(),
            },
        );
        let offer = offer_for_agent(&registry.approved_for(&agent), &fleet, &agent);
        assert_eq!(offer.len(), 1);
        assert_eq!(offer[0].accelerators, vec![(accelerator, Some(1))]);
        assert!(encode_offer(&offer).is_some());

        registry.revoke(id, "user:b", 4_000).unwrap();
        assert!(offer_for_agent(&registry.approved_for(&agent), &fleet, &agent).is_empty());
    }
}
