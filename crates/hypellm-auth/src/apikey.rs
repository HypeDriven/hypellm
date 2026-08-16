//! Router API keys.
//!
//! Specification 9.2: "256-bit random secret; display once; store keyed digest;
//! prefix identifies key record; scopes, tenant, expiry, IP/workload
//! restrictions."
//!
//! # Shape of a key
//!
//! ```text
//! hypellmk_<key_id>_<secret>
//!   │        │        └── 43 base64url characters = 256 bits
//!   │        └── 16 lowercase hex characters, the record identifier
//!   └── a fixed prefix, so a leaked key is greppable in a repository scan
//! ```
//!
//! The identifier is **hex, not base64url**, because `_` is the field
//! separator and the base64url alphabet contains it. An identifier that could
//! embed a separator would make the split ambiguous, and an ambiguous parse of
//! a credential is exactly the kind of thing that turns into a confusion bug.
//!
//! The **prefix identifies the record**, which is what makes verification a
//! single indexed lookup plus one constant-time comparison rather than a scan
//! over every key. It also means a leaked key can be revoked from its first few
//! characters alone, without the holder having to send the secret.
//!
//! The stored value is `HMAC(server_key, secret)`, not the secret. A database
//! disclosure yields verifier values that cannot be replayed as keys.

use hypellm_core::ids::{KeyId, PrincipalId, TenantId};
use hypellm_core::rbac::{PermissionSet, Role};
use hypellm_crypto::{Digest, base64, ct, hex, hmac_sha256_parts, random};
use core::fmt;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::RwLock;

/// The fixed prefix on every router API key.
pub const KEY_PREFIX: &str = "hypellmk";

/// Characters in the key identifier: 8 random bytes as lowercase hex.
pub const KEY_ID_LEN: usize = 16;

/// Bytes of secret material.
pub const SECRET_BYTES: usize = 32;

/// What a key is allowed to do on the inference path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Chat and responses.
    Inference,
    /// Embeddings.
    Embeddings,
    /// Model discovery.
    Models,
    /// Tokenisation.
    Tokenize,
    /// Read-only management access.
    ManagementRead,
    /// Write management access.
    ManagementWrite,
}

impl Scope {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Embeddings => "embeddings",
            Self::Models => "models",
            Self::Tokenize => "tokenize",
            Self::ManagementRead => "management:read",
            Self::ManagementWrite => "management:write",
        }
    }

    /// Parse from configuration or a stored record.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|x| x.as_str() == s)
    }

    /// Every scope.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Inference,
            Self::Embeddings,
            Self::Models,
            Self::Tokenize,
            Self::ManagementRead,
            Self::ManagementWrite,
        ]
    }

    /// The scope an operation requires.
    #[must_use]
    pub const fn for_operation(op: hypellm_core::canonical::Operation) -> Self {
        use hypellm_core::canonical::Operation as O;
        match op {
            O::Chat | O::Responses | O::Rerank => Self::Inference,
            O::Embeddings => Self::Embeddings,
            O::Tokenize => Self::Tokenize,
        }
    }
}

/// A restriction on where a key may be used from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRestriction {
    /// Usable from anywhere.
    Any,
    /// Usable only from these exact addresses.
    Addresses(Vec<IpAddr>),
    /// Usable only from these CIDR blocks.
    Networks(Vec<(IpAddr, u8)>),
}

impl SourceRestriction {
    /// Whether `addr` is permitted.
    #[must_use]
    pub fn permits(&self, addr: Option<IpAddr>) -> bool {
        match self {
            Self::Any => true,
            Self::Addresses(list) => addr.is_some_and(|a| list.contains(&a)),
            Self::Networks(nets) => {
                // A restricted key with an unknown peer address fails closed:
                // the restriction cannot be evaluated, so it is not satisfied.
                addr.is_some_and(|a| nets.iter().any(|(net, bits)| in_network(a, *net, *bits)))
            }
        }
    }
}

fn in_network(addr: IpAddr, network: IpAddr, prefix_bits: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix_bits > 32 {
                return false;
            }
            let mask = if prefix_bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - u32::from(prefix_bits))
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix_bits > 128 {
                return false;
            }
            let mask = if prefix_bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - u32::from(prefix_bits))
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        // Address families do not match: not in the network.
        _ => false,
    }
}

/// A stored key record. Holds a verifier, never the secret.
///
/// `PartialEq` compares the whole record; the `verifier` field it contains
/// compares in constant time (see [`hypellm_crypto::Digest`]), so this is safe to
/// use against attacker-influenced input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The record identifier, which is the key's prefix.
    pub id: KeyId,
    /// The keyed digest of the secret.
    pub verifier: Digest,
    /// The tenant the key belongs to.
    pub tenant: TenantId,
    /// The principal the key authenticates as.
    pub principal: PrincipalId,
    /// What the key may do.
    pub scopes: Vec<Scope>,
    /// Management roles, for a key used against `/admin/v1`.
    pub roles: Vec<Role>,
    /// Wall-clock expiry in milliseconds, if any.
    pub expires_at_millis: Option<u64>,
    /// Where the key may be used from.
    pub source: SourceRestriction,
    /// When the key was created.
    pub created_at_millis: u64,
    /// A short description.
    pub description: Option<String>,
    /// Whether the key has been revoked.
    pub revoked: bool,
}

impl KeyRecord {
    /// Whether the key carries a scope.
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The permissions this key's roles grant.
    #[must_use]
    pub fn permissions(&self) -> PermissionSet {
        PermissionSet::from_roles(&self.roles)
    }

    /// Whether the key is expired at `now`.
    #[must_use]
    pub fn is_expired(&self, now_wall_millis: u64) -> bool {
        self.expires_at_millis
            .is_some_and(|e| now_wall_millis >= e)
    }
}

/// The secret half of a newly created key.
///
/// Specification 9.2: "display once". The type is not `Clone`, and the value is
/// consumed by [`NewKey::into_secret`] — so a caller has to decide, visibly,
/// where the one copy goes.
pub struct NewKey {
    /// The stored record.
    pub record: KeyRecord,
    secret: String,
}

impl KeyRecord {
    /// Encode for the durable log.
    ///
    /// The record carries the *verifier* — a keyed digest — never the secret,
    /// so a state directory read by an attacker yields nothing that
    /// authenticates without the separate verifier key (specification 9.2).
    ///
    /// Encoding is JSON rather than a packed binary layout because the record
    /// has optional and variable-length fields, and a hand-packed format for
    /// those is where off-by-one parsing bugs live. The store frame already
    /// provides the integrity guarantee.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut object = wire_json::Object::new();
        object.push("id", wire_json::Value::from(self.id.as_str()));
        object.push("verifier", wire_json::Value::from(self.verifier.to_hex().as_str()));
        object.push("tenant", wire_json::Value::from(self.tenant.as_str()));
        object.push("principal", wire_json::Value::from(self.principal.as_str()));
        object.push(
            "scopes",
            wire_json::Value::Array(
                self.scopes.iter().map(|s| wire_json::Value::from(s.as_str())).collect(),
            ),
        );
        object.push(
            "roles",
            wire_json::Value::Array(
                self.roles.iter().map(|r| wire_json::Value::from(r.as_str())).collect(),
            ),
        );
        object.push_opt("expires_at_millis", self.expires_at_millis.map(wire_json::Value::from));
        object.push("source", source_to_json(&self.source));
        object.push("created_at_millis", wire_json::Value::from(self.created_at_millis));
        object.push_opt(
            "description",
            self.description.as_deref().map(wire_json::Value::from),
        );
        object.push("revoked", wire_json::Value::from(self.revoked));
        wire_json::to_string(&wire_json::Value::Object(object)).into_bytes()
    }

    /// Decode a record recovered from the durable log.
    ///
    /// Returns `None` for anything that does not parse. A record that cannot be
    /// read is dropped rather than guessed at: a key whose scopes decoded
    /// partially would authenticate with the wrong authority.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let value = wire_json::parse(payload, &wire_json::Limits::SMALL).ok()?;
        Some(Self {
            id: KeyId::new(value.get("id")?.as_str()?).ok()?,
            verifier: Digest::parse_hex(value.get("verifier")?.as_str()?).ok()?,
            tenant: TenantId::new(value.get("tenant")?.as_str()?).ok()?,
            principal: PrincipalId::new(value.get("principal")?.as_str()?).ok()?,
            scopes: value
                .get("scopes")?
                .as_array()?
                .iter()
                .map(|v| v.as_str().and_then(Scope::parse))
                .collect::<Option<Vec<_>>>()?,
            roles: value
                .get("roles")?
                .as_array()?
                .iter()
                .map(|v| v.as_str().and_then(Role::parse))
                .collect::<Option<Vec<_>>>()?,
            expires_at_millis: value.get("expires_at_millis").and_then(|v| v.as_u64()),
            source: source_from_json(value.get("source")?)?,
            created_at_millis: value.get("created_at_millis")?.as_u64()?,
            description: value
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            revoked: value.get("revoked").and_then(wire_json::Value::as_bool).unwrap_or(false),
        })
    }
}

fn source_to_json(source: &SourceRestriction) -> wire_json::Value {
    let mut object = wire_json::Object::new();
    match source {
        SourceRestriction::Any => object.push("kind", wire_json::Value::from("any")),
        SourceRestriction::Addresses(list) => {
            object.push("kind", wire_json::Value::from("addresses"));
            object.push(
                "values",
                wire_json::Value::Array(
                    list.iter()
                        .map(|a| wire_json::Value::from(a.to_string().as_str()))
                        .collect(),
                ),
            );
        }
        SourceRestriction::Networks(list) => {
            object.push("kind", wire_json::Value::from("networks"));
            object.push(
                "values",
                wire_json::Value::Array(
                    list.iter()
                        .map(|(a, bits)| wire_json::Value::from(format!("{a}/{bits}").as_str()))
                        .collect(),
                ),
            );
        }
    }
    wire_json::Value::Object(object)
}

fn source_from_json(value: &wire_json::Value) -> Option<SourceRestriction> {
    match value.get("kind")?.as_str()? {
        "any" => Some(SourceRestriction::Any),
        "addresses" => {
            let list = value
                .get("values")?
                .as_array()?
                .iter()
                .map(|v| v.as_str()?.parse::<IpAddr>().ok())
                .collect::<Option<Vec<_>>>()?;
            Some(SourceRestriction::Addresses(list))
        }
        "networks" => {
            let list = value
                .get("values")?
                .as_array()?
                .iter()
                .map(|v| {
                    let (addr, bits) = v.as_str()?.split_once('/')?;
                    Some((addr.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(SourceRestriction::Networks(list))
        }
        _ => None,
    }
}

impl fmt::Debug for NewKey {
    /// Redacted. A derived `Debug` here prints the one live copy of the API
    /// key, and specification 17 keeps credentials out of logs entirely — a
    /// single `{new_key:?}` in an error path would publish it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewKey")
            .field("record", &self.record)
            .field("secret", &"[redacted api key]")
            .finish()
    }
}

impl NewKey {
    /// Take the presentable key string. Consumes the value.
    #[must_use]
    pub fn into_secret(self) -> String {
        self.secret
    }

    /// The key identifier, which is safe to log and display.
    #[must_use]
    pub fn id(&self) -> &KeyId {
        &self.record.id
    }
}

/// Why a key could not be created.
#[derive(Debug)]
pub enum KeyCreationError {
    /// The OS entropy source was unavailable.
    ///
    /// Creation fails rather than falling back: a key from a degraded random
    /// source is worse than no key at all.
    Entropy(random::RandomError),
    /// The generated identifier did not satisfy the identifier grammar.
    ///
    /// Unreachable in practice — base64url output is within the permitted
    /// alphabet — but reported rather than panicked on.
    Identifier,
}

impl fmt::Display for KeyCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(e) => write!(f, "cannot create key: {e}"),
            Self::Identifier => f.write_str("generated key identifier was not valid"),
        }
    }
}

impl std::error::Error for KeyCreationError {}

impl From<random::RandomError> for KeyCreationError {
    fn from(e: random::RandomError) -> Self {
        Self::Entropy(e)
    }
}

/// Why a presented key was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRejection {
    /// The string was not shaped like a router key.
    Malformed,
    /// No record matches the prefix.
    UnknownKey,
    /// The secret did not verify.
    BadSecret,
    /// The key was revoked.
    Revoked,
    /// The key has expired.
    Expired,
    /// The key may not be used from this address.
    SourceNotPermitted,
    /// The key lacks the scope the request needs.
    ScopeNotPermitted,
}

impl KeyRejection {
    /// Stable code for metrics and audit records.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed_key",
            Self::UnknownKey => "unknown_key",
            Self::BadSecret => "bad_secret",
            Self::Revoked => "revoked_key",
            Self::Expired => "expired_key",
            Self::SourceNotPermitted => "source_not_permitted",
            Self::ScopeNotPermitted => "scope_not_permitted",
        }
    }

    /// What the caller is told.
    ///
    /// Every rejection except a scope failure reports `unauthenticated`. The
    /// caller learns that the key did not work, not *why* — distinguishing
    /// "unknown key" from "bad secret" tells an attacker when they have found a
    /// valid identifier.
    #[must_use]
    pub const fn client_code(self) -> hypellm_core::error::ErrorCode {
        match self {
            Self::ScopeNotPermitted => hypellm_core::error::ErrorCode::Forbidden,
            _ => hypellm_core::error::ErrorCode::Unauthenticated,
        }
    }
}

impl fmt::Display for KeyRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The key store.
pub struct KeyStore {
    /// The key that turns a secret into a stored verifier.
    verifier_key: Vec<u8>,
    records: RwLock<BTreeMap<KeyId, KeyRecord>>,
}

impl fmt::Debug for KeyStore {
    /// Redacted. The verifier key forges any API key in the store, so it must
    /// never reach a log line; the record count is enough for diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore")
            .field("verifier_key", &"[redacted key material]")
            .field("records", &self.records.read().map(|r| r.len()).unwrap_or(0))
            .finish()
    }
}

impl KeyStore {
    /// Create a store.
    ///
    /// `verifier_key` comes from the platform secret facility. Rotating it
    /// invalidates every stored key, which is the intended behaviour for a
    /// compromise of the state directory.
    #[must_use]
    pub fn new(verifier_key: &[u8]) -> Self {
        Self {
            verifier_key: verifier_key.to_vec(),
            records: RwLock::new(BTreeMap::new()),
        }
    }

    /// Compute the stored verifier for a secret.
    #[must_use]
    pub fn verifier_for(&self, key_id: &KeyId, secret: &[u8]) -> Digest {
        // The key identifier is bound into the digest, so a verifier cannot be
        // moved from one record to another.
        Digest::from_bytes(hmac_sha256_parts(
            &self.verifier_key,
            &[b"hypellm.apikey.v1", key_id.as_str().as_bytes(), secret],
        ))
    }

    /// Insert a record recovered from the store.
    pub fn insert(&self, record: KeyRecord) {
        if let Ok(mut map) = self.records.write() {
            map.insert(record.id.clone(), record);
        }
    }

    /// Fetch a record.
    #[must_use]
    pub fn get(&self, id: &KeyId) -> Option<KeyRecord> {
        self.records.read().ok()?.get(id).cloned()
    }

    /// Every record, for the management listing.
    #[must_use]
    pub fn list(&self) -> Vec<KeyRecord> {
        self.records
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.read().map_or(0, |m| m.len())
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Revoke a key.
    ///
    /// Specification 22.3: "Revoke key id immediately; revocation bypasses
    /// configuration publication delay." Revocation is a direct mutation of the
    /// in-memory record, not a configuration change.
    pub fn revoke(&self, id: &KeyId) -> bool {
        match self.records.write() {
            Ok(mut map) => match map.get_mut(id) {
                Some(record) => {
                    record.revoked = true;
                    true
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Create a new key.
    ///
    /// # Errors
    ///
    /// Fails only if the OS entropy source is unavailable, in which case no key
    /// is produced — a key from a degraded random source would be worse than no
    /// key at all.
    #[allow(clippy::too_many_arguments, reason = "a key record has this many attributes")]
    pub fn create(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
        scopes: Vec<Scope>,
        roles: Vec<Role>,
        expires_at_millis: Option<u64>,
        source: SourceRestriction,
        description: Option<String>,
        now_wall_millis: u64,
    ) -> Result<NewKey, KeyCreationError> {
        let id_bytes = random::bytes::<8>()?;
        let id_text = hex::encode(&id_bytes);
        let key_id = KeyId::new(&id_text).map_err(|_| KeyCreationError::Identifier)?;

        let secret_bytes = random::bytes::<SECRET_BYTES>()?;
        let secret_text = base64::encode_url_nopad(&secret_bytes);

        let record = KeyRecord {
            id: key_id.clone(),
            verifier: self.verifier_for(&key_id, secret_text.as_bytes()),
            tenant,
            principal,
            scopes,
            roles,
            expires_at_millis,
            source,
            created_at_millis: now_wall_millis,
            description,
            revoked: false,
        };
        self.insert(record.clone());

        Ok(NewKey {
            record,
            secret: format!("{KEY_PREFIX}_{key_id}_{secret_text}"),
        })
    }

    /// Verify a presented key.
    ///
    /// The lookup is by prefix and the comparison is constant-time. An unknown
    /// prefix still performs a digest computation, so the two failure paths cost
    /// approximately the same.
    pub fn verify(
        &self,
        presented: &str,
        peer: Option<IpAddr>,
        now_wall_millis: u64,
    ) -> Result<KeyRecord, KeyRejection> {
        let (key_id, secret) = parse_key(presented)?;

        let record = self.get(&key_id);
        let candidate = self.verifier_for(&key_id, secret.as_bytes());

        let Some(record) = record else {
            // Compare against a dummy so that an unknown prefix and a wrong
            // secret take a similar path.
            let dummy = Digest::from_bytes([0u8; 32]);
            let _ = ct::eq(candidate.as_bytes(), dummy.as_bytes());
            return Err(KeyRejection::UnknownKey);
        };

        if !ct::eq(candidate.as_bytes(), record.verifier.as_bytes()) {
            return Err(KeyRejection::BadSecret);
        }
        if record.revoked {
            return Err(KeyRejection::Revoked);
        }
        if record.is_expired(now_wall_millis) {
            return Err(KeyRejection::Expired);
        }
        if !record.source.permits(peer) {
            return Err(KeyRejection::SourceNotPermitted);
        }

        Ok(record)
    }

    /// Verify a key and require a scope.
    pub fn verify_scoped(
        &self,
        presented: &str,
        scope: Scope,
        peer: Option<IpAddr>,
        now_wall_millis: u64,
    ) -> Result<KeyRecord, KeyRejection> {
        let record = self.verify(presented, peer, now_wall_millis)?;
        if !record.has_scope(scope) {
            return Err(KeyRejection::ScopeNotPermitted);
        }
        Ok(record)
    }
}

/// Split a presented key into its identifier and secret.
fn parse_key(presented: &str) -> Result<(KeyId, String), KeyRejection> {
    // Bound the work before doing any of it.
    if presented.len() > 256 {
        return Err(KeyRejection::Malformed);
    }
    let rest = presented
        .strip_prefix(KEY_PREFIX)
        .and_then(|r| r.strip_prefix('_'))
        .ok_or(KeyRejection::Malformed)?;
    let (id_text, secret) = rest.split_once('_').ok_or(KeyRejection::Malformed)?;
    if id_text.len() != KEY_ID_LEN
        || secret.is_empty()
        || !id_text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(KeyRejection::Malformed);
    }
    let key_id = KeyId::new(id_text).map_err(|_| KeyRejection::Malformed)?;
    Ok((key_id, secret.to_owned()))
}

/// Extract a bearer token from an `Authorization` header value.
///
/// Accepts `Bearer <token>` case-insensitively on the scheme, as clients vary.
#[must_use]
pub fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim_start();
    if token.is_empty() { None } else { Some(token) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::canonical::Operation;

    const VERIFIER_KEY: &[u8] = b"api-key-verifier-key-for-tests";
    const NOW: u64 = 1_767_225_600_000;

    fn store() -> KeyStore {
        KeyStore::new(VERIFIER_KEY)
    }

    fn create(store: &KeyStore) -> NewKey {
        store
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:harness").unwrap(),
                vec![Scope::Inference, Scope::Models],
                Vec::new(),
                None,
                SourceRestriction::Any,
                Some("test key".to_owned()),
                NOW,
            )
            .expect("entropy")
    }

    #[test]
    fn a_key_record_round_trips_through_the_durable_encoding() {
        let store = store();
        let new_key = create(&store);
        let record = new_key.record.clone();

        let decoded = KeyRecord::from_payload(&record.to_payload()).expect("decodes");
        assert_eq!(decoded, record);
    }

    #[test]
    fn the_durable_encoding_carries_the_verifier_and_never_the_secret() {
        // Specification 9.2: the stored form authenticates a presented key
        // without being usable as one.
        let store = store();
        let new_key = create(&store);
        let record = new_key.record.clone();
        let secret = new_key.into_secret();

        let payload = record.to_payload();
        let text = String::from_utf8(payload).expect("utf-8");
        assert!(!text.contains(&secret), "the stored record leaked the key secret");
        assert!(text.contains(&record.verifier.to_hex()));
    }

    #[test]
    fn every_source_restriction_shape_round_trips() {
        for source in [
            SourceRestriction::Any,
            SourceRestriction::Addresses(vec![
                "127.0.0.1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ]),
            SourceRestriction::Networks(vec![
                ("10.0.0.0".parse().unwrap(), 8),
                ("2001:db8::".parse().unwrap(), 32),
            ]),
        ] {
            let json = source_to_json(&source);
            assert_eq!(source_from_json(&json), Some(source));
        }
    }

    #[test]
    fn a_revoked_record_stays_revoked_across_the_encoding() {
        let store = store();
        let new_key = create(&store);
        let id = new_key.id().clone();
        assert!(store.revoke(&id));
        let record = store.get(&id).expect("record");
        assert!(record.revoked);

        let decoded = KeyRecord::from_payload(&record.to_payload()).expect("decodes");
        assert!(decoded.revoked, "a revocation must survive a restart");
    }

    #[test]
    fn a_malformed_payload_is_dropped_rather_than_guessed_at() {
        assert!(KeyRecord::from_payload(b"not json").is_none());
        assert!(KeyRecord::from_payload(b"{}").is_none());
        // A record missing its scopes must not decode as a scopeless key.
        assert!(KeyRecord::from_payload(br#"{"id":"abc","verifier":"00"}"#).is_none());
    }

    #[test]
    fn debug_output_never_contains_the_secret_or_the_verifier_key() {
        // Specification 17 keeps credentials out of logs. A derived `Debug` on
        // either type defeats that with one `{:?}` in an error path, and the
        // compiler will not warn about it — so the redaction is asserted here.
        let store = store();
        let new_key = create(&store);

        let rendered = format!("{new_key:?}");
        assert!(!rendered.contains(new_key.secret.as_str()), "NewKey leaked the API key");
        assert!(rendered.contains("[redacted"), "expected a redaction marker: {rendered}");

        let store_rendered = format!("{store:?}");
        assert!(
            !store_rendered.contains(&hex::encode(VERIFIER_KEY)),
            "KeyStore leaked the verifier key"
        );
        assert!(
            !store_rendered.contains(&String::from_utf8_lossy(VERIFIER_KEY).to_string()),
            "KeyStore leaked the verifier key"
        );
        assert!(store_rendered.contains("[redacted"));
    }

    #[test]
    fn a_created_key_verifies() {
        let store = store();
        let new_key = create(&store);
        let id = new_key.id().clone();
        let secret = new_key.into_secret();

        let record = store.verify(&secret, None, NOW).expect("verifies");
        assert_eq!(record.id, id);
        assert_eq!(record.tenant.as_str(), "acme");
        assert_eq!(record.principal.as_str(), "svc:harness");
    }

    #[test]
    fn a_key_looks_like_a_key() {
        let store = store();
        let secret = create(&store).into_secret();
        assert!(secret.starts_with("hypellmk_"));
        // The key has exactly three fields, but only the first two separators
        // are structural: the base64url secret may itself contain `_`, which is
        // why the identifier is hex and the parser splits on the *first*
        // separator after the prefix.
        let parts: Vec<&str> = secret.splitn(3, '_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "hypellmk");
        assert_eq!(parts[1].len(), KEY_ID_LEN);
        assert!(
            parts[1].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "the identifier must be lowercase hex so it cannot contain a separator"
        );
        // 32 bytes base64url without padding is 43 characters.
        assert_eq!(parts[2].len(), 43);
    }

    #[test]
    fn the_store_holds_a_verifier_not_the_secret() {
        let store = store();
        let new_key = create(&store);
        let id = new_key.id().clone();
        let secret = new_key.into_secret();
        let record = store.get(&id).expect("record");

        // The stored value must not contain the secret in any form.
        //
        // The secret's random component is the third `_`-separated field:
        // `{prefix}_{id}_{base64url}`. It must be taken by position, not with
        // `rsplit('_')` — base64url's alphabet includes `_`, so a secret whose
        // random part happened to end in one yielded an empty string, and
        // `contains("")` is always true. That made this test fail roughly once
        // in sixty runs for a reason that had nothing to do with the property
        // under test.
        let stored = record.verifier.to_hex();
        assert!(!stored.contains(&secret));

        let random_part = secret.splitn(3, '_').nth(2).expect("the random component");
        assert!(!random_part.is_empty());
        assert!(!stored.contains(random_part));

        // Also check a substantial slice, so a partial leak is caught too.
        let slice = random_part.get(..16).unwrap_or(random_part);
        assert!(!stored.contains(slice), "the verifier echoes part of the secret");

        // And the verifier alone cannot be replayed as a key.
        assert!(store.verify(&stored, None, NOW).is_err());
    }

    #[test]
    fn keys_are_unique() {
        use std::collections::BTreeSet;
        let store = store();
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            let secret = create(&store).into_secret();
            assert!(seen.insert(secret), "a key was generated twice");
        }
        assert_eq!(store.len(), 64);
    }

    #[test]
    fn a_wrong_secret_is_rejected() {
        let store = store();
        let new_key = create(&store);
        let id = new_key.id().clone();
        let secret = new_key.into_secret();

        // Same identifier, different secret.
        let forged = format!("{KEY_PREFIX}_{id}_{}", "A".repeat(43));
        assert_eq!(
            store.verify(&forged, None, NOW).unwrap_err(),
            KeyRejection::BadSecret
        );
        // The genuine key still works.
        assert!(store.verify(&secret, None, NOW).is_ok());
    }

    #[test]
    fn an_unknown_prefix_is_rejected() {
        let store = store();
        let unknown = format!("{KEY_PREFIX}_{}_{}", "b".repeat(KEY_ID_LEN), "C".repeat(43));
        assert_eq!(
            store.verify(&unknown, None, NOW).unwrap_err(),
            KeyRejection::UnknownKey
        );
    }

    #[test]
    fn an_identifier_can_never_contain_the_separator() {
        // The bug this guards against: a base64url identifier can contain `_`,
        // the field separator, which makes the split ambiguous. Generating many
        // keys exercises the roughly 1-in-32 chance per character that base64url
        // would have produced one.
        let store = store();
        for _ in 0..500 {
            let new_key = create(&store);
            let expected_id = new_key.id().clone();
            let secret = new_key.into_secret();

            let id_field = secret
                .splitn(3, '_')
                .nth(1)
                .expect("three fields");
            assert!(
                !id_field.contains('_'),
                "identifier {id_field} contains the separator"
            );
            assert_eq!(id_field, expected_id.as_str());

            // And the key still verifies, whatever characters the secret drew.
            let record = store
                .verify(&secret, None, NOW)
                .unwrap_or_else(|e| panic!("key {secret} failed to verify: {e}"));
            assert_eq!(record.id, expected_id);
        }
    }

    #[test]
    fn a_non_hex_identifier_is_malformed() {
        let store = store();
        let bad = format!("{KEY_PREFIX}_{}_{}", "Z".repeat(KEY_ID_LEN), "C".repeat(43));
        assert_eq!(
            store.verify(&bad, None, NOW).unwrap_err(),
            KeyRejection::Malformed
        );
        let uppercase = format!("{KEY_PREFIX}_{}_{}", "A".repeat(KEY_ID_LEN), "C".repeat(43));
        assert_eq!(
            store.verify(&uppercase, None, NOW).unwrap_err(),
            KeyRejection::Malformed
        );
    }

    #[test]
    fn malformed_keys_are_rejected_without_a_lookup() {
        let store = store();
        for bad in [
            "",
            "not-a-key",
            "hypellmk",
            "hypellmk_",
            "hypellmk_short_secret",
            "wrongprefix_0123456789abcdef_secret",
            &format!("{KEY_PREFIX}_{}_", "a".repeat(KEY_ID_LEN)),
            &"x".repeat(10_000),
        ] {
            assert_eq!(
                store.verify(bad, None, NOW).unwrap_err(),
                KeyRejection::Malformed,
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn failure_modes_are_indistinguishable_to_the_caller() {
        // An attacker must not learn that a prefix exists.
        assert_eq!(
            KeyRejection::UnknownKey.client_code(),
            KeyRejection::BadSecret.client_code()
        );
        assert_eq!(
            KeyRejection::Revoked.client_code(),
            KeyRejection::Expired.client_code()
        );
        for r in [
            KeyRejection::Malformed,
            KeyRejection::UnknownKey,
            KeyRejection::BadSecret,
            KeyRejection::Revoked,
            KeyRejection::Expired,
            KeyRejection::SourceNotPermitted,
        ] {
            assert_eq!(
                r.client_code(),
                hypellm_core::error::ErrorCode::Unauthenticated,
                "{r} must report as unauthenticated"
            );
        }
        // A scope failure is a different thing: the caller is authenticated.
        assert_eq!(
            KeyRejection::ScopeNotPermitted.client_code(),
            hypellm_core::error::ErrorCode::Forbidden
        );
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let store = store();
        let new_key = create(&store);
        let id = new_key.id().clone();
        let secret = new_key.into_secret();

        assert!(store.verify(&secret, None, NOW).is_ok());
        assert!(store.revoke(&id));
        assert_eq!(
            store.verify(&secret, None, NOW).unwrap_err(),
            KeyRejection::Revoked
        );
        assert!(!store.revoke(&KeyId::new("00000000deadbeef").unwrap()));
    }

    #[test]
    fn expiry_is_enforced() {
        let store = store();
        let new_key = store
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:x").unwrap(),
                vec![Scope::Inference],
                Vec::new(),
                Some(NOW + 1000),
                SourceRestriction::Any,
                None,
                NOW,
            )
            .unwrap();
        let secret = new_key.into_secret();

        assert!(store.verify(&secret, None, NOW).is_ok());
        assert!(store.verify(&secret, None, NOW + 999).is_ok());
        assert_eq!(
            store.verify(&secret, None, NOW + 1000).unwrap_err(),
            KeyRejection::Expired
        );
    }

    #[test]
    fn scopes_are_enforced() {
        let store = store();
        let secret = create(&store).into_secret();

        assert!(store.verify_scoped(&secret, Scope::Inference, None, NOW).is_ok());
        assert!(store.verify_scoped(&secret, Scope::Models, None, NOW).is_ok());
        assert_eq!(
            store
                .verify_scoped(&secret, Scope::Embeddings, None, NOW)
                .unwrap_err(),
            KeyRejection::ScopeNotPermitted
        );
        assert_eq!(
            store
                .verify_scoped(&secret, Scope::ManagementWrite, None, NOW)
                .unwrap_err(),
            KeyRejection::ScopeNotPermitted
        );
    }

    #[test]
    fn operations_map_to_scopes() {
        assert_eq!(Scope::for_operation(Operation::Chat), Scope::Inference);
        assert_eq!(Scope::for_operation(Operation::Responses), Scope::Inference);
        assert_eq!(
            Scope::for_operation(Operation::Embeddings),
            Scope::Embeddings
        );
        assert_eq!(Scope::for_operation(Operation::Tokenize), Scope::Tokenize);
    }

    #[test]
    fn address_restrictions_are_enforced() {
        let store = store();
        let allowed: IpAddr = "10.0.0.5".parse().unwrap();
        let new_key = store
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:x").unwrap(),
                vec![Scope::Inference],
                Vec::new(),
                None,
                SourceRestriction::Addresses(vec![allowed]),
                None,
                NOW,
            )
            .unwrap();
        let secret = new_key.into_secret();

        assert!(store.verify(&secret, Some(allowed), NOW).is_ok());
        assert_eq!(
            store
                .verify(&secret, Some("10.0.0.6".parse().unwrap()), NOW)
                .unwrap_err(),
            KeyRejection::SourceNotPermitted
        );
        // An unknown peer address fails closed against a restricted key.
        assert_eq!(
            store.verify(&secret, None, NOW).unwrap_err(),
            KeyRejection::SourceNotPermitted
        );
    }

    #[test]
    fn network_restrictions_match_cidr_blocks() {
        let net: IpAddr = "10.1.0.0".parse().unwrap();
        let restriction = SourceRestriction::Networks(vec![(net, 16)]);
        assert!(restriction.permits(Some("10.1.0.1".parse().unwrap())));
        assert!(restriction.permits(Some("10.1.255.254".parse().unwrap())));
        assert!(!restriction.permits(Some("10.2.0.1".parse().unwrap())));
        assert!(!restriction.permits(None));

        // A /0 permits everything in the family.
        let any_v4 = SourceRestriction::Networks(vec![("0.0.0.0".parse().unwrap(), 0)]);
        assert!(any_v4.permits(Some("203.0.113.9".parse().unwrap())));
        // But not the other family.
        assert!(!any_v4.permits(Some("::1".parse().unwrap())));

        let v6 = SourceRestriction::Networks(vec![("2001:db8::".parse().unwrap(), 32)]);
        assert!(v6.permits(Some("2001:db8::1".parse().unwrap())));
        assert!(!v6.permits(Some("2001:db9::1".parse().unwrap())));

        // An out-of-range prefix matches nothing rather than panicking.
        let bad = SourceRestriction::Networks(vec![(net, 99)]);
        assert!(!bad.permits(Some("10.1.0.1".parse().unwrap())));
    }

    #[test]
    fn unrestricted_keys_accept_any_source() {
        assert!(SourceRestriction::Any.permits(None));
        assert!(SourceRestriction::Any.permits(Some("1.2.3.4".parse().unwrap())));
    }

    #[test]
    fn a_verifier_cannot_be_moved_between_records() {
        // The key identifier is bound into the digest, so copying a verifier
        // from one record to another does not make the secret work there.
        let store = store();
        let a = KeyId::new("aaaaaaaaaaaaaaaa").unwrap();
        let b = KeyId::new("bbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(
            store.verifier_for(&a, b"same-secret"),
            store.verifier_for(&b, b"same-secret")
        );
    }

    #[test]
    fn a_different_verifier_key_invalidates_every_key() {
        let store = store();
        let secret = create(&store).into_secret();
        let record = store.list().into_iter().next().unwrap();

        let rotated = KeyStore::new(b"a-different-verifier-key");
        rotated.insert(record);
        assert_eq!(
            rotated.verify(&secret, None, NOW).unwrap_err(),
            KeyRejection::BadSecret
        );
    }

    #[test]
    fn roles_resolve_to_permissions() {
        let store = store();
        let new_key = store
            .create(
                TenantId::new("acme").unwrap(),
                PrincipalId::new("svc:ops").unwrap(),
                vec![Scope::ManagementRead],
                vec![Role::Operator],
                None,
                SourceRestriction::Any,
                None,
                NOW,
            )
            .unwrap();
        let permissions = new_key.record.permissions();
        assert!(permissions.has(hypellm_core::rbac::Permission::OperateTargets));
        assert!(!permissions.has(hypellm_core::rbac::Permission::PublishPolicy));
    }

    #[test]
    fn bearer_extraction() {
        assert_eq!(bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("BEARER  abc123"), Some("abc123"));
        assert_eq!(bearer_token("Basic abc123"), None);
        assert_eq!(bearer_token("abc123"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token(""), None);
    }

    #[test]
    fn scope_names_round_trip_and_are_distinct() {
        let mut names: Vec<&str> = Scope::all().iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        for s in Scope::all() {
            assert_eq!(Scope::parse(s.as_str()), Some(*s));
        }
        assert_eq!(Scope::parse("root"), None);
    }
}
