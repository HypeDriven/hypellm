//! The shared router state.
//!
//! Everything a request handler needs, assembled once at startup and shared
//! immutably. The configuration itself lives behind an
//! [`Activatable`](hypellm_store::Activatable), so a reload swaps a pointer
//! without disturbing requests already in flight (specification 11).

use hypellm_auth::{KeyStore, SessionStore, TrustedEdge};
use hypellm_config::ValidatedConfig;
use hypellm_core::admission::AdmissionController;
use hypellm_core::health::HealthRegistry;
use hypellm_core::ids::CredentialRef;
use hypellm_core::netaddr::EgressProfile;
use hypellm_core::time::Clock;
use hypellm_net::Egress;
use hypellm_store::{Activatable, Store};
use hypellm_telemetry::Telemetry;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Narrow a secret file to owner-only access.
///
/// `write_atomic` creates the file with the process umask, which commonly
/// leaves it group- and world-readable. A provider credential — or the store
/// MAC key — sitting at 0644 in the state directory is readable by every
/// account on the host.
#[cfg(unix)]
pub fn restrict_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// No portable equivalent; the caller is expected to secure the directory.
#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Narrow a directory holding secrets to owner-only access.
///
/// A directory the world can list tells an attacker exactly which credentials
/// exist and what they are called, even when each file is unreadable.
#[cfg(unix)]
pub(crate) fn restrict_dir_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// No portable equivalent.
#[cfg(not(unix))]
pub(crate) fn restrict_dir_to_owner(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Provider credentials, held only long enough to build a request header.
///
/// Specification 10: "At rest, secrets use an OS/platform secret facility or an
/// approved external vault accessed through a narrow local agent." This type is
/// the in-process cache in front of that facility, and it never returns a
/// secret through the management API.
///
/// # Where a rotated secret goes
///
/// When a directory is configured, [`CredentialStore::store`] writes the value
/// to `<secrets>/credentials/<reference>` — the same file startup reads — and
/// only then updates the in-memory map. That ordering matters: a rotation that
/// took effect in memory but never reached disk would be silently undone by the
/// next restart, which is the failure specification 22.2's rotation runbook
/// exists to prevent.
///
/// The secret deliberately does **not** go into the append-only log. That log
/// is replicated, backed up, and read by anything holding the state directory;
/// specification 11.2's `CredentialMeta` record says "Never a secret value" for
/// exactly that reason.
/// How long a superseded credential stays usable after a rotation.
///
/// Specification 22.2 step 16: "Activate new reference atomically with bounded
/// overlap." The window exists for one failure — rotating before the provider
/// has activated the new secret — and it is short because that is the only
/// failure it should cover.
pub const CREDENTIAL_OVERLAP_MILLIS: u64 = hypellm_core::OVERLAP_HINT_MILLIS;

pub struct CredentialStore {
    secrets: RwLock<BTreeMap<CredentialRef, Vec<u8>>>,
    /// The superseded secret for a reference, and when it stops being usable.
    ///
    /// # Why this cannot be allowed to hide a bad rotation
    ///
    /// A fallback that quietly serves requests with the old secret turns "the
    /// new one is wrong" into "everything is fine, until the window closes and
    /// everything fails at once, uncorrelated with the rotation that caused
    /// it". That is worse than the hard cutover it replaces.
    ///
    /// So the window is not a grace period, it is a **safety net that reports
    /// itself**: the first request that succeeds with the *new* secret retires
    /// the old one immediately, and any use of the old one is a `critical` log
    /// event and a flag on the credential listing. In a healthy rotation the
    /// overlap is over within one request and nothing is emitted.
    previous: RwLock<BTreeMap<CredentialRef, Superseded>>,
    /// Where secrets are persisted. `None` makes the store in-memory only,
    /// which is what tests use.
    dir: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for CredentialStore {
    /// Redacted. The map values are live provider credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("dir", &self.dir)
            .field(
                "secrets",
                &format_args!(
                    "{} credential(s) [redacted]",
                    self.secrets.read().map(|s| s.len()).unwrap_or(0)
                ),
            )
            .finish()
    }
}

/// A superseded credential inside its overlap window.
struct Superseded {
    secret: Vec<u8>,
    expires_at_millis: u64,
    /// Whether the old secret has actually been used since the rotation.
    used: bool,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            secrets: RwLock::new(BTreeMap::new()),
            previous: RwLock::new(BTreeMap::new()),
            dir: None,
        }
    }
}

impl CredentialStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that persists rotations under `dir`.
    #[must_use]
    pub fn persisting_in(dir: std::path::PathBuf) -> Self {
        Self {
            secrets: RwLock::new(BTreeMap::new()),
            previous: RwLock::new(BTreeMap::new()),
            dir: Some(dir),
        }
    }

    /// Load a secret into memory, replacing any previous value.
    ///
    /// Used at startup for values already on disk. Use
    /// [`CredentialStore::store`] for a value arriving through the management
    /// API, which must be persisted as well.
    pub fn set(&self, reference: &CredentialRef, secret: Vec<u8>) {
        if let Ok(mut map) = self.secrets.write() {
            map.insert(reference.clone(), secret);
        }
    }

    /// Persist a secret and make it live.
    ///
    /// Durable first: a rotation reported as stored but absent from disk would
    /// be undone by the next restart, and the operator would have no signal
    /// until requests started failing.
    ///
    /// # Errors
    ///
    /// Fails if no directory is configured, or if the write does not complete.
    /// Both are reported rather than swallowed — the caller answers the
    /// operator, and telling them a rotation succeeded when it did not is the
    /// one outcome worth avoiding.
    pub fn store(
        &self,
        reference: &CredentialRef,
        secret: Vec<u8>,
        now_millis: u64,
    ) -> std::io::Result<()> {
        let Some(dir) = &self.dir else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no credential directory is configured; this router cannot store credentials",
            ));
        };

        // The same check startup applies. A credential that cannot appear in
        // an authentication header would be stored, reported as rotated, and
        // then silently omitted from every request the adapter built — and one
        // containing CR or LF would inject headers instead.
        if !hypellm_adapters::is_usable_credential(&secret) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the credential contains bytes that cannot appear in an authentication \
                 header (visible ASCII and tab only)",
            ));
        }

        hypellm_store::ensure_dir(dir)?;
        hypellm_store::write_atomic(dir, reference.as_str(), &secret)?;
        restrict_to_owner(&dir.join(reference.as_str()))?;

        self.rotate(reference, secret, now_millis);
        Ok(())
    }

    /// Make `secret` live, keeping the previous value inside its overlap
    /// window.
    ///
    /// Separate from [`CredentialStore::set`], which *loads* a value at
    /// startup: loading is not a rotation and must not open a window, or every
    /// restart would look like one. Separate from
    /// [`CredentialStore::store`] because persistence and activation are
    /// different concerns, and a deployment with no credential directory still
    /// has the second.
    pub fn rotate(&self, reference: &CredentialRef, secret: Vec<u8>, now_millis: u64) {
        // Specification 22.2 step 16's bounded overlap. Captured *before* the
        // new value replaces it, and only when there was a previous value: a
        // first activation is a creation, not a rotation, and has nothing to
        // fall back to.
        if let Some(superseded) = self.with_secret(reference, <[u8]>::to_vec) {
            if let Ok(mut previous) = self.previous.write() {
                previous.insert(
                    reference.clone(),
                    Superseded {
                        secret: superseded,
                        expires_at_millis: now_millis
                            .saturating_add(CREDENTIAL_OVERLAP_MILLIS),
                        used: false,
                    },
                );
            }
        }
        self.set(reference, secret);
    }

    /// Run `f` with the superseded secret, if one is still inside its window.
    ///
    /// The caller is expected to have already failed with the current secret;
    /// this is not a value to reach for first. Using it marks the rotation as
    /// unaccepted, which is what makes the fallback visible instead of silent.
    pub fn with_superseded_secret<R>(
        &self,
        reference: &CredentialRef,
        now_millis: u64,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Option<R> {
        let mut previous = self.previous.write().ok()?;
        let entry = previous.get_mut(reference)?;
        if now_millis >= entry.expires_at_millis {
            previous.remove(reference);
            return None;
        }
        entry.used = true;
        Some(f(&entry.secret))
    }

    /// Retire a superseded secret, because the new one has been accepted.
    ///
    /// Called on the first success with the current secret. In a healthy
    /// rotation this happens on the next request, so the overlap window exists
    /// for one exchange and never reports anything.
    pub fn retire_superseded(&self, reference: &CredentialRef) {
        if let Ok(mut previous) = self.previous.write() {
            previous.remove(reference);
        }
    }

    /// Whether a rotation is still relying on the superseded secret.
    ///
    /// True only once the old value has actually served a request: the
    /// operator is being told "the provider has not accepted your new
    /// credential", which is a different and more urgent fact than "a rotation
    /// happened recently".
    #[must_use]
    pub fn rotation_unaccepted(&self, reference: &CredentialRef, now_millis: u64) -> bool {
        self.previous
            .read()
            .map(|previous| {
                previous
                    .get(reference)
                    .is_some_and(|entry| entry.used && now_millis < entry.expires_at_millis)
            })
            .unwrap_or(false)
    }

    /// Whether this store can persist a rotation at all.
    #[must_use]
    pub const fn can_store(&self) -> bool {
        self.dir.is_some()
    }

    /// Every reference currently loaded, for diagnostics.
    ///
    /// Returns identifiers only. There is no method anywhere that returns a
    /// secret value.
    #[must_use]
    pub fn references(&self) -> Vec<CredentialRef> {
        self.secrets
            .read()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Run `f` with the secret, if it is present.
    ///
    /// A borrow-scoped accessor rather than a getter: the secret never leaves
    /// the store as an owned value, so a caller cannot hold one past the header
    /// construction it was needed for.
    pub fn with_secret<R>(
        &self,
        reference: &CredentialRef,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Option<R> {
        let map = self.secrets.read().ok()?;
        map.get(reference).map(|secret| f(secret))
    }

    /// Whether a reference resolves.
    #[must_use]
    pub fn contains(&self, reference: &CredentialRef) -> bool {
        self.secrets
            .read()
            .map(|m| m.contains_key(reference))
            .unwrap_or(false)
    }

    /// Remove a credential from memory, for revocation.
    pub fn remove(&self, reference: &CredentialRef) -> bool {
        self.secrets
            .write()
            .map(|mut m| m.remove(reference).is_some())
            .unwrap_or(false)
    }

    /// How many credentials are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.read().map_or(0, |m| m.len())
    }

    /// Whether no credentials are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The management API's write-only view of the credential store.
///
/// Specification 15.3 makes credential values "write-only" and specification 5
/// says the secret is "never returned through management API". The trait has no
/// read method, so that is a property of the interface rather than a rule a
/// future handler has to remember.
/// The management plane's view of credential storage.
///
/// Bundles the store with the connection pool because rotating a credential and
/// draining the connections opened under it are one operation from the
/// management API's point of view — and that API cannot reach either directly:
/// specification 3 keeps the management path out of the data path, and
/// `hypellm-admin-api` has no network access at all.
#[derive(Debug)]
pub struct CredentialSinkAdapter {
    router: Arc<RouterState>,
}

impl CredentialSinkAdapter {
    /// View the router's credential store and connection pool as one sink.
    ///
    /// Holds the router state rather than its two parts because the pool lives
    /// inside `Egress`, which is owned by value; reaching it through the shared
    /// state avoids restructuring the data plane to serve a management
    /// operation. No cycle: `AdminState` points at this, this points at
    /// `RouterState`, and `RouterState` points at neither.
    #[must_use]
    pub const fn new(router: Arc<RouterState>) -> Self {
        Self { router }
    }
}

impl hypellm_admin_api::CredentialSink for CredentialSinkAdapter {
    fn store(&self, reference: &CredentialRef, secret: Vec<u8>) -> Result<(), String> {
        CredentialStore::store(
            &self.router.credentials,
            reference,
            secret,
            self.router.clock.wall_millis(),
        )
            .map_err(|e| e.to_string())
    }

    fn contains(&self, reference: &CredentialRef) -> bool {
        CredentialStore::contains(&self.router.credentials, reference)
    }

    fn rotation_unaccepted(&self, reference: &CredentialRef, now_millis: u64) -> bool {
        CredentialStore::rotation_unaccepted(&self.router.credentials, reference, now_millis)
    }

    fn probe(
        &self,
        reference: &CredentialRef,
    ) -> Option<hypellm_admin_api::ProbeOutcome> {
        probe_credential(&self.router, reference)
    }

    fn drain_connections(&self, reference: &CredentialRef) -> usize {
        // The credential class is one `|`-separated component of the pool key,
        // and is itself `{len}:{tenant}:{len}:{reference}`. Matching on the
        // length-prefixed reference at the end of that component drains every
        // tenant's sockets for this credential without matching a different
        // credential whose name merely ends the same way.
        let suffix = format!(":{}:{}", reference.as_str().len(), reference.as_str());
        self.router.egress.pool.drain_where(|key| {
            key.split('|')
                .nth(3)
                .is_some_and(|class| class.ends_with(&suffix))
        })
    }
}

impl hypellm_admin_api::CredentialSink for CredentialStore {
    fn store(&self, reference: &CredentialRef, secret: Vec<u8>) -> Result<(), String> {
        // No clock on the bare store, so no overlap window: this impl exists
        // for a deployment without a data path, where there are no upstream
        // requests to fall back for.
        Self::store(self, reference, secret, 0).map_err(|e| e.to_string())
    }

    fn contains(&self, reference: &CredentialRef) -> bool {
        Self::contains(self, reference)
    }
}

/// The router's shared state.
///
/// The components the management plane also needs are held behind `Arc` so
/// that both planes observe the same configuration pointer, the same key
/// store, and the same audit chain. Specification 3 separates the two paths in
/// code and scheduling — not in what they are looking at, which must be one
/// truth or an operator's change would apply to only one of them.
#[derive(Debug)]
pub struct RouterState {
    /// The active configuration. Swapped atomically on reload.
    pub config: Arc<Activatable<ValidatedConfig>>,
    /// API keys.
    pub keys: Arc<KeyStore>,
    /// Management sessions.
    pub sessions: Arc<SessionStore>,
    /// Provider credentials.
    pub credentials: Arc<CredentialStore>,
    /// Target health and circuit breakers.
    pub health: Arc<HealthRegistry>,
    /// Admission control.
    ///
    /// Behind an `Arc` because the management plane reports occupancy against
    /// these limits on `GET /admin/v1/traffic`, and a capacity panel built from
    /// a copy of the limits would show the configured ceiling beside an
    /// occupancy that some other controller was counting.
    pub admission: Arc<AdmissionController>,
    /// Outbound networking.
    pub egress: Egress,
    /// Metrics and logs.
    pub telemetry: Arc<Telemetry>,
    /// Durable state.
    pub store: Arc<Store>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The forwarded-identity policy.
    pub trusted_edge: TrustedEdge,
    /// Whether the inference listener serves a request that presents no
    /// credential, as the configured anonymous subject.
    ///
    /// Runtime state, shared with the management plane, and deliberately *not*
    /// part of `config`. A deployment declares who an anonymous caller would be
    /// in the configuration document; only `POST /admin/v1/settings/anonymous`
    /// decides whether one is served. Editing a file cannot open the router,
    /// and the state survives a restart because every change is a
    /// `RecordKind::AnonymousAccess` frame replayed at startup.
    ///
    /// `false` on a router that has never been told otherwise, including one
    /// whose log is empty or truncated past the last such frame.
    pub anonymous_access: Arc<std::sync::atomic::AtomicBool>,
    /// Recent decision traces, shared with the management plane.
    pub decisions: Arc<hypellm_admin_api::DecisionCache>,
    /// Usage aggregates, shared with the management plane.
    pub usage: Arc<hypellm_admin_api::UsageAggregate>,
    /// The rolling rate and latency window, shared with the management plane.
    ///
    /// Written once per completed request in `pipeline::record_completion` and
    /// read by `GET /admin/v1/traffic`. The metric registry cannot answer for
    /// it: its counters are cumulative since start, and specification 15.3 asks
    /// the overview for a *rate*.
    pub traffic: Arc<hypellm_admin_api::TrafficWindow>,
    /// Fleet orchestration, when a fleet is declared and enabled.
    ///
    /// Unset is not a degraded mode. A router with no fleet classifies every
    /// target `Unmanaged`, which sits at the top of the warmth ladder, so
    /// routing is byte-identical to what it was before orchestration existed.
    ///
    /// A `OnceLock` because the runtime is built *after* the state it shares —
    /// it needs the same store, clock, and telemetry — and must then be visible
    /// to every holder of the `Arc`. Set exactly once at startup, and never
    /// replaced: a configuration reload swaps the fleet *inside* the runtime
    /// through `FleetRuntime::adopt_fleet`, so in-flight activations keep the
    /// ledger that authorised them.
    pub fleet: std::sync::OnceLock<Arc<crate::fleet::FleetRuntime>>,
}

impl RouterState {
    /// The fleet runtime, if one was configured.
    #[must_use]
    pub fn fleet(&self) -> Option<&Arc<crate::fleet::FleetRuntime>> {
        self.fleet.get()
    }

    /// A fleet view for one routing decision, or an empty one.
    ///
    /// Computed once per request, before routing, and borrowed by
    /// [`crate::fleet::FleetAwareLiveState`] for the whole decision. Sampling
    /// twice would let a target be filtered under one belief and ranked under
    /// another, which is exactly the determinism Appendix B requires once fleet
    /// state is live state.
    #[must_use]
    pub fn fleet_view(
        &self,
        request: &hypellm_core::canonical::CanonicalRequest,
        permissions: &hypellm_core::rbac::PermissionSet,
    ) -> crate::fleet::FleetView {
        let Some(fleet) = self.fleet() else {
            return crate::fleet::FleetView::default();
        };
        let config = self.config();
        let snapshot = &config.snapshot;
        let Some(alias) = snapshot.aliases.get(&request.requested_model) else {
            return crate::fleet::FleetView::default();
        };
        if let Some(capability) = alias.capability {
            fleet.record_request(capability);
        }

        // The effort multiplier used for the feasibility check is the *largest*
        // any permitted target declares. Using a specific target's would mean
        // classifying each one against a different deadline, and the check must
        // be conservative: a cold target offered on the strength of a cheap
        // multiplier and then dispatched under an expensive one would miss its
        // deadline after paying for an eviction.
        let multiplier = alias
            .permitted_targets
            .iter()
            .filter_map(|t| snapshot.targets.get(t))
            .map(|t| {
                t.capabilities
                    .effort_multipliers
                    .for_effort(request.reasoning_effort)
            })
            .max()
            .unwrap_or(1);

        let remaining = request
            .limits
            .deadline
            .remaining(self.clock.as_ref())
            .as_millis();
        let remaining_ms = u64::try_from(remaining).unwrap_or(u64::MAX);

        let context = hypellm_fleet::plan::PlanContext {
            now_ms: fleet.now_ms(),
            deadline_remaining_ms: remaining_ms,
            effort_multiplier: multiplier,
            effort_headroom_ms: snapshot.activation_effort_headroom_ms,
            may_activate: permissions.has(hypellm_core::rbac::Permission::FleetActivate),
            may_fetch: permissions.has(hypellm_core::rbac::Permission::FleetFetch),
            capability: alias.capability,
            // Tenant priority would enter here. It is zero until a tenant
            // priority class exists to read: a bonus derived from nothing would
            // be a number in a trace that means nothing.
            priority_bonus: 0,
        };
        let mut view = fleet.view_for(&alias.permitted_targets, &context);
        for target in &alias.permitted_targets {
            let in_flight = self
                .health
                .entry(target, request.operation)
                .in_flight();
            fleet.mark_busy(&mut view, target, in_flight);
        }
        view
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> Arc<ValidatedConfig> {
        self.config.load()
    }

    /// The egress profile for a provider, defaulting to the most restrictive.
    ///
    /// An unknown provider gets [`EgressProfile::NONE`]: a configuration that
    /// somehow references a provider with no profile must not fall back to a
    /// permissive one.
    #[must_use]
    pub fn egress_profile(&self, provider: &hypellm_core::ids::ProviderId) -> EgressProfile {
        self.config()
            .egress_profiles
            .get(provider)
            .copied()
            .unwrap_or(EgressProfile::NONE)
    }

    /// The credential isolation class for a tenant and provider.
    ///
    /// Specification 19 keys connection pools partly on this, so that two
    /// tenants using different credentials never share a socket.
    #[must_use]
    pub fn credential_class(
        &self,
        tenant: &hypellm_core::ids::TenantId,
        credential: Option<&CredentialRef>,
    ) -> String {
        credential_class(tenant, credential)
    }
}

/// Issue specification 22.2 step 15's low-cost probe for `reference`.
///
/// Picks the cheapest *enabled* target whose provider uses this credential and
/// sends the smallest request that operation admits — a one-token completion,
/// or a single short embedding — through the ordinary adapter and dispatch
/// path. Going through the real path is the point: a probe that used a special
/// code path would validate the special code path.
///
/// It deliberately does **not** reserve admission capacity. A probe is an
/// operator action on the management plane, not tenant traffic, and charging it
/// to the tenant's quota would let a rotation check push a real request out.
/// The cost is bounded instead by what it sends: one target, one attempt, a
/// short deadline, and no failover.
///
/// Returns `None` when nothing can be probed, which the handler reports as such
/// rather than as a pass.
fn probe_credential(
    router: &Arc<RouterState>,
    reference: &CredentialRef,
) -> Option<hypellm_admin_api::ProbeOutcome> {
    use hypellm_core::canonical::{
        ClientProtocol, Message, Operation, RequestLimits, Role, Sampling, StreamOptions,
    };

    let config = router.config();
    // Cheapest first, so a probe costs as little as the deployment allows.
    let mut candidates: Vec<&hypellm_core::target::Target> = config
        .snapshot
        .targets
        .values()
        .filter(|target| {
            config
                .snapshot
                .providers
                .get(&target.provider_id)
                .is_some_and(|p| p.credential_ref.as_ref() == Some(reference))
        })
        .filter(|target| target.admin_state == hypellm_core::target::AdminState::Enabled)
        .collect();
    candidates.sort_by_key(|t| (t.cost_class.0, t.id.as_str().to_owned()));

    let target = candidates.first().copied()?;
    let provider = config.snapshot.providers.get(&target.provider_id)?;
    let operation = if target.capabilities.operations.contains(&Operation::Chat) {
        Operation::Chat
    } else if target.capabilities.operations.contains(&Operation::Embeddings) {
        Operation::Embeddings
    } else {
        // Nothing this router knows how to construct a minimal request for.
        return None;
    };

    let clock = router.clock.as_ref();
    let deadline = hypellm_core::time::Deadline::after(clock, PROBE_TIMEOUT);
    let request = hypellm_core::canonical::CanonicalRequest {
        request_id: hypellm_core::ids::RequestId::from_u128(
            hypellm_crypto::random::u128_value().ok()?,
        ),
        tenant: config.tenants.keys().next()?.clone(),
        principal: hypellm_core::ids::PrincipalId::new("router:probe").ok()?,
        protocol: ClientProtocol::OpenAiChat,
        operation,
        requested_model: config.snapshot.aliases.keys().next()?.clone(),
        messages: if operation == Operation::Chat {
            vec![Message::text(Role::User, "ping")]
        } else {
            Vec::new()
        },
        inputs: if operation == Operation::Embeddings {
            vec!["ping".to_owned()]
        } else {
            Vec::new()
        },
        tools: Vec::new(),
        tool_choice: None,
        response_format: None,
        sampling: Sampling::default(),
        reasoning_effort: Default::default(),
        limits: RequestLimits {
            // One token: enough to prove the credential was accepted, and as
            // close to free as the provider's billing allows.
            max_output_tokens: Some(1),
            deadline,
            max_cost_class: None,
            min_quality_class: None,
            residency: None,
        },
        stream: StreamOptions::default(),
        hints: hypellm_core::canonical::RoutingHints::default(),
    };

    let started = clock.now_millis();
    let adapter = hypellm_adapters::adapter_for(provider.family);
    let mut sink = crate::dispatch::AccumulatingSink::default();
    let result = crate::dispatch::attempt(
        router,
        &request,
        target,
        provider,
        adapter,
        deadline,
        &mut sink,
    );
    let millis = clock.now_millis().saturating_sub(started);

    Some(match result {
        Ok(_) => hypellm_admin_api::ProbeOutcome {
            ok: true,
            target: target.id.as_str().to_owned(),
            class: None,
            provider_code: None,
            millis,
        },
        Err(failure) => hypellm_admin_api::ProbeOutcome {
            ok: false,
            target: target.id.as_str().to_owned(),
            class: Some(failure.class.as_str().to_owned()),
            // The narrowed code only. The provider's *message* never crosses
            // into a management response (specification 10).
            provider_code: failure.provider_code.clone(),
            millis,
        },
    })
}

/// How long a probe may take.
///
/// Short: an operator is waiting on the response, and a probe that hangs is
/// worse than one that fails, because it tells them nothing either way.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The pool-key component that keeps two tenants off one socket.
///
/// Length-prefixed, not delimited. `:` is a legal identifier character
/// (`hypellm_core::ids::validate`), so `format!("{tenant}:{reference}")` is
/// ambiguous: tenant `a:b` with credential `c` and tenant `a` with credential
/// `b:c` produce the same class, and two tenants that must never share a pooled
/// connection then do (specification 19, "no cross-tenant reuse where auth
/// binding is unsafe").
///
/// A length prefix has no such collision: the byte count is not drawn from the
/// alphabet it is counting, so exactly one split of the string is consistent
/// with it. Identifiers come from operator configuration rather than from
/// callers, which bounds the exposure — but a configuration mistake should not
/// be able to merge two tenants' connection pools.
///
/// A free function rather than a method because it depends on nothing but its
/// arguments, and a test for it should not have to assemble a router.
#[must_use]
pub fn credential_class(
    tenant: &hypellm_core::ids::TenantId,
    credential: Option<&CredentialRef>,
) -> String {
    let tenant = tenant.as_str();
    match credential {
        Some(reference) => {
            let reference = reference.as_str();
            format!("{}:{tenant}:{}:{reference}", tenant.len(), reference.len())
        }
        None => format!("{}:{tenant}:0:", tenant.len()),
    }
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
    #[test]
    fn a_rotation_keeps_the_previous_secret_for_a_bounded_window() {
        // Specification 22.2 step 16: "Activate new reference atomically with
        // bounded overlap." Without it a rotation performed before the provider
        // activated the new secret took the target out of service until
        // somebody noticed.
        let dir = hypellm_store::TempDir::new("credential-overlap");
        let store = CredentialStore::persisting_in(dir.path().to_path_buf());
        let reference = CredentialRef::new("cred").expect("reference");

        // A first store is a *creation*, not a rotation: there is nothing to
        // fall back to and no window is opened.
        store.store(&reference, b"first".to_vec(), 0).expect("store");
        assert!(
            store
                .with_superseded_secret(&reference, 1, <[u8]>::to_vec)
                .is_none(),
            "a creation must not open an overlap window"
        );

        // A rotation opens one.
        store.store(&reference, b"second".to_vec(), 1_000).expect("rotate");
        assert_eq!(
            store.with_secret(&reference, <[u8]>::to_vec),
            Some(b"second".to_vec())
        );
        assert_eq!(
            store.with_superseded_secret(&reference, 1_001, <[u8]>::to_vec),
            Some(b"first".to_vec())
        );

        // Using it is *reported*, because a fallback that works quietly is how
        // a bad rotation stays invisible until the window closes.
        assert!(store.rotation_unaccepted(&reference, 1_002));

        // Bounded: past the window the old secret is gone whatever happens.
        let past = 1_000 + CREDENTIAL_OVERLAP_MILLIS + 1;
        assert!(
            store
                .with_superseded_secret(&reference, past, <[u8]>::to_vec)
                .is_none()
        );
        assert!(!store.rotation_unaccepted(&reference, past));
    }

    #[test]
    fn an_unused_overlap_window_reports_nothing() {
        // The healthy case, and the reason `rotation_unaccepted` keys on *use*
        // rather than on the window existing: a rotation that the provider
        // accepted must not raise an alarm just for having happened.
        let dir = hypellm_store::TempDir::new("credential-overlap-quiet");
        let store = CredentialStore::persisting_in(dir.path().to_path_buf());
        let reference = CredentialRef::new("cred").expect("reference");

        store.store(&reference, b"first".to_vec(), 0).expect("store");
        store.store(&reference, b"second".to_vec(), 1_000).expect("rotate");
        assert!(
            !store.rotation_unaccepted(&reference, 1_001),
            "an unused window must not report a problem"
        );

        // And a success with the new secret retires it at once, so the window
        // lasts one request rather than its full duration.
        store.retire_superseded(&reference);
        assert!(
            store
                .with_superseded_secret(&reference, 1_002, <[u8]>::to_vec)
                .is_none()
        );
    }


    use super::*;

    fn reference(name: &str) -> CredentialRef {
        CredentialRef::new(name).expect("valid identifier")
    }

    #[test]
    fn a_secret_is_reachable_only_through_a_scoped_borrow() {
        let store = CredentialStore::new();
        let key = reference("cred_openai");
        store.set(&key, b"sk-live-secret".to_vec());

        let length = store.with_secret(&key, <[u8]>::len).expect("present");
        assert_eq!(length, 14);
        assert!(store.contains(&key));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_stored_credential_is_written_where_startup_reads_it() {
        // The management API previously validated the secret's presence,
        // discarded it, and replied `stored: true`. An operator following the
        // rotation runbook was told the credential was in place while the
        // router still held the old one.
        let dir = hypellm_store::TempDir::new("credential-store");
        let store = CredentialStore::persisting_in(dir.path().to_path_buf());
        let key = reference("cred_openai");

        store.store(&key, b"sk-new-secret".to_vec(), 0).expect("stores");

        // Live immediately...
        assert!(store.contains(&key));
        // ...and on disk, under the name startup looks for.
        let written = std::fs::read(dir.path().join("cred_openai")).expect("file exists");
        assert_eq!(written, b"sk-new-secret");
    }

    #[cfg(unix)]
    #[test]
    fn a_stored_credential_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = hypellm_store::TempDir::new("credential-permissions");
        let store = CredentialStore::persisting_in(dir.path().to_path_buf());
        let key = reference("cred_openai");
        store.store(&key, b"sk-new-secret".to_vec(), 0).expect("stores");

        let mode = std::fs::metadata(dir.path().join("cred_openai"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the credential is readable beyond its owner");
    }

    #[test]
    fn a_store_with_nowhere_to_write_refuses_rather_than_pretending() {
        // Reporting a rotation that did not happen is the failure this whole
        // path exists to prevent.
        let store = CredentialStore::new();
        let error = store
            .store(&reference("cred_openai"), b"sk".to_vec(), 0)
            .expect_err("must refuse");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(!store.contains(&reference("cred_openai")));
    }

    #[test]
    fn debug_output_never_contains_a_credential() {
        let store = CredentialStore::new();
        store.set(&reference("cred_openai"), b"sk-live-secret".to_vec());
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("sk-live-secret"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn an_absent_credential_yields_nothing() {
        let store = CredentialStore::new();
        assert!(store.is_empty());
        assert_eq!(store.with_secret(&reference("missing"), |_| ()), None);
        assert!(!store.contains(&reference("missing")));
    }

    #[test]
    fn setting_replaces_and_removing_revokes() {
        let store = CredentialStore::new();
        let key = reference("cred");
        store.set(&key, b"first".to_vec());
        store.set(&key, b"second".to_vec());
        assert_eq!(
            store.with_secret(&key, |s| s.to_vec()).expect("present"),
            b"second"
        );

        assert!(store.remove(&key));
        assert!(!store.contains(&key));
        assert!(!store.remove(&key), "already removed");
    }

    #[test]
    fn the_debug_rendering_does_not_disclose_a_secret() {
        let store = CredentialStore::new();
        store.set(&reference("cred"), b"sk-live-super-secret".to_vec());
        // The map holds raw bytes, so Debug renders them as numbers rather than
        // text; assert on the readable form a log would actually contain.
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("sk-live-super-secret"));
    }

    #[test]
    fn credential_classes_separate_tenants_and_credentials() {
        // The pool-key component that stops cross-tenant connection reuse.
        //
        // This used to reconstruct the format inline and compare the strings it
        // had just built, so it passed whatever `credential_class` did. It now
        // calls the real function, which is the only version of this test that
        // could ever have failed.
        let class = |tenant: &str, credential: Option<&str>| {
            super::credential_class(
                &hypellm_core::ids::TenantId::new(tenant).expect("tenant"),
                credential
                    .map(|c| CredentialRef::new(c).expect("credential"))
                    .as_ref(),
            )
        };

        assert_ne!(class("tenant-a", Some("cred-1")), class("tenant-b", Some("cred-1")));
        assert_ne!(class("tenant-a", Some("cred-1")), class("tenant-a", Some("cred-2")));
        assert_ne!(class("tenant-a", None), class("tenant-b", None));
        assert_ne!(class("tenant-a", None), class("tenant-a", Some("cred-1")));

        // The collision the length prefix exists to prevent: `:` is a legal
        // identifier character, so a delimited encoding maps these two to the
        // same class and lets two tenants share a pooled socket.
        assert_ne!(class("a:b", Some("c")), class("a", Some("b:c")));
    }
}
