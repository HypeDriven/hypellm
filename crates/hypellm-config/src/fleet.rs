//! Building and validating the fleet configuration.
//!
//! Specification-extension 13 adds six record types to the specification 11.1
//! grammar. No new syntax: the same `type key=value` records, the same
//! JSON-style quoted strings, the same `#` comments, unknown fields still
//! errors, still no includes, environment expansion, or templates.
//!
//! # Validation is off-path and fails closed
//!
//! Every rule here rejects a configuration that would produce a bad decision
//! *later*, when the cost is minutes of fleet time rather than a refused
//! reload:
//!
//! - a deployment whose memory exceeds its pool can never be placed, so it is
//!   an activation that will always fail after paying for an eviction;
//! - an artifact whose architecture mismatches its host is a download that
//!   cannot run when it finishes;
//! - two deployments for one target make "which is resident" ambiguous, and
//!   the planner would answer it by map order;
//! - a dangling reference is a plan step naming something the agent will
//!   refuse, discovered after the lease is written.

use crate::parse::{Document, Position};
use crate::schema::{ConfigError, Fields};
use hypellm_core::ids::{
    AcceleratorId, AgentId, ArtifactId, DeploymentId, HostId, PoolId, TargetId,
};
use hypellm_core::target::Target;
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Artifact, ArtifactKind, Deployment, FleetAgent,
    FleetConfig, FleetPolicy, Host, HostState, Readiness,
};
use std::collections::{BTreeMap, BTreeSet};

/// Read a field and construct a validated identifier from it.
macro_rules! fleet_id {
    ($fields:expr, $key:expr, $ty:ty) => {{
        let raw = $fields.str_field($key)?;
        <$ty>::new(raw).map_err(|e| {
            $fields.error(
                "invalid_identifier",
                format!("field '{}' value '{}' is invalid: {}", $key, raw, e),
            )
        })
    }};
}

/// Build the fleet configuration from a parsed document.
///
/// `targets` is the already-validated target map, so a deployment naming a
/// target that does not exist is caught here rather than at the agent.
/// `enabled` comes from `settings fleet_enabled=`, and deliberately does *not*
/// gate validation: a fleet can be written, checked with `--check`, and
/// reviewed before it is switched on.
pub fn build_fleet(
    document: &Document,
    targets: &BTreeMap<TargetId, Target>,
    enabled: bool,
    errors: &mut Vec<ConfigError>,
) -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = enabled;

    // -- Agents -----------------------------------------------------------
    for record in document.of_kind("fleet_agent") {
        let f = Fields::new(record);
        match build_agent(&f) {
            Ok(agent) => {
                if fleet.agents.contains_key(&agent.id) {
                    errors.push(ConfigError::new(
                        "duplicate_id",
                        format!("duplicate fleet_agent '{}'", agent.id),
                        f.position(),
                    ));
                    continue;
                }
                fleet.agents.insert(agent.id.clone(), agent);
            }
            Err(e) => errors.push(e),
        }
    }

    // -- Hosts ------------------------------------------------------------
    for record in document.of_kind("host") {
        let f = Fields::new(record);
        match build_host(&f) {
            Ok(host) => {
                if fleet.hosts.contains_key(&host.id) {
                    errors.push(ConfigError::new(
                        "duplicate_id",
                        format!("duplicate host '{}'", host.id),
                        f.position(),
                    ));
                    continue;
                }
                if !fleet.agents.contains_key(&host.agent) {
                    errors.push(ConfigError::new(
                        "unresolved_reference",
                        format!(
                            "host '{}' names fleet_agent '{}', which is not defined",
                            host.id, host.agent
                        ),
                        f.position(),
                    ));
                    continue;
                }
                fleet.hosts.insert(host.id.clone(), host);
            }
            Err(e) => errors.push(e),
        }
    }

    // -- Accelerators -----------------------------------------------------
    for record in document.of_kind("accelerator") {
        let f = Fields::new(record);
        match build_accelerator(&f) {
            Ok(accelerator) => {
                if fleet.accelerators.contains_key(&accelerator.id) {
                    errors.push(ConfigError::new(
                        "duplicate_id",
                        format!("duplicate accelerator '{}'", accelerator.id),
                        f.position(),
                    ));
                    continue;
                }
                if !fleet.hosts.contains_key(&accelerator.host) {
                    errors.push(ConfigError::new(
                        "unresolved_reference",
                        format!(
                            "accelerator '{}' names host '{}', which is not defined",
                            accelerator.id, accelerator.host
                        ),
                        f.position(),
                    ));
                    continue;
                }
                fleet
                    .accelerators
                    .insert(accelerator.id.clone(), accelerator);
            }
            Err(e) => errors.push(e),
        }
    }

    // A pool that spans two hosts cannot be reasoned about: the host
    // reservation would belong to neither, and evicting on one machine would
    // appear to free memory on the other.
    let mut pool_hosts: BTreeMap<PoolId, BTreeSet<HostId>> = BTreeMap::new();
    for accelerator in fleet.accelerators.values() {
        pool_hosts
            .entry(accelerator.pool.clone())
            .or_default()
            .insert(accelerator.host.clone());
    }
    for (pool, hosts) in &pool_hosts {
        if hosts.len() > 1 {
            errors.push(ConfigError::new(
                "pool_spans_hosts",
                format!(
                    "pool '{pool}' is shared by {} hosts; a memory pool belongs to one machine",
                    hosts.len()
                ),
                Position { line: 1, column: 1 },
            ));
        }
    }

    // -- Artifacts --------------------------------------------------------
    for record in document.of_kind("artifact") {
        let f = Fields::new(record);
        match build_artifact(&f) {
            Ok(artifact) => {
                if fleet.artifacts.contains_key(&artifact.id) {
                    errors.push(ConfigError::new(
                        "duplicate_id",
                        format!("duplicate artifact '{}'", artifact.id),
                        f.position(),
                    ));
                    continue;
                }
                fleet.artifacts.insert(artifact.id.clone(), artifact);
            }
            Err(e) => errors.push(e),
        }
    }

    // -- Deployments ------------------------------------------------------
    let mut targets_seen: BTreeMap<TargetId, DeploymentId> = BTreeMap::new();
    for record in document.of_kind("deployment") {
        let f = Fields::new(record);
        let deployment = match build_deployment(&f) {
            Ok(d) => d,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        if fleet.deployments.contains_key(&deployment.id) {
            errors.push(ConfigError::new(
                "duplicate_id",
                format!("duplicate deployment '{}'", deployment.id),
                f.position(),
            ));
            continue;
        }
        if !targets.contains_key(&deployment.target) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "deployment '{}' names target '{}', which is not defined",
                    deployment.id, deployment.target
                ),
                f.position(),
            ));
            continue;
        }
        if let Some(existing) = targets_seen.get(&deployment.target) {
            errors.push(ConfigError::new(
                "duplicate_deployment_target",
                format!(
                    "target '{}' already has deployment '{existing}'; a model runnable in \
                     two places is two targets sharing an alias",
                    deployment.target
                ),
                f.position(),
            ));
            continue;
        }
        let Some(accelerator) = fleet.accelerators.get(&deployment.accelerator) else {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!(
                    "deployment '{}' names accelerator '{}', which is not defined",
                    deployment.id, deployment.accelerator
                ),
                f.position(),
            ));
            continue;
        };
        if let Some(artifact_id) = &deployment.artifact {
            match fleet.artifacts.get(artifact_id) {
                None => {
                    errors.push(ConfigError::new(
                        "unresolved_reference",
                        format!(
                            "deployment '{}' names artifact '{artifact_id}', which is not defined",
                            deployment.id
                        ),
                        f.position(),
                    ));
                    continue;
                }
                Some(artifact) => {
                    let host_arch = fleet.hosts.get(&accelerator.host).map(|h| h.arch);
                    if host_arch.is_some_and(|arch| arch != artifact.arch) {
                        errors.push(ConfigError::new(
                            "artifact_arch_mismatch",
                            format!(
                                "deployment '{}' places {} artifact '{artifact_id}' on a {} host",
                                deployment.id,
                                artifact.arch,
                                host_arch.map_or("unknown", Arch::as_str)
                            ),
                            f.position(),
                        ));
                        continue;
                    }
                }
            }
        }
        targets_seen.insert(deployment.target.clone(), deployment.id.clone());
        fleet
            .deployments
            .insert(deployment.id.clone(), deployment);
    }

    // -- Policies ---------------------------------------------------------
    for record in document.of_kind("fleet_policy") {
        let f = Fields::new(record);
        let scope = match f.str_field("scope") {
            Ok(s) => s,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        // Both a fleet-wide record and a host override start from the current
        // fleet default. The host case is then re-applied below, after every
        // `scope=fleet` record has been read, so record order in the file
        // cannot change the effective limits.
        let policy = match build_policy(&f, fleet.default_policy) {
            Ok(p) => p,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        if scope == "fleet" {
            fleet.default_policy = policy;
            continue;
        }
        let Some(host_name) = scope.strip_prefix("host:") else {
            errors.push(ConfigError::new(
                "invalid_scope",
                format!("fleet_policy scope must be 'fleet' or 'host:<id>', found '{scope}'"),
                f.position(),
            ));
            continue;
        };
        let Ok(host) = HostId::new(host_name) else {
            errors.push(ConfigError::new(
                "invalid_identifier",
                format!("fleet_policy names an invalid host '{host_name}'"),
                f.position(),
            ));
            continue;
        };
        if !fleet.hosts.contains_key(&host) {
            errors.push(ConfigError::new(
                "unresolved_reference",
                format!("fleet_policy names host '{host}', which is not defined"),
                f.position(),
            ));
            continue;
        }
        fleet.host_policies.insert(host, policy);
    }

    // A per-host policy written before the fleet default is still relative to
    // the default it was written against, so the defaults are re-applied to any
    // host policy that predates a `scope=fleet` record. Without this, record
    // order in the file would silently change the effective limits.
    for record in document.of_kind("fleet_policy") {
        let f = Fields::new(record);
        let Ok(scope) = f.str_field("scope") else {
            continue;
        };
        let Some(host_name) = scope.strip_prefix("host:") else {
            continue;
        };
        let Ok(host) = HostId::new(host_name) else {
            continue;
        };
        if let Ok(policy) = build_policy(&f, fleet.default_policy) {
            if fleet.hosts.contains_key(&host) {
                fleet.host_policies.insert(host, policy);
            }
        }
    }

    // -- Cross-record invariants -------------------------------------------
    check_pool_capacity(&fleet, errors);

    fleet
}

/// A deployment that cannot fit its pool is an activation that will always
/// fail — after it has drained and stopped whatever it displaced.
fn check_pool_capacity(fleet: &FleetConfig, errors: &mut Vec<ConfigError>) {
    for deployment in fleet.deployments.values() {
        let Some(accelerator) = fleet.accelerators.get(&deployment.accelerator) else {
            continue;
        };
        let capacity = fleet.pool_capacity_bytes(&accelerator.pool);
        if deployment.memory_bytes > capacity {
            errors.push(ConfigError::new(
                "deployment_exceeds_pool",
                format!(
                    "deployment '{}' declares {} bytes, but pool '{}' offers {capacity} after \
                     the host reservation",
                    deployment.id, deployment.memory_bytes, accelerator.pool
                ),
                Position { line: 1, column: 1 },
            ));
        }
    }
}

fn build_agent(f: &Fields<'_>) -> Result<FleetAgent, ConfigError> {
    let id = fleet_id!(f, "id", AgentId)?;
    let socket = f.str_field("socket")?.to_owned();
    if !socket.starts_with('/') {
        return Err(f.error(
            "invalid_socket_path",
            "a fleet agent socket must be an absolute path".to_owned(),
        ));
    }
    let observation_interval_ms = f.u64_field("observation_interval_ms", 5_000)?;
    let observation_max_age_ms = f.u64_field("observation_max_age_ms", 30_000)?;
    if observation_interval_ms == 0 {
        return Err(f.error(
            "invalid_interval",
            "observation_interval_ms must be greater than zero".to_owned(),
        ));
    }
    if observation_max_age_ms < observation_interval_ms {
        // Belief that expires before the next observation is due means every
        // decision is made against stale state, which is a fleet that refuses
        // to do anything and cannot say why.
        return Err(f.error(
            "invalid_interval",
            format!(
                "observation_max_age_ms ({observation_max_age_ms}) is below \
                 observation_interval_ms ({observation_interval_ms}), so belief would always \
                 be stale"
            ),
        ));
    }
    Ok(FleetAgent {
        id,
        socket,
        observation_interval_ms,
        observation_max_age_ms,
        request_timeout_ms: f.u64_field("request_timeout_ms", 5_000)?,
    })
}

fn build_host(f: &Fields<'_>) -> Result<Host, ConfigError> {
    let id = fleet_id!(f, "id", HostId)?;
    let agent = fleet_id!(f, "agent", AgentId)?;
    let arch_raw = f.str_field("arch")?;
    let arch = Arch::parse(arch_raw)
        .ok_or_else(|| f.error("invalid_arch", format!("unknown architecture '{arch_raw}'")))?;
    let state = match f.opt_str("status") {
        None => HostState::Enabled,
        Some(raw) => HostState::parse(raw)
            .ok_or_else(|| f.error("invalid_state", format!("unknown host status '{raw}'")))?,
    };
    Ok(Host {
        id,
        agent,
        arch,
        state,
        reserved_memory_bytes: f.u64_field("reserved_memory_bytes", 0)?,
        // One at a time by default. A host bringing up two large models at
        // once is competing with itself for the same disk and the same memory.
        max_concurrent_activations: f.u32_field("max_concurrent_activations", 1)?.max(1),
    })
}

fn build_accelerator(f: &Fields<'_>) -> Result<Accelerator, ConfigError> {
    let id = fleet_id!(f, "id", AcceleratorId)?;
    let host = fleet_id!(f, "host", HostId)?;
    let kind_raw = f.str_field("kind")?;
    let kind = AcceleratorKind::parse(kind_raw).ok_or_else(|| {
        f.error(
            "invalid_accelerator_kind",
            format!("unknown accelerator kind '{kind_raw}'"),
        )
    })?;
    let memory_bytes = f.u64_field("memory_bytes", 0)?;
    if memory_bytes == 0 {
        return Err(f.error(
            "invalid_memory",
            "an accelerator must declare memory_bytes greater than zero".to_owned(),
        ));
    }
    // Defaulting the pool to the accelerator's own identifier is right for a
    // discrete GPU and wrong for unified memory, which is why the field exists.
    let pool = match f.opt_str("pool") {
        None => PoolId::new(id.as_str()).map_err(|e| {
            f.error(
                "invalid_identifier",
                format!("accelerator '{id}' cannot be used as a pool name: {e}"),
            )
        })?,
        Some(raw) => PoolId::new(raw).map_err(|e| {
            f.error("invalid_identifier", format!("pool '{raw}' is invalid: {e}"))
        })?,
    };
    Ok(Accelerator {
        id,
        host,
        kind,
        memory_bytes,
        pool,
    })
}

fn build_artifact(f: &Fields<'_>) -> Result<Artifact, ConfigError> {
    let id = fleet_id!(f, "id", ArtifactId)?;
    let kind_raw = f.str_field("kind")?;
    let kind = ArtifactKind::parse(kind_raw).ok_or_else(|| {
        f.error(
            "invalid_artifact_kind",
            format!("unknown artifact kind '{kind_raw}'"),
        )
    })?;
    let arch_raw = f.str_field("arch")?;
    let arch = Arch::parse(arch_raw)
        .ok_or_else(|| f.error("invalid_arch", format!("unknown architecture '{arch_raw}'")))?;
    let digest = f.str_field("digest")?.to_owned();
    // The router does not verify digests — it never holds the bytes — but a
    // malformed one is a configuration error the agent would otherwise
    // discover after downloading forty gigabytes.
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(f.error(
            "invalid_digest",
            "an artifact digest must be written sha256:<64 hex characters>".to_owned(),
        ));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(f.error(
            "invalid_digest",
            "an artifact digest must be sha256: followed by 64 hex characters".to_owned(),
        ));
    }
    Ok(Artifact {
        id,
        kind,
        arch,
        size_bytes: f.u64_field("size_bytes", 0)?,
        digest,
        source: f.opt_str("source").unwrap_or("").to_owned(),
    })
}

fn build_deployment(f: &Fields<'_>) -> Result<Deployment, ConfigError> {
    let id = fleet_id!(f, "id", DeploymentId)?;
    let target = fleet_id!(f, "target", TargetId)?;
    let accelerator = fleet_id!(f, "accelerator", AcceleratorId)?;
    let artifact = match f.opt_str("artifact") {
        None => None,
        Some(raw) => Some(ArtifactId::new(raw).map_err(|e| {
            f.error(
                "invalid_identifier",
                format!("artifact '{raw}' is invalid: {e}"),
            )
        })?),
    };
    let memory_bytes = f.u64_field("memory_bytes", 0)?;
    if memory_bytes == 0 {
        return Err(f.error(
            "invalid_memory",
            "a deployment must declare memory_bytes greater than zero; a deployment that \
             costs nothing would let any number of models co-reside"
                .to_owned(),
        ));
    }
    let readiness = match f.opt_str("readiness") {
        None => Readiness::HttpOk,
        Some(raw) => Readiness::parse(raw).ok_or_else(|| {
            f.error(
                "invalid_readiness",
                format!("unknown readiness check '{raw}'"),
            )
        })?,
    };
    Ok(Deployment {
        id,
        target,
        accelerator,
        artifact,
        memory_bytes,
        start_ms: f.u64_field("start_ms", 60_000)?,
        stop_ms: f.u64_field("stop_ms", 15_000)?,
        drain_ms: f.u64_field("drain_ms", 30_000)?,
        probe_ms: f.u64_field("probe_ms", 10_000)?,
        readiness,
        min_resident_ms: f.u64_field("min_resident_ms", 300_000)?,
        evictable: f.bool_field("evictable", true)?,
        pinned: f.bool_field("pinned", false)?,
        // Off by default. Routing demand starting a model is the feature; a
        // configuration that acquires it by omission is not.
        autostart: f.bool_field("autostart", false)?,
        retention_weight: f.i64_field("retention_weight", 0)?,
        max_drainable_inflight: f.u32_field("max_drainable_inflight", 0)?,
        force_stop: f.bool_field("force_stop", false)?,
    })
}

fn build_policy(f: &Fields<'_>, base: FleetPolicy) -> Result<FleetPolicy, ConfigError> {
    let policy = FleetPolicy {
        max_activations_per_hour: f
            .u32_field("max_activations_per_hour", base.max_activations_per_hour)?,
        eviction_margin_permille: f
            .u32_field("eviction_margin_permille", base.eviction_margin_permille)?,
        max_eviction_set: f.u32_field("max_eviction_set", base.max_eviction_set)?,
        activation_min_demand: f.u32_field("activation_min_demand", base.activation_min_demand)?,
        activation_max_wait_ms: f
            .u64_field("activation_max_wait_ms", base.activation_max_wait_ms)?,
        reactivation_cooldown_ms: f
            .u64_field("reactivation_cooldown_ms", base.reactivation_cooldown_ms)?,
        flap_window_ms: f.u64_field("flap_window_ms", base.flap_window_ms)?,
        max_flap_cooldown_ms: f.u64_field("max_flap_cooldown_ms", base.max_flap_cooldown_ms)?,
        allow_fetch: f.bool_field("allow_fetch", base.allow_fetch)?,
        fetch_disk_headroom_bytes: f
            .u64_field("fetch_disk_headroom_bytes", base.fetch_disk_headroom_bytes)?,
        memory_drift_tolerance_permille: f.u32_field(
            "memory_drift_tolerance_permille",
            base.memory_drift_tolerance_permille,
        )?,
        adopt_unmanaged: f.bool_field("adopt_unmanaged", base.adopt_unmanaged)?,
    };
    if policy.max_activations_per_hour == 0 {
        // A budget that underflows to zero is a fleet that can never start
        // anything, reported as an eligibility rejection on every request. An
        // operator who wants that disables `autostart` or `fleet_enabled`,
        // where the intent is legible.
        return Err(f.error(
            "invalid_budget",
            "max_activations_per_hour must be greater than zero; to stop the router \
             starting anything, set autostart=false or fleet_enabled=false"
                .to_owned(),
        ));
    }
    if policy.max_eviction_set == 0 {
        return Err(f.error(
            "invalid_budget",
            "max_eviction_set must be greater than zero; to forbid eviction entirely, set \
             evictable=false on the deployments that must not be stopped"
                .to_owned(),
        ));
    }
    if policy.max_eviction_set > 8 {
        return Err(f.error(
            "invalid_budget",
            "max_eviction_set must be at most 8; a plan that stops more models than that \
             is a misconfigured fleet rather than a good idea"
                .to_owned(),
        ));
    }
    Ok(policy)
}
