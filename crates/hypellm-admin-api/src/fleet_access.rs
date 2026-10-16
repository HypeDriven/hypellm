//! `GET /admin/v1/fleet/access`: who may use which slave, and which model on it.
//!
//! Read-only. The dashboard renders a matrix of hosts × models from this and
//! writes changes back as `fleet_grant` records through `POST
//! /admin/v1/policies:edit`, so an access change is a draft like any other: it
//! validates, it needs a second approver, and it activates atomically. There is
//! no second path to activation here.
//!
//! Built from configuration alone, so it answers whether or not a fleet runtime
//! is running: deciding who may use a machine should not have to wait for the
//! machine to be switched on.
//!
//! # What it shows
//!
//! The same tenant scope as the fleet views. Hosts appear only when they carry
//! a deployment whose target the caller's tenant can reach, models only when
//! that target is reachable, and grants only when their scope concerns this
//! tenant and what they name is itself shown. A grant for another tenant's
//! machine is another tenant's business.
//!
//! The list of principals is identity data. It is included only for a caller
//! who can author the drafts this screen exists to produce (`EditPolicy`); a
//! caller with `ReadFleet` alone sees the matrix and the grants, and
//! `subjects` is `null`.

use hypellm_config::ValidatedConfig;
use hypellm_core::fleet_access::{FleetGrant, FleetModelSelector, HostSelector};
use hypellm_core::ids::{PrincipalId, TargetId, TenantId};
use hypellm_core::policy::{BindingScope, ModelSelector};
use std::collections::{BTreeMap, BTreeSet};
use wire_json::{Object, Value};

/// The configuration spelling of a scope.
#[must_use]
pub fn scope_token(scope: &BindingScope) -> String {
    match scope {
        BindingScope::Principal(p) => format!("principal:{p}"),
        BindingScope::Group(g) => format!("group:{g}"),
        BindingScope::Tenant(t) => format!("tenant:{t}"),
        BindingScope::Global => "global".to_owned(),
    }
}

/// The configuration spelling of a host selector.
#[must_use]
pub fn host_token(host: &HostSelector) -> String {
    match host {
        HostSelector::Exact(h) => h.as_str().to_owned(),
        HostSelector::Any => "*".to_owned(),
    }
}

/// The configuration spelling of a model selector.
#[must_use]
pub fn model_token(model: &FleetModelSelector) -> String {
    match model {
        FleetModelSelector::Target(t) => format!("target:{t}"),
        FleetModelSelector::Alias(ModelSelector::Exact(a)) => a.as_str().to_owned(),
        FleetModelSelector::Alias(ModelSelector::Prefix(p)) => format!("{p}*"),
        FleetModelSelector::Alias(ModelSelector::Any) => "*".to_owned(),
    }
}

/// Principals known to belong to `tenant`: from identities, local users, group
/// membership, and the API keys issued in it.
///
/// Keys are the reason this takes a list from outside the configuration: most
/// existing credentials are keys, and "grant every existing principal access"
/// has to reach the principals those keys name.
#[must_use]
pub fn tenant_principals(
    config: &ValidatedConfig,
    tenant: &TenantId,
    key_principals: impl IntoIterator<Item = PrincipalId>,
) -> BTreeSet<PrincipalId> {
    let mut out: BTreeSet<PrincipalId> = key_principals.into_iter().collect();
    out.extend(
        config
            .identities
            .iter()
            .filter(|i| &i.tenant == tenant)
            .map(|i| i.principal.clone()),
    );
    out.extend(
        config
            .local_users
            .iter()
            .filter(|u| &u.tenant == tenant)
            .map(|u| u.principal.clone()),
    );
    for group in config.groups.iter().filter(|g| &g.tenant == tenant) {
        out.extend(group.members.iter().cloned());
    }
    out
}

/// Whether a grant concerns this tenant and names only what the caller may see.
fn grant_shown(
    grant: &FleetGrant,
    config: &ValidatedConfig,
    tenant: &TenantId,
    principals: &BTreeSet<PrincipalId>,
    hosts: &BTreeSet<&hypellm_core::ids::HostId>,
    visible: &BTreeSet<TargetId>,
) -> bool {
    let scope_ok = match &grant.scope {
        BindingScope::Global => true,
        BindingScope::Tenant(t) => t == tenant,
        BindingScope::Group(g) => config
            .groups
            .iter()
            .any(|group| &group.id == g && &group.tenant == tenant),
        BindingScope::Principal(p) => principals.contains(p),
    };
    let host_ok = match &grant.host {
        HostSelector::Any => true,
        HostSelector::Exact(h) => hosts.contains(h),
    };
    let model_ok = match &grant.model {
        FleetModelSelector::Target(t) => visible.contains(t),
        FleetModelSelector::Alias(_) => true,
    };
    scope_ok && host_ok && model_ok
}

/// Render the access view.
///
/// `visible` is the set of targets the caller's tenant can reach, exactly as
/// the fleet views compute it. `principals` is `Some` only for a caller who may
/// see the principal list.
#[must_use]
pub fn render_access(
    config: &ValidatedConfig,
    tenant: &TenantId,
    visible: &BTreeSet<TargetId>,
    principals: Option<&BTreeSet<PrincipalId>>,
    all_tenant_principals: &BTreeSet<PrincipalId>,
) -> Value {
    let snapshot = &config.snapshot;
    let fleet = &config.fleet;

    // Host → models on it, from declared placement. Ordered by identifier,
    // so the matrix is stable between loads.
    let mut by_host: BTreeMap<&hypellm_core::ids::HostId, Vec<Value>> = BTreeMap::new();
    for deployment in fleet.deployments.values() {
        if !visible.contains(&deployment.target) {
            continue;
        }
        let Some(host) = snapshot.fleet_placement.get(&deployment.target) else {
            continue;
        };
        let aliases: Vec<Value> = snapshot
            .aliases
            .values()
            .filter(|a| a.permitted_targets.contains(&deployment.target))
            .map(|a| Value::from(a.id.as_str()))
            .collect();
        let mut model = Object::new();
        model.push("target", Value::from(deployment.target.as_str()));
        model.push("deployment", Value::from(deployment.id.as_str()));
        model.push("aliases", Value::Array(aliases));
        by_host.entry(host).or_default().push(Value::Object(model));
    }
    let shown_hosts: BTreeSet<&hypellm_core::ids::HostId> = by_host.keys().copied().collect();

    let hosts: Vec<Value> = by_host
        .into_iter()
        .map(|(id, models)| {
            let mut object = Object::new();
            object.push("id", Value::from(id.as_str()));
            object.push_opt(
                "status",
                fleet.hosts.get(id).map(|h| Value::from(h.state.as_str())),
            );
            object.push("models", Value::Array(models));
            Value::Object(object)
        })
        .collect();

    let grants: Vec<Value> = snapshot
        .fleet_grants
        .iter()
        .filter(|g| {
            grant_shown(
                g,
                config,
                tenant,
                all_tenant_principals,
                &shown_hosts,
                visible,
            )
        })
        .map(|g| {
            let mut object = Object::new();
            object.push("id", Value::from(g.id.as_str()));
            object.push("scope", Value::from(scope_token(&g.scope)));
            object.push("host", Value::from(host_token(&g.host)));
            object.push("model", Value::from(model_token(&g.model)));
            object.push("allow", Value::from(g.allow));
            Value::Object(object)
        })
        .collect();

    let subjects = principals.map_or(Value::Null, |principals| {
        let mut object = Object::new();
        object.push(
            "principals",
            Value::Array(principals.iter().map(|p| Value::from(p.as_str())).collect()),
        );
        object.push(
            "groups",
            Value::Array(
                config
                    .groups
                    .iter()
                    .filter(|g| &g.tenant == tenant)
                    .map(|g| Value::from(g.id.as_str()))
                    .collect(),
            ),
        );
        object.push("tenants", Value::Array(vec![Value::from(tenant.as_str())]));
        Value::Object(object)
    });

    let mut root = Object::new();
    root.push("default", Value::from(snapshot.fleet_access_default.as_str()));
    root.push("hosts", Value::Array(hosts));
    root.push("grants", Value::Array(grants));
    root.push("subjects", subjects);
    root.push("config_version", Value::from(snapshot.version));
    Value::Object(root)
}
