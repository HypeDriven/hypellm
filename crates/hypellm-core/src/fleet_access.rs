//! Who may use which slave, and which model on it.
//!
//! An alias grant (specification 6.2's first filter) answers "may this caller
//! ask for this alias at all". A fleet grant answers a narrower question that
//! only exists once a target runs on a machine the fleet manages: "may this
//! caller be served by *that* machine, and by that model on it". The two are
//! independent filters, and both must pass.
//!
//! # Resolution
//!
//! A grant applies to a (caller, alias, target) triple when its scope covers
//! the caller, its host selector covers the target's host, and its model
//! selector covers the alias or the target. Among the applicable grants the
//! one at the best **level** decides, where a level is the pair
//!
//! 1. scope — principal, then group, then tenant, then global; and
//! 2. specificity within the scope — an exact host before `*`, and within that
//!    `target:<id>` before an exact alias before a `prefix*` before `*`.
//!
//! Two grants at the same level that disagree resolve to **deny**. No
//! applicable grant at all falls back to [`FleetAccessDefault`], which is
//! `allow` unless the operator says otherwise — every credential that existed
//! before fleet grants did keeps using every slave and every model.
//!
//! Scope dominates specificity, so a principal's `host=* model=* allow=false`
//! is not overturned by a tenant's exact allow: a higher-precedence deny is
//! sticky, as specification 6.1 requires of bindings. Within one scope the more
//! specific grant wins, so "deny everything, allow this one model on this one
//! machine" can be written for one principal without a deny that defeats it.
//!
//! # Why global grants ignore tenant inheritance
//!
//! Alias grants skip `global` for a tenant that does not inherit, which fails
//! closed because alias authorization is default-deny. Fleet access defaults to
//! allow, so the same rule would fail *open*: a global deny of a machine would
//! not reach a non-inheriting tenant. A global fleet grant therefore applies to
//! every tenant.
//!
//! # What this module does not do
//!
//! It holds no host topology of its own. [`PolicySnapshot`] carries the
//! target-to-host placement, built from the fleet configuration, and a target
//! with no placement is not fleet-managed: no fleet grant applies to it and
//! this filter passes it unconditionally.
//!
//! [`PolicySnapshot`]: crate::policy::PolicySnapshot

use crate::ids::{AliasId, BindingId, HostId, TargetId};
use crate::policy::{BindingScope, ModelSelector, RoutingContext};
use core::fmt;

/// The most fleet grants one configuration may declare.
///
/// Every routed request walks the list once per fleet-managed target, so it is
/// bounded (specification 3.2). A thousand covers a matrix of dozens of
/// principals over dozens of machines with room to spare.
pub const MAX_FLEET_GRANTS: usize = 1_024;

/// What happens to a caller no fleet grant mentions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FleetAccessDefault {
    /// Every slave and every model on it. The default, so a configuration
    /// written before fleet grants existed routes exactly as before.
    #[default]
    Allow,
    /// Nothing, unless a grant allows it.
    Deny,
}

impl FleetAccessDefault {
    /// Parse the configuration token.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    /// The configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    const fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for FleetAccessDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which slaves a fleet grant covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSelector {
    /// One host.
    Exact(HostId),
    /// Every host, written `*`.
    Any,
}

impl HostSelector {
    fn matches(&self, host: &HostId) -> bool {
        match self {
            Self::Exact(h) => h == host,
            Self::Any => true,
        }
    }
}

/// Which models on a slave a fleet grant covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetModelSelector {
    /// Requested aliases, as an alias grant names them.
    Alias(ModelSelector),
    /// One target — one model as deployed — written `target:<id>`.
    Target(TargetId),
}

impl FleetModelSelector {
    fn matches(&self, alias: &AliasId, target: &TargetId) -> bool {
        match self {
            Self::Alias(selector) => selector.matches(alias),
            Self::Target(t) => t == target,
        }
    }

    /// Specificity, higher being more specific.
    const fn specificity(&self) -> u8 {
        match self {
            Self::Target(_) => 3,
            Self::Alias(ModelSelector::Exact(_)) => 2,
            Self::Alias(ModelSelector::Prefix(_)) => 1,
            Self::Alias(ModelSelector::Any) => 0,
        }
    }
}

/// One `fleet_grant` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetGrant {
    /// Identifier, so the dashboard can edit one record rather than rewrite
    /// the set.
    pub id: BindingId,
    /// Who it applies to.
    pub scope: BindingScope,
    /// Which slaves.
    pub host: HostSelector,
    /// Which models on them.
    pub model: FleetModelSelector,
    /// Whether it permits or forbids.
    pub allow: bool,
}

impl FleetGrant {
    /// The level at which this grant applies, lower being stronger, or `None`
    /// when it does not apply.
    ///
    /// Scope occupies the high digit and specificity the low one, so scope
    /// always dominates: no specificity at tenant scope outranks anything at
    /// principal scope.
    fn level(
        &self,
        ctx: &RoutingContext<'_>,
        alias: &AliasId,
        target: &TargetId,
        host: &HostId,
    ) -> Option<u8> {
        if !self.host.matches(host) || !self.model.matches(alias, target) {
            return None;
        }
        let scope: u8 = match &self.scope {
            BindingScope::Principal(p) if p == ctx.principal => 0,
            BindingScope::Group(g) if ctx.groups.contains(g) => 1,
            BindingScope::Tenant(t) if t == ctx.tenant => 2,
            BindingScope::Global => 3,
            _ => return None,
        };
        let host_specificity: u8 = match self.host {
            HostSelector::Exact(_) => 4,
            HostSelector::Any => 0,
        };
        // 0..=7, inverted so that more specific is numerically lower.
        let specificity = host_specificity.saturating_add(self.model.specificity());
        Some(
            scope
                .saturating_mul(8)
                .saturating_add(7_u8.saturating_sub(specificity)),
        )
    }
}

/// Whether `grants` let the caller in `ctx` be served by `target`, running on
/// `host`, for a request naming `alias`.
///
/// The one predicate every caller of this rule uses: the routing filter, the
/// models list, and any path that lets a request cause work on a machine. Two
/// copies of a security rule drift; one cannot.
#[must_use]
pub fn permits(
    grants: &[FleetGrant],
    default: FleetAccessDefault,
    ctx: &RoutingContext<'_>,
    alias: &AliasId,
    target: &TargetId,
    host: &HostId,
) -> bool {
    let mut best: Option<(u8, bool)> = None;
    for grant in grants {
        let Some(level) = grant.level(ctx, alias, target, host) else {
            continue;
        };
        best = Some(match best {
            None => (level, grant.allow),
            Some((best_level, best_allow)) => {
                if level < best_level {
                    (level, grant.allow)
                } else if level == best_level {
                    // Deny wins a tie.
                    (best_level, best_allow && grant.allow)
                } else {
                    (best_level, best_allow)
                }
            }
        });
    }
    best.map_or(default.allows(), |(_, allow)| allow)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "specification 18.2 permits these in tests")]
mod tests {
    use super::*;
    use crate::ids::{GroupId, PrincipalId, TenantId};

    fn grant(scope: BindingScope, host: HostSelector, model: FleetModelSelector, allow: bool) -> FleetGrant {
        FleetGrant {
            id: BindingId::new("g").unwrap(),
            scope,
            host,
            model,
            allow,
        }
    }

    #[test]
    fn within_one_scope_the_more_specific_grant_wins_and_across_scopes_scope_wins() {
        let principal = PrincipalId::new("alice").unwrap();
        let tenant = TenantId::new("acme").unwrap();
        let groups: Vec<GroupId> = Vec::new();
        let ctx = RoutingContext {
            principal: &principal,
            groups: &groups,
            tenant: &tenant,
            attempted: &[],
            now_millis: 0,
            key: None,
        };
        let alias = AliasId::new("coder").unwrap();
        let target = TargetId::new("spark:qwen").unwrap();
        let host = HostId::new("spark").unwrap();

        // "Deny everything but this one model on this one machine", for one
        // principal. The exact allow must survive the wildcard deny beside it.
        let grants = vec![
            grant(
                BindingScope::Principal(principal.clone()),
                HostSelector::Any,
                FleetModelSelector::Alias(ModelSelector::Any),
                false,
            ),
            grant(
                BindingScope::Principal(principal.clone()),
                HostSelector::Exact(host.clone()),
                FleetModelSelector::Target(target.clone()),
                true,
            ),
        ];
        assert!(permits(&grants, FleetAccessDefault::Deny, &ctx, &alias, &target, &host));
        let other = TargetId::new("spark:llama").unwrap();
        assert!(!permits(&grants, FleetAccessDefault::Allow, &ctx, &alias, &other, &host));

        // A tenant-wide exact allow cannot reopen a principal's wildcard deny.
        let sticky = vec![
            grant(
                BindingScope::Principal(principal.clone()),
                HostSelector::Any,
                FleetModelSelector::Alias(ModelSelector::Any),
                false,
            ),
            grant(
                BindingScope::Tenant(tenant.clone()),
                HostSelector::Exact(host.clone()),
                FleetModelSelector::Target(target.clone()),
                true,
            ),
        ];
        assert!(!permits(&sticky, FleetAccessDefault::Allow, &ctx, &alias, &target, &host));
    }
}
