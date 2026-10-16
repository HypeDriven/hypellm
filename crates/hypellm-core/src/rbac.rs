//! Roles and permissions (specification 9.3).
//!
//! The permission set is deliberately fine-grained in exactly the places where
//! the specification separates duties:
//!
//! - A policy editor "cannot publish own draft by default"; publishing is a
//!   distinct permission held by an approver.
//! - A credential manager can create, rotate, and revoke a credential but
//!   "cannot read secret back" — there is no permission that reads one, for any
//!   role, so the management API has nothing to gate.
//! - Break-glass is time-limited and separately audited, so it is a role rather
//!   than a flag on an existing one.

use core::fmt;

/// A management permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Read sanitized health and configuration summaries.
    ReadSummary,
    /// Read own usage.
    ReadOwnUsage,
    /// Read usage across the tenant.
    ReadTenantUsage,
    /// Drain, undrain, and set maintenance on a target.
    OperateTargets,
    /// Quarantine a target, overriding automated recovery.
    QuarantineTargets,
    /// Read redacted decision traces.
    ReadDecisionTraces,
    /// Create and edit policy drafts.
    EditPolicy,
    /// Run policy simulation.
    SimulatePolicy,
    /// Publish a validated policy draft.
    PublishPolicy,
    /// Create, rotate, and revoke provider credential references.
    ManageCredentials,
    /// Create and revoke router API keys.
    ManageKeys,
    /// Read and change a key's cumulative token budget and its payment
    /// instructions (specification 12.3).
    ///
    /// Distinct from [`Permission::ManageKeys`] so that payment automation can
    /// credit a key without being able to mint or revoke one. It moves an
    /// allowance; it never produces a credential.
    ManageKeyBudgets,
    /// Read the immutable audit view.
    ReadAudit,
    /// Export audit records.
    ExportAudit,
    /// Manage principals, groups, and role bindings.
    ManagePrincipals,
    /// Change router settings.
    ManageSettings,
    /// Perform a break-glass action.
    BreakGlass,
    /// Cause a deployment to be started or stopped.
    ///
    /// Distinct from using a model that is already running: this is permission
    /// to make the *fleet* do work. Not granted to an ordinary inference key,
    /// because an activation costs minutes of a host's time and may displace
    /// something else.
    FleetActivate,
    /// Cause an artifact to be acquired.
    ///
    /// Separate from [`Permission::FleetActivate`] and not granted by default.
    /// This is the one permission on which a single request can cost the fleet
    /// hours of bandwidth and hundreds of gigabytes of disk.
    FleetFetch,
    /// Enroll a new slave: mint an enrollment token, and approve, reject or
    /// revoke what registered with one (specification 26.8).
    ///
    /// Separate from [`Permission::FleetActivate`] because its consequence is
    /// of a different kind: an approval is the first step toward the fleet
    /// agent holding SSH trust in a machine. It drafts records rather than
    /// publishing them, so a second person still decides — but minting a
    /// token hands out a credential, which is why it needs a fresh sign-in.
    FleetEnroll,
    /// Read fleet topology, residency, and activation history.
    ///
    /// Management-plane data. Host identifiers, memory figures, and which
    /// models are co-resident are not visible to a data-plane caller at any
    /// permission level.
    ReadFleet,
}

impl Permission {
    /// Stable name for the session response and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadSummary => "read_summary",
            Self::ReadOwnUsage => "read_own_usage",
            Self::ReadTenantUsage => "read_tenant_usage",
            Self::OperateTargets => "operate_targets",
            Self::QuarantineTargets => "quarantine_targets",
            Self::ReadDecisionTraces => "read_decision_traces",
            Self::EditPolicy => "edit_policy",
            Self::SimulatePolicy => "simulate_policy",
            Self::PublishPolicy => "publish_policy",
            Self::ManageCredentials => "manage_credentials",
            Self::ManageKeys => "manage_keys",
            Self::ManageKeyBudgets => "manage_key_budgets",
            Self::ReadAudit => "read_audit",
            Self::ExportAudit => "export_audit",
            Self::ManagePrincipals => "manage_principals",
            Self::ManageSettings => "manage_settings",
            Self::BreakGlass => "break_glass",
            Self::FleetActivate => "fleet_activate",
            Self::FleetFetch => "fleet_fetch",
            Self::FleetEnroll => "fleet_enroll",
            Self::ReadFleet => "read_fleet",
        }
    }

    /// Whether performing this action requires a fresh authentication.
    ///
    /// Specification 9.1: "Reauthentication is required for credential changes,
    /// role grants, break-glass actions, and policy publication."
    #[must_use]
    pub const fn requires_reauthentication(self) -> bool {
        matches!(
            self,
            Self::ManageCredentials
                | Self::ManageKeys
                | Self::PublishPolicy
                | Self::ManagePrincipals
                | Self::BreakGlass
                | Self::ManageSettings
                // A fetch commits the fleet to hours of bandwidth and hundreds
                // of gigabytes of disk. That is the same class of consequence
                // as publishing a policy.
                | Self::FleetFetch
                // A token is a credential that lets a machine register.
                | Self::FleetEnroll
        )
    }

    /// Every permission, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ReadSummary,
            Self::ReadOwnUsage,
            Self::ReadTenantUsage,
            Self::OperateTargets,
            Self::QuarantineTargets,
            Self::ReadDecisionTraces,
            Self::EditPolicy,
            Self::SimulatePolicy,
            Self::PublishPolicy,
            Self::ManageCredentials,
            Self::ManageKeys,
            Self::ManageKeyBudgets,
            Self::ReadAudit,
            Self::ExportAudit,
            Self::ManagePrincipals,
            Self::ManageSettings,
            Self::BreakGlass,
            Self::FleetActivate,
            Self::FleetFetch,
            Self::FleetEnroll,
            Self::ReadFleet,
        ]
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A management role (specification 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Read sanitized health, configuration summaries, and own usage.
    Viewer,
    /// Drain targets, open and close maintenance, view redacted traces.
    Operator,
    /// Draft policies and simulate; cannot publish by default.
    PolicyEditor,
    /// Review and publish signed, versioned configuration.
    PolicyApprover,
    /// Create, rotate, and revoke credential references; cannot read a secret.
    CredentialManager,
    /// Read and update key token budgets and payment instructions; cannot
    /// create or revoke a key. Assignable to payment automation.
    KeyBudgetManager,
    /// Create, revoke and change the expiry of router API keys.
    ///
    /// An addition to specification 9.3's table, recorded in
    /// spec/deferred-issues.html. Without it `ManageKeys` exists only inside
    /// break-glass, and a key minted under break-glass expires with the
    /// session that minted it — so no ordinary sign-in could issue a key that
    /// outlives an hour. Holding this role is what lets a key's lifetime be
    /// decided by a person rather than by the emergency path's clock; it
    /// carries nothing else, and a management-scoped key it mints may still
    /// not carry a role its minter lacks.
    KeyManager,
    /// Read immutable audit and export views.
    Auditor,
    /// Time-limited full access with reauthentication, reason, and alert.
    BreakGlassAdmin,
}

impl Role {
    /// Stable configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::PolicyEditor => "policy_editor",
            Self::PolicyApprover => "policy_approver",
            Self::CredentialManager => "credential_manager",
            Self::KeyBudgetManager => "key_budget_manager",
            Self::KeyManager => "key_manager",
            Self::Auditor => "auditor",
            Self::BreakGlassAdmin => "break_glass_admin",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "viewer" => Self::Viewer,
            "operator" => Self::Operator,
            "policy_editor" => Self::PolicyEditor,
            "policy_approver" => Self::PolicyApprover,
            "credential_manager" => Self::CredentialManager,
            "key_budget_manager" => Self::KeyBudgetManager,
            "key_manager" => Self::KeyManager,
            "auditor" => Self::Auditor,
            "break_glass_admin" => Self::BreakGlassAdmin,
            _ => return None,
        })
    }

    /// The permissions this role carries.
    #[must_use]
    pub const fn permissions(self) -> &'static [Permission] {
        use Permission as P;
        match self {
            Self::Viewer => &[P::ReadSummary, P::ReadOwnUsage],
            Self::Operator => &[
                P::ReadSummary,
                P::ReadOwnUsage,
                P::ReadTenantUsage,
                P::OperateTargets,
                P::QuarantineTargets,
                P::ReadDecisionTraces,
                // Starting and stopping declared deployments is operating
                // targets by another name: the same person, the same shift,
                // the same audit trail. Fetching an artifact is not — it
                // spends bandwidth and disk on a scale an operator action
                // usually does not — so it stays out of every default role.
                P::ReadFleet,
                P::FleetActivate,
                // Bringing a machine into the fleet is the operator's job;
                // making it routable is still a publication by an approver.
                P::FleetEnroll,
            ],
            Self::PolicyEditor => &[
                P::ReadSummary,
                P::ReadOwnUsage,
                P::ReadTenantUsage,
                P::ReadDecisionTraces,
                P::ReadFleet,
                P::EditPolicy,
                P::SimulatePolicy,
            ],
            Self::PolicyApprover => &[
                P::ReadSummary,
                P::ReadOwnUsage,
                P::ReadTenantUsage,
                P::ReadDecisionTraces,
                P::SimulatePolicy,
                P::PublishPolicy,
            ],
            Self::CredentialManager => &[P::ReadSummary, P::ReadOwnUsage, P::ManageCredentials],
            // Specification 12.3: "This permission does not grant key
            // creation/revocation, credential access, policy publication".
            // The role is that permission and nothing a payment system has
            // no use for.
            Self::KeyBudgetManager => &[P::ReadSummary, P::ManageKeyBudgets],
            // Keys and nothing else: not their budgets, which move an
            // allowance and are `key_budget_manager`'s, and not the
            // principals or settings break-glass also carries.
            Self::KeyManager => &[P::ReadSummary, P::ReadOwnUsage, P::ManageKeys],
            Self::Auditor => &[P::ReadSummary, P::ReadAudit, P::ExportAudit],
            Self::BreakGlassAdmin => &[
                P::ReadSummary,
                P::ReadOwnUsage,
                P::ReadTenantUsage,
                P::OperateTargets,
                P::QuarantineTargets,
                P::ReadDecisionTraces,
                P::EditPolicy,
                P::SimulatePolicy,
                P::PublishPolicy,
                P::ManageCredentials,
                P::ManageKeys,
                P::ManageKeyBudgets,
                P::ReadAudit,
                P::ExportAudit,
                P::ManagePrincipals,
                P::ManageSettings,
                P::BreakGlass,
                P::ReadFleet,
                P::FleetActivate,
                P::FleetFetch,
                P::FleetEnroll,
            ],
        }
    }

    /// Whether this role carries a permission.
    #[must_use]
    pub fn grants(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }

    /// Whether this role is time-limited and separately audited.
    #[must_use]
    pub const fn is_break_glass(self) -> bool {
        matches!(self, Self::BreakGlassAdmin)
    }

    /// Every role, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Viewer,
            Self::Operator,
            Self::PolicyEditor,
            Self::PolicyApprover,
            Self::CredentialManager,
            Self::KeyBudgetManager,
            Self::KeyManager,
            Self::Auditor,
            Self::BreakGlassAdmin,
        ]
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The permissions a principal holds, resolved from its role bindings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionSet {
    permissions: Vec<Permission>,
}

impl PermissionSet {
    /// An empty set. The default for any principal with no role binding.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    /// Build from a list of roles.
    #[must_use]
    pub fn from_roles(roles: &[Role]) -> Self {
        let mut permissions: Vec<Permission> = roles
            .iter()
            .flat_map(|r| r.permissions().iter().copied())
            .collect();
        permissions.sort_unstable();
        permissions.dedup();
        Self { permissions }
    }

    /// Whether the set contains a permission.
    #[must_use]
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// The permissions, sorted.
    #[must_use]
    pub fn as_slice(&self) -> &[Permission] {
        &self.permissions
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_parsing_roundtrips() {
        for r in Role::all() {
            assert_eq!(Role::parse(r.as_str()), Some(*r));
        }
        assert_eq!(Role::parse("root"), None);
        assert_eq!(Role::parse("Viewer"), None);
    }

    #[test]
    fn a_policy_editor_cannot_publish() {
        // Specification 9.3: "Draft policies and simulate; cannot publish own
        // draft by default." This is the separation of duties that makes the
        // approver role meaningful.
        assert!(Role::PolicyEditor.grants(Permission::EditPolicy));
        assert!(Role::PolicyEditor.grants(Permission::SimulatePolicy));
        assert!(!Role::PolicyEditor.grants(Permission::PublishPolicy));

        assert!(Role::PolicyApprover.grants(Permission::PublishPolicy));
        assert!(!Role::PolicyApprover.grants(Permission::EditPolicy));
    }

    #[test]
    fn no_role_can_read_a_credential_secret() {
        // Specification 9.3: a credential manager "cannot read secret back".
        // There is no such permission to grant, which is stronger than a check.
        let reads_secret = Permission::all()
            .iter()
            .any(|p| p.as_str().contains("read_credential") || p.as_str().contains("secret"));
        assert!(
            !reads_secret,
            "no permission may exist that reads a credential secret"
        );
        assert!(Role::CredentialManager.grants(Permission::ManageCredentials));
    }

    #[test]
    fn a_key_budget_manager_can_move_an_allowance_and_nothing_else() {
        // Specification 12.3. The holder is typically a payment system's
        // service key, so anything beyond the budget is excess authority.
        assert!(Role::KeyBudgetManager.grants(Permission::ManageKeyBudgets));
        for p in Permission::all() {
            if Role::KeyBudgetManager.grants(*p) {
                assert!(
                    matches!(p, Permission::ReadSummary | Permission::ManageKeyBudgets),
                    "key budget manager unexpectedly holds {p}"
                );
            }
        }
        // Automation holds no session to refresh.
        assert!(!Permission::ManageKeyBudgets.requires_reauthentication());
    }

    #[test]
    fn a_key_manager_manages_keys_and_nothing_else() {
        assert!(Role::KeyManager.grants(Permission::ManageKeys));
        assert!(!Role::KeyManager.is_break_glass());
        for p in Permission::all() {
            if Role::KeyManager.grants(*p) {
                assert!(
                    matches!(
                        p,
                        Permission::ReadSummary | Permission::ReadOwnUsage | Permission::ManageKeys
                    ),
                    "key manager unexpectedly holds {p}"
                );
            }
        }
        // Minting a credential still wants a recent sign-in.
        assert!(Permission::ManageKeys.requires_reauthentication());
    }

    #[test]
    fn a_viewer_sees_only_summaries_and_own_usage() {
        assert!(Role::Viewer.grants(Permission::ReadSummary));
        assert!(Role::Viewer.grants(Permission::ReadOwnUsage));
        assert!(!Role::Viewer.grants(Permission::ReadTenantUsage));
        assert!(!Role::Viewer.grants(Permission::ReadAudit));
        assert!(!Role::Viewer.grants(Permission::OperateTargets));
        assert!(!Role::Viewer.grants(Permission::EditPolicy));
    }

    #[test]
    fn an_auditor_cannot_change_anything() {
        for p in Permission::all() {
            if Role::Auditor.grants(*p) {
                assert!(
                    matches!(
                        p,
                        Permission::ReadSummary | Permission::ReadAudit | Permission::ExportAudit
                    ),
                    "auditor unexpectedly holds {p}"
                );
            }
        }
    }

    #[test]
    fn break_glass_holds_everything_and_is_marked() {
        for p in Permission::all() {
            assert!(
                Role::BreakGlassAdmin.grants(*p),
                "break-glass must hold {p}"
            );
        }
        assert!(Role::BreakGlassAdmin.is_break_glass());
        for r in Role::all() {
            if *r != Role::BreakGlassAdmin {
                assert!(!r.is_break_glass(), "{r} must not be break-glass");
            }
        }
    }

    #[test]
    fn no_ordinary_role_holds_break_glass() {
        for r in Role::all() {
            if *r != Role::BreakGlassAdmin {
                assert!(
                    !r.grants(Permission::BreakGlass),
                    "{r} must not hold the break-glass permission"
                );
            }
        }
    }

    #[test]
    fn sensitive_permissions_require_reauthentication() {
        // Specification 9.1 names exactly these.
        for p in [
            Permission::ManageCredentials,
            Permission::PublishPolicy,
            Permission::ManagePrincipals,
            Permission::BreakGlass,
        ] {
            assert!(p.requires_reauthentication(), "{p} must require reauth");
        }
        for p in [
            Permission::ReadSummary,
            Permission::ReadOwnUsage,
            Permission::SimulatePolicy,
            Permission::ReadAudit,
        ] {
            assert!(!p.requires_reauthentication(), "{p} should not require reauth");
        }
    }

    #[test]
    fn permission_sets_union_and_deduplicate() {
        let set = PermissionSet::from_roles(&[Role::Viewer, Role::Operator]);
        assert!(set.has(Permission::ReadSummary));
        assert!(set.has(Permission::OperateTargets));
        assert!(!set.has(Permission::PublishPolicy));

        let count = set
            .as_slice()
            .iter()
            .filter(|p| **p == Permission::ReadSummary)
            .count();
        assert_eq!(count, 1, "duplicates must be removed");

        // Sorted, so the session response is deterministic.
        let mut sorted = set.as_slice().to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, set.as_slice());
    }

    #[test]
    fn no_roles_means_no_permissions() {
        // Default deny for a principal with no role binding.
        let set = PermissionSet::from_roles(&[]);
        assert!(set.is_empty());
        for p in Permission::all() {
            assert!(!set.has(*p));
        }
        assert!(PermissionSet::empty().is_empty());
    }

    #[test]
    fn permission_names_are_distinct() {
        let mut names: Vec<&str> = Permission::all().iter().map(|p| p.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }
}
