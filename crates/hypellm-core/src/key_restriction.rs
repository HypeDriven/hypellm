//! What one API key may do *within* what its principal may do.
//!
//! A key authenticates as a principal, and the principal's policy — its alias
//! grants, its bindings, its fleet grants, its admission class — is the
//! ceiling. A key restriction can only narrow that ceiling: every predicate
//! here is a further condition a request must meet, never a substitute for one
//! the policy already applies. That is why each field is an allowlist and why
//! "absent" means "no further condition" rather than "nothing": there is no
//! value of this type that makes a request eligible which the policy alone
//! would have refused.
//!
//! Enforcement is the intersection with the *live* policy, evaluated on every
//! request. A key limited to `{a, b}` whose principal later loses `b` can use
//! `a` alone; nothing has to go back and edit the key.

use crate::admission::PriorityClass;
use crate::ids::{AliasId, HostId, TargetId};
use std::collections::BTreeSet;

/// Most entries one allowlist may hold.
///
/// Larger than any real configuration's alias or target count, and small
/// enough that a restriction is a bounded thing to store, encode and check.
pub const MAX_RESTRICTION_ENTRIES: usize = 256;

/// One key's narrowing of its principal's access.
///
/// `Default` is unrestricted: a key minted before restrictions existed, or one
/// nobody has narrowed, behaves exactly as its principal does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRestriction {
    /// The aliases the key may see and call. `None` is every alias the
    /// principal may use.
    pub models: Option<BTreeSet<AliasId>>,
    /// The targets — a model on a specific provider — the key may be served
    /// by. `None` is every target the principal may be served by.
    pub targets: Option<BTreeSet<TargetId>>,
    /// The fleet slaves the key may be served on. Applies only to
    /// fleet-managed targets; a target with no fleet placement is governed by
    /// `targets` alone. `None` is every slave the principal may use.
    pub hosts: Option<BTreeSet<HostId>>,
    /// The highest admission class the key's requests may queue at. The
    /// effective class is the lower of this and the principal's; `None` leaves
    /// the principal's class as it is.
    pub priority: Option<PriorityClass>,
}

impl KeyRestriction {
    /// Whether the restriction narrows nothing.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.models.is_none()
            && self.targets.is_none()
            && self.hosts.is_none()
            && self.priority.is_none()
    }

    /// Whether the key may see and call `alias`, as far as the key is
    /// concerned. The principal's grant is checked separately and both must
    /// pass.
    #[must_use]
    pub fn permits_alias(&self, alias: &AliasId) -> bool {
        self.models.as_ref().is_none_or(|models| models.contains(alias))
    }

    /// Whether the key may be served by `target`.
    #[must_use]
    pub fn permits_target(&self, target: &TargetId) -> bool {
        self.targets.as_ref().is_none_or(|targets| targets.contains(target))
    }

    /// Whether the key may be served on fleet slave `host`.
    #[must_use]
    pub fn permits_host(&self, host: &HostId) -> bool {
        self.hosts.as_ref().is_none_or(|hosts| hosts.contains(host))
    }

    /// The admission class a request from this key queues at, given the
    /// principal's.
    ///
    /// The lower of the two. [`PriorityClass`] orders `Interactive` before
    /// `Standard` before `Batch`, and the queue serves lower first, so the
    /// lower *priority* is the greater value.
    #[must_use]
    pub fn cap_priority(&self, principal_class: PriorityClass) -> PriorityClass {
        self.priority.map_or(principal_class, |key| key.max(principal_class))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(s: &str) -> AliasId {
        AliasId::new(s).unwrap()
    }

    #[test]
    fn an_absent_field_narrows_nothing_and_a_present_one_is_an_allowlist() {
        let open = KeyRestriction::default();
        assert!(open.is_unrestricted());
        assert!(open.permits_alias(&alias("anything")));

        let narrowed = KeyRestriction {
            models: Some([alias("agent")].into_iter().collect()),
            ..KeyRestriction::default()
        };
        assert!(!narrowed.is_unrestricted());
        assert!(narrowed.permits_alias(&alias("agent")));
        assert!(!narrowed.permits_alias(&alias("chat")));
    }

    #[test]
    fn a_key_can_lower_its_priority_but_never_raise_it() {
        use PriorityClass::{Batch, Interactive, Standard};
        for principal in [Interactive, Standard, Batch] {
            for key in [None, Some(Interactive), Some(Standard), Some(Batch)] {
                let restriction = KeyRestriction {
                    priority: key,
                    ..KeyRestriction::default()
                };
                let effective = restriction.cap_priority(principal);
                // Served no earlier than the principal would be.
                assert!(effective >= principal, "{key:?} raised {principal:?} to {effective:?}");
                if let Some(key) = key {
                    assert!(effective >= key);
                }
            }
        }
        let batch = KeyRestriction {
            priority: Some(Batch),
            ..KeyRestriction::default()
        };
        assert_eq!(batch.cap_priority(Interactive), Batch);
    }
}
