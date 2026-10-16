//! Structured record edits over a configuration text.
//!
//! The management API lets an operator add a machine or reorder a preference
//! list without hand-authoring the whole document. It does that by editing
//! records, never text: the active configuration is parsed, each edit changes
//! one record, and the result is rendered canonically. What comes out is an
//! ordinary draft, which still validates, still needs its approver, and still
//! activates atomically — this module adds no second path to activation.
//!
//! Two properties make that safe:
//!
//! - **A field name must be in its record's schema.** Names are written bare,
//!   so an unchecked one could carry a space or a newline and become several
//!   fields or a second record.
//! - **Values go through [`quote_if_needed`](crate::parse::quote_if_needed)**
//!   at rendering, which escapes quotes, backslashes and control characters, so
//!   no value can end its record early.
//!
//! Only the record kinds a routing, fleet or access screen needs are editable.
//! `grant` and `quota` are editable narrowly — see [`scope_rule`] — so that a
//! principal's ceiling — its models, queue class and limits — can be drafted
//! without hand-authoring policy text. Keys, credentials, local users, role
//! bindings, and tenant, global, target and alias quotas are not: each has its
//! own endpoint or reviewer, and an edit here must not become a way around them.

use crate::parse::{Document, ParseLimits, Position, Record, parse};
use crate::schema::schema_for;
use core::fmt;

/// Record kinds this module may edit.
pub const EDITABLE_KINDS: &[&str] = &[
    "provider",
    "target",
    "alias",
    "binding",
    "fleet_agent",
    "host",
    "accelerator",
    "deployment",
    "artifact",
    "fleet_policy",
    "fleet_grant",
    "grant",
    "quota",
    "settings",
];

/// The `quota` fields an edit may touch on a principal's quota: its scope,
/// when it is created, its admission-queue class, and its limits.
///
/// A limit is a capacity and cost control, and raising or removing one widens
/// what a principal may consume. That is a policy decision like any other here:
/// the edit produces a draft, the draft validates, and a second person reviews
/// and publishes it — the author cannot (`DraftStore`). The control is that
/// review, not this list. The list is limited to one subject at a time —
/// [`scope_rule`] keeps tenant, global, alias and target quotas, which throttle
/// many callers or a shared machine, in the policy text.
///
/// Two quota fields stay out:
///
/// - the byte rates (`input_bytes_*`, `output_bytes_*`), which specification 12
///   places at the Global layer only and the loader refuses anywhere else;
/// - `operation`, which qualifies an `alias:` quota and means nothing on a
///   principal's.
pub const QUOTA_EDITABLE: &[&str] = &[
    "scope",
    "class",
    "concurrency",
    "queued",
    "rps",
    "burst",
    "tpm",
    "token_burst",
    "budget",
    "budget_period",
];

/// The `settings` fields an edit may touch. The rest of `settings` governs
/// listeners, identity and limits, and belongs to the policy text itself.
pub const EDITABLE_SETTINGS: &[&str] = &["fleet_enabled", "fleet_access_default"];

/// The most edits one request may carry.
pub const MAX_EDITS: usize = 64;

/// Which record an edit addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// By its `id` field.
    Id(String),
    /// A `fleet_policy`, by its `scope` field.
    Scope(String),
    /// The `settings` singleton.
    Singleton,
}

/// One edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Merge fields into the record, creating it if absent. `None` removes a
    /// field.
    Set {
        /// Record kind.
        kind: String,
        /// Which record.
        identity: Identity,
        /// Field changes, in order.
        fields: Vec<(String, Option<String>)>,
    },
    /// Remove the record.
    Remove {
        /// Record kind.
        kind: String,
        /// Which record.
        identity: Identity,
    },
}

/// Why an edit could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditError {
    /// Which edit, counting from zero.
    pub index: usize,
    /// What was wrong.
    pub message: String,
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "edit {}: {}", self.index, self.message)
    }
}

/// The result of a successful application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The canonical text after the edits.
    pub text: String,
    /// How many edits changed something.
    pub changed: usize,
}

/// Apply `edits` to `text`, returning canonical text.
///
/// All or nothing: the first invalid edit refuses the whole batch, because a
/// half-applied "add this machine" is a draft that names an accelerator for a
/// host it does not contain.
pub fn apply(text: &str, edits: &[Edit]) -> Result<Applied, EditError> {
    if edits.len() > MAX_EDITS {
        return Err(EditError {
            index: MAX_EDITS,
            message: format!("at most {MAX_EDITS} edits may be applied at once"),
        });
    }
    let mut document = parse(text, &ParseLimits::DEFAULT).map_err(|e| EditError {
        index: 0,
        message: format!("the base configuration does not parse: {e:?}"),
    })?;

    let mut changed = 0usize;
    for (index, edit) in edits.iter().enumerate() {
        let fail = |message: String| EditError { index, message };
        let (kind, identity) = match edit {
            Edit::Set { kind, identity, .. } | Edit::Remove { kind, identity } => {
                (kind.as_str(), identity)
            }
        };
        check_identity(kind, identity).map_err(fail)?;
        if let Edit::Set { fields, .. } = edit {
            // A field named twice is applied twice, last value winning, while
            // any check of it reads one of them. Refused for every kind.
            for (at, (name, _)) in fields.iter().enumerate() {
                if fields.iter().skip(at + 1).any(|(other, _)| other == name) {
                    return Err(fail(format!("'{}' is named more than once", name.escape_debug())));
                }
            }
        }
        let position = find(&document, kind, identity);
        if let Some(prefixes) = scope_rule(kind) {
            let existing = position.and_then(|at| document.records.get(at));
            check_scoped(kind, prefixes, existing, edit).map_err(fail)?;
        }

        match edit {
            Edit::Remove { .. } => {
                let Some(at) = position else {
                    return Err(fail(format!("there is no {kind} {} to remove", describe(identity))));
                };
                document.records.remove(at);
                changed = changed.saturating_add(1);
            }
            Edit::Set { fields, .. } => {
                let schema = schema_for(kind).ok_or_else(|| fail(format!("unknown kind '{kind}'")))?;
                for (name, _) in fields {
                    let known = schema.required.contains(&name.as_str())
                        || schema.optional.contains(&name.as_str());
                    if !known {
                        return Err(fail(format!("'{name}' is not a field of {kind}")));
                    }
                    if kind == "settings" && !EDITABLE_SETTINGS.contains(&name.as_str()) {
                        return Err(fail(format!(
                            "settings field '{name}' cannot be edited here; edit the policy text"
                        )));
                    }
                    let identity_field = match identity {
                        Identity::Id(_) => Some("id"),
                        Identity::Scope(_) => Some("scope"),
                        Identity::Singleton => None,
                    };
                    if identity_field == Some(name.as_str()) {
                        return Err(fail(format!(
                            "'{name}' identifies the record and cannot be changed; remove it and \
                             add a new one"
                        )));
                    }
                }

                let record = match position {
                    Some(at) => document.records.get_mut(at),
                    None => {
                        document.records.push(new_record(kind, identity));
                        document.records.last_mut()
                    }
                };
                let Some(record) = record else {
                    return Err(fail("the record could not be addressed".to_owned()));
                };
                let before = record.fields.clone();
                for (name, value) in fields {
                    match value {
                        Some(value) => match record.fields.iter_mut().find(|(k, _)| k == name) {
                            Some(slot) => slot.1.clone_from(value),
                            None => record.fields.push((name.clone(), value.clone())),
                        },
                        None => record.fields.retain(|(k, _)| k != name),
                    }
                }
                if position.is_none() || record.fields != before {
                    changed = changed.saturating_add(1);
                }
            }
        }
    }

    Ok(Applied {
        text: document.to_canonical_string(),
        changed,
    })
}

fn check_identity(kind: &str, identity: &Identity) -> Result<(), String> {
    if !EDITABLE_KINDS.contains(&kind) {
        return Err(format!("records of kind '{kind}' cannot be edited here"));
    }
    match (kind, identity) {
        ("settings", Identity::Singleton) => Ok(()),
        ("settings", _) => Err("settings takes no id".to_owned()),
        ("fleet_policy", Identity::Scope(scope)) if is_token(scope) => Ok(()),
        ("fleet_policy", _) => Err("a fleet_policy is identified by 'scope'".to_owned()),
        (_, Identity::Id(id)) if is_token(id) => Ok(()),
        (_, Identity::Id(id)) => Err(format!("'{}' is not a valid identifier", id.escape_debug())),
        _ => Err(format!("a {kind} is identified by 'id'")),
    }
}

/// The scopes at which records of `kind` may be edited, for the kinds that are
/// editable only at some.
///
/// A `grant` at `tenant:` or `global` decides what everyone in a tenant may
/// use, and a `quota` there throttles all of them; those stay policy text. A
/// principal's or a group's record decides only for its subject, which is what
/// an access screen edits.
fn scope_rule(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "grant" => Some(&["principal:", "group:"]),
        // There is no `group:` quota scope in the grammar.
        "quota" => Some(&["principal:"]),
        _ => None,
    }
}

/// Refuse an edit to a scoped kind that would reach past its subject.
///
/// The scope is fixed at creation: moving a principal's grant to a tenant would
/// widen it to everyone there, so a different subject is a different record.
fn check_scoped(
    kind: &str,
    prefixes: &[&str],
    existing: Option<&Record>,
    edit: &Edit,
) -> Result<(), String> {
    let narrow = |scope: &str| prefixes.iter().any(|p| scope.starts_with(p));
    let allowed = prefixes.join(" or ");
    if let Some(record) = existing {
        let scope = record.get("scope").unwrap_or("");
        if !narrow(scope) {
            return Err(format!(
                "{kind} at scope '{}' cannot be edited here; only {allowed} scopes can",
                scope.escape_debug()
            ));
        }
    }
    match edit {
        Edit::Remove { .. } => {
            // A principal's quota carries nothing this path cannot also set,
            // so removing one is the same decision as clearing its fields —
            // and like every edit here it is reviewed before it applies.
            if kind == "quota" {
                if let Some(record) = existing {
                    if let Some((name, _)) = record
                        .fields
                        .iter()
                        .find(|(name, _)| name != "id" && !QUOTA_EDITABLE.contains(&name.as_str()))
                    {
                        return Err(format!(
                            "this quota also sets '{name}', which cannot be edited here; \
                             removing the record would drop it too, so edit the policy text instead"
                        ));
                    }
                }
            }
            Ok(())
        }
        Edit::Set { fields, .. } => {
            if kind == "quota" {
                if let Some((name, _)) = fields.iter().find(|(n, _)| !QUOTA_EDITABLE.contains(&n.as_str())) {
                    return Err(format!(
                        "quota field '{}' cannot be edited here; only {} can",
                        name.escape_debug(),
                        QUOTA_EDITABLE.join(" and ")
                    ));
                }
            }
            let scope = fields.iter().find(|(n, _)| n == "scope").map(|(_, v)| v);
            match (existing, scope) {
                (Some(_), Some(_)) => Err(format!(
                    "a {kind}'s scope is fixed when it is created; remove it and add a new one"
                )),
                (Some(_), None) => Ok(()),
                (None, Some(Some(scope))) if narrow(scope) => Ok(()),
                (None, Some(Some(scope))) => Err(format!(
                    "a {kind} created here must have a {allowed} scope, not '{}'",
                    scope.escape_debug()
                )),
                (None, _) => Err(format!("a new {kind} needs a 'scope'")),
            }
        }
    }
}

/// An identifier or scope: what the grammar would accept bare, so it cannot be
/// used to smuggle a second field into the record.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
}

fn find(document: &Document, kind: &str, identity: &Identity) -> Option<usize> {
    document.records.iter().position(|r| {
        r.kind == kind
            && match identity {
                Identity::Id(id) => r.get("id") == Some(id.as_str()),
                Identity::Scope(scope) => r.get("scope") == Some(scope.as_str()),
                Identity::Singleton => true,
            }
    })
}

fn new_record(kind: &str, identity: &Identity) -> Record {
    let fields = match identity {
        Identity::Id(id) => vec![("id".to_owned(), id.clone())],
        Identity::Scope(scope) => vec![("scope".to_owned(), scope.clone())],
        Identity::Singleton => Vec::new(),
    };
    Record {
        kind: kind.to_owned(),
        fields,
        position: Position { line: 0, column: 0 },
    }
}

fn describe(identity: &Identity) -> String {
    match identity {
        Identity::Id(id) => format!("'{id}'"),
        Identity::Scope(scope) => format!("with scope '{scope}'"),
        Identity::Singleton => "record".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(kind: &str, id: &str, fields: &[(&str, Option<&str>)]) -> Edit {
        Edit::Set {
            kind: kind.to_owned(),
            identity: Identity::Id(id.to_owned()),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.map(str::to_owned)))
                .collect(),
        }
    }

    const BASE: &str = "host id=spark agent=local arch=aarch64\nfleet_agent id=local socket=/run/f.sock\n";

    #[test]
    fn a_new_host_is_added_and_an_existing_one_merged() {
        let applied = apply(
            BASE,
            &[
                set("host", "spark3", &[("agent", Some("local")), ("arch", Some("x86_64"))]),
                set("host", "spark", &[("reserved_memory_bytes", Some("1024"))]),
            ],
        )
        .expect("applies");
        assert_eq!(applied.changed, 2);
        let doc = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
        let spark = doc.of_kind("host").find(|r| r.get("id") == Some("spark")).expect("spark");
        assert_eq!(spark.get("arch"), Some("aarch64"), "a merge must keep fields it did not name");
        assert_eq!(spark.get("reserved_memory_bytes"), Some("1024"));
        assert!(doc.of_kind("host").any(|r| r.get("id") == Some("spark3")));
    }

    #[test]
    fn a_value_cannot_escape_its_record() {
        // The attack is a value that ends the record and starts another: a
        // role binding appended by way of a host's status field.
        let hostile = "enabled\nrole_binding subject=principal:mallory role=admin";
        let applied = apply(BASE, &[set("host", "spark", &[("status", Some(hostile))])])
            .expect("applies");
        let doc = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
        assert_eq!(doc.of_kind("role_binding").count(), 0);
        let spark = doc.of_kind("host").find(|r| r.get("id") == Some("spark")).expect("spark");
        assert_eq!(spark.get("status"), Some(hostile), "the value survives intact, as one field");
    }

    #[test]
    fn a_field_name_outside_the_schema_is_refused() {
        for name in ["arch x=y", "nonsense", "id"] {
            assert!(
                apply(BASE, &[set("host", "spark", &[(name, Some("v"))])]).is_err(),
                "field name {name:?} was accepted"
            );
        }
    }

    #[test]
    fn kinds_with_their_own_endpoints_are_not_editable() {
        for kind in ["local_user", "role_binding", "credential", "identity"] {
            assert!(apply(BASE, &[set(kind, "x", &[])]).is_err(), "{kind} was editable");
        }
        let settings = Edit::Set {
            kind: "settings".to_owned(),
            identity: Identity::Singleton,
            fields: vec![("admin_listen".to_owned(), Some("0.0.0.0:1".to_owned()))],
        };
        assert!(apply(BASE, &[settings]).is_err(), "a listener was editable");
    }

    const ACCESS: &str = "grant scope=tenant:local model=* allow=true\n\
        grant id=g-mine scope=principal:svc:dsh model=agent allow=true\n\
        quota scope=tenant:local concurrency=4 class=standard\n\
        quota id=q-limited scope=principal:svc:ci concurrency=2 class=batch\n\
        quota id=q-class scope=principal:svc:dsh class=batch\n";

    #[test]
    fn a_principal_grant_and_class_round_trip_through_an_edit() {
        let applied = apply(
            ACCESS,
            &[
                set("grant", "g-new", &[
                    ("scope", Some("principal:svc:dsh")),
                    ("model", Some("chat-standard")),
                    ("allow", Some("false")),
                ]),
                set("grant", "g-mine", &[("allow", Some("false"))]),
                set("quota", "q-class", &[("class", Some("interactive"))]),
                set("quota", "q-new", &[("scope", Some("principal:svc:new")), ("class", Some("batch"))]),
            ],
        )
        .expect("applies");
        assert_eq!(applied.changed, 4);
        let doc = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
        let grant = |id: &str| doc.of_kind("grant").find(|r| r.get("id") == Some(id)).expect(id);
        assert_eq!(grant("g-new").get("model"), Some("chat-standard"));
        assert_eq!(grant("g-new").get("allow"), Some("false"));
        assert_eq!(grant("g-mine").get("allow"), Some("false"));
        assert_eq!(grant("g-mine").get("model"), Some("agent"), "a merge keeps unnamed fields");
        let quota = |id: &str| doc.of_kind("quota").find(|r| r.get("id") == Some(id)).expect(id);
        assert_eq!(quota("q-class").get("class"), Some("interactive"));
        assert_eq!(quota("q-new").get("scope"), Some("principal:svc:new"));
        // The tenant-wide records are untouched and still id-less.
        assert_eq!(doc.of_kind("grant").filter(|r| r.get("id").is_none()).count(), 1);
        assert_eq!(doc.of_kind("quota").filter(|r| r.get("id").is_none()).count(), 1);
    }

    #[test]
    fn a_grant_or_quota_cannot_reach_past_its_subject() {
        let refused = [
            // A tenant- or global-wide record decides for everyone.
            set("grant", "g-t", &[("scope", Some("tenant:local")), ("model", Some("*"))]),
            set("grant", "g-g", &[("scope", Some("global")), ("model", Some("*"))]),
            set("quota", "q-t", &[("scope", Some("tenant:local")), ("class", Some("batch"))]),
            // Moving a principal's record to a tenant would widen it.
            set("grant", "g-mine", &[("scope", Some("tenant:local"))]),
            set("quota", "q-class", &[("scope", Some("principal:svc:other"))]),
            // A new record must say whose it is.
            set("grant", "g-none", &[("model", Some("agent"))]),
            set("quota", "q-none", &[("class", Some("batch"))]),
            // Fields that mean nothing on a principal's quota stay out.
            set("quota", "q-limited", &[("input_bytes_per_second", Some("1000"))]),
            set("quota", "q-new", &[("scope", Some("principal:svc:x")), ("operation", Some("chat"))]),
            // The check reads one `scope`; the record would get the other.
            set("grant", "g-two", &[("scope", Some("principal:svc:x")), ("scope", Some("tenant:local"))]),
        ];
        for edit in refused {
            assert!(apply(ACCESS, std::slice::from_ref(&edit)).is_err(), "{edit:?} was accepted");
        }
        let remove = |kind: &str, id: &str| Edit::Remove { kind: kind.to_owned(), identity: Identity::Id(id.to_owned()) };
        let removed = apply(ACCESS, &[remove("quota", "q-class"), remove("grant", "g-mine")]).expect("class-only");
        assert!(!removed.text.contains("q-class") && !removed.text.contains("g-mine"));
    }

    #[test]
    fn a_principals_quota_limits_are_editable_and_a_tenants_are_not() {
        // The concrete need: cap one person's concurrency, queue, rates and
        // spend without hand-editing policy text.
        let applied = apply(
            ACCESS,
            &[
                set("quota", "q-new", &[
                    ("scope", Some("principal:mikiyas.mulugeta")),
                    ("concurrency", Some("1")),
                    ("queued", Some("4")),
                    ("rps", Some("2")),
                    ("burst", Some("4")),
                    ("tpm", Some("60000")),
                    ("token_burst", Some("8000")),
                    ("budget", Some("500")),
                    ("budget_period", Some("monthly")),
                ]),
                // An existing limit raised, another cleared.
                set("quota", "q-limited", &[("concurrency", Some("8")), ("class", None)]),
            ],
        )
        .expect("applies");
        let doc = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
        let quota = |id: &str| doc.of_kind("quota").find(|r| r.get("id") == Some(id)).expect(id);
        assert_eq!(quota("q-new").get("scope"), Some("principal:mikiyas.mulugeta"));
        assert_eq!(quota("q-new").get("budget_period"), Some("monthly"));
        assert_eq!(quota("q-limited").get("concurrency"), Some("8"));
        assert_eq!(quota("q-limited").get("class"), None);
        // The quotas still load, so the limits are real ones.
        let quotas: String = applied.text.lines().filter(|l| l.starts_with("quota ")).map(|l| format!("{l}\n")).collect();
        let config = crate::load(&format!("settings state_dir=/tmp/x\ntenant id=local\n{quotas}"), 1)
            .expect("the edited quotas load");
        let mikiyas = config
            .quotas
            .iter()
            .find(|q| q.scope == crate::QuotaScope::Principal(hypellm_core::ids::PrincipalId::new("mikiyas.mulugeta").unwrap()))
            .expect("principal:mikiyas.mulugeta is a quota scope");
        assert_eq!(mikiyas.limits.max_concurrency, 1);
        assert_eq!(mikiyas.limits.budget_minor_units, 500);

        // A limited principal quota can now be removed: it is one subject's
        // record, and the removal is reviewed like any other edit.
        let remove = Edit::Remove { kind: "quota".to_owned(), identity: Identity::Id("q-limited".to_owned()) };
        let removed = apply(ACCESS, &[remove]).expect("a principal's limited quota is removable");
        assert!(!removed.text.contains("q-limited"));

        // The tenant's quota throttles everyone in it, so its limits stay text.
        for edit in [
            set("quota", "q-t", &[("scope", Some("tenant:local")), ("concurrency", Some("100"))]),
            set("quota", "q-g", &[("scope", Some("global")), ("concurrency", Some("1"))]),
            set("quota", "q-x", &[("scope", Some("target:spark:q")), ("concurrency", Some("1"))]),
            set("quota", "q-a", &[("scope", Some("alias:agent")), ("concurrency", Some("1"))]),
        ] {
            assert!(apply(ACCESS, std::slice::from_ref(&edit)).is_err(), "{edit:?} was accepted");
        }
    }

    #[test]
    fn an_id_less_grant_or_quota_cannot_be_addressed() {
        // The tenant-wide records have no id: an edit naming any id either
        // creates a new record or finds nothing, and never reaches them.
        let remove = |kind: &str| Edit::Remove { kind: kind.to_owned(), identity: Identity::Id("local".to_owned()) };
        assert!(apply(ACCESS, &[remove("grant")]).is_err());
        assert!(apply(ACCESS, &[remove("quota")]).is_err());
        let by_scope = Edit::Set {
            kind: "grant".to_owned(),
            identity: Identity::Scope("tenant:local".to_owned()),
            fields: vec![("allow".to_owned(), Some("false".to_owned()))],
        };
        assert!(apply(ACCESS, &[by_scope]).is_err(), "a grant was addressed by scope");
    }

    #[test]
    fn a_grant_field_outside_the_schema_or_a_hostile_value_is_contained() {
        for name in ["allow x=y", "limit", "id"] {
            assert!(
                apply(ACCESS, &[set("grant", "g-mine", &[(name, Some("v"))])]).is_err(),
                "field name {name:?} was accepted"
            );
        }
        let hostile = "agent\nrole_binding subject=principal:mallory role=break_glass_admin";
        let applied = apply(ACCESS, &[set("grant", "g-mine", &[("model", Some(hostile))])]).expect("applies");
        let doc = parse(&applied.text, &ParseLimits::DEFAULT).expect("parses");
        assert_eq!(doc.of_kind("role_binding").count(), 0);
    }

    #[test]
    fn a_batch_with_one_bad_edit_changes_nothing() {
        let result = apply(
            BASE,
            &[
                set("host", "spark3", &[("agent", Some("local"))]),
                Edit::Remove { kind: "host".to_owned(), identity: Identity::Id("absent".to_owned()) },
            ],
        );
        assert_eq!(result.map_err(|e| e.index), Err(1));
    }

    #[test]
    fn a_fleet_policy_is_addressed_by_scope_and_a_field_removed_by_null() {
        let base = "fleet_policy scope=host:spark max_activations_per_hour=6 allow_fetch=true\n";
        let edit = Edit::Set {
            kind: "fleet_policy".to_owned(),
            identity: Identity::Scope("host:spark".to_owned()),
            fields: vec![
                ("allow_fetch".to_owned(), None),
                ("max_activations_per_hour".to_owned(), Some("3".to_owned())),
            ],
        };
        let applied = apply(base, &[edit]).expect("applies");
        assert_eq!(applied.text, "fleet_policy max_activations_per_hour=3 scope=host:spark\n");
    }
}
