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
//! Only the record kinds a routing or fleet screen needs are editable. Keys,
//! credentials, local users, role bindings and quotas are not: each has its
//! own endpoint with its own checks, and an edit here must not become a way
//! around them.

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
    "settings",
];

/// The `settings` fields an edit may touch. The rest of `settings` governs
/// listeners, identity and limits, and belongs to the policy text itself.
pub const EDITABLE_SETTINGS: &[&str] = &["fleet_enabled"];

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
        let position = find(&document, kind, identity);

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
        for kind in ["local_user", "role_binding", "credential", "quota", "grant", "identity"] {
            assert!(apply(BASE, &[set(kind, "x", &[])]).is_err(), "{kind} was editable");
        }
        let settings = Edit::Set {
            kind: "settings".to_owned(),
            identity: Identity::Singleton,
            fields: vec![("admin_listen".to_owned(), Some("0.0.0.0:1".to_owned()))],
        };
        assert!(apply(BASE, &[settings]).is_err(), "a listener was editable");
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
