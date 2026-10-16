//! Slave enrollment, where it meets the store and the wire (specification
//! 26.8).
//!
//! The record, its state machine and the registration parser are
//! `hypellm_fleet::enroll`, which is pure. This module is the journal that
//! makes a record durable, the restore that replays them, the JSON an
//! administrator reads, and the install script the router serves.
//!
//! The handlers themselves are in `handlers.rs`, beside every other
//! management handler, so the authentication gate in front of them is the
//! same code — with the one deliberate exception of the two public
//! `/fleet/v1/` endpoints, which a slave reaches with nothing but its token.

use hypellm_fleet::enroll::{
    EnrollError, Enrollment, EnrollmentJournal, EnrollmentRegistry, JournalError,
    decode_enrollment, encode_enrollment, registration_value,
};
use hypellm_store::{RecordKind, Recovery, Store};
use std::sync::Arc;
use wire_json::{Object, Value};

use crate::response::{ApiError, ApiErrorCode};

/// The install script a slave runs, served at `GET /fleet/v1/install.sh`.
///
/// Compiled into the binary rather than read from disk: the router serves
/// exactly the script this build was tested with, there is no path to get
/// wrong, and the version the script embeds is the one the router reports.
pub const INSTALL_SCRIPT: &str = include_str!("../../../host/install.sh");

/// Commits enrollment records as [`RecordKind::FleetEnrollment`].
#[derive(Debug)]
pub struct StoreJournal {
    store: Arc<Store>,
}

impl StoreJournal {
    /// A journal over `store`.
    #[must_use]
    pub const fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl EnrollmentJournal for StoreJournal {
    fn commit(&self, record: &Enrollment) -> Result<(), JournalError> {
        self.store
            .append(RecordKind::FleetEnrollment, &encode_enrollment(record))
            .map(|_| ())
            .map_err(|_| JournalError)
    }
}

/// A registry backed by `store`, with every enrollment in `recovery` applied.
///
/// Returns the registry and how many frames could not be read. An unreadable
/// frame has passed the store's MAC, so it is a record this build does not
/// understand rather than tampering; it is skipped and counted.
#[must_use]
pub fn restore(store: &Arc<Store>, recovery: &Recovery) -> (Arc<EnrollmentRegistry>, usize) {
    let registry = Arc::new(EnrollmentRegistry::new(Arc::new(StoreJournal::new(
        Arc::clone(store),
    ))));
    let mut unreadable = 0_usize;
    for frame in &recovery.frames {
        if frame.kind != RecordKind::FleetEnrollment {
            continue;
        }
        match decode_enrollment(&frame.payload) {
            Some(record) => registry.restore(record),
            None => unreadable = unreadable.saturating_add(1),
        }
    }
    (registry, unreadable)
}

/// The command an administrator pastes on the new machine.
///
/// Every part is from a validated source — the origin from configuration
/// (`hypellm_config::enroll_origin`), the token hex, the version a constant —
/// so nothing in it needs quoting and nothing in it can end an argument.
#[must_use]
pub fn install_command(origin: &str, token: &str) -> String {
    format!(
        "curl -fsSL {origin}/fleet/v1/install.sh | sh -s -- --router {origin} --token {token} \
         --version {}",
        hypellm_fleet::enroll::HOST_KIT_VERSION
    )
}

/// An enrollment as the dashboard shows it: fingerprints, never key material,
/// and never anything derived from the token.
#[must_use]
pub fn enrollment_value(enrollment: &Enrollment, now_ms: u64) -> Value {
    let mut object = Object::new();
    object.push("id", Value::from(enrollment.id.as_str()));
    object.push("host", Value::from(enrollment.host.as_str()));
    object.push("agent", Value::from(enrollment.agent.as_str()));
    object.push("state", Value::from(enrollment.state_at(now_ms).as_str()));
    object.push("issued_by", Value::from(enrollment.issued_by.as_str()));
    object.push("issued_at", Value::from(enrollment.issued_at_ms));
    object.push("expires_at", Value::from(enrollment.expires_at_ms));
    object.push_opt("registered_at", enrollment.registered_at_ms.map(Value::from));
    object.push_opt(
        "decided_by",
        enrollment.decided_by.as_deref().map(Value::from),
    );
    object.push_opt("decided_at", enrollment.decided_at_ms.map(Value::from));
    object.push_opt("draft", enrollment.draft.as_deref().map(Value::from));
    object.push(
        "registration",
        enrollment
            .registration
            .as_ref()
            .map_or(Value::Null, |r| registration_value(r, false)),
    );
    Value::Object(object)
}

/// Map a registry refusal onto a stable API error.
#[must_use]
pub fn enroll_error(error: EnrollError) -> ApiError {
    match error {
        EnrollError::Unknown => ApiError::not_found("enrollment"),
        // One answer for every token failure, so a caller cannot tell a spent
        // token from one that never existed.
        EnrollError::InvalidToken => ApiError::new(
            ApiErrorCode::Unauthenticated,
            "this enrollment token is not valid; ask an administrator for a new one",
        ),
        EnrollError::Throttled => ApiError::new(
            ApiErrorCode::TooManyRequests,
            "too many invalid enrollment attempts; wait a minute and retry",
        ),
        EnrollError::TooMany => ApiError::new(
            ApiErrorCode::Conflict,
            "too many enrollments are open; reject or finish some first",
        ),
        EnrollError::HostTaken => ApiError::new(
            ApiErrorCode::Conflict,
            "an open or approved enrollment already names this host",
        ),
        EnrollError::WrongState => ApiError::new(
            ApiErrorCode::Conflict,
            "the enrollment is not in a state that permits this action",
        ),
        EnrollError::Journal => ApiError::new(
            ApiErrorCode::InternalFault,
            "the enrollment could not be recorded durably and was not changed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_served_script_embeds_the_version_the_router_reports() {
        // The script refuses a `--version` that differs from its own, and the
        // router prints this version in every command it mints; if the two
        // drifted, every pasted command would fail.
        let line = format!(
            "HOST_KIT_VERSION=\"{}\"",
            hypellm_fleet::enroll::HOST_KIT_VERSION
        );
        assert!(INSTALL_SCRIPT.contains(&line), "install.sh lacks {line}");
        assert!(INSTALL_SCRIPT.starts_with("#!/bin/sh\n"));
    }

    #[test]
    fn the_command_is_one_line_of_unquoted_safe_words() {
        let command = install_command(
            "https://router.example.ts.net",
            &"a".repeat(64),
        );
        assert!(command.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
        assert!(!command.contains('\''));
        assert!(!command.contains('"'));
        assert!(command.contains("--version 1.1.0"));
    }
}
