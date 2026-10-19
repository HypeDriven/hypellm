//! `GET /admin/v1/jobs`: the job queue, as an operator sees it
//! (orchestration §11.9).
//!
//! # Why this is a trait rather than a direct dependency
//!
//! The job store and its workers live in the router, which depends on this
//! crate rather than the other way round — the shape `FleetControl` and
//! `CredentialSink` already use for the same reason.
//!
//! # What it reveals, and to whom
//!
//! A caller's own tenant only, and only with `read_tenant_usage`: who is
//! waiting, at which class and round, for which alias, and why. The queue's
//! order between tenants, and anything about another tenant's work, is not
//! reachable from here. Prompts are never part of a job's listing.

use hypellm_core::admission::PriorityClass;
use hypellm_core::ids::{AliasId, PrincipalId, TenantId};
use wire_json::{Object, Value};

/// One job in the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedJob {
    /// Its identifier.
    pub id: String,
    /// Who submitted it.
    pub principal: PrincipalId,
    /// The alias it asked for.
    pub alias: AliasId,
    /// Its priority class, stamped at submission.
    pub class: PriorityClass,
    /// How many of its principal's jobs of the same class were already waiting
    /// when it was submitted.
    pub round: u32,
    /// `running` once its pass holds its reservations, otherwise `queued`.
    pub state: &'static str,
    /// While queued, why: `turn`, `slot`, `activation` or `backoff`.
    pub waiting_for: Option<&'static str>,
    /// When it was submitted, in wall milliseconds.
    pub created_ms: u64,
}

impl QueuedJob {
    /// The JSON object for one row, its age measured at `now_wall_ms`.
    #[must_use]
    pub fn to_json(&self, now_wall_ms: u64) -> Value {
        let mut object = Object::new();
        object.push("job_id", Value::from(self.id.as_str()));
        object.push("principal", Value::from(self.principal.as_str()));
        object.push("alias", Value::from(self.alias.as_str()));
        object.push("class", Value::from(self.class.as_str()));
        object.push("round", Value::from(u64::from(self.round)));
        object.push("state", Value::from(self.state));
        object.push_opt("waiting_for", self.waiting_for.map(Value::from));
        object.push("created_ms", Value::from(self.created_ms));
        object.push("age_ms", Value::from(now_wall_ms.saturating_sub(self.created_ms)));
        Value::Object(object)
    }
}

/// The router's job queue, read-only.
pub trait JobQueue: Send + Sync + std::fmt::Debug {
    /// One tenant's jobs that have not finished: running first, then queued
    /// in class and share order. Model locality may still reorder queued jobs
    /// within a class when a worker takes one, which this order does not
    /// predict.
    fn queue(&self, tenant: &TenantId) -> Vec<QueuedJob>;
}
