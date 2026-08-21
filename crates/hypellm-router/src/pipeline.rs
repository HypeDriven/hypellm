//! The request lifecycle.
//!
//! Specification 3.1 numbers the steps; this module is steps 4 through 8:
//!
//! ```text
//! 4. resolve alias, compute eligible targets
//! 5. rank, reserve capacity atomically, attach a decision identifier
//! 6. serialize, send, stream with bounded buffers and cancellation
//! 7. normalize usage, errors, finish reasons, tool calls, stream events
//! 8. commit metering and a redacted audit record; release reservations once
//! ```
//!
//! # Routing happens once
//!
//! The ranked candidate list is computed once per request and the retry loop
//! walks it. Re-routing between attempts would evaluate a *different* policy
//! snapshot if a reload landed mid-request, and Appendix B requires that equal
//! inputs produce equal ordered candidates — including across the attempts of
//! one request. The snapshot a request starts under is the snapshot it
//! finishes under.
//!
//! # Reservations
//!
//! Appendix B: "Every successful selection owns an admission reservation before
//! outbound I/O" and "Every reservation is released exactly once". A
//! reservation is taken immediately before an attempt and committed or dropped
//! immediately after, so a failed attempt returns its capacity before the next
//! one asks for any.

use hypellm_adapters::adapter_for;
use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::decision::{Attempt, AttemptOutcome, DecisionTrace, ExclusionReason};
use hypellm_core::error::{ErrorCode, RouterError};
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::{GroupId, TargetId};
use hypellm_core::policy::RoutingContext;
use hypellm_core::target::ProviderFamily;
use hypellm_core::time::Deadline;
use std::time::Duration;

use crate::dispatch::{self, AttemptFailure, AttemptSummary, EventSink};
use crate::state::RouterState;

/// What the pipeline produced.
#[derive(Debug)]
pub struct Outcome {
    /// The redacted decision trace.
    pub trace: DecisionTrace,
    /// The successful attempt's summary, if one succeeded.
    pub summary: Option<AttemptSummary>,
    /// The error to report, if none succeeded.
    pub error: Option<RouterError>,
    /// Whether semantic output reached the client.
    ///
    /// Once true, the caller must not send an error body: the response has
    /// already begun (specification 6.5).
    pub saw_output: bool,
}

impl Outcome {
    /// Whether the request succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.error.is_none()
    }
}

/// Execute a request end to end.
///
/// `permissions` are the principal's, and are consulted for exactly two
/// things: whether this caller may cause a deployment to start, and whether
/// they may cause an artifact to be fetched. Neither is permission to *reach* a
/// model — that is the alias grant, unchanged — and a caller without them
/// still uses whatever is already warm.
pub fn execute(
    state: &RouterState,
    request: &CanonicalRequest,
    groups: &[GroupId],
    permissions: hypellm_core::rbac::PermissionSet,
    sink: &mut dyn EventSink,
) -> Outcome {
    let clock = state.clock.as_ref();
    // Specification 19 budgets the *whole* router overhead at 2 ms p50. The
    // millisecond clock that governs deadlines cannot resolve that, so routing
    // is measured on the microsecond source instead.
    let started_micros = clock.now_micros();
    let config = state.config();
    let snapshot = &config.snapshot;

    let attempted: Vec<TargetId> = Vec::new();
    let context = RoutingContext {
        principal: &request.principal,
        groups,
        tenant: &request.tenant,
        attempted: &attempted,
        now_millis: clock.now_millis(),
    };

    // Sampled once, before routing, and borrowed for the whole decision. A
    // second sample could classify a target one way for the filter and another
    // for the score.
    let fleet_view = state.fleet_view(request, &permissions);
    let live = crate::fleet::FleetAwareLiveState::new(state.health.as_ref(), &fleet_view);
    let route = snapshot.route(&context, request, &live);

    let mut trace = DecisionTrace {
        request_id: request.request_id,
        policy_digest: snapshot.digest,
        candidates: route.candidates.clone(),
        exclusions: route.exclusions.clone(),
        chosen: None,
        attempts: Vec::new(),
        routing_micros: clock.now_micros().saturating_sub(started_micros),
        pinned: route.pinned,
    };

    if route.candidates.is_empty() {
        return Outcome {
            error: Some(no_candidate_error(&route.exclusions, snapshot, request)),
            trace,
            summary: None,
            saw_output: false,
        };
    }

    let idempotent = request.hints.idempotency_key.is_some();
    let max_attempts = config.settings.max_attempts.max(1);
    let retry_budget = Deadline::after(
        clock,
        Duration::from_millis(config.settings.retry_budget_ms),
    );
    let overall = request.limits.deadline.min(retry_budget);
    let queue_timeout_ms = config.settings.queue_timeout_ms;

    let mut last_failure: Option<AttemptFailure> = None;
    let mut saw_output = false;

    // Specification 6.5: "A model-family change must be explicitly allowed in
    // the alias failover policy."
    //
    // The policy engine also carries this check, but it is reachable only when
    // routing is given a non-empty attempted list, and routing runs once per
    // request with an empty one. Failover happens here, in the retry loop, so
    // the constraint is enforced here — against the family of the first target
    // actually dispatched to, which is the point the request became associated
    // with a model family.
    let allow_family_failover = snapshot
        .aliases
        .get(&request.requested_model)
        .is_none_or(|alias| alias.allow_family_failover);
    let mut first_family: Option<ProviderFamily> = None;

    for (sequence, candidate) in route.candidates.iter().enumerate() {
        if sequence >= usize::try_from(max_attempts).unwrap_or(usize::MAX) {
            break;
        }
        if overall.is_expired(clock) {
            // The deadline is terminal: whatever the last failure was, the
            // caller is told the request ran out of time.
            trace.attempts.push(Attempt {
                target: candidate.target.clone(),
                sequence: u16::try_from(sequence).unwrap_or(u16::MAX),
                first_byte_millis: None,
                total_millis: 0,
                outcome: AttemptOutcome::DeadlineExceeded,
            });
            return Outcome {
                error: Some(RouterError::new(
                    ErrorCode::DeadlineExceeded,
                    "the request deadline expired before a provider responded",
                )),
                trace,
                summary: None,
                saw_output,
            };
        }

        let Some(target) = snapshot.targets.get(&candidate.target) else {
            continue;
        };
        let Some(provider) = snapshot.providers.get(&target.provider_id) else {
            continue;
        };

        if !allow_family_failover && first_family.is_some_and(|f| f != provider.family) {
            trace.exclusions.push(hypellm_core::decision::Exclusion {
                target: target.id.clone(),
                reason: ExclusionReason::FamilyFailoverNotAllowed,
            });
            continue;
        }

        // The breaker gate. A half-open breaker admits a limited probe here and
        // is told the outcome below, which is what advances its state machine.
        let health = state.health.entry(&target.id, request.operation);
        if !health.breaker.try_admit(clock.now_millis()) {
            trace.exclusions.push(hypellm_core::decision::Exclusion {
                target: target.id.clone(),
                reason: ExclusionReason::CircuitOpen,
            });
            continue;
        }

        // Specification 12's Global-layer input byte rate (`DI-053`), checked
        // before the reservation so an exhausted byte budget refuses with no
        // narrower bookkeeping to unwind. This catches what a request-rate
        // limit cannot: a modest number of very large requests.
        // `max_body_bytes` bounds any one of them and the request rate bounds
        // how many arrive, but neither bounds their product.
        if let Err(rejection) = state.admission.try_admit_bytes(
            u64::try_from(request.input_byte_len()).unwrap_or(u64::MAX),
            clock.now_millis(),
        ) {
            trace.exclusions.push(hypellm_core::decision::Exclusion {
                target: target.id.clone(),
                reason: rejection.exclusion_reason(),
            });
            continue;
        }

        // Reserve before any outbound I/O (Appendix B).
        let estimate = request.estimated_total_tokens();
        // Specification 3.2 makes a queue timeout mandatory, and specification
        // 12 removes requests past their deadline "without invoking the
        // provider" — so the wait is the smaller of the two, and a request that
        // has already run out of deadline waits not at all.
        let queue_budget = std::time::Duration::from_millis(queue_timeout_ms)
            .min(overall.remaining(clock));
        let class = state
            .admission
            .class_for(&request.tenant, &request.principal);
        // The alias, not just the resolved target: specification 12's
        // "Alias/model" layer limits what the caller asked for, which is the
        // thing they control. A limit attached only to targets would be spread
        // across however many the alias resolves to.
        let reserved = state.admission.reserve_queued_for(
            &request.tenant,
            &request.principal,
            Some((&request.requested_model, request.operation)),
            &target.id,
            estimate,
            class,
            queue_budget,
        );
        let reservation = match reserved {
            Ok((reservation, waited_millis)) => {
                if waited_millis > 0 {
                    state.telemetry.metrics.histogram_observe(
                        hypellm_telemetry::names::QUEUE_WAIT_MS,
                        "Time spent waiting in the admission queue.",
                        &hypellm_telemetry::Labels::one(
                            hypellm_telemetry::LabelName::Target,
                            target.id.as_str(),
                        ),
                        waited_millis,
                    );
                }
                publish_queue_depth(state, &target.id);
                reservation
            }
            Err((rejection, scope)) => {
                publish_queue_depth(state, &target.id);
                trace.exclusions.push(hypellm_core::decision::Exclusion {
                    target: target.id.clone(),
                    reason: rejection.exclusion_reason(),
                });
                state.telemetry.count(
                    hypellm_telemetry::names::ADMISSION_REJECTIONS,
                    "Admission rejections by scope and reason.",
                    &hypellm_telemetry::Labels::new()
                        .with(hypellm_telemetry::LabelName::Scope, &scope)
                        .with(hypellm_telemetry::LabelName::Reason, rejection.as_str()),
                );
                last_failure = Some(AttemptFailure {
                    phase: dispatch::AttemptPhase::BeforeAcceptance,
                    class: hypellm_core::event::UpstreamErrorClass::RateLimited,
                    error: RouterError::new(
                        rejection.error_code(),
                        "the request exceeded a configured capacity or rate limit",
                    ),
                    provider_code: None,
                });
                continue;
            }
        };

        // The fleet step, placed here deliberately: after the admission
        // reservation and before any outbound I/O. Evicting a running model and
        // *then* discovering the tenant is over quota is exactly the unforced
        // error Appendix B's ordering exists to prevent.
        //
        // Activation failure is strictly before upstream acceptance, so
        // specification 6.5 failover applies unchanged and the no-splice rule
        // is untouched: the loop simply moves to the next candidate.
        if candidate.residency == hypellm_core::decision::ResidencyClass::Activating {
            // Somebody else already paid for this swap; this request rides on
            // it rather than dispatching into a model that has not finished
            // loading. This is what turns a burst of ten requests into one
            // activation *and* ten served requests, rather than one activation
            // and nine failovers.
            if let Err(reason) = wait_for(state, request, candidate, overall) {
                trace.exclusions.push(hypellm_core::decision::Exclusion {
                    target: target.id.clone(),
                    reason,
                });
                drop(reservation);
                continue;
            }
        } else if candidate.residency.requires_activation() {
            match activate_for(state, request, &fleet_view, candidate, overall) {
                Ok(()) => {}
                Err(reason) => {
                    trace.exclusions.push(hypellm_core::decision::Exclusion {
                        target: target.id.clone(),
                        reason,
                    });
                    // The reservation is dropped here, on this path as on every
                    // other, before the next candidate asks for capacity.
                    drop(reservation);
                    last_failure = Some(AttemptFailure {
                        phase: dispatch::AttemptPhase::BeforeAcceptance,
                        class: hypellm_core::event::UpstreamErrorClass::Connection,
                        // Deliberately vague: "capability unavailable", and not
                        // a word about which host, which accelerator, or what
                        // else is loaded there.
                        error: RouterError::new(
                            ErrorCode::NoEligibleTarget,
                            "the requested capability is not available",
                        ),
                        provider_code: None,
                    });
                    continue;
                }
            }
        }

        // Recorded before dispatch: the request is bound to this family from
        // the moment an attempt is made against it, whether or not it succeeds.
        first_family.get_or_insert(provider.family);

        health.enter();
        // Specification 17 lists active streams among the required signals.
        // Bracketed around the dispatch itself rather than around the request,
        // because the number an operator needs is how many upstream exchanges
        // are open right now — a request queued behind admission is not one.
        let streaming = request.stream.enabled;
        let by_target =
            hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Target, target.id.as_str());
        if streaming {
            state.telemetry.metrics.gauge_add(
                hypellm_telemetry::names::ACTIVE_STREAMS,
                "Upstream streams currently open, by target.",
                &by_target,
                1,
            );
        }
        let adapter = adapter_for(provider.family);
        let mut result = dispatch::attempt(
            state,
            request,
            target,
            provider,
            adapter,
            overall,
            sink,
        );

        // Specification 22.2 step 16's bounded overlap. A rotation performed
        // before the provider activated the new secret would otherwise take the
        // target out of service until somebody noticed; inside the window the
        // superseded secret carries the request instead.
        //
        // Deliberately narrow, because a fallback that quietly works is how a
        // bad rotation stays invisible until the window closes and everything
        // fails at once, uncorrelated with the change that caused it:
        //
        // - only on an authentication failure, and only *before acceptance*, so
        //   nothing has reached the client and no inference was billed;
        // - only once, and only if a superseded secret is still live;
        // - every use is a `critical` log event and sets `rotation_unaccepted`
        //   on the credential listing, so the operator is told that their new
        //   credential is not being accepted rather than left to find out.
        let mut served_by_superseded = false;
        if let Err(failure) = &result {
            if failure.class == hypellm_core::event::UpstreamErrorClass::Authentication
                && failure.phase == dispatch::AttemptPhase::BeforeAcceptance
                && provider.credential_ref.is_some()
            {
                let retried = dispatch::attempt_with(
                    state,
                    request,
                    target,
                    provider,
                    adapter,
                    overall,
                    sink,
                    dispatch::CredentialChoice::Superseded,
                );
                if retried.is_ok() {
                    state.telemetry.log(
                        &hypellm_telemetry::Event::critical("credential.rotation_unaccepted")
                            .str_field(
                                hypellm_telemetry::Field::Detail,
                                "the provider refused the rotated credential; the superseded \
                                 one is carrying requests until its overlap window closes",
                            )
                            .str_field(
                                hypellm_telemetry::Field::Target,
                                target.id.as_str(),
                            ),
                    );
                    state.telemetry.count(
                        hypellm_telemetry::names::CREDENTIAL_FALLBACKS,
                        "Requests served with a superseded credential after a rotation.",
                        &hypellm_telemetry::Labels::one(
                            hypellm_telemetry::LabelName::Target,
                            target.id.as_str(),
                        ),
                    );
                    result = retried;
                    served_by_superseded = true;
                }
            }
        }

        // A success with the *current* secret retires the superseded one at
        // once, so in a healthy rotation the window lasts one request and
        // nothing above ever fires.
        //
        // Only the current one: retiring after a fallback success would discard
        // the secret that just carried the request and close the window on its
        // first use, which is the opposite of a bounded overlap.
        if result.is_ok() && !served_by_superseded {
            if let Some(reference) = &provider.credential_ref {
                state.credentials.retire_superseded(reference);
            }
        }
        if streaming {
            // Decremented on every path out of the dispatch — success, error,
            // timeout, cancellation — for the same reason a reservation is
            // released on every path: a gauge that only counts up is worse than
            // no gauge, because it reads as load that is not there.
            state.telemetry.metrics.gauge_add(
                hypellm_telemetry::names::ACTIVE_STREAMS,
                "Upstream streams currently open, by target.",
                &by_target,
                -1,
            );
        }
        health.exit();

        match result {
            Ok(summary) => {
                saw_output |= summary.saw_output;
                // Reconcile the estimate against what the provider reported
                // (specification 12).
                let actual = summary.usage.total();
                // Reserved minus reconciled, which is what validates the
                // effort multipliers and the per-document constants against
                // reality. Labelled by what made the estimate hard: a request
                // with documents and one with a reasoning tier over-estimate
                // for different reasons, and an operator tuning one needs to
                // see it separately from the other.
                //
                // Only the over-estimate is recorded, because that is the
                // direction the estimator is *supposed* to err in; an
                // under-estimate would mean a request slipped past a quota,
                // which is a defect rather than a tuning signal.
                let source = if request.document_parts() > 0 {
                    "document"
                } else if request.reasoning_effort
                    != hypellm_core::canonical::ReasoningEffort::Unset
                {
                    "effort"
                } else {
                    "base"
                };
                state.telemetry.metrics.histogram_observe(
                    hypellm_telemetry::names::TOKEN_ESTIMATE_ERROR,
                    "Reserved minus reconciled tokens, when the estimate was high.",
                    &hypellm_telemetry::Labels::one(
                        hypellm_telemetry::LabelName::UsageSource,
                        source,
                    ),
                    estimate.saturating_sub(actual),
                );
                reservation.commit(actual);
                health.record_success(
                    summary.first_byte_millis.unwrap_or(0),
                    summary.total_millis,
                    clock.now_millis(),
                );
                publish_breaker_state(state, &health, &target.id, clock.now_millis());
                trace.attempts.push(Attempt {
                    target: target.id.clone(),
                    sequence: u16::try_from(sequence).unwrap_or(u16::MAX),
                    first_byte_millis: summary.first_byte_millis,
                    total_millis: summary.total_millis,
                    outcome: AttemptOutcome::Success,
                });
                trace.chosen = Some(target.id.clone());
                return Outcome {
                    trace,
                    summary: Some(summary),
                    error: None,
                    saw_output,
                };
            }
            Err(failure) => {
                // Drop returns the estimate; nothing was consumed.
                drop(reservation);
                health.record_failure(failure.class, clock.now_millis());
                publish_breaker_state(state, &health, &target.id, clock.now_millis());

                let outcome = match failure.phase {
                    dispatch::AttemptPhase::BeforeAcceptance => {
                        AttemptOutcome::FailedBeforeAcceptance(failure.class)
                    }
                    dispatch::AttemptPhase::AfterAcceptance => {
                        AttemptOutcome::FailedAfterAcceptance(failure.class)
                    }
                    dispatch::AttemptPhase::AfterOutput => {
                        saw_output = true;
                        AttemptOutcome::FailedAfterOutput(failure.class)
                    }
                };
                trace.attempts.push(Attempt {
                    target: target.id.clone(),
                    sequence: u16::try_from(sequence).unwrap_or(u16::MAX),
                    first_byte_millis: None,
                    total_millis: 0,
                    outcome,
                });

                state.telemetry.count(
                    hypellm_telemetry::names::UPSTREAM_ERRORS,
                    "Upstream errors by class.",
                    &hypellm_telemetry::Labels::new()
                        .with(hypellm_telemetry::LabelName::Target, target.id.as_str())
                        .with(hypellm_telemetry::LabelName::Reason, failure.class.as_str()),
                );

                let may_retry = failure.may_failover(idempotent);
                let error = failure.error.clone();
                last_failure = Some(failure);
                if !may_retry {
                    return Outcome {
                        trace,
                        summary: None,
                        error: Some(error),
                        saw_output,
                    };
                }
                state.telemetry.count(
                    hypellm_telemetry::names::RETRIES_TOTAL,
                    "Retries and failovers.",
                    &hypellm_telemetry::Labels::one(
                        hypellm_telemetry::LabelName::Target,
                        target.id.as_str(),
                    ),
                );
            }
        }
    }

    let error = last_failure.map_or_else(
        || {
            RouterError::new(
                ErrorCode::NoEligibleTarget,
                "no target met the policy, health, and capability requirements",
            )
        },
        |f| f.error,
    );

    Outcome {
        trace,
        summary: None,
        error: Some(error),
        saw_output,
    }
}

/// Choose the error for a request that produced no candidate at all.
///
/// The distinction matters to a caller: an alias they are not authorized for
/// must look the same as one that does not exist (specification 8.2's
/// `model_not_found`: "Alias absent **or hidden for caller**"), while a
/// genuine capacity or health problem is a 503.
fn no_candidate_error(
    exclusions: &[hypellm_core::decision::Exclusion],
    snapshot: &hypellm_core::policy::PolicySnapshot,
    request: &CanonicalRequest,
) -> RouterError {
    if !snapshot.aliases.contains_key(&request.requested_model)
        || exclusions
            .iter()
            .all(|e| e.reason == ExclusionReason::NotAuthorizedForAlias)
    {
        return RouterError::new(
            ErrorCode::ModelNotFound,
            "the requested model is not available",
        )
        .with_param("model");
    }

    if exclusions
        .iter()
        .any(|e| e.reason == ExclusionReason::CapacityExhausted)
    {
        return RouterError::new(
            ErrorCode::CapacityExhausted,
            "no target has capacity for this request",
        );
    }

    RouterError::new(
        ErrorCode::NoEligibleTarget,
        "no target met the policy, health, and capability requirements",
    )
}

/// Publish how many requests are waiting for this target's capacity.
///
/// Specification 17 lists queue depth among the required signals. Published
/// from the scope's own counter rather than tracked separately, so the gauge
/// cannot disagree with the bound `max_queued` actually enforces.
fn publish_queue_depth(state: &RouterState, target: &hypellm_core::ids::TargetId) {
    let Some(scope) = state.admission.target_scope(target) else {
        return;
    };
    state.telemetry.metrics.gauge_set(
        hypellm_telemetry::names::QUEUE_DEPTH,
        "Requests waiting for a concurrency slot, by target.",
        &hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Target, target.as_str()),
        i64::from(scope.queued()),
    );
}

/// Publish the breaker's current state as a gauge.
///
/// Specification 17 lists breaker state among the required signals. Published
/// as one series per state with a zero/one value rather than as a single series
/// holding an enum ordinal, because an ordinal is unreadable in an alert
/// expression and its meaning changes silently if a variant is ever inserted.
fn publish_breaker_state(
    state: &RouterState,
    health: &hypellm_core::health::TargetHealth,
    target: &hypellm_core::ids::TargetId,
    now_ms: u64,
) {
    let current = health.breaker.state(now_ms);
    for candidate in [
        hypellm_core::health::BreakerState::Closed,
        hypellm_core::health::BreakerState::Open,
        hypellm_core::health::BreakerState::HalfOpen,
    ] {
        state.telemetry.metrics.gauge_set(
            hypellm_telemetry::names::BREAKER_STATE,
            "Circuit breaker state per target: 1 for the current state, 0 otherwise.",
            &hypellm_telemetry::Labels::new()
                .with(hypellm_telemetry::LabelName::Target, target.as_str())
                .with(
                    hypellm_telemetry::LabelName::BreakerState,
                    candidate.as_str(),
                ),
            i64::from(candidate == current),
        );
    }
}

/// Emit the metrics and the log line for a completed request.
pub fn record_completion(
    state: &RouterState,
    request: &CanonicalRequest,
    outcome: &Outcome,
    total_millis: u64,
    principal_key: Option<&hypellm_core::ids::KeyId>,
) {
    let code = outcome
        .error
        .as_ref()
        .map_or("ok", |e| e.code.as_str());

    let labels = hypellm_telemetry::Labels::new()
        .with(
            hypellm_telemetry::LabelName::Protocol,
            request.protocol.as_str(),
        )
        .with(
            hypellm_telemetry::LabelName::Operation,
            request.operation.as_str(),
        )
        .with(hypellm_telemetry::LabelName::Outcome, code);
    state.telemetry.count(
        hypellm_telemetry::names::REQUESTS_TOTAL,
        "Requests by protocol, operation, and outcome.",
        &labels,
    );

    // Whether the reasoning tiers are used as expected, and whether the
    // expensive ones succeed at the same rate as the cheap ones. Both labels
    // are closed enums, so the series count is bounded by construction.
    state.telemetry.count(
        hypellm_telemetry::names::REQUESTS_BY_EFFORT,
        "Requests by reasoning tier and outcome.",
        &hypellm_telemetry::Labels::new()
            .with(
                hypellm_telemetry::LabelName::Effort,
                request.reasoning_effort.as_str(),
            )
            .with(hypellm_telemetry::LabelName::Outcome, code),
    );

    // `hypellm_router_overhead_milliseconds` and the `router_ms` log field are
    // published series: changing their unit under a deployment would silently
    // reinterpret every existing dashboard and alert threshold, so the trace's
    // microseconds are converted here rather than the series being renamed.
    //
    // Rounding up keeps a bucketed sample an upper bound on the true value,
    // matching `Histogram::quantile_upper_bound`, and keeps a 1.4 ms overhead
    // from being reported as if it were under one millisecond. The cost is that
    // this metric cannot distinguish 1 µs from 1000 µs — which is precisely why
    // specification 19's targets are measured by `hypellm-bench` against the
    // trace's `routing_micros`, not by scraping this series.
    let routing_millis = outcome.trace.routing_micros.div_ceil(1000);

    state.telemetry.metrics.histogram_observe(
        hypellm_telemetry::names::ROUTER_OVERHEAD_MS,
        "Router processing time, excluding upstream time.",
        &hypellm_telemetry::Labels::one(
            hypellm_telemetry::LabelName::Operation,
            request.operation.as_str(),
        ),
        routing_millis,
    );

    // Specification 17 lists "target latency/error" among the required signals.
    // The error half was already emitted per attempt; this is the latency half,
    // and it is deliberately per *target* rather than per operation — the
    // question an operator asks of it is "which provider got slow", which a
    // per-operation series cannot answer.
    if let (Some(summary), Some(target)) = (&outcome.summary, &outcome.trace.chosen) {
        let by_target =
            hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Target, target.as_str());
        if let Some(first_byte) = summary.first_byte_millis {
            state.telemetry.metrics.histogram_observe(
                hypellm_telemetry::names::UPSTREAM_FIRST_BYTE_MS,
                "Time to the first byte from the selected target.",
                &by_target,
                first_byte,
            );
        }
        state.telemetry.metrics.histogram_observe(
            hypellm_telemetry::names::UPSTREAM_LATENCY_MS,
            "Total upstream exchange time for the selected target.",
            &by_target,
            summary.total_millis,
        );
    }

    // Every exclusion the decision recorded. Without this the exposition can
    // say that requests failed but not why no target was eligible, which is the
    // first question asked when a routing change goes wrong — and the decision
    // trace that does carry the answer is sampled, not scraped.
    for exclusion in &outcome.trace.exclusions {
        state.telemetry.count(
            hypellm_telemetry::names::ROUTING_EXCLUSIONS,
            "Targets excluded from a routing decision, by reason.",
            &hypellm_telemetry::Labels::new()
                .with(
                    hypellm_telemetry::LabelName::Target,
                    exclusion.target.as_str(),
                )
                .with(
                    hypellm_telemetry::LabelName::Reason,
                    exclusion.reason.code(),
                ),
        );
    }

    if let Some(summary) = &outcome.summary {
        state.telemetry.metrics.counter_add(
            hypellm_telemetry::names::TOKENS_TOTAL,
            "Tokens accounted, by provenance.",
            &hypellm_telemetry::Labels::new()
                .with(
                    hypellm_telemetry::LabelName::UsageSource,
                    summary.usage.source.as_str(),
                )
                .with(
                    hypellm_telemetry::LabelName::Operation,
                    request.operation.as_str(),
                ),
            summary.usage.total(),
        );
    }

    let event = hypellm_telemetry::Event::new(
        if outcome.is_success() {
            hypellm_telemetry::Severity::Info
        } else {
            hypellm_telemetry::Severity::Warn
        },
        "request.completed",
    )
    .str_field(
        hypellm_telemetry::Field::RequestId,
        &request.request_id.to_string(),
    )
    .str_field(
        hypellm_telemetry::Field::Tenant,
        &state.telemetry.pseudonyms.tenant(request.tenant.as_str()),
    )
    .str_field(
        hypellm_telemetry::Field::Principal,
        &state
            .telemetry
            .pseudonyms
            .principal(request.principal.as_str()),
    )
    .str_field(
        hypellm_telemetry::Field::Alias,
        request.requested_model.as_str(),
    )
    .opt_str_field(
        hypellm_telemetry::Field::Target,
        outcome.trace.chosen.as_ref().map(TargetId::as_str),
    )
    .str_field(
        hypellm_telemetry::Field::Operation,
        request.operation.as_str(),
    )
    .str_field(hypellm_telemetry::Field::Code, code)
    .str_field(
        hypellm_telemetry::Field::ConfigDigest,
        &outcome.trace.policy_digest.short(),
    )
    .int_field(hypellm_telemetry::Field::RouterMs, routing_millis)
    .int_field(hypellm_telemetry::Field::TotalMs, total_millis)
    .int_field(
        hypellm_telemetry::Field::Attempts,
        u64::try_from(outcome.trace.attempts.len()).unwrap_or(u64::MAX),
    );

    // The trace is retained for the decision explorer (specification 15.3).
    // Recording it here, once, means every completed request is explorable and
    // no handler can forget to do it.
    state.decisions.record(
        request.tenant.clone(),
        outcome.trace.clone(),
        state.clock.wall_millis(),
    );

    record_usage(state, request, outcome, principal_key);

    let event = match &outcome.summary {
        Some(summary) => event
            .int_field(
                hypellm_telemetry::Field::InputTokens,
                summary.usage.input_tokens,
            )
            .int_field(
                hypellm_telemetry::Field::OutputTokens,
                summary.usage.output_tokens,
            ),
        None => event,
    };

    state.telemetry.log(&event);
}

/// Fold a completed request into the usage aggregate.
///
/// Specification 15.3's usage screen is "per authorized scope, model/alias,
/// operation, status, cost class". Every one of those dimensions is known here
/// and nowhere later, so the fold happens on the completion path rather than
/// being reconstructed from logs.
///
/// A request that never reached a target still counts: a tenant that is being
/// refused for capacity needs to see the refusals, and a usage screen that
/// showed only successes would make a broken deployment look idle.
fn record_usage(
    state: &RouterState,
    request: &CanonicalRequest,
    outcome: &Outcome,
    principal_key: Option<&hypellm_core::ids::KeyId>,
) {
    let status = match &outcome.error {
        None => hypellm_admin_api::UsageStatus::Success,
        Some(error) => hypellm_admin_api::UsageStatus::from_status(error.code.status()),
    };

    let target = outcome.trace.chosen.clone();
    let cost_class = target
        .as_ref()
        .and_then(|id| {
            state
                .config()
                .snapshot
                .targets
                .get(id)
                .map(|target| target.cost_class)
        })
        .unwrap_or(hypellm_core::canonical::CostClass::CHEAPEST);

    let usage = outcome
        .summary
        .as_ref()
        .map(|summary| summary.usage)
        .unwrap_or_default();

    state.usage.record(
        &hypellm_admin_api::UsageSample {
            tenant: request.tenant.clone(),
            principal: request.principal.clone(),
            alias: request.requested_model.clone(),
            target,
            operation: request.operation,
            status,
            cost_class,
            usage,
            key_id: principal_key.cloned(),
        },
        state.clock.wall_millis(),
    );

    // Specification 12's budget layer, charged from provider-reported usage
    // rather than from the admission estimate (`DI-053`). A scope with no
    // budget configured is unaffected: `record_spend` returns immediately when
    // the figure is zero, and a scope whose `budget_minor_units` is zero never
    // consults its ledger.
    let config = state.config();
    let spent = target_of(&outcome.trace)
        .and_then(|id| hypellm_config::price_in_effect(&config.prices, id, state.clock.wall_millis()))
        .map_or(0, |price| {
            price.cost_minor_units(
                usage.input_tokens,
                usage.cached_input_tokens,
                usage.output_tokens,
            )
        });
    state.admission.record_spend(
        &request.tenant,
        &request.principal,
        Some((&request.requested_model, request.operation)),
        outcome.trace.chosen.as_ref(),
        spent,
        state.clock.now_millis(),
    );

}

/// The target a decision chose, if it chose one.
fn target_of(trace: &hypellm_core::decision::DecisionTrace) -> Option<&hypellm_core::ids::TargetId> {
    trace.chosen.as_ref()
}

/// Wait for an activation somebody else started.
///
/// Bounded by the request's own deadline. The wait is reported as
/// `hypellm_fleet_queue_wait_milliseconds`, which is the cost of batching as
/// the caller actually experienced it — the number an operator needs to decide
/// whether `activation_max_wait_ms` is set well.
fn wait_for(
    state: &RouterState,
    request: &CanonicalRequest,
    candidate: &hypellm_core::decision::Candidate,
    deadline: Deadline,
) -> Result<(), ExclusionReason> {
    let Some(fleet) = state.fleet() else {
        return Err(ExclusionReason::FleetAgentUnavailable);
    };
    let clock = state.clock.as_ref();
    let remaining = u64::try_from(deadline.remaining(clock).as_millis()).unwrap_or(u64::MAX);
    match fleet.await_ready(&candidate.target, remaining) {
        Ok(waited) => {
            let capability = state
                .config()
                .snapshot
                .aliases
                .get(&request.requested_model)
                .and_then(|a| a.capability);
            if let Some(capability) = capability {
                state.telemetry.metrics.histogram_observe(
                    hypellm_telemetry::names::FLEET_QUEUE_WAIT_MS,
                    "Time a request spent waiting for a cold capability to become available.",
                    &hypellm_telemetry::Labels::one(
                        hypellm_telemetry::LabelName::Capability,
                        capability.as_str(),
                    ),
                    waited,
                );
            }
            fleet.record_served(&candidate.target);
            Ok(())
        }
        Err("fleet_activation_timeout") => Err(ExclusionReason::ActivationExceedsDeadline),
        Err(_) => Err(ExclusionReason::HostCapacityInsufficient),
    }
}

/// Make a cold candidate ready, or say why it could not be.
///
/// Returns the exclusion reason to record against the target. Nothing here
/// names a host, an accelerator, or what else is loaded: specification-extension
/// 15 makes fleet topology management-plane data, and a data-plane error that
/// disclosed it would be a cross-tenant leak by another name.
fn activate_for(
    state: &RouterState,
    request: &CanonicalRequest,
    view: &crate::fleet::FleetView,
    candidate: &hypellm_core::decision::Candidate,
    deadline: Deadline,
) -> Result<(), ExclusionReason> {
    let Some(fleet) = state.fleet() else {
        // A candidate classified as needing activation by a router with no
        // fleet runtime is a contradiction; refuse rather than dispatch to
        // something that is not running.
        return Err(ExclusionReason::FleetAgentUnavailable);
    };
    let Some(plan) = view.plan(&candidate.target) else {
        return Err(ExclusionReason::FleetStateStale);
    };

    // Batching. Ten requests for one cold capability should cost one swap, not
    // ten, so only the request that trips the threshold pays for it.
    let config = state.config();
    let capability = config
        .snapshot
        .aliases
        .get(&request.requested_model)
        .and_then(|a| a.capability);
    if let Some(capability) = capability {
        match fleet.admit_to_queue(capability, &plan.host) {
            hypellm_fleet::governance::QueueAdmission::Activate => {}
            hypellm_fleet::governance::QueueAdmission::Wait { .. } => {
                // Waiting is not this request\'s job: it fails over to the next
                // candidate, and the activation the queue triggered serves
                // whoever asks next. A request that blocked here would hold a
                // connection and an admission slot for a whole model load.
                fleet.leave_queue(capability);
                return Err(ExclusionReason::ActivationExceedsDeadline);
            }
            hypellm_fleet::governance::QueueAdmission::Full => {
                fleet.leave_queue(capability);
                return Err(ExclusionReason::ActivationBudgetExhausted);
            }
        }
    }

    let clock = state.clock.as_ref();
    let remaining = u64::try_from(deadline.remaining(clock).as_millis()).unwrap_or(u64::MAX);
    let result = fleet.ensure_ready(
        &candidate.target,
        plan,
        &request.request_id.to_hex(),
        remaining,
    );
    if let Some(capability) = capability {
        fleet.leave_queue(capability);
    }

    match result {
        crate::fleet::ActivationResult::Ready => {
            fleet.record_served(&candidate.target);
            Ok(())
        }
        crate::fleet::ActivationResult::Failed { code } => Err(match code {
            "fleet_budget_exhausted" | "fleet_busy" => ExclusionReason::ActivationBudgetExhausted,
            "fleet_activation_timeout" => ExclusionReason::ActivationExceedsDeadline,
            "fleet_unavailable" => ExclusionReason::FleetAgentUnavailable,
            _ => ExclusionReason::HostCapacityInsufficient,
        }),
    }
}

/// A terminal error event for a stream that has already begun.
///
/// Specification 14: "Emit protocol-supported error event if possible, then
/// close. **Never append failover output.**"
#[must_use]
pub fn terminal_error_event(error: &RouterError) -> CanonicalEvent {
    CanonicalEvent::Error(error.clone())
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
    use super::*;
    use hypellm_core::decision::Exclusion;
    use hypellm_core::ids::AliasId;

    fn request_for(alias: &str) -> CanonicalRequest {
        let mut request = hypellm_adapters::testing::request_fixture();
        request.requested_model = AliasId::new(alias).unwrap();
        request
    }

    fn empty_snapshot() -> hypellm_core::policy::PolicySnapshot {
        hypellm_core::policy::PolicySnapshot::empty()
    }

    #[test]
    fn an_unknown_alias_is_model_not_found() {
        let error = no_candidate_error(&[], &empty_snapshot(), &request_for("nope"));
        assert_eq!(error.code, ErrorCode::ModelNotFound);
        assert_eq!(error.param.expect("param").as_str(), "model");
    }

    #[test]
    fn an_unauthorized_alias_looks_identical_to_a_missing_one() {
        // Specification 8.2: "Alias absent or hidden for caller." Telling the
        // difference would enumerate the model catalogue.
        let mut snapshot = empty_snapshot();
        let alias = AliasId::new("secret-model").unwrap();
        snapshot.aliases.insert(
            alias.clone(),
            hypellm_core::target::Alias {
                id: alias.clone(),
                capability: None,
                permitted_targets: vec![TargetId::new("t").unwrap()],
                allow_family_failover: false,
                description: None,
            },
        );
        let exclusions = vec![Exclusion {
            target: TargetId::new("t").unwrap(),
            reason: ExclusionReason::NotAuthorizedForAlias,
        }];

        let hidden = no_candidate_error(&exclusions, &snapshot, &request_for("secret-model"));
        let absent = no_candidate_error(&[], &empty_snapshot(), &request_for("nope"));
        assert_eq!(hidden.code, absent.code);
        assert_eq!(hidden.detail.as_str(), absent.detail.as_str());
    }

    #[test]
    fn a_capacity_exclusion_reports_capacity_not_a_missing_model() {
        let mut snapshot = empty_snapshot();
        let alias = AliasId::new("code-premium").unwrap();
        snapshot.aliases.insert(
            alias.clone(),
            hypellm_core::target::Alias {
                id: alias,
                capability: None,
                permitted_targets: vec![TargetId::new("t").unwrap()],
                allow_family_failover: false,
                description: None,
            },
        );
        let exclusions = vec![Exclusion {
            target: TargetId::new("t").unwrap(),
            reason: ExclusionReason::CapacityExhausted,
        }];
        let error = no_candidate_error(&exclusions, &snapshot, &request_for("code-premium"));
        assert_eq!(error.code, ErrorCode::CapacityExhausted);
        assert_eq!(error.status(), 429);
    }

    #[test]
    fn other_exclusions_report_no_eligible_target() {
        let mut snapshot = empty_snapshot();
        let alias = AliasId::new("code-premium").unwrap();
        snapshot.aliases.insert(
            alias.clone(),
            hypellm_core::target::Alias {
                id: alias,
                capability: None,
                permitted_targets: vec![TargetId::new("t").unwrap()],
                allow_family_failover: false,
                description: None,
            },
        );
        let exclusions = vec![Exclusion {
            target: TargetId::new("t").unwrap(),
            reason: ExclusionReason::ContextWindowTooSmall,
        }];
        let error = no_candidate_error(&exclusions, &snapshot, &request_for("code-premium"));
        assert_eq!(error.code, ErrorCode::NoEligibleTarget);
        assert_eq!(error.status(), 503);
    }

    #[test]
    fn a_terminal_error_event_is_an_error_not_output() {
        let event = terminal_error_event(&RouterError::internal());
        assert!(event.is_terminal());
        assert!(
            !event.is_semantic_output(),
            "an error event must not count as model output"
        );
    }
}
