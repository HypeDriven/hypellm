//! The target liveness probe.
//!
//! Without it a target's health is learned only from the requests routed to
//! it, so a slave whose server stopped while nothing was being sent to it reads
//! as healthy until a caller's request finds out. This asks each probed
//! endpoint `GET /health` on a fixed interval and folds the answer into
//! [`HealthRegistry`](hypellm_core::health::HealthRegistry), where routing
//! reads it as an eligibility filter (`probe_unreachable`).
//!
//! # Bounds
//!
//! - **One thread**, started once at boot and never from a request
//!   (specification 3.2). Endpoints are probed in turn, not concurrently, so
//!   the thread count is one whatever the configuration declares.
//! - **Every probe has a deadline**: connect, send and response head together
//!   finish within `target_probe_timeout_ms`, and only the head is read — the
//!   body is never buffered. No probe is retried; the next round is the retry.
//! - **Destinations come from configuration only**, through
//!   [`Egress::dial_probe`](hypellm_net::Egress::dial_probe): the same
//!   resolve-validate-pin path and egress profile as a request to that
//!   provider. Nothing a caller sends can name what is probed.
//! - **Shutdown** is observed between probes and during the wait between
//!   rounds, so a drain waits for at most the probe in hand.
//!
//! # What is probed
//!
//! Providers of the two families that serve a cheap liveness path at their
//! root: llama.cpp (`/health` answers 503 while a model loads and 200 once it
//! can serve) and the SemIf bridge. Remote API families have no such path a
//! router could call without spending a request, so they are not probed and
//! keep the request-driven breaker alone. A target with a fleet deployment is
//! not probed either: a stopped container there is a cold target the planner
//! may start, not a dead one (specification 26.4 — only `Infeasible`
//! excludes), and the fleet's own observation is its liveness signal.

use crate::state::RouterState;
use hypellm_core::health::ProbeState;
use hypellm_core::ids::{ProviderId, TargetId};
use hypellm_core::target::{Endpoint, ProviderFamily};
use hypellm_core::time::Deadline;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use wire_http1::{Limits as HttpLimits, Method, RequestBuilder};

/// How often the thread looks at the shutdown flag while waiting.
const POLL: Duration = Duration::from_millis(200);

/// The liveness path, at the endpoint's root rather than under its base path:
/// llama.cpp serves `/health` beside `/v1`, not inside it.
const HEALTH_PATH: &str = "/health";

/// One endpoint to probe and the targets its answer speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// The provider.
    pub provider: ProviderId,
    /// The endpoint, exactly as configured.
    pub endpoint: Endpoint,
    /// Every target served through this endpoint.
    pub targets: Vec<TargetId>,
}

/// The families whose servers answer a liveness path at their root.
const fn probes_family(family: ProviderFamily) -> bool {
    matches!(family, ProviderFamily::LlamaCpp | ProviderFamily::SemIf)
}

/// Everything the probe would dial under `config`, in a stable order.
///
/// Derived from the validated configuration and nothing else, which is the
/// property the "never dials an unconfigured address" test pins: the result is
/// a function of the document, so a request cannot add to it.
#[must_use]
pub fn probe_set(config: &hypellm_config::ValidatedConfig) -> Vec<ProbeTarget> {
    let fleet_managed: BTreeSet<&TargetId> = if config.fleet.enabled {
        config.fleet.deployments.values().map(|d| &d.target).collect()
    } else {
        BTreeSet::new()
    };
    let mut grouped: BTreeMap<(&ProviderId, usize), Vec<TargetId>> = BTreeMap::new();
    for target in config.snapshot.targets.values() {
        if fleet_managed.contains(&target.id) {
            continue;
        }
        let Some(provider) = config.snapshot.providers.get(&target.provider_id) else {
            continue;
        };
        if !provider.enabled || !probes_family(provider.family) {
            continue;
        }
        grouped
            .entry((&provider.id, target.endpoint_index))
            .or_default()
            .push(target.id.clone());
    }
    grouped
        .into_iter()
        .filter_map(|((provider_id, index), targets)| {
            let provider = config.snapshot.providers.get(provider_id)?;
            let endpoint = provider.endpoints.get(index)?;
            Some(ProbeTarget {
                provider: provider_id.clone(),
                endpoint: endpoint.clone(),
                targets,
            })
        })
        .collect()
}

/// Probe one endpoint: `true` if it answered `/health` with 200 in time.
fn probe_endpoint(state: &RouterState, probe: &ProbeTarget, timeout: Duration) -> bool {
    let clock = state.clock.as_ref();
    let deadline = Deadline::after(clock, timeout);
    let profile = state.egress_profile(&probe.provider);
    let Ok(mut connection) = state.egress.dial_probe(&probe.endpoint, profile, timeout) else {
        return false;
    };
    let Ok(wire) = RequestBuilder::new(Method::Get, HEALTH_PATH, &probe.endpoint.authority())
        .and_then(|builder| builder.header("connection", "close"))
        .and_then(|builder| builder.finish_with_body(b""))
    else {
        return false;
    };
    let answered = connection
        .send(&wire, b"", clock, deadline)
        .and_then(|()| connection.read_head(&Method::Get, &HttpLimits::UPSTREAM, clock, deadline));
    // Never pooled: the body was not read, and a probe socket is not a
    // request's to reuse.
    connection.close();
    matches!(answered, Ok(head) if head.status == 200)
}

/// One probe round over the current configuration.
///
/// Returns how many endpoints were probed. Stops early, without recording
/// anything for the endpoints it skipped, once `stop` says so.
pub fn run_round(state: &RouterState, timeout: Duration, stop: &dyn Fn() -> bool) -> usize {
    let config = state.config();
    let set = probe_set(&config);
    let probed: BTreeSet<TargetId> = set.iter().flat_map(|p| p.targets.iter().cloned()).collect();
    state.health.retain_probes(&probed);

    let mut count = 0;
    for probe in &set {
        if stop() {
            break;
        }
        let ok = probe_endpoint(state, probe, timeout);
        count += 1;
        for target in &probe.targets {
            let changed = state.health.record_probe(target, ok);
            publish(state, target, ok);
            if let Some(now) = changed {
                log_transition(state, target, now);
            }
        }
    }
    count
}

fn publish(state: &RouterState, target: &TargetId, ok: bool) {
    let labels = hypellm_telemetry::Labels::one(hypellm_telemetry::LabelName::Target, target.as_str());
    let up = state
        .health
        .probe_status(target)
        .is_some_and(|status| status.state == ProbeState::Reachable);
    state.telemetry.metrics.gauge_set(
        hypellm_telemetry::names::TARGET_PROBE_UP,
        "Whether the liveness probe currently finds the target reachable: 1 or 0.",
        &labels,
        i64::from(up),
    );
    state.telemetry.metrics.counter_inc(
        hypellm_telemetry::names::TARGET_PROBES,
        "Liveness probes completed, by target and outcome.",
        &hypellm_telemetry::Labels::new()
            .with(hypellm_telemetry::LabelName::Target, target.as_str())
            .with(
                hypellm_telemetry::LabelName::Outcome,
                if ok { "ok" } else { "failed" },
            ),
    );
}

fn log_transition(state: &RouterState, target: &TargetId, now: ProbeState) {
    let event = match now {
        ProbeState::Unreachable => hypellm_telemetry::Event::warn("target.probe_unreachable")
            .str_field(
                hypellm_telemetry::Field::Detail,
                "the liveness probe failed repeatedly; the target is excluded until it answers again",
            ),
        ProbeState::Reachable => hypellm_telemetry::Event::info("target.probe_reachable")
            .str_field(
                hypellm_telemetry::Field::Detail,
                "the liveness probe succeeded again; the target is routable, ramping back",
            ),
    };
    state
        .telemetry
        .log(&event.str_field(hypellm_telemetry::Field::Target, target.as_str()));
}

/// The probe thread's body: rounds on the configured interval until shutdown.
///
/// The settings are re-read every round, so a publication that changes the
/// interval, switches the probe off, or adds a slave takes effect without a
/// restart. Switched off, every probe record is dropped at once, so nothing
/// stays excluded on a verdict the router has stopped revising.
///
/// `stop` is the router's shutdown flag; it is read between probes and every
/// [`POLL`] while waiting, so returning `true` ends the loop within one probe
/// timeout.
pub fn probe_loop(state: &RouterState, stop: &dyn Fn() -> bool) {
    while !stop() {
        let (interval, timeout) = {
            let config = state.config();
            (
                config.settings.target_probe_interval_ms,
                config.settings.target_probe_timeout_ms,
            )
        };
        let wait = if interval == 0 {
            state.health.retain_probes(&BTreeSet::new());
            POLL
        } else {
            run_round(state, Duration::from_millis(timeout), stop);
            Duration::from_millis(interval)
        };
        let mut waited = Duration::ZERO;
        while waited < wait && !stop() {
            std::thread::sleep(POLL.min(wait.saturating_sub(waited)));
            waited = waited.saturating_add(POLL);
        }
    }
}
