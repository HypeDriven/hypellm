//! The benchmark scenarios.
//!
//! Specification 19.1 requires a "synthetic local upstream" and open-/closed-loop
//! tests across non-streaming and streaming shapes, comparing "direct-to-provider
//! versus routed latency" and reporting "distributions, not averages".
//!
//! Every scenario here is closed-loop and single-threaded: one request at a
//! time, against `hypellm_router::testing::FakeUpstream`, over loopback. Nothing
//! here leaves 127.0.0.1, resolves a name, reads a credential, or depends on
//! wall-clock time, so a run is reproducible on any machine — the *behaviour*
//! is, at least. The *numbers* depend on the hardware; see `MODULE.md`.
//!
//! # What "router overhead" means here
//!
//! Specification 19 budgets "warm router overhead … excluding edge/provider
//! network". That is the work the router does on its own behalf: resolve the
//! alias, filter and rank targets, and translate between the client's protocol
//! and the provider's. It is *not* the end-to-end latency, which is dominated by
//! the provider.
//!
//! Two independent estimates are reported, because neither is free of
//! assumptions and they should agree:
//!
//! | Series | How | Weakness |
//! |---|---|---|
//! | `router_overhead` | per iteration: the pipeline's own `routing_micros`, plus the adapter encode and decode calls re-run on the same inputs | the translate half is re-run outside the pipeline, so it excludes the pipeline's own call and framing overhead |
//! | `overhead_by_diff` | per iteration: `pipeline_total` minus a bare socket exchange with the same upstream in the same loop | the subtraction assumes the two exchanges cost the upstream the same, which loopback scheduling noise violates |
//!
//! `router_overhead` is the one the regression test asserts on: it is the
//! tighter measurement and it never goes negative. `overhead_by_diff` is
//! reported so a large disagreement between the two is visible rather than
//! assumed away.
//!
//! # What is deliberately not measured
//!
//! The pipeline does not instrument its own translate step, so this harness
//! cannot report the *exact* microseconds the pipeline spent inside
//! `Adapter::encode_request` on a given request. Adding that instrumentation
//! would put two more clock reads on the data path for every request. Naming
//! the gap is more useful than pretending the reconstruction is identical.

use hypellm_adapters::{Adapter, RequestMeta, adapter_for};
use hypellm_core::canonical::CanonicalRequest;
use hypellm_core::event::CanonicalEvent;
use hypellm_core::ids::{AliasId, TargetId};
use hypellm_core::policy::RoutingContext;
use hypellm_core::target::{Endpoint, Target};
use hypellm_core::time::Deadline;
use hypellm_router::dispatch::{AccumulatingSink, EventSink, SinkClosed};
use hypellm_router::pipeline;
use hypellm_router::testing::{CannedResponse, FakeUpstream, TestRouter, router_for};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::distribution::{Distribution, Samples, Unit};

/// How many iterations to run, and how many to throw away first.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// Measured iterations.
    pub iterations: usize,
    /// Iterations run and discarded before measuring.
    ///
    /// Specification 19's target is explicitly for a *warm* router. The first
    /// requests through a fresh process pay for lazily grown maps, an empty
    /// connection pool, and a cold instruction cache, and reporting them as if
    /// they were steady state would make every run look worse than the system
    /// it is measuring.
    pub warmup: usize,
}

impl Plan {
    /// The default plan for the routing-only scenario, which is cheap enough to
    /// run many times.
    pub const DECISION: Self = Self {
        iterations: 20_000,
        warmup: 2_000,
    };

    /// The default plan for a scenario that crosses a socket.
    pub const END_TO_END: Self = Self {
        iterations: 500,
        warmup: 50,
    };

    /// Scale a plan down, for the regression test, which must stay fast.
    ///
    /// Rounding down is the point: a scaled plan must never run *more* than the
    /// original. Iterations are floored at one, because a plan that measures
    /// nothing would report an empty distribution as a pass. `checked_div`
    /// rather than `/` so a zero divisor cannot trap even if the clamp below is
    /// ever removed.
    #[must_use]
    pub const fn scaled(self, divisor: usize) -> Self {
        let divisor = if divisor == 0 { 1 } else { divisor };
        let iterations = match self.iterations.checked_div(divisor) {
            Some(0) | None => 1,
            Some(scaled) => scaled,
        };
        let warmup = match self.warmup.checked_div(divisor) {
            Some(scaled) => scaled,
            None => 0,
        };
        Self { iterations, warmup }
    }
}

/// One scenario's result.
#[derive(Debug)]
pub struct ScenarioReport {
    /// Stable scenario name.
    pub name: &'static str,
    /// One line describing what was exercised.
    pub what: &'static str,
    /// The measured series, most important first.
    pub series: Vec<Distribution>,
    /// Iterations that did not complete successfully.
    ///
    /// A benchmark that silently benchmarks the error path is worse than no
    /// benchmark: errors are fast, so the report improves as the system breaks.
    pub failures: u64,
    /// Caveats a reader needs in order to interpret the numbers.
    pub notes: Vec<String>,
}

impl ScenarioReport {
    /// Find a series by label.
    #[must_use]
    pub fn series(&self, label: &str) -> Option<&Distribution> {
        self.series.iter().find(|d| d.label == label)
    }
}

/// The canned non-streaming provider response.
///
/// Shaped like a real OpenAI chat completion, including a usage block, so the
/// decode path does the work it does in production rather than short-circuiting
/// on a minimal body.
const CHAT_COMPLETION_BODY: &str = concat!(
    r#"{"id":"chatcmpl-bench","model":"test-model","choices":[{"index":0,"#,
    r#""message":{"role":"assistant","content":"Backpressure is flow control."},"#,
    r#""finish_reason":"stop"}],"#,
    r#""usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#
);

/// The canned streaming frames, as an upstream would emit them.
const CHAT_STREAM_FRAMES: &[&str] = &[
    r#"{"id":"1","choices":[{"delta":{"role":"assistant","content":"Back"}}]}"#,
    r#"{"id":"1","choices":[{"delta":{"content":"pressure"}}]}"#,
    r#"{"id":"1","choices":[{"delta":{"content":" is flow control."}}]}"#,
    r#"{"id":"1","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
];

/// The canned non-streaming response, with reuse turned off.
///
/// `FakeUpstream` serves one request per accepted connection and then shuts its
/// write side. Without an explicit `Connection: close` the router pools that
/// socket and the following attempt fails against a half-closed peer — the
/// benchmark would then measure a connection error, which is fast, and the
/// report would improve as it broke. Declaring `close` makes every iteration
/// take a fresh connection, which is honest but means pooled reuse
/// (specification 19, `Connection reuse`) is never on the measured path.
fn chat_completion_response() -> CannedResponse {
    let mut response = CannedResponse::json(200, CHAT_COMPLETION_BODY);
    response
        .headers
        .push(("Connection".to_owned(), "close".to_owned()));
    response
}

/// The client body a direct-to-provider comparison sends.
const DIRECT_REQUEST_BODY: &str =
    r#"{"model":"test-model","messages":[{"role":"user","content":"Explain backpressure."}]}"#;

/// A sink that counts events and keeps nothing.
///
/// The streaming scenario must not accumulate the response: holding every event
/// would measure the harness's allocator alongside the router.
#[derive(Debug, Default)]
struct CountingSink {
    events: u64,
}

impl EventSink for CountingSink {
    fn deliver(&mut self, _event: &CanonicalEvent) -> Result<(), SinkClosed> {
        self.events = self.events.saturating_add(1);
        Ok(())
    }
}

/// Everything a scenario needs, assembled once.
struct Fixture {
    router: TestRouter,
    request: CanonicalRequest,
    /// Kept alive for the router's lifetime; dropped last.
    upstream: FakeUpstream,
}

impl Fixture {
    /// Build a router over an upstream answering with `response`.
    ///
    /// # Panics
    ///
    /// Panics if the fixture configuration or identifiers are wrong, which
    /// would be a defect in this file rather than a benchmark result.
    #[allow(
        clippy::expect_used,
        reason = "a broken fixture must stop the run, not be reported as a slow one"
    )]
    fn new(response: CannedResponse, streaming: bool) -> Self {
        let upstream = FakeUpstream::start(response);
        let router = router_for(&upstream);

        let mut request = hypellm_adapters::testing::request_fixture();
        request.requested_model = AliasId::new("test-alias").expect("fixture alias is valid");
        request.stream.enabled = streaming;
        // The fixture's deadline is absolute on a `TestClock` origin. Rebase it
        // on the router's own clock, or a long run walks past it and the
        // benchmark starts measuring `DeadlineExceeded`.
        request.limits.deadline =
            Deadline::after(router.state.clock.as_ref(), Duration::from_secs(30));

        Self {
            router,
            request,
            upstream,
        }
    }

    fn upstream_address(&self) -> SocketAddr {
        self.upstream.address
    }

    /// The target and endpoint the router will choose, for the translate
    /// measurement.
    ///
    /// # Panics
    ///
    /// Panics if the fixture configuration does not contain them.
    #[allow(
        clippy::expect_used,
        reason = "a broken fixture must stop the run, not be reported as a slow one"
    )]
    fn chosen_target(&self) -> (Target, Endpoint, &'static dyn Adapter) {
        let config = self.router.state.config();
        let id = TargetId::new("local:model").expect("fixture target id is valid");
        let target = config
            .snapshot
            .targets
            .get(&id)
            .expect("fixture target is configured")
            .clone();
        let provider = config
            .snapshot
            .providers
            .get(&target.provider_id)
            .expect("fixture provider is configured");
        let endpoint = provider
            .endpoints
            .get(target.endpoint_index)
            .expect("fixture endpoint is configured")
            .clone();
        (target, endpoint, adapter_for(provider.family))
    }
}

/// Scenario 1: the routing decision alone.
///
/// `PolicySnapshot::route` performs no I/O (specification 18.3), so this is the
/// purest router-overhead number available: alias resolution, binding
/// precedence, eligibility filtering, scoring, and ordering, with nothing else
/// in the sample.
#[must_use]
pub fn routing_decision(plan: Plan) -> ScenarioReport {
    let fixture = Fixture::new(chat_completion_response(), false);
    let state = &fixture.router.state;
    let clock = state.clock.as_ref();
    let config = state.config();
    let snapshot = &config.snapshot;

    let attempted: Vec<TargetId> = Vec::new();
    let groups: Vec<hypellm_core::ids::GroupId> = Vec::new();
    let context = RoutingContext {
        principal: &fixture.request.principal,
        groups: &groups,
        tenant: &fixture.request.tenant,
        attempted: &attempted,
        now_millis: 0,
    };

    let mut route = Samples::new("route", Unit::Micros, plan.iterations);
    let mut candidates = Samples::new("candidates", Unit::Count, plan.iterations);
    let mut failures = 0u64;

    for i in 0..plan.warmup.saturating_add(plan.iterations) {
        let start = clock.now_micros();
        let outcome = snapshot.route(&context, &fixture.request, state.health.as_ref());
        let elapsed = clock.now_micros().saturating_sub(start);
        if i < plan.warmup {
            continue;
        }
        if outcome.candidates.is_empty() {
            failures = failures.saturating_add(1);
            continue;
        }
        route.push(elapsed);
        candidates.push(u64::try_from(outcome.candidates.len()).unwrap_or(u64::MAX));
    }

    ScenarioReport {
        name: "routing_decision",
        what: "PolicySnapshot::route only — no adapter, no socket, no upstream",
        series: vec![route.summarize(), candidates.summarize()],
        failures,
        notes: vec![
            "Sole measurement of specification 18.3's `route`: eligibility, scoring, ordering."
                .to_owned(),
            "One alias over one target. A production policy with more bindings and \
             targets will be slower; this is a floor, not a forecast."
                .to_owned(),
        ],
    }
}

/// Scenario 2: a non-streaming chat request, end to end.
#[must_use]
pub fn chat_non_streaming(plan: Plan) -> ScenarioReport {
    let fixture = Fixture::new(chat_completion_response(), false);
    end_to_end(
        &fixture,
        plan,
        "chat_non_streaming",
        "buffered chat: route, encode, POST to the fake upstream, decode a complete body",
        |adapter, body| {
            // The decode half of translation, on the bytes the upstream sent.
            adapter.decode_response(200, body).ok().map(|e| e.len())
        },
        CHAT_COMPLETION_BODY.as_bytes(),
    )
}

/// Scenario 3: a streaming chat request, end to end.
#[must_use]
pub fn chat_streaming(plan: Plan) -> ScenarioReport {
    let fixture = Fixture::new(CannedResponse::event_stream(CHAT_STREAM_FRAMES), true);
    end_to_end(
        &fixture,
        plan,
        "chat_streaming",
        "streamed chat: route, encode, POST, decode every SSE frame to canonical events",
        |adapter, _body| {
            let mut decoded = 0usize;
            for frame in CHAT_STREAM_FRAMES {
                let events = adapter.decode_stream_event(None, frame).ok()?;
                decoded = decoded.saturating_add(events.len());
            }
            Some(decoded)
        },
        &[],
    )
}

/// The shared body of the two end-to-end scenarios.
///
/// `decode` re-runs the response half of translation on the same bytes the
/// upstream sent, which is what makes a per-iteration `router_overhead` sample
/// possible without instrumenting the data path.
fn end_to_end(
    fixture: &Fixture,
    plan: Plan,
    name: &'static str,
    what: &'static str,
    decode: impl Fn(&dyn Adapter, &[u8]) -> Option<usize>,
    response_body: &[u8],
) -> ScenarioReport {
    let state = &fixture.router.state;
    let clock = state.clock.as_ref();
    let groups: Vec<hypellm_core::ids::GroupId> = Vec::new();
    let (target, endpoint, adapter) = fixture.chosen_target();
    let address = fixture.upstream_address();

    let meta = RequestMeta {
        target: &target,
        endpoint: &endpoint,
        request_id: fixture.request.request_id.to_string(),
        streaming: fixture.request.stream.enabled,
        idempotency_key: fixture.request.hints.idempotency_key.clone(),
    };

    let n = plan.iterations;
    let mut overhead = Samples::new("router_overhead", Unit::Micros, n);
    let mut route = Samples::new("route", Unit::Micros, n);
    let mut translate_out = Samples::new("translate_out", Unit::Micros, n);
    let mut translate_in = Samples::new("translate_in", Unit::Micros, n);
    let mut total = Samples::new("pipeline_total", Unit::Micros, n);
    let mut direct = Samples::new("upstream_direct", Unit::Micros, n);
    let mut by_diff = Samples::new("overhead_by_diff", Unit::Micros, n);
    let mut failures = 0u64;

    for i in 0..plan.warmup.saturating_add(n) {
        let measured = i >= plan.warmup;

        // (a) A bare socket exchange with the same upstream, in the same loop,
        // so the two samples see the same machine state. Specification 19.1:
        // "compare direct-to-provider versus routed latency".
        let direct_start = clock.now_micros();
        let direct_ok = direct_exchange(address).is_ok();
        let direct_micros = clock.now_micros().saturating_sub(direct_start);

        // (b) The same request through the router.
        let total_start = clock.now_micros();
        let (outcome, delivered) = if fixture.request.stream.enabled {
            let mut sink = CountingSink::default();
            let outcome = pipeline::execute(
                state,
                &fixture.request,
                &groups,
                hypellm_core::rbac::PermissionSet::empty(),
                &mut sink,
            );
            (outcome, sink.events)
        } else {
            let mut sink = AccumulatingSink::default();
            let outcome = pipeline::execute(
                state,
                &fixture.request,
                &groups,
                hypellm_core::rbac::PermissionSet::empty(),
                &mut sink,
            );
            // The accumulator does not count events; a buffered response that
            // succeeded delivered one by definition.
            (outcome, 1)
        };
        let total_micros = clock.now_micros().saturating_sub(total_start);

        // (c) The translate half, re-run on the same inputs.
        let out_start = clock.now_micros();
        let encoded = adapter
            .validate(&fixture.request, &target.capabilities)
            .ok()
            .and_then(|()| adapter.path_for(&fixture.request).ok())
            .and_then(|_| adapter.encode_request(&fixture.request, &meta).ok());
        let out_micros = clock.now_micros().saturating_sub(out_start);

        let in_start = clock.now_micros();
        let decoded = decode(adapter, response_body);
        let in_micros = clock.now_micros().saturating_sub(in_start);

        if !measured {
            continue;
        }
        if !direct_ok
            || !outcome.is_success()
            || delivered == 0
            || encoded.is_none()
            || decoded.is_none()
        {
            failures = failures.saturating_add(1);
            continue;
        }

        route.push(outcome.trace.routing_micros);
        translate_out.push(out_micros);
        translate_in.push(in_micros);
        overhead.push(
            outcome
                .trace
                .routing_micros
                .saturating_add(out_micros)
                .saturating_add(in_micros),
        );
        total.push(total_micros);
        direct.push(direct_micros);
        by_diff.push(total_micros.saturating_sub(direct_micros));
    }

    ScenarioReport {
        name,
        what,
        series: vec![
            overhead.summarize(),
            route.summarize(),
            translate_out.summarize(),
            translate_in.summarize(),
            by_diff.summarize(),
            total.summarize(),
            direct.summarize(),
        ],
        failures,
        notes: vec![
            "`router_overhead` = `route` + `translate_out` + `translate_in`, summed per \
             iteration. The translate halves are re-run outside the pipeline on the same \
             inputs; the pipeline's own calls are not separately instrumented."
                .to_owned(),
            "`pipeline_total` includes the loopback upstream and is NOT the specification 19 \
             number. `upstream_direct` is the same exchange without the router."
                .to_owned(),
            "`overhead_by_diff` = `pipeline_total` - `upstream_direct` per iteration. It \
             saturates at zero, so scheduling noise biases it low; treat it as \
             corroboration of `router_overhead`, not as a second target."
                .to_owned(),
            "The fake upstream serves one request per accepted connection and closes, so \
             connection reuse is not exercised. Specification 19's pooled-reuse behaviour \
             is out of this harness's reach."
                .to_owned(),
        ],
    }
}

/// One request/response exchange with the upstream, with no router involved.
fn direct_exchange(address: SocketAddr) -> std::io::Result<usize> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{DIRECT_REQUEST_BODY}",
        DIRECT_REQUEST_BODY.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.flush()?;
    let mut received = Vec::new();
    stream.read_to_end(&mut received)?;
    Ok(received.len())
}

/// Run every scenario at its default plan.
#[must_use]
pub fn all(scale: usize) -> Vec<ScenarioReport> {
    vec![
        routing_decision(Plan::DECISION.scaled(scale)),
        chat_non_streaming(Plan::END_TO_END.scaled(scale)),
        chat_streaming(Plan::END_TO_END.scaled(scale)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_scales_without_reaching_zero_iterations() {
        let p = Plan::END_TO_END.scaled(1_000_000);
        assert_eq!(p.iterations, 1, "a scaled plan must still measure something");
        assert_eq!(p.warmup, 0);
        assert_eq!(Plan::DECISION.scaled(0).iterations, Plan::DECISION.iterations);
    }

    #[test]
    fn the_routing_scenario_produces_a_populated_distribution() {
        let report = routing_decision(Plan {
            iterations: 200,
            warmup: 20,
        });
        assert_eq!(report.failures, 0, "routing must not fail on the fixture");
        let route = report.series("route").expect("a route series");
        assert_eq!(route.count, 200);
        assert!(route.p99 >= route.p50, "quantiles must be ordered");
        assert!(route.max >= route.p999);
        let candidates = report.series("candidates").expect("a candidates series");
        assert_eq!(candidates.min, 1, "the fixture has exactly one eligible target");
    }

    #[test]
    fn the_non_streaming_scenario_completes_every_iteration() {
        let report = chat_non_streaming(Plan {
            iterations: 20,
            warmup: 5,
        });
        assert_eq!(report.failures, 0, "every request must succeed: {report:?}");
        let overhead = report.series("router_overhead").expect("an overhead series");
        assert_eq!(overhead.count, 20);
        let total = report.series("pipeline_total").expect("a total series");
        assert!(
            total.p50 >= overhead.p50,
            "end-to-end cannot be faster than the overhead it contains"
        );
    }

    #[test]
    fn the_streaming_scenario_completes_every_iteration() {
        let report = chat_streaming(Plan {
            iterations: 20,
            warmup: 5,
        });
        assert_eq!(report.failures, 0, "every request must succeed: {report:?}");
        let overhead = report.series("router_overhead").expect("an overhead series");
        assert_eq!(overhead.count, 20);
    }

    #[test]
    fn every_scenario_reports_the_series_the_report_names() {
        // A report that dropped a series would print a header with no row and
        // read as if the measurement had been taken.
        for report in all(50) {
            assert!(!report.series.is_empty(), "{} has no series", report.name);
            for series in &report.series {
                assert!(
                    series.count > 0,
                    "{}/{} is empty",
                    report.name,
                    series.label
                );
                assert_eq!(series.overflowed, 0, "{}/{} overflowed", report.name, series.label);
            }
        }
    }
}
