//! Bounded, redacted observability.
//!
//! Specification 18.1: "telemetry — Bounded structured logs, counters,
//! histograms, text exposition."
//!
//! Specification 17 sets the shape: metrics are local-first and exposed as text
//! for a platform collector to scrape, logs are newline-delimited JSON, and
//! neither carries a high-cardinality or sensitive value. The router embeds no
//! third-party agent or exporter — partly because the dependency policy admits
//! none, and partly because an agent with in-process access to request state is
//! a data-exfiltration path that no amount of configuration can close.
//!
//! # Why the vocabularies are closed
//!
//! [`metrics::LabelName`] and [`logs::Field`] are enums, not strings. It is not
//! possible to write `labels.with("user_id", …)` or `event.field("prompt", …)`:
//! those are compile errors. The alternative — a runtime allowlist — fails
//! open the first time someone adds a field in a hurry.

#![forbid(unsafe_code)]

pub mod logs;
pub mod metrics;

pub use logs::{
    Event, Field, Logger, Pseudonymizer, QueueingSink, Severity, Sink, StderrSink,
};
#[cfg(any(test, feature = "test-harness"))]
pub use logs::MemorySink;
pub use metrics::{LabelName, Labels, Registry, names};

use std::sync::Arc;

/// The observability facade the rest of the router uses.
///
/// Bundles the registry, logger, and pseudonymizer so that a request handler
/// holds one value rather than three, and so that a component that has a
/// `Telemetry` can always emit both a metric and a log line for the same event.
#[derive(Debug)]
pub struct Telemetry {
    /// The metric registry.
    pub metrics: Registry,
    /// The structured logger.
    pub logger: Logger,
    /// The identity pseudonymizer.
    pub pseudonyms: Pseudonymizer,
}

impl Telemetry {
    /// Assemble a facade.
    #[must_use]
    pub fn new(logger: Logger, pseudonym_key: &[u8]) -> Self {
        Self {
            metrics: Registry::new(),
            logger,
            pseudonyms: Pseudonymizer::new(pseudonym_key),
        }
    }

    /// A facade that logs to standard error at `minimum` severity, through a
    /// background writer.
    ///
    /// The queue is what keeps a stalled log reader from stalling the router:
    /// `StderrSink` writes synchronously under the process-wide stderr lock
    /// with no deadline, so a pipe nobody drains would otherwise block every
    /// thread that emits a line. If the writer thread cannot be started the
    /// facade falls back to writing synchronously — running without logs would
    /// be a worse answer than running with a stall that has never been
    /// observed.
    #[must_use]
    pub fn stderr(
        minimum: Severity,
        clock: Arc<dyn hypellm_core::time::Clock>,
        pseudonym_key: &[u8],
    ) -> Self {
        let sink: Box<dyn Sink> = match QueueingSink::start(Box::new(StderrSink)) {
            Ok(queued) => Box::new(queued),
            Err(_) => Box::new(StderrSink),
        };
        Self::new(Logger::new(sink, minimum, clock), pseudonym_key)
    }

    /// Emit a log event.
    pub fn log(&self, event: &Event) {
        self.logger.emit(event);
    }

    /// Increment a counter by one.
    pub fn count(&self, name: &'static str, help: &'static str, labels: &Labels) {
        self.metrics.counter_inc(name, help, labels);
    }

    /// Render the metric exposition.
    #[must_use]
    pub fn exposition(&self) -> String {
        self.metrics.exposition()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypellm_core::time::TestClock;

    fn facade() -> (Telemetry, Arc<MemorySink>) {
        #[derive(Debug)]
        struct Shared(Arc<MemorySink>);
        impl Sink for Shared {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }
        let sink = Arc::new(MemorySink::new());
        let logger = Logger::new(
            Box::new(Shared(Arc::clone(&sink))),
            Severity::Info,
            Arc::new(TestClock::new()),
        );
        (Telemetry::new(logger, b"pseudonym-key"), sink)
    }

    #[test]
    fn a_request_produces_both_a_metric_and_a_log_line() {
        let (t, sink) = facade();

        let labels = Labels::new()
            .with(LabelName::Operation, "chat")
            .with(LabelName::Outcome, "ok");
        t.count(names::REQUESTS_TOTAL, "Total requests.", &labels);
        t.log(
            &Event::info("request.completed")
                .str_field(Field::Tenant, &t.pseudonyms.tenant("acme"))
                .str_field(Field::Alias, "code-premium")
                .int_field(Field::Status, 200),
        );

        assert_eq!(t.metrics.counter_value(names::REQUESTS_TOTAL, &labels), Some(1));
        assert_eq!(sink.len(), 1);
        let line = &sink.lines()[0];
        assert!(line.contains("request.completed"));
        assert!(!line.contains("acme"), "the tenant must be pseudonymous");
    }

    #[test]
    fn exposition_reflects_recorded_metrics() {
        let (t, _) = facade();
        t.count(
            names::AUTH_FAILURES,
            "Authentication failures.",
            &Labels::one(LabelName::Listener, "inference"),
        );
        let text = t.exposition();
        assert!(text.contains("hypellm_auth_failures_total"));
        assert!(text.contains(r#"listener="inference""#));
    }

    #[test]
    fn the_facade_is_shareable_across_threads() {
        use std::thread;
        let (t, sink) = facade();
        let t = Arc::new(t);

        let mut handles = Vec::new();
        for i in 0..4u64 {
            let t = Arc::clone(&t);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    t.count(
                        names::REQUESTS_TOTAL,
                        "h",
                        &Labels::one(LabelName::Operation, "chat"),
                    );
                    t.log(&Event::info("tick").int_field(Field::Count, i));
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        assert_eq!(
            t.metrics
                .counter_value(names::REQUESTS_TOTAL, &Labels::one(LabelName::Operation, "chat")),
            Some(400)
        );
        assert_eq!(sink.len(), 400);
    }
}
