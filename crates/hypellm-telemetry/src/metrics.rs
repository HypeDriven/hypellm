//! Bounded metrics with an allowlisted label vocabulary.
//!
//! Specification 17: "High-cardinality labels such as raw user id, request id,
//! prompt, URL, and error text are forbidden in metrics."
//!
//! That rule is enforced structurally rather than by convention. A metric
//! series is identified by a [`Labels`] value, which can only be built from
//! [`LabelName`] variants — a closed enum. There is no way to attach a raw
//! string key, so a well-meaning addition of `user_id` to a counter is a
//! compile error rather than a cardinality explosion that takes down the
//! metrics backend at 3am.
//!
//! Label *values* are bounded too: each is capped and passed through
//! [`sanitize_value`], which rejects anything that would need escaping in the
//! exposition format.

use hypellm_core::time::{Histogram, LATENCY_BUCKETS_MS};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;

/// The closed vocabulary of metric label names.
///
/// Adding a variant is a deliberate act that shows up in review. Each one
/// should be low-cardinality by construction: an operation is one of five
/// values, a target is one of a configured set, an outcome is one of a handful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelName {
    /// The client protocol.
    Protocol,
    /// The operation.
    Operation,
    /// The client-visible alias.
    Alias,
    /// The selected target.
    Target,
    /// The provider family.
    Family,
    /// The router error code, or `ok`.
    Outcome,
    /// The circuit breaker state.
    BreakerState,
    /// The admission scope that rejected a request.
    Scope,
    /// The exclusion reason from a routing decision.
    Reason,
    /// The HTTP status class, as `2xx`, `4xx`, `5xx`.
    StatusClass,
    /// The listener a request arrived on.
    Listener,
    /// Whether usage was provider-reported or router-estimated.
    UsageSource,
    /// A fleet host. Administrator-configured, therefore bounded.
    Host,
    /// A fleet deployment. Administrator-configured, therefore bounded.
    Deployment,
    /// An accelerator. Administrator-configured, therefore bounded.
    Accelerator,
    /// A fleet agent. Administrator-configured, therefore bounded.
    Agent,
    /// A capability verb. A closed enum in the router.
    Capability,
    /// A reasoning tier. Five values, closed.
    Effort,
    /// Reserved: marks the series that absorbed a cardinality overflow.
    ///
    /// Its own name rather than a value of [`LabelName::Outcome`], because an
    /// overflow series shares a metric with real ones and has to be
    /// distinguishable from them. `{outcome="overflow"}` was not: nothing in
    /// the exposition told a reader whether that sample was a router outcome
    /// or the registry admitting it had stopped attributing.
    Overflow,
}

impl LabelName {
    /// The exposition name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Operation => "operation",
            Self::Alias => "alias",
            Self::Target => "target",
            Self::Family => "family",
            Self::Outcome => "outcome",
            Self::BreakerState => "breaker_state",
            Self::Scope => "scope",
            Self::Reason => "reason",
            Self::StatusClass => "status_class",
            Self::Listener => "listener",
            Self::UsageSource => "usage_source",
            Self::Host => "host",
            Self::Deployment => "deployment",
            Self::Accelerator => "accelerator",
            Self::Agent => "agent",
            Self::Capability => "capability",
            Self::Effort => "effort",
            Self::Overflow => "hypellm_overflow",
        }
    }

    /// Every label name, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Protocol,
            Self::Operation,
            Self::Alias,
            Self::Target,
            Self::Family,
            Self::Outcome,
            Self::BreakerState,
            Self::Scope,
            Self::Reason,
            Self::StatusClass,
            Self::Listener,
            Self::UsageSource,
            Self::Host,
            Self::Deployment,
            Self::Accelerator,
            Self::Agent,
            Self::Capability,
            Self::Effort,
            Self::Overflow,
        ]
    }
}

/// Maximum length of a label value.
pub const MAX_LABEL_VALUE_LEN: usize = 64;

/// Maximum number of distinct series one metric may have.
///
/// A backstop for the case a label value turns out to be higher-cardinality
/// than expected — a misconfigured alias naming scheme, say. Past the limit,
/// new series are folded into an `overflow` series rather than growing the map
/// without bound.
pub const MAX_SERIES_PER_METRIC: usize = 2_000;

/// How many accesses to a metric may pass without touching a series before
/// that series may be evicted to make room for a new one.
///
/// The cardinality cap on its own turns a memory attack into an observability
/// attack: whoever fills the table first keeps it, and every series created
/// afterwards — including every legitimate one — is unattributable for the life
/// of the process. Eviction is what makes the damage temporary.
///
/// Staleness is counted in accesses to the metric rather than in milliseconds,
/// which keeps the registry clock-free and makes the threshold scale with load
/// instead of with wall time: on a busy router a series that has missed eight
/// full sweeps of the table really is idle, and on an idle one nothing is
/// evicted because nothing is competing for the space.
#[allow(
    clippy::as_conversions,
    reason = "specification 18.2 requires checked conversions on data-plane \
              input; this one is neither. Both operands are compile-time \
              literals, the source is a `usize` that this file fixes at 2_000, \
              and the widening to `u64` is lossless on every target this router \
              builds for (16-bit targets have no std). `usize::try_from` and \
              `From` are not usable in a `const` initialiser, so `as` is the \
              only conversion available here; the alternative is duplicating \
              the literal and letting the two drift apart."
)]
pub const STALE_AFTER_ACCESSES: u64 = (MAX_SERIES_PER_METRIC as u64).saturating_mul(8);

/// How often the full-table scan that finds an eviction candidate may run.
///
/// The scan is O(series) under the write lock, and the path that triggers it is
/// exactly the path an attacker spraying label values takes. Running it on
/// every insert would hand them a lock-amplification lever; running it once per
/// this many attempts bounds the amortised cost to a few nanoseconds per
/// request while still reclaiming the table promptly.
const SCAN_INTERVAL: u64 = 256;

/// Reduce a label value to something safe for the exposition format.
///
/// Keeps ASCII alphanumerics and `-._:/`, replaces everything else with `_`,
/// and truncates. This is not escaping — it is narrowing, so that no label
/// value can carry a newline, a quote, or a backslash into the exposition
/// output and forge a metric line.
#[must_use]
pub fn sanitize_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_LABEL_VALUE_LEN));
    for c in raw.chars().take(MAX_LABEL_VALUE_LEN) {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '/') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

/// A sorted, bounded set of labels identifying one series.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Labels {
    pairs: Vec<(LabelName, String)>,
}

impl Labels {
    /// No labels.
    #[must_use]
    pub const fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Add a label, sanitizing the value.
    #[must_use]
    pub fn with(mut self, name: LabelName, value: &str) -> Self {
        let value = sanitize_value(value);
        match self.pairs.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = value,
            None => self.pairs.push((name, value)),
        }
        // Sorted so that two label sets built in different orders are the same
        // series.
        self.pairs.sort_by_key(|(n, _)| *n);
        self
    }

    /// One label.
    #[must_use]
    pub fn one(name: LabelName, value: &str) -> Self {
        Self::new().with(name, value)
    }

    /// Whether there are no labels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The exposition rendering, including braces.
    #[must_use]
    pub fn render(&self) -> String {
        if self.pairs.is_empty() {
            return String::new();
        }
        let mut out = String::from("{");
        for (i, (name, value)) in self.pairs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(name.as_str());
            out.push_str("=\"");
            out.push_str(value);
            out.push('"');
        }
        out.push('}');
        out
    }

    /// The overflow series used once a metric exceeds its cardinality budget.
    ///
    /// Only counters get one. Summing counters that could not be attributed is
    /// meaningful — "this many requests happened that I stopped labelling".
    /// Summing gauges from unrelated label sets is not, and merging histograms
    /// from unrelated label sets is not, so those observations are dropped and
    /// counted instead of being folded into a number that reads as data.
    #[must_use]
    pub fn overflow() -> Self {
        Self::one(LabelName::Overflow, "true")
    }
}

/// What kind of value a metric holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonically increasing.
    Counter,
    /// Goes up and down.
    Gauge,
    /// A latency or size distribution.
    Histogram,
}

impl MetricKind {
    const fn exposition_type(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

#[derive(Debug)]
enum Series {
    Counter(AtomicU64),
    Gauge(AtomicI64),
    Histogram(Histogram),
}

#[derive(Debug)]
struct Entry {
    value: Series,
    /// The metric access count at which this series was last touched.
    last_touch: AtomicU64,
}

#[derive(Debug)]
struct Metric {
    kind: MetricKind,
    help: &'static str,
    series: RwLock<BTreeMap<Labels, Entry>>,
    /// Monotonic count of accesses to this metric; the logical clock staleness
    /// is measured against.
    accesses: AtomicU64,
    /// Series evicted to make room, for the self-observability counters.
    evicted: AtomicU64,
    /// Observations that were folded into the overflow series or dropped.
    overflowed: AtomicU64,
}

/// The metric registry.
///
/// Specification 17: "Metrics are local first: a dependency-free text
/// exposition endpoint … The router does not embed third-party agents or
/// exporters."
#[derive(Debug, Default)]
pub struct Registry {
    metrics: RwLock<BTreeMap<&'static str, Metric>>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure(&self, name: &'static str, kind: MetricKind, help: &'static str) {
        if let Ok(map) = self.metrics.read() {
            if map.contains_key(name) {
                return;
            }
        }
        if let Ok(mut map) = self.metrics.write() {
            map.entry(name).or_insert_with(|| Metric {
                kind,
                help,
                series: RwLock::new(BTreeMap::new()),
                accesses: AtomicU64::new(0),
                evicted: AtomicU64::new(0),
                overflowed: AtomicU64::new(0),
            });
        }
    }

    fn with_series<R>(
        &self,
        name: &'static str,
        kind: MetricKind,
        help: &'static str,
        labels: &Labels,
        make: impl FnOnce() -> Series,
        f: impl FnOnce(&Series) -> R,
    ) -> Option<R> {
        self.ensure(name, kind, help);
        let map = self.metrics.read().ok()?;
        let metric = map.get(name)?;
        let now = metric.accesses.fetch_add(1, Ordering::Relaxed);

        if let Ok(series) = metric.series.read() {
            if let Some(entry) = series.get(labels) {
                entry.last_touch.store(now, Ordering::Relaxed);
                return Some(f(&entry.value));
            }
        }

        let mut series = metric.series.write().ok()?;
        // Re-check: another writer may have created it between the two locks.
        if !series.contains_key(labels) && series.len() >= MAX_SERIES_PER_METRIC {
            match evictable(&series, now) {
                Some(victim) => {
                    series.remove(&victim);
                    metric.evicted.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    metric.overflowed.fetch_add(1, Ordering::Relaxed);
                    // Only a counter gets an overflow series. A gauge folded
                    // with unrelated gauges is a wrong number rather than a
                    // missing one, and merged histograms describe no
                    // distribution that exists; both are worse than an absent
                    // sample, because a reader cannot tell they are wrong.
                    if kind != MetricKind::Counter {
                        return None;
                    }
                    let overflow = Labels::overflow();
                    let entry = series.entry(overflow).or_insert_with(|| Entry {
                        value: make(),
                        last_touch: AtomicU64::new(now),
                    });
                    entry.last_touch.store(now, Ordering::Relaxed);
                    return Some(f(&entry.value));
                }
            }
        }

        let entry = series.entry(labels.clone()).or_insert_with(|| Entry {
            value: make(),
            last_touch: AtomicU64::new(now),
        });
        entry.last_touch.store(now, Ordering::Relaxed);
        Some(f(&entry.value))
    }

    /// Increment a counter.
    pub fn counter_add(
        &self,
        name: &'static str,
        help: &'static str,
        labels: &Labels,
        delta: u64,
    ) {
        self.with_series(
            name,
            MetricKind::Counter,
            help,
            labels,
            || Series::Counter(AtomicU64::new(0)),
            |s| {
                if let Series::Counter(c) = s {
                    c.fetch_add(delta, Ordering::Relaxed);
                }
            },
        );
    }

    /// Increment a counter by one.
    pub fn counter_inc(&self, name: &'static str, help: &'static str, labels: &Labels) {
        self.counter_add(name, help, labels, 1);
    }

    /// Set a gauge.
    pub fn gauge_set(&self, name: &'static str, help: &'static str, labels: &Labels, value: i64) {
        self.with_series(
            name,
            MetricKind::Gauge,
            help,
            labels,
            || Series::Gauge(AtomicI64::new(0)),
            |s| {
                if let Series::Gauge(g) = s {
                    g.store(value, Ordering::Relaxed);
                }
            },
        );
    }

    /// Add to a gauge.
    pub fn gauge_add(&self, name: &'static str, help: &'static str, labels: &Labels, delta: i64) {
        self.with_series(
            name,
            MetricKind::Gauge,
            help,
            labels,
            || Series::Gauge(AtomicI64::new(0)),
            |s| {
                if let Series::Gauge(g) = s {
                    g.fetch_add(delta, Ordering::Relaxed);
                }
            },
        );
    }

    /// Observe a histogram sample.
    pub fn histogram_observe(
        &self,
        name: &'static str,
        help: &'static str,
        labels: &Labels,
        value: u64,
    ) {
        self.with_series(
            name,
            MetricKind::Histogram,
            help,
            labels,
            || Series::Histogram(Histogram::new(LATENCY_BUCKETS_MS)),
            |s| {
                if let Series::Histogram(h) = s {
                    h.observe(value);
                }
            },
        );
    }

    /// Read a counter, for tests and self-checks.
    #[must_use]
    pub fn counter_value(&self, name: &str, labels: &Labels) -> Option<u64> {
        let map = self.metrics.read().ok()?;
        let metric = map.get(name)?;
        let series = metric.series.read().ok()?;
        match &series.get(labels)?.value {
            Series::Counter(c) => Some(c.load(Ordering::Relaxed)),
            _ => None,
        }
    }

    /// Read a gauge.
    #[must_use]
    pub fn gauge_value(&self, name: &str, labels: &Labels) -> Option<i64> {
        let map = self.metrics.read().ok()?;
        let metric = map.get(name)?;
        let series = metric.series.read().ok()?;
        match &series.get(labels)?.value {
            Series::Gauge(g) => Some(g.load(Ordering::Relaxed)),
            _ => None,
        }
    }

    /// How many series a metric has.
    #[must_use]
    pub fn series_count(&self, name: &str) -> usize {
        self.metrics
            .read()
            .ok()
            .and_then(|m| m.get(name).map(|metric| {
                metric.series.read().map_or(0, |s| s.len())
            }))
            .unwrap_or(0)
    }

    /// How many series of a metric were evicted to make room for newer ones.
    #[must_use]
    pub fn evicted_series(&self, name: &str) -> u64 {
        self.metrics.read().ok().map_or(0, |m| {
            m.get(name)
                .map_or(0, |metric| metric.evicted.load(Ordering::Relaxed))
        })
    }

    /// How many observations of a metric were folded into its overflow series
    /// or dropped because the table was full of live series.
    #[must_use]
    pub fn overflowed_observations(&self, name: &str) -> u64 {
        self.metrics.read().ok().map_or(0, |m| {
            m.get(name)
                .map_or(0, |metric| metric.overflowed.load(Ordering::Relaxed))
        })
    }

    /// Render the text exposition format.
    ///
    /// Deliberately the widely-understood `# HELP` / `# TYPE` / sample layout,
    /// so a platform collector can scrape it without the router embedding an
    /// exporter (specification 17).
    #[must_use]
    pub fn exposition(&self) -> String {
        let mut out = String::new();
        let Ok(map) = self.metrics.read() else {
            return out;
        };
        for (name, metric) in map.iter() {
            let Ok(series) = metric.series.read() else {
                continue;
            };
            if series.is_empty() {
                continue;
            }
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(metric.help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(metric.kind.exposition_type());
            out.push('\n');

            for (labels, entry) in series.iter() {
                match &entry.value {
                    Series::Counter(c) => {
                        out.push_str(name);
                        out.push_str(&labels.render());
                        out.push(' ');
                        out.push_str(&c.load(Ordering::Relaxed).to_string());
                        out.push('\n');
                    }
                    Series::Gauge(g) => {
                        out.push_str(name);
                        out.push_str(&labels.render());
                        out.push(' ');
                        out.push_str(&g.load(Ordering::Relaxed).to_string());
                        out.push('\n');
                    }
                    Series::Histogram(h) => {
                        for (bound, count) in h.buckets() {
                            // `le` is rendered separately: it is a histogram
                            // structural label rather than part of the closed
                            // vocabulary, and its value is always a number the
                            // router chose.
                            let le = match bound {
                                Some(b) => b.to_string(),
                                None => "+Inf".to_owned(),
                            };
                            out.push_str(name);
                            out.push_str("_bucket");
                            out.push_str(&render_with_le(labels, &le));
                            out.push(' ');
                            out.push_str(&count.to_string());
                            out.push('\n');
                        }
                        out.push_str(name);
                        out.push_str("_sum");
                        out.push_str(&labels.render());
                        out.push(' ');
                        out.push_str(&h.sum().to_string());
                        out.push('\n');
                        out.push_str(name);
                        out.push_str("_count");
                        out.push_str(&labels.render());
                        out.push(' ');
                        out.push_str(&h.count().to_string());
                        out.push('\n');
                    }
                }
            }
        }

        // The registry reports on itself. Without this, a metric that has
        // stopped attributing looks exactly like a metric that is attributing
        // fine, and the difference is only visible to whoever thinks to
        // compare series counts against a number they would have to know.
        //
        // Emitted here rather than through `counter_add` so the registry cannot
        // recurse into itself while holding its own lock.
        let mut evicted = String::new();
        let mut overflowed = String::new();
        for (name, metric) in map.iter() {
            let e = metric.evicted.load(Ordering::Relaxed);
            let o = metric.overflowed.load(Ordering::Relaxed);
            if e > 0 {
                evicted.push_str(&format!(
                    "{}{{metric=\"{}\"}} {}\n",
                    names::SERIES_EVICTED,
                    sanitize_value(name),
                    e
                ));
            }
            if o > 0 {
                overflowed.push_str(&format!(
                    "{}{{metric=\"{}\"}} {}\n",
                    names::SERIES_OVERFLOWED,
                    sanitize_value(name),
                    o
                ));
            }
        }
        if !evicted.is_empty() {
            out.push_str("# HELP ");
            out.push_str(names::SERIES_EVICTED);
            out.push_str(" Series dropped to make room for newer label sets.\n# TYPE ");
            out.push_str(names::SERIES_EVICTED);
            out.push_str(" counter\n");
            out.push_str(&evicted);
        }
        if !overflowed.is_empty() {
            out.push_str("# HELP ");
            out.push_str(names::SERIES_OVERFLOWED);
            out.push_str(
                " Observations that exceeded a metric's cardinality budget and \
                 were folded or dropped.\n# TYPE ",
            );
            out.push_str(names::SERIES_OVERFLOWED);
            out.push_str(" counter\n");
            out.push_str(&overflowed);
        }
        out
    }
}

/// The stalest series, if one is stale enough to give up its slot.
///
/// Returns `None` when every series in the table has been touched recently,
/// which is the case that must still fold rather than evict: a table that is
/// full of *live* series is reporting a genuinely high-cardinality metric, and
/// evicting from it would just thrash. The overflow series itself is never a
/// victim — reclaiming it would erase the record that attribution was lost.
fn evictable(series: &BTreeMap<Labels, Entry>, now: u64) -> Option<Labels> {
    let overflow = Labels::overflow();
    // The scan is rate-limited by the caller's access counter rather than by a
    // clock, so that a spray of new label values cannot make every request pay
    // for a full-table walk under the write lock.
    if now % SCAN_INTERVAL != 0 {
        return None;
    }
    let (labels, touch) = series
        .iter()
        .filter(|(labels, _)| **labels != overflow)
        .map(|(labels, entry)| (labels, entry.last_touch.load(Ordering::Relaxed)))
        .min_by_key(|(_, touch)| *touch)?;
    if now.saturating_sub(touch) >= STALE_AFTER_ACCESSES {
        Some(labels.clone())
    } else {
        None
    }
}

fn render_with_le(labels: &Labels, le: &str) -> String {
    let base = labels.render();
    if base.is_empty() {
        return format!("{{le=\"{le}\"}}");
    }
    // Insert before the closing brace.
    let mut out = base;
    out.pop();
    out.push_str(",le=\"");
    out.push_str(le);
    out.push_str("\"}");
    out
}

/// The metric names the router publishes.
///
/// Centralised so that a name is defined once and every emit site refers to
/// the constant. Specification 17 lists the required signals.
pub mod names {
    /// Requests accepted, by protocol, operation, and outcome.
    pub const REQUESTS_TOTAL: &str = "hypellm_requests_total";
    /// Streams currently open.
    pub const ACTIVE_STREAMS: &str = "hypellm_active_streams";
    /// Tokens accounted, by source.
    pub const TOKENS_TOTAL: &str = "hypellm_tokens_total";
    /// Bytes read from clients.
    pub const CLIENT_BYTES_IN: &str = "hypellm_client_bytes_in_total";
    /// Bytes written to clients.
    pub const CLIENT_BYTES_OUT: &str = "hypellm_client_bytes_out_total";
    /// Requests waiting for admission.
    pub const QUEUE_DEPTH: &str = "hypellm_queue_depth";
    /// Time spent waiting for admission.
    pub const QUEUE_WAIT_MS: &str = "hypellm_queue_wait_milliseconds";
    /// Router processing overhead, excluding upstream time.
    pub const ROUTER_OVERHEAD_MS: &str = "hypellm_router_overhead_milliseconds";
    /// Time a stream spent blocked writing to a slow client.
    ///
    /// Specification 14 asks for explicit high/low watermarks; the blocking
    /// model produces the *behaviour* without a tunable, so this measures what
    /// the watermark would have controlled (`DI-037`).
    pub const STREAM_BACKPRESSURE_MS: &str = "hypellm_stream_backpressure_milliseconds";
    /// Upstream time to first byte.
    pub const UPSTREAM_FIRST_BYTE_MS: &str = "hypellm_upstream_first_byte_milliseconds";
    /// Upstream total latency.
    pub const UPSTREAM_LATENCY_MS: &str = "hypellm_upstream_latency_milliseconds";
    /// Upstream errors, by class.
    pub const UPSTREAM_ERRORS: &str = "hypellm_upstream_errors_total";
    /// Circuit breaker state, as a gauge per target.
    pub const BREAKER_STATE: &str = "hypellm_breaker_state";
    /// Authentication failures.
    pub const AUTH_FAILURES: &str = "hypellm_auth_failures_total";
    /// Admission rejections, by scope and reason.
    pub const ADMISSION_REJECTIONS: &str = "hypellm_admission_rejections_total";
    /// Routing exclusions, by reason.
    pub const ROUTING_EXCLUSIONS: &str = "hypellm_routing_exclusions_total";
    /// Retries and failovers.
    pub const RETRIES_TOTAL: &str = "hypellm_retries_total";
    /// The active configuration version.
    pub const CONFIG_VERSION: &str = "hypellm_config_version";
    /// Connections currently open.
    pub const OPEN_CONNECTIONS: &str = "hypellm_open_connections";
    /// Wall-clock synchronisation steps observed.
    pub const CLOCK_STEPS: &str = "hypellm_clock_steps_total";
    /// Requests served with a superseded credential after a rotation.
    pub const CREDENTIAL_FALLBACKS: &str = "hypellm_credential_fallbacks_total";
    /// Requests refused because no entropy was available.
    pub const ENTROPY_FAILURES: &str = "hypellm_entropy_failures_total";
    /// Series dropped from a metric to make room for newer label sets.
    pub const SERIES_EVICTED: &str = "hypellm_metric_series_evicted_total";
    /// Observations that exceeded a metric's cardinality budget.
    pub const SERIES_OVERFLOWED: &str = "hypellm_metric_series_overflowed_total";

    // -- Fleet orchestration (specification-extension 18) -------------------
    //
    // `host`, `deployment`, `accelerator`, `agent`, `capability`, and `effort`
    // are administrator-configured identifiers or closed enums, so they are
    // bounded by construction and admissible as labels — unlike a user id, a
    // request id, or a prompt, which remain forbidden.

    /// Activations attempted, by host and outcome.
    pub const FLEET_ACTIVATIONS: &str = "hypellm_fleet_activations_total";
    /// Deployments displaced, by host and reason.
    pub const FLEET_EVICTIONS: &str = "hypellm_fleet_evictions_total";
    /// Time from decision to ready, as a distribution.
    pub const FLEET_TIME_TO_READY_MS: &str = "hypellm_fleet_time_to_ready_milliseconds";
    /// Memory committed on an accelerator.
    pub const FLEET_RESIDENT_BYTES: &str = "hypellm_fleet_resident_bytes";
    /// Activations left in a host's hourly allowance.
    pub const FLEET_BUDGET_REMAINING: &str = "hypellm_fleet_activation_budget_remaining";
    /// How long requests waited for a cold capability, as experienced.
    pub const FLEET_QUEUE_WAIT_MS: &str = "hypellm_fleet_queue_wait_milliseconds";
    /// Age of the newest valid observation, which gates everything.
    pub const FLEET_OBSERVATION_AGE_MS: &str = "hypellm_fleet_observation_age_milliseconds";
    /// **The KPI**: activations divided by requests served from activated
    /// deployments, in permille.
    ///
    /// A healthy fleet trends toward zero as batching amortises each swap. A
    /// ratio near 1,000 means every request costs a swap and the configuration
    /// is wrong. Publishing it turns "relatively intelligent about it" from an
    /// aspiration into something an operator can check.
    pub const FLEET_THRASH_RATIO: &str = "hypellm_fleet_thrash_ratio_permille";
    /// Requests by reasoning tier and outcome.
    pub const REQUESTS_BY_EFFORT: &str = "hypellm_requests_by_effort_total";
    /// Reserved minus reconciled tokens, validating the effort multipliers and
    /// the document constants.
    pub const TOKEN_ESTIMATE_ERROR: &str = "hypellm_token_estimate_error";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_per_series() {
        let r = Registry::new();
        let a = Labels::one(LabelName::Operation, "chat");
        let b = Labels::one(LabelName::Operation, "embeddings");

        r.counter_inc(names::REQUESTS_TOTAL, "requests", &a);
        r.counter_inc(names::REQUESTS_TOTAL, "requests", &a);
        r.counter_add(names::REQUESTS_TOTAL, "requests", &b, 5);

        assert_eq!(r.counter_value(names::REQUESTS_TOTAL, &a), Some(2));
        assert_eq!(r.counter_value(names::REQUESTS_TOTAL, &b), Some(5));
        assert_eq!(r.series_count(names::REQUESTS_TOTAL), 2);
    }

    #[test]
    fn gauges_move_in_both_directions() {
        let r = Registry::new();
        let l = Labels::new();
        r.gauge_add(names::ACTIVE_STREAMS, "streams", &l, 3);
        assert_eq!(r.gauge_value(names::ACTIVE_STREAMS, &l), Some(3));
        r.gauge_add(names::ACTIVE_STREAMS, "streams", &l, -1);
        assert_eq!(r.gauge_value(names::ACTIVE_STREAMS, &l), Some(2));
        r.gauge_set(names::ACTIVE_STREAMS, "streams", &l, 0);
        assert_eq!(r.gauge_value(names::ACTIVE_STREAMS, &l), Some(0));
    }

    #[test]
    fn label_order_does_not_create_a_new_series() {
        let r = Registry::new();
        let a = Labels::new()
            .with(LabelName::Operation, "chat")
            .with(LabelName::Target, "local:qwen");
        let b = Labels::new()
            .with(LabelName::Target, "local:qwen")
            .with(LabelName::Operation, "chat");
        assert_eq!(a, b);

        r.counter_inc(names::REQUESTS_TOTAL, "h", &a);
        r.counter_inc(names::REQUESTS_TOTAL, "h", &b);
        assert_eq!(r.series_count(names::REQUESTS_TOTAL), 1);
        assert_eq!(r.counter_value(names::REQUESTS_TOTAL, &a), Some(2));
    }

    #[test]
    fn setting_a_label_twice_replaces_it() {
        let l = Labels::new()
            .with(LabelName::Operation, "chat")
            .with(LabelName::Operation, "embeddings");
        assert_eq!(l.render(), r#"{operation="embeddings"}"#);
    }

    #[test]
    fn label_values_are_narrowed_not_escaped() {
        // A value that could forge an exposition line must not survive intact.
        let hostile = "a\"b\nc\\d e";
        let sanitized = sanitize_value(hostile);
        assert!(!sanitized.contains('"'));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\\'));
        assert!(!sanitized.contains(' '));

        let l = Labels::one(LabelName::Alias, hostile);
        let rendered = l.render();
        assert_eq!(rendered.matches('"').count(), 2, "only the quoting pair");
        assert!(!rendered.contains('\n'));
    }

    #[test]
    fn label_values_are_capped() {
        let long = "a".repeat(1000);
        assert_eq!(sanitize_value(&long).len(), MAX_LABEL_VALUE_LEN);
    }

    #[test]
    fn an_empty_label_value_becomes_a_placeholder() {
        assert_eq!(sanitize_value(""), "none");
        assert_eq!(Labels::one(LabelName::Alias, "").render(), r#"{alias="none"}"#);
    }

    #[test]
    fn legitimate_identifier_characters_survive() {
        assert_eq!(sanitize_value("local:qwen-2.5_coder"), "local:qwen-2.5_coder");
        assert_eq!(sanitize_value("2xx"), "2xx");
    }

    #[test]
    fn cardinality_is_capped_by_an_overflow_series() {
        // The backstop for a label that turns out higher-cardinality than
        // expected: the map stops growing rather than exhausting memory.
        let r = Registry::new();
        for i in 0..(MAX_SERIES_PER_METRIC + 500) {
            let l = Labels::one(LabelName::Alias, &format!("alias-{i}"));
            r.counter_inc(names::REQUESTS_TOTAL, "h", &l);
        }
        let count = r.series_count(names::REQUESTS_TOTAL);
        assert!(
            count <= MAX_SERIES_PER_METRIC + 1,
            "series grew to {count}, past the cap"
        );
        assert!(
            r.counter_value(names::REQUESTS_TOTAL, &Labels::overflow())
                .unwrap_or(0)
                > 0,
            "overflow series must accumulate the excess"
        );
        assert!(
            r.overflowed_observations(names::REQUESTS_TOTAL) > 0,
            "the registry must report that it stopped attributing"
        );
    }

    #[test]
    fn the_overflow_series_is_distinguishable_from_a_real_outcome() {
        // It used to be `{outcome="overflow"}`, which reads in the exposition
        // exactly like a router outcome named "overflow" — so a metric that had
        // given up attributing was indistinguishable from one that had not.
        let r = Registry::new();
        for i in 0..(MAX_SERIES_PER_METRIC + 10) {
            r.counter_inc(
                names::REQUESTS_TOTAL,
                "h",
                &Labels::one(LabelName::Alias, &format!("a-{i}")),
            );
        }
        let text = r.exposition();
        assert!(
            text.contains("hypellm_overflow=\"true\""),
            "the overflow series must carry its own reserved label:\n{text}"
        );
        assert!(
            !text.contains("outcome=\"overflow\""),
            "the overflow series must not impersonate a router outcome:\n{text}"
        );
        assert!(
            text.contains(names::SERIES_OVERFLOWED),
            "the registry must expose its own overflow count:\n{text}"
        );
    }

    #[test]
    fn a_full_table_of_idle_series_is_reclaimed_rather_than_blinding_the_metric() {
        // The defect this replaces: whoever filled the table first kept it, and
        // every series created afterwards was unattributable for the life of
        // the process. Filling it with 2 000 values that are then never touched
        // again must not cost the router its ability to measure anything else.
        let r = Registry::new();
        for i in 0..MAX_SERIES_PER_METRIC {
            r.counter_inc(
                names::REQUESTS_TOTAL,
                "h",
                &Labels::one(LabelName::Alias, &format!("spray-{i}")),
            );
        }

        // Age the table past the staleness threshold without touching any of
        // the sprayed series: one live series absorbing the accesses is enough,
        // because staleness is measured in accesses to the metric.
        let live = Labels::one(LabelName::Alias, "legitimate");
        for _ in 0..(STALE_AFTER_ACCESSES + SCAN_INTERVAL) {
            r.counter_inc(names::REQUESTS_TOTAL, "h", &live);
        }

        // A new series now gets a slot of its own rather than the overflow bin.
        let fresh = Labels::one(LabelName::Alias, "after-the-spray");
        for _ in 0..(SCAN_INTERVAL * 2) {
            r.counter_inc(names::REQUESTS_TOTAL, "h", &fresh);
        }
        assert!(
            r.counter_value(names::REQUESTS_TOTAL, &fresh).is_some(),
            "a new series was still unattributable after the sprayed ones went idle"
        );
        assert!(
            r.evicted_series(names::REQUESTS_TOTAL) > 0,
            "nothing was reclaimed"
        );
        assert!(
            r.series_count(names::REQUESTS_TOTAL) <= MAX_SERIES_PER_METRIC + 1,
            "reclaiming must not let the table grow"
        );
    }

    #[test]
    fn a_live_series_is_never_evicted_by_a_spray_of_new_ones() {
        // The other half of the tradeoff. Eviction must not become a way to
        // delete someone else's measurements: a table full of *live* series is
        // reporting a genuinely high-cardinality metric, and folding is the
        // right answer there.
        let r = Registry::new();
        let mut all: Vec<Labels> = Vec::new();
        for i in 0..MAX_SERIES_PER_METRIC {
            let l = Labels::one(LabelName::Alias, &format!("live-{i}"));
            r.counter_inc(names::REQUESTS_TOTAL, "h", &l);
            all.push(l);
        }

        for round in 0..4 {
            // Everything stays warm...
            for l in &all {
                r.counter_inc(names::REQUESTS_TOTAL, "h", l);
            }
            // ...while new label values arrive.
            for i in 0..SCAN_INTERVAL {
                r.counter_inc(
                    names::REQUESTS_TOTAL,
                    "h",
                    &Labels::one(LabelName::Alias, &format!("new-{round}-{i}")),
                );
            }
        }

        assert_eq!(
            r.evicted_series(names::REQUESTS_TOTAL),
            0,
            "a live series was evicted to make room for a sprayed one"
        );
        for l in &all {
            assert!(
                r.counter_value(names::REQUESTS_TOTAL, l).is_some(),
                "a live series disappeared"
            );
        }
    }

    #[test]
    fn gauges_and_histograms_drop_rather_than_fold_on_overflow() {
        // Summing counters that could not be attributed answers a question.
        // Summing unrelated gauges, or merging unrelated histograms, produces a
        // number that looks like data and describes nothing — worse than a
        // missing sample, because a reader cannot tell it is wrong.
        let r = Registry::new();
        for i in 0..(MAX_SERIES_PER_METRIC + 50) {
            let l = Labels::one(LabelName::Alias, &format!("g-{i}"));
            r.gauge_set(names::QUEUE_DEPTH, "h", &l, 7);
            r.histogram_observe(names::UPSTREAM_LATENCY_MS, "h", &l, 12);
        }

        assert!(
            r.gauge_value(names::QUEUE_DEPTH, &Labels::overflow())
                .is_none(),
            "gauges must not be folded into one meaningless sum"
        );
        let text = r.exposition();
        assert!(
            !text.contains(&format!(
                "{}_count{}",
                names::UPSTREAM_LATENCY_MS,
                Labels::overflow().render()
            )),
            "histograms must not be merged across unrelated label sets:\n{text}"
        );
        assert!(
            r.overflowed_observations(names::QUEUE_DEPTH) > 0
                && r.overflowed_observations(names::UPSTREAM_LATENCY_MS) > 0,
            "dropped observations must still be counted"
        );
    }

    #[test]
    fn exposition_is_well_formed() {
        let r = Registry::new();
        r.counter_add(
            names::REQUESTS_TOTAL,
            "Total requests.",
            &Labels::one(LabelName::Operation, "chat"),
            7,
        );
        r.gauge_set(
            names::ACTIVE_STREAMS,
            "Open streams.",
            &Labels::new(),
            3,
        );
        r.histogram_observe(
            names::ROUTER_OVERHEAD_MS,
            "Router overhead.",
            &Labels::new(),
            5,
        );

        let text = r.exposition();
        assert!(text.contains("# HELP hypellm_requests_total Total requests."));
        assert!(text.contains("# TYPE hypellm_requests_total counter"));
        assert!(text.contains(r#"hypellm_requests_total{operation="chat"} 7"#));
        assert!(text.contains("# TYPE hypellm_active_streams gauge"));
        assert!(text.contains("hypellm_active_streams 3"));
        assert!(text.contains("# TYPE hypellm_router_overhead_milliseconds histogram"));
        assert!(text.contains(r#"hypellm_router_overhead_milliseconds_bucket{le="5"} 1"#));
        assert!(text.contains(r#"hypellm_router_overhead_milliseconds_bucket{le="+Inf"} 1"#));
        assert!(text.contains("hypellm_router_overhead_milliseconds_count 1"));
        assert!(text.contains("hypellm_router_overhead_milliseconds_sum 5"));

        // Every line is either a comment or `name[{labels}] value`.
        for line in text.lines() {
            assert!(!line.is_empty());
            if line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
            assert_eq!(parts.len(), 2, "malformed sample line: {line}");
            assert!(
                parts[0].parse::<f64>().is_ok(),
                "value is not numeric in: {line}"
            );
        }
    }

    #[test]
    fn exposition_is_deterministic() {
        let build = || {
            let r = Registry::new();
            for op in ["chat", "embeddings", "responses"] {
                r.counter_inc(
                    names::REQUESTS_TOTAL,
                    "h",
                    &Labels::one(LabelName::Operation, op),
                );
            }
            r.exposition()
        };
        assert_eq!(build(), build(), "ordering must not depend on hashing");
    }

    #[test]
    fn an_empty_registry_exposes_nothing() {
        assert_eq!(Registry::new().exposition(), "");
    }

    #[test]
    fn histogram_labels_include_the_bucket_bound() {
        let r = Registry::new();
        r.histogram_observe(
            names::UPSTREAM_LATENCY_MS,
            "h",
            &Labels::one(LabelName::Target, "t1"),
            300,
        );
        let text = r.exposition();
        assert!(text.contains(r#"{target="t1",le="500"}"#), "{text}");
        assert!(text.contains(r#"{target="t1",le="+Inf"}"#));
    }

    #[test]
    fn label_names_are_distinct() {
        let mut names: Vec<&str> = LabelName::all().iter().map(|l| l.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn the_vocabulary_excludes_high_cardinality_dimensions() {
        // Specification 17 forbids raw user id, request id, prompt, URL, and
        // error text as metric labels. None of them is expressible.
        let forbidden = ["user", "user_id", "principal", "request_id", "prompt", "url", "error"];
        for name in LabelName::all() {
            assert!(
                !forbidden.contains(&name.as_str()),
                "{} is a forbidden metric dimension",
                name.as_str()
            );
        }
    }

    #[test]
    fn concurrent_updates_are_counted_exactly() {
        use std::sync::Arc;
        use std::thread;

        let r = Arc::new(Registry::new());
        let labels = Labels::one(LabelName::Operation, "chat");
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = Arc::clone(&r);
            let labels = labels.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    r.counter_inc(names::REQUESTS_TOTAL, "h", &labels);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(r.counter_value(names::REQUESTS_TOTAL, &labels), Some(8000));
    }
}
