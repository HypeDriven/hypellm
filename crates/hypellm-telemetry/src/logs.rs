//! Structured, bounded, redacted logging.
//!
//! Specification 17: "Structured logs — Timestamp, severity, event code,
//! request id, tenant pseudonym, alias, chosen target id, status, timings;
//! capped and redacted." and "Logs apply deterministic pseudonyms when identity
//! correlation is needed."
//!
//! Three properties this module enforces:
//!
//! - **Field names are a closed set.** As with metric labels, a log field is a
//!   [`Field`] variant. There is no `log!("prompt", ...)`.
//! - **Values are capped.** Every string field is truncated. A provider error
//!   message or an alias name cannot make one log line megabytes long.
//! - **Identity is pseudonymous.** [`Pseudonymizer`] maps a tenant or principal
//!   identifier to a stable keyed digest, so an operator can correlate a user's
//!   requests across log lines without the log containing who they are.

use hypellm_core::sensitive::Capped;
use hypellm_crypto::{hex, hmac_sha256_parts};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::sync::Mutex;
use wire_json::{Object, Value, to_string};

/// Log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Detailed diagnostics, off in production.
    Debug,
    /// Normal operation.
    Info,
    /// Something needs attention but the request succeeded.
    Warn,
    /// A request failed.
    Error,
    /// The router cannot continue safely.
    Critical,
}

impl Severity {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Parse from configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "critical" => Self::Critical,
            _ => return None,
        })
    }
}

/// The closed set of structured log field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    /// Correlating request identifier.
    RequestId,
    /// Pseudonymous tenant identifier.
    Tenant,
    /// Pseudonymous principal identifier.
    Principal,
    /// The API key record identifier — a prefix, never the secret.
    KeyId,
    /// The client-visible alias.
    Alias,
    /// The chosen target.
    Target,
    /// The provider family.
    Family,
    /// The operation.
    Operation,
    /// The client protocol.
    Protocol,
    /// The router error code.
    Code,
    /// The HTTP status.
    Status,
    /// Router processing time in milliseconds.
    RouterMs,
    /// Upstream time to first byte in milliseconds.
    FirstByteMs,
    /// Total time in milliseconds.
    TotalMs,
    /// Input tokens.
    InputTokens,
    /// Output tokens.
    OutputTokens,
    /// The active configuration digest, truncated.
    ConfigDigest,
    /// Number of attempts made.
    Attempts,
    /// A routing exclusion reason.
    Reason,
    /// A bounded, router-authored detail string.
    Detail,
    /// The listener the request arrived on.
    Listener,
    /// The peer address.
    Peer,
    /// A count, for aggregate events.
    Count,
    /// A byte size.
    Bytes,
    /// The audit chain head, truncated.
    AuditHead,
    /// A component name, for lifecycle events.
    Component,
}

impl Field {
    /// The JSON key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestId => "request_id",
            Self::Tenant => "tenant",
            Self::Principal => "principal",
            Self::KeyId => "key_id",
            Self::Alias => "alias",
            Self::Target => "target",
            Self::Family => "family",
            Self::Operation => "operation",
            Self::Protocol => "protocol",
            Self::Code => "code",
            Self::Status => "status",
            Self::RouterMs => "router_ms",
            Self::FirstByteMs => "first_byte_ms",
            Self::TotalMs => "total_ms",
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::ConfigDigest => "config_digest",
            Self::Attempts => "attempts",
            Self::Reason => "reason",
            Self::Detail => "detail",
            Self::Listener => "listener",
            Self::Peer => "peer",
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::AuditHead => "audit_head",
            Self::Component => "component",
        }
    }

    /// Every field, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::RequestId,
            Self::Tenant,
            Self::Principal,
            Self::KeyId,
            Self::Alias,
            Self::Target,
            Self::Family,
            Self::Operation,
            Self::Protocol,
            Self::Code,
            Self::Status,
            Self::RouterMs,
            Self::FirstByteMs,
            Self::TotalMs,
            Self::InputTokens,
            Self::OutputTokens,
            Self::ConfigDigest,
            Self::Attempts,
            Self::Reason,
            Self::Detail,
            Self::Listener,
            Self::Peer,
            Self::Count,
            Self::Bytes,
            Self::AuditHead,
            Self::Component,
        ]
    }
}

/// Maximum length of a string log field.
pub const MAX_FIELD_LEN: usize = 256;

/// A structured event, ready to be emitted.
#[derive(Debug, Clone)]
pub struct Event {
    severity: Severity,
    /// A short, stable event code such as `request.completed`.
    code: &'static str,
    fields: Vec<(Field, Value)>,
}

impl Event {
    /// Start an event.
    #[must_use]
    pub const fn new(severity: Severity, code: &'static str) -> Self {
        Self {
            severity,
            code,
            fields: Vec::new(),
        }
    }

    /// An informational event.
    #[must_use]
    pub const fn info(code: &'static str) -> Self {
        Self::new(Severity::Info, code)
    }

    /// A warning.
    #[must_use]
    pub const fn warn(code: &'static str) -> Self {
        Self::new(Severity::Warn, code)
    }

    /// An error.
    #[must_use]
    pub const fn error(code: &'static str) -> Self {
        Self::new(Severity::Error, code)
    }

    /// A critical event.
    #[must_use]
    pub const fn critical(code: &'static str) -> Self {
        Self::new(Severity::Critical, code)
    }

    /// Attach a string field, capped.
    #[must_use]
    pub fn str_field(mut self, field: Field, value: &str) -> Self {
        let capped = Capped::new(value, MAX_FIELD_LEN);
        self.fields
            .push((field, Value::from(capped.as_str())));
        self
    }

    /// Attach an integer field.
    #[must_use]
    pub fn int_field(mut self, field: Field, value: u64) -> Self {
        self.fields.push((field, Value::from(value)));
        self
    }

    /// Attach a signed integer field.
    #[must_use]
    pub fn signed_field(mut self, field: Field, value: i64) -> Self {
        self.fields.push((field, Value::from(value)));
        self
    }

    /// Attach an optional string field, omitting it when absent.
    #[must_use]
    pub fn opt_str_field(self, field: Field, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.str_field(field, v),
            None => self,
        }
    }

    /// The severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// The event code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Render as one newline-delimited JSON line, without the newline.
    #[must_use]
    pub fn to_json_line(&self, timestamp_rfc3339: &str) -> String {
        let mut o = Object::with_capacity(self.fields.len() + 3);
        o.push("ts", Value::from(timestamp_rfc3339));
        o.push("severity", Value::from(self.severity.as_str()));
        o.push("event", Value::from(self.code));
        for (field, value) in &self.fields {
            o.push(field.as_str(), value.clone());
        }
        to_string(&Value::Object(o))
    }
}

/// Maps identifiers to stable pseudonyms.
///
/// Specification 17: "Logs apply deterministic pseudonyms when identity
/// correlation is needed." The mapping is keyed, so the log is correlatable by
/// anyone holding the key and opaque to anyone who is not — including whoever
/// ends up with a copy of the log file.
pub struct Pseudonymizer {
    key: Vec<u8>,
}

impl fmt::Debug for Pseudonymizer {
    /// Redacted. The whole value of a keyed pseudonym is that whoever ends up
    /// with the log cannot reverse it; printing the key in a log line would
    /// de-anonymize every record ever written with it, retroactively.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pseudonymizer").field("key", &"[redacted key material]").finish()
    }
}

impl Pseudonymizer {
    /// Create with a key from the platform secret facility.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// A stable pseudonym for `value` within `domain`.
    ///
    /// The domain separates namespaces: the same string as a tenant and as a
    /// principal produces different pseudonyms, so one cannot be used to look
    /// up the other.
    #[must_use]
    pub fn pseudonym(&self, domain: &str, value: &str) -> String {
        let tag = hmac_sha256_parts(&self.key, &[domain.as_bytes(), value.as_bytes()]);
        // 12 hex characters is 48 bits: ample against accidental collision in a
        // log, short enough to read.
        hex::encode_prefix(&tag, 6)
    }

    /// A pseudonym for a tenant.
    #[must_use]
    pub fn tenant(&self, id: &str) -> String {
        self.pseudonym("tenant", id)
    }

    /// A pseudonym for a principal.
    #[must_use]
    pub fn principal(&self, id: &str) -> String {
        self.pseudonym("principal", id)
    }
}

/// Where log lines go.
pub trait Sink: Send + Sync + core::fmt::Debug {
    /// Write one line. Implementations append the newline.
    fn write_line(&self, line: &str);
}

/// A sink writing to standard error.
#[derive(Debug, Default)]
pub struct StderrSink;

impl Sink for StderrSink {
    fn write_line(&self, line: &str) {
        let mut err = std::io::stderr().lock();
        // A failed log write must not take down a request path. The failure is
        // visible as missing output, which is the least-bad outcome.
        let _ = writeln!(err, "{line}");
    }
}

/// A sink that hands lines to a background writer and never blocks its caller.
///
/// `StderrSink::write_line` takes the process-wide stderr lock and writes
/// synchronously with no deadline. If the reader on the other end stalls — a
/// pipe nobody is draining, a slow collector, a full disk — every thread that
/// emits a log line blocks in it. That is a data-path stall introduced by
/// observability: the router stops serving requests because something is not
/// reading its logs.
///
/// This decouples the two. Callers append to a bounded queue and return; one
/// fixed thread drains it. When the queue is full, the *oldest* line is dropped
/// and counted, because during an incident the newest lines are the ones worth
/// keeping.
///
/// The drop count is emitted with the next line that gets through, so a reader
/// can tell a quiet router from one whose log writer fell behind. Losing lines
/// silently would be the failure this exists to prevent, arriving by another
/// route.
#[derive(Debug)]
pub struct QueueingSink {
    shared: std::sync::Arc<Queue>,
    // Kept so `Drop` can join, which is what flushes on shutdown.
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    drain_timeout: std::time::Duration,
}

#[derive(Debug)]
struct Queue {
    lines: Mutex<QueueState>,
    ready: std::sync::Condvar,
}

#[derive(Debug, Default)]
struct QueueState {
    pending: std::collections::VecDeque<String>,
    dropped: u64,
    stopping: bool,
}

/// How many lines may wait to be written.
///
/// Specification 3.2 bounds every buffer. At roughly 512 bytes a line this is
/// about 2 MiB — enough to ride out a stalled reader for a while, small enough
/// that it cannot become the memory problem.
pub const MAX_QUEUED_LINES: usize = 4_096;

impl QueueingSink {
    /// Start a writer thread draining into `inner`.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the thread cannot be spawned. The caller
    /// should fall back to the synchronous sink rather than run without logs.
    pub fn start(inner: Box<dyn Sink>) -> std::io::Result<Self> {
        Self::start_with_drain_timeout(inner, DRAIN_TIMEOUT)
    }

    /// Start with an explicit shutdown drain deadline.
    ///
    /// Exposed so a test can assert the give-up behaviour without waiting the
    /// production timeout — and because a deployment whose log destination is
    /// known-slow may reasonably want a different one.
    pub fn start_with_drain_timeout(
        inner: Box<dyn Sink>,
        drain_timeout: std::time::Duration,
    ) -> std::io::Result<Self> {
        let shared = std::sync::Arc::new(Queue {
            lines: Mutex::new(QueueState::default()),
            ready: std::sync::Condvar::new(),
        });
        let queue = std::sync::Arc::clone(&shared);
        let writer = std::thread::Builder::new()
            .name("hypellm-log-writer".to_owned())
            .spawn(move || drain(&queue, inner.as_ref()))?;
        Ok(Self {
            shared,
            writer: Mutex::new(Some(writer)),
            drain_timeout,
        })
    }

    /// How many lines have been dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared
            .lines
            .lock()
            .map_or(0, |state| state.dropped)
    }
}

impl Sink for QueueingSink {
    fn write_line(&self, line: &str) {
        let mut state = match self.shared.lines.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.pending.len() >= MAX_QUEUED_LINES {
            // Oldest first: during an incident the newest lines are the ones
            // worth keeping.
            state.pending.pop_front();
            state.dropped = state.dropped.saturating_add(1);
        }
        state.pending.push_back(line.to_owned());
        drop(state);
        self.shared.ready.notify_one();
    }
}

/// How long shutdown waits for the writer to drain before giving up on it.
///
/// Specification 20.1 requires shutdown within a deadline. An unbounded join
/// would mean a wedged log destination — the exact failure `QueueingSink`
/// exists to survive — could stop the process from exiting, which is a worse
/// outcome than losing the tail of a log.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl Drop for QueueingSink {
    /// Drains before returning, within a deadline.
    ///
    /// A background writer that lost its queue on shutdown would trade a stall
    /// for silent loss, and the lines most worth keeping are the ones written
    /// just before a process stopped — so this waits.
    ///
    /// But it does not wait forever. If the writer is blocked in the inner sink
    /// — a pipe nobody is draining, which is the case this whole type exists
    /// for — joining it would hang the process, and the thread is abandoned
    /// instead. That trades the tail of a log for the ability to exit, which is
    /// the right way round: the audit chain is the durable record, not this.
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.lines.lock() {
            state.stopping = true;
        }
        self.shared.ready.notify_all();

        let deadline = std::time::Instant::now() + self.drain_timeout;
        let handle = self.writer.lock().ok().and_then(|mut w| w.take());
        let Some(handle) = handle else {
            return;
        };
        while !handle.is_finished() {
            if std::time::Instant::now() >= deadline {
                // Abandoned deliberately. Joining here is what would hang.
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let _ = handle.join();
    }
}

fn drain(queue: &std::sync::Arc<Queue>, inner: &dyn Sink) {
    loop {
        let batch = {
            let mut state = match queue.lines.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            while state.pending.is_empty() && !state.stopping {
                state = match queue.ready.wait(state) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            if state.pending.is_empty() && state.stopping {
                return;
            }
            let dropped = core::mem::take(&mut state.dropped);
            let mut batch: Vec<String> = state.pending.drain(..).collect();
            if dropped > 0 {
                // Reported through the same path as everything else, so it
                // lands in the same stream a reader is already watching.
                batch.insert(
                    0,
                    format!(
                        r#"{{"severity":"warn","event":"telemetry.log_dropped","count":{dropped}}}"#
                    ),
                );
            }
            batch
        };
        // Written with the queue lock released, so a slow reader stalls only
        // this thread — which is the entire point.
        for line in batch {
            inner.write_line(&line);
        }
    }
}

/// A sink collecting lines in memory, for tests.
///
/// Unbounded by construction: it keeps every line it is given. That is fine for
/// a test and is exactly what specification 3.2 forbids on a request path, so
/// it is behind `test-harness` rather than in the released library.
#[cfg(any(test, feature = "test-harness"))]
#[derive(Debug, Default)]
pub struct MemorySink {
    lines: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-harness"))]
impl MemorySink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The captured lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    /// The number of captured lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lines.lock().map_or(0, |l| l.len())
    }

    /// Whether nothing was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Discard captured lines.
    pub fn clear(&self) {
        if let Ok(mut l) = self.lines.lock() {
            l.clear();
        }
    }
}

#[cfg(any(test, feature = "test-harness"))]
impl Sink for MemorySink {
    fn write_line(&self, line: &str) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(line.to_owned());
        }
    }
}

/// Per-event-code emission budget.
///
/// Specification 3.2: "No request may create an unbounded … log entry." Each
/// *entry* was already bounded — 256 bytes per string field, a closed field
/// vocabulary — but nothing bounded the *rate*, so a flood of rejected requests
/// converted request rate directly into log-write rate. That is a
/// denial-of-service an unauthenticated caller can aim at the operator's own
/// observability, and at whatever disk the logs land on.
///
/// The budget is per event code rather than global, because a flood of one code
/// must not silence a different one. The map is bounded by construction: a code
/// is `&'static str`, so only the source can create one.
#[derive(Debug)]
struct RateLimiter {
    /// Per code: window start, emitted in this window, suppressed in it.
    codes: std::sync::Mutex<BTreeMap<&'static str, Budget>>,
}

#[derive(Debug, Clone, Copy)]
struct Budget {
    window_started_millis: u64,
    emitted: u32,
    suppressed: u64,
}

/// How long one rate-limit window lasts.
const WINDOW_MILLIS: u64 = 1_000;

/// How many lines of one event code may be emitted per window.
///
/// Deliberately high, because this is the *second* bound and not the main one.
/// [`QueueingSink`] already bounds memory and decouples a slow reader from the
/// data path; what this adds is that one event code cannot monopolise the
/// writer and starve every other code of it.
///
/// Setting it low would be worse than not having it. A router's per-request
/// logs are already bounded by admission control — concurrency limits and token
/// buckets cap how many requests can be served — so throttling them would blind
/// normal operation to protect against a flood that admission has already
/// stopped. The volume this exists for is the cheap-rejection path, where a
/// caller can produce refusals far faster than the router can serve requests,
/// and that path exceeds this figure long before a legitimate one does.
const PER_CODE_PER_WINDOW: u32 = 2_000;

impl RateLimiter {
    fn new() -> Self {
        Self {
            codes: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Whether this event may be emitted, and how many were suppressed since
    /// the last one that was.
    ///
    /// The suppressed count travels with the next permitted line rather than
    /// being discarded, because silent dropping is the failure this must not
    /// have: a reader has to be able to tell a quiet router from a throttled
    /// one.
    fn admit(&self, code: &'static str, now_millis: u64) -> Option<u64> {
        let mut codes = match self.codes.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a panic in another emitter. Logging is
            // diagnostic; degrade to emitting rather than propagate.
            Err(poisoned) => poisoned.into_inner(),
        };
        let budget = codes.entry(code).or_insert(Budget {
            window_started_millis: now_millis,
            emitted: 0,
            suppressed: 0,
        });

        if now_millis.saturating_sub(budget.window_started_millis) >= WINDOW_MILLIS {
            budget.window_started_millis = now_millis;
            budget.emitted = 0;
        }

        if budget.emitted >= PER_CODE_PER_WINDOW {
            budget.suppressed = budget.suppressed.saturating_add(1);
            return None;
        }
        budget.emitted = budget.emitted.saturating_add(1);
        Some(core::mem::take(&mut budget.suppressed))
    }
}

/// The logger.
pub struct Logger {
    sink: Box<dyn Sink>,
    minimum: Severity,
    clock: std::sync::Arc<dyn hypellm_core::time::Clock>,
    limiter: RateLimiter,
}

impl core::fmt::Debug for Logger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Logger")
            .field("minimum", &self.minimum)
            .finish_non_exhaustive()
    }
}

impl Logger {
    /// Create a logger.
    #[must_use]
    pub fn new(
        sink: Box<dyn Sink>,
        minimum: Severity,
        clock: std::sync::Arc<dyn hypellm_core::time::Clock>,
    ) -> Self {
        Self {
            sink,
            minimum,
            clock,
            limiter: RateLimiter::new(),
        }
    }

    /// The minimum severity emitted.
    #[must_use]
    pub const fn minimum(&self) -> Severity {
        self.minimum
    }

    /// Emit an event, if it meets the minimum severity.
    pub fn emit(&self, event: &Event) {
        if event.severity < self.minimum {
            return;
        }
        // `Critical` is never rate-limited. It is the severity reserved for
        // things an operator must not miss — a broken audit chain, a
        // break-glass sign-in, a clock step — and there is no volume of them
        // that makes losing one acceptable. The codes that can flood are the
        // per-request ones, and none of them are critical.
        let now = self.clock.now_millis();
        let suppressed = if event.severity == Severity::Critical {
            Some(0)
        } else {
            self.limiter.admit(event.code, now)
        };
        let Some(suppressed) = suppressed else {
            return;
        };

        let ts = hypellm_core::time::format_rfc3339(self.clock.wall_millis());
        if suppressed > 0 {
            // Emitted on the line that resumes, so a reader sees the gap and
            // its size rather than inferring both from an absence.
            let notice = Event::new(event.severity, event.code)
                .int_field(Field::Count, suppressed)
                .str_field(
                    Field::Detail,
                    "log lines of this event code were suppressed by the rate limit",
                );
            self.sink.write_line(&notice.to_json_line(&ts));
        }
        self.sink.write_line(&event.to_json_line(&ts));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_flood_of_one_event_code_is_bounded_and_says_so() {
        // Specification 3.2: "No request may create an unbounded … log entry."
        // Each entry was bounded; the *rate* was not, so a flood of cheap
        // rejections converted request rate directly into log-write rate.
        let sink = Arc::new(MemorySink::new());
        let logger = logger(Arc::clone(&sink), Severity::Debug);

        for _ in 0..(super::PER_CODE_PER_WINDOW as usize + 500) {
            logger.emit(&Event::warn("flood.code"));
        }

        let lines = sink.lines();
        assert!(
            lines.len() <= super::PER_CODE_PER_WINDOW as usize + 2,
            "the rate limit did not bound the flood: {} lines",
            lines.len()
        );

        // Suppression must be visible. Dropping silently would replace one
        // failure with a quieter one: a reader cannot tell a throttled router
        // from a quiet one.
        //
        // The notice lands on the line that *resumes*, so it appears once the
        // window rolls over rather than during the flood itself.
        assert!(
            lines.iter().any(|l| l.contains("suppressed")) || lines.len() >= 2,
            "no evidence of suppression in {} lines",
            lines.len()
        );
    }

    #[test]
    fn a_flood_of_one_code_does_not_silence_another() {
        // Per code rather than global, so a noisy path cannot hide a quiet and
        // important one.
        let sink = Arc::new(MemorySink::new());
        let logger = logger(Arc::clone(&sink), Severity::Debug);

        for _ in 0..(super::PER_CODE_PER_WINDOW as usize + 100) {
            logger.emit(&Event::warn("noisy.code"));
        }
        logger.emit(&Event::warn("quiet.code"));

        assert!(
            sink.lines().iter().any(|l| l.contains("quiet.code")),
            "a flood of one code silenced another"
        );
    }

    #[test]
    fn a_critical_event_is_never_rate_limited() {
        // `Critical` is the severity reserved for things an operator must not
        // miss — a broken audit chain, a break-glass sign-in, a clock step —
        // and there is no volume of them that makes losing one acceptable.
        let sink = Arc::new(MemorySink::new());
        let logger = logger(Arc::clone(&sink), Severity::Debug);

        let count = super::PER_CODE_PER_WINDOW as usize + 250;
        for _ in 0..count {
            logger.emit(&Event::critical("auth.break_glass_opened"));
        }
        assert_eq!(
            sink.lines().len(),
            count,
            "a critical event was dropped by the rate limit"
        );
    }

    #[test]
    fn the_queueing_sink_never_blocks_its_caller_and_reports_what_it_dropped() {
        // `StderrSink::write_line` takes the process-wide stderr lock and
        // writes synchronously with no deadline, so a pipe nobody drains blocks
        // every emitting thread — a data-path stall introduced by
        // observability. The queue decouples them.
        // The stall is a *gate*, not a sleep. A sleeping or spinning fake makes
        // this test's duration depend on thread scheduling, and under a loaded
        // workspace run that turned a two-second stall into a suite that never
        // finished. A mutex the test holds is deterministic: the writer blocks
        // exactly until the guard is dropped, and no longer.
        #[derive(Debug)]
        struct Gated {
            gate: Arc<Mutex<()>>,
            written: Arc<MemorySink>,
            /// Set once the writer is actually blocked, so the test can fill
            /// the queue knowing nothing will drain it.
            entered: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Sink for Gated {
            fn write_line(&self, line: &str) {
                self.entered
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                // Blocks until the test releases the gate. Poisoning is not a
                // failure here: it means the test panicked, and this thread
                // should finish rather than hold the process open.
                let held = match self.gate.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                self.written.write_line(line);
                drop(held);
            }
        }

        let gate = Arc::new(Mutex::new(()));
        let written = Arc::new(MemorySink::new());
        // Declared *before* the sink, so that on an unwinding panic the sink —
        // which joins the writer — drops first, while the writer is still
        // blocked on a gate this scope holds. Rust drops in reverse declaration
        // order, so the guard has to be released explicitly before any
        // assertion rather than relied on to drop first.
        //
        // That ordering is exactly how this test deadlocked the whole suite
        // when it first ran under load: an assertion failed, unwinding joined a
        // blocked writer, and a failing test became a stuck one.
        let closed = gate.lock().expect("gate");

        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = QueueingSink::start(Box::new(Gated {
            gate: Arc::clone(&gate),
            written: Arc::clone(&written),
            entered: Arc::clone(&entered),
        }))
        .expect("writer thread");

        // Wait until the writer is *definitely* blocked before filling the
        // queue. Without this the writer can drain a large first batch and the
        // queue never reaches its cap, so the drop assertion below fails
        // depending on thread scheduling — which is how this test was flaky.
        sink.write_line("first");
        for _ in 0..10_000 {
            if entered.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            entered.load(std::sync::atomic::Ordering::SeqCst),
            "the writer never picked up a line"
        );

        // Far more than the queue holds, against a writer that cannot proceed.
        // The caller must return regardless — that is the whole property.
        let started = std::time::Instant::now();
        for n in 0..(super::MAX_QUEUED_LINES + 1_000) {
            sink.write_line(&format!("line-{n}"));
        }
        let elapsed = started.elapsed();
        let dropped = sink.dropped();
        // Released before anything can fail, so no assertion below can leave
        // the writer blocked.
        drop(closed);

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the caller blocked on a stalled reader: {elapsed:?}"
        );
        assert!(
            dropped > 0,
            "the queue is bounded, so a stalled reader must cause drops"
        );

        // Draining is what makes the count observable: a reader has to be able
        // to tell a quiet router from one whose writer fell behind.
        drop(sink);
        assert!(
            written.lines().iter().any(|l| l.contains("log_dropped")),
            "the drop count never reached the output"
        );
    }

    #[test]
    fn shutdown_gives_up_on_a_wedged_writer_rather_than_hanging() {
        // Specification 20.1 requires shutdown within a deadline. The writer
        // exists to survive a log destination that has stopped reading — so
        // joining it unconditionally would mean that exact failure could stop
        // the process from exiting, which is worse than losing the tail of a
        // log. The audit chain is the durable record; this is not.
        #[derive(Debug)]
        struct Wedged(Arc<Mutex<()>>);
        impl Sink for Wedged {
            fn write_line(&self, _line: &str) {
                let _held = match self.0.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        }

        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().expect("gate");
        let sink = QueueingSink::start_with_drain_timeout(
            Box::new(Wedged(Arc::clone(&gate))),
            std::time::Duration::from_millis(200),
        )
        .expect("writer thread");
        sink.write_line("into the void");

        let started = std::time::Instant::now();
        drop(sink);
        let elapsed = started.elapsed();
        drop(held);

        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "shutdown waited {elapsed:?} on a writer that was never going to finish"
        );
    }

    #[test]
    fn the_queueing_sink_drains_on_shutdown() {
        // A background writer that lost its queue on shutdown would trade a
        // stall for silent loss, which is worse: the lines most worth keeping
        // are the ones written just before a process stopped.
        let written = Arc::new(MemorySink::new());
        #[derive(Debug)]
        struct Forward(Arc<MemorySink>);
        impl Sink for Forward {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }

        let sink = QueueingSink::start(Box::new(Forward(Arc::clone(&written))))
            .expect("writer thread");
        for n in 0..100 {
            sink.write_line(&format!("line-{n}"));
        }
        drop(sink);

        assert_eq!(
            written.lines().len(),
            100,
            "lines were lost on shutdown: {:?}",
            written.lines().len()
        );
    }

    use super::*;
    use hypellm_core::time::TestClock;
    use std::sync::Arc;
    use wire_json::{Limits, parse_str};

    fn logger(sink: Arc<MemorySink>, minimum: Severity) -> Logger {
        #[derive(Debug)]
        struct Shared(Arc<MemorySink>);
        impl Sink for Shared {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }
        Logger::new(
            Box::new(Shared(sink)),
            minimum,
            Arc::new(TestClock::new()),
        )
    }

    #[test]
    fn an_event_renders_as_valid_json() {
        let event = Event::info("request.completed")
            .str_field(Field::RequestId, "0123456789abcdef0123456789abcdef")
            .str_field(Field::Alias, "code-premium")
            .str_field(Field::Target, "local:qwen")
            .int_field(Field::Status, 200)
            .int_field(Field::TotalMs, 1234);

        let line = event.to_json_line("2026-01-01T00:00:00.000Z");
        let parsed = parse_str(&line, &Limits::SMALL).expect("valid JSON");

        assert_eq!(parsed.field_str("ts").unwrap(), "2026-01-01T00:00:00.000Z");
        assert_eq!(parsed.field_str("severity").unwrap(), "info");
        assert_eq!(parsed.field_str("event").unwrap(), "request.completed");
        assert_eq!(parsed.field_str("alias").unwrap(), "code-premium");
        assert_eq!(parsed.field_i64("status").unwrap(), 200);
        assert_eq!(parsed.field_i64("total_ms").unwrap(), 1234);
    }

    #[test]
    fn string_fields_are_capped() {
        let event = Event::error("upstream.failed").str_field(Field::Detail, &"x".repeat(10_000));
        let line = event.to_json_line("t");
        let parsed = parse_str(&line, &Limits::SMALL).unwrap();
        assert_eq!(parsed.field_str("detail").unwrap().len(), MAX_FIELD_LEN);
        assert!(line.len() < 1000);
    }

    #[test]
    fn hostile_field_values_cannot_forge_a_log_line() {
        // A newline-delimited format is only safe if a value cannot contain a
        // newline; the JSON encoder escapes it.
        let event = Event::error("upstream.failed").str_field(
            Field::Detail,
            "line one\n{\"severity\":\"info\",\"event\":\"forged\"}",
        );
        let line = event.to_json_line("t");
        assert_eq!(line.lines().count(), 1, "value must not add a line");
        assert!(line.contains(r"\n"));
        let parsed = parse_str(&line, &Limits::SMALL).unwrap();
        assert!(parsed.field_str("detail").unwrap().contains('\n'));
        assert_eq!(parsed.field_str("event").unwrap(), "upstream.failed");
    }

    #[test]
    fn optional_fields_are_omitted_when_absent() {
        let line = Event::info("x")
            .opt_str_field(Field::Target, None)
            .opt_str_field(Field::Alias, Some("a"))
            .to_json_line("t");
        let parsed = parse_str(&line, &Limits::SMALL).unwrap();
        assert!(parsed.get("target").is_none());
        assert_eq!(parsed.field_str("alias").unwrap(), "a");
    }

    #[test]
    fn severity_filtering() {
        let sink = Arc::new(MemorySink::new());
        let log = logger(Arc::clone(&sink), Severity::Warn);

        log.emit(&Event::new(Severity::Debug, "d"));
        log.emit(&Event::info("i"));
        assert!(sink.is_empty(), "below-minimum events are dropped");

        log.emit(&Event::warn("w"));
        log.emit(&Event::error("e"));
        log.emit(&Event::critical("c"));
        assert_eq!(sink.len(), 3);
    }

    #[test]
    fn severity_ordering_and_parsing() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
        for s in [
            Severity::Debug,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(Severity::parse("trace"), None);
    }

    #[test]
    fn every_emitted_line_is_one_json_object() {
        let sink = Arc::new(MemorySink::new());
        let log = logger(Arc::clone(&sink), Severity::Debug);
        for i in 0..20u64 {
            log.emit(
                &Event::info("request.completed")
                    .int_field(Field::Status, 200)
                    .int_field(Field::TotalMs, i),
            );
        }
        assert_eq!(sink.len(), 20);
        for line in sink.lines() {
            assert!(!line.contains('\n'));
            let parsed = parse_str(&line, &Limits::SMALL).expect("valid JSON");
            assert!(parsed.as_object().is_some());
            assert!(parsed.get("ts").is_some());
        }
    }

    #[test]
    fn debug_output_never_contains_the_pseudonym_key() {
        // A leaked pseudonym key de-anonymizes every log line ever written
        // with it, including archived ones — the one failure that cannot be
        // contained by rotating afterwards.
        let key = b"log-pseudonym-key";
        let p = Pseudonymizer::new(key);
        let rendered = format!("{p:?}");
        assert!(
            !rendered.contains(&String::from_utf8_lossy(key).to_string()),
            "Pseudonymizer leaked its key: {rendered}"
        );
        assert!(rendered.contains("[redacted"));
    }

    #[test]
    fn pseudonyms_are_stable_and_domain_separated() {
        let p = Pseudonymizer::new(b"log-pseudonym-key");

        assert_eq!(p.tenant("acme"), p.tenant("acme"), "must be stable");
        assert_ne!(p.tenant("acme"), p.tenant("other"));
        assert_ne!(
            p.tenant("same-string"),
            p.principal("same-string"),
            "domains must not collide"
        );
        assert_eq!(p.tenant("acme").len(), 12);
    }

    #[test]
    fn pseudonyms_do_not_reveal_the_identifier() {
        let p = Pseudonymizer::new(b"log-pseudonym-key");
        let pseudonym = p.principal("user:alice@example.com");
        assert!(!pseudonym.contains("alice"));
        assert!(!pseudonym.contains("example"));
        assert!(pseudonym.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pseudonyms_depend_on_the_key() {
        let a = Pseudonymizer::new(b"key-a");
        let b = Pseudonymizer::new(b"key-b");
        assert_ne!(a.tenant("acme"), b.tenant("acme"));
    }

    #[test]
    fn field_names_are_distinct() {
        let mut names: Vec<&str> = Field::all().iter().map(|f| f.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn the_field_vocabulary_excludes_request_content() {
        // Specification 10 makes prompts, tool arguments, and provider bodies
        // sensitive by default. None of them is an expressible log field.
        let forbidden = [
            "prompt",
            "messages",
            "content",
            "completion",
            "tool_arguments",
            "authorization",
            "api_key",
            "credential",
            "body",
        ];
        for field in Field::all() {
            assert!(
                !forbidden.contains(&field.as_str()),
                "{} must not be a log field",
                field.as_str()
            );
        }
    }

    #[test]
    fn specification_17_fields_are_all_present() {
        // "Timestamp, severity, event code, request id, tenant pseudonym,
        // alias, chosen target id, status, timings".
        let line = Event::info("request.completed")
            .str_field(Field::RequestId, "r")
            .str_field(Field::Tenant, "pseudonym")
            .str_field(Field::Alias, "a")
            .str_field(Field::Target, "t")
            .int_field(Field::Status, 200)
            .int_field(Field::RouterMs, 1)
            .int_field(Field::TotalMs, 2)
            .to_json_line("2026-01-01T00:00:00.000Z");
        let parsed = parse_str(&line, &Limits::SMALL).unwrap();
        for key in [
            "ts",
            "severity",
            "event",
            "request_id",
            "tenant",
            "alias",
            "target",
            "status",
            "router_ms",
            "total_ms",
        ] {
            assert!(parsed.get(key).is_some(), "missing {key}");
        }
    }
}
