#pragma once

#include "json.hpp"

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hypellm_monitor {

// Milliseconds on whatever clock the caller keeps. The tracker only subtracts
// them, so a monotonic tick and a wall clock both work as long as one is used
// consistently.
using Millis = std::uint64_t;

enum class ConnectionState {
    NotConfigured,
    Refreshing,
    Connected,
    Unreachable,
    AuthenticationRequired,
    Forbidden,
    Malformed,
};

// One target's live occupancy, from `GET /admin/v1/traffic`.
struct TargetActivity {
    std::string id;
    std::uint64_t inFlight{};
    std::uint64_t queued{};
    std::uint64_t maxConcurrency{};
    std::optional<std::uint64_t> activeStreams;
    // False when the router reported a declared limit that nothing enforces.
    bool admissionScope{false};

    [[nodiscard]] bool busy() const;
    [[nodiscard]] std::optional<double> utilisation() const;
};

struct TrafficSnapshot {
    bool capacityAvailable{false};
    std::optional<std::uint64_t> globalInFlight;
    std::optional<std::uint64_t> globalMaxConcurrency;
    std::uint64_t activeStreams{};
    std::vector<TargetActivity> targets;
    // False when the router dropped this tenant's samples; the minute figures
    // are then absent rather than a confident zero.
    bool attributed{true};
    std::optional<std::uint64_t> minuteRequests;
    std::optional<std::uint64_t> minuteInputTokens;
    std::optional<std::uint64_t> minuteOutputTokens;
};

// A cumulative counter for one principal, key or target, summed over the
// usage view's other dimensions.
struct UsageCounter {
    std::string id;
    std::uint64_t requests{};
    std::uint64_t inputTokens{};
    std::uint64_t outputTokens{};
};

struct UsageSnapshot {
    // The counters' epoch. It changes when the router restarts, and every
    // rate derived across that boundary is meaningless.
    Millis since{};
    bool truncated{false};
    bool tenantWide{false};
    std::vector<UsageCounter> principals;
    std::vector<UsageCounter> targets;
    std::vector<UsageCounter> keys;
};

// What the management API says about a target's availability.
//
// This is not a liveness probe. The router does not poll its targets; it
// learns that one is broken by routing to it and watching it fail, so the
// strongest thing it can say about a target nothing has been routed to lately
// is "it is enabled and nothing is known to be wrong with it". The monitor
// reports that as `Ready` and says exactly that in the tooltip, rather than
// claiming the container was pinged.
enum class Availability { Unknown, Ready, Recovering, Unavailable };

struct TargetStatus {
    Availability availability{Availability::Unknown};
    // One word for the row caption: "ready", "draining", "failing"…
    std::string word;
    // A sentence for the tooltip, saying what the word is evidence of.
    std::string detail;
};

struct TargetInfo {
    std::string id;
    std::string model;
    std::string provider;
    // The administrative state now in force: "enabled", "draining",
    // "maintenance", "quarantined" or "disabled".
    std::string state;
    // The worst circuit-breaker state across the target's operations:
    // "closed", "half_open" or "open".
    std::string breakerState;
    bool quarantined{false};
    bool local{false};
};

struct SessionInfo {
    std::string principal;
    std::string tenant;
    std::string authMethod;
    std::vector<std::string> permissions;
};

struct OverviewInfo {
    std::string configDigest;
    std::uint64_t targetsTotal{};
    std::uint64_t targetsHealthy{};
};

[[nodiscard]] std::optional<TrafficSnapshot> parseTraffic(const JsonValue& root);
[[nodiscard]] std::optional<UsageSnapshot> parseUsage(const JsonValue& root);
[[nodiscard]] std::vector<TargetInfo> parseTargets(const JsonValue& root);
// What the listing says about one target, by identifier. A target the listing
// does not contain is `Unknown`, never `Ready`: the monitor may not assume a
// target is fine because it could not find out.
[[nodiscard]] TargetStatus targetStatus(std::string_view id, const std::vector<TargetInfo>& targets);
[[nodiscard]] std::optional<SessionInfo> parseSession(const JsonValue& root);
[[nodiscard]] std::optional<OverviewInfo> parseOverview(const JsonValue& root);
// The `error.message` of a refusal, if the body is one.
[[nodiscard]] std::optional<std::string> parseErrorMessage(std::string_view body);

struct Rate {
    double inputPerSecond{};
    double outputPerSecond{};
    double requestsPerSecond{};
    // How much time the two samples that produced this rate span.
    Millis spanMillis{};

    [[nodiscard]] double tokensPerSecond() const { return inputPerSecond + outputPerSecond; }
    // Whether this rate is evidence of work. Tokens are not the test: a
    // reranking scorer answers with scores and reports no output tokens at
    // all, so the request counter is the only counter its traffic moves.
    [[nodiscard]] bool moving() const { return tokensPerSecond() > 0.0 || requestsPerSecond > 0.0; }
};

// Turns cumulative counters into a rate over a sliding window. The router
// counts a request's tokens when it completes, so what comes out is the
// throughput of completed work, smoothed over the window - a long stream
// appears as a step when it ends, not as a ramp while it runs.
class RateTracker {
public:
    explicit RateTracker(Millis windowMillis = 60000, std::size_t maxSeries = 1024, std::size_t maxSamplesPerSeries = 720);

    void setWindow(Millis windowMillis);
    [[nodiscard]] Millis window() const { return window_; }

    // Records every counter in `counters`. A counter that went backwards
    // restarts its own series; a changed `epoch` restarts all of them.
    void observe(const std::vector<UsageCounter>& counters, Millis epoch, Millis now);
    [[nodiscard]] std::optional<Rate> rate(std::string_view id, Millis now) const;
    [[nodiscard]] std::size_t series() const { return series_.size(); }
    void clear();

private:
    struct Sample {
        Millis at;
        std::uint64_t requests;
        std::uint64_t input;
        std::uint64_t output;
    };

    Millis window_;
    std::size_t maxSeries_;
    std::size_t maxSamples_;
    std::optional<Millis> epoch_;
    std::map<std::string, std::deque<Sample>, std::less<>> series_;
};

struct RateBook {
    RateTracker principals;
    RateTracker keys;
    RateTracker targets;

    explicit RateBook(Millis windowMillis = 60000);
    void setWindow(Millis windowMillis);
    void observe(const UsageSnapshot& usage, Millis now);
    void clear();
};

enum class RowKind { Status, Heading, Model, Principal, Key };

struct MonitorRow {
    RowKind kind{RowKind::Status};
    std::string label;
    std::string caption;
    std::optional<double> fraction;
    // Rows with work in flight or tokens moving are drawn brighter.
    bool active{false};
    // Model rows only: what the router says about the target behind the row,
    // so the renderer can colour "not available" differently from "available
    // and quiet". Those two look identical when only activity is drawn, and an
    // operator reads the panel as the second question.
    Availability availability{Availability::Unknown};
    std::string tooltip;
};

struct MonitorOptions {
    // Every target the key can see, not only the ones with traffic.
    //
    // On by default. A list gated on activity answers "which models are
    // working right now", and is read as "which models are up" - and on a
    // fleet serving a request every few minutes those differ by the whole
    // fleet. A target that is not available is listed either way; it is
    // exactly what an operator scanning the panel needs to see.
    bool showAllModels{true};
    bool showPrincipals{true};
    bool showKeys{true};
};

struct MonitorInput {
    ConnectionState state{ConnectionState::NotConfigured};
    std::string diagnostic;
    std::optional<TrafficSnapshot> traffic;
    std::optional<UsageSnapshot> usage;
    std::vector<TargetInfo> targets;
    const RateBook* rates{nullptr};
    Millis now{};
};

[[nodiscard]] std::vector<MonitorRow> buildMonitorRows(const MonitorInput& input, const MonitorOptions& options);

// Row geometry in logical pixels. Headings are short, status lines wrap, and
// every other row is a label line over a thin bar.
inline constexpr int kRowHeadingHeight = 18;
inline constexpr int kRowLabelHeight = 20;
inline constexpr int kRowBarHeight = 6;
inline constexpr int kRowGap = 7;

struct RowStack {
    std::vector<int> tops;
    std::vector<int> heights;
    int bottom{0};
};

// Stacks `rows` downwards from `top`. `wrappedStatusHeights[i]` is the measured
// text height of status row `i`; a row with no measurement - every row, when
// the renderer could not get a device context to measure with - takes one
// line. The result always has exactly one top and one height per row, because
// the renderer indexes both by row.
[[nodiscard]] RowStack stackRows(const std::vector<MonitorRow>& rows, int top,
                                 const std::vector<int>& wrappedStatusHeights = {});

struct RgbColor {
    int red;
    int green;
    int blue;
};

struct TraySummary {
    RgbColor color;
    bool active{false};
    std::string tooltip;
};

[[nodiscard]] TraySummary traySummary(const MonitorInput& input);
[[nodiscard]] RgbColor utilisationColor(double utilisation);
[[nodiscard]] RgbColor applyActivity(RgbColor color, bool active);
[[nodiscard]] std::string formatRate(double perSecond);
[[nodiscard]] std::string formatCount(std::uint64_t value);
[[nodiscard]] std::string_view connectionStateName(ConnectionState state);
[[nodiscard]] std::string modelLabel(const TargetActivity& target, const std::vector<TargetInfo>& targets);
// The machine behind a target: its provider, or the part of the identifier
// before the colon when no listing was fetched. Appended to a label that two
// rows would otherwise share.
[[nodiscard]] std::string modelQualifier(const TargetActivity& target, const std::vector<TargetInfo>& targets);

} // namespace hypellm_monitor
