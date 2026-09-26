#include "model.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace hypellm_monitor {

namespace {

UsageCounter& counterFor(std::vector<UsageCounter>& counters, std::string_view id) {
    for (auto& counter : counters) {
        if (counter.id == id) return counter;
    }
    counters.push_back({std::string(id), 0, 0, 0});
    return counters.back();
}

void addTotals(UsageCounter& counter, const JsonValue& row) {
    counter.requests += row.count("requests").value_or(0);
    counter.inputTokens += row.count("input_tokens").value_or(0);
    counter.outputTokens += row.count("output_tokens").value_or(0);
}

std::string shortId(std::string_view id) {
    if (id.size() <= 8) return std::string(id);
    return std::string(id.substr(0, 8)) + "…";
}

} // namespace

bool TargetActivity::busy() const {
    return inFlight > 0 || queued > 0 || activeStreams.value_or(0) > 0;
}

std::optional<double> TargetActivity::utilisation() const {
    if (maxConcurrency == 0) return std::nullopt;
    return std::min(1.0, static_cast<double>(inFlight) / static_cast<double>(maxConcurrency));
}

std::optional<TrafficSnapshot> parseTraffic(const JsonValue& root) {
    if (root.kind != JsonValue::Kind::Object) return std::nullopt;
    const auto* capacity = root.get("capacity");
    if (!capacity || capacity->kind != JsonValue::Kind::Object) return std::nullopt;
    TrafficSnapshot snapshot;
    snapshot.attributed = root.flag("attributed", true);
    if (const auto* windows = root.list("windows"); windows && snapshot.attributed) {
        for (const auto& window : *windows) {
            if (window.count("window_millis").value_or(0) != 60000) continue;
            snapshot.minuteRequests = window.count("requests");
            snapshot.minuteInputTokens = window.count("input_tokens");
            snapshot.minuteOutputTokens = window.count("output_tokens");
        }
    }
    snapshot.capacityAvailable = capacity->flag("available", false);
    if (!snapshot.capacityAvailable) return snapshot;
    if (const auto* global = capacity->get("global")) {
        snapshot.globalInFlight = global->count("in_flight");
        snapshot.globalMaxConcurrency = global->count("max_concurrency");
    }
    snapshot.activeStreams = capacity->count("active_streams").value_or(0);
    if (const auto* targets = capacity->list("targets")) {
        for (const auto& row : *targets) {
            const auto id = row.str("id");
            if (!id || id->empty()) continue;
            TargetActivity target;
            target.id = std::string(*id);
            target.inFlight = row.count("in_flight").value_or(0);
            target.queued = row.count("queued").value_or(0);
            target.maxConcurrency = row.count("max_concurrency").value_or(0);
            target.activeStreams = row.count("active_streams");
            target.admissionScope = row.flag("admission_scope", false);
            snapshot.targets.push_back(std::move(target));
        }
    }
    return snapshot;
}

std::optional<UsageSnapshot> parseUsage(const JsonValue& root) {
    if (root.kind != JsonValue::Kind::Object) return std::nullopt;
    const auto* rows = root.list("data");
    if (!rows) return std::nullopt;
    UsageSnapshot snapshot;
    snapshot.since = root.count("since").value_or(0);
    snapshot.truncated = root.flag("truncated", false);
    snapshot.tenantWide = root.str("scope").value_or("") == "tenant";
    for (const auto& row : *rows) {
        // The folded remainder belongs to nobody; attributing it to a
        // principal would invent a user.
        if (row.flag("aggregated", false)) continue;
        if (const auto principal = row.str("principal"); principal && !principal->empty()) {
            addTotals(counterFor(snapshot.principals, *principal), row);
        }
        if (const auto target = row.str("target"); target && !target->empty()) {
            addTotals(counterFor(snapshot.targets, *target), row);
        }
    }
    if (const auto* keys = root.list("by_key")) {
        for (const auto& row : *keys) {
            const auto id = row.str("key_id");
            if (!id || id->empty()) continue;
            addTotals(counterFor(snapshot.keys, *id), row);
        }
    }
    return snapshot;
}

std::vector<TargetInfo> parseTargets(const JsonValue& root) {
    std::vector<TargetInfo> targets;
    const auto* rows = root.list("data");
    if (!rows) return targets;
    for (const auto& row : *rows) {
        const auto id = row.str("id");
        if (!id || id->empty()) continue;
        TargetInfo info;
        info.id = std::string(*id);
        info.model = std::string(row.str("model").value_or(""));
        info.provider = std::string(row.str("provider").value_or(""));
        info.state = std::string(row.str("state").value_or(""));
        info.breakerState = std::string(row.str("breaker_state").value_or(""));
        info.quarantined = row.flag("quarantined", false);
        info.local = row.flag("local", false);
        targets.push_back(std::move(info));
    }
    return targets;
}

TargetStatus targetStatus(std::string_view id, const std::vector<TargetInfo>& targets) {
    const TargetInfo* info = nullptr;
    for (const auto& candidate : targets) {
        if (candidate.id == id) {
            info = &candidate;
            break;
        }
    }
    // No listing, or a target absent from one: unknown, and unknown is not
    // ready. Silence about a target is not evidence that it is fine.
    if (!info) {
        return {Availability::Unknown, "",
                "The monitor holds no target listing for this row, so it cannot say whether the target is available."};
    }
    // Operator decisions first, because they override the automated ones: a
    // quarantine exists precisely to keep a target out of routing that the
    // breaker would otherwise have let back in.
    if (info->quarantined || info->state == "quarantined") {
        return {Availability::Unavailable, "quarantined",
                "An operator has quarantined this target. Nothing routes here until the quarantine is lifted."};
    }
    if (info->state == "disabled") {
        return {Availability::Unavailable, "disabled",
                "Configured but switched off. Nothing routes here."};
    }
    if (info->state == "maintenance") {
        return {Availability::Unavailable, "maintenance",
                "Withdrawn for planned work. Nothing routes here."};
    }
    if (info->state == "draining") {
        return {Availability::Unavailable, "draining",
                "Finishing the requests it already holds and accepting no new ones."};
    }
    if (info->breakerState == "open") {
        return {Availability::Unavailable, "failing",
                "The circuit breaker is open: requests to this target failed, so it is excluded until a probe succeeds."};
    }
    if (info->breakerState == "half_open") {
        return {Availability::Recovering, "recovering",
                "The circuit breaker is half open: this target is taking probe requests after a failure."};
    }
    // A state the monitor does not have a word for. Reporting it verbatim and
    // as unavailable is the safe direction to be wrong in - a new withdrawn
    // state must not read as ready because this build predates it.
    if (!info->state.empty() && info->state != "enabled") {
        return {Availability::Unavailable, info->state,
                "The router reports an administrative state this monitor does not recognise."};
    }
    return {Availability::Ready, "ready",
            "Enabled, and nothing is known to be wrong with it. The router has no liveness probe: it learns a target is "
            "broken by routing to it, so this is what it knows, not a check on the container."};
}

std::optional<SessionInfo> parseSession(const JsonValue& root) {
    const auto principal = root.str("principal");
    const auto tenant = root.str("tenant");
    if (!principal || !tenant) return std::nullopt;
    SessionInfo info;
    info.principal = std::string(*principal);
    info.tenant = std::string(*tenant);
    info.authMethod = std::string(root.str("auth_method").value_or(""));
    if (const auto* permissions = root.list("permissions")) {
        for (const auto& permission : *permissions) {
            if (permission.kind == JsonValue::Kind::String) info.permissions.push_back(permission.string);
        }
    }
    return info;
}

std::optional<OverviewInfo> parseOverview(const JsonValue& root) {
    if (root.kind != JsonValue::Kind::Object) return std::nullopt;
    OverviewInfo info;
    info.configDigest = std::string(root.str("config_digest").value_or(""));
    info.targetsTotal = root.count("targets_total").value_or(0);
    info.targetsHealthy = root.count("targets_healthy").value_or(0);
    return info;
}

std::optional<std::string> parseErrorMessage(std::string_view body) {
    const auto parsed = parseJson(body, {64 * 1024, 8, 256});
    if (!parsed) return std::nullopt;
    const auto* error = parsed->get("error");
    if (!error) return std::nullopt;
    const auto message = error->str("message");
    if (!message) return std::nullopt;
    return std::string(*message);
}

RateTracker::RateTracker(Millis windowMillis, std::size_t maxSeries, std::size_t maxSamplesPerSeries)
    : window_(std::max<Millis>(windowMillis, 1000)), maxSeries_(maxSeries), maxSamples_(std::max<std::size_t>(maxSamplesPerSeries, 2)) {}

void RateTracker::setWindow(Millis windowMillis) {
    window_ = std::max<Millis>(windowMillis, 1000);
}

void RateTracker::clear() {
    series_.clear();
    epoch_.reset();
}

void RateTracker::observe(const std::vector<UsageCounter>& counters, Millis epoch, Millis now) {
    if (epoch_ && *epoch_ != epoch) series_.clear();
    epoch_ = epoch;
    for (const auto& counter : counters) {
        auto found = series_.find(counter.id);
        if (found == series_.end()) {
            if (series_.size() >= maxSeries_) continue;
            found = series_.emplace(counter.id, std::deque<Sample>{}).first;
        }
        auto& samples = found->second;
        if (!samples.empty()) {
            const auto& last = samples.back();
            if (now < last.at) continue;
            if (counter.requests < last.requests || counter.inputTokens < last.input || counter.outputTokens < last.output) {
                samples.clear();
            }
        }
        samples.push_back({now, counter.requests, counter.inputTokens, counter.outputTokens});
        while (samples.size() > 2 && samples.front().at + window_ < now) samples.pop_front();
        while (samples.size() > maxSamples_) samples.pop_front();
    }
}

std::optional<Rate> RateTracker::rate(std::string_view id, Millis now) const {
    const auto found = series_.find(id);
    if (found == series_.end()) return std::nullopt;
    const auto& samples = found->second;
    if (samples.size() < 2) return std::nullopt;
    const auto& last = samples.back();
    // Nothing observed recently: the series is stale, not zero.
    if (last.at + window_ < now) return std::nullopt;
    const Sample* first = nullptr;
    for (const auto& sample : samples) {
        if (sample.at + window_ >= now) { first = &sample; break; }
    }
    if (!first) first = &samples[samples.size() - 2];
    if (first == &last) first = &samples[samples.size() - 2];
    const Millis span = last.at - first->at;
    if (span < 500) return std::nullopt;
    const double seconds = static_cast<double>(span) / 1000.0;
    Rate rate;
    rate.spanMillis = span;
    rate.inputPerSecond = static_cast<double>(last.input - first->input) / seconds;
    rate.outputPerSecond = static_cast<double>(last.output - first->output) / seconds;
    rate.requestsPerSecond = static_cast<double>(last.requests - first->requests) / seconds;
    return rate;
}

RateBook::RateBook(Millis windowMillis) : principals(windowMillis), keys(windowMillis), targets(windowMillis) {}

void RateBook::setWindow(Millis windowMillis) {
    principals.setWindow(windowMillis);
    keys.setWindow(windowMillis);
    targets.setWindow(windowMillis);
}

void RateBook::observe(const UsageSnapshot& usage, Millis now) {
    principals.observe(usage.principals, usage.since, now);
    keys.observe(usage.keys, usage.since, now);
    targets.observe(usage.targets, usage.since, now);
}

void RateBook::clear() {
    principals.clear();
    keys.clear();
    targets.clear();
}

std::string formatCount(std::uint64_t value) {
    char buffer[32]{};
    if (value >= 1000000000ULL) std::snprintf(buffer, sizeof(buffer), "%.1fG", static_cast<double>(value) / 1e9);
    else if (value >= 1000000ULL) std::snprintf(buffer, sizeof(buffer), "%.1fM", static_cast<double>(value) / 1e6);
    else if (value >= 10000ULL) std::snprintf(buffer, sizeof(buffer), "%.1fk", static_cast<double>(value) / 1e3);
    else std::snprintf(buffer, sizeof(buffer), "%llu", static_cast<unsigned long long>(value));
    return buffer;
}

std::string formatRate(double perSecond) {
    char buffer[32]{};
    if (perSecond >= 10000.0) std::snprintf(buffer, sizeof(buffer), "%.1fk", perSecond / 1000.0);
    else if (perSecond >= 100.0) std::snprintf(buffer, sizeof(buffer), "%.0f", perSecond);
    else if (perSecond >= 10.0) std::snprintf(buffer, sizeof(buffer), "%.1f", perSecond);
    else std::snprintf(buffer, sizeof(buffer), "%.2f", perSecond);
    return buffer;
}

std::string_view connectionStateName(ConnectionState state) {
    switch (state) {
    case ConnectionState::NotConfigured: return "not configured";
    case ConnectionState::Refreshing: return "refreshing";
    case ConnectionState::Connected: return "connected";
    case ConnectionState::Unreachable: return "unreachable";
    case ConnectionState::AuthenticationRequired: return "authentication required";
    case ConnectionState::Forbidden: return "forbidden";
    case ConnectionState::Malformed: return "unexpected reply";
    }
    return "unknown";
}

std::string modelQualifier(const TargetActivity& target, const std::vector<TargetInfo>& targets);

// The machine first, then the model. A model name does not identify a target
// here: three machines serve the same weights, two of them the same
// quantisation, and rows reading `Qwen3.5-4B-Q6_K` twice name neither. Leading
// with the machine also means the half that tells them apart is the half that
// survives when the label is too long for the window.
std::string modelLabel(const TargetActivity& target, const std::vector<TargetInfo>& targets) {
    for (const auto& info : targets) {
        if (info.id == target.id && !info.model.empty()) {
            return modelQualifier(target, targets) + " · " + info.model;
        }
    }
    // No listing yet, or a target the caller may not see in one: the
    // identifier already carries both halves.
    return target.id;
}

std::string modelQualifier(const TargetActivity& target, const std::vector<TargetInfo>& targets) {
    for (const auto& info : targets) {
        if (info.id == target.id && !info.provider.empty()) return info.provider;
    }
    // No listing to read a provider from: the part of the identifier before
    // the colon is the deployment's own name for the machine, which is what
    // the provider would have said.
    const auto colon = target.id.find(':');
    if (colon != std::string::npos && colon > 0) return target.id.substr(0, colon);
    return target.id;
}

RgbColor utilisationColor(double utilisation) {
    // hypelimits' remaining-allowance ramp, read as free capacity: an empty
    // target is green, a full one red.
    const double remaining = std::clamp(1.0 - utilisation, 0.0, 1.0);
    if (remaining >= 0.5) {
        const double t = (remaining - 0.5) * 2.0;
        return {static_cast<int>(255 * (1.0 - t)), static_cast<int>(255 * (0.78 + 0.17 * t)), 38};
    }
    const double t = remaining * 2.0;
    return {static_cast<int>(255 * (0.92 + 0.08 * t)), static_cast<int>(255 * (0.18 + 0.60 * t)), 31};
}

RgbColor applyActivity(RgbColor color, bool active) {
    auto channel = [](int value, double factor, int lift) {
        return std::clamp(static_cast<int>(std::lround(value * factor + lift)), 0, 255);
    };
    if (active) return {channel(color.red, 1.14, 20), channel(color.green, 1.14, 20), channel(color.blue, 1.14, 14)};
    return {channel(color.red, 0.52, 0), channel(color.green, 0.52, 0), channel(color.blue, 0.52, 0)};
}

namespace {

// The unit the row has evidence for. A target that generates tokens is
// captioned in tokens; one that does not - a reranking scorer answers with
// scores - is captioned in completed requests, because "0.00 tok/s" beside a
// scorer serving ninety calls a minute is a wrong reading, not a cautious one.
std::string rateCaption(const std::optional<Rate>& rate) {
    if (!rate) return "";
    if (rate->outputPerSecond > 0.0) return formatRate(rate->outputPerSecond) + " tok/s";
    if (rate->inputPerSecond > 0.0) return formatRate(rate->inputPerSecond) + " tok/s in";
    if (rate->requestsPerSecond > 0.0) return formatRate(rate->requestsPerSecond * 60.0) + " req/min";
    return "";
}

std::string rateTooltip(const std::optional<Rate>& rate, const UsageCounter* totals, Millis windowMillis) {
    std::string text;
    const bool tokens = rate && rate->tokensPerSecond() > 0.0;
    if (rate && rate->moving()) {
        // Claimed only where there are tokens to claim. A row whose counters
        // never move is a scorer, not a stalled generator, and a tok/s line of
        // zeroes over it reads as the second.
        if (tokens) {
            text += "out " + formatRate(rate->outputPerSecond) + " tok/s, in " + formatRate(rate->inputPerSecond) + " tok/s\r\n";
        }
        text += formatRate(rate->requestsPerSecond * 60.0) + " requests/min over the last " + std::to_string(rate->spanMillis / 1000) + " s\r\n";
    } else {
        text += "No completed requests in the last " + std::to_string(windowMillis / 1000) + " s\r\n";
    }
    if (totals) {
        text += "Since the router started: " + formatCount(totals->requests) + " requests, "
              + formatCount(totals->inputTokens) + " in / " + formatCount(totals->outputTokens) + " out tokens\r\n";
    }
    if (tokens) {
        text += "Rates count tokens when a request completes; a stream in progress shows once it ends.";
    } else {
        text += "This traffic reports no tokens, so the rate above counts completed requests.";
    }
    return text;
}

const UsageCounter* find(const std::vector<UsageCounter>& counters, std::string_view id) {
    for (const auto& counter : counters) {
        if (counter.id == id) return &counter;
    }
    return nullptr;
}

struct RatedRow {
    const UsageCounter* counter;
    Rate rate;
};

std::vector<RatedRow> ratedRows(const std::vector<UsageCounter>& counters, const RateTracker& tracker, Millis now) {
    std::vector<RatedRow> rows;
    for (const auto& counter : counters) {
        const auto rate = tracker.rate(counter.id, now);
        if (!rate || !rate->moving()) continue;
        rows.push_back({&counter, *rate});
    }
    // Output tokens first, then tokens of any kind, then completed requests:
    // each key is the one that separates rows the key above it ties. The last
    // is what orders a section whose traffic generates no tokens at all.
    std::stable_sort(rows.begin(), rows.end(), [](const RatedRow& a, const RatedRow& b) {
        if (a.rate.outputPerSecond != b.rate.outputPerSecond) return a.rate.outputPerSecond > b.rate.outputPerSecond;
        if (a.rate.tokensPerSecond() != b.rate.tokensPerSecond()) return a.rate.tokensPerSecond() > b.rate.tokensPerSecond();
        if (a.rate.requestsPerSecond != b.rate.requestsPerSecond) return a.rate.requestsPerSecond > b.rate.requestsPerSecond;
        return a.counter->id < b.counter->id;
    });
    return rows;
}

} // namespace

std::vector<MonitorRow> buildMonitorRows(const MonitorInput& input, const MonitorOptions& options) {
    std::vector<MonitorRow> rows;
    auto status = [&](std::string text, std::string tooltip = {}) {
        rows.push_back({RowKind::Status, std::move(text), "", std::nullopt, false, Availability::Unknown, std::move(tooltip)});
    };
    if (input.state == ConnectionState::NotConfigured) {
        status("Set the router address and key in Options");
        return rows;
    }
    if (!input.traffic && !input.usage) {
        switch (input.state) {
        case ConnectionState::Refreshing: status("Connecting to the router…"); return rows;
        case ConnectionState::Unreachable: status("Router unreachable", input.diagnostic); return rows;
        case ConnectionState::AuthenticationRequired: status("Key rejected — open Options", input.diagnostic); return rows;
        case ConnectionState::Forbidden: status("Key lacks management access", input.diagnostic); return rows;
        case ConnectionState::Malformed: status("Unexpected reply from the router", input.diagnostic); return rows;
        default: break;
        }
    }

    const Millis windowMillis = input.rates ? input.rates->principals.window() : 60000;
    bool anything = false;

    // The models section answers "which models can serve me, and what are
    // they doing", in that order. Gating the list on activity answered only
    // the second, and on a fleet that takes a request every few minutes it
    // left one row standing for eight running containers.
    {
        std::vector<TargetActivity> withoutCapacity;
        const std::vector<TargetActivity>* occupancy = nullptr;
        bool occupancyKnown = false;
        if (input.traffic && input.traffic->capacityAvailable) {
            occupancy = &input.traffic->targets;
            occupancyKnown = true;
        } else if (!input.targets.empty()) {
            // No admission controller is exposed to the management API, so
            // there is no occupancy to report - but the target listing still
            // says which targets exist and whether each is available, which is
            // the half of the question this section is read for. Such a row
            // draws no bar rather than an empty one, and claims no figure.
            for (const auto& info : input.targets) {
                TargetActivity activity;
                activity.id = info.id;
                withoutCapacity.push_back(std::move(activity));
            }
            occupancy = &withoutCapacity;
        }

        struct Candidate {
            const TargetActivity* target;
            TargetStatus status;
            std::optional<Rate> rate;
            bool moving;
            int tier;
        };
        std::vector<Candidate> models;
        if (occupancy) {
            for (const auto& target : *occupancy) {
                Candidate candidate{&target, targetStatus(target.id, input.targets), std::nullopt, false, 0};
                if (input.rates) candidate.rate = input.rates->targets.rate(target.id, input.now);
                // Requests, not tokens: a scoring call is milliseconds long
                // against a two-second poll, so it is almost never caught in
                // flight, and a scorer moves no token counter ever. Tokens as
                // the test for "this model is working" hides a whole provider
                // family.
                candidate.moving = candidate.rate && candidate.rate->moving();
                const bool degraded = candidate.status.availability == Availability::Unavailable
                                   || candidate.status.availability == Availability::Recovering;
                // A target that is not available is listed whatever the option
                // says. Hiding the one row an operator opened the panel for,
                // because it was too broken to have any traffic, is the failure
                // this whole section exists to avoid.
                if (!(target.busy() || candidate.moving || degraded || options.showAllModels)) continue;
                candidate.tier = target.busy()                                        ? 0
                               : candidate.moving                                     ? 1
                               : candidate.status.availability == Availability::Ready ? 2
                               : candidate.status.availability == Availability::Recovering ? 3
                               : candidate.status.availability == Availability::Unavailable ? 4
                               : 5;
                models.push_back(std::move(candidate));
            }
        }
        // Work first, then what is ready to take work, then what is not, then
        // what the monitor cannot say. Within a tier the old keys still order:
        // occupancy, queue, output rate, identifier.
        std::stable_sort(models.begin(), models.end(), [](const Candidate& a, const Candidate& b) {
            if (a.tier != b.tier) return a.tier < b.tier;
            if (a.target->inFlight != b.target->inFlight) return a.target->inFlight > b.target->inFlight;
            if (a.target->queued != b.target->queued) return a.target->queued > b.target->queued;
            const double ra = a.rate.value_or(Rate{}).outputPerSecond;
            const double rb = b.rate.value_or(Rate{}).outputPerSecond;
            if (ra != rb) return ra > rb;
            return a.target->id < b.target->id;
        });
        if (!models.empty()) {
            anything = true;
            std::size_t unavailable = 0;
            for (const auto& candidate : models) {
                if (candidate.status.availability == Availability::Unavailable
                    || candidate.status.availability == Availability::Recovering) {
                    ++unavailable;
                }
            }
            std::string heading = "Models";
            if (unavailable > 0) heading += " — " + std::to_string(unavailable) + " not available";
            rows.push_back({RowKind::Heading, std::move(heading), "", std::nullopt, false, Availability::Unknown, ""});
            for (const auto& candidate : models) {
                const TargetActivity* target = candidate.target;
                // Not `status`: that name is the status-row helper above.
                const TargetStatus& report = candidate.status;
                const std::optional<Rate>& rate = candidate.rate;
                MonitorRow row;
                row.kind = RowKind::Model;
                row.label = modelLabel(*target, input.targets);
                row.availability = report.availability;

                std::vector<std::string> parts;
                if (occupancyKnown) {
                    std::string figures = std::to_string(target->inFlight);
                    if (target->maxConcurrency > 0) figures += "/" + std::to_string(target->maxConcurrency);
                    if (target->queued > 0) figures += " +" + std::to_string(target->queued) + " queued";
                    parts.push_back(std::move(figures));
                }
                if (candidate.moving) {
                    if (auto caption = rateCaption(rate); !caption.empty()) parts.push_back(std::move(caption));
                }
                // The availability word wherever the figures do not already
                // answer the question. "0/3" and nothing else is exactly the
                // row an operator reads as a model that is down.
                const bool quiet = !target->busy() && !candidate.moving;
                if (!report.word.empty() && (report.availability != Availability::Ready || quiet)) {
                    parts.push_back(report.word);
                }
                for (std::size_t index = 0; index < parts.size(); ++index) {
                    if (index > 0) row.caption += " · ";
                    row.caption += parts[index];
                }

                row.fraction = target->utilisation();
                row.active = target->busy();
                const UsageCounter* totals = input.usage ? find(input.usage->targets, target->id) : nullptr;
                row.tooltip = row.label + " (" + target->id + ")\r\n";
                if (occupancyKnown) {
                    row.tooltip += std::to_string(target->inFlight) + " in flight";
                    if (target->maxConcurrency > 0) {
                        row.tooltip += " of " + std::to_string(target->maxConcurrency);
                        if (!target->admissionScope) row.tooltip += " declared (no admission scope enforces it)";
                    }
                    if (target->queued > 0) row.tooltip += ", " + std::to_string(target->queued) + " queued";
                    if (target->activeStreams) row.tooltip += ", " + std::to_string(*target->activeStreams) + " streaming";
                    row.tooltip += "\r\n";
                }
                if (!report.detail.empty()) row.tooltip += report.detail + "\r\n";
                row.tooltip += rateTooltip(rate, totals, windowMillis);
                rows.push_back(std::move(row));
            }
        }
    }

    if (input.usage && input.rates) {
        auto section = [&](RowKind kind, const char* heading, const std::vector<UsageCounter>& counters, const RateTracker& tracker, bool shorten) {
            const auto rated = ratedRows(counters, tracker, input.now);
            if (rated.empty()) return;
            anything = true;
            rows.push_back({RowKind::Heading, heading, "", std::nullopt, false, Availability::Unknown, ""});
            // The unit the section ranks in: tokens where any row has tokens
            // moving, completed requests where none does. A rerank-only
            // deployment moves no token counter at all, and a section that
            // insisted on tokens would rank every row at zero and draw every
            // bar empty. `ratedRows` sorts by the same keys in the same order,
            // so the first row is the largest in whichever unit is chosen.
            const bool tokenUnit = std::any_of(rated.begin(), rated.end(),
                                               [](const RatedRow& entry) { return entry.rate.tokensPerSecond() > 0.0; });
            auto magnitude = [tokenUnit](const Rate& rate) {
                if (!tokenUnit) return rate.requestsPerSecond;
                return rate.outputPerSecond > 0.0 ? rate.outputPerSecond : rate.tokensPerSecond();
            };
            const double top = magnitude(rated.front().rate);
            for (const auto& entry : rated) {
                MonitorRow row;
                row.kind = kind;
                row.label = shorten ? shortId(entry.counter->id) : entry.counter->id;
                row.caption = rateCaption(entry.rate);
                const double value = magnitude(entry.rate);
                row.fraction = top > 0.0 ? std::clamp(value / top, 0.0, 1.0) : 0.0;
                row.active = true;
                row.tooltip = std::string(shorten ? "Key " : "") + entry.counter->id + "\r\n" + rateTooltip(entry.rate, entry.counter, windowMillis);
                rows.push_back(std::move(row));
            }
        };
        if (options.showPrincipals) section(RowKind::Principal, "Users", input.usage->principals, input.rates->principals, false);
        if (options.showKeys && input.usage->tenantWide) section(RowKind::Key, "Keys", input.usage->keys, input.rates->keys, true);
    }

    if (!anything) {
        std::string tooltip;
        if (input.traffic && input.traffic->minuteRequests) {
            tooltip = "Last minute: " + formatCount(*input.traffic->minuteRequests) + " requests, "
                    + formatCount(input.traffic->minuteOutputTokens.value_or(0)) + " output tokens";
        }
        status("Idle — nothing in flight", tooltip);
    }
    if (input.state == ConnectionState::Unreachable) status("Router unreachable — showing last data", input.diagnostic);
    else if (input.state == ConnectionState::AuthenticationRequired) status("Key rejected — open Options", input.diagnostic);
    else if (input.state == ConnectionState::Forbidden) status("Key lacks management access", input.diagnostic);
    else if (input.state == ConnectionState::Malformed) status("Unexpected reply from the router", input.diagnostic);
    return rows;
}

TraySummary traySummary(const MonitorInput& input) {
    TraySummary summary{{140, 145, 154}, false, "HypeLLM — not configured"};
    switch (input.state) {
    case ConnectionState::NotConfigured: return summary;
    case ConnectionState::Refreshing:
        if (!input.traffic) { summary.tooltip = "HypeLLM — connecting"; return summary; }
        break;
    case ConnectionState::Unreachable:
        summary.color = {235, 64, 52};
        summary.tooltip = "HypeLLM — router unreachable";
        return summary;
    case ConnectionState::AuthenticationRequired:
    case ConnectionState::Forbidden:
        summary.color = {255, 160, 48};
        summary.tooltip = "HypeLLM — management key rejected";
        return summary;
    case ConnectionState::Malformed:
        summary.color = {255, 160, 48};
        summary.tooltip = "HypeLLM — unexpected reply";
        return summary;
    case ConnectionState::Connected: break;
    }
    std::uint64_t inFlight = 0;
    std::size_t busyModels = 0;
    double utilisation = 0.0;
    if (input.traffic && input.traffic->capacityAvailable) {
        for (const auto& target : input.traffic->targets) {
            inFlight += target.inFlight;
            if (target.busy()) ++busyModels;
            utilisation = std::max(utilisation, target.utilisation().value_or(0.0));
        }
    }
    // Availability from the listing rather than from the occupancy rows: a
    // tooltip that counted only busy targets says "0 models" about a fleet
    // that is entirely up and merely quiet.
    std::size_t ready = 0;
    std::size_t unavailable = 0;
    for (const auto& info : input.targets) {
        switch (targetStatus(info.id, input.targets).availability) {
        case Availability::Ready: ++ready; break;
        case Availability::Recovering:
        case Availability::Unavailable: ++unavailable; break;
        case Availability::Unknown: break;
        }
    }
    double outputPerSecond = 0.0;
    double requestsPerSecond = 0.0;
    if (input.usage && input.rates) {
        for (const auto& counter : input.usage->targets) {
            if (const auto rate = input.rates->targets.rate(counter.id, input.now)) {
                outputPerSecond += rate->outputPerSecond;
                requestsPerSecond += rate->requestsPerSecond;
            }
        }
    }
    summary.active = inFlight > 0 || busyModels > 0;
    summary.color = utilisationColor(summary.active ? utilisation : 0.0);
    if (!summary.active) summary.color = applyActivity(summary.color, false);
    summary.tooltip = "HypeLLM — " + std::to_string(inFlight) + " in flight";
    if (busyModels > 0) summary.tooltip += ", " + std::to_string(busyModels) + (busyModels == 1 ? " model" : " models");
    if (ready > 0 || unavailable > 0) {
        summary.tooltip += ", " + std::to_string(ready) + " of " + std::to_string(ready + unavailable) + " ready";
    }
    if (outputPerSecond > 0.0) summary.tooltip += ", " + formatRate(outputPerSecond) + " tok/s out";
    // A fleet of scorers produces no tokens to count, so the request rate is
    // what the tooltip has to say about how busy the router has been.
    else if (requestsPerSecond > 0.0) summary.tooltip += ", " + formatRate(requestsPerSecond * 60.0) + " req/min";
    return summary;
}

RowStack stackRows(const std::vector<MonitorRow>& rows, int top, const std::vector<int>& wrappedStatusHeights) {
    RowStack stack;
    stack.tops.reserve(rows.size());
    stack.heights.reserve(rows.size());
    int y = top;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        int height = kRowLabelHeight + kRowBarHeight + kRowGap;
        if (rows[index].kind == RowKind::Heading) {
            height = kRowHeadingHeight;
        } else if (rows[index].kind == RowKind::Status) {
            const int wrapped = index < wrappedStatusHeights.size() ? wrappedStatusHeights[index] : 0;
            height = std::max(kRowLabelHeight, wrapped) + 6;
        }
        stack.tops.push_back(y);
        stack.heights.push_back(height);
        y += height;
    }
    stack.bottom = y;
    return stack;
}

} // namespace hypellm_monitor
