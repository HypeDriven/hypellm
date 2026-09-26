#include "json.hpp"
#include "model.hpp"

#include <cmath>
#include <iostream>
#include <string>

using namespace hypellm_monitor;

namespace {
int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

bool near(double a, double b, double epsilon = 0.01) { return std::abs(a - b) < epsilon; }

// Shaped like `GET /admin/v1/traffic` in crates/hypellm-admin-api/src/handlers.rs.
constexpr const char* kTraffic = R"({
  "slot_millis": 10000, "latency_estimate": "bucket_upper_bound", "largest_bucket_millis": 120000,
  "attributed": true,
  "windows": [
    {"window_millis": 60000, "covered_millis": 60000, "complete": true, "requests": 12, "successes": 11,
     "client_errors": 1, "throttled": 0, "server_errors": 0, "input_tokens": 5000, "output_tokens": 900,
     "router_latency": {"samples": 12, "mean_millis": 1, "p50_millis": 1, "p90_millis": 2, "p99_millis": 5, "above_largest_bucket": 0},
     "upstream_latency": {"samples": 11, "mean_millis": 800, "p50_millis": 500, "p90_millis": 1000, "p99_millis": 2500, "above_largest_bucket": 0}},
    {"window_millis": 300000, "covered_millis": 300000, "complete": true, "requests": 40, "successes": 40,
     "client_errors": 0, "throttled": 0, "server_errors": 0, "input_tokens": 1, "output_tokens": 2,
     "router_latency": {"samples": 0, "above_largest_bucket": 0}, "upstream_latency": {"samples": 0, "above_largest_bucket": 0}}
  ],
  "unattributed_samples": 0,
  "capacity": {
    "available": true,
    "global": {"name": "global", "exists": true, "in_flight": 3, "queued": 0, "acquired": 100, "released": 97, "spent_minor_units": 0, "max_concurrency": 64, "max_queued": 128, "requests_per_second": 50},
    "tenant": {"name": "tenant:default", "exists": true, "in_flight": 3, "queued": 0, "acquired": 100, "released": 97, "spent_minor_units": 0, "max_concurrency": 32, "max_queued": 64, "requests_per_second": 20},
    "targets": [
      {"id": "local-qwen", "active_streams": 2, "in_flight": 2, "queued": 1, "max_concurrency": 4, "max_queued": 8, "requests_per_second": 10, "admission_scope": true},
      {"id": "openai-gpt", "active_streams": 0, "in_flight": 0, "max_concurrency": 16, "requests_per_second": 20, "admission_scope": false},
      {"id": "anthropic-sonnet", "active_streams": 1, "in_flight": 1, "queued": 0, "max_concurrency": 8, "max_queued": 8, "requests_per_second": 10, "admission_scope": true}
    ],
    "active_streams": 3
  }
})";

std::string usageJson(std::uint64_t since, std::uint64_t albertOut, std::uint64_t bobOut, std::uint64_t keyOut) {
    return "{\"object\":\"list\",\"data\":["
           "{\"principal\":\"albert\",\"alias\":\"fast\",\"target\":\"local-qwen\",\"operation\":\"chat\",\"status\":\"success\",\"cost_class\":1,"
           "\"requests\":10,\"input_tokens\":4000,\"output_tokens\":" + std::to_string(albertOut) + ",\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":false},"
           "{\"principal\":\"albert\",\"alias\":\"fast\",\"target\":\"local-qwen\",\"operation\":\"chat\",\"status\":\"client_error\",\"cost_class\":1,"
           "\"requests\":1,\"input_tokens\":10,\"output_tokens\":0,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":1,\"aggregated\":false},"
           "{\"principal\":\"bob\",\"alias\":\"smart\",\"target\":\"anthropic-sonnet\",\"operation\":\"chat\",\"status\":\"success\",\"cost_class\":3,"
           "\"requests\":2,\"input_tokens\":900,\"output_tokens\":" + std::to_string(bobOut) + ",\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":false},"
           "{\"operation\":\"chat\",\"status\":\"success\",\"cost_class\":0,\"requests\":5,\"input_tokens\":999999,\"output_tokens\":999999,"
           "\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":true}"
           "],\"by_key\":[{\"key_id\":\"e75e4806c274423b\",\"requests\":10,\"input_tokens\":4000,\"output_tokens\":" + std::to_string(keyOut) + ",\"estimated_requests\":0}],"
           "\"scope\":\"tenant\",\"tenant\":\"default\",\"since\":" + std::to_string(since) + ",\"truncated\":false,"
           "\"totals\":{\"requests\":13,\"input_tokens\":4910,\"output_tokens\":1,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":1}}";
}

// Shaped like `render_target` in crates/hypellm-admin-api/src/handlers.rs:
// `state` is `AdminState::as_str()` and `breaker_state` is the worst state
// across the target's operations. `openai-gpt` is deliberately missing - the
// traffic view reports occupancy for it, so the monitor has to say something
// about a target it holds no listing row for.
constexpr const char* kTargets = R"({"object":"list","data":[
  {"id":"local-qwen","provider":"llamacpp","model":"qwen3-30b-a3b","state":"enabled","local":true,"cost_class":1,"breaker_state":"closed","quarantined":false,"capabilities":{}},
  {"id":"anthropic-sonnet","provider":"anthropic","model":"claude-sonnet-5","state":"enabled","local":false,"cost_class":3,"breaker_state":"closed","quarantined":false,"capabilities":{}}
]})";


// A rerank-only deployment, shaped like the SemIf targets in docker/hypellm.conf:
// a scorer answers with scores, not tokens, so its rows move the request
// counter and nothing else. The occupancy poll almost never catches one in
// flight - a scoring call is milliseconds long against a two-second refresh -
// so the request rate is the only evidence the monitor ever sees.
constexpr const char* kRerankTraffic = R"({
  "attributed": true,
  "windows": [{"window_millis": 60000, "covered_millis": 60000, "complete": true, "requests": 90, "successes": 90,
     "client_errors": 0, "throttled": 0, "server_errors": 0, "input_tokens": 0, "output_tokens": 0,
     "router_latency": {"samples": 90, "above_largest_bucket": 0}, "upstream_latency": {"samples": 90, "above_largest_bucket": 0}}],
  "unattributed_samples": 0,
  "capacity": {
    "available": true,
    "global": {"in_flight": 0, "queued": 0, "max_concurrency": 64, "max_queued": 128, "requests_per_second": 50},
    "tenant": {"in_flight": 0, "queued": 0, "max_concurrency": 32, "max_queued": 64, "requests_per_second": 20},
    "targets": [
      {"id": "semif-spark:qwen35-4b", "active_streams": 0, "in_flight": 0, "queued": 0, "max_concurrency": 1, "max_queued": 8, "requests_per_second": 10, "admission_scope": true},
      {"id": "semif-spark2:qwen35-4b", "active_streams": 0, "in_flight": 0, "queued": 0, "max_concurrency": 1, "max_queued": 8, "requests_per_second": 10, "admission_scope": true},
      {"id": "semif-1080:qwen35-4b", "active_streams": 0, "in_flight": 0, "queued": 0, "max_concurrency": 1, "max_queued": 8, "requests_per_second": 10, "admission_scope": true}
    ],
    "active_streams": 0
  }
})";

// The two Sparks run the same quantisation of the same weights, so the model
// name alone names neither of them - which is exactly the shape of the live
// deployment in docker/hypellm.conf.
constexpr const char* kRerankTargets = R"({"object":"list","data":[
  {"id":"semif-spark:qwen35-4b","provider":"semif-spark","model":"Qwen3.5-4B-Q6_K","state":"enabled","local":true,"cost_class":0,"breaker_state":"closed","quarantined":false,"capabilities":{}},
  {"id":"semif-spark2:qwen35-4b","provider":"semif-spark2","model":"Qwen3.5-4B-Q6_K","state":"enabled","local":true,"cost_class":0,"breaker_state":"closed","quarantined":false,"capabilities":{}},
  {"id":"semif-1080:qwen35-4b","provider":"semif-1080","model":"Qwen3.5-4B-Q4_K_M","state":"enabled","local":true,"cost_class":0,"breaker_state":"closed","quarantined":false,"capabilities":{}}
]})";

// `requests` is the only counter that moves: the SemIf adapter reports no
// output tokens at all, and a scorer that does not report `input_tokens`
// leaves the input counter flat too.
std::string rerankUsageJson(std::uint64_t sparkRequests, std::uint64_t oldRequests) {
    return "{\"object\":\"list\",\"data\":["
           "{\"principal\":\"carol\",\"alias\":\"decide\",\"target\":\"semif-spark:qwen35-4b\",\"operation\":\"rerank\",\"status\":\"success\",\"cost_class\":0,"
           "\"requests\":" + std::to_string(sparkRequests) + ",\"input_tokens\":0,\"output_tokens\":0,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":false},"
           "{\"principal\":\"erin\",\"alias\":\"decide\",\"target\":\"semif-spark2:qwen35-4b\",\"operation\":\"rerank\",\"status\":\"success\",\"cost_class\":0,"
           "\"requests\":" + std::to_string(oldRequests * 2) + ",\"input_tokens\":0,\"output_tokens\":0,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":false},"
           "{\"principal\":\"dave\",\"alias\":\"decide\",\"target\":\"semif-1080:qwen35-4b\",\"operation\":\"rerank\",\"status\":\"success\",\"cost_class\":0,"
           "\"requests\":" + std::to_string(oldRequests) + ",\"input_tokens\":0,\"output_tokens\":0,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0,\"aggregated\":false}"
           "],\"by_key\":[],\"scope\":\"tenant\",\"tenant\":\"local\",\"since\":7000,\"truncated\":false,"
           "\"totals\":{\"requests\":" + std::to_string(sparkRequests + oldRequests) + ",\"input_tokens\":0,\"output_tokens\":0,\"cached_input_tokens\":0,\"reasoning_tokens\":0,\"estimated_requests\":0}}";
}

} // namespace

int main() {
    // JSON reader: bounded, exact on integers, strict on shape.
    {
        const auto value = parseJson(R"({"a": [1, 2.5, "xé😀", true, null], "b": {"c": 18446744073709551615}})");
        check(value.has_value(), "well-formed document parses");
        check(value && value->list("a") && value->list("a")->size() == 5, "array elements are kept");
        check(value && value->list("a")->at(2).string == "x\xC3\xA9\xF0\x9F\x98\x80", "escapes decode to UTF-8 including surrogate pairs");
        check(value && value->get("b") && value->get("b")->count("c") == 18446744073709551615ULL, "64-bit counters survive exactly");
        check(!parseJson("{\"a\": 1,}"), "trailing comma is refused");
        check(!parseJson("[1] x"), "trailing garbage is refused");
        check(!parseJson("{\"a\": \"unterminated"), "unterminated string is refused");
        check(!parseJson("{\"a\": 1e}"), "malformed exponent is refused");
        std::string deep;
        for (int index = 0; index < 40; ++index) deep += '[';
        for (int index = 0; index < 40; ++index) deep += ']';
        check(!parseJson(deep), "nesting past the depth limit is refused");
        check(!parseJson(std::string(20, ' ') + "1", {8, 8, 8}), "documents past the byte limit are refused");
        check(!parseJson("[1,2,3,4,5,6,7,8,9,10]", {1024, 8, 5}), "documents past the element limit are refused");
        check(parseJson("-5") && parseJson("-5")->count("") == std::nullopt, "negative literal is not a count");
        const auto neg = parseJson("{\"n\": -5}");
        check(neg && !neg->count("n"), "a negative number is not accepted as a counter");
        // Past 2^64 the double-to-integer conversion is undefined behaviour;
        // the reader must refuse such a counter, not return whatever it yields.
        const auto huge = parseJson(R"({"a": 1e20, "b": 18446744073709551616, "c": 1.8446744073709552e19, "d": 1.5e3})");
        check(huge && !huge->count("a"), "a counter far past 2^64 is refused");
        check(huge && !huge->count("b"), "an integer literal one past UINT64_MAX is refused");
        check(huge && !huge->count("c"), "a counter of exactly 2^64 is refused");
        check(huge && huge->count("d") == 1500u, "an in-range non-integer literal is still a counter");
    }

    // Row geometry. The renderer indexes tops and heights by row, so a layout
    // must produce one of each per row even when nothing could be measured -
    // the Win32 side once returned early without a device context, and the
    // next paint read past the end of an empty vector.
    {
        std::vector<MonitorRow> rows(3);
        rows[0].kind = RowKind::Heading;
        rows[1].kind = RowKind::Status;
        rows[2].kind = RowKind::Model;
        const auto unmeasured = stackRows(rows, 8);
        check(unmeasured.tops.size() == rows.size() && unmeasured.heights.size() == rows.size(),
              "an unmeasured layout still has one top and one height per row");
        check(unmeasured.tops.size() == 3 && unmeasured.tops[0] == 8 && unmeasured.tops[1] == 8 + kRowHeadingHeight &&
                  unmeasured.tops[2] == 8 + kRowHeadingHeight + kRowLabelHeight + 6,
              "rows stack downwards, a status row taking one line when unmeasured");
        check(unmeasured.bottom == unmeasured.tops[2] + kRowLabelHeight + kRowBarHeight + kRowGap,
              "the stack's bottom is below its last row");
        const auto measured = stackRows(rows, 0, {0, 55});
        check(measured.heights.size() == 3 && measured.heights[1] == 61, "a measured status row wraps to its height");
        check(stackRows({}, 8).bottom == 8 && stackRows({}, 8).tops.empty(), "no rows, no geometry");
    }

    // Traffic view.
    const auto trafficJson = parseJson(kTraffic);
    check(trafficJson.has_value(), "traffic fixture parses");
    const auto traffic = parseTraffic(*trafficJson);
    check(traffic.has_value(), "traffic view is understood");
    check(traffic && traffic->targets.size() == 3, "every target row is kept");
    check(traffic && traffic->activeStreams == 3, "active stream total is read");
    check(traffic && traffic->globalInFlight == 3 && traffic->globalMaxConcurrency == 64, "global scope occupancy is read");
    check(traffic && traffic->minuteRequests == 12 && traffic->minuteOutputTokens == 900, "the one-minute window is picked, not the five-minute one");
    check(traffic && traffic->targets[0].busy() && !traffic->targets[1].busy(), "busy is in-flight, queued or streaming");
    check(traffic && near(*traffic->targets[0].utilisation(), 0.5), "utilisation is in-flight over the limit");
    check(traffic && !traffic->targets[1].admissionScope, "a declared-only limit is marked as such");
    {
        const auto unattributed = parseJson(R"({"attributed": false, "windows": [], "unattributed_samples": 9, "capacity": {"available": false, "reason": "x"}})");
        const auto parsed = parseTraffic(*unattributed);
        check(parsed && !parsed->attributed && !parsed->minuteRequests, "dropped samples give no minute figures rather than zero");
        check(parsed && !parsed->capacityAvailable && parsed->targets.empty(), "absent admission controller gives no target rows");
        check(!parseTraffic(*parseJson("{\"windows\": []}")), "a traffic reply without capacity is malformed");
    }

    // Usage view.
    const auto usage = parseUsage(*parseJson(usageJson(1000, 500, 200, 500)));
    check(usage.has_value(), "usage view is understood");
    check(usage && usage->tenantWide, "tenant-wide scope is recognised");
    check(usage && usage->principals.size() == 2, "rows fold to one counter per principal");
    check(usage && usage->principals[0].id == "albert" && usage->principals[0].requests == 11 && usage->principals[0].inputTokens == 4010,
          "a principal's rows sum across status");
    check(usage && usage->targets.size() == 2 && usage->targets[0].id == "local-qwen" && usage->targets[0].outputTokens == 500,
          "rows fold to one counter per target");
    check(usage && usage->keys.size() == 1 && usage->keys[0].id == "e75e4806c274423b", "per-key rows are kept");
    check(usage && usage->since == 1000, "the counters' epoch is read");
    bool aggregatedLeaked = false;
    if (usage) {
        for (const auto& counter : usage->principals) if (counter.outputTokens >= 999999) aggregatedLeaked = true;
    }
    check(!aggregatedLeaked, "the aggregated remainder is attributed to nobody");
    check(!parseUsage(*parseJson("{\"object\":\"list\"}")), "usage without rows is malformed");

    const auto targets = parseTargets(*parseJson(kTargets));
    check(targets.size() == 2 && targets[0].model == "qwen3-30b-a3b", "target model names are read");
    check(targets.size() == 2 && targets[0].state == "enabled" && targets[0].breakerState == "closed" && !targets[0].quarantined,
          "administrative state, breaker state and quarantine are read off the wire");
    check(targetStatus("local-qwen", targets).availability == Availability::Ready, "an enabled target with a closed breaker is ready");
    check(targetStatus("openai-gpt", targets).availability == Availability::Unknown, "a target absent from the listing is unknown");
    {
        const auto withdrawn = parseTargets(*parseJson(R"({"object":"list","data":[
          {"id":"drained","provider":"p","model":"m","state":"draining","breaker_state":"closed","quarantined":false,"local":true},
          {"id":"broken","provider":"p","model":"m","state":"enabled","breaker_state":"open","quarantined":false,"local":true},
          {"id":"probing","provider":"p","model":"m","state":"enabled","breaker_state":"half_open","quarantined":false,"local":true},
          {"id":"held","provider":"p","model":"m","state":"enabled","breaker_state":"closed","quarantined":true,"local":true},
          {"id":"future","provider":"p","model":"m","state":"hibernating","breaker_state":"closed","quarantined":false,"local":true}
        ]})"));
        check(withdrawn.size() == 5, "every listing row is kept");
        check(targetStatus("drained", withdrawn).word == "draining" && targetStatus("broken", withdrawn).word == "failing"
                  && targetStatus("held", withdrawn).word == "quarantined",
              "each withdrawn target is named by what withdrew it");
        check(targetStatus("probing", withdrawn).availability == Availability::Recovering, "a half-open breaker is recovering");
        // An administrative state added after this monitor was built must not
        // read as ready because the monitor has no word for it.
        check(targetStatus("future", withdrawn).availability == Availability::Unavailable && targetStatus("future", withdrawn).word == "hibernating",
              "an unrecognised administrative state is reported verbatim and never as ready");
    }
    check(modelLabel(traffic->targets[0], targets) == "llamacpp · qwen3-30b-a3b", "a target row is labelled by its machine and its model");
    check(modelLabel(traffic->targets[1], targets) == "openai-gpt", "an unknown target falls back to its identifier");

    check(parseErrorMessage(R"({"error":{"code":"unauthenticated","message":"this credential is not valid for the management API"}})")
              == "this credential is not valid for the management API", "refusal messages are extracted");
    check(!parseErrorMessage("<html>"), "a non-JSON body has no message");

    // Rate tracking: a rate needs two samples, honours the window, and is
    // reset by an epoch change or a counter going backwards.
    {
        RateTracker tracker(60000);
        std::vector<UsageCounter> counters{{"albert", 1, 100, 1000}};
        tracker.observe(counters, 1000, 0);
        check(!tracker.rate("albert", 0), "one sample is not a rate");
        counters[0] = {"albert", 3, 300, 3000};
        tracker.observe(counters, 1000, 10000);
        auto rate = tracker.rate("albert", 10000);
        check(rate && near(rate->outputPerSecond, 200.0) && near(rate->inputPerSecond, 20.0) && near(rate->requestsPerSecond, 0.2),
              "rate is the counter delta over the elapsed time");
        check(!tracker.rate("nobody", 10000), "an unknown series has no rate");

        // Nothing new for a while: the oldest sample falls out of the window and
        // the rate follows the recent, flat stretch rather than the old burst.
        for (Millis at = 20000; at <= 80000; at += 10000) tracker.observe(counters, 1000, at);
        rate = tracker.rate("albert", 80000);
        check(rate && near(rate->outputPerSecond, 0.0), "a burst older than the window no longer counts");

        // Silence past the window is stale, not zero.
        check(!tracker.rate("albert", 200000), "a series with no recent sample has no rate");

        // The router restarted: the epoch changes, and the old samples go.
        counters[0] = {"albert", 1, 10, 10};
        tracker.observe(counters, 2000, 90000);
        check(!tracker.rate("albert", 90000), "an epoch change discards the previous samples");
        counters[0] = {"albert", 2, 20, 30};
        tracker.observe(counters, 2000, 100000);
        rate = tracker.rate("albert", 100000);
        check(rate && near(rate->outputPerSecond, 2.0), "rates resume from the new epoch");

        // A counter going backwards under the same epoch also restarts.
        counters[0] = {"albert", 1, 5, 5};
        tracker.observe(counters, 2000, 110000);
        check(!tracker.rate("albert", 110000), "a counter that went backwards restarts its series");

        RateTracker bounded(60000, 2, 4);
        std::vector<UsageCounter> many{{"a", 1, 1, 1}, {"b", 1, 1, 1}, {"c", 1, 1, 1}};
        bounded.observe(many, 1, 0);
        check(bounded.series() == 2, "the series count is bounded");
        for (Millis at = 1000; at < 20000; at += 1000) bounded.observe(many, 1, at);
        check(bounded.rate("a", 19000).has_value(), "sample cap keeps the latest samples usable");
    }

    // Monitor rows: every visible model with its availability, users ranked by
    // throughput, honest empty and failure states.
    {
        RateBook rates(60000);
        const auto first = parseUsage(*parseJson(usageJson(1000, 500, 200, 500)));
        const auto second = parseUsage(*parseJson(usageJson(1000, 2500, 300, 2500)));
        rates.observe(*first, 0);
        rates.observe(*second, 10000);

        MonitorInput input;
        input.state = ConnectionState::Connected;
        input.traffic = traffic;
        input.usage = second;
        input.targets = targets;
        input.rates = &rates;
        input.now = 10000;

        auto rows = buildMonitorRows(input, {});
        std::size_t models = 0, users = 0, keys = 0, headings = 0;
        for (const auto& row : rows) {
            if (row.kind == RowKind::Model) ++models;
            if (row.kind == RowKind::Principal) ++users;
            if (row.kind == RowKind::Key) ++keys;
            if (row.kind == RowKind::Heading) ++headings;
        }
        check(models == 3, "every visible target is listed, not only the ones with traffic");
        check(headings == 3 && users == 2 && keys == 1, "users and keys each get a section");
        check(rows.size() > 1 && rows[1].kind == RowKind::Model && rows[1].label == "llamacpp · qwen3-30b-a3b" && rows[1].active,
              "the busiest model is first and drawn active");
        check(rows[1].caption.rfind("2/4 +1 queued", 0) == 0, "model caption shows occupancy and queue");
        check(rows[1].caption.find("200 tok/s") != std::string::npos, "model caption carries the target's rate");
        const MonitorRow* albert = nullptr;
        const MonitorRow* bob = nullptr;
        for (const auto& row : rows) {
            if (row.kind == RowKind::Principal && row.label == "albert") albert = &row;
            if (row.kind == RowKind::Principal && row.label == "bob") bob = &row;
        }
        check(albert && bob, "both active principals are listed");
        check(albert && near(*albert->fraction, 1.0) && bob && near(*bob->fraction, 0.05), "user bars are relative to the fastest user");
        check(albert && albert->caption == "200 tok/s", "user caption is output tokens per second");
        check(albert && albert->tooltip.find("in 0.00 tok/s") != std::string::npos, "user tooltip separates input and output rates");
        bool keyShortened = false;
        for (const auto& row : rows) if (row.kind == RowKind::Key && row.label == "e75e4806…") keyShortened = true;
        check(keyShortened, "key identifiers are shortened on the monitor");

        MonitorOptions onlyBusy;
        onlyBusy.showAllModels = false;
        rows = buildMonitorRows(input, onlyBusy);
        models = 0;
        for (const auto& row : rows) if (row.kind == RowKind::Model) ++models;
        check(models == 2, "the narrowed list keeps only the targets with traffic");

        MonitorOptions noKeys;
        noKeys.showKeys = false;
        rows = buildMonitorRows(input, noKeys);
        keys = 0;
        for (const auto& row : rows) if (row.kind == RowKind::Key) ++keys;
        check(keys == 0, "keys can be hidden");

        // Principal-scoped key: the router sends no by_key, so no Keys section.
        auto scoped = *second;
        scoped.tenantWide = false;
        scoped.keys.clear();
        input.usage = scoped;
        rows = buildMonitorRows(input, {});
        keys = 0;
        for (const auto& row : rows) if (row.kind == RowKind::Key) ++keys;
        check(keys == 0, "a principal-scoped key gets no key section");
        input.usage = second;

        // Long after the window, users disappear; the models are still listed
        // because they are still targets, which is the question that section
        // answers.
        input.now = 200000;
        rows = buildMonitorRows(input, {});
        users = 0; models = 0;
        for (const auto& row : rows) { if (row.kind == RowKind::Principal) ++users; if (row.kind == RowKind::Model) ++models; }
        check(users == 0 && models == 3, "stale rates drop off while the targets themselves stay listed");
        rows = buildMonitorRows(input, onlyBusy);
        models = 0;
        for (const auto& row : rows) if (row.kind == RowKind::Model) ++models;
        check(models == 2, "narrowed to traffic, a stale rate still leaves the in-flight targets");

        // A whole fleet at rest. The old panel answered this with one line and
        // no rows, which is the reading this monitor exists to correct: an
        // operator asking which models are up got "Idle" and no names.
        // `input.now` is already past the rate window, so nothing is moving
        // either: the fleet is at rest in every sense.
        MonitorInput idle = input;
        TrafficSnapshot quiet = *traffic;
        for (auto& target : quiet.targets) { target.inFlight = 0; target.queued = 0; target.activeStreams = 0; }
        idle.traffic = quiet;
        rows = buildMonitorRows(idle, onlyBusy);
        check(rows.size() == 1 && rows[0].kind == RowKind::Status && rows[0].label.rfind("Idle", 0) == 0,
              "narrowed to traffic, an idle router says so");
        rows = buildMonitorRows(idle, {});
        const MonitorRow* quietQwen = nullptr;
        for (const auto& row : rows) if (row.kind == RowKind::Model && row.label == "llamacpp · qwen3-30b-a3b") quietQwen = &row;
        check(quietQwen, "an enabled target with nothing in flight is still listed");
        check(quietQwen && quietQwen->availability == Availability::Ready && quietQwen->caption.find("ready") != std::string::npos,
              "a quiet enabled target reads as ready, not as an empty bar");
        check(quietQwen && quietQwen->tooltip.find("liveness") != std::string::npos,
              "the tooltip says ready is what the router knows, not a probe of the container");
        const MonitorRow* unlisted = nullptr;
        for (const auto& row : rows) if (row.kind == RowKind::Model && row.label == "openai-gpt") unlisted = &row;
        check(unlisted && unlisted->availability == Availability::Unknown && unlisted->caption.find("ready") == std::string::npos,
              "a target the listing does not contain is unknown, never ready");

        // Availability is not activity: a target an operator withdrew, or one
        // whose breaker is open, must be told apart from one that is merely
        // quiet - and must survive a list narrowed to traffic, because a
        // broken target has none.
        {
            MonitorInput broken = idle;
            auto listing = targets;
            listing[0].state = "draining";
            listing[1].breakerState = "open";
            listing.push_back({"openai-gpt", "gpt-5", "openai", "enabled", "half_open", false, false});
            broken.targets = listing;
            const auto brokenRows = buildMonitorRows(broken, onlyBusy);
            const MonitorRow* drained = nullptr;
            const MonitorRow* failing = nullptr;
            const MonitorRow* recovering = nullptr;
            const MonitorRow* heading = nullptr;
            for (const auto& row : brokenRows) {
                if (row.kind == RowKind::Heading && row.label.rfind("Models", 0) == 0) heading = &row;
                if (row.kind != RowKind::Model) continue;
                if (row.label == "llamacpp · qwen3-30b-a3b") drained = &row;
                if (row.label == "anthropic · claude-sonnet-5") failing = &row;
                if (row.label == "openai · gpt-5") recovering = &row;
            }
            check(drained && failing && recovering,
                  "a withdrawn, a failing and a recovering target are listed even when the list is narrowed to traffic");
            check(drained && drained->availability == Availability::Unavailable && drained->caption.find("draining") != std::string::npos,
                  "a draining target is named as draining, not drawn as idle");
            check(failing && failing->availability == Availability::Unavailable && failing->caption.find("failing") != std::string::npos,
                  "an open breaker reads as failing");
            check(recovering && recovering->availability == Availability::Recovering && recovering->caption.find("recovering") != std::string::npos,
                  "a half-open breaker reads as recovering");
            check(heading && heading->label.find("3 not available") != std::string::npos,
                  "the heading counts what is not available");

            MonitorInput quarantined = idle;
            auto quarantinedListing = targets;
            quarantinedListing[0].quarantined = true;
            quarantined.targets = quarantinedListing;
            const auto quarantinedRows = buildMonitorRows(quarantined, {});
            const MonitorRow* first = nullptr;
            const MonitorRow* held = nullptr;
            for (const auto& row : quarantinedRows) {
                if (row.kind != RowKind::Model) continue;
                if (!first) first = &row;
                if (row.label == "llamacpp · qwen3-30b-a3b") held = &row;
            }
            check(held && held->availability == Availability::Unavailable && held->caption.find("quarantined") != std::string::npos,
                  "an operator quarantine outranks a closed breaker");
            check(first && first->availability == Availability::Ready,
                  "a ready target is ranked above a quarantined one, however the listing is ordered");
        }

        // No admission controller exposed: no occupancy exists, but which
        // targets there are and whether each is available still does.
        {
            MonitorInput noCapacity;
            noCapacity.state = ConnectionState::Connected;
            TrafficSnapshot unavailable;
            unavailable.capacityAvailable = false;
            noCapacity.traffic = unavailable;
            noCapacity.targets = targets;
            noCapacity.now = 10000;
            const auto capacityless = buildMonitorRows(noCapacity, {});
            std::size_t listed = 0;
            const MonitorRow* row = nullptr;
            for (const auto& candidate : capacityless) {
                if (candidate.kind != RowKind::Model) continue;
                ++listed;
                if (candidate.label == "llamacpp · qwen3-30b-a3b") row = &candidate;
            }
            check(listed == 2, "a router with no admission controller still lists its targets");
            check(row && row->caption == "ready" && !row->fraction,
                  "a row with no occupancy claims none: the word, and no bar");
            check(row && row->tooltip.find("in flight") == std::string::npos,
                  "a row with no occupancy reports no in-flight figure");
        }

        MonitorInput unconfigured;
        rows = buildMonitorRows(unconfigured, {});
        check(rows.size() == 1 && rows[0].label.find("Options") != std::string::npos, "an unconfigured monitor points to Options");

        MonitorInput down = input;
        down.now = 10000;
        down.state = ConnectionState::Unreachable;
        down.diagnostic = "connect refused";
        rows = buildMonitorRows(down, {});
        check(!rows.empty() && rows.back().kind == RowKind::Status && rows.back().label.find("unreachable") != std::string::npos
              && rows.back().tooltip == "connect refused", "an unreachable router keeps the last data and says so");
        bool keptModels = false;
        for (const auto& row : rows) if (row.kind == RowKind::Model) keptModels = true;
        check(keptModels, "last known rows stay visible while unreachable");

        MonitorInput rejected;
        rejected.state = ConnectionState::AuthenticationRequired;
        rows = buildMonitorRows(rejected, {});
        check(rows.size() == 1 && rows[0].label.find("Key rejected") != std::string::npos, "a rejected key is named as such");
    }

    // A scorer generates no tokens, so a token rate is not the test for
    // whether it is working. Without the request rate the SemIf targets in
    // docker/hypellm.conf never appear: their calls are too short to be caught
    // in flight and their token counters never move.
    {
        RateBook rates(60000);
        const auto firstRerank = parseUsage(*parseJson(rerankUsageJson(40, 10)));
        const auto secondRerank = parseUsage(*parseJson(rerankUsageJson(70, 12)));
        rates.observe(*firstRerank, 0);
        rates.observe(*secondRerank, 10000);

        MonitorInput input;
        input.state = ConnectionState::Connected;
        input.traffic = parseTraffic(*parseJson(kRerankTraffic));
        input.usage = secondRerank;
        input.targets = parseTargets(*parseJson(kRerankTargets));
        input.rates = &rates;
        input.now = 10000;

        const auto rows = buildMonitorRows(input, {});
        const MonitorRow* spark = nullptr;
        const MonitorRow* carol = nullptr;
        const MonitorRow* dave = nullptr;
        const MonitorRow* spark2 = nullptr;
        for (const auto& row : rows) {
            if (row.kind == RowKind::Model && row.label == "semif-spark · Qwen3.5-4B-Q6_K") spark = &row;
            if (row.kind == RowKind::Model && row.label == "semif-spark2 · Qwen3.5-4B-Q6_K") spark2 = &row;
            if (row.kind == RowKind::Principal && row.label == "carol") carol = &row;
            if (row.kind == RowKind::Principal && row.label == "dave") dave = &row;
        }
        check(spark, "a target with requests moving and no tokens is still shown");
        check(spark && spark2, "two targets serving the same model name are told apart by machine");
        check(spark && spark->tooltip.rfind("semif-spark · Qwen3.5-4B-Q6_K (semif-spark:qwen35-4b)", 0) == 0,
              "the tooltip names the row and the target identifier it stands for");
        bool thirdScorer = false;
        for (const auto& row : rows) if (row.kind == RowKind::Model && row.label == "semif-1080 · Qwen3.5-4B-Q4_K_M") thirdScorer = true;
        check(thirdScorer, "every scorer names its machine, not only the pair that share a model name");
        check(spark && spark->caption.find("180 req/min") != std::string::npos,
              "a token-less model is captioned by its request rate");
        check(spark && spark->tooltip.find("tok/s") == std::string::npos,
              "a token-less model claims no token throughput");
        check(carol && dave, "principals whose traffic generates no tokens are still listed");
        check(carol && near(*carol->fraction, 1.0) && dave && near(*dave->fraction, 0.2 / 3.0),
              "a token-less section ranks by request rate");
        check(carol && carol->caption.find("req/min") != std::string::npos,
              "a token-less user is captioned by its request rate");

        std::size_t models = 0;
        for (const auto& row : rows) if (row.kind == RowKind::Model) ++models;
        check(models == 3, "every rerank target with requests moving is shown");

        const auto summary = traySummary(input);
        check(summary.tooltip.find("req/min") != std::string::npos,
              "the tray tooltip reports request rate when no tokens are moving");
    }

    // Tray summary.
    {
        RateBook rates(60000);
        MonitorInput input;
        input.state = ConnectionState::Connected;
        input.traffic = traffic;
        input.rates = &rates;
        auto summary = traySummary(input);
        check(summary.active && summary.tooltip.find("3 in flight") != std::string::npos && summary.tooltip.find("2 models") != std::string::npos,
              "tray tooltip counts in-flight requests and busy models");
        const auto half = utilisationColor(0.5);
        check(summary.color.red == half.red && summary.color.green == half.green, "tray colour follows the busiest target's utilisation");

        MonitorInput down;
        down.state = ConnectionState::Unreachable;
        check(traySummary(down).color.red > 200 && traySummary(down).color.green < 100, "unreachable is red");
        MonitorInput rejected;
        rejected.state = ConnectionState::AuthenticationRequired;
        check(traySummary(rejected).color.red == 255 && traySummary(rejected).color.green == 160, "rejected key is orange");
        MonitorInput none;
        check(traySummary(none).color.red == 140, "unconfigured is grey");
        check(!traySummary(none).active, "unconfigured is inactive");

        const auto green = utilisationColor(0.0);
        const auto red = utilisationColor(1.0);
        check(green.green > green.red && red.red > red.green, "utilisation ramps green to red");
    }

    check(formatRate(0.5) == "0.50" && formatRate(12.34) == "12.3" && formatRate(1234.0) == "1234" && formatRate(12345.0) == "12.3k",
          "rates are formatted to a readable width");
    check(formatCount(999) == "999" && formatCount(12345) == "12.3k" && formatCount(2500000) == "2.5M", "counts are abbreviated");

    if (failures == 0) std::cout << "hypellm-monitor core tests passed\n";
    return failures == 0 ? 0 : 1;
}
