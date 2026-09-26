#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hypellm_monitor {

// A small, bounded JSON reader for the management API's replies. Depth and
// size are limited up front so a misbehaving router cannot make the monitor
// recurse or allocate without bound; anything past a limit is a parse failure,
// never a partial value.
struct JsonValue {
    enum class Kind { Null, Bool, Number, String, Array, Object };

    Kind kind{Kind::Null};
    bool boolean{false};
    double number{0.0};
    // Set when the literal was a plain non-negative integer, so token counters
    // survive intact past the 2^53 point where `number` would round.
    std::optional<std::uint64_t> integer;
    std::string string;
    std::vector<JsonValue> array;
    std::vector<std::pair<std::string, JsonValue>> object;

    [[nodiscard]] const JsonValue* get(std::string_view key) const;
    [[nodiscard]] std::optional<std::string_view> str(std::string_view key) const;
    [[nodiscard]] std::optional<std::uint64_t> count(std::string_view key) const;
    [[nodiscard]] std::optional<double> num(std::string_view key) const;
    [[nodiscard]] bool flag(std::string_view key, bool fallback) const;
    [[nodiscard]] const std::vector<JsonValue>* list(std::string_view key) const;
};

struct JsonLimits {
    std::size_t maxBytes{4 * 1024 * 1024};
    std::size_t maxDepth{32};
    std::size_t maxElements{100000};
};

[[nodiscard]] std::optional<JsonValue> parseJson(std::string_view text, JsonLimits limits = {});

} // namespace hypellm_monitor
