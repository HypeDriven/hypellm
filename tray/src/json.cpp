#include "json.hpp"

#include <cmath>
#include <cstdlib>

namespace hypellm_monitor {

namespace {

class Parser {
public:
    Parser(std::string_view text, JsonLimits limits) : text_(text), limits_(limits) {}

    std::optional<JsonValue> parseDocument() {
        skipSpace();
        auto value = parseValue(0);
        if (!value) return std::nullopt;
        skipSpace();
        if (pos_ != text_.size()) return std::nullopt;
        return value;
    }

private:
    std::string_view text_;
    JsonLimits limits_;
    std::size_t pos_{0};
    std::size_t elements_{0};

    void skipSpace() {
        while (pos_ < text_.size()) {
            const char ch = text_[pos_];
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') ++pos_;
            else break;
        }
    }

    bool consume(std::string_view literal) {
        if (text_.substr(pos_, literal.size()) != literal) return false;
        pos_ += literal.size();
        return true;
    }

    bool countElement() {
        if (++elements_ > limits_.maxElements) return false;
        return true;
    }

    std::optional<JsonValue> parseValue(std::size_t depth) {
        if (depth > limits_.maxDepth) return std::nullopt;
        if (!countElement()) return std::nullopt;
        if (pos_ >= text_.size()) return std::nullopt;
        JsonValue value;
        switch (text_[pos_]) {
        case '{': return parseObject(depth);
        case '[': return parseArray(depth);
        case '"': {
            auto string = parseString();
            if (!string) return std::nullopt;
            value.kind = JsonValue::Kind::String;
            value.string = std::move(*string);
            return value;
        }
        case 't':
            if (!consume("true")) return std::nullopt;
            value.kind = JsonValue::Kind::Bool;
            value.boolean = true;
            return value;
        case 'f':
            if (!consume("false")) return std::nullopt;
            value.kind = JsonValue::Kind::Bool;
            value.boolean = false;
            return value;
        case 'n':
            if (!consume("null")) return std::nullopt;
            value.kind = JsonValue::Kind::Null;
            return value;
        default: return parseNumber();
        }
    }

    std::optional<JsonValue> parseNumber() {
        const std::size_t start = pos_;
        bool integer = true;
        if (pos_ < text_.size() && text_[pos_] == '-') { ++pos_; integer = false; }
        std::size_t digits = 0;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') { ++pos_; ++digits; }
        if (digits == 0) return std::nullopt;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            integer = false;
            ++pos_;
            std::size_t fraction = 0;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') { ++pos_; ++fraction; }
            if (fraction == 0) return std::nullopt;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            integer = false;
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            std::size_t exponent = 0;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') { ++pos_; ++exponent; }
            if (exponent == 0) return std::nullopt;
        }
        const std::string literal(text_.substr(start, pos_ - start));
        JsonValue value;
        value.kind = JsonValue::Kind::Number;
        value.number = std::strtod(literal.c_str(), nullptr);
        if (!std::isfinite(value.number)) return std::nullopt;
        if (integer && literal.size() <= 20) {
            std::uint64_t parsed = 0;
            bool overflow = false;
            for (const char ch : literal) {
                const auto digit = static_cast<std::uint64_t>(ch - '0');
                if (parsed > (UINT64_MAX - digit) / 10) { overflow = true; break; }
                parsed = parsed * 10 + digit;
            }
            if (!overflow) value.integer = parsed;
        }
        return value;
    }

    static void appendUtf8(std::string& out, std::uint32_t code) {
        if (code < 0x80) {
            out.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (code >> 18)));
            out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }

    std::optional<std::uint32_t> parseHex4() {
        if (pos_ + 4 > text_.size()) return std::nullopt;
        std::uint32_t value = 0;
        for (int index = 0; index < 4; ++index) {
            const char ch = text_[pos_++];
            value <<= 4;
            if (ch >= '0' && ch <= '9') value |= static_cast<std::uint32_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value |= static_cast<std::uint32_t>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value |= static_cast<std::uint32_t>(ch - 'A' + 10);
            else return std::nullopt;
        }
        return value;
    }

    std::optional<std::string> parseString() {
        if (pos_ >= text_.size() || text_[pos_] != '"') return std::nullopt;
        ++pos_;
        std::string out;
        while (pos_ < text_.size()) {
            const char ch = text_[pos_++];
            if (ch == '"') return out;
            if (static_cast<unsigned char>(ch) < 0x20) return std::nullopt;
            if (ch != '\\') { out.push_back(ch); continue; }
            if (pos_ >= text_.size()) return std::nullopt;
            const char escape = text_[pos_++];
            switch (escape) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                auto code = parseHex4();
                if (!code) return std::nullopt;
                if (*code >= 0xD800 && *code <= 0xDBFF) {
                    if (!consume("\\u")) return std::nullopt;
                    auto low = parseHex4();
                    if (!low || *low < 0xDC00 || *low > 0xDFFF) return std::nullopt;
                    *code = 0x10000 + ((*code - 0xD800) << 10) + (*low - 0xDC00);
                } else if (*code >= 0xDC00 && *code <= 0xDFFF) {
                    return std::nullopt;
                }
                appendUtf8(out, *code);
                break;
            }
            default: return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<JsonValue> parseArray(std::size_t depth) {
        ++pos_;
        JsonValue value;
        value.kind = JsonValue::Kind::Array;
        skipSpace();
        if (consume("]")) return value;
        while (true) {
            skipSpace();
            auto element = parseValue(depth + 1);
            if (!element) return std::nullopt;
            value.array.push_back(std::move(*element));
            skipSpace();
            if (consume(",")) continue;
            if (consume("]")) return value;
            return std::nullopt;
        }
    }

    std::optional<JsonValue> parseObject(std::size_t depth) {
        ++pos_;
        JsonValue value;
        value.kind = JsonValue::Kind::Object;
        skipSpace();
        if (consume("}")) return value;
        while (true) {
            skipSpace();
            auto key = parseString();
            if (!key) return std::nullopt;
            skipSpace();
            if (!consume(":")) return std::nullopt;
            skipSpace();
            auto element = parseValue(depth + 1);
            if (!element) return std::nullopt;
            value.object.emplace_back(std::move(*key), std::move(*element));
            skipSpace();
            if (consume(",")) continue;
            if (consume("}")) return value;
            return std::nullopt;
        }
    }
};

} // namespace

const JsonValue* JsonValue::get(std::string_view key) const {
    if (kind != Kind::Object) return nullptr;
    for (const auto& [name, value] : object) {
        if (name == key) return &value;
    }
    return nullptr;
}

std::optional<std::string_view> JsonValue::str(std::string_view key) const {
    const auto* value = get(key);
    if (!value || value->kind != Kind::String) return std::nullopt;
    return std::string_view(value->string);
}

std::optional<std::uint64_t> JsonValue::count(std::string_view key) const {
    const auto* value = get(key);
    if (!value || value->kind != Kind::Number) return std::nullopt;
    if (value->integer) return value->integer;
    // 2^64 is exact as a double. Converting a value at or past it to uint64_t
    // is undefined behaviour, not a saturation, so it is refused first — as is
    // anything negative. (NaN and infinity never reach here: the parser
    // refuses non-finite numbers.)
    constexpr double kTwoTo64 = 18446744073709551616.0;
    if (!(value->number >= 0.0 && value->number < kTwoTo64)) return std::nullopt;
    return static_cast<std::uint64_t>(value->number);
}

std::optional<double> JsonValue::num(std::string_view key) const {
    const auto* value = get(key);
    if (!value || value->kind != Kind::Number) return std::nullopt;
    return value->number;
}

bool JsonValue::flag(std::string_view key, bool fallback) const {
    const auto* value = get(key);
    if (!value || value->kind != Kind::Bool) return fallback;
    return value->boolean;
}

const std::vector<JsonValue>* JsonValue::list(std::string_view key) const {
    const auto* value = get(key);
    if (!value || value->kind != Kind::Array) return nullptr;
    return &value->array;
}

std::optional<JsonValue> parseJson(std::string_view text, JsonLimits limits) {
    if (text.size() > limits.maxBytes) return std::nullopt;
    Parser parser(text, limits);
    return parser.parseDocument();
}

} // namespace hypellm_monitor
