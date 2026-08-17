#include "core/core.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace abyss {

// ---------------------------------------------------------------------------
// Enum <-> string
// ---------------------------------------------------------------------------

std::string toString(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "INFO";
}

std::string toString(Confidence c) {
    switch (c) {
        case Confidence::Unknown: return "UNKNOWN";
        case Confidence::Low: return "LOW";
        case Confidence::Medium: return "MEDIUM";
        case Confidence::High: return "HIGH";
        case Confidence::Confirmed: return "CONFIRMED";
    }
    return "UNKNOWN";
}

std::string toString(RuleType t) {
    switch (t) {
        case RuleType::Ioc: return "IOC";
        case RuleType::Structural: return "STRUCTURAL";
        case RuleType::Behavior: return "BEHAVIOR";
        case RuleType::Correlation: return "CORRELATION";
    }
    return "BEHAVIOR";
}

static std::string upper(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return std::toupper(c); });
    return r;
}

std::optional<Severity> severityFromString(const std::string& s) {
    std::string u = upper(s);
    if (u == "INFO") return Severity::Info;
    if (u == "LOW") return Severity::Low;
    if (u == "MEDIUM") return Severity::Medium;
    if (u == "HIGH") return Severity::High;
    if (u == "CRITICAL") return Severity::Critical;
    return std::nullopt;
}

std::optional<Confidence> confidenceFromString(const std::string& s) {
    std::string u = upper(s);
    if (u == "UNKNOWN") return Confidence::Unknown;
    if (u == "LOW") return Confidence::Low;
    if (u == "MEDIUM") return Confidence::Medium;
    if (u == "HIGH") return Confidence::High;
    if (u == "CONFIRMED") return Confidence::Confirmed;
    return std::nullopt;
}

std::optional<RuleType> ruleTypeFromString(const std::string& s) {
    std::string u = upper(s);
    if (u == "IOC") return RuleType::Ioc;
    if (u == "STRUCTURAL") return RuleType::Structural;
    if (u == "BEHAVIOR") return RuleType::Behavior;
    if (u == "CORRELATION") return RuleType::Correlation;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------

JsonValue JsonValue::makeBool(bool b) {
    JsonValue v;
    v.kind_ = Kind::Bool;
    v.boolVal_ = b;
    return v;
}

JsonValue JsonValue::makeNumber(double n) {
    JsonValue v;
    v.kind_ = Kind::Number;
    v.numVal_ = n;
    return v;
}

JsonValue JsonValue::makeString(std::string s) {
    JsonValue v;
    v.kind_ = Kind::String;
    v.strVal_ = std::move(s);
    return v;
}

JsonValue JsonValue::makeArray(JsonArray a) {
    JsonValue v;
    v.kind_ = Kind::Array;
    v.arrVal_ = std::make_shared<JsonArray>(std::move(a));
    return v;
}

JsonValue JsonValue::makeObject(JsonObject o) {
    JsonValue v;
    v.kind_ = Kind::Object;
    v.objVal_ = std::make_shared<JsonObject>(std::move(o));
    return v;
}

bool JsonValue::asBool(bool def) const { return kind_ == Kind::Bool ? boolVal_ : def; }
double JsonValue::asNumber(double def) const { return kind_ == Kind::Number ? numVal_ : def; }

static const std::string kEmptyString;

const std::string& JsonValue::asString() const {
    return kind_ == Kind::String ? strVal_ : kEmptyString;
}

std::string JsonValue::asStringOr(const std::string& def) const {
    return kind_ == Kind::String ? strVal_ : def;
}

static const JsonArray kEmptyArray;
static const JsonObject kEmptyObject;

const JsonArray& JsonValue::asArray() const {
    return arrVal_ ? *arrVal_ : kEmptyArray;
}

const JsonObject& JsonValue::asObject() const {
    return objVal_ ? *objVal_ : kEmptyObject;
}

const JsonValue* JsonValue::find(const std::string& key) const {
    if (kind_ != Kind::Object || !objVal_) return nullptr;
    for (const auto& [k, v] : *objVal_) {
        if (k == key) return &v;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// JSON / JSONC parser
// ---------------------------------------------------------------------------

namespace {

class JsonParser {
public:
    JsonParser(const std::string& text, const JsonParseLimits& limits)
        : text_(text), pos_(0), limits_(limits) {}

    JsonParseResult parse() {
        JsonParseResult result;
        if (text_.size() > limits_.maxInputBytes) {
            result.ok = false;
            result.error = "input exceeds maximum size (" + std::to_string(limits_.maxInputBytes) + " bytes)";
            return result;
        }
        if (!skipWhitespaceAndComments()) {
            result.ok = false;
            result.error = error_;
            return result;
        }
        if (!parseValue(result.value, 0)) {
            result.ok = false;
            result.error = error_.empty() ? "parse error" : error_;
            return result;
        }
        if (!skipWhitespaceAndComments()) {
            result.ok = false;
            result.error = error_;
            return result;
        }
        if (!atEnd()) {
            result.ok = false;
            result.error = "trailing content after root value at offset " + std::to_string(pos_);
            return result;
        }
        result.ok = true;
        return result;
    }

private:
    const std::string& text_;
    std::size_t pos_;
    JsonParseLimits limits_;
    std::string error_;
    std::size_t nodeCount_ = 0;

    bool atEnd() const { return pos_ >= text_.size(); }
    char peek() const { return atEnd() ? '\0' : text_[pos_]; }

    // Returns false (with error_ set) only on an unterminated block comment;
    // whitespace/line-comment skipping cannot itself fail.
    bool skipWhitespaceAndComments() {
        for (;;) {
            while (!atEnd() && (unsigned char)peek() <= ' ') pos_++;
            if (!atEnd() && peek() == '/' && pos_ + 1 < text_.size()) {
                if (text_[pos_ + 1] == '/') {
                    pos_ += 2;
                    while (!atEnd() && peek() != '\n') pos_++;
                    continue;
                }
                if (text_[pos_ + 1] == '*') {
                    std::size_t start = pos_;
                    pos_ += 2;
                    bool closed = false;
                    while (pos_ + 1 < text_.size()) {
                        if (text_[pos_] == '*' && text_[pos_ + 1] == '/') { closed = true; break; }
                        pos_++;
                    }
                    if (!closed) {
                        pos_ = start;
                        error_ = "unterminated block comment at offset " + std::to_string(start);
                        return false;
                    }
                    pos_ += 2;
                    continue;
                }
            }
            break;
        }
        return true;
    }

    bool fail(const std::string& msg) {
        error_ = msg + " at offset " + std::to_string(pos_);
        return false;
    }

    bool checkBudget() {
        nodeCount_++;
        if (nodeCount_ > limits_.maxNodes) return fail("exceeded maximum node count (" + std::to_string(limits_.maxNodes) + ")");
        return true;
    }

    bool parseValue(JsonValue& out, int depth) {
        if (depth > limits_.maxDepth) return fail("exceeded maximum nesting depth (" + std::to_string(limits_.maxDepth) + ")");
        if (!checkBudget()) return false;
        if (!skipWhitespaceAndComments()) return false;
        if (atEnd()) return fail("unexpected end of input");
        char c = peek();
        if (c == '{') return parseObject(out, depth);
        if (c == '[') return parseArray(out, depth);
        if (c == '"') {
            std::string s;
            if (!parseString(s)) return false;
            out = JsonValue::makeString(std::move(s));
            return true;
        }
        if (c == 't' || c == 'f') return parseBool(out);
        if (c == 'n') return parseNull(out);
        if (c == '-' || std::isdigit((unsigned char)c)) return parseNumber(out);
        return fail("unexpected character");
    }

    bool parseObject(JsonValue& out, int depth) {
        pos_++; // '{'
        JsonObject obj;
        std::set<std::string> seenKeys;
        if (!skipWhitespaceAndComments()) return false;
        if (!atEnd() && peek() == '}') {
            pos_++;
            out = JsonValue::makeObject(std::move(obj));
            return true;
        }
        for (;;) {
            if (!skipWhitespaceAndComments()) return false;
            if (atEnd() || peek() != '"') return fail("expected string key");
            std::string key;
            if (!parseString(key)) return false;
            if (!seenKeys.insert(key).second) return fail("duplicate object key '" + key + "'");
            if (!skipWhitespaceAndComments()) return false;
            if (atEnd() || peek() != ':') return fail("expected ':'");
            pos_++;
            JsonValue val;
            if (!parseValue(val, depth + 1)) return false;
            obj.emplace_back(std::move(key), std::move(val));
            if (!skipWhitespaceAndComments()) return false;
            if (atEnd()) return fail("unterminated object");
            if (peek() == ',') {
                pos_++;
                if (!skipWhitespaceAndComments()) return false;
                if (!atEnd() && peek() == '}') { pos_++; break; } // trailing comma
                continue;
            }
            if (peek() == '}') { pos_++; break; }
            return fail("expected ',' or '}'");
        }
        out = JsonValue::makeObject(std::move(obj));
        return true;
    }

    bool parseArray(JsonValue& out, int depth) {
        pos_++; // '['
        JsonArray arr;
        if (!skipWhitespaceAndComments()) return false;
        if (!atEnd() && peek() == ']') {
            pos_++;
            out = JsonValue::makeArray(std::move(arr));
            return true;
        }
        for (;;) {
            JsonValue val;
            if (!parseValue(val, depth + 1)) return false;
            arr.push_back(std::move(val));
            if (!skipWhitespaceAndComments()) return false;
            if (atEnd()) return fail("unterminated array");
            if (peek() == ',') {
                pos_++;
                if (!skipWhitespaceAndComments()) return false;
                if (!atEnd() && peek() == ']') { pos_++; break; } // trailing comma
                continue;
            }
            if (peek() == ']') { pos_++; break; }
            return fail("expected ',' or ']'");
        }
        out = JsonValue::makeArray(std::move(arr));
        return true;
    }

    static void encodeUtf8(std::string& s, std::uint32_t code) {
        if (code < 0x80) {
            s += (char)code;
        } else if (code < 0x800) {
            s += (char)(0xC0 | (code >> 6));
            s += (char)(0x80 | (code & 0x3F));
        } else if (code < 0x10000) {
            s += (char)(0xE0 | (code >> 12));
            s += (char)(0x80 | ((code >> 6) & 0x3F));
            s += (char)(0x80 | (code & 0x3F));
        } else {
            s += (char)(0xF0 | (code >> 18));
            s += (char)(0x80 | ((code >> 12) & 0x3F));
            s += (char)(0x80 | ((code >> 6) & 0x3F));
            s += (char)(0x80 | (code & 0x3F));
        }
    }

    // Reads exactly 4 hex digits at pos_ into `code`. Does not advance on
    // failure.
    bool readHex4(unsigned& code) {
        if (pos_ + 4 > text_.size()) return false;
        unsigned v = 0;
        for (int i = 0; i < 4; i++) {
            char h = text_[pos_ + i];
            v <<= 4;
            if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
            else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
            else return false;
        }
        pos_ += 4;
        code = v;
        return true;
    }

    bool parseString(std::string& out) {
        pos_++; // opening quote
        std::string s;
        while (!atEnd() && peek() != '"') {
            unsigned char c = (unsigned char)text_[pos_];
            // Strict JSON: raw control characters are rejected below.
            if (c < 0x20) return fail("raw control character (0x00-0x1F) in string literal; must be JSON-escaped");
            pos_++;
            if (c == '\\') {
                if (atEnd()) return fail("unterminated escape");
                char e = text_[pos_++];
                switch (e) {
                    case '"': s += '"'; break;
                    case '\\': s += '\\'; break;
                    case '/': s += '/'; break;
                    case 'b': s += '\b'; break;
                    case 'f': s += '\f'; break;
                    case 'n': s += '\n'; break;
                    case 'r': s += '\r'; break;
                    case 't': s += '\t'; break;
                    case 'u': {
                        unsigned code = 0;
                        if (!readHex4(code)) return fail("bad unicode escape digit");
                        if (code >= 0xD800 && code <= 0xDBFF) {
                            // High surrogate: must be immediately followed by
                            // a low surrogate \u escape to form a valid
                            // supplementary-plane code point.
                            if (pos_ + 2 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
                                return fail("lone UTF-16 high surrogate (no following low surrogate)");
                            }
                            pos_ += 2;
                            unsigned low = 0;
                            if (!readHex4(low)) return fail("bad unicode escape digit in low surrogate");
                            if (low < 0xDC00 || low > 0xDFFF) {
                                return fail("high surrogate not followed by a valid low surrogate");
                            }
                            std::uint32_t combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            encodeUtf8(s, combined);
                        } else if (code >= 0xDC00 && code <= 0xDFFF) {
                            return fail("lone UTF-16 low surrogate");
                        } else {
                            encodeUtf8(s, code);
                        }
                        break;
                    }
                    default: return fail("unknown escape");
                }
            } else {
                s += (char)c;
            }
        }
        if (atEnd()) return fail("unterminated string");
        pos_++; // closing quote
        out = std::move(s);
        return true;
    }

    bool parseBool(JsonValue& out) {
        if (text_.compare(pos_, 4, "true") == 0) { pos_ += 4; out = JsonValue::makeBool(true); return true; }
        if (text_.compare(pos_, 5, "false") == 0) { pos_ += 5; out = JsonValue::makeBool(false); return true; }
        return fail("invalid literal");
    }

    bool parseNull(JsonValue& out) {
        if (text_.compare(pos_, 4, "null") == 0) { pos_ += 4; out = JsonValue::makeNull(); return true; }
        return fail("invalid literal");
    }

    // Strict JSON number grammar: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
    // Every optional component that *starts* must be fully well-formed —
    // "1.", "1e", "01", and trailing junk are all rejected rather than
    // silently accepted as a truncated prefix parse.
    bool parseNumber(JsonValue& out) {
        std::size_t start = pos_;
        bool isDigit19 = false;

        if (!atEnd() && peek() == '-') pos_++;

        if (atEnd() || !std::isdigit((unsigned char)peek())) return fail("invalid number: expected a digit");
        if (peek() == '0') {
            pos_++;
        } else {
            isDigit19 = true;
            while (!atEnd() && std::isdigit((unsigned char)peek())) pos_++;
        }
        (void)isDigit19;

        if (!atEnd() && peek() == '.') {
            pos_++;
            if (atEnd() || !std::isdigit((unsigned char)peek())) {
                return fail("invalid number: '.' must be followed by at least one digit");
            }
            while (!atEnd() && std::isdigit((unsigned char)peek())) pos_++;
        }

        if (!atEnd() && (peek() == 'e' || peek() == 'E')) {
            pos_++;
            if (!atEnd() && (peek() == '+' || peek() == '-')) pos_++;
            if (atEnd() || !std::isdigit((unsigned char)peek())) {
                return fail("invalid number: exponent must have at least one digit");
            }
            while (!atEnd() && std::isdigit((unsigned char)peek())) pos_++;
        }

        double val = 0.0;
        auto [ptr, ec] = std::from_chars(text_.data() + start, text_.data() + pos_, val);
        // The grammar above already validated the full span; this also
        // guards against std::from_chars accepting only a shorter prefix
        // than what was consumed (it must not — ptr must land exactly at
        // pos_) and against overflow (errc::result_out_of_range).
        if (ec != std::errc() || ptr != text_.data() + pos_) return fail("invalid number");
        out = JsonValue::makeNumber(val);
        return true;
    }
};

} // namespace

JsonParseResult parseJson(const std::string& text, const JsonParseLimits& limits) {
    JsonParser parser(text, limits);
    return parser.parse();
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string findingToJsonLine(const Finding& f) {
    std::ostringstream os;
    os << "{";
    os << "\"findingId\":\"" << jsonEscape(f.findingId) << "\",";
    os << "\"ruleId\":\"" << jsonEscape(f.ruleId) << "\",";
    os << "\"ruleName\":\"" << jsonEscape(f.ruleName) << "\",";
    os << "\"type\":\"" << toString(f.type) << "\",";
    os << "\"severity\":\"" << toString(f.severity) << "\",";
    os << "\"confidence\":\"" << toString(f.confidence) << "\",";
    os << "\"description\":\"" << jsonEscape(f.description) << "\",";
    os << "\"filePath\":\"" << jsonEscape(f.filePath) << "\",";
    if (f.line) os << "\"line\":" << *f.line << ",";
    else os << "\"line\":null,";
    os << "\"evidence\":\"" << jsonEscape(f.evidence) << "\",";
    os << "\"tags\":[";
    for (std::size_t i = 0; i < f.tags.size(); i++) {
        if (i) os << ",";
        os << "\"" << jsonEscape(f.tags[i]) << "\"";
    }
    os << "],";
    os << "\"campaign\":\"" << jsonEscape(f.campaign) << "\",";
    os << "\"attributionConfidence\":\"" << toString(f.attributionConfidence) << "\"";
    os << "}";
    return os.str();
}

// ---------------------------------------------------------------------------
// Block format
// ---------------------------------------------------------------------------

std::string Block::get(const std::string& key, const std::string& def) const {
    auto it = fields.find(key);
    return it != fields.end() ? it->second : def;
}

std::vector<std::string> Block::getAll(const std::string& key) const {
    std::vector<std::string> out;
    auto range = fields.equal_range(key);
    for (auto it = range.first; it != range.second; ++it) out.push_back(it->second);
    return out;
}

bool Block::has(const std::string& key) const { return fields.find(key) != fields.end(); }

std::vector<std::string> Block::splitList(const std::string& value) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : value) {
        if (c == ';') {
            std::string t = trim(cur);
            if (!t.empty()) out.push_back(t);
            cur.clear();
        } else {
            cur += c;
        }
    }
    std::string t = trim(cur);
    if (!t.empty()) out.push_back(t);
    return out;
}

BlockParseResult parseBlocks(const std::string& text, const BlockParseLimits& limits) {
    BlockParseResult result;

    if (text.size() > limits.maxInputBytes) {
        result.error = "input exceeds maximum size (" + std::to_string(limits.maxInputBytes) + " bytes)";
        return result;
    }

    auto lines = splitLines(text);
    if (lines.size() > limits.maxLines) {
        result.error = "input exceeds maximum line count (" + std::to_string(limits.maxLines) + ")";
        return result;
    }

    Block current;
    bool haveCurrent = false;
    std::size_t lineNo = 0;
    std::size_t fieldsInCurrent = 0;

    auto flush = [&]() {
        if (haveCurrent) result.blocks.push_back(current);
        current = Block{};
        haveCurrent = false;
        fieldsInCurrent = 0;
    };

    for (const auto& rawLine : lines) {
        lineNo++;
        if (rawLine.size() > limits.maxLineLength) {
            result.error = "line " + std::to_string(lineNo) + " exceeds maximum length (" +
                            std::to_string(limits.maxLineLength) + " characters)";
            return result;
        }
        std::string line = trim(rawLine);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.front() == '[' && line.back() == ']') {
            flush();
            if (result.blocks.size() >= limits.maxBlocks) {
                result.error = "input exceeds maximum block count (" + std::to_string(limits.maxBlocks) + ")";
                return result;
            }
            current.section = trim(line.substr(1, line.size() - 2));
            haveCurrent = true;
            continue;
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            result.ok = false;
            result.error = "expected 'key=value' at line " + std::to_string(lineNo);
            return result;
        }
        if (!haveCurrent) {
            result.ok = false;
            result.error = "key=value outside of any [section] at line " + std::to_string(lineNo);
            return result;
        }
        if (++fieldsInCurrent > limits.maxFieldsPerBlock) {
            result.error = "block starting before line " + std::to_string(lineNo) + " exceeds maximum field "
                            "count (" + std::to_string(limits.maxFieldsPerBlock) + ")";
            return result;
        }
        std::string key = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));
        current.fields.emplace(std::move(key), std::move(value));
    }
    flush();
    result.ok = true;
    return result;
}

// ---------------------------------------------------------------------------
// Byte / text utilities
// ---------------------------------------------------------------------------

std::string toHex(const std::uint8_t* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; i++) {
        out += digits[(data[i] >> 4) & 0xF];
        out += digits[data[i] & 0xF];
    }
    return out;
}

std::string trim(const std::string& s) {
    std::size_t start = 0, end = s.size();
    while (start < end && (unsigned char)s[start] <= ' ') start++;
    while (end > start && (unsigned char)s[end - 1] <= ' ') end--;
    return s.substr(start, end - start);
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text) {
        if (c == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            lines.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    lines.push_back(cur);
    return lines;
}

bool readFileBytes(const std::string& path, std::vector<std::uint8_t>& out, bool& truncated,
                    std::size_t maxBytes) {
    truncated = false;
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamoff size = f.tellg();
    if (size < 0) return false;
    std::size_t toRead = (std::size_t)size;
    if (toRead > maxBytes) {
        toRead = maxBytes;
        truncated = true;
    }
    out.resize(toRead);
    f.seekg(0, std::ios::beg);
    if (toRead > 0) {
        f.read(reinterpret_cast<char*>(out.data()), (std::streamsize)toRead);
        if (!f && !f.eof()) return false;
    }
    return true;
}

std::string bytesToStringLossy(const std::vector<std::uint8_t>& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string nextFindingId() {
    static std::atomic<std::size_t> counter{0};
    std::size_t n = ++counter;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "F%06zu", n);
    return std::string(buf);
}

namespace {

struct SecretPattern {
    std::regex re;
    std::string kind;
    int valueGroup; // regex group index to replace; 0 = replace the whole match
};

const std::vector<SecretPattern>& secretPatterns() {
    // All patterns use bounded quantifiers (no nested unbounded repetition
    // on overlapping character classes) to avoid catastrophic backtracking
    // — these run on untrusted evidence text. std::regex is C++ standard
    // library, not a third-party dependency.
    static const std::vector<SecretPattern> patterns = {
        // AWS access key ID (fixed 16-char suffix after AKIA/ASIA).
        {std::regex(R"(\b((?:AKIA|ASIA)[0-9A-Z]{16})\b)"), "aws-access-key", 1},
        // GitHub / GitLab / Slack / OpenAI / Stripe token prefixes — long
        // fixed-prefix tokens with low false-positive risk.
        {std::regex(R"(\b(gh[pousr]_[A-Za-z0-9]{20,255})\b)"), "github-token", 1},
        {std::regex(R"(\b(glpat-[A-Za-z0-9\-_]{20,64})\b)"), "gitlab-token", 1},
        {std::regex(R"(\b(xox[baprs]-[A-Za-z0-9\-]{10,64})\b)"), "slack-token", 1},
        {std::regex(R"(\b(sk-[A-Za-z0-9]{20,64})\b)"), "api-secret-key", 1},
        {std::regex(R"(\b(sk_live_[A-Za-z0-9]{10,64})\b)"), "stripe-live-key", 1},
        // PEM private-key blocks (any algorithm label). Lazy match is
        // unbounded here deliberately — callers apply this to already
        // length-capped evidence excerpts (a few hundred bytes), so the
        // worst case is small and a bounded lazy quantifier isn't needed.
        {std::regex(R"(-----BEGIN [A-Z ]*?PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*?PRIVATE KEY-----)"),
         "private-key-block", 0},
        // Authorization: Bearer/Basic <token>
        {std::regex(R"((?:[Aa]uthorization\s*:\s*(?:[Bb]earer|[Bb]asic)\s+)([A-Za-z0-9_\-\.=]{8,512}))"),
         "authorization-header", 1},
        // key=value / key: "value" where the key name suggests a secret
        // (api key, token, password, secret, private key) — matched
        // case-insensitively so conventional ALL_CAPS .env-style names
        // (DB_PASSWORD, API_KEY) are caught, not just Capitalized/lower.
        // No word-boundary is added before the key name deliberately:
        // underscore counts as a "word" character to \b, so a leading \b
        // would break matching "DB_PASSWORD"/"API_KEY" themselves (there is
        // no boundary between '_' and the following letter) — the exact
        // .env convention this pattern exists to catch. The mid-identifier
        // false positive this could cause ("getPassword: someFn()") is
        // instead filtered by scanner::scanCredentialExposure's
        // looksPlaceholder(), which can safely reason about the *value*
        // without risking the key-name side effect above. The trailing
        // (?!\s*\() here excludes the single most common false-positive
        // shape found in practice — `api_key: getSomething(...)` — where
        // the "value" is a function call, not a literal. This doesn't
        // require the value to be quoted, since real .env-style secrets are
        // routinely unquoted (KEY=value) and that's the detection this
        // pattern exists for.
        {std::regex(R"((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|)"
                     R"(secret[_-]?key|private[_-]?key|password|passwd|pwd))"
                     R"((\s*[:=]\s*['"]?)([A-Za-z0-9_\-\.\/+=]{6,256})(['"]?)(?!\s*\())",
                     std::regex::ECMAScript | std::regex::icase),
         "credential-value", 2},
        // Connection-string embedded password: scheme://user:PASSWORD@host
        {std::regex(R"((://[^:\s/@]+:)([^@\s]{1,256})(@))"), "connection-string-password", 2},
    };
    return patterns;
}

} // namespace

std::string redactSecrets(const std::string& s) {
    std::string out = s;
    for (const auto& p : secretPatterns()) {
        std::string replaced;
        replaced.reserve(out.size());
        auto begin = std::sregex_iterator(out.begin(), out.end(), p.re);
        auto end = std::sregex_iterator();
        std::size_t lastPos = 0;
        std::string placeholder = "[REDACTED:" + p.kind + "]";
        for (auto it = begin; it != end; ++it) {
            const std::smatch& m = *it;
            std::size_t groupStart, groupLen;
            if (p.valueGroup == 0) {
                groupStart = (std::size_t)m.position(0);
                groupLen = (std::size_t)m.length(0);
            } else {
                groupStart = (std::size_t)m.position(p.valueGroup);
                groupLen = (std::size_t)m.length(p.valueGroup);
            }
            replaced.append(out, lastPos, groupStart - lastPos);
            replaced += placeholder;
            lastPos = groupStart + groupLen;
        }
        replaced.append(out, lastPos, out.size() - lastPos);
        out = std::move(replaced);
    }
    return out;
}

std::vector<SecretMatch> detectSecretMatches(const std::string& s) {
    std::vector<SecretMatch> matches;
    for (const auto& p : secretPatterns()) {
        auto begin = std::sregex_iterator(s.begin(), s.end(), p.re);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            const std::smatch& m = *it;
            std::size_t pos, len;
            if (p.valueGroup == 0) {
                pos = static_cast<std::size_t>(m.position(0));
                len = static_cast<std::size_t>(m.length(0));
            } else {
                pos = static_cast<std::size_t>(m.position(p.valueGroup));
                len = static_cast<std::size_t>(m.length(p.valueGroup));
            }
            matches.push_back({p.kind, pos, s.substr(pos, len)});
        }
    }
    return matches;
}

std::string getEnvVar(const std::string& name) {
#if defined(_WIN32)
    DWORD required = GetEnvironmentVariableA(name.c_str(), nullptr, 0);
    if (required == 0 || required > 32768) return {};
    std::vector<char> buffer(required);
    DWORD copied = GetEnvironmentVariableA(name.c_str(), buffer.data(), required);
    if (copied == 0 || copied >= required) return {};
    return std::string(buffer.data(), copied);
#else
    const char* v = std::getenv(name.c_str());
    return v ? std::string(v) : std::string();
#endif
}

std::optional<long long> parseStrictInt(const std::string& s) {
    std::string t = trim(s);
    if (t.empty()) return std::nullopt;
    long long val = 0;
    auto [ptr, ec] = std::from_chars(t.data(), t.data() + t.size(), val);
    if (ec != std::errc() || ptr != t.data() + t.size()) return std::nullopt;
    return val;
}

std::optional<double> parseStrictDouble(const std::string& s) {
    std::string t = trim(s);
    if (t.empty()) return std::nullopt;
    double val = 0.0;
    auto [ptr, ec] = std::from_chars(t.data(), t.data() + t.size(), val);
    if (ec != std::errc() || ptr != t.data() + t.size()) return std::nullopt;
    if (!std::isfinite(val)) return std::nullopt; // reject NaN/Infinity
    return val;
}

bool pathStartsWith(const std::filesystem::path& child, const std::filesystem::path& ancestor) {
    auto ci = child.begin(), ce = child.end();
    auto ai = ancestor.begin(), ae = ancestor.end();
    for (; ai != ae; ++ai, ++ci) {
        if (ci == ce || *ci != *ai) return false;
    }
    return true;
}

#if defined(_WIN32)
bool isReparsePoint(const std::filesystem::path& p) {
    DWORD attrs = GetFileAttributesW(p.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}
#else
bool isReparsePoint(const std::filesystem::path&) { return false; }
#endif

std::string sanitizeForOutput(const std::string& s, std::size_t maxLen) {
    std::string out;
    out.reserve(std::min(s.size(), maxLen) + 3);
    for (std::size_t i = 0; i < s.size() && out.size() < maxLen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1B) {
            // ESC: drop the escape byte and the CSI/OSC sequence that
            // follows it, so an attacker-controlled filename can't move the
            // cursor, clear the screen, or rewrite prior terminal output.
            // CSI: ESC '[' ... final byte in 0x40-0x7E. OSC: ESC ']' ...
            // terminated by BEL or ESC '\'. Anything else after ESC: drop
            // just the ESC and let the following byte be re-evaluated
            // normally (it is very unlikely to be a legitimate use of a
            // raw ESC byte in a filename/evidence excerpt).
            if (i + 1 < s.size() && s[i + 1] == '[') {
                std::size_t j = i + 2;
                while (j < s.size() && !(s[j] >= 0x40 && s[j] <= 0x7E)) j++;
                i = j; // land on the final byte; loop's ++i skips past it
            } else if (i + 1 < s.size() && s[i + 1] == ']') {
                std::size_t j = i + 2;
                while (j < s.size() && s[j] != '\a' && !(s[j] == 0x1B && j + 1 < s.size() && s[j + 1] == '\\')) j++;
                i = j;
            }
            continue;
        }
        if (c == 0x7F) { out += '?'; continue; }
        if (c < 0x20 && c != '\t') { out += '?'; continue; }
        out += (char)c;
    }
    if (s.size() > maxLen) out += "...";
    return out;
}

} // namespace abyss
