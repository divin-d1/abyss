#include "scanner/deobfuscate.h"

#include <algorithm>
#include <cctype>
#include <regex>

namespace abyss::scanner {

namespace {

// Only the leading slice of a file is subjected to the more expensive
// decode passes below — obfuscated loader payloads are, in every
// documented sample, near the top of a small config/script file, not
// buried past hundreds of KB into a legitimate large file. This bounds
// worst-case per-file cost independent of the overall file size cap.
constexpr std::size_t kMaxWorkingSlice = 512 * 1024;
constexpr std::size_t kMaxDecodedOutput = 65536;
constexpr std::size_t kMaxCandidatesPerFile = 64;

const std::vector<std::string>& dangerousKeywordsLower() {
    static const std::vector<std::string> kws = {
        "require(", "child_process", "eval(", "function(", "new function(", "exec(",
        "execsync(", "spawn(", "spawnsync(", "process.env", "fetch(", "http.request",
        "https.request", "xmlhttprequest", "createrequire",
    };
    return kws;
}

std::string lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

bool findDangerousKeyword(const std::string& decodedLower, std::string& which) {
    for (const auto& kw : dangerousKeywordsLower()) {
        if (decodedLower.find(kw) != std::string::npos) { which = kw; return true; }
    }
    return false;
}

Finding makeFinding(const std::string& ruleId, const std::string& name, Severity sev, Confidence conf,
                     const std::string& desc, const std::string& relPath, const std::string& evidence,
                     std::vector<std::string> tags) {
    Finding f;
    f.findingId = nextFindingId();
    f.ruleId = ruleId;
    f.ruleName = name;
    f.type = RuleType::Behavior;
    f.severity = sev;
    f.confidence = conf;
    f.description = desc;
    f.filePath = relPath;
    f.evidence = evidence.size() > 160 ? evidence.substr(0, 160) + "..." : evidence;
    f.tags = std::move(tags);
    return f;
}

// --- Bounded decode primitives -------------------------------------------
// Every one of these is a pure data transform: table lookups and character
// arithmetic only. Nothing here parses JavaScript syntax or executes
// anything. Each takes an explicit output-size bound and stops (returning
// whatever was decoded so far) rather than growing unboundedly.

bool base64DecodeBounded(const std::string& in, std::string& out, std::size_t maxOutput) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = -8;
    out.clear();
    for (unsigned char c : in) {
        if (c == '=') break;
        auto pos = alphabet.find((char)c);
        if (pos == std::string::npos) continue; // skip non-alphabet chars defensively
        val = (val << 6) + (int)pos;
        bits += 6;
        if (bits >= 0) {
            if (out.size() >= maxOutput) return true; // bounded stop, not a failure
            out += (char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return true;
}

// Decodes \xNN and \uNNNN escapes found in `in`, passing all other
// characters through unchanged. For \uNNNN, only the low byte is kept
// (sufficient to reveal an ASCII keyword hidden this way — this is a
// keyword-detection aid, not a correctness-complete JS string decoder).
void decodeBackslashEscapes(const std::string& in, std::string& out, std::size_t maxOutput) {
    out.clear();
    for (std::size_t i = 0; i < in.size() && out.size() < maxOutput; i++) {
        if (in[i] == '\\' && i + 1 < in.size()) {
            if (in[i + 1] == 'x' && i + 3 < in.size() && std::isxdigit((unsigned char)in[i + 2]) &&
                std::isxdigit((unsigned char)in[i + 3])) {
                out += (char)std::stoi(in.substr(i + 2, 2), nullptr, 16);
                i += 3;
                continue;
            }
            if (in[i + 1] == 'u' && i + 5 < in.size() && std::isxdigit((unsigned char)in[i + 2]) &&
                std::isxdigit((unsigned char)in[i + 3]) && std::isxdigit((unsigned char)in[i + 4]) &&
                std::isxdigit((unsigned char)in[i + 5])) {
                out += (char)(std::stoi(in.substr(i + 2, 4), nullptr, 16) & 0xFF);
                i += 5;
                continue;
            }
        }
        out += in[i];
    }
}

void decodePercentEscapes(const std::string& in, std::string& out, std::size_t maxOutput) {
    out.clear();
    for (std::size_t i = 0; i < in.size() && out.size() < maxOutput; i++) {
        if (in[i] == '%' && i + 2 < in.size() && std::isxdigit((unsigned char)in[i + 1]) &&
            std::isxdigit((unsigned char)in[i + 2])) {
            out += (char)std::stoi(in.substr(i + 1, 2), nullptr, 16);
            i += 2;
            continue;
        }
        out += in[i];
    }
}

} // namespace

std::vector<Finding> scanObfuscationIndicators(const std::string& relPath, const std::string& content) {
    std::vector<Finding> findings;
    std::string slice = content.substr(0, std::min(content.size(), kMaxWorkingSlice));
    std::string sliceLower = lower(slice);

    // 1. Rotation-tolerant global[...] campaign-marker SHAPE, not a literal
    //    string — catches a property-name or value-prefix rotation that
    //    would defeat the literal IOC rules in rules/campaigns/*.rules.
    //    Bounded character classes throughout; backreference \1/\2 ties the
    //    opening/closing quote character together without a second literal
    //    quote-matching pass.
    {
        static const std::regex markerPattern(
            R"(global\s*\[\s*(['"])[^'"]{1,12}\1\s*\]\s*=\s*(['"])[A-Za-z]?\d{1,4}-\d{1,6}(?:-\d{1,6})?\2)");
        std::smatch m;
        if (std::regex_search(slice, m, markerPattern)) {
            findings.push_back(makeFinding(
                "core.obfuscation_global_marker_pattern", "Structural global[...] campaign-marker assignment",
                Severity::High, Confidence::Medium,
                "Content matches the *shape* of a `global[<key>]=<value>` campaign-marker assignment "
                "(short quoted property name, short numeric-dash-numeric value) independent of the exact "
                "property name or value — this catches a rotated variant that literal signature rules "
                "would miss. See rules/campaigns/polinrider.rules for the specific confirmed variants this "
                "generalizes from.",
                relPath, m.str(0), {"obfuscation", "structural", "rotation-tolerant"}));
        }
    }

    // 2. String.fromCharCode( usage — weak alone (also appears in
    //    legitimate code), corroborating alongside anything else.
    if (sliceLower.find("fromcharcode(") != std::string::npos) {
        findings.push_back(makeFinding(
            "core.obfuscation_charcode_construction", "Character-code string construction", Severity::Low,
            Confidence::Low,
            "File uses String.fromCharCode() to construct string content at runtime — common in both "
            "legitimate minified code and obfuscated payloads; weak evidence alone.",
            relPath, "fromCharCode(", {"obfuscation", "charcode"}));
    }

    // 3. Base64 blobs: decode as data (never evaluated) and check whether
    //    the decoded bytes reveal a dangerous keyword invisible in the raw
    //    (encoded) text.
    {
        static const std::regex base64Pattern(R"(\b[A-Za-z0-9+/]{40,4000}={0,2}\b)");
        auto begin = std::sregex_iterator(slice.begin(), slice.end(), base64Pattern);
        auto end = std::sregex_iterator();
        std::size_t checked = 0;
        for (auto it = begin; it != end && checked < kMaxCandidatesPerFile; ++it, ++checked) {
            std::string candidate = it->str();
            std::string decoded;
            base64DecodeBounded(candidate, decoded, kMaxDecodedOutput);
            std::string decodedLower = lower(decoded);
            std::string which;
            if (findDangerousKeyword(decodedLower, which)) {
                findings.push_back(makeFinding(
                    "core.obfuscation_base64_hidden_keyword", "Base64 content decodes to a dynamic-execution keyword",
                    Severity::High, Confidence::Medium,
                    "A base64-shaped token in this file decodes (as inert data — never executed) to content "
                    "containing '" + which + "', which is not visible in the file's raw text.",
                    relPath, candidate.substr(0, 60), {"obfuscation", "base64", "hidden-keyword"}));
            }
        }
    }

    // 4. Backslash-escape (\xNN / \uNNNN) decoding, same principle.
    {
        std::string decoded;
        decodeBackslashEscapes(slice, decoded, kMaxDecodedOutput);
        std::string decodedLower = lower(decoded);
        std::string which;
        if (decoded != slice.substr(0, decoded.size()) && findDangerousKeyword(decodedLower, which)) {
            // Only meaningful if the raw text doesn't already show the same
            // keyword plainly — otherwise this is just normal escaped code,
            // not concealment.
            if (sliceLower.find(which) == std::string::npos) {
                findings.push_back(makeFinding(
                    "core.obfuscation_hex_escape_hidden_keyword",
                    "Hex/Unicode-escaped content decodes to a dynamic-execution keyword", Severity::High,
                    Confidence::Medium,
                    "Decoding \\xNN/\\uNNNN escape sequences in this file (as inert data) reveals '" + which +
                        "', which does not appear in the file's raw, un-decoded text.",
                    relPath, which, {"obfuscation", "hex-escape", "hidden-keyword"}));
            }
        }
    }

    // 5. Percent-encoding decoding, same principle.
    {
        std::string decoded;
        decodePercentEscapes(slice, decoded, kMaxDecodedOutput);
        std::string decodedLower = lower(decoded);
        std::string which;
        if (decoded != slice.substr(0, decoded.size()) && findDangerousKeyword(decodedLower, which)) {
            if (sliceLower.find(which) == std::string::npos) {
                findings.push_back(makeFinding(
                    "core.obfuscation_percent_encoded_hidden_keyword",
                    "Percent-encoded content decodes to a dynamic-execution keyword", Severity::High,
                    Confidence::Medium,
                    "Percent-decoding (%XX) content in this file (as inert data) reveals '" + which +
                        "', which does not appear in the file's raw, un-decoded text.",
                    relPath, which, {"obfuscation", "percent-encoding", "hidden-keyword"}));
            }
        }
    }

    // 6. Reversed-string-literal idiom: '<literal>'.split('').reverse().join('')
    //    — a common trick to hide a keyword spelled backwards in source.
    //    Reversal here is a pure data operation on the captured literal.
    {
        static const std::regex reversedPattern(
            R"(['"]([^'"\\]{1,512})['"]\s*\.\s*split\s*\(\s*['"]{2}\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*['"]{2}\s*\))");
        auto begin = std::sregex_iterator(slice.begin(), slice.end(), reversedPattern);
        auto end = std::sregex_iterator();
        std::size_t checked = 0;
        for (auto it = begin; it != end && checked < kMaxCandidatesPerFile; ++it, ++checked) {
            std::string literal = (*it)[1].str();
            std::string reversed(literal.rbegin(), literal.rend());
            std::string which;
            if (findDangerousKeyword(lower(reversed), which)) {
                findings.push_back(makeFinding(
                    "core.obfuscation_reversed_string_hidden_keyword",
                    "Reversed string literal decodes to a dynamic-execution keyword", Severity::High,
                    Confidence::Medium,
                    "A string literal reversed via .split('').reverse().join('') (computed here as inert "
                    "data, never executed) reveals '" + which + "'.",
                    relPath, literal, {"obfuscation", "reversed-string", "hidden-keyword"}));
            }
        }
    }

    return findings;
}

} // namespace abyss::scanner
