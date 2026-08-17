#include "scanner/scanner.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

#include "crypto/sha256.h"
#include "git/git_propagation.h"
#include "scanner/deobfuscate.h"
#include "vscode/vscode.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace abyss::scanner {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Magic / structural validation
// ---------------------------------------------------------------------------

std::string toString(FileKind k) {
    switch (k) {
        case FileKind::Unknown: return "UNKNOWN";
        case FileKind::Woff: return "WOFF";
        case FileKind::Woff2: return "WOFF2";
        case FileKind::Ttf: return "TTF";
        case FileKind::Otf: return "OTF";
        case FileKind::Png: return "PNG";
        case FileKind::Jpeg: return "JPEG";
        case FileKind::Gif: return "GIF";
        case FileKind::Pdf: return "PDF";
        case FileKind::Zip: return "ZIP";
        case FileKind::Pe: return "PE";
    }
    return "UNKNOWN";
}

namespace {
bool startsWith(const std::uint8_t* data, std::size_t len, std::initializer_list<std::uint8_t> sig) {
    if (len < sig.size()) return false;
    std::size_t i = 0;
    for (auto b : sig) {
        if (data[i++] != b) return false;
    }
    return true;
}
} // namespace

FileKind detectMagic(const std::uint8_t* data, std::size_t len) {
    if (len == 0) return FileKind::Unknown;

    if (startsWith(data, len, {0x77, 0x4F, 0x46, 0x32})) return FileKind::Woff2; // 'wOF2'
    if (startsWith(data, len, {0x77, 0x4F, 0x46, 0x46})) return FileKind::Woff;  // 'wOFF'
    if (startsWith(data, len, {0x4F, 0x54, 0x54, 0x4F})) return FileKind::Otf;   // 'OTTO'
    if (startsWith(data, len, {0x00, 0x01, 0x00, 0x00})) return FileKind::Ttf;   // sfnt v1
    if (startsWith(data, len, {0x74, 0x72, 0x75, 0x65})) return FileKind::Ttf;   // 'true'
    if (startsWith(data, len, {0x74, 0x74, 0x63, 0x66})) return FileKind::Ttf;   // 'ttcf' collection
    if (startsWith(data, len, {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})) return FileKind::Png;
    if (startsWith(data, len, {0xFF, 0xD8, 0xFF})) return FileKind::Jpeg;
    if (startsWith(data, len, {'G', 'I', 'F', '8', '7', 'a'})) return FileKind::Gif;
    if (startsWith(data, len, {'G', 'I', 'F', '8', '9', 'a'})) return FileKind::Gif;
    if (startsWith(data, len, {'%', 'P', 'D', 'F', '-'})) return FileKind::Pdf;
    if (startsWith(data, len, {'P', 'K', 0x03, 0x04})) return FileKind::Zip;
    if (startsWith(data, len, {'P', 'K', 0x05, 0x06})) return FileKind::Zip;
    if (startsWith(data, len, {'P', 'K', 0x07, 0x08})) return FileKind::Zip;
    if (startsWith(data, len, {'M', 'Z'})) {
        if (len >= 0x40) {
            std::uint32_t peOffset = (std::uint32_t)data[0x3C] | ((std::uint32_t)data[0x3D] << 8) |
                                      ((std::uint32_t)data[0x3E] << 16) | ((std::uint32_t)data[0x3F] << 24);
            if (peOffset + 4 <= len && startsWith(data + peOffset, len - peOffset, {'P', 'E', 0x00, 0x00})) {
                return FileKind::Pe;
            }
        }
        return FileKind::Pe; // DOS header present even if PE header unverifiable (truncated read)
    }
    return FileKind::Unknown;
}

std::vector<FileKind> expectedKindsForExtension(const std::string& extensionLower) {
    static const std::unordered_map<std::string, std::vector<FileKind>> table = {
        {".woff", {FileKind::Woff}},
        {".woff2", {FileKind::Woff2}},
        {".ttf", {FileKind::Ttf}},
        {".otf", {FileKind::Otf}},
        {".png", {FileKind::Png}},
        {".jpg", {FileKind::Jpeg}},
        {".jpeg", {FileKind::Jpeg}},
        {".gif", {FileKind::Gif}},
        {".pdf", {FileKind::Pdf}},
        {".zip", {FileKind::Zip}},
        {".exe", {FileKind::Pe}},
        {".dll", {FileKind::Pe}},
    };
    auto it = table.find(extensionLower);
    if (it == table.end()) return {};
    return it->second;
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

double shannonEntropyBits(const std::uint8_t* data, std::size_t len) {
    if (len == 0) return 0.0;
    std::array<std::size_t, 256> counts{};
    for (std::size_t i = 0; i < len; i++) counts[data[i]]++;
    double entropy = 0.0;
    double total = (double)len;
    for (std::size_t c : counts) {
        if (c == 0) continue;
        double p = (double)c / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ---------------------------------------------------------------------------
// Threshold loading
// ---------------------------------------------------------------------------

namespace {

// Strict, checked threshold read: a present-but-invalid value (negative,
// non-numeric, overflowing, NaN/Infinity, trailing junk) falls back to the
// existing default rather than being silently coerced to 0 or accepted as
// poisoned data — thresholds are tuning, but a corrupted/adversarial
// threshold file must not be able to zero out a detector's sensitivity.
void applyStrictSizeThreshold(const Block& b, const char* key, std::size_t& target) {
    if (!b.has(key)) return;
    auto v = parseStrictInt(b.get(key));
    if (v && *v >= 0) target = (std::size_t)*v;
}

void applyStrictDoubleThreshold(const Block& b, const char* key, double& target) {
    if (!b.has(key)) return;
    auto v = parseStrictDouble(b.get(key));
    if (v && *v >= 0.0) target = *v;
}

} // namespace

ScanThresholds loadThresholds(const std::string& path) {
    ScanThresholds t = ScanThresholds::withDefaults();
    std::ifstream f(path, std::ios::binary);
    if (!f) return t;
    std::ostringstream ss;
    ss << f.rdbuf();
    auto parsed = parseBlocks(ss.str());
    if (!parsed.ok) return t;
    for (const auto& b : parsed.blocks) {
        if (b.section != "thresholds") continue;
        applyStrictSizeThreshold(b, "oversized_line_length", t.oversizedLineLength);
        applyStrictSizeThreshold(b, "concealment_gap_length", t.concealmentGapLength);
        applyStrictSizeThreshold(b, "escape_density_min_count", t.escapeDensityMinCount);
        applyStrictSizeThreshold(b, "long_token_length", t.longTokenLength);
        applyStrictDoubleThreshold(b, "high_entropy_threshold", t.highEntropyThreshold);
        applyStrictSizeThreshold(b, "high_entropy_min_line_length", t.highEntropyMinLineLength);
        applyStrictDoubleThreshold(b, "high_entropy_max_whitespace_ratio", t.highEntropyMaxWhitespaceRatio);
    }
    return t;
}

// ---------------------------------------------------------------------------
// Text heuristics
// ---------------------------------------------------------------------------

namespace {

Finding makeFinding(const std::string& ruleId, const std::string& name, RuleType type, Severity sev,
                     Confidence conf, const std::string& desc, const std::string& relPath,
                     std::optional<std::size_t> line, const std::string& evidence,
                     std::vector<std::string> tags) {
    Finding f;
    f.findingId = nextFindingId();
    f.ruleId = ruleId;
    f.ruleName = name;
    f.type = type;
    f.severity = sev;
    f.confidence = conf;
    f.description = desc;
    f.filePath = relPath;
    f.line = line;
    f.evidence = evidence.size() > 120 ? evidence.substr(0, 120) + "..." : evidence;
    f.tags = std::move(tags);
    return f;
}

bool isHorizontalWhitespace(char c) { return c == ' ' || c == '\t'; }

std::size_t longestNonWhitespaceRun(const std::string& line) {
    std::size_t best = 0, cur = 0;
    for (char c : line) {
        if ((unsigned char)c > ' ') {
            cur++;
            best = std::max(best, cur);
        } else {
            cur = 0;
        }
    }
    return best;
}

// The actual text of the longest unbroken non-whitespace run in `line`
// (there can be more than one run of the winning length; the first is
// returned, matching longestNonWhitespaceRun()'s tie-breaking).
std::string longestNonWhitespaceRunText(const std::string& line) {
    std::size_t bestStart = 0, bestLen = 0, curStart = 0, curLen = 0;
    for (std::size_t i = 0; i < line.size(); i++) {
        if ((unsigned char)line[i] > ' ') {
            if (curLen == 0) curStart = i;
            curLen++;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else {
            curLen = 0;
        }
    }
    return line.substr(bestStart, bestLen);
}

// True if `token` is shaped like a URL (a scheme, "://", and more content),
// allowing at most one leading wrapper character (the quote/bracket the
// token is embedded in, e.g. `"https://...` inside JSON). A long URL is
// structured, human-readable text -- a resolved package registry tarball
// link, a CDN asset link, an image src -- not opaque encoded/compressed
// payload data, however long and unbroken it is. match_continuous anchors
// the scheme to the very start (after the optional wrapper) so this can't
// become a loophole where an opaque blob defeats the detector merely by
// containing "://" somewhere in its middle.
bool looksLikeUrl(const std::string& token) {
    static const std::regex urlPattern(R"([A-Za-z][A-Za-z0-9+.-]{1,15}://\S)");
    std::size_t start = 0;
    if (start < token.size() && std::strchr("\"'`([<", token[start]) != nullptr) start++;
    if (start >= token.size()) return false;
    return std::regex_search(token.cbegin() + static_cast<std::ptrdiff_t>(start), token.cend(), urlPattern,
                             std::regex_constants::match_continuous);
}

std::size_t countEscapeSequences(const std::string& line) {
    std::size_t count = 0;
    for (std::size_t i = 0; i + 1 < line.size(); i++) {
        if (line[i] != '\\') continue;
        char next = line[i + 1];
        if (next == 'x' && i + 3 < line.size() &&
            std::isxdigit((unsigned char)line[i + 2]) && std::isxdigit((unsigned char)line[i + 3])) {
            count++;
            i += 3;
        } else if (next == 'u' && i + 5 < line.size() &&
                   std::isxdigit((unsigned char)line[i + 2]) && std::isxdigit((unsigned char)line[i + 3]) &&
                   std::isxdigit((unsigned char)line[i + 4]) && std::isxdigit((unsigned char)line[i + 5])) {
            count++;
            i += 5;
        }
    }
    return count;
}

// Detects: <non-whitespace> <run of horizontal whitespace >= gapLength> <non-whitespace>
// i.e. content deliberately pushed off-screen after legitimate-looking code.
//
// Exempts the case where the only thing after the gap is a single trailing
// '\' — the standard C/C++ preprocessor line-continuation marker, routinely
// padded with spaces for macro-body column alignment (see this project's own
// tests/test_harness.h for a real example this exemption was written for).
// That idiom is extremely common and benign; without the exemption it is
// indistinguishable from the concealment pattern this detector targets.
std::optional<std::size_t> findConcealmentGap(const std::string& line, std::size_t gapLength) {
    std::size_t i = 0;
    bool sawNonWsBefore = false;
    while (i < line.size()) {
        if (isHorizontalWhitespace(line[i])) {
            std::size_t start = i;
            while (i < line.size() && isHorizontalWhitespace(line[i])) i++;
            std::size_t runLen = i - start;
            std::size_t nonWsAfterCount = 0;
            std::size_t firstNonWsAfter = std::string::npos;
            for (std::size_t j = i; j < line.size(); j++) {
                if ((unsigned char)line[j] > ' ') {
                    nonWsAfterCount++;
                    if (firstNonWsAfter == std::string::npos) firstNonWsAfter = j;
                }
            }
            bool isLineContinuationOnly = nonWsAfterCount == 1 && firstNonWsAfter != std::string::npos &&
                                           line[firstNonWsAfter] == '\\';
            if (sawNonWsBefore && runLen >= gapLength && nonWsAfterCount > 0 && !isLineContinuationOnly) {
                return start;
            }
        } else {
            if ((unsigned char)line[i] > ' ') sawNonWsBefore = true;
            i++;
        }
    }
    return std::nullopt;
}

bool containsAny(const std::string& text, const std::vector<std::string>& needles, std::string* which = nullptr) {
    for (const auto& n : needles) {
        if (text.find(n) != std::string::npos) {
            if (which) *which = n;
            return true;
        }
    }
    return false;
}

} // namespace

namespace {
// A Markdown table row: `| cell | cell |...`. These are routinely padded
// with runs of spaces for column alignment (`| Property | Type |` style),
// which is indistinguishable in shape from the whitespace-concealment
// technique this file's other detector targets — without this exemption,
// documentation in *any* Markdown file that contains a table triggers a
// false "Critical" concealment finding, which is exactly the kind of
// claim-something-is-malicious-when-it-isn't false positive that makes a
// scanner's output untrustworthy. Restricted to files whose extension is
// actually .md/.markdown, so a script file can't get a free pass by
// wrapping a real payload in `|` characters.
bool isMarkdownFile(const std::string& relPath) {
    auto dot = relPath.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = relPath.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return ext == ".md" || ext == ".markdown";
}

bool looksLikeMarkdownTableRow(const std::string& line) {
    std::size_t i = 0;
    while (i < line.size() && isHorizontalWhitespace(line[i])) i++;
    if (i >= line.size() || line[i] != '|') return false;
    std::size_t pipeCount = 0;
    for (char c : line) {
        if (c == '|') ++pipeCount;
    }
    return pipeCount >= 2;
}
} // namespace

std::vector<Finding> scanTextHeuristics(const std::string& relPath, const std::string& content,
                                         const ScanThresholds& thresholds) {
    std::vector<Finding> findings;
    auto lines = splitLines(content);
    const bool markdownTablesExempt = isMarkdownFile(relPath);

    for (std::size_t idx = 0; idx < lines.size(); idx++) {
        const std::string& line = lines[idx];
        std::size_t lineNo = idx + 1;
        const bool skipConcealmentCheck = markdownTablesExempt && looksLikeMarkdownTableRow(line);

        if (line.size() > thresholds.oversizedLineLength) {
            findings.push_back(makeFinding(
                "core.oversized_line", "Oversized line", RuleType::Structural, Severity::Low,
                Confidence::Low,
                "Line length (" + std::to_string(line.size()) + ") exceeds " +
                    std::to_string(thresholds.oversizedLineLength) + " characters.",
                relPath, lineNo, line.substr(0, 80), {"oversized-line", "concealment-candidate"}));
        }

        if (auto gap = skipConcealmentCheck ? std::nullopt
                                             : findConcealmentGap(line, thresholds.concealmentGapLength)) {
            std::string evidence = line.substr(0, std::min(line.size(), *gap + 20));
            findings.push_back(makeFinding(
                "core.concealment_whitespace_gap", "Whitespace concealment gap", RuleType::Structural,
                Severity::Critical, Confidence::Medium,
                "Content follows a run of " + std::to_string(thresholds.concealmentGapLength) +
                    "+ whitespace characters mid-line, a technique used to push payloads past the "
                    "visible viewport in diffs and editors.",
                relPath, lineNo, evidence, {"concealment", "whitespace-injection"}));
        }

        std::size_t escapes = countEscapeSequences(line);
        if (escapes >= thresholds.escapeDensityMinCount) {
            findings.push_back(makeFinding(
                "core.escape_density", "High escape-sequence density", RuleType::Behavior, Severity::Medium,
                Confidence::Medium,
                std::to_string(escapes) + " \\xNN/\\uNNNN escape sequences on one line.",
                relPath, lineNo, line.substr(0, 80), {"obfuscation", "escape-density"}));
        }

        std::size_t longest = longestNonWhitespaceRun(line);
        if (longest >= thresholds.longTokenLength && !looksLikeUrl(longestNonWhitespaceRunText(line))) {
            findings.push_back(makeFinding(
                "core.long_token", "Unbroken long token", RuleType::Behavior, Severity::Low, Confidence::Low,
                "Unbroken non-whitespace run of " + std::to_string(longest) +
                    " characters, consistent with encoded payload data.",
                relPath, lineNo, line.substr(0, 80), {"obfuscation", "encoded-payload"}));
        }

        if (line.size() >= thresholds.highEntropyMinLineLength) {
            std::size_t whitespaceChars = static_cast<std::size_t>(
                std::count_if(line.begin(), line.end(), [](unsigned char c) { return c == ' ' || c == '\t'; }));
            double whitespaceRatio = static_cast<double>(whitespaceChars) / static_cast<double>(line.size());
            if (whitespaceRatio <= thresholds.highEntropyMaxWhitespaceRatio) {
                double e = shannonEntropyBits(reinterpret_cast<const std::uint8_t*>(line.data()), line.size());
                if (e >= thresholds.highEntropyThreshold) {
                    std::ostringstream desc;
                    desc << "Line entropy " << e << " bits/char over " << line.size() << " characters.";
                    findings.push_back(makeFinding(
                        "core.high_entropy_line", "High-entropy line", RuleType::Behavior, Severity::Low,
                        Confidence::Low, desc.str(), relPath, lineNo, line.substr(0, 80),
                        {"entropy", "obfuscation-candidate"}));
                }
            }
        }

        if (line.find("constructor.constructor") != std::string::npos) {
            findings.push_back(makeFinding(
                "core.constructor_chain", "Constructor-chain primitive access", RuleType::Behavior,
                Severity::Medium, Confidence::Medium,
                "`constructor.constructor` reaches the Function primitive, a common eval-avoidance "
                "technique for dynamic code execution.",
                relPath, lineNo, line.substr(0, 80), {"exec-sink", "constructor-abuse"}));
        }
    }

    static const std::vector<std::string> execSinks = {
        "eval(", "Function(", "new Function(", " exec(", "execSync(", "spawn(", "spawnSync(",
        "child_process",
    };
    static const std::vector<std::string> networkIndicators = {
        "fetch(", "http.request", "https.request", "XMLHttpRequest", "require('http')",
        "require(\"http\")", "require('https')", "require(\"https\")", "require('net')",
        "require(\"net\")", "new WebSocket(", "axios.",
    };
    static const std::vector<std::string> indirectRequire = {
        "global['r']", "global[\"r\"]", "global.r =", "[\"require\"]", "['require']",
    };

    std::string execHit, netHit, reqHit;
    bool hasExec = containsAny(content, execSinks, &execHit);
    bool hasNet = containsAny(content, networkIndicators, &netHit);
    bool hasIndirectRequire = containsAny(content, indirectRequire, &reqHit);

    if (hasExec && hasNet) {
        findings.push_back(makeFinding(
            "core.network_exec_combo", "Network + dynamic execution combination", RuleType::Behavior,
            Severity::High, Confidence::Medium,
            "File contains both a network capability (" + netHit + ") and a dynamic execution sink (" +
                execHit + "). Individually common; together consistent with runtime-fetched payload "
                "execution.",
            relPath, std::nullopt, netHit + " ... " + execHit, {"network", "exec-sink", "correlation"}));
    }

    if (hasIndirectRequire) {
        findings.push_back(makeFinding(
            "core.indirect_require", "Indirect require() access", RuleType::Behavior, Severity::Medium,
            Confidence::Low,
            "Module system accessed indirectly via a global/bracket-notation alias rather than a "
            "literal require() call, a common static-analysis evasion technique.",
            relPath, std::nullopt, reqHit, {"evasion", "indirect-require"}));
    }

    return findings;
}

// Credential-shaped content is never auto-remediated (Severity::High, not
// Critical+Confirmed — see response::buildPlan eligibility) and evidence is
// always passed through redactSecrets() first: a finding whose entire reason
// for existing is "secret material was found" must still be safe to print.
//
// A placeholder filter runs before any finding is emitted: documentation and
// `.env.example` files routinely contain token-shaped strings like
// "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" specifically so a developer knows
// what to paste where, and without this filter every one of those would be a
// false positive.
std::vector<Finding> scanCredentialExposure(const std::string& relPath, const std::string& content) {
    std::vector<Finding> findings;

    // Deliberately no per-package allowlist here (there is no way to know
    // every module that might contain a doc-example credential) — these
    // checks target the *shape* of an example/non-secret value, which
    // applies equally regardless of which package the text came from.
    auto looksPlaceholder = [](std::string value, const std::string& kind) {
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        static const std::vector<std::string> placeholderWords = {
            "example", "placeholder", "changeme", "dummy", "sample", "your_token", "your-secret", "xxxx",
        };
        for (const auto& word : placeholderWords) {
            if (value.find(word) != std::string::npos) return true;
        }
        // A low-variety value ("xxxxxxxx...", "0000...", "aaaa...") is a
        // template/masked placeholder, not real secret material — real
        // tokens are high-entropy by construction.
        std::set<char> distinctChars;
        for (char c : value) {
            if (std::isalnum(static_cast<unsigned char>(c))) distinctChars.insert(c);
        }
        if (distinctChars.size() <= 3) return true;

        // Common documentation-example conventions ("someuser", "yourApiKey",
        // "DBHost", "somepassword@somehost" style values) — a generic prefix
        // check plus a small set of standalone generic tokens, rather than
        // trying to enumerate every package's own made-up example username.
        for (const char* prefix : {"some", "your", "my"}) {
            std::size_t prefixLen = std::strlen(prefix);
            if (value.size() > prefixLen && value.compare(0, prefixLen, prefix) == 0) {
                bool restIsAlpha = std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefixLen), value.end(),
                                               [](unsigned char c) { return std::isalpha(c) != 0; });
                if (restIsAlpha) return true;
            }
        }
        static const std::set<std::string> genericTokens = {
            "user", "username", "password", "passwd", "pass", "host", "hostname", "database",
            "dbname", "dbuser", "dbhost", "dbpass", "table", "admin", "root", "test", "demo",
            "foo", "bar", "baz", "localhost", "secret", "token", "key",
        };
        if (genericTokens.count(value) > 0) return true;

        // The generic "key=value"/"key: value" pattern (as opposed to a
        // fixed-prefix token shape like gh_/AKIA/sk-) cannot itself tell a
        // real secret literal apart from a bare identifier or property-access
        // chain being assigned — `api_key: getOption(...)`,
        // `url.password = someVar`, and `currentPassword: e.target.value`
        // (a completely ordinary React form handler) all match the same
        // shape as `API_KEY=aB3xY9k2`. Real secret material is overwhelmingly
        // high-entropy (mixed letters and digits); a value that's purely
        // alphabetic, underscores, and dots (property-access chains like
        // `e.target.value` or `localStorage.getItem` — the latter reachable
        // here because the regex's own function-call guard is itself
        // defeatable by backtracking into a shorter match, so this
        // post-filter is the actual backstop for that shape too), with no
        // digits at all, reads far more like source code than a credential —
        // and this only narrows the generic pattern, not the fixed-prefix
        // token patterns (github/aws/stripe/...), which don't have this
        // ambiguity in the first place.
        if (kind == "credential-value") {
            bool hasDigit = std::any_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
            bool isIdentifierShaped = std::all_of(value.begin(), value.end(), [](unsigned char c) {
                return std::isalpha(c) || c == '_' || c == '.';
            });
            if (!hasDigit && isIdentifierShaped) return true;
        }
        return false;
    };

    for (const auto& match : detectSecretMatches(content)) {
        if (looksPlaceholder(match.value, match.kind)) continue;
        std::size_t lineStart = content.rfind('\n', match.position);
        lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
        std::size_t lineEnd = content.find('\n', match.position);
        if (lineEnd == std::string::npos) lineEnd = content.size();
        std::size_t lineNo = 1 + static_cast<std::size_t>(
            std::count(content.begin(), content.begin() + static_cast<std::ptrdiff_t>(match.position), '\n'));
        findings.push_back(makeFinding(
            "core.credential_exposure", "Credential-shaped content in repository file", RuleType::Behavior,
            Severity::High, Confidence::Medium,
            "File content matches a known credential/token pattern (" + match.kind +
                "). This is reviewed, never auto-quarantined, and the reported evidence is redacted.",
            relPath, lineNo, redactSecrets(content.substr(lineStart, lineEnd - lineStart)),
            {"credential-exposure", "secret", "review-only", match.kind}));
    }

    if (findings.empty()) {
        static const std::vector<std::string> credentialFileNames = {
            "id_rsa", "id_ecdsa", "id_ed25519", ".npmrc", ".git-credentials", ".pgpass",
        };
        std::string base = pathToUtf8(fs::path(relPath).filename());
        for (const auto& name : credentialFileNames) {
            if (base == name) {
                findings.push_back(makeFinding(
                    "core.credential_file_present", "Credential-shaped filename in repository",
                    RuleType::Behavior, Severity::Medium, Confidence::Low,
                    "File name (" + name + ") is conventionally used to store credentials. No matching "
                    "secret pattern was found in its content, but committing this file is reviewed "
                    "regardless.",
                    relPath, std::nullopt, base, {"credential-exposure", "review-only"}));
                break;
            }
        }
    }

    return findings;
}

namespace {

// Shallow structural sanity checks beyond a 4-byte magic match — a correct
// header does not make the rest of the file safe. Deliberately limited to
// fixed-offset, fixed-size header fields (no variable-length/untrusted-
// length-driven parsing loops): this is exactly the kind of complex parsing
// task that tends to produce its own vulnerabilities, so Abyss does not
// attempt a full WOFF2/PE/ZIP parser here. ZIP central-directory validation
// is deliberately NOT implemented for the same reason — see
// README.md.
struct StructuralIssue {
    std::string ruleId;
    std::string name;
    Severity severity;
    Confidence confidence;
    std::string description;
    std::string evidence;
};

std::uint32_t readU32BE(const std::uint8_t* d) {
    return ((std::uint32_t)d[0] << 24) | ((std::uint32_t)d[1] << 16) | ((std::uint32_t)d[2] << 8) | d[3];
}
std::uint16_t readU16BE(const std::uint8_t* d) {
    return (std::uint16_t)(((std::uint16_t)d[0] << 8) | d[1]);
}
std::uint16_t readU16LE(const std::uint8_t* d) {
    return (std::uint16_t)(d[0] | ((std::uint16_t)d[1] << 8));
}

// WOFF2 fixed header: signature(4) flavor(4) length(4,BE) numTables(2,BE) ...
std::optional<StructuralIssue> validateWoff2(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 16) {
        return StructuralIssue{"core.woff2_structural_anomaly", "WOFF2 header truncated", Severity::Medium,
                                Confidence::Low,
                                "WOFF2 magic present but the file is smaller than the fixed 16-byte header.", ""};
    }
    std::uint32_t declaredLength = readU32BE(&bytes[8]);
    std::uint16_t numTables = readU16BE(&bytes[12]);

    if (numTables == 0 || numTables > 100) {
        return StructuralIssue{
            "core.woff2_structural_anomaly", "WOFF2 implausible table count", Severity::Medium, Confidence::Low,
            "Declared numTables=" + std::to_string(numTables) +
                " is outside the plausible range for a real font (1-100).",
            ""};
    }

    if ((std::size_t)declaredLength == bytes.size()) return std::nullopt;

    if (bytes.size() > (std::size_t)declaredLength + 8) {
        // The header validates and declares a length — but the file keeps
        // going past it. This is exactly "correct header followed by
        // invalid/script content": a real font used to carry an appended
        // payload, rather than a font-shaped file with no real font at all.
        std::size_t trailingLen = bytes.size() - declaredLength;
        std::size_t sampleLen = std::min<std::size_t>(trailingLen, 4096);
        std::string trailing(reinterpret_cast<const char*>(&bytes[declaredLength]), sampleLen);
        std::size_t printable = 0;
        for (unsigned char c : trailing) {
            if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') printable++;
        }
        double ratio = sampleLen == 0 ? 0.0 : (double)printable / (double)sampleLen;
        static const std::vector<std::string> markers = {"require(", "function(", "eval(", "module.exports", "=>"};
        std::string which;
        bool scriptLike = ratio > 0.85 && containsAny(trailing, markers, &which);
        if (scriptLike) {
            return StructuralIssue{
                "core.woff2_trailing_payload", "Script content appended after a structurally valid WOFF2 payload",
                Severity::Critical, Confidence::High,
                "The WOFF2 header validates and declares length=" + std::to_string(declaredLength) +
                    " bytes, but the file continues for " + std::to_string(trailingLen) +
                    " more bytes that are " + std::to_string((int)(ratio * 100)) +
                    "% printable ASCII containing script markers (e.g. '" + which +
                    "'). A structurally valid font header does not make the whole file safe.",
                trailing.substr(0, 80)};
        }
        return StructuralIssue{
            "core.woff2_structural_anomaly", "WOFF2 declared length does not match file size", Severity::Medium,
            Confidence::Low,
            "WOFF2 header declares length=" + std::to_string(declaredLength) + " but the file is " +
                std::to_string(bytes.size()) + " bytes.",
            ""};
    }
    return StructuralIssue{
        "core.woff2_structural_anomaly", "WOFF2 declared length exceeds file size", Severity::Low, Confidence::Low,
        "WOFF2 header declares length=" + std::to_string(declaredLength) + " but the file is only " +
            std::to_string(bytes.size()) + " bytes (consistent with a truncated read, capped at maxFileBytes).",
        ""};
}

// PE fixed header fields: DOS header e_lfanew(@0x3C) -> 'PE\0\0' signature ->
// IMAGE_FILE_HEADER{Machine(2) NumberOfSections(2) ...}.
std::optional<StructuralIssue> validatePe(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 0x40) {
        return StructuralIssue{"core.pe_structural_anomaly", "PE DOS header truncated", Severity::Medium,
                                Confidence::Low,
                                "'MZ' present but the file is smaller than the 64-byte DOS header.", ""};
    }
    std::uint32_t peOffset = (std::uint32_t)bytes[0x3C] | ((std::uint32_t)bytes[0x3D] << 8) |
                              ((std::uint32_t)bytes[0x3E] << 16) | ((std::uint32_t)bytes[0x3F] << 24);
    if ((std::size_t)peOffset + 24 > bytes.size()) {
        return StructuralIssue{
            "core.pe_structural_anomaly", "PE header offset leaves no room for a file header", Severity::Medium,
            Confidence::Low,
            "e_lfanew points to offset " + std::to_string(peOffset) + " but the file is only " +
                std::to_string(bytes.size()) + " bytes.",
            ""};
    }
    if (!(bytes[peOffset] == 'P' && bytes[peOffset + 1] == 'E' && bytes[peOffset + 2] == 0 &&
          bytes[peOffset + 3] == 0)) {
        return StructuralIssue{"core.pe_structural_anomaly", "PE signature missing at declared offset",
                                Severity::Medium, Confidence::Low,
                                "e_lfanew points to offset " + std::to_string(peOffset) +
                                    " but no 'PE\\0\\0' signature is present there.",
                                ""};
    }
    std::uint16_t numberOfSections = readU16LE(&bytes[peOffset + 4 + 2]);
    if (numberOfSections == 0 || numberOfSections > 96) {
        return StructuralIssue{
            "core.pe_structural_anomaly", "PE implausible section count", Severity::Medium, Confidence::Low,
            "Declared NumberOfSections=" + std::to_string(numberOfSections) +
                " is outside the plausible range (1-96, per the PE format's own practical limit).",
            ""};
    }
    return std::nullopt;
}

} // namespace

std::vector<Finding> scanBinaryExtensionMasquerade(const std::string& relPath,
                                                    const std::string& extensionLower,
                                                    const std::vector<std::uint8_t>& bytes) {
    std::vector<Finding> findings;
    auto expected = expectedKindsForExtension(extensionLower);
    if (expected.empty()) return findings;

    FileKind detected = detectMagic(bytes.data(), bytes.size());
    bool matches = std::find(expected.begin(), expected.end(), detected) != expected.end();

    if (matches) {
        std::optional<StructuralIssue> issue;
        if (detected == FileKind::Woff2) issue = validateWoff2(bytes);
        else if (detected == FileKind::Pe) issue = validatePe(bytes);
        if (issue) {
            findings.push_back(makeFinding(issue->ruleId, issue->name, RuleType::Structural, issue->severity,
                                            issue->confidence, issue->description, relPath, std::nullopt,
                                            issue->evidence, {"structural", "shallow-validation"}));
        }
        return findings;
    }

    std::size_t sampleLen = std::min<std::size_t>(bytes.size(), 4096);
    std::size_t printable = 0;
    for (std::size_t i = 0; i < sampleLen; i++) {
        std::uint8_t b = bytes[i];
        if ((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t') printable++;
    }
    double printableRatio = sampleLen == 0 ? 0.0 : (double)printable / (double)sampleLen;

    std::string sample(reinterpret_cast<const char*>(bytes.data()), sampleLen);
    static const std::vector<std::string> scriptMarkers = {
        "require(", "function(", "function (", "eval(", "module.exports", "=>", "import ",
        "var ", "const ", "let ",
    };
    std::string marker;
    bool looksLikeScript = printableRatio > 0.85 && containsAny(sample, scriptMarkers, &marker);

    if (looksLikeScript) {
        findings.push_back(makeFinding(
            "core.binary_extension_masquerade", "Binary-extension masquerade (script content)",
            RuleType::Structural, Severity::Critical, Confidence::High,
            "File has extension '" + extensionLower + "' (expected " + toString(expected.front()) +
                ") but its magic bytes don't match and its content is " +
                std::to_string((int)(printableRatio * 100)) +
                "% printable ASCII containing script markers (e.g. '" + marker +
                "'). Consistent with a script disguised as a binary asset (fake-font pattern).",
            relPath, std::nullopt, sample.substr(0, 80), {"masquerade", "fake-asset", "structural"}));
    } else {
        findings.push_back(makeFinding(
            "core.magic_mismatch", "File extension / magic-byte mismatch", RuleType::Structural,
            Severity::Medium, Confidence::Low,
            "File has extension '" + extensionLower + "' (expected " + toString(expected.front()) +
                ") but its magic bytes indicate " + toString(detected) + ".",
            relPath, std::nullopt, "", {"magic-mismatch", "structural"}));
    }
    return findings;
}

namespace {

struct DecodedCp {
    std::uint32_t codepoint;
    std::size_t byteOffset;
};

std::vector<DecodedCp> decodeUtf8(const std::string& content) {
    std::vector<DecodedCp> out;
    std::size_t i = 0;
    const auto* d = reinterpret_cast<const unsigned char*>(content.data());
    std::size_t n = content.size();
    while (i < n) {
        unsigned char c = d[i];
        std::uint32_t cp = 0;
        std::size_t len = 1;
        if ((c & 0x80) == 0) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0 && i + 1 < n) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0 && i + 2 < n) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0 && i + 3 < n) { cp = c & 0x07; len = 4; }
        else { i++; continue; } // invalid lead byte, skip

        bool valid = true;
        for (std::size_t k = 1; k < len; k++) {
            unsigned char cont = d[i + k];
            if ((cont & 0xC0) != 0x80) { valid = false; break; }
            cp = (cp << 6) | (cont & 0x3F);
        }
        if (!valid) { i++; continue; }
        out.push_back({cp, i});
        i += len;
    }
    return out;
}

bool isBidiControl(std::uint32_t cp) {
    return (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
}

bool isZeroWidthOrVariationOrPua(std::uint32_t cp) {
    if (cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0x2060) return true; // zero-width
    if (cp >= 0xFE00 && cp <= 0xFE0F) return true; // variation selectors
    if (cp >= 0xE000 && cp <= 0xF8FF) return true; // private use area
    return false;
}

// True for codepoints that legitimately serve as the base character of a
// standard emoji sequence -- a variation selector (U+FE0F/FE0E) or ZWJ
// (U+200D) immediately following one of these is participating in an
// ordinary, human-visible emoji (an emoji picker, a reaction list, a
// decorative icon in JSX) rather than being smuggled into plain text to
// steganographically encode data or defeat string matching. This is not a
// blanket exemption: zero-width space/non-joiner (U+200B/U+200C) and a
// standalone word-joiner (U+2060), and any variation selector/ZWJ that is
// NOT adjacent to an emoji base, are still always flagged -- those have no
// legitimate use in typical source/config text and are exactly the
// concealment shape this detector exists to catch.
bool isLikelyEmojiBase(std::uint32_t cp) {
    if (cp >= 0x2600 && cp <= 0x27BF) return true;    // Misc Symbols + Dingbats (❤ ✌ ☝ ✍ ☺ …)
    if (cp >= 0x2B00 && cp <= 0x2BFF) return true;    // Misc Symbols and Arrows (⭐ ➡ …)
    if (cp >= 0x2190 && cp <= 0x21FF) return true;    // Arrows (↔ used with VS16 in some emoji)
    if (cp >= 0x1F1E6 && cp <= 0x1F1FF) return true;  // regional indicators (flag emoji)
    if (cp >= 0x1F300 && cp <= 0x1FAFF) return true;  // Misc Symbols/Pictographs, Emoticons, Transport, …
    if (cp == 0x23 || cp == 0x2A || (cp >= 0x30 && cp <= 0x39)) return true; // keycap bases # * 0-9
    return false;
}

} // namespace

std::vector<Finding> scanInvisibleUnicode(const std::string& relPath, const std::string& content) {
    std::vector<Finding> findings;
    auto codepoints = decodeUtf8(content);

    auto lineOf = [&](std::size_t byteOffset) -> std::size_t {
        return 1 + (std::size_t)std::count(content.begin(), content.begin() + (long)byteOffset, '\n');
    };

    std::size_t bidiCount = 0, concealCount = 0;
    std::size_t firstBidiOffset = 0, firstConcealOffset = 0;

    for (std::size_t idx = 0; idx < codepoints.size(); idx++) {
        auto [cp, offset] = codepoints[idx];
        if (cp == 0xFEFF && offset == 0) continue; // legitimate BOM
        if (isBidiControl(cp)) {
            if (bidiCount == 0) firstBidiOffset = offset;
            bidiCount++;
        } else if (isZeroWidthOrVariationOrPua(cp)) {
            const bool isEmojiSequenceJoiner = (cp == 0x200D || (cp >= 0xFE00 && cp <= 0xFE0F)) &&
                                               idx > 0 && isLikelyEmojiBase(codepoints[idx - 1].codepoint);
            if (!isEmojiSequenceJoiner) {
                if (concealCount == 0) firstConcealOffset = offset;
                concealCount++;
            }
        }
    }

    if (bidiCount >= 1) {
        findings.push_back(makeFinding(
            "core.invisible_unicode_bidi", "Unicode bidirectional control characters", RuleType::Structural,
            Severity::High, Confidence::Medium,
            std::to_string(bidiCount) + " Unicode bidi-override control character(s) found. These can "
            "reorder how code is *displayed* without changing how it *executes*, hiding malicious "
            "logic from visual review.",
            relPath, lineOf(firstBidiOffset), "", {"concealment", "invisible-unicode", "bidi"}));
    }
    if (concealCount >= 2) {
        findings.push_back(makeFinding(
            "core.invisible_unicode_concealment", "Zero-width / variation-selector / PUA characters",
            RuleType::Structural, Severity::Medium,
            concealCount >= 5 ? Confidence::Medium : Confidence::Low,
            std::to_string(concealCount) + " zero-width, variation-selector, or private-use Unicode "
            "code points found, which are invisible in most editors and can be used to steganographically "
            "encode data or defeat literal string matching.",
            relPath, lineOf(firstConcealOffset), "", {"concealment", "invisible-unicode"}));
    }

    return findings;
}

// ---------------------------------------------------------------------------
// Repository discovery
// ---------------------------------------------------------------------------

namespace {

std::string normalizeSlashes(const std::string& s) {
    std::string r = s;
    std::replace(r.begin(), r.end(), '\\', '/');
    return r;
}

// pathStartsWith() and isReparsePoint() now live in abyss::core (see
// core.h) — rules::verifyRuleManifest() needs the same containment logic
// for manifest-path validation, so it's shared rather than duplicated.

} // namespace

RepositoryDiscovery discoverRepository(const std::string& root) {
    RepositoryDiscovery result;
    fs::path rootPath(root);
    std::error_code ec;
    if (!fs::exists(rootPath, ec)) return result;

    fs::path canonicalRoot = fs::weakly_canonical(rootPath, ec);
    if (ec) { canonicalRoot = fs::absolute(rootPath); ec.clear(); }

    if (fs::exists(rootPath / ".git", ec)) result.isGitRepository = true;
    ec.clear();

    fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator endIt;
    if (ec) {
        result.directoryErrors.push_back(root + ": " + ec.message());
        return result;
    }

    while (it != endIt) {
        const auto p = it->path();

        std::error_code symEc;
        auto symStatus = it->symlink_status(symEc);
        bool isSym = (!symEc && fs::is_symlink(symStatus)) || isReparsePoint(p);

        if (isSym) {
            // Any symlink/junction/reparse point whose resolved target
            // falls outside the requested scan root is refused entirely —
            // never read as a file, never descended into as a directory —
            // and recorded so coverage reporting stays honest about it.
            std::error_code resolveEc;
            fs::path target = fs::weakly_canonical(p, resolveEc);
            bool within = !resolveEc && pathStartsWith(target, canonicalRoot);
            if (resolveEc || !within) {
                result.symlinkEscapesSkipped.push_back(normalizeSlashes(pathToUtf8(p)));
                it.disable_recursion_pending();
                std::error_code incEc;
                it.increment(incEc);
                if (incEc) { result.directoryErrors.push_back(pathToUtf8(p) + ": " + incEc.message()); break; }
                continue;
            }
            // In-root symlink target: still never followed as a directory
            // below (conservative by design — see README.md).
        }

        std::error_code typeEc;
        bool isDir = it->is_directory(typeEc);
        if (typeEc) {
            result.directoryErrors.push_back(pathToUtf8(p) + ": " + typeEc.message());
            std::error_code incEc;
            it.increment(incEc);
            if (incEc) break;
            continue;
        }

        if (isDir) {
            if (p.filename() == ".git") {
                result.isGitRepository = true;
                it.disable_recursion_pending(); // git internals are binary object storage; see src/git
            } else if (p.filename() == "abyss-results") {
                // Abyss's own output (see main.cpp's reportTo/writeReportFile),
                // written inside the scan root itself. Scanning it as
                // ordinary repository content creates a feedback loop: a
                // prior report's own redacted evidence lines ("Evidence:
                // DATABASE_URL=...[REDACTED]...") are text that itself
                // matches the credential/exec-combo detectors, so a repeat
                // scan starts reporting findings about Abyss's own report
                // file instead of about the project.
                it.disable_recursion_pending();
            } else if (isSym) {
                it.disable_recursion_pending(); // never descend into a directory symlink/junction, even in-root
            }
            std::error_code incEc;
            it.increment(incEc);
            if (incEc) { result.directoryErrors.push_back(pathToUtf8(p) + ": " + incEc.message()); break; }
            continue;
        }

        std::error_code fileEc;
        bool isRegular = it->is_regular_file(fileEc);
        if (fileEc || !isRegular) {
            std::error_code incEc;
            it.increment(incEc);
            if (incEc) break;
            continue;
        }

        DiscoveredFile df;
        df.absolutePath = pathToUtf8(p);
        std::error_code relEc;
        auto rel = fs::relative(p, rootPath, relEc);
        df.relativePath = normalizeSlashes(relEc ? pathToUtf8(p) : pathToUtf8(rel));
        df.filename = pathToUtf8(p.filename());
        std::string ext = pathToUtf8(p.extension());
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        df.extensionLower = ext;
        df.isSymlink = isSym;
        result.files.push_back(std::move(df));

        std::error_code incEc;
        it.increment(incEc);
        if (incEc) { result.directoryErrors.push_back(pathToUtf8(p) + ": " + incEc.message()); break; }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

namespace {

const std::set<std::string>& textLikeExtensions() {
    static const std::set<std::string> exts = {
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".json", ".jsonc",
        ".py", ".rb", ".php", ".sh", ".bat", ".cmd", ".ps1", ".yml", ".yaml", ".toml",
        ".html", ".htm", ".css", ".scss", ".md", ".txt", ".cfg", ".ini", ".xml", ".vue",
        ".svelte", ".gitignore", ".env", ".code-workspace",
    };
    return exts;
}

// Deliberately ASCII-strict: bytes >= 0x80 are NOT counted as printable here.
// A looser rule (e.g. "any high-bit byte is probably UTF-8") makes this
// trivially satisfied by arbitrary binary data, since roughly half of all
// byte values are >= 0x80 — that previously caused legitimate binary
// fixtures (e.g. a real WOFF2) to be misclassified as text. Files with
// known text extensions are still always treated as text regardless of
// this ratio (see textLikeExtensions()); this heuristic only gates the
// fallback case of extension-less/unrecognized files.
double printableRatio(const std::vector<std::uint8_t>& bytes) {
    std::size_t sample = std::min<std::size_t>(bytes.size(), 4096);
    if (sample == 0) return 0.0;
    std::size_t printable = 0;
    for (std::size_t i = 0; i < sample; i++) {
        std::uint8_t b = bytes[i];
        if ((b >= 0x09 && b <= 0x0D) || (b >= 0x20 && b <= 0x7E)) printable++;
    }
    return (double)printable / (double)sample;
}

Confidence bumpConfidence(Confidence c) {
    switch (c) {
        case Confidence::Unknown: return Confidence::Unknown;
        case Confidence::Low: return Confidence::Medium;
        case Confidence::Medium: return Confidence::High;
        case Confidence::High: return Confidence::High;
        case Confidence::Confirmed: return Confidence::Confirmed;
    }
    return c;
}

} // namespace

namespace {

// The worst case per file in flight is bounded by ScanOptions::maxFileBytes
// (default 64MB): the raw bytes, plus a full second copy when
// bytesToStringLossy() converts it to text, plus working space for
// regex/entropy analysis on that content — budgeted here at roughly 3x the
// per-file cap, rounded up for thread-stack and general overhead. This is a
// worst case, not a typical one: almost no file in a real project is
// anywhere near 64MB, so in practice per-thread usage is far smaller.
constexpr std::size_t kAssumedPerThreadBudgetBytes = 200ull * 1024 * 1024;

// Caps the thread count by *currently available* physical memory, not just
// CPU core count — a machine with 8 cores but 8GB total RAM (and a browser
// and an IDE already open) can have very little actually free, and
// launching 8 workers each capable of holding a 64MB file plus its decoded
// copy in memory at once is exactly the kind of thing that starts thrashing
// a memory-constrained machine. Returns SIZE_MAX (i.e. "no additional
// constraint") when available memory can't be queried, or on non-Windows
// builds, rather than guessing.
std::size_t maxThreadsForAvailableMemory() {
#if defined(_WIN32)
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status)) return SIZE_MAX;
    std::size_t byBudget = static_cast<std::size_t>(status.ullAvailPhys / kAssumedPerThreadBudgetBytes);
    return std::max<std::size_t>(1, byBudget);
#else
    return SIZE_MAX;
#endif
}

// Coverage counters accumulated by one worker while analyzing its share of
// files; merged into the real ScanCoverage after all workers finish. Kept
// separate from ScanCoverage itself so that struct's public fields never
// need to be atomics for callers outside this function.
struct CoverageDelta {
    std::size_t filesAnalyzed = 0;
    std::size_t filesTruncated = 0;
    std::size_t filesUnreadable = 0;
    std::size_t filesChangedDuringScan = 0;
};

// The complete analysis for one already-discovered file: TOCTOU check, every
// native detector, rule-engine evaluation, and execution-surface confidence
// bump. Pure with respect to its arguments — no shared mutable state is
// touched — which is exactly what makes calling this concurrently from
// multiple threads over disjoint files safe (see scanRepository below).
void analyzeOneFile(const DiscoveredFile& file, const rules::RuleEngine& ruleEngine,
                    const preflight::ExecutionSurfaceRegistry& esr, const ScanOptions& options,
                    std::vector<Finding>& outFindings, CoverageDelta& coverage) {
    // TOCTOU guard: capture size + mtime before and after the read. A
    // mismatch means the file was written to (or replaced) concurrently
    // with the scan, so the bytes just analyzed may not correspond to
    // any single consistent version of it — coverage is marked
    // incomplete for the whole run rather than silently trusting a
    // possibly-torn read.
    std::error_code preEc, postEc;
    auto preSize = fs::file_size(file.absolutePath, preEc);
    auto preTime = fs::last_write_time(file.absolutePath, preEc);

    std::vector<std::uint8_t> bytes;
    bool truncated = false;
    if (!readFileBytes(file.absolutePath, bytes, truncated, options.maxFileBytes)) {
        coverage.filesUnreadable++;
        return;
    }
    coverage.filesAnalyzed++;
    if (truncated) coverage.filesTruncated++;

    auto postSize = fs::file_size(file.absolutePath, postEc);
    auto postTime = fs::last_write_time(file.absolutePath, postEc);
    bool statAvailable = !preEc && !postEc;
    if (statAvailable && (preSize != postSize || preTime != postTime)) {
        coverage.filesChangedDuringScan++;
    }

    std::vector<Finding> fileFindings;

    auto masq = scanBinaryExtensionMasquerade(file.relativePath, file.extensionLower, bytes);
    fileFindings.insert(fileFindings.end(), masq.begin(), masq.end());

    bool treatAsText = textLikeExtensions().count(file.extensionLower) > 0 || printableRatio(bytes) > 0.85;
    std::string content;
    if (treatAsText) {
        content = bytesToStringLossy(bytes);
        auto textFindings = scanTextHeuristics(file.relativePath, content, options.thresholds);
        fileFindings.insert(fileFindings.end(), textFindings.begin(), textFindings.end());
        auto credentialFindings = scanCredentialExposure(file.relativePath, content);
        fileFindings.insert(fileFindings.end(), credentialFindings.begin(), credentialFindings.end());
        auto unicodeFindings = scanInvisibleUnicode(file.relativePath, content);
        fileFindings.insert(fileFindings.end(), unicodeFindings.begin(), unicodeFindings.end());
        auto obfuscationFindings = scanObfuscationIndicators(file.relativePath, content);
        fileFindings.insert(fileFindings.end(), obfuscationFindings.begin(), obfuscationFindings.end());
    } else {
        content = bytesToStringLossy(bytes); // IOC substrings still meaningful in near-text binaries
    }

    std::string sha256Lower = options.computeHashes ? crypto::sha256Hex(bytes) : std::string{};
    auto ruleFindings =
        ruleEngine.evaluateFile(file.relativePath, file.filename, file.extensionLower, content, sha256Lower);
    fileFindings.insert(fileFindings.end(), ruleFindings.begin(), ruleFindings.end());

    auto propagationFindings = git::scanGitPropagationArtifacts(file.relativePath, file.filename,
                                                                  file.extensionLower, content);
    fileFindings.insert(fileFindings.end(), propagationFindings.begin(), propagationFindings.end());

    auto gitignoreFindings = git::scanGitignoreForHiddenArtifacts(file.relativePath, file.filename, content);
    fileFindings.insert(fileFindings.end(), gitignoreFindings.begin(), gitignoreFindings.end());

    if (file.filename == "tasks.json" && file.relativePath.find(".vscode/") != std::string::npos) {
        auto taskFindings = vscode::scanTasksJson(file.relativePath, content);
        fileFindings.insert(fileFindings.end(), taskFindings.begin(), taskFindings.end());
    }
    if (file.extensionLower == ".code-workspace") {
        auto workspaceFindings = vscode::scanCodeWorkspace(file.relativePath, content);
        fileFindings.insert(fileFindings.end(), workspaceFindings.begin(), workspaceFindings.end());
    }

    if (const auto* surface = esr.match(file.filename); surface != nullptr && !fileFindings.empty()) {
        for (auto& f : fileFindings) {
            f.tags.push_back("autoload-context:" + surface->tool);
            f.confidence = bumpConfidence(f.confidence);
            f.description += " [Autoloaded by " + surface->tool + " — " + surface->risk + "]";
        }
    }

    outFindings.insert(outFindings.end(), fileFindings.begin(), fileFindings.end());
}

} // namespace

ScanReport scanRepository(const std::string& root, const rules::RuleEngine& ruleEngine,
                           const preflight::ExecutionSurfaceRegistry& esr, const ScanOptions& options) {
    ScanReport report;
    auto discovery = discoverRepository(root);
    const std::size_t fileCount = discovery.files.size();
    report.coverage.filesDiscovered = fileCount;
    report.coverage.gitDetected = discovery.isGitRepository;
    report.coverage.symlinkEscapesSkipped = discovery.symlinkEscapesSkipped.size();
    report.coverage.directoryErrors = discovery.directoryErrors.size();

    // Per-file analysis (I/O + regex/entropy work) is independent across
    // files — nothing here shares mutable state (RuleEngine::evaluateFile
    // and the ExecutionSurfaceRegistry are const/read-only; every detector
    // is a pure function over its arguments) — so it parallelizes safely
    // over a simple shared work index. Small scans stay single-threaded to
    // avoid thread-creation overhead outweighing the work itself; large
    // ones (a typical node_modules tree is tens of thousands of files, and
    // node_modules is deliberately never skipped — see README.md) are
    // where this matters. The thread count is bounded by three independent
    // things, and the smallest one wins: CPU cores (more worker threads
    // than logical cores means the OS just time-slices them for this
    // CPU-bound work, which tends to cost more in context-switching than it
    // gains), currently available memory (maxThreadsForAvailableMemory() —
    // this is what stops a memory-constrained machine from being pushed
    // into swapping), and a flat ceiling of 15 regardless of how much
    // memory/cores are available, since I/O and diminishing returns limit
    // the benefit of going wider than that for this workload. There is
    // deliberately no minimum thread count: on a machine where available
    // memory or core count is genuinely low, running fewer threads (down to
    // 1) is correct, not a bug to work around — forcing a higher floor
    // regardless of measured resources is exactly how a memory-constrained
    // machine gets pushed into swapping or the OS starts killing processes.
    const unsigned hardwareThreads = std::thread::hardware_concurrency();
    const std::size_t threadCount =
        fileCount < 200 ? 1
                         : std::min<std::size_t>({hardwareThreads == 0 ? 1 : hardwareThreads,
                                                  maxThreadsForAvailableMemory(), std::size_t{15}});

    if (threadCount <= 1) {
        std::vector<Finding> findings;
        CoverageDelta coverage;
        for (const auto& file : discovery.files) {
            analyzeOneFile(file, ruleEngine, esr, options, findings, coverage);
            if (options.onProgress)
                options.onProgress(coverage.filesAnalyzed + coverage.filesUnreadable, fileCount, 1);
        }
        report.findings = std::move(findings);
        report.coverage.filesAnalyzed = coverage.filesAnalyzed;
        report.coverage.filesTruncated = coverage.filesTruncated;
        report.coverage.filesUnreadable = coverage.filesUnreadable;
        report.coverage.filesChangedDuringScan = coverage.filesChangedDuringScan;
        report.coverage.threadsUsed = 1;
        return report;
    }

    std::atomic<std::size_t> nextIndex{0};
    std::atomic<std::size_t> filesHandled{0};
    std::vector<std::vector<Finding>> perThreadFindings(threadCount);
    std::vector<CoverageDelta> perThreadCoverage(threadCount);
    std::vector<std::thread> workers;
    workers.reserve(threadCount);

    for (std::size_t t = 0; t < threadCount; ++t) {
        workers.emplace_back([&, t]() {
            for (;;) {
                std::size_t i = nextIndex.fetch_add(1, std::memory_order_relaxed);
                if (i >= fileCount) break;
                analyzeOneFile(discovery.files[i], ruleEngine, esr, options, perThreadFindings[t],
                               perThreadCoverage[t]);
                std::size_t handled = filesHandled.fetch_add(1, std::memory_order_relaxed) + 1;
                if (options.onProgress) options.onProgress(handled, fileCount, threadCount);
            }
        });
    }
    for (auto& worker : workers) worker.join();

    for (std::size_t t = 0; t < threadCount; ++t) {
        report.findings.insert(report.findings.end(), perThreadFindings[t].begin(), perThreadFindings[t].end());
        report.coverage.filesAnalyzed += perThreadCoverage[t].filesAnalyzed;
        report.coverage.filesTruncated += perThreadCoverage[t].filesTruncated;
        report.coverage.filesUnreadable += perThreadCoverage[t].filesUnreadable;
        report.coverage.filesChangedDuringScan += perThreadCoverage[t].filesChangedDuringScan;
    }
    report.coverage.threadsUsed = threadCount;
    return report;
}

} // namespace abyss::scanner
