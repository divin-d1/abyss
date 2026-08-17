#include "test_harness.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/core.h"
#include "evidence/evidence.h"
#include "scanner/scanner.h"

using namespace abyss;

ABYSS_TEST("json: parses object with comments and trailing commas (JSONC)") {
    std::string text = R"({
        // comment
        "a": 1,
        "b": [1, 2, 3,],
        "c": { "nested": true, }, /* block comment */
    })";
    auto result = parseJson(text);
    ABYSS_CHECK(result.ok);
    ABYSS_CHECK(result.value.isObject());
    ABYSS_CHECK_EQ(result.value.find("a")->asNumber(), 1.0);
    ABYSS_CHECK_EQ(result.value.find("b")->asArray().size(), (std::size_t)3);
    ABYSS_CHECK(result.value.find("c")->find("nested")->asBool());
}

ABYSS_TEST("json: rejects malformed input") {
    auto result = parseJson("{ \"a\": ");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects trailing content after the root value") {
    auto result = parseJson("{\"a\":1} garbage");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: trailing whitespace/comments after root value are still accepted") {
    auto result = parseJson("{\"a\":1}   // trailing comment\n");
    ABYSS_CHECK(result.ok);
}

ABYSS_TEST("json: rejects duplicate object keys") {
    auto result = parseJson(R"({"a":1,"b":2,"a":3})");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects an unterminated block comment instead of consuming to EOF") {
    auto result = parseJson("{\"a\":1} /* never closed");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: enforces maximum nesting depth") {
    std::string text;
    for (int i = 0; i < 1000; i++) text += "[";
    for (int i = 0; i < 1000; i++) text += "]";
    JsonParseLimits limits;
    limits.maxDepth = 32;
    auto result = parseJson(text, limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: enforces maximum node count") {
    std::string text = "[";
    for (int i = 0; i < 10000; i++) text += (i ? ",1" : "1");
    text += "]";
    JsonParseLimits limits;
    limits.maxNodes = 100;
    auto result = parseJson(text, limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: enforces maximum input size") {
    JsonParseLimits limits;
    limits.maxInputBytes = 5; // "{"a":1}" is 7 bytes
    auto result = parseJson("{\"a\":1}", limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects a raw control character inside a string literal") {
    std::string text = std::string("{\"a\":\"x") + '\x01' + "y\"}";
    auto result = parseJson(text);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: accepts an escaped control character inside a string literal") {
    auto result = parseJson("{\"a\":\"x\\u0001y\"}");
    ABYSS_CHECK(result.ok);
}

ABYSS_TEST("json: correctly decodes a valid UTF-16 surrogate pair") {
    // U+1F600 GRINNING FACE = surrogate pair D83D DE00 = UTF-8 F0 9F 98 80
    auto result = parseJson("{\"a\":\"\\uD83D\\uDE00\"}");
    ABYSS_CHECK(result.ok);
    if (result.ok) {
        std::string s = result.value.find("a")->asString();
        ABYSS_CHECK_EQ(s.size(), (std::size_t)4);
        ABYSS_CHECK((unsigned char)s[0] == 0xF0 && (unsigned char)s[1] == 0x9F && (unsigned char)s[2] == 0x98 &&
                    (unsigned char)s[3] == 0x80);
    }
}

ABYSS_TEST("json: rejects a lone high surrogate with no following low surrogate") {
    auto result = parseJson("{\"a\":\"\\uD83D\"}");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects a lone low surrogate") {
    auto result = parseJson("{\"a\":\"\\uDE00\"}");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects a high surrogate followed by a non-surrogate escape") {
    auto result = parseJson("{\"a\":\"\\uD83D\\u0041\"}");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("json: rejects trailing '.' with no fractional digit") {
    ABYSS_CHECK(!parseJson("[1.]").ok);
}

ABYSS_TEST("json: rejects trailing 'e' with no exponent digit") {
    ABYSS_CHECK(!parseJson("[1e]").ok);
    ABYSS_CHECK(!parseJson("[1e+]").ok);
}

ABYSS_TEST("json: rejects a leading zero followed by more digits") {
    ABYSS_CHECK(!parseJson("[01]").ok);
}

ABYSS_TEST("json: accepts a standalone zero and zero-prefixed fraction") {
    ABYSS_CHECK(parseJson("[0]").ok);
    ABYSS_CHECK(parseJson("[0.5]").ok);
}

ABYSS_TEST("json: accepts well-formed negative/exponent numbers") {
    auto r = parseJson("[-12.5e+10, 3E-2, 0]");
    ABYSS_CHECK(r.ok);
}

ABYSS_TEST("block format: enforces maximum input size") {
    BlockParseLimits limits;
    limits.maxInputBytes = 10;
    auto result = parseBlocks("[rule]\nid=x\n", limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("block format: enforces maximum line length") {
    BlockParseLimits limits;
    limits.maxLineLength = 20;
    auto result = parseBlocks("[rule]\nid=" + std::string(100, 'x') + "\n", limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("block format: enforces maximum fields per block") {
    BlockParseLimits limits;
    limits.maxFieldsPerBlock = 3;
    std::string text = "[rule]\n";
    for (int i = 0; i < 10; i++) text += "k" + std::to_string(i) + "=v\n";
    auto result = parseBlocks(text, limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("block format: enforces maximum block count") {
    BlockParseLimits limits;
    limits.maxBlocks = 2;
    std::string text;
    for (int i = 0; i < 10; i++) text += "[rule]\nid=x" + std::to_string(i) + "\n";
    auto result = parseBlocks(text, limits);
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("strict numeric parsing: rejects malformed/NaN-like input, accepts well-formed numbers") {
    ABYSS_CHECK(parseStrictInt("-5").has_value()); // negative IS a valid strict int; callers decide sign policy
    ABYSS_CHECK(!parseStrictInt("5x").has_value());
    ABYSS_CHECK(!parseStrictInt("").has_value());
    ABYSS_CHECK(!parseStrictInt("abc").has_value());
    ABYSS_CHECK(parseStrictInt("42").has_value());
    ABYSS_CHECK(!parseStrictDouble("1.5x").has_value());
    ABYSS_CHECK(!parseStrictDouble("nan").has_value());
    ABYSS_CHECK(!parseStrictDouble("inf").has_value());
    ABYSS_CHECK(parseStrictDouble("4.8").has_value());
}

ABYSS_TEST("scanner thresholds: a poisoned (negative/non-numeric) value falls back to the default") {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "abyss_test_poisoned_thresholds.rules";
    {
        std::ofstream f(tmp, std::ios::binary);
        f << "[thresholds]\noversized_line_length=-999\nescape_density_min_count=not_a_number\n";
    }
    auto t = scanner::loadThresholds(tmp.string());
    auto defaults = scanner::ScanThresholds::withDefaults();
    ABYSS_CHECK_EQ(t.oversizedLineLength, defaults.oversizedLineLength);
    ABYSS_CHECK_EQ(t.escapeDensityMinCount, defaults.escapeDensityMinCount);
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

ABYSS_TEST("json: reasonable nested JSONC still parses within default limits") {
    std::string text = R"({
        "tasks": [
            {"label": "a", "runOptions": {"runOn": "folderOpen"}, "presentation": {"reveal": "silent"}},
            {"label": "b", "args": ["x", "y", "z"]}
        ]
    })";
    auto result = parseJson(text);
    ABYSS_CHECK(result.ok);
}

ABYSS_TEST("json: escapes control characters and quotes") {
    std::string escaped = jsonEscape("line1\nline2\t\"quoted\"");
    ABYSS_CHECK(escaped.find("\\n") != std::string::npos);
    ABYSS_CHECK(escaped.find("\\t") != std::string::npos);
    ABYSS_CHECK(escaped.find("\\\"") != std::string::npos);
}

ABYSS_TEST("block format: parses sections and repeated keys") {
    std::string text = R"(
# comment
[rule]
id=test.rule
match.contains=foo
match.contains_any=a;b;c
)";
    auto result = parseBlocks(text);
    ABYSS_CHECK(result.ok);
    ABYSS_CHECK_EQ(result.blocks.size(), (std::size_t)1);
    ABYSS_CHECK_EQ(result.blocks[0].section, std::string("rule"));
    ABYSS_CHECK_EQ(result.blocks[0].get("id"), std::string("test.rule"));
    auto list = Block::splitList(result.blocks[0].get("match.contains_any"));
    ABYSS_CHECK_EQ(list.size(), (std::size_t)3);
}

ABYSS_TEST("block format: rejects key=value outside any section") {
    auto result = parseBlocks("dangling=value\n[rule]\nid=x\n");
    ABYSS_CHECK(!result.ok);
}

ABYSS_TEST("finding: JSONL serialization round-trips key fields") {
    Finding f;
    f.findingId = "F000001";
    f.ruleId = "core.test";
    f.ruleName = "Test rule";
    f.type = RuleType::Behavior;
    f.severity = Severity::High;
    f.confidence = Confidence::Medium;
    f.description = "desc with \"quotes\"";
    f.filePath = "a/b.js";
    f.line = 42;
    std::string line = findingToJsonLine(f);
    ABYSS_CHECK(line.find("\"severity\":\"HIGH\"") != std::string::npos);
    ABYSS_CHECK(line.find("\"line\":42") != std::string::npos);
    ABYSS_CHECK(line.find("\\\"quotes\\\"") != std::string::npos);
}

ABYSS_TEST("sanitizeForOutput: strips raw control bytes") {
    std::string s = sanitizeForOutput(std::string("safe") + '\x01' + "text" + '\x00' + "here");
    ABYSS_CHECK(s.find('\x01') == std::string::npos);
    ABYSS_CHECK(s.find('\x00') == std::string::npos);
    ABYSS_CHECK(s.find("safe") != std::string::npos);
}

ABYSS_TEST("sanitizeForOutput: strips ANSI CSI escape sequences") {
    std::string malicious = std::string("normal") + "\x1b[2J\x1b[H" + "text";
    std::string s = sanitizeForOutput(malicious);
    ABYSS_CHECK(s.find('\x1b') == std::string::npos);
    ABYSS_CHECK(s.find("normal") != std::string::npos);
    ABYSS_CHECK(s.find("text") != std::string::npos);
}

ABYSS_TEST("sanitizeForOutput: preserves ordinary printable text and tabs") {
    std::string s = sanitizeForOutput("clean\tfilename.js");
    ABYSS_CHECK_EQ(s, std::string("clean\tfilename.js"));
}

ABYSS_TEST("sanitizeForOutput: truncates beyond maxLen") {
    std::string long_(10000, 'a');
    std::string s = sanitizeForOutput(long_, 100);
    ABYSS_CHECK(s.size() <= 103);
}

ABYSS_TEST("redactSecrets: AWS access key ID is redacted") {
    std::string s = redactSecrets("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
    ABYSS_CHECK(s.find("AKIAIOSFODNN7EXAMPLE") == std::string::npos);
    ABYSS_CHECK(s.find("[REDACTED:aws-access-key]") != std::string::npos);
}

ABYSS_TEST("redactSecrets: GitHub token is redacted") {
    std::string s = redactSecrets("token: ghp_1234567890abcdefghij1234567890ABCD");
    ABYSS_CHECK(s.find("ghp_1234567890abcdefghij1234567890ABCD") == std::string::npos);
    ABYSS_CHECK(s.find("[REDACTED:github-token]") != std::string::npos);
}

ABYSS_TEST("redactSecrets: Authorization Bearer header is redacted, keeping the scheme visible") {
    std::string s = redactSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpart");
    ABYSS_CHECK(s.find("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpart") == std::string::npos);
    ABYSS_CHECK(s.find("Authorization") != std::string::npos); // context preserved
    ABYSS_CHECK(s.find("[REDACTED:authorization-header]") != std::string::npos);
}

ABYSS_TEST("redactSecrets: password= assignment redacts the value, keeps the key name") {
    std::string s = redactSecrets("DB_PASSWORD=SuperSecretValue123!");
    ABYSS_CHECK(s.find("SuperSecretValue123!") == std::string::npos);
    ABYSS_CHECK(s.find("PASSWORD") != std::string::npos);
}

ABYSS_TEST("redactSecrets: PEM private key block is redacted wholesale") {
    std::string s = redactSecrets(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----");
    ABYSS_CHECK(s.find("MIIEpAIBAAKCAQEA1234567890abcdef") == std::string::npos);
    ABYSS_CHECK(s.find("[REDACTED:private-key-block]") != std::string::npos);
}

ABYSS_TEST("redactSecrets: connection-string embedded password is redacted, host/user preserved") {
    std::string s = redactSecrets("postgres://dbuser:hunter2pass@db.example.com:5432/mydb");
    ABYSS_CHECK(s.find("hunter2pass") == std::string::npos);
    ABYSS_CHECK(s.find("dbuser") != std::string::npos);
    ABYSS_CHECK(s.find("db.example.com") != std::string::npos);
}

ABYSS_TEST("redactSecrets: ordinary non-secret text passes through unchanged") {
    std::string original = "const cfg = { plugins: [], server: { port: 5173 } };";
    ABYSS_CHECK_EQ(redactSecrets(original), original);
}

ABYSS_TEST("redactSecrets + finding pipeline: a finding still fires and prints, but the raw secret never appears") {
    Finding f;
    f.findingId = "F1";
    f.ruleId = "test.secret_leak";
    f.ruleName = "test";
    f.type = RuleType::Behavior;
    f.severity = Severity::High;
    f.confidence = Confidence::Medium;
    f.description = "Found hardcoded credential: aws_secret_access_key=AKIAABCDEFGHIJKLMNOP in config";
    f.filePath = "config.js";
    f.evidence = "AKIAABCDEFGHIJKLMNOP";

    std::ostringstream jsonOut;
    evidence::writeFindingsJsonl({f}, jsonOut);
    std::string jsonLine = jsonOut.str();
    ABYSS_CHECK(jsonLine.find("test.secret_leak") != std::string::npos); // the finding IS present
    ABYSS_CHECK(jsonLine.find("AKIAABCDEFGHIJKLMNOP") == std::string::npos); // the secret is NOT

    scanner::ScanCoverage coverage;
    evidence::RuleTrustStatus trust;
    trust.trustLevel = "official";
    trust.integrityStatus = "verified";
    evidence::Verdict verdict = evidence::computeVerdict(coverage, {f}, trust);
    std::ostringstream humanOut;
    evidence::writeHumanReport("scope", {f}, coverage, trust, verdict, humanOut);
    std::string humanText = humanOut.str();
    ABYSS_CHECK(humanText.find("test.secret_leak") != std::string::npos);
    ABYSS_CHECK(humanText.find("AKIAABCDEFGHIJKLMNOP") == std::string::npos);
}

ABYSS_TEST("trim: strips leading and trailing whitespace only") {
    ABYSS_CHECK_EQ(trim("   hello world   "), std::string("hello world"));
    ABYSS_CHECK_EQ(trim(""), std::string(""));
    ABYSS_CHECK_EQ(trim("no-trim"), std::string("no-trim"));
}

ABYSS_TEST("pathToUtf8: round-trips non-Latin and emoji filenames without throwing") {
    // On Windows, std::filesystem::path::string() converts via the
    // process's ANSI codepage and throws std::system_error for any
    // character that codepage can't represent -- which is most non-Latin
    // scripts and all emoji. This is what actually crashed a real
    // system-scan run when it walked a real file the machine's ANSI
    // codepage (e.g. Western European, CP1252) can't represent. pathToUtf8
    // must handle all of these without throwing, including characters
    // outside the Basic Multilingual Plane that require UTF-16 surrogate
    // pairs (the emoji below).
    namespace fs = std::filesystem;
    const std::vector<std::string> samples = {
        "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82",         // "Привет" (Cyrillic)
        "\xe4\xbd\xa0\xe5\xa5\xbd",                                  // "你好" (CJK)
        "\xf0\x9f\x9a\x80\xf0\x9f\x94\x92",                          // rocket + lock emoji (astral plane)
    };
    for (const auto& utf8Name : samples) {
        fs::path p(reinterpret_cast<const char8_t*>(utf8Name.c_str()));
        std::string roundTripped = pathToUtf8(p);
        ABYSS_CHECK_EQ(roundTripped, utf8Name);
    }
}

ABYSS_TEST("pathToUtf8: a real file with a non-ASCII name can be discovered and read without throwing") {
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path() / "abyss_unicode_path_test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    ABYSS_CHECK(!ec);

    const std::string utf8Name = "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82.txt"; // "Привет.txt"
    fs::path filePath = dir / fs::path(reinterpret_cast<const char8_t*>(utf8Name.c_str()));
    { std::ofstream out(filePath, std::ios::binary); out << "content"; }
    ABYSS_CHECK(fs::exists(filePath, ec));

    bool found = false;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         it != end && !ec; it.increment(ec)) {
        // The old p.string() call here would throw on this exact filename
        // on a machine whose ANSI codepage isn't Cyrillic -- reproducing
        // the real crash mechanism, not just a synthetic one.
        std::string name = pathToUtf8(it->path().filename());
        if (name == utf8Name) found = true;
    }
    ABYSS_CHECK(!ec);
    ABYSS_CHECK(found);

    fs::remove_all(dir, ec);
}
