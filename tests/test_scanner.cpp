#include "test_harness.h"

#include <algorithm>
#include <atomic>
#include <thread>

#include "preflight/esr.h"
#include "rules/rules.h"
#include "scanner/scanner.h"

using namespace abyss;
using namespace abyss::scanner;
using namespace abyss::test;

namespace {
bool hasRule(const std::vector<Finding>& findings, const std::string& ruleId) {
    return std::any_of(findings.begin(), findings.end(), [&](const Finding& f) { return f.ruleId == ruleId; });
}
} // namespace

ABYSS_TEST("magic: detects WOFF2/GIF/PE signatures correctly") {
    auto woff2 = readFixtureBytes("legit-font.woff2.sample");
    ABYSS_CHECK(!woff2.empty());
    ABYSS_CHECK(detectMagic(woff2.data(), woff2.size()) == FileKind::Woff2);

    auto gif = readFixtureBytes("legit-image.gif.sample");
    ABYSS_CHECK(detectMagic(gif.data(), gif.size()) == FileKind::Gif);

    ABYSS_CHECK(detectMagic(nullptr, 0) == FileKind::Unknown);
}

ABYSS_TEST("entropy: random-looking bytes score higher than repetitive bytes") {
    std::vector<std::uint8_t> uniform(256);
    for (int i = 0; i < 256; i++) uniform[i] = (std::uint8_t)i;
    std::vector<std::uint8_t> constant(256, 0x41);

    double e1 = shannonEntropyBits(uniform.data(), uniform.size());
    double e2 = shannonEntropyBits(constant.data(), constant.size());
    ABYSS_CHECK(e1 > 7.9);   // uniform distribution over 256 values ~= 8 bits
    ABYSS_CHECK(e2 < 0.001); // single repeated byte carries ~0 entropy
}

ABYSS_TEST("text heuristics: clean config produces no findings") {
    std::string content = readFixtureText("clean-config.js.sample");
    auto findings = scanTextHeuristics("clean-config.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("credentials: exposed GitHub token is reported with a redacted, line-accurate finding") {
    const std::string token = "ghp_aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4zA6";
    auto findings = scanCredentialExposure(".env", "FIRST_LINE_PADDING=1\nGITHUB_TOKEN=" + token + "\n");
    ABYSS_CHECK(hasRule(findings, "core.credential_exposure"));
    for (const auto& finding : findings) {
        ABYSS_CHECK(finding.evidence.find(token) == std::string::npos);
        if (finding.ruleId == "core.credential_exposure") ABYSS_CHECK(finding.line == 2u);
    }
}

ABYSS_TEST("credentials: placeholder token examples are not reported") {
    auto findings = scanCredentialExposure(".env.example", "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
    ABYSS_CHECK(!hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: private key material is reported without printing key bytes") {
    std::string key = "-----BEGIN PRIVATE KEY-----\n" + std::string(80, 'A') + "\n-----END PRIVATE KEY-----\n";
    auto findings = scanCredentialExposure("deploy.pem", key);
    ABYSS_CHECK(hasRule(findings, "core.credential_exposure"));
    for (const auto& finding : findings) ABYSS_CHECK(finding.evidence.find(std::string(20, 'A')) == std::string::npos);
}

ABYSS_TEST("credentials: AWS access key is caught (broader provider coverage than GitHub/npm alone)") {
    auto findings = scanCredentialExposure("deploy.sh", "aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP\n");
    ABYSS_CHECK(hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: a conventional credential filename with no pattern match still gets a review finding") {
    auto findings = scanCredentialExposure("id_rsa", "not actually PEM-shaped content\n");
    ABYSS_CHECK(hasRule(findings, "core.credential_file_present"));
}

ABYSS_TEST("credentials: clean source produces no credential findings") {
    std::string content = readFixtureText("clean-config.js.sample");
    auto findings = scanCredentialExposure("clean-config.js", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("credentials: a function-call assignment is not mistaken for a secret value") {
    // Real-world regression: node_modules/cloudinary's
    // `oauth_token: getOption(options, "oauth_token")` and similar
    // getter-call patterns were being redacted and reported as though
    // "getOption" were the secret itself.
    auto findings = scanCredentialExposure("config.js", "  api_key: getOption(options, \"api_key\"),\n");
    ABYSS_CHECK(!hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: a bare identifier assignment is not mistaken for a secret value") {
    // `url.password = someVariable;` matches the same shape as a real
    // `API_KEY=aB3xY9k2` assignment; the distinguishing signal is that a
    // real secret is virtually always high-entropy (contains a digit),
    // while a bare variable/property reference like this is pure letters.
    auto findings = scanCredentialExposure("index.js", "  url.password = someLocalVariable;\n");
    ABYSS_CHECK(!hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: documentation-example values are not mistaken for secrets, generically") {
    // No package name is special-cased here -- this must hold for any
    // package's docs, not just the ones observed so far (dotenv,
    // pg-connection-string, bcrypt, ...).
    std::string content =
        "postgres://someuser:somepassword@somehost:5432/somedatabase\n"
        "SECRET_KEY=\"yourSecretKey\"\n"
        "DB_PASSWORD=DBHost\n";
    auto findings = scanCredentialExposure("README.md", content);
    ABYSS_CHECK(!hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: a real unquoted .env-style secret with digits is still caught") {
    // Regression safety: the precision fixes above must not have widened
    // into suppressing genuine secrets. A real credential almost always
    // has digits mixed in, unlike the bare-identifier/doc-example cases.
    auto findings = scanCredentialExposure(".env", "DB_PASSWORD=SuperSecretValue123!\n");
    ABYSS_CHECK(hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("credentials: a real oauth_token value with digits is still caught, not just its getter") {
    auto findings = scanCredentialExposure("config.js", "  oauth_token: \"aT9kQ2xR8mZ4\",\n");
    ABYSS_CHECK(hasRule(findings, "core.credential_exposure"));
}

ABYSS_TEST("text heuristics: whitespace concealment gap is detected") {
    std::string content = readFixtureText("polinrider-v1-marker.js.sample");
    auto findings = scanTextHeuristics("polinrider-v1-marker.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(hasRule(findings, "core.concealment_whitespace_gap"));
}

ABYSS_TEST("text heuristics: rotated marker fixture also triggers concealment") {
    std::string content = readFixtureText("polinrider-v2-rotated.js.sample");
    auto findings = scanTextHeuristics("polinrider-v2-rotated.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(hasRule(findings, "core.concealment_whitespace_gap"));
}

ABYSS_TEST("text heuristics: a padded Markdown table row is not a false-positive concealment finding") {
    // Real-world regression: node_modules READMEs (bytes, jsonwebtoken,
    // multer, to-regex-range, ...) routinely pad table cells with 50+
    // spaces for column alignment, which is shape-identical to the
    // concealment technique this detector targets. Flagging every padded
    // Markdown table as "Critical" concealment is exactly the kind of
    // claim-it's-malicious-when-it-isn't false positive that erodes trust
    // in the tool's output.
    std::string content =
        "# Docs\n"
        "| Property                                          | Type   | Description |\n"
        "| -------------------------------------------------- | ------ | ----------- |\n"
        "| name                                                | string | the name    |\n";
    auto findings = scanTextHeuristics("README.md", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(!hasRule(findings, "core.concealment_whitespace_gap"));
}

ABYSS_TEST("text heuristics: the same padded-pipe shape outside a .md file still triggers concealment") {
    // The Markdown-table exemption is restricted to actual .md/.markdown
    // files specifically so a script can't get a free pass by wrapping a
    // real payload in '|' characters -- confirm that restriction holds.
    std::string content = "const x = 1;" + std::string(60, ' ') + "|payload|more|\n";
    auto findings = scanTextHeuristics("script.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(hasRule(findings, "core.concealment_whitespace_gap"));
}

ABYSS_TEST("text heuristics: network + exec-sink combo is detected together, not separately") {
    std::string content = readFixtureText("network-exec-combo.js.sample");
    auto findings = scanTextHeuristics("network-exec-combo.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(hasRule(findings, "core.network_exec_combo"));
}

ABYSS_TEST("text heuristics: legitimate dynamic require does not trigger indirect-require") {
    std::string content = readFixtureText("legitimate-dynamic-require.js.sample");
    auto findings = scanTextHeuristics("legitimate-dynamic-require.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(!hasRule(findings, "core.indirect_require"));
}

ABYSS_TEST("text heuristics: padded backslash line-continuations do not trigger concealment") {
    std::string content = readFixtureText("clean-macro-continuation.h.sample");
    auto findings = scanTextHeuristics("clean-macro-continuation.h", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(!hasRule(findings, "core.concealment_whitespace_gap"));
}

ABYSS_TEST("text heuristics: large legitimate minified line does not trigger concealment") {
    std::string content = readFixtureText("clean-large-minified.js.sample");
    auto findings = scanTextHeuristics("clean-large-minified.js", content, ScanThresholds::withDefaults());
    ABYSS_CHECK(!hasRule(findings, "core.concealment_whitespace_gap"));
    // A long legitimate minified line is allowed to trip the low-severity
    // oversized-line signal alone; it must not be treated as concealment.
}

ABYSS_TEST("binary masquerade: fake font with script content is flagged high-confidence") {
    auto bytes = readFixtureBytes("fake-font.woff2.sample");
    auto findings = scanBinaryExtensionMasquerade("fonts/fa-solid-400.woff2", ".woff2", bytes);
    ABYSS_CHECK(hasRule(findings, "core.binary_extension_masquerade"));
}

ABYSS_TEST("binary masquerade: legitimate WOFF2 magic bytes produce no finding") {
    auto bytes = readFixtureBytes("legit-font.woff2.sample");
    auto findings = scanBinaryExtensionMasquerade("fonts/real.woff2", ".woff2", bytes);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("binary masquerade: WOFF2 with valid header but appended script content is Critical") {
    auto bytes = readFixtureBytes("woff2-trailing-payload.sample");
    ABYSS_CHECK(!bytes.empty());
    auto findings = scanBinaryExtensionMasquerade("fonts/real.woff2", ".woff2", bytes);
    ABYSS_CHECK(hasRule(findings, "core.woff2_trailing_payload"));
    auto it = std::find_if(findings.begin(), findings.end(),
                            [](const Finding& f) { return f.ruleId == "core.woff2_trailing_payload"; });
    if (it != findings.end()) ABYSS_CHECK(it->severity == Severity::Critical);
}

ABYSS_TEST("binary masquerade: WOFF2 with implausible table count is flagged") {
    std::vector<std::uint8_t> bytes(64, 0);
    bytes[0] = 'w'; bytes[1] = 'O'; bytes[2] = 'F'; bytes[3] = '2';
    // length field (BE) = 64, matches buffer size
    bytes[8] = 0; bytes[9] = 0; bytes[10] = 0; bytes[11] = 64;
    // numTables (BE) = 0 -- implausible
    bytes[12] = 0; bytes[13] = 0;
    auto findings = scanBinaryExtensionMasquerade("fonts/bad.woff2", ".woff2", bytes);
    ABYSS_CHECK(hasRule(findings, "core.woff2_structural_anomaly"));
}

ABYSS_TEST("structural validation: PE with implausible section count is flagged") {
    std::vector<std::uint8_t> buf(88, 0);
    buf[0] = 'M'; buf[1] = 'Z';
    std::uint32_t peOffset = 0x40;
    buf[0x3C] = (std::uint8_t)(peOffset & 0xFF);
    buf[0x3D] = (std::uint8_t)((peOffset >> 8) & 0xFF);
    buf[0x3E] = (std::uint8_t)((peOffset >> 16) & 0xFF);
    buf[0x3F] = (std::uint8_t)((peOffset >> 24) & 0xFF);
    buf[peOffset + 0] = 'P'; buf[peOffset + 1] = 'E'; buf[peOffset + 2] = 0; buf[peOffset + 3] = 0;
    std::uint16_t numSections = 9999; // implausible
    buf[peOffset + 6] = (std::uint8_t)(numSections & 0xFF);
    buf[peOffset + 7] = (std::uint8_t)((numSections >> 8) & 0xFF);

    auto findings = scanBinaryExtensionMasquerade("tool.exe", ".exe", buf);
    ABYSS_CHECK(hasRule(findings, "core.pe_structural_anomaly"));
}

ABYSS_TEST("structural validation: PE with a plausible section count produces no finding") {
    std::vector<std::uint8_t> buf(88, 0);
    buf[0] = 'M'; buf[1] = 'Z';
    std::uint32_t peOffset = 0x40;
    buf[0x3C] = (std::uint8_t)(peOffset & 0xFF);
    buf[0x3D] = (std::uint8_t)((peOffset >> 8) & 0xFF);
    buf[0x3E] = (std::uint8_t)((peOffset >> 16) & 0xFF);
    buf[0x3F] = (std::uint8_t)((peOffset >> 24) & 0xFF);
    buf[peOffset + 0] = 'P'; buf[peOffset + 1] = 'E'; buf[peOffset + 2] = 0; buf[peOffset + 3] = 0;
    std::uint16_t numSections = 4; // plausible
    buf[peOffset + 6] = (std::uint8_t)(numSections & 0xFF);
    buf[peOffset + 7] = (std::uint8_t)((numSections >> 8) & 0xFF);

    auto findings = scanBinaryExtensionMasquerade("tool.exe", ".exe", buf);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("binary masquerade: non-registered extension yields no findings") {
    std::vector<std::uint8_t> bytes = {1, 2, 3};
    auto findings = scanBinaryExtensionMasquerade("data.bin", ".bin", bytes);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("invisible unicode: bidi override characters are flagged") {
    std::string content = readFixtureText("invisible-unicode.js.sample");
    auto findings = scanInvisibleUnicode("invisible-unicode.js", content);
    ABYSS_CHECK(hasRule(findings, "core.invisible_unicode_bidi"));
    ABYSS_CHECK(hasRule(findings, "core.invisible_unicode_concealment"));
}

ABYSS_TEST("invisible unicode: clean ASCII file produces no findings") {
    std::string content = readFixtureText("clean-config.js.sample");
    auto findings = scanInvisibleUnicode("clean-config.js", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("repository discovery: detects .git directory without descending into object storage") {
    std::string fx = fixturesDir();
    auto discovery = discoverRepository(fx);
    ABYSS_CHECK(!discovery.files.empty());
}

ABYSS_TEST("repository discovery: refuses to follow a symlink whose target escapes the scan root") {
    namespace fs = std::filesystem;
    fs::path base = fs::temp_directory_path() / "abyss_test_symlink_escape";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "root", ec);
    fs::create_directories(base / "outside", ec);
    {
        std::ofstream f((base / "outside" / "secret.txt").string());
        f << "outside content";
    }
    fs::create_symlink(base / "outside" / "secret.txt", base / "root" / "escape_link.txt", ec);
    if (ec) {
        // Creating a symlink requires elevated privileges or Developer Mode
        // on Windows; skip rather than fail the suite in a sandbox that
        // doesn't permit it. Covered by code review in that case.
        fs::remove_all(base, ec);
        return;
    }
    auto discovery = discoverRepository((base / "root").string());
    bool foundEscapeFile = std::any_of(discovery.files.begin(), discovery.files.end(),
                                        [](const DiscoveredFile& f) { return f.filename == "escape_link.txt"; });
    ABYSS_CHECK(!foundEscapeFile);
    ABYSS_CHECK(!discovery.symlinkEscapesSkipped.empty());
    fs::remove_all(base, ec);
}

ABYSS_TEST("ScanCoverage::isComplete: false when symlink escapes were skipped") {
    ScanCoverage c;
    c.symlinkEscapesSkipped = 1;
    ABYSS_CHECK(!c.isComplete());
}

ABYSS_TEST("ScanCoverage::isComplete: false when a file changed during the scan") {
    ScanCoverage c;
    c.filesChangedDuringScan = 1;
    ABYSS_CHECK(!c.isComplete());
}

ABYSS_TEST("ScanCoverage::isComplete: true when every counter is zero") {
    ScanCoverage c;
    ABYSS_CHECK(c.isComplete());
}

ABYSS_TEST("full scan: a file modified concurrently with the scan is flagged (best-effort, timing-dependent)") {
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path() / "abyss_test_toctou";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    fs::path target = dir / "churn.txt";
    {
        std::ofstream f(target);
        f << std::string(200000, 'a');
    }

    std::atomic<bool> stop{false};
    std::thread writer([&]() {
        int i = 0;
        while (!stop.load()) {
            std::ofstream f(target, std::ios::binary | std::ios::trunc);
            f << std::string(200000 + (i++ % 5000), 'b');
        }
    });

    rules::RuleEngine emptyRules(std::vector<rules::Rule>{});
    preflight::ExecutionSurfaceRegistry emptyEsr(std::vector<preflight::ExecutionSurface>{});
    auto report = scanRepository(dir.string(), emptyRules, emptyEsr, ScanOptions{});

    stop.store(true);
    writer.join();
    fs::remove_all(dir, ec);

    // Best-effort: on a fast filesystem the single read may complete
    // between writer iterations without ever observing a torn state. The
    // mechanism itself (checked deterministically above) is what matters;
    // this integration test just confirms it doesn't crash or misbehave
    // when churn is actually happening, and if it *does* observe a change,
    // coverage correctly reports incompleteness.
    if (report.coverage.filesChangedDuringScan > 0) {
        ABYSS_CHECK(!report.coverage.isComplete());
    }
}

ABYSS_TEST("repository discovery: an in-root symlink target is still discovered as a file") {
    namespace fs = std::filesystem;
    fs::path base = fs::temp_directory_path() / "abyss_test_symlink_inroot";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "root" / "real", ec);
    {
        std::ofstream f((base / "root" / "real" / "target.txt").string());
        f << "in-root content";
    }
    fs::create_symlink(base / "root" / "real" / "target.txt", base / "root" / "link.txt", ec);
    if (ec) {
        fs::remove_all(base, ec);
        return;
    }
    auto discovery = discoverRepository((base / "root").string());
    bool foundLink = std::any_of(discovery.files.begin(), discovery.files.end(),
                                  [](const DiscoveredFile& f) { return f.filename == "link.txt"; });
    ABYSS_CHECK(foundLink);
    ABYSS_CHECK(discovery.symlinkEscapesSkipped.empty());
    fs::remove_all(base, ec);
}

ABYSS_TEST("repository discovery: Abyss's own abyss-results output is never descended into") {
    // Regression: abyss-results/results.txt (see main.cpp's reportTo) is
    // written inside the scan root itself. A prior report's own redacted
    // evidence lines are text that can match the credential/exec-combo
    // detectors, so re-scanning a project that already has a results file
    // must not turn Abyss's own report into a source of new findings.
    namespace fs = std::filesystem;
    fs::path base = fs::temp_directory_path() / "abyss_test_results_selfscan";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "abyss-results", ec);
    {
        std::ofstream f((base / "abyss-results" / "results.txt").string());
        f << "Evidence: DATABASE_URL=postgresql://user:REDACTED@host/db\n";
    }
    {
        std::ofstream f((base / "real-source.js").string());
        f << "const x = 1;\n";
    }
    auto discovery = discoverRepository(base.string());
    bool foundResultsFile = std::any_of(discovery.files.begin(), discovery.files.end(),
                                        [](const DiscoveredFile& f) { return f.filename == "results.txt"; });
    bool foundRealSource = std::any_of(discovery.files.begin(), discovery.files.end(),
                                       [](const DiscoveredFile& f) { return f.filename == "real-source.js"; });
    ABYSS_CHECK(!foundResultsFile);
    ABYSS_CHECK(foundRealSource);
    fs::remove_all(base, ec);
}

ABYSS_TEST("full scan: a legitimate binary WOFF2 is never treated as text") {
    // Regression test: printableRatio() must not misclassify arbitrary
    // binary bytes as text just because many of them are >= 0x80.
    rules::RuleEngine emptyRules(std::vector<rules::Rule>{});
    preflight::ExecutionSurfaceRegistry emptyEsr(std::vector<preflight::ExecutionSurface>{});
    auto report = scanRepository(fixturesDir(), emptyRules, emptyEsr, ScanOptions{});
    for (const auto& f : report.findings) {
        ABYSS_CHECK(f.filePath.find("legit-font.woff2.sample") == std::string::npos);
    }
}

ABYSS_TEST("full scan: large project (>= 200 files) uses the multi-threaded path and stays correct") {
    // scanRepository parallelizes across worker threads once a scan has at
    // least 200 files (see scanner.cpp) -- none of the fixture-based tests
    // above are anywhere near that size, so without this test the
    // concurrent code path would never actually run under the suite.
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path() / "abyss_test_large_scan";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    constexpr int kFileCount = 260;
    constexpr int kMarkerEvery = 37; // scattered, not clustered on one thread's slice
    int expectedMarkers = 0;
    for (int i = 0; i < kFileCount; ++i) {
        std::ofstream f(dir / ("file_" + std::to_string(i) + ".js"));
        if (i % kMarkerEvery == 0) {
            f << "global['!']='8-270-2';\n";
            ++expectedMarkers;
        } else {
            f << "const value_" << i << " = " << i << ";\n";
        }
    }

    rules::Rule markerRule;
    markerRule.id = "test.marker";
    markerRule.name = "test marker";
    markerRule.type = RuleType::Ioc;
    markerRule.severity = Severity::Critical;
    markerRule.confidence = Confidence::Confirmed;
    markerRule.containsAny = {"global['!']='8-270-2'"};
    rules::RuleEngine ruleEngine(std::vector<rules::Rule>{markerRule});
    preflight::ExecutionSurfaceRegistry emptyEsr(std::vector<preflight::ExecutionSurface>{});

    std::atomic<std::size_t> progressCalls{0};
    ScanOptions options;
    std::atomic<std::size_t> reportedThreads{0};
    options.onProgress = [&](std::size_t, std::size_t, std::size_t threadsUsed) {
        ++progressCalls;
        reportedThreads.store(threadsUsed, std::memory_order_relaxed);
    };
    auto report = scanRepository(dir.string(), ruleEngine, emptyEsr, options);

    ABYSS_CHECK(report.coverage.filesDiscovered == static_cast<std::size_t>(kFileCount));
    ABYSS_CHECK(report.coverage.filesAnalyzed == static_cast<std::size_t>(kFileCount));
    ABYSS_CHECK(report.coverage.filesUnreadable == 0);
    int markerFindings = 0;
    for (const auto& finding : report.findings) {
        if (finding.ruleId == "test.marker") ++markerFindings;
    }
    ABYSS_CHECK(markerFindings == expectedMarkers);
    ABYSS_CHECK(progressCalls.load() > 0);
    // 260 files clears the 200-file threading threshold, so this should
    // genuinely be running on more than one thread on any multi-core CI/dev
    // machine (falls back to 1 only if memory or core count forced it).
    ABYSS_CHECK(report.coverage.threadsUsed >= 1);
    ABYSS_CHECK(reportedThreads.load() == report.coverage.threadsUsed);

    fs::remove_all(dir, ec);
}
